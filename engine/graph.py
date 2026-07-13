"""Fact-Intent Graph engine for Atoolkit v8.4.

Manages discovery->exploration direction generation and cross-run
knowledge persistence.
"""

from __future__ import annotations

import json
import pathlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

try:
    from .vuln_classes import norm_vc, vc_matches, is_chainable
    from .surface_key import canonical_surface_key
except ImportError:
    from vuln_classes import norm_vc, vc_matches, is_chainable
    from surface_key import canonical_surface_key


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class IntentStatus(str, Enum):
    PENDING = "pending"
    CLAIMED = "claimed"             # v8.6: actively being worked on this turn
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"         # executed, produced new Fact(s)
    ABANDONED = "abandoned"         # executed but no value
    BLOCKED = "blocked"             # prerequisite not met
    DEFERRED = "deferred"           # v8.6: postponed with structured reason
    SUPERSEDED = "superseded"       # v8.6: replaced by a better Intent


class IntentSource(str, Enum):
    CHAIN = "chain"                # derived from chain_assessment
    CROSS_ENDPOINT = "cross"       # cross-endpoint testing
    ESCALATION = "escalation"      # privilege escalation direction
    RECON = "recon"                # reconnaissance expansion
    ANOMALY = "anomaly"            # anomalous response follow-up


class FactType(str, Enum):
    CONFIRMED_VULN = "confirmed"
    NEGATIVE_WITH_CONTEXT = "negative"
    INFO_DISCLOSURE = "info_disclosure"
    ANOMALY = "anomaly"


# ---------------------------------------------------------------------------
# Dataclass schemas (reference only)
# ---------------------------------------------------------------------------

@dataclass
class Fact:
    fact_id: str
    source_type: str
    source_candidate_id: str
    endpoint: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    vuln_class: str = ""
    summary: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    phase: int = 1
    agent: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    chain_feasible: bool = False
    chain_path: str = ""
    chain_final_impact: str = ""


@dataclass
class Intent:
    intent_id: str
    source_fact_id: str
    source: str
    description: str
    vuln_class: str = ""
    target_endpoint: str = ""
    target_params: list[str] = field(default_factory=list)
    priority: str = "medium"
    status: str = "pending"
    assigned_phase: int = 2
    assigned_agent: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resolved_at: str = ""
    outcome_summary: str = ""
    spawned_facts: list[str] = field(default_factory=list)


# Note: Fact/Intent dataclasses define the field schema (for documentation and
# IDE hints).  FactIntentGraph uses plain dicts internally so that the graph is
# directly JSON-serializable.  Field names and types correspond 1:1.


# ---------------------------------------------------------------------------
# FactIntentGraph
# ---------------------------------------------------------------------------

class FactIntentGraph:
    """Fact-Intent graph: a directed graph of discoveries and exploration
    directions."""

    def __init__(self):
        self.facts: list[dict] = []
        self.intents: list[dict] = []
        self._next_fact_id = 1
        self._next_intent_id = 1

    # -- core operations (section 3.2) --------------------------------------

    def add_fact(self, fact_data: dict) -> tuple:
        fact_data.setdefault("fact_id", f"fact_{self._next_fact_id:03d}")
        self._next_fact_id += 1
        self.facts.append(fact_data)
        new_intents = IntentRuleEngine.generate_intents(fact_data, self)
        for intent in new_intents:
            intent.setdefault("target_method", fact_data.get("method", ""))
            intent.setdefault("method", intent.get("target_method", ""))
            intent["intent_id"] = f"intent_{self._next_intent_id:03d}"
            intent.setdefault("status", "pending")  # v8.5.1: ensure status is always set
            self._next_intent_id += 1
            self.intents.append(intent)
        return fact_data, new_intents

    def fact_from_candidate(self, candidate: dict, fact_type: str = "confirmed") -> dict:
        chain = candidate.get("chain_assessment") or {}
        chain_status = str(chain.get("status") or "not_tested").lower()
        chain_proven = (
            chain_status == "proven"
            and bool(chain.get("proof_refs"))
            and not bool(chain.get("blockers"))
        )
        return {
            "source_type": fact_type,
            "source_candidate_id": candidate.get("candidate_id", ""),
            "endpoint": candidate.get("endpoint", ""),
            "method": candidate.get("method", "GET"),
            "params": [candidate.get("param", "")] if candidate.get("param") else [],
            "vuln_class": norm_vc(candidate.get("vuln_class", "")),  # v8.5.2: normalize at creation
            "summary": candidate.get("hypothesis", ""),
            "evidence_refs": candidate.get("evidence_refs", []),
            "proof_status": candidate.get("proof_status", "pending"),
            "chain_status": chain_status,
            "chain_feasible": chain_proven,
            "chain_path": chain.get("chain_path", ""),
            "chain_final_impact": chain.get("final_impact", "") if chain_proven else "",
            "chain_hypothesis": chain.get("chain_path", "") if not chain_proven else "",
        }

    def get_pending_intents(self, *, agent: str = "", phase: int = 0,
                            priority: str = "", limit: int = 10) -> list[dict]:
        pending = [
            i for i in self.intents
            if i.get("status") == "pending"
            and (not agent or i.get("assigned_agent") in (agent, "any", ""))
            and (not phase or i.get("assigned_phase", 0) <= phase)
            and (not priority or i.get("priority") == priority)
        ]
        priority_order = {"high": 0, "medium": 1, "low": 2}
        pending.sort(key=lambda x: (
            priority_order.get(x.get("priority", "low"), 9),
            int(x.get("dispatches", 0) or 0),
            str(x.get("created_at", "")),
            str(x.get("intent_id", "")),
        ))
        return pending[:limit]

    def resolve_intent(self, intent_id, status, summary="", spawned_facts=None,
                       *, reason="", attempts=0):
        """Resolve an Intent with status, summary, and optional structured reason.

        Structured reasons (for deferred/blocked):
          missing_account, missing_object_state, human_verification_needed,
          insufficient_traffic, no_observable_signal.
        """
        for intent in self.intents:
            if intent.get("intent_id") == intent_id:
                intent["status"] = status
                intent["outcome_summary"] = summary
                intent["spawned_facts"] = spawned_facts or []
                intent["resolved_at"] = datetime.now(timezone.utc).isoformat()
                if reason:
                    intent["defer_reason"] = reason
                if attempts:
                    intent["attempts"] = attempts
                return intent
        return None

    def claim_intent(self, intent_id, *, increment_attempt: bool = True):
        """Mark an Intent as claimed (actively being worked on)."""
        for intent in self.intents:
            if intent.get("intent_id") == intent_id:
                intent["status"] = "claimed"
                intent.setdefault("attempts", 0)
                intent["dispatches"] = int(intent.get("dispatches", 0) or 0) + 1
                if increment_attempt:
                    intent["attempts"] += 1
                return intent
        return None

    def release_intent(self, intent_id, summary=""):
        """Return a claimed Intent to pending for another evidence attempt."""
        for intent in self.intents:
            if intent.get("intent_id") == intent_id:
                intent["status"] = "pending"
                if summary:
                    intent["outcome_summary"] = summary
                intent["last_attempt_at"] = datetime.now(timezone.utc).isoformat()
                return intent
        return None

    def merge_graph(self, other):
        id_map = {}
        for fact in other.facts:
            old_id = fact["fact_id"]
            fact_copy = dict(fact)
            fact_copy["fact_id"] = f"fact_{self._next_fact_id:03d}"
            self._next_fact_id += 1
            id_map[old_id] = fact_copy["fact_id"]
            self.facts.append(fact_copy)
        for intent in other.intents:
            intent_copy = dict(intent)
            intent_copy["intent_id"] = f"intent_{self._next_intent_id:03d}"
            self._next_intent_id += 1
            old_src = intent_copy.get("source_fact_id", "")
            if old_src in id_map:
                intent_copy["source_fact_id"] = id_map[old_src]
            self.intents.append(intent_copy)

    def stats(self) -> dict:
        intent_by_status = {}
        for i in self.intents:
            s = i.get("status")  # v8.5.1: no default — expose missing status
            intent_by_status[s] = intent_by_status.get(s, 0) + 1
        return {
            "total_facts": len(self.facts),
            "total_intents": len(self.intents),
            "intents_by_status": intent_by_status,
            "chain_links": sum(
                1 for f in self.facts if f.get("chain_status") == "proven"
            ),
            "chain_hypotheses": sum(
                1 for f in self.facts
                if f.get("chain_status") in {"hypothesis", "partial"}
                or f.get("chain_hypothesis")
            ),
            "high_priority_pending": sum(
                1 for i in self.intents
                if i.get("status") == "pending" and i.get("priority") == "high"
            ),
        }

    # -- cross-run persistence (section 9.7) --------------------------------

    def export_to_blackboard(self, run_id: str) -> dict:
        """Export this run's Graph as a blackboard-increment payload."""
        return {
            "new_facts": [
                {**f, "source_run": run_id}
                for f in self.facts
                if (f.get("source_type") == "confirmed"
                    and f.get("proof_status") == "confirmed")
            ],
            "new_intents": self.intents,
            "run_id": run_id,
            "stats": self.stats(),
        }

    def import_from_blackboard(self, blackboard: dict, domain: str = ""):
        """Import historical state from the project-level blackboard.

        - confirmed facts are loaded as pre-existing (skip re-testing)
        - pending intents are added to the work queue
        - dead_ends and depth-sufficient negatives are returned as a skip list
        """
        blackboard = normalize_blackboard_schema(blackboard)
        # Import historical facts (no domain filter -- facts are cross-domain
        # knowledge that every domain should inherit).
        # e.g. a token leak found in the auth domain may be exploited by a txn
        # domain Intent.
        for fact in blackboard.get("facts", []):
            self.facts.append({
                **fact,
                "_pre_existing": True,  # mark as historical, do not re-test
            })

        # Import pending intents
        for intent in blackboard.get("intents", []):
            if intent.get("status") == "pending":
                if domain and intent.get("assigned_domain", "") != domain:
                    continue
                self.intents.append(intent)

        # Build skip list (for CoverageLedger initialisation)
        skip_surfaces = []
        for neg in blackboard.get("negatives", []):
            if neg.get("depth_sufficient"):
                skip_surfaces.append({
                    "endpoint": neg["endpoint"],
                    "method": neg.get("method", ""),
                    "param": neg.get("param", ""),
                    "vuln_class": neg.get("vuln_class", ""),
                    "status": "not_vulnerable",
                    "reason": f"excluded in {neg.get('deepest_run', '?')}",
                    "evidence_ref": neg.get("file", ""),
                    "negative_depth_checked": True,
                    "negative": {
                        "vectors": neg.get("vectors", []),
                        "response_count": neg.get("response_count", 0),
                        "evidence_types": neg.get("evidence_types", []),
                        "identities": neg.get("identities", []),
                    },
                })
        for de in blackboard.get("dead_ends", []):
            skip_surfaces.append({
                "endpoint": de["endpoint"],
                "method": de.get("method", ""),
                "param": de.get("param", ""),
                "vuln_class": de.get("vuln_class", ""),
                "status": "not_applicable",
                "reason": f"dead end: {de.get('refutation', '')}",
            })
        return skip_surfaces


# ---------------------------------------------------------------------------
# IntentRuleEngine (section 3.3)
# ---------------------------------------------------------------------------

class IntentRuleEngine:
    """Deterministic Intent generation rule engine."""

    MAX_INTENTS_PER_FACT = 5  # max 5 Intents per Fact

    @staticmethod
    def generate_intents(fact, graph):
        intents = []
        for rule in IntentRuleEngine._rules():
            if rule["condition"](fact, graph):
                intent = rule["generate"](fact)
                if intent:
                    intents.append(intent)
        # deduplicate + cap
        seen = set()
        deduped = []
        for i in intents:
            key = (i.get("target_endpoint"), tuple(i.get("target_params", [])),
                   i.get("vuln_class"))
            if key not in seen:
                seen.add(key)
                deduped.append(i)
        return deduped[:IntentRuleEngine.MAX_INTENTS_PER_FACT]

    @staticmethod
    def _rules():
        """Intent generation rules. v8.5.1: uses vc_matches() for vuln_class
        matching instead of hardcoded strings. Single source of truth in
        vuln_classes.py."""
        return [
            # Rule 1: auth weakness -> chain exploitation
            {
                "name": "auth_chain",
                "condition": lambda f, g: (
                    f.get("source_type") == "confirmed"
                    and vc_matches(f.get("vuln_class", ""), "auth")
                    and f.get("chain_feasible")),
                "generate": lambda f: {
                    "source_fact_id": f["fact_id"],
                    "source": "chain",
                    "description": f"\u94fe\u5f0f\u5229\u7528\uff1a{f.get('chain_path', f.get('summary', ''))}",
                    "vuln_class": "auth-bypass-chain",
                    "priority": "high", "assigned_phase": 2,
                    "assigned_agent": "input_precision",
                },
            },
            # Rule 2: info disclosure -> credential exploitation
            # (keyword-based on summary text, not vuln_class)
            {
                "name": "info_leak_credential",
                "condition": lambda f, g: (
                    f.get("source_type") in ("confirmed", "info_disclosure")
                    and any(kw in (f.get("summary", "") + f.get("vuln_class", "")).lower()
                            for kw in ("\u6cc4\u9732", "leak", "disclosure", "sign", "key",
                                       "secret", "token", "credential", "\u5bc6\u7801", "\u5bc6\u94a5"))),
                "generate": lambda f: {
                    "source_fact_id": f["fact_id"],
                    "source": "escalation",
                    "description": (
                        f"\u5229\u7528\u6cc4\u9732\u51ed\u8bc1\u5c1d\u8bd5\u4f2a\u9020\u8bf7\u6c42\u6216\u63d0\u6743"
                        f"\uff08\u6765\u6e90: {f.get('endpoint', '?')}\uff0c"
                        f"\u5bfb\u627e\u4f7f\u7528\u8be5\u51ed\u8bc1\u7684\u4e0b\u6e38\u7aef\u70b9\uff09"),
                    "vuln_class": "privilege-escalation",
                    "target_endpoint": "",
                    "priority": "high", "assigned_phase": 2,
                    "assigned_agent": "input_precision",
                },
            },
            # Rule 3: SQLi -> data extraction
            {
                "name": "sqli_extraction",
                "condition": lambda f, g: (
                    f.get("source_type") == "confirmed"
                    and vc_matches(f.get("vuln_class", ""), "sqli")),
                "generate": lambda f: {
                    "source_fact_id": f["fact_id"],
                    "source": "escalation",
                    "description": "SQLi \u6570\u636e\u63d0\u53d6\uff1a\u5c1d\u8bd5\u8bfb\u53d6\u654f\u611f\u8868/\u5217",
                    "vuln_class": "sqli",
                    "target_endpoint": f.get("endpoint", ""),
                    "target_params": f.get("params", []),
                    "priority": "high", "assigned_phase": 2,
                    "assigned_agent": "input_precision",
                },
            },
            # Rule 4: cross-param testing (param-count based, no vuln_class)
            {
                "name": "cross_param_type",
                "condition": lambda f, g: (
                    f.get("source_type") == "confirmed"
                    and len(f.get("params", [])) >= 2),
                "generate": lambda f: {
                    "source_fact_id": f["fact_id"],
                    "source": "cross",
                    "description": f"\u8de8\u7c7b\u578b\u4ea4\u53c9\u6d4b\u8bd5\uff1a{f.get('endpoint', '')} \u591a\u53c2\u6570\u7c7b\u578b",
                    "vuln_class": "cross-validation",
                    "target_endpoint": f.get("endpoint", ""),
                    "target_params": f.get("params", []),
                    "priority": "medium", "assigned_phase": 2,
                    "assigned_agent": "input_precision",
                },
            },
            # Rule 5: WAF blocked -> bypass retry (summary keyword based)
            {
                "name": "waf_bypass_retry",
                "condition": lambda f, g: (
                    f.get("source_type") == "negative"
                    and any(kw in (f.get("summary", "")).lower()
                            for kw in ("waf", "\u62e6\u622a", "blocked", "forbidden",
                                       "\u975e\u6cd5", "\u5173\u952e\u5b57"))),
                "generate": lambda f: {
                    "source_fact_id": f["fact_id"],
                    "source": "anomaly",
                    "description": f"WAF \u7ed5\u8fc7\u91cd\u6d4b\uff1a{f.get('endpoint', '')}",
                    "vuln_class": f.get("vuln_class", "input-validation"),
                    "target_endpoint": f.get("endpoint", ""),
                    "target_params": f.get("params", []),
                    "priority": "medium", "assigned_phase": 2,
                    "assigned_agent": "input_precision",
                },
            },
            # Rule 6: business logic -> fund chain
            {
                "name": "business_logic_chain",
                "condition": lambda f, g: (
                    f.get("source_type") == "confirmed"
                    and (vc_matches(f.get("vuln_class", ""), "business")
                         or any(kw in f.get("endpoint", "").lower()
                                for kw in ("amount", "refund", "recharge", "payment",
                                           "points", "balance", "coupon", "order",
                                           "lottery", "\u91d1\u989d", "\u9000\u6b3e",
                                           "\u5145\u503c", "\u79ef\u5206", "\u652f\u4ed8")))),
                "generate": lambda f: {
                    "source_fact_id": f["fact_id"],
                    "source": "chain",
                    "description": "\u4e1a\u52a1\u903b\u8f91\u94fe\uff1a\u9a8c\u8bc1\u662f\u5426\u53ef\u6784\u9020\u5b8c\u6574\u8d44\u91d1\u653b\u51fb\u94fe",
                    "vuln_class": "business-logic-chain",
                    "priority": "high", "assigned_phase": 2,
                    "assigned_agent": "input_precision",
                },
            },
            # Rule 7: IDOR -> impact escalation
            {
                "name": "idor_impact",
                "condition": lambda f, g: (
                    f.get("source_type") == "confirmed"
                    and vc_matches(f.get("vuln_class", ""), "idor")),
                "generate": lambda f: {
                    "source_fact_id": f["fact_id"],
                    "source": "escalation",
                    "description": "IDOR \u5f71\u54cd\u5347\u7ea7\uff1a\u8bc4\u4f30\u6279\u91cf\u8bbf\u95ee\u6216\u66f4\u5927\u5f71\u54cd",
                    "vuln_class": "idor",
                    "target_endpoint": f.get("endpoint", ""),
                    "target_params": f.get("params", []),
                    "priority": "medium", "assigned_phase": 2,
                    "assigned_agent": "input_precision",
                },
            },
            # Rule 8: SSRF -> internal probing
            {
                "name": "ssrf_internal",
                "condition": lambda f, g: (
                    f.get("source_type") == "confirmed"
                    and vc_matches(f.get("vuln_class", ""), "ssrf")),
                "generate": lambda f: {
                    "source_fact_id": f["fact_id"],
                    "source": "recon",
                    "description": "SSRF \u5185\u7f51\u63a2\u6d4b\uff1a\u63a2\u6d4b\u5185\u7f51\u670d\u52a1\u548c\u5143\u6570\u636e\u7aef\u70b9",
                    "vuln_class": "ssrf",
                    "target_endpoint": f.get("endpoint", ""),
                    "target_params": f.get("params", []),
                    "priority": "high", "assigned_phase": 2,
                    "assigned_agent": "input_precision",
                },
            },
            # Rule 9: generic fallback — ensures EVERY confirmed finding
            # produces at least one Intent, even if no specific rule matches.
            # This prevents the pipeline from silently dropping vuln_classes
            # like 'stored-xss' or 'privilege-escalation' that have no
            # dedicated rule.
            {
                "name": "generic_followup",
                "condition": lambda f, g: (
                    f.get("source_type") == "confirmed"
                    and not any(
                        r["condition"](f, g)
                        for r in IntentRuleEngine._rules()[:-1]
                    )),
                "generate": lambda f: {
                    "source_fact_id": f["fact_id"],
                    "source": "escalation",
                    "description": f"\u8bc4\u4f30\u5f71\u54cd\u8303\u56f4\u548c\u5229\u7528\u6df1\u5ea6\uff1a{f.get('endpoint', '')} ({f.get('vuln_class', '?')})",
                    "vuln_class": f.get("vuln_class", ""),
                    "target_endpoint": f.get("endpoint", ""),
                    "target_params": f.get("params", []),
                    "priority": "low", "assigned_phase": 2,
                    "assigned_agent": "input_precision",
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level helper functions
# ---------------------------------------------------------------------------

def merge_agent_graphs(agent_graphs: list) -> FactIntentGraph:
    """Merge multiple agent Graphs at a phase transition, deduplicating Intents."""
    merged = FactIntentGraph()
    for g in agent_graphs:
        merged.merge_graph(g)
    # Intent dedup: same source_fact_id + target_endpoint + vuln_class keeps
    # only the highest-priority copy.
    # NOTE: source_fact_id MUST be part of the dedup key -- otherwise Intents
    # from *different* Facts targeting the same endpoint would be incorrectly
    # merged (e.g. refund.php and coupon.php both produce business-logic-chain
    # with target_endpoint="" and would collide).
    seen = {}
    deduped = []
    prio = {"high": 0, "medium": 1, "low": 2}
    for intent in merged.intents:
        key = (intent.get("source_fact_id"), intent.get("target_endpoint"),
               intent.get("vuln_class"))
        if key in seen:
            existing = seen[key]
            if prio.get(intent.get("priority"), 9) < prio.get(existing.get("priority"), 9):
                deduped = [i for i in deduped
                           if i.get("intent_id") != existing.get("intent_id")]
                deduped.append(intent)
                seen[key] = intent
        else:
            seen[key] = intent
            deduped.append(intent)
    merged.intents = deduped
    return merged


def intent_work_queue(graph, remaining_surfaces, phase=2):
    """Build a unified work queue: Intents + Surfaces, sorted by priority."""
    queue = []
    for intent in graph.get_pending_intents(phase=phase, limit=30):
        tier = 0 if intent.get("priority") == "high" else (
               2 if intent.get("priority") == "medium" else 4)
        queue.append({"type": "intent", "data": intent, "sort_key": (tier,)})
    for surface in remaining_surfaces:
        is_high = any(t in ("auth-flow", "amount-tamper", "idor", "payment")
                      for t in surface.get("risk_tags", []))
        queue.append({"type": "surface", "data": surface,
                      "sort_key": (1 if is_high else 3,)})
    queue.sort(key=lambda x: x["sort_key"])
    return queue


def _method_and_path(value: str, fallback_method: str = "GET") -> tuple[str, str]:
    canonical = canonical_surface_key(value, default_method=fallback_method)
    method, _, path = canonical.partition(" ")
    return (method or fallback_method).upper(), path or str(value or "")


def normalize_blackboard_schema(data: dict | None) -> dict:
    """Normalize Engine v2 and the historical Skill-Mode v1 artifact to v2.

    Legacy ``depth_negatives`` lack vectors/response proof, so migration keeps
    them open (depth_sufficient=False) rather than silently trusting the label.
    """
    src = dict(data or {})
    if (str(src.get("schema_version")) == "2.0"
            and all(key in src for key in ("facts", "intents", "negatives", "dead_ends"))):
        src.setdefault("domains_covered", {})
        src.setdefault("surface_index", {})
        src.setdefault("merged_run_ids", [])
        return src

    facts = list(src.get("facts") or [])
    intents = list(src.get("intents") or [])
    for index, old in enumerate(src.get("confirmed_facts") or [], start=1):
        method, endpoint = _method_and_path(
            old.get("endpoint", ""), old.get("method", "GET"))
        finding_id = str(old.get("id") or f"legacy_fact_{index:03d}")
        facts.append({
            "fact_id": finding_id,
            "source_type": "legacy_unvalidated",
            "source_candidate_id": "",
            "source_run": str(old.get("run") or "legacy"),
            "endpoint": endpoint,
            "method": method,
            "params": list(old.get("params") or []),
            "vuln_class": old.get("type", ""),
            "summary": old.get("title") or finding_id,
            "evidence_refs": [f"findings/{finding_id}/finding.json"],
            "affected_role": old.get("affected_role", ""),
            "legacy_domain": old.get("domain", ""),
            "proof_status": "untrusted_legacy",
        })
        legacy_intent_id = f"legacy_revalidate_{finding_id}"
        if not any(str(item.get("intent_id")) == legacy_intent_id for item in intents):
            intents.append({
                "intent_id": legacy_intent_id,
                "source_fact_id": finding_id,
                "source": "revalidation",
                "description": f"复验历史 Skill Mode 根结论：{old.get('title') or finding_id}",
                "vuln_class": old.get("type", ""),
                "target_endpoint": endpoint,
                "target_params": list(old.get("params") or []),
                "priority": "high",
                "status": "pending",
                "assigned_phase": 1,
                "assigned_agent": "input_precision",
            })

    for index, old in enumerate(src.get("pending_intents") or [], start=1):
        if isinstance(old, dict):
            item = dict(old)
        else:
            item = {"description": str(old)}
        item.setdefault("intent_id", f"legacy_intent_{index:03d}")
        item.setdefault("status", "pending")
        item.setdefault("priority", "medium")
        intents.append(item)

    negatives = list(src.get("negatives") or [])
    for index, old in enumerate(src.get("depth_negatives") or [], start=1):
        method, endpoint = _method_and_path(
            old.get("surface", old.get("endpoint", "")), old.get("method", "GET"))
        vuln_class = old.get("vuln_class", "")
        negatives.append({
            "surface_key": f"{method} {endpoint}::{old.get('param', '')}::{vuln_class}",
            "endpoint": endpoint,
            "method": method,
            "param": old.get("param", ""),
            "vuln_class": vuln_class,
            "vectors_tried": 0,
            "depth_sufficient": False,
            "file": old.get("file", ""),
            "deepest_run": str(old.get("run") or "legacy"),
            "legacy_id": old.get("id", f"legacy_negative_{index:03d}"),
            "migration_note": "legacy record lacked vectors/response evidence; revalidate",
        })

    migrated = {
        "schema_version": "2.0",
        "facts": facts,
        "intents": intents,
        "negatives": negatives,
        "dead_ends": list(src.get("dead_ends") or []),
        "discovered_endpoints": list(src.get("discovered_endpoints") or []),
        "domains_covered": dict(src.get("domains_covered") or {}),
        "surface_index": dict(src.get("surface_index") or {}),
        "total_runs": int(src.get("total_runs", src.get("runs_completed", 0)) or 0),
        "last_run": src.get("last_run", ""),
        "last_updated": src.get("last_updated", ""),
        "merged_run_ids": list(src.get("merged_run_ids") or []),
    }
    if src:
        migrated["migrated_from_schema"] = str(src.get("schema_version") or "legacy")
    return migrated


def merge_run_to_blackboard(blackboard_path: str, run_graph: FactIntentGraph,
                            run_id: str, run_negatives: list[dict] = None):
    """Merge a run's output into the project-level blackboard at run end."""
    bb_path = pathlib.Path(blackboard_path)
    raw_bb = json.loads(bb_path.read_text(encoding="utf-8")) if bb_path.exists() else {
        "schema_version": "2.0", "facts": [], "intents": [],
        "negatives": [], "dead_ends": [], "discovered_endpoints": [],
        "domains_covered": {}, "surface_index": {},
    }
    bb = normalize_blackboard_schema(raw_bb)
    merged_run_ids = list(bb.get("merged_run_ids") or [])
    is_new_run = run_id not in merged_run_ids

    # -- merge facts --------------------------------------------------------
    def _fact_key(f):
        return (
            canonical_surface_key({
                "endpoint": f.get("endpoint", ""),
                "method": f.get("method", "GET"),
            }),
            norm_vc(f.get("vuln_class", "")),
            str(f.get("affected_role", "")),
        )

    existing_facts = {_fact_key(f): f for f in bb.get("facts", [])}
    fact_id_map = {str(f.get("fact_id", "")): str(f.get("fact_id", ""))
                   for f in bb.get("facts", []) if f.get("fact_id")}
    for fact in run_graph.facts:
        if (fact.get("source_type") != "confirmed"
                or fact.get("proof_status") != "confirmed"):
            continue
        key = _fact_key(fact)
        old_id = str(fact.get("fact_id", ""))
        if key in existing_facts:
            if old_id:
                fact_id_map[old_id] = str(existing_facts[key].get("fact_id", old_id))
        else:
            fact_copy = {k: v for k, v in fact.items() if not str(k).startswith("_")}
            fact_copy["fact_id"] = f"bb_fact_{len(bb['facts']) + 1:03d}"
            fact_copy["source_run"] = run_id
            bb["facts"].append(fact_copy)
            existing_facts[key] = fact_copy
            if old_id:
                fact_id_map[old_id] = fact_copy["fact_id"]

    # -- merge intents (update status) --------------------------------------
    def _intent_key(i):
        return (
            str(i.get("source_fact_id", "")),
            str(i.get("description", "")),
            str(i.get("vuln_class", "")),
            canonical_surface_key(i.get("target_endpoint", ""))
            if i.get("target_endpoint") else "",
        )

    for intent in run_graph.intents:
        intent_copy = {k: v for k, v in intent.items() if not str(k).startswith("_")}
        source_id = str(intent_copy.get("source_fact_id", ""))
        intent_copy["source_fact_id"] = fact_id_map.get(source_id, source_id)
        by_id = next((i for i in bb.get("intents", [])
                      if i.get("intent_id") == intent_copy.get("intent_id")), None)
        by_key = next((i for i in bb.get("intents", [])
                       if _intent_key(i) == _intent_key(intent_copy)), None)
        existing = by_id or by_key
        if existing is not None:
            stable_id = existing.get("intent_id")
            created_in_run = existing.get("created_in_run")
            existing.update(intent_copy)
            existing["intent_id"] = stable_id
            if created_in_run:
                existing["created_in_run"] = created_in_run
        else:
            intent_copy["intent_id"] = f"bb_intent_{len(bb['intents']) + 1:03d}"
            intent_copy["created_in_run"] = run_id
            intent_copy.setdefault("runs_without_execution", 0)
            bb["intents"].append(intent_copy)

    # -- merge negatives -----------------------------------------------------
    for neg in (run_negatives or []):
        surface_key = neg.get("surface_key", "")
        existing_neg = next(
            (n for n in bb.get("negatives", []) if n.get("surface_key") == surface_key),
            None,
        )
        if existing_neg:
            # keep the deeper record
            if neg.get("vectors_tried", 0) > existing_neg.get("vectors_tried", 0):
                existing_neg.update(neg)
                existing_neg["deepest_run"] = run_id
        else:
            neg_copy = dict(neg)
            neg_copy["deepest_run"] = run_id
            bb.setdefault("negatives", []).append(neg_copy)

    # -- Intent decay -------------------------------------------------------
    # Never infer run age from the spelling of run_id: the public default is
    # sess-YYYYMMDD-HHMMSS and callers may provide any --sid.  Persist an
    # explicit counter instead.
    DECAY_FACTOR = 0.9
    ABANDON_THRESHOLD = 0.5  # priority_score < this -> abandoned
    PRIO_BASE = {"high": 3.0, "medium": 2.0, "low": 1.0}
    if is_new_run:
        for intent in bb.get("intents", []):
            if intent.get("status") != "pending":
                continue
            if intent.get("created_in_run", "") == run_id:
                intent["runs_without_execution"] = 0
                continue  # intents created this run are not decayed
            runs_since = int(intent.get("runs_without_execution", 0) or 0) + 1
            intent["runs_without_execution"] = runs_since
            base_score = PRIO_BASE.get(intent.get("priority", "low"), 1.0)
            effective = base_score * (DECAY_FACTOR ** runs_since)
            if effective < ABANDON_THRESHOLD:
                intent["status"] = "abandoned"
                intent["outcome_summary"] = (
                    f"\u8870\u51cf\u653e\u5f03: {runs_since} run \u672a\u6267\u884c, effective={effective:.2f}")

    # -- update metadata ----------------------------------------------------
    bb["schema_version"] = "2.0"
    bb["total_runs"] = bb.get("total_runs", 0) + (1 if is_new_run else 0)
    if is_new_run:
        merged_run_ids.append(run_id)
    bb["merged_run_ids"] = merged_run_ids
    bb["last_run"] = run_id
    bb["last_updated"] = datetime.now(timezone.utc).isoformat()
    bb.setdefault("domains_covered", {})
    bb.setdefault("surface_index", {})

    bb_path.parent.mkdir(parents=True, exist_ok=True)
    bb_path.write_text(json.dumps(bb, ensure_ascii=False, indent=2), encoding="utf-8")
    return bb


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    g = FactIntentGraph()
    fact_data = {
        "source_type": "confirmed",
        "source_candidate_id": "cand_001",
        "endpoint": "/api/user/refund.php",
        "method": "POST",
        "params": ["refund_amount"],
        "vuln_class": "amount-tamper",
        "summary": "\u9000\u6b3e\u91d1\u989d\u65e0\u4e0a\u9650\u6821\u9a8c",
        "chain_feasible": True,
        "chain_path": "\u9000\u6b3e\u65e0\u4e0a\u9650\u2192\u53cd\u590d\u9000\u6b3e\u2192\u4f59\u989d\u81a8\u80c0",
    }
    fact, intents = g.add_fact(fact_data)
    print(f"Added fact: {fact['fact_id']}")
    print(f"Generated {len(intents)} intent(s):")
    for i in intents:
        print(f"  - {i['intent_id']}: {i['description']}  [{i['priority']}]")
    print(f"\nGraph stats: {g.stats()}")
