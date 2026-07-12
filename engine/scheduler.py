"""Run Scheduler for Atoolkit v8.6.

Determines what surfaces to test and in what order, based on blackboard
history, business graph priorities, and domain scope.
"""

from __future__ import annotations

import json
import pathlib

try:
    from .surface_key import canonical_cell_key, canonical_surface_key, is_canonical
except ImportError:
    from surface_key import canonical_cell_key, canonical_surface_key, is_canonical

_PRIORITY_SCORE = {"high": 0, "medium": 1, "low": 2}
_DOMAIN_SEQUENCE = ["auth", "txn", "idor", "input", "admin", "file", "info"]

# Default vuln classes used to expand surfaces into cells when no explicit
# vuln_class list is provided to compute_run_scope.
_DEFAULT_VC = ["未授权访问", "越权/IDOR", "SQLi", "XSS", "SSRF",
               "命令执行/RCE", "文件读取/穿越", "CSRF", "业务逻辑"]


# -- Internal helpers -------------------------------------------------------

def _canonicalize_set(items) -> set[str]:
    """Canonicalize an iterable of endpoint-like values into a set of surface keys."""
    out: set[str] = set()
    for it in items:
        if isinstance(it, dict):
            ep = it.get("endpoint", "") or it.get("path", "") or it.get("url", "")
            m = it.get("method", "")
        else:
            ep = str(it or "")
            m = ""
        if not ep:
            continue
        ck = canonical_surface_key({"endpoint": ep, "method": m} if m else ep)
        if ck:
            out.add(ck)
    return out


def _endpoints_in_blackboard(bb: dict, *, fully_covered: bool = False) -> set[str]:
    """Return evidence-touched or fully covered canonical endpoint keys.

    A single fact/negative is useful for flow completion, but must not make all
    remaining params/roles/risk families on that endpoint look completed.
    """
    eps: set[str] = set()
    if fully_covered:
        for key, meta in (bb.get("surface_index") or {}).items():
            if isinstance(meta, dict) and meta.get("tested"):
                ck = canonical_surface_key(key)
                if ck:
                    eps.add(ck)
        return eps
    for fact in bb.get("facts", []):
        if (fact.get("source_type") != "confirmed"
                or fact.get("proof_status") in {"untrusted_legacy", "pending", "refuted"}):
            continue
        ck = canonical_surface_key({"endpoint": fact.get("endpoint", ""),
                                     "method": fact.get("method", "GET")})
        if ck:
            eps.add(ck)
    for neg in bb.get("negatives", []):
        if not neg.get("depth_sufficient"):
            continue
        ck = canonical_surface_key({"endpoint": neg.get("endpoint", ""),
                                     "method": neg.get("method", "GET")})
        if ck:
            eps.add(ck)
    for dead_end in bb.get("dead_ends", []):
        ck = canonical_surface_key(dead_end)
        if ck:
            eps.add(ck)
    return eps

def _high_value_endpoints(bg: dict, target_domains: list[str]) -> list[str]:
    """High-value endpoints sorted by value, target-domain first (advisory)."""
    emap = bg.get("endpoint_map", {})
    if not emap:
        for flow in bg.get("flows", []):
            for step in flow.get("steps", []):
                ep = step.get("endpoint", "")
                if ep and ep not in emap:
                    emap[ep] = {"domains": [flow.get("domain", "")],
                                "value": flow.get("value", "medium")}
    scored: list[tuple[int, bool, str]] = []
    for ep, meta in emap.items():
        in_target = (bool(set(meta.get("domains", [])) & set(target_domains))
                     if target_domains else True)
        scored.append((_PRIORITY_SCORE.get(meta.get("value", "medium"), 1),
                       not in_target, ep))
    scored.sort()
    return [ep for _, _, ep in scored]

def _flow_completion_endpoints(bg: dict, bb: dict) -> list[str]:
    """Endpoints needed to complete partially-explored business flows."""
    tested = _endpoints_in_blackboard(bb)
    needed: list[str] = []
    for flow in bg.get("flows", []):
        steps = flow.get("steps", [])
        tested_count = sum(1 for s in steps
                           if canonical_surface_key(s.get("endpoint", "")) in tested)
        if 0 < tested_count < len(steps):
            for s in steps:
                ck = canonical_surface_key(s.get("endpoint", ""))
                if ck and ck not in tested and ck not in needed:
                    needed.append(ck)
    return needed

def _shallow_negatives(bb: dict) -> list[str]:
    """Canonical surface keys from negatives where depth_sufficient=False."""
    result: list[str] = []
    for neg in bb.get("negatives", []):
        if not neg.get("depth_sufficient", True):
            ck = canonical_surface_key({"endpoint": neg.get("endpoint", ""),
                                         "method": neg.get("method", "GET")})
            if ck and ck not in result:
                result.append(ck)
    return result

def _carryover_intents(bb: dict) -> list[dict]:
    """High-priority pending intents to carry into the next run."""
    return [{"intent_id": i.get("intent_id", ""), "priority": i.get("priority", "high")}
            for i in bb.get("intents", [])
            if i.get("status") == "pending" and i.get("priority") == "high"]


def select_target_domains(blackboard: dict, requested: list[str] | None = None) -> list[str]:
    """Choose the next advisory domain focus from cumulative coverage."""
    if requested:
        return list(dict.fromkeys(requested))
    covered = (blackboard or {}).get("domains_covered", {}) or {}
    if not covered:
        return ["auth", "txn"]
    partial = []
    for domain, stats in covered.items():
        total = int((stats or {}).get("total", 0) or 0)
        tested = int((stats or {}).get("tested", 0) or 0)
        if total and tested < total:
            partial.append((tested / total, _DOMAIN_SEQUENCE.index(domain)
                            if domain in _DOMAIN_SEQUENCE else 99, domain))
    if partial:
        partial.sort()
        return [domain for _, _, domain in partial[:2]]
    unseen = [domain for domain in _DOMAIN_SEQUENCE if domain not in covered]
    return unseen[:2] or ["auth", "txn"]

# -- Core scheduling function -----------------------------------------------

def compute_run_scope(
    blackboard: dict,
    business_graph: dict,
    inventory: list[str],
    target_domains: list[str],
    surface_budget: int = 80,
    intent_budget: int = 15,
    vuln_classes: list[str] | None = None,
) -> dict:
    """Compute the run scope: which surfaces to test and in what order.

    Domain scope is ADVISORY -- target-domain surfaces sort first, but
    cross-domain surfaces are never dropped, just deprioritized.
    """
    bb = blackboard or {}
    bg = business_graph or {}
    target_domains = select_target_domains(bb, target_domains)
    known_eps = _endpoints_in_blackboard(bb, fully_covered=True)

    # Normalize inventory: accept both strings and dicts → canonical surface keys
    inv_eps: list[str] = []
    inv_params: dict[str, list[str]] = {}
    for item in (inventory or []):
        ck = canonical_surface_key(item)
        if ck:
            inv_eps.append(ck)
            raw_params = []
            if isinstance(item, dict):
                value = item.get("params") or item.get("param") or []
                raw_params = value if isinstance(value, list) else [value]
            params = inv_params.setdefault(ck, [])
            for param in raw_params:
                text = str(param or "").strip()
                if text and text not in params:
                    params.append(text)
    inv_set = set(inv_eps)

    # Tier 1: high-priority pending intents (carried over)
    carryover = _carryover_intents(bb)
    # Tier 2: high-value target-domain surfaces
    biz_surfaces = [ep for ep in _high_value_endpoints(bg, target_domains)
                    if ep in inv_set]
    # Tier 3: flow completion surfaces
    flow_surfaces = [ep for ep in _flow_completion_endpoints(bg, bb)
                     if ep in inv_set]
    # Tier 4: shallow negatives with signal
    shallow_negs = [ep for ep in _shallow_negatives(bb) if ep in inv_set]
    # Tier 5: newly discovered endpoints (in inventory, not in bb)
    new_eps = [ep for ep in inv_eps if ep and ep not in known_eps]
    # Tier 6: low-value remaining coverage
    higher_tiers = set(biz_surfaces) | set(flow_surfaces) | set(shallow_negs)
    remaining = [ep for ep in inv_eps
                 if ep in known_eps and ep not in higher_tiers]

    # Merge tiers respecting budget, deduplicate preserving priority
    must_test: list[str] = []
    seen: set[str] = set()

    def _add(endpoints: list[str]) -> None:
        for ep in endpoints:
            if ep not in seen and (surface_budget <= 0 or len(must_test) < surface_budget):
                seen.add(ep)
                must_test.append(ep)

    for batch in (biz_surfaces, flow_surfaces, shallow_negs, new_eps, remaining):
        _add(batch)

    # Hard invariant: every must_test entry must be canonical "METHOD /path".
    # This is the contract that prevents bare paths (e.g. "/api/refund") from
    # mixing with canonical keys in downstream budget/match logic.
    _bad = [k for k in must_test if not is_canonical(k)]
    if _bad:
        # Defensive: canonicalize stragglers rather than silently emitting
        # non-canonical keys.  This should not trigger if helpers are correct.
        must_test = [canonical_surface_key(k) if not is_canonical(k) else k
                     for k in must_test]

    # Product budget contract: surface_budget counts canonical METHOD/path
    # surfaces.  Every vuln-class cell belonging to an admitted surface is
    # authorized; otherwise a budget of N would accidentally mean "N columns
    # of the first endpoint" rather than N attack surfaces.
    vuln_classes = list(vuln_classes or _DEFAULT_VC)
    all_cells: list[str] = []
    for sk in must_test:
        for param in (inv_params.get(sk) or [""]):
            for vc in vuln_classes:
                all_cells.append(canonical_cell_key(sk, vc, param))
    surface_cell_total = len(all_cells)
    must_test_cells = all_cells

    # Reason string
    if carryover:
        reason = "highest high-value untested domain count"
    elif biz_surfaces:
        reason = "high-value business graph surfaces available"
    elif flow_surfaces:
        reason = "partial business flows need completion"
    elif shallow_negs:
        reason = "shallow negatives warrant deeper testing"
    elif new_eps:
        reason = "newly discovered endpoints need initial coverage"
    else:
        reason = "remaining low-value coverage"

    return {
        "target_domains": target_domains,
        "excluded_domains": [d for d in _DOMAIN_SEQUENCE if d not in target_domains],
        "surface_budget": surface_budget,
        "intent_budget": intent_budget,
        "must_test": must_test,
        "budget_unit": "surface",
        "must_test_cells": must_test_cells,
        "surface_cell_total": surface_cell_total,
        "carryover_intents": (carryover[:intent_budget]
                              if intent_budget and intent_budget > 0 else carryover),
        "reason": reason,
    }

# -- Persistence helpers ----------------------------------------------------

def load_run_scope(project_dir: str | pathlib.Path) -> list[str]:
    """Load run_scope.json if it exists, return target_domains list."""
    path = pathlib.Path(project_dir) / "run_scope.json"
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8")).get("target_domains", [])

def save_run_scope(project_dir: str | pathlib.Path, scope: dict) -> None:
    """Persist run_scope.json to the project directory."""
    path = pathlib.Path(project_dir) / "run_scope.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(scope, ensure_ascii=False, indent=2), encoding="utf-8")

# -- Budget gate ------------------------------------------------------------

def budget_check(current_tested: int, current_intents: int, scope: dict) -> bool:
    """Return True if neither surface nor intent budgets are exhausted."""
    return (current_tested < scope.get("surface_budget", 80)
            and current_intents < scope.get("intent_budget", 15))


# -- Smoke test -------------------------------------------------------------

if __name__ == "__main__":
    bb = {"facts": [{"endpoint": "/api/login", "vuln_class": "auth-bypass"}],
          "intents": [
              {"intent_id": "bb_intent_001", "status": "pending", "priority": "high"},
              {"intent_id": "bb_intent_002", "status": "pending", "priority": "low"}],
          "negatives": [
              {"endpoint": "/api/refund", "depth_sufficient": False},
              {"endpoint": "/api/search", "depth_sufficient": True}],
          "dead_ends": [], "discovered_endpoints": ["/api/login", "/api/refund"]}
    bg = {"endpoint_map": {
              "POST /api/refund": {"domains": ["txn"], "value": "high"},
              "GET /api/admin/users": {"domains": ["auth"], "value": "high"},
              "GET /api/products": {"domains": ["catalog"], "value": "low"}},
          "flows": [{"domain": "txn", "value": "high", "steps": [
              {"endpoint": "POST /api/order"}, {"endpoint": "POST /api/refund"}]}]}
    inv = ["POST /api/refund", "GET /api/admin/users", "GET /api/products",
           "POST /api/order", "GET /api/health"]
    scope = compute_run_scope(bb, bg, inv, target_domains=["auth", "txn"])
    print("=== Run Scope ===")
    for k, v in scope.items():
        print(f"  {k}: {v}")
    print(f"\nBudget OK (0/80): {budget_check(0, 0, scope)}")
    print(f"Budget OK (80/80): {budget_check(80, 0, scope)}")
    empty = compute_run_scope({}, {}, [], [])
    print(f"\nEmpty must_test: {empty['must_test']}")
    print(f"Empty reason: {empty['reason']}")
