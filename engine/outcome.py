"""Deterministic v9 run outcome attribution and continuation planning.

Attribution explains why an exact run object is terminal or still open.  It
never closes a coverage cell: accepted Finding, canonical negative and
structured not-applicable contracts remain the only terminal truth sources.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

try:
    from .surface_key import canonical_surface_key
except ImportError:  # pragma: no cover - direct engine script compatibility
    from surface_key import canonical_surface_key


OUTCOME_CONTRACT_VERSION = 1

_TERMINAL = {"confirmed", "not_vulnerable", "not_applicable"}
_KNOWN_OPEN = {"not_tested", "shallow_negative", "blocked", "exploring"}
_PRIORITY = {
    "proof_rejected": "critical",
    "identity_missing": "high",
    "prerequisite_blocked": "high",
    "discovery_next_run": "high",
    "planning_unassigned": "high",
    "method_unresolved": "high",
    "insufficient_depth": "medium",
    "experiment_incomplete": "medium",
    "execution_not_started": "medium",
    "state_unsupported": "critical",
}
_ACTION = {
    "proof_rejected": "repair canonical proof package and revalidate",
    "identity_missing": "provide distinct authorized identity/object context",
    "prerequisite_blocked": "recover the recorded prerequisite and reacquire baseline",
    "discovery_next_run": "replan the discovered surface in a new sibling run",
    "planning_unassigned": "bind the inventory surface to a feature and threat",
    "method_unresolved": "resolve HTTP method and parameter location from evidence",
    "insufficient_depth": "complete missing experiment obligations with evidence",
    "experiment_incomplete": "continue the exact experiment contract",
    "execution_not_started": "execute the frozen experiment contract",
    "state_unsupported": "repair unsupported or ambiguous machine state",
}


def _list(value: Any) -> list[Any]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _strings(value: Any) -> list[str]:
    result: list[str] = []
    for item in _list(value):
        text = str(item or "").strip()
        if text and text not in result:
            result.append(text)
    return result


def _digest(prefix: str, value: Any) -> str:
    raw = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return f"{prefix}_{hashlib.sha256(raw).hexdigest()[:20]}"


def _sha256(value: Any) -> str:
    raw = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _endpoint(item: Any) -> str:
    if isinstance(item, str):
        text = item.strip()
    elif isinstance(item, dict):
        text = str(
            item.get("endpoint") or item.get("path") or item.get("url") or ""
        ).strip()
    else:
        return ""
    parts = text.split(None, 1)
    return parts[1] if len(parts) == 2 and parts[0].isalpha() else text


def _method(item: Any) -> str:
    if isinstance(item, dict):
        value = str(item.get("method") or "").strip().upper()
        if value:
            return value
        text = str(item.get("endpoint") or item.get("path") or "").strip()
    else:
        text = str(item or "").strip()
    parts = text.split(None, 1)
    return parts[0].upper() if len(parts) == 2 and parts[0].isalpha() else ""


def _evidence_from_progress(progress: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for values in (progress.get("obligation_evidence") or {}).values():
        for ref in _strings(values):
            if ref not in refs:
                refs.append(ref)
    return refs


def _cell_cause(
    surface: dict[str, Any], progress: dict[str, Any] | None,
) -> tuple[str, bool, str]:
    status = str(surface.get("status") or "not_tested").strip().lower()
    execution = str((progress or {}).get("execution_status") or "").strip()
    barriers = set(_strings((progress or {}).get("barrier_signals")))
    if execution == "proof_repair":
        return "proof_rejected", False, _ACTION["proof_rejected"]
    if status == "confirmed":
        return "confirmed", True, "accepted proof-confirmed root finding"
    if status == "not_vulnerable":
        if not progress or execution == "closed":
            return "negative_proven", True, "canonical negative and depth contract passed"
        return "insufficient_depth", False, _ACTION["insufficient_depth"]
    if status == "not_applicable":
        return "not_applicable", True, "structured not-applicable contract passed"
    if status not in _KNOWN_OPEN:
        return "state_unsupported", False, _ACTION["state_unsupported"]
    if barriers & {"missing_role", "ownership_unproven"}:
        return "identity_missing", False, _ACTION["identity_missing"]
    if status == "blocked" or execution == "blocked_recoverable" or barriers:
        return "prerequisite_blocked", False, _ACTION["prerequisite_blocked"]
    if status == "shallow_negative" or execution == "needs_followup":
        return "insufficient_depth", False, _ACTION["insufficient_depth"]
    if execution in {"executing"} or status == "exploring":
        return "experiment_incomplete", False, _ACTION["experiment_incomplete"]
    return "execution_not_started", False, _ACTION["execution_not_started"]


def _continuation(row: dict[str, Any]) -> dict[str, Any] | None:
    cause = str(row.get("cause_code") or "")
    if row.get("terminal") or cause not in _PRIORITY:
        return None
    identity = {
        "kind": row.get("kind"),
        "cause_code": cause,
        "surface_id": row.get("surface_id", ""),
        "method": row.get("method", ""),
        "endpoint": row.get("endpoint", ""),
        "param": row.get("param", ""),
        "roles": row.get("roles", []),
        "vuln_class": row.get("vuln_class", ""),
        "feature_id": row.get("feature_id", ""),
        "threat_id": row.get("threat_id", ""),
        "finding_id": row.get("finding_id", ""),
    }
    return {
        "intent_id": _digest("continuation", identity),
        "source": "v9_host_continuation",
        "source_kind": row.get("kind", ""),
        "source_surface_id": row.get("surface_id", ""),
        "source_finding_id": row.get("finding_id", ""),
        "cause_code": cause,
        "description": str(row.get("next_action") or _ACTION[cause]),
        "priority": _PRIORITY[cause],
        "status": "pending",
        "target_endpoint": row.get("endpoint", ""),
        "target_method": row.get("method", ""),
        "target_params": [row["param"]] if row.get("param") else list(
            row.get("params") or []),
        "target_roles": list(row.get("roles") or []),
        "vuln_class": row.get("vuln_class", ""),
        "feature_id": row.get("feature_id", ""),
        "threat_id": row.get("threat_id", ""),
        "evidence_refs": list(row.get("evidence_refs") or []),
    }


def build_miss_attribution(
    *,
    surfaces: Iterable[dict[str, Any]] = (),
    inventory_rows: Iterable[dict[str, Any] | str] = (),
    unresolved_rows: Iterable[dict[str, Any] | str] = (),
    execution_projection: dict[str, Any] | None = None,
    rejected_findings: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Attribute every frozen/open object without changing its truth state."""
    projection = execution_projection or {}
    progress_by_id = {
        str(item.get("surface_id") or ""): item
        for item in projection.get("progress") or [] if isinstance(item, dict)
    }
    rows: list[dict[str, Any]] = []
    covered_keys: set[str] = set()
    covered_dimensions: dict[str, set[tuple[str, str]]] = {}
    for position, raw in enumerate(surfaces):
        if not isinstance(raw, dict) or raw.get("in_run_scope") is False:
            continue
        surface = dict(raw)
        surface_id = str(surface.get("surface_id") or _digest("surface", surface))
        progress = progress_by_id.get(surface_id)
        cause, terminal, action = _cell_cause(surface, progress)
        method = str(surface.get("method") or "").upper()
        endpoint = _endpoint(surface)
        key = canonical_surface_key({"method": method, "endpoint": endpoint})
        if key:
            covered_keys.add(key)
            params = _strings(surface.get("param") or surface.get("params")) or [""]
            roles = _strings(
                surface.get("roles") or surface.get("role")
                or surface.get("actor_role") or surface.get("role_scope")) or [""]
            covered_dimensions.setdefault(key, set()).update(
                (param, role) for param in params for role in roles)
        refs = _evidence_from_progress(progress or {})
        for ref in _strings(surface.get("evidence_refs") or surface.get("evidence_ref")):
            if ref not in refs:
                refs.append(ref)
        rows.append({
            "attribution_id": _digest("attribution", {
                "kind": "cell", "surface_id": surface_id, "position": position,
            }),
            "kind": "cell",
            "surface_id": surface_id,
            "feature_id": str(surface.get("feature_id") or ""),
            "threat_id": str(surface.get("threat_id") or ""),
            "method": method,
            "endpoint": endpoint,
            "param": str(surface.get("param") or ""),
            "roles": _strings(
                surface.get("roles") or surface.get("role")
                or surface.get("actor_role") or surface.get("role_scope")),
            "vuln_class": str(
                surface.get("vuln_class") or surface.get("legacy_vuln") or ""),
            "ledger_status": str(surface.get("status") or "not_tested").lower(),
            "execution_status": str((progress or {}).get("execution_status") or ""),
            "cause_code": cause,
            "terminal": terminal,
            "next_action": action,
            "evidence_refs": refs,
        })

    for position, item in enumerate(inventory_rows):
        method, endpoint = _method(item), _endpoint(item)
        key = canonical_surface_key({"method": method, "endpoint": endpoint})
        row = item if isinstance(item, dict) else {}
        cause = "planning_unassigned" if method else "method_unresolved"
        params = _strings(row.get("params") or row.get("param")) or [""]
        roles = _strings(
            row.get("roles") or row.get("role")
            or row.get("actor_role") or row.get("role_scope")) or [""]
        dimensions = covered_dimensions.get(key, set()) if key else set()
        for param in params:
            for role in roles:
                covered = bool(key and key in covered_keys and any(
                    (not param or covered_param == param)
                    and (not role or covered_role == role)
                    for covered_param, covered_role in dimensions
                ))
                if covered:
                    continue
                rows.append({
                    "attribution_id": _digest("attribution", {
                        "kind": "inventory", "method": method,
                        "endpoint": endpoint, "param": param, "role": role,
                        "position": position,
                    }),
                    "kind": "inventory",
                    "method": method,
                    "endpoint": endpoint,
                    "param": param,
                    "params": [param] if param else [],
                    "roles": [role] if role else [],
                    "vuln_class": "",
                    "cause_code": cause,
                    "terminal": False,
                    "next_action": _ACTION[cause],
                    "evidence_refs": _strings(
                        row.get("evidence_refs") or row.get("source_file")),
                })

    for position, item in enumerate(unresolved_rows):
        row = item if isinstance(item, dict) else {}
        rows.append({
            "attribution_id": _digest("attribution", {
                "kind": "unresolved", "endpoint": _endpoint(item), "position": position,
            }),
            "kind": "unresolved",
            "method": _method(item),
            "endpoint": _endpoint(item),
            "params": _strings(row.get("params") or row.get("param")),
            "roles": _strings(row.get("roles") or row.get("role")),
            "vuln_class": "",
            "cause_code": "method_unresolved",
            "terminal": False,
            "next_action": _ACTION["method_unresolved"],
            "evidence_refs": _strings(row.get("evidence_refs") or row.get("source_file")),
        })

    for position, item in enumerate(projection.get("backlog") or []):
        if not isinstance(item, dict):
            continue
        rows.append({
            "attribution_id": _digest("attribution", {
                "kind": "discovery", "item": item, "position": position,
            }),
            "kind": "discovery",
            "surface_id": str(item.get("source_surface_id") or ""),
            "method": str(item.get("method") or "").upper(),
            "endpoint": _endpoint(item),
            "params": _strings(item.get("params") or item.get("param")),
            "roles": [],
            "vuln_class": "",
            "cause_code": "discovery_next_run",
            "terminal": False,
            "next_action": _ACTION["discovery_next_run"],
            "evidence_refs": _strings(item.get("source_evidence_refs")),
        })

    # Finding and cell are different frozen objects.  Even when a rejected
    # Finding reopens its exact execution cell, retain one attribution for the
    # proof package itself so multiple rejected packages cannot collapse into
    # one surface-level repair signal.
    for position, item in enumerate(rejected_findings):
        if not isinstance(item, dict):
            continue
        rows.append({
            "attribution_id": _digest("attribution", {
                "kind": "finding", "id": item.get("id"), "position": position,
            }),
            "kind": "finding",
            "finding_id": str(item.get("id") or ""),
            "feature_id": str(item.get("feature_id") or ""),
            "threat_id": str(item.get("threat_id") or ""),
            "method": str(item.get("method") or "").upper(),
            "endpoint": _endpoint(item),
            "params": _strings(item.get("params") or item.get("param")),
            "roles": _strings(item.get("roles") or item.get("role")),
            "vuln_class": str(item.get("vuln_class") or ""),
            "cause_code": "proof_rejected",
            "terminal": False,
            "next_action": _ACTION["proof_rejected"],
            "evidence_refs": _strings(item.get("path")),
            "reasons": _strings(item.get("reasons")),
        })

    unexplained = [row for row in rows if row.get("cause_code") == "state_unsupported"]
    continuations: dict[str, dict[str, Any]] = {}
    for row in rows:
        item = _continuation(row)
        if item is not None:
            continuations.setdefault(str(item["intent_id"]), item)
    cause_counts: dict[str, int] = {}
    for row in rows:
        cause = str(row.get("cause_code") or "state_unsupported")
        cause_counts[cause] = cause_counts.get(cause, 0) + 1
    result = {
        "schema_version": OUTCOME_CONTRACT_VERSION,
        "outcome_contract_version": OUTCOME_CONTRACT_VERSION,
        "complete": not unexplained,
        "total_objects": len(rows),
        "attributed_objects": len(rows) - len(unexplained),
        "unexplained_objects": len(unexplained),
        "terminal_objects": sum(1 for row in rows if row.get("terminal")),
        "open_objects": sum(1 for row in rows if not row.get("terminal")),
        "cause_counts": dict(sorted(cause_counts.items())),
        "rows": rows,
        "continuations": list(continuations.values()),
    }
    result["attribution_sha256"] = _sha256(result)
    return result


def build_next_run_agenda(attribution: dict[str, Any]) -> dict[str, Any]:
    """Render the bounded model-independent continuation queue."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    items = [
        dict(item) for item in attribution.get("continuations") or []
        if isinstance(item, dict)
    ]
    items.sort(key=lambda item: (
        order.get(str(item.get("priority") or "low"), 9),
        str(item.get("intent_id") or ""),
    ))
    return {
        "schema_version": OUTCOME_CONTRACT_VERSION,
        "outcome_contract_version": OUTCOME_CONTRACT_VERSION,
        "source_attribution_sha256": str(
            attribution.get("attribution_sha256") or ""),
        "status": "ready" if items else "no_work",
        "count": len(items),
        "items": items,
    }


__all__ = [
    "OUTCOME_CONTRACT_VERSION",
    "build_miss_attribution",
    "build_next_run_agenda",
]
