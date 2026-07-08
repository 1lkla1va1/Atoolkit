"""Run Scheduler for Atoolkit v8.6.

Determines what surfaces to test and in what order, based on blackboard
history, business graph priorities, and domain scope.
"""

from __future__ import annotations

import json
import pathlib

_PRIORITY_SCORE = {"high": 0, "medium": 1, "low": 2}


# -- Internal helpers -------------------------------------------------------

def _endpoints_in_blackboard(bb: dict) -> set[str]:
    """Return the set of endpoint strings already recorded in the blackboard."""
    eps: set[str] = set()
    for fact in bb.get("facts", []):
        if ep := fact.get("endpoint", ""):
            eps.add(ep)
    for neg in bb.get("negatives", []):
        if ep := neg.get("endpoint", ""):
            eps.add(ep)
    for ep in bb.get("discovered_endpoints", []):
        eps.add(ep if isinstance(ep, str) else ep.get("endpoint", ""))
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
        tested_count = sum(1 for s in steps if s.get("endpoint", "") in tested)
        if 0 < tested_count < len(steps):
            for s in steps:
                ep = s.get("endpoint", "")
                if ep and ep not in tested and ep not in needed:
                    needed.append(ep)
    return needed

def _shallow_negatives(bb: dict) -> list[str]:
    """Endpoints from negatives where depth_sufficient=False."""
    result: list[str] = []
    for neg in bb.get("negatives", []):
        if not neg.get("depth_sufficient", True):
            ep = neg.get("endpoint", "")
            if ep and ep not in result:
                result.append(ep)
    return result

def _carryover_intents(bb: dict) -> list[dict]:
    """High-priority pending intents to carry into the next run."""
    return [{"intent_id": i.get("intent_id", ""), "priority": i.get("priority", "high")}
            for i in bb.get("intents", [])
            if i.get("status") == "pending" and i.get("priority") == "high"]

# -- Core scheduling function -----------------------------------------------

def compute_run_scope(
    blackboard: dict,
    business_graph: dict,
    inventory: list[str],
    target_domains: list[str],
    surface_budget: int = 80,
    intent_budget: int = 15,
) -> dict:
    """Compute the run scope: which surfaces to test and in what order.

    Domain scope is ADVISORY -- target-domain surfaces sort first, but
    cross-domain surfaces are never dropped, just deprioritized.
    """
    bb = blackboard or {}
    bg = business_graph or {}
    target_domains = target_domains or []
    known_eps = _endpoints_in_blackboard(bb)

    # Normalize inventory: accept both strings and dicts
    inv_eps = []
    for item in (inventory or []):
        if isinstance(item, dict):
            inv_eps.append(item.get("endpoint", ""))
        else:
            inv_eps.append(str(item))

    # Tier 1: high-priority pending intents (carried over)
    carryover = _carryover_intents(bb)
    # Tier 2: high-value target-domain surfaces
    biz_surfaces = _high_value_endpoints(bg, target_domains)
    # Tier 3: flow completion surfaces
    flow_surfaces = _flow_completion_endpoints(bg, bb)
    # Tier 4: shallow negatives with signal
    shallow_negs = _shallow_negatives(bb)
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
        "surface_budget": surface_budget,
        "intent_budget": intent_budget,
        "must_test": must_test,
        "carryover_intents": carryover[:intent_budget],
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
