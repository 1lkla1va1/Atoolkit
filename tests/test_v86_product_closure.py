"""Behavior-level acceptance tests for the v8.6 product closure contract."""
from __future__ import annotations

import json

from engine.business_graph import BusinessGraph
from engine.graph import FactIntentGraph, merge_run_to_blackboard
from engine.orchestrator import (
    CognitiveState, NEGATIVE_WITH_EVIDENCE, SKIPPED,
    _apply_blackboard_skips, _build_project_coverage, _parse_negative, run_session,
)
from engine.scheduler import compute_run_scope, select_target_domains
from run import safe_project_slug


def _auth_graph() -> FactIntentGraph:
    graph = FactIntentGraph()
    graph.add_fact({
        "source_type": "confirmed",
        "endpoint": "/api/login",
        "method": "POST",
        "vuln_class": "auth-bypass",
        "summary": "login bypass",
        "chain_feasible": True,
    })
    return graph


def test_post_surface_budget_uses_inventory_method():
    inventory = [{"endpoint": "/api/refund", "method": "POST"}]
    bg = BusinessGraph()
    bg.build_from_inventory(inventory)
    scope = compute_run_scope(
        {}, bg.export_dict(), inventory, ["txn"],
        surface_budget=1, intent_budget=1, vuln_classes=["SQLi"],
    )
    state = CognitiveState("s", "https://t.example", vuln_classes=["SQLi"])
    state.seed_matrix(inventory)
    state.set_budget(set(scope["must_test_cells"]))

    ok, reason = state.set_cell(
        "/api/refund", "SQLi", NEGATIVE_WITH_EVIDENCE, evidence="negative.md"
    )
    assert ok, reason
    assert state.ignored_by_budget == 0


def test_same_path_different_methods_are_distinct_and_bare_lookup_is_ambiguous():
    state = CognitiveState("s", "https://t.example", vuln_classes=["SQLi"])
    state.seed_matrix(["GET /api/refund", "POST /api/refund"])
    assert len(state.matrix) == 2
    assert state._find_cell("GET /api/refund", "SQLi")["method"] == "GET"
    assert state._find_cell("POST /api/refund", "SQLi")["method"] == "POST"
    assert state._find_cell("/api/refund", "SQLi") is None


def test_surface_budget_counts_surfaces_not_cells():
    inventory = ["GET /api/login", "POST /api/refund", "GET /api/products"]
    bg = BusinessGraph()
    bg.build_from_inventory(inventory)
    scope = compute_run_scope(
        {}, bg.export_dict(), inventory, ["auth", "txn"],
        surface_budget=2, intent_budget=1, vuln_classes=["SQLi", "XSS", "IDOR"],
    )
    assert scope["budget_unit"] == "surface"
    assert len(scope["must_test"]) == 2
    assert len(scope["must_test_cells"]) == 6


def test_scheduler_never_spends_budget_on_absent_inventory_surface():
    inventory = ["GET /api/current"]
    graph = {"endpoint_map": {
        "POST /api/historical-refund": {"domains": ["txn"], "value": "high"},
        "GET /api/current": {"domains": ["info"], "value": "low"},
    }}
    scope = compute_run_scope(
        {}, graph, inventory, ["txn"], surface_budget=1, intent_budget=0,
    )
    assert scope["must_test"] == ["GET /api/current"]


def test_intent_budget_zero_means_unlimited():
    bb = {"intents": [
        {"intent_id": f"i{n}", "status": "pending", "priority": "high"}
        for n in range(4)
    ]}
    scope = compute_run_scope(bb, {}, [], [], surface_budget=0, intent_budget=0)
    assert len(scope["carryover_intents"]) == 4


def test_blackboard_accepts_default_session_ids_and_preserves_links(tmp_path):
    path = tmp_path / "blackboard.json"
    first = _auth_graph()
    merge_run_to_blackboard(str(path), first, "sess-20260710-120000")
    after_first = json.loads(path.read_text(encoding="utf-8"))
    assert after_first["intents"][0]["source_fact_id"] == after_first["facts"][0]["fact_id"]

    second = FactIntentGraph()
    second.import_from_blackboard(after_first)
    second.add_fact({
        "source_type": "confirmed",
        "endpoint": "/api/search",
        "method": "GET",
        "vuln_class": "sqli",
        "summary": "search injection",
    })
    merged = merge_run_to_blackboard(str(path), second, "sess-20260710-130000")
    assert merged["total_runs"] == 2
    assert len(merged["facts"]) == 2


def test_blackboard_persists_structured_intent_outcome(tmp_path):
    path = tmp_path / "blackboard.json"
    merge_run_to_blackboard(str(path), _auth_graph(), "run_001")
    stored = json.loads(path.read_text(encoding="utf-8"))

    graph = FactIntentGraph()
    graph.import_from_blackboard(stored)
    intent_id = graph.intents[0]["intent_id"]
    graph.claim_intent(intent_id)
    graph.resolve_intent(
        intent_id, "deferred", summary="no signal",
        reason="no_observable_signal", attempts=3,
    )
    merged = merge_run_to_blackboard(str(path), graph, "run_002")
    intent = merged["intents"][0]
    assert intent["status"] == "deferred"
    assert intent["attempts"] == 3
    assert intent["defer_reason"] == "no_observable_signal"
    assert intent["resolved_at"]


def test_target_domains_do_not_delete_business_graph_domains():
    bg = BusinessGraph()
    bg.build_from_inventory(["GET /api/user_id/refund"], target_domains=["txn"])
    assert set(bg.endpoint_map["GET /api/user_id/refund"]["domains"]) == {"txn", "idor"}


def test_negative_record_preserves_method():
    parsed = _parse_negative(
        """endpoint: /api/refund
method: POST
vuln: SQLi
vectors:
  - boolean
  - error
  - time

curl response status
""",
        "negative.md",
    )
    assert parsed["method"] == "POST"


def test_run_session_never_leaves_claimed_intent(tmp_path):
    project = tmp_path / "target"
    workdir = project / "sessions" / "sess-second"
    workdir.mkdir(parents=True)
    merge_run_to_blackboard(
        str(project / "blackboard.json"), _auth_graph(), "sess-first"
    )

    class NoSignalAdapter:
        name = "no-signal"

        def run(self, prompt, *, session_id):
            yield "No new fact was produced in this attempt.\n"

    run_session(
        NoSignalAdapter(), target="https://t.example", authz="demo",
        core_skill="test", workdir=str(workdir), authorized_hosts=["t.example"],
        endpoints=["GET /api/health"], vuln_classes=["SQLi"],
        max_turns=4, intent_budget=1, verbose=False,
    )
    blackboard = json.loads((project / "blackboard.json").read_text(encoding="utf-8"))
    statuses = [intent.get("status") for intent in blackboard["intents"]]
    assert "claimed" not in statuses
    assert statuses == ["deferred"]
    assert blackboard["intents"][0]["attempts"] == 3
    assert blackboard["intents"][0]["defer_reason"] == "no_observable_signal"


def test_dynamic_surface_receives_inherited_deep_negative():
    state = CognitiveState("s", "https://t.example", vuln_classes=["SQLi"])
    state.seed_matrix(["GET /api/base"])
    inherited = [{
        "endpoint": "/api/later", "method": "GET", "vuln_class": "SQLi",
        "reason": "depth-sufficient negative from prior run",
    }]
    assert _apply_blackboard_skips(state, inherited) == 0

    state.seed_matrix(["GET /api/later"])
    assert _apply_blackboard_skips(state, inherited) == 1
    cell = state._find_cell("GET /api/later", "SQLi")
    assert cell and cell["state"] == SKIPPED


def test_domain_coverage_uses_canonical_keys_and_is_cumulative():
    bg = BusinessGraph()
    bg.build_from_inventory(["POST /api/refund", "GET /api/login"])
    prior = {
        "GET /api/login": {
            "domains": ["auth"], "value": "medium", "tested": True,
        }
    }
    domains, index = _build_project_coverage(bg, [{
        "endpoint": "/api/refund", "method": "POST", "status": "not_vulnerable",
    }], prior)
    assert index["POST /api/refund"]["tested"] is True
    assert index["POST /api/refund"]["value"] == "high"
    assert domains["auth"]["tested"] == 1
    assert domains["txn"]["tested"] == 1


def test_scheduler_advances_to_uncovered_domains():
    bb = {"domains_covered": {
        "auth": {"tested": 3, "total": 3},
        "txn": {"tested": 2, "total": 2},
    }}
    assert select_target_domains(bb) == ["idor", "input"]


def test_project_slug_cannot_escape_runs_directory():
    slug = safe_project_slug("../../outside target")
    assert "/" not in slug and "\\" not in slug
    assert slug not in {"", ".", ".."}
