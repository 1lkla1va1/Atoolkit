"""Behavior-level acceptance tests for the v8.6 product closure contract."""
from __future__ import annotations

import json

from engine.business_graph import BusinessGraph
from engine.graph import FactIntentGraph, merge_run_to_blackboard, normalize_blackboard_schema
from engine.orchestrator import (
    CognitiveState, NEGATIVE_WITH_EVIDENCE, SKIPPED,
    _apply_blackboard_skips, _build_project_coverage, _parse_negative,
    _sync_candidate_facts, _sync_coverage_ledger, run_session,
)
from engine.candidate import (CandidateLedger, compute_depth_score,
                              make_candidate, top_work_queue)
from engine.scheduler import compute_run_scope, select_target_domains
from engine.session_gate import evaluate_session_gate
from run import (_inventory_records_from_endpoint_arg, _summary_findings,
                 safe_project_slug)


def _auth_graph() -> FactIntentGraph:
    graph = FactIntentGraph()
    graph.add_fact({
        "source_type": "confirmed",
        "endpoint": "/api/login",
        "method": "POST",
        "vuln_class": "auth-bypass",
        "summary": "login bypass",
        "chain_feasible": True,
        "proof_status": "confirmed",
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


def test_cli_endpoint_inventory_splits_embedded_methods():
    endpoints, records = _inventory_records_from_endpoint_arg(
        "POST /api/x,GET /api/x"
    )
    assert endpoints == ["POST /api/x", "GET /api/x"]
    assert records == [
        {**records[0], "endpoint": "/api/x", "method": "POST"},
        {**records[1], "endpoint": "/api/x", "method": "GET"},
    ]


def test_surface_budget_closes_all_cells_on_selected_surface(tmp_path):
    class OneCellPerTurn:
        name = "one-cell"

        def __init__(self):
            self.calls = 0

        def run(self, prompt, *, session_id):
            self.calls += 1
            vuln = "SQLi" if self.calls == 1 else "XSS"
            yield f"CELL: /api/only | {vuln} | SKIP | fixture not applicable\nLOW_ROI\n"

    adapter = OneCellPerTurn()
    out = run_session(
        adapter,
        target="https://t.example",
        authz="demo",
        core_skill="test",
        workdir=str(tmp_path / "project" / "sessions" / "run1"),
        authorized_hosts=["t.example"],
        endpoints=["GET /api/only", "GET /api/out-of-budget"],
        vuln_classes=["SQLi", "XSS"],
        surface_budget=1,
        max_turns=3,
        verbose=False,
    )
    selected = [
        cell for cell in out["state"]["matrix"].values()
        if cell["endpoint"] == "/api/only"
    ]
    assert adapter.calls == 2
    assert len(selected) == 2
    assert all(cell["state"] == "skipped" for cell in selected)
    stats = out["coverage_ledger"]["stats"]
    assert stats["in_scope_closed"] == stats["in_scope_total"] == 2
    assert stats["out_of_run"] == 2
    assert out["status"] == "incomplete"


def test_same_path_different_methods_are_distinct_and_bare_lookup_is_ambiguous():
    state = CognitiveState("s", "https://t.example", vuln_classes=["SQLi"])
    state.seed_matrix(["GET /api/refund", "POST /api/refund"])
    assert len(state.matrix) == 2
    assert state._find_cell("GET /api/refund", "SQLi")["method"] == "GET"
    assert state._find_cell("POST /api/refund", "SQLi")["method"] == "POST"
    assert state._find_cell("/api/refund", "SQLi") is None


def test_same_method_path_keeps_each_parameter_as_an_independent_cell():
    inventory = [{
        "endpoint": "/api/create-order", "method": "POST",
        "params": ["quantity", "use_points", "order_time"],
    }]
    state = CognitiveState("s", "https://t.example", vuln_classes=["业务逻辑"])
    state.seed_matrix(inventory)
    assert len(state.matrix) == 3
    assert state._find_cell("POST /api/create-order", "业务逻辑") is None
    ok, reason = state.set_cell(
        "POST /api/create-order", "业务逻辑", "positive",
        evidence="finding.json", param="use_points",
    )
    assert ok, reason
    assert state._find_cell(
        "POST /api/create-order", "业务逻辑", param="use_points")["state"] == "positive"
    assert state._find_cell(
        "POST /api/create-order", "业务逻辑", param="quantity")["state"] == "untested"

    bg = BusinessGraph()
    bg.build_from_inventory(inventory)
    scope = compute_run_scope(
        {}, bg.export_dict(), inventory, ["txn"], surface_budget=1,
        intent_budget=1, vuln_classes=["业务逻辑"],
    )
    assert len(scope["must_test_cells"]) == 3


def test_resume_keeps_each_parameter_cell_independent(tmp_path):
    state = CognitiveState("s", "https://t.example", vuln_classes=["业务逻辑"])
    state.seed_matrix([{
        "endpoint": "/api/create-order", "method": "POST",
        "params": ["quantity", "use_points"],
        "risk_tags": ["business-logic"],
    }])
    path = tmp_path / "state.json"
    state.save(path)

    loaded = CognitiveState.load(path)
    assert len(loaded.matrix) == 2
    assert loaded._find_cell(
        "POST /api/create-order", "业务逻辑", param="quantity") is not None
    assert loaded._find_cell(
        "POST /api/create-order", "业务逻辑", param="use_points") is not None


def test_new_high_value_roots_rank_before_old_spread_work():
    old = make_candidate(
        surface_id="old", endpoint="/api/orders", vuln_class="idor",
        hypothesis="old confirmed", status="confirmed",
    )
    old["candidate_id"] = "old"
    old["status"] = "confirmed"
    auth = make_candidate(
        surface_id="auth", endpoint="/api/login", vuln_class="auth-bypass",
        hypothesis="new auth root",
    )
    auth["candidate_id"] = "auth"
    idor = make_candidate(
        surface_id="idor", endpoint="/api/profile", vuln_class="idor",
        hypothesis="new idor root",
    )
    idor["candidate_id"] = "idor"
    assert [c["candidate_id"] for c in top_work_queue([old, idor, auth])] == [
        "auth", "idor", "old"
    ]


def test_spread_text_without_independent_evidence_gets_no_depth_credit():
    candidate = make_candidate(
        surface_id="s", endpoint="/api/orders", vuln_class="idor",
        hypothesis="candidate",
    )
    candidate["candidate_id"] = "cand_001"
    candidate["status"] = "confirmed"
    ledger = CandidateLedger([candidate])
    ledger.apply("SPREAD: cand_001 | missing ownership check | /api/refund", turn=2)
    assert candidate.get("root_cause_spread_done") is False
    assert candidate.get("spread_requested") is True
    assert compute_depth_score(candidate, ledger.candidates) == 0


def test_structured_finding_closes_only_its_method():
    state = CognitiveState("s", "https://t.example", vuln_classes=["IDOR"])
    state.seed_matrix(["GET /api/item", "POST /api/item"])
    state.update("", {
        "files": ["finding.json"],
        "normalized_findings": [{
            "endpoint": "/api/item", "method": "POST", "methods": ["POST"],
            "vuln_class": "IDOR", "evidence_file": "finding.json",
        }],
    })
    assert state._find_cell("POST /api/item", "IDOR")["state"] == "positive"
    assert state._find_cell("GET /api/item", "IDOR")["state"] == "untested"


def test_negative_closes_only_its_method():
    state = CognitiveState("s", "https://t.example", vuln_classes=["SQLi"])
    state.seed_matrix(["GET /api/item", "POST /api/item"])
    neg = {
        "endpoint": "/api/item", "method": "POST", "vuln": "SQLi",
        "reason": "deep negative", "file": "negative.md",
        "vectors": ["boolean", "error", "time"], "response_count": 1,
        "evidence_types": [], "identities": [], "roles": [],
    }
    state.update("", {"files": ["negative.md"], "negatives": [neg]})
    assert state._find_cell("POST /api/item", "SQLi")["state"] == NEGATIVE_WITH_EVIDENCE
    assert state._find_cell("GET /api/item", "SQLi")["state"] == "untested"


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
        "proof_status": "confirmed",
    })
    merged = merge_run_to_blackboard(str(path), second, "sess-20260710-130000")
    assert merged["total_runs"] == 2
    assert len(merged["facts"]) == 2


def test_legacy_skillmode_blackboard_migrates_without_trusting_shallow_proof():
    legacy = {
        "schema_version": "1.0", "runs_completed": 2,
        "confirmed_facts": [{
            "id": "finding_001", "run": 1, "endpoint": "POST /api/refund",
            "type": "amount-tamper", "domain": "txn",
        }],
        "depth_negatives": [{
            "id": "NF-001", "run": 1, "surface": "GET /api/search",
        }],
        "pending_intents": [{"description": "follow up", "priority": "high"}],
    }
    migrated = normalize_blackboard_schema(legacy)
    assert migrated["schema_version"] == "2.0"
    assert migrated["facts"][0]["method"] == "POST"
    assert migrated["facts"][0]["endpoint"] == "/api/refund"
    assert migrated["facts"][0]["source_type"] == "legacy_unvalidated"
    assert migrated["facts"][0]["proof_status"] == "untrusted_legacy"
    assert migrated["intents"][0]["status"] == "pending"
    assert migrated["negatives"][0]["depth_sufficient"] is False

    graph = FactIntentGraph()
    skips = graph.import_from_blackboard(legacy)
    assert len(graph.facts) == 1
    assert len(graph.intents) == 2
    assert any(intent.get("source") == "revalidation" for intent in graph.intents)
    assert skips == []


def test_blackboard_merge_is_idempotent_per_run_id(tmp_path):
    path = tmp_path / "blackboard.json"
    graph = _auth_graph()
    first = merge_run_to_blackboard(str(path), graph, "sess-same")
    second = merge_run_to_blackboard(str(path), graph, "sess-same")
    assert first["total_runs"] == second["total_runs"] == 1
    assert second["merged_run_ids"] == ["sess-same"]


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


def test_refuted_candidate_can_upgrade_to_confirmed_fact():
    graph = FactIntentGraph()
    biz = BusinessGraph()
    candidate = {
        "candidate_id": "cand_001", "endpoint": "/api/orders/1", "method": "GET",
        "param": "id", "vuln_class": "idor", "hypothesis": "order IDOR",
        "status": "refuted", "evidence_refs": ["negative.md"],
        "chain_assessment": {},
    }
    ledger = CandidateLedger(candidates=[candidate])
    assert _sync_candidate_facts(ledger, graph, biz) == 1
    assert [f["source_type"] for f in graph.facts] == ["negative"]

    candidate["status"] = "confirmed"
    candidate["evidence_refs"] = ["finding.json"]
    assert _sync_candidate_facts(ledger, graph, biz) == 0
    assert not any(f["source_type"] == "confirmed" for f in graph.facts)
    candidate["proof_status"] = "confirmed"
    assert _sync_candidate_facts(ledger, graph, biz) == 1
    assert any(f["source_type"] == "confirmed" for f in graph.facts)
    assert graph.facts[0].get("superseded_by_fact_id")
    assert graph.get_pending_intents(limit=10)


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


def test_negative_depth_requires_vectors_and_response_evidence():
    no_response = _parse_negative(
        """endpoint: /api/search
method: GET
vuln: SQLi
vectors: boolean, error, time

Only a prose conclusion, with no response packet.
""",
        "negative.md",
    )
    assert no_response["vectors_tried"] == 3
    assert no_response["response_count"] == 0
    assert no_response["depth_sufficient"] is False


def test_valid_negative_sets_checked_flag_and_passes_gate(tmp_path):
    state = CognitiveState("s", "https://t.example", vuln_classes=["SQLi"])
    state.seed_matrix(["GET /api/search"])
    neg = _parse_negative(
        """endpoint: /api/search
method: GET
vuln: SQLi
vectors: boolean, error, time
evidence_types: response_diff

HTTP/1.1 200 OK
响应内容与基线一致
""",
        "negative_search.md",
    )
    state.update("", {"files": ["negative_search.md"], "negatives": [neg]})
    ledger = _sync_coverage_ledger(state, tmp_path)
    assert ledger.surfaces[0]["status"] == "not_vulnerable"
    assert ledger.surfaces[0]["negative_depth_checked"] is True
    assert evaluate_session_gate(ledger)["result"] == "pass"


def test_repeated_no_evidence_chain_intent_is_deferred(tmp_path):
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
    assert blackboard["intents"][0]["attempts"] == 0
    assert blackboard["intents"][0]["dispatches"] == 2


def test_intent_budget_limits_unique_claims_for_whole_run(tmp_path):
    project = tmp_path / "target"
    workdir = project / "sessions" / "sess-second"
    workdir.mkdir(parents=True)
    graph = _auth_graph()
    # Add a second, distinct pending Intent.
    graph.add_fact({
        "source_type": "confirmed", "endpoint": "/api/search", "method": "GET",
        "vuln_class": "sqli", "summary": "search injection",
        "proof_status": "confirmed",
    })
    merge_run_to_blackboard(str(project / "blackboard.json"), graph, "sess-first")

    class NoSignalAdapter:
        name = "no-signal"

        def run(self, prompt, *, session_id):
            yield "No new physical evidence.\n"

    out = run_session(
        NoSignalAdapter(), target="https://t.example", authz="demo",
        core_skill="test", workdir=str(workdir), authorized_hosts=["t.example"],
        endpoints=["GET /api/health"], vuln_classes=["SQLi"],
        max_turns=4, intent_budget=1, verbose=False,
    )
    assert out["scheduler_stats"]["claimed_intents_this_run"] == 1
    blackboard = json.loads((project / "blackboard.json").read_text(encoding="utf-8"))
    assert sum(intent.get("status") == "deferred" for intent in blackboard["intents"]) == 1
    assert sum(intent.get("status") == "pending" for intent in blackboard["intents"]) >= 1
    assert sum(int(intent.get("attempts", 0) or 0) for intent in blackboard["intents"]) == 0


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
    assert cell and cell["state"] == NEGATIVE_WITH_EVIDENCE
    assert cell["negative_depth_checked"] is True


def test_inherited_deep_negative_remains_not_vulnerable_in_ledger(tmp_path):
    state = CognitiveState("s", "https://t.example", vuln_classes=["SQLi"])
    state.seed_matrix(["GET /api/search"])
    inherited = [{
        "endpoint": "/api/search", "method": "GET", "vuln_class": "SQLi",
        "status": "not_vulnerable", "negative_depth_checked": True,
        "reason": "depth-sufficient negative from prior run",
    }]
    assert _apply_blackboard_skips(state, inherited) == 1
    ledger = _sync_coverage_ledger(state, tmp_path)
    assert ledger.surfaces[0]["status"] == "not_vulnerable"
    assert ledger.surfaces[0]["negative_depth_checked"] is True


def test_inherited_dead_end_is_not_applicable():
    state = CognitiveState("s", "https://t.example", vuln_classes=["SQLi", "XSS"])
    state.seed_matrix(["GET /api/removed"])
    inherited = [{
        "endpoint": "/api/removed", "method": "GET", "status": "not_applicable",
        "reason": "dead end: endpoint removed",
    }]
    assert _apply_blackboard_skips(state, inherited) == 2
    assert {cell["state"] for cell in state.matrix.values()} == {SKIPPED}


def test_ledger_keeps_one_row_per_vulnerability_cell(tmp_path):
    state = CognitiveState(
        "s", "https://t.example", vuln_classes=["命令执行/RCE", "CSRF"]
    )
    state.seed_matrix(["GET /api/orders/{id}"])
    evidence = tmp_path / "finding.json"
    evidence.write_text('{"confirmed": true}', encoding="utf-8")
    ok, reason = state.set_cell(
        "GET /api/orders/{id}", "命令执行/RCE", "positive",
        evidence=str(evidence),
    )
    assert ok, reason
    ledger = _sync_coverage_ledger(state, tmp_path)
    assert len(state.matrix) == 2
    assert len(ledger.surfaces) == 2
    assert {row["vuln_class"] for row in ledger.surfaces} == {"命令执行/RCE", "CSRF"}
    assert sorted(row["status"] for row in ledger.surfaces) == ["confirmed", "not_tested"]
    gate = evaluate_session_gate(ledger, evidence_dir=tmp_path)
    assert gate["result"] == "incomplete"


def test_summary_join_respects_method_and_vulnerability_class(tmp_path):
    ledger_path = tmp_path / "coverage-ledger.json"
    ledger_path.write_text(json.dumps({
        "schema_version": 1,
        "surfaces": [
            {"surface_id": "get", "endpoint": "/api/x", "method": "GET",
             "param": "q", "roles": ["user"], "risk_tags": ["input-validation"],
             "vuln_class": "XSS", "status": "confirmed", "evidence_ref": "get-xss.json"},
            {"surface_id": "post", "endpoint": "/api/x", "method": "POST",
             "param": "id", "roles": ["user"], "risk_tags": ["idor"],
             "vuln_class": "IDOR", "status": "confirmed", "evidence_ref": "post-idor.json"},
        ],
    }), encoding="utf-8")
    rows = _summary_findings({
        "coverage_ledger_path": str(ledger_path),
        "normalized_findings": [{
            "id": "f1", "endpoint": "/api/x", "endpoints": ["/api/x"],
            "method": "POST", "methods": ["POST"], "vuln_class": "IDOR",
            "class": "IDOR", "params": ["id"], "evidence_file": "post-idor.json",
            "acceptance_status": "accepted", "proof_status": "confirmed",
            "claim_kind": "root_finding",
        }],
    })
    assert rows[0]["method"] == "POST"
    assert rows[0]["methods"] == ["POST"]
    assert rows[0]["evidence_file"] == "post-idor.json"


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


def test_domain_coverage_requires_all_cells_on_surface_closed():
    bg = BusinessGraph()
    bg.build_from_inventory(["GET /api/login"])
    prior = {"GET /api/login": {"domains": ["auth"], "tested": True}}
    domains, index = _build_project_coverage(bg, [
        {"endpoint": "/api/login", "method": "GET", "status": "not_vulnerable",
         "vuln_class": "SQLi"},
        {"endpoint": "/api/login", "method": "GET", "status": "not_tested",
         "vuln_class": "Auth bypass"},
    ], prior)
    assert index["GET /api/login"]["tested"] is False
    assert index["GET /api/login"]["cells_closed"] == 1
    assert index["GET /api/login"]["cells_total"] == 2
    assert domains["auth"]["status"] == "not_started"


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
