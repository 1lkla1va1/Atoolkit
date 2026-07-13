"""v8.8 cross-run project truth behavior tests.

These tests exercise public behavior.  They intentionally avoid source-text
assertions so regressions in merge/scheduling semantics are observable.
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from engine.business_graph import BusinessGraph
from engine.project_state import (
    ProjectStateCorrupt,
    ProjectStateStore,
    canonical_project_cell_key,
    finding_fingerprint,
)
from engine.scheduler import compute_run_scope


SCOPE = "https://api.example.test/"


def _store(tmp_path):
    return ProjectStateStore(tmp_path, project_scope=[SCOPE])


def test_project_store_schema_revision_and_run_history_are_idempotent(tmp_path):
    store = _store(tmp_path)
    first = store.commit_run(
        "run-1",
        inventory=[{"asset": SCOPE, "method": "GET", "endpoint": "/api/users"}],
        run_summary={"status": "incomplete", "inventory_delta": 1},
    )
    second = store.commit_run(
        "run-1",
        run_summary={"status": "complete", "inventory_delta": 1},
    )

    assert first["schema_version"] == 1
    assert second["revision"] == first["revision"] + 1
    assert second["merged_run_ids"] == ["run-1"]
    assert list(second["run_history"]) == ["run-1"]
    assert second["run_history"]["run-1"]["status"] == "complete"

    on_disk = json.loads((tmp_path / "project_state.json").read_text(encoding="utf-8"))
    assert on_disk == second


def test_project_store_serializes_two_writers_without_lost_update(tmp_path):
    _store(tmp_path).initialize()

    def commit(run_id, endpoint):
        return _store(tmp_path).commit_run(
            run_id,
            inventory=[{"asset": SCOPE, "method": "GET", "endpoint": endpoint}],
            run_summary={"status": "complete"},
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda args: commit(*args), [
            ("run-a", "/api/a"), ("run-b", "/api/b"),
        ]))

    state = _store(tmp_path).load()
    assert set(state["merged_run_ids"]) == {"run-a", "run-b"}
    assert {entry["path"] for entry in state["inventory"]["surfaces"].values()} == {
        "/api/a", "/api/b",
    }


def test_corrupt_project_state_fails_closed_and_is_not_overwritten(tmp_path):
    path = tmp_path / "project_state.json"
    original = "{ definitely-not-json"
    path.write_text(original, encoding="utf-8")
    store = _store(tmp_path)

    with pytest.raises(ProjectStateCorrupt):
        store.commit_run("run-1", run_summary={"status": "complete"})
    assert path.read_text(encoding="utf-8") == original


def test_asset_and_role_are_part_of_project_cell_identity():
    base = dict(method="GET", path="/api/users/123", param="id", vuln_class="idor")
    user = canonical_project_cell_key(SCOPE, role_scope="user", **base)
    admin = canonical_project_cell_key(SCOPE, role_scope="admin", **base)
    other_asset = canonical_project_cell_key(
        "https://admin.example.test/", role_scope="user", **base)

    assert user != admin
    assert user != other_asset
    assert "https://api.example.test:443" in user


def test_unresolved_inventory_is_preserved_then_promoted_idempotently(tmp_path):
    store = _store(tmp_path)
    unresolved = store.commit_run(
        "run-1",
        inventory=[{"asset": SCOPE, "endpoint": "/api/refund", "source": "model_text"}],
    )
    assert len(unresolved["inventory"]["unresolved"]) == 1
    assert not unresolved["inventory"]["surfaces"]

    promoted = store.commit_run(
        "run-2",
        inventory=[{
            "asset": SCOPE, "method": "POST", "endpoint": "/api/refund",
            "params": ["amount"], "roles": ["user"], "source": "har",
        }],
    )
    assert not promoted["inventory"]["unresolved"]
    assert len(promoted["inventory"]["surfaces"]) == 1
    record = next(iter(promoted["inventory"]["surfaces"].values()))
    assert record["method"] == "POST"
    assert record["params"] == ["amount"]
    assert record["seen_in_runs"] == ["run-1", "run-2"]


def test_confirmed_supersedes_only_same_role_negative(tmp_path):
    store = _store(tmp_path)
    run1 = tmp_path / "sessions" / "run-1"
    run2 = tmp_path / "sessions" / "run-2" / "findings" / "f-1"
    run1.mkdir(parents=True)
    run2.mkdir(parents=True)
    (run1 / "negative.json").write_text("{}", encoding="utf-8")
    (run1 / "admin-negative.json").write_text("{}", encoding="utf-8")
    (run2 / "finding.json").write_text("{}", encoding="utf-8")
    store.commit_run(
        "run-1",
        negatives=[
            {
                "asset": SCOPE, "method": "GET", "endpoint": "/api/orders/{id}",
                "param": "id", "role": "user", "vuln_class": "idor",
                "depth_sufficient": True, "evidence_refs": ["session:run-1/negative.json"],
            },
            {
                "asset": SCOPE, "method": "GET", "endpoint": "/api/orders/{id}",
                "param": "id", "role": "admin", "vuln_class": "idor",
                "depth_sufficient": True, "evidence_refs": ["session:run-1/admin-negative.json"],
            },
        ],
    )
    state = store.commit_run(
        "run-2",
        findings=[{
            "id": "f-1", "acceptance_status": "accepted", "proof_status": "confirmed",
            "claim_kind": "root_finding", "target": f"{SCOPE}api/orders/9001",
            "method": "GET", "params": ["id"], "affected_role": "user",
            "vuln_class": "idor", "proof_files": ["findings/f-1/finding.json"],
        }],
    )

    cells = list(state["cell_registry"].values())
    by_role = {cell["role_scope"]: cell for cell in cells}
    assert by_role["user"]["status"] == "confirmed"
    assert by_role["admin"]["status"] == "not_vulnerable"
    negatives = {item["role_scope"]: item for item in state["negatives"]}
    assert negatives["user"]["status"] == "superseded"
    assert negatives["admin"]["status"] == "active"


def test_finding_fingerprint_is_conservative_and_templates_object_ids():
    common = {
        "asset": SCOPE, "method": "GET", "vuln_class": "idor",
        "params": ["id"], "affected_role": "user",
    }
    first = finding_fingerprint({**common, "endpoint": "/api/orders/1001"})
    same_root = finding_fingerprint({**common, "endpoint": "/api/orders/9876"})
    other_param = finding_fingerprint({
        **common, "endpoint": "/api/orders/1001", "params": ["owner_id"],
    })
    other_role = finding_fingerprint({
        **common, "endpoint": "/api/orders/1001", "affected_role": "admin",
    })

    assert first == same_root
    assert first != other_param
    assert first != other_role


def test_legacy_blackboard_import_is_conservative_and_idempotent(tmp_path):
    legacy = {
        "schema_version": "2.0",
        "facts": [{
            "fact_id": "old-fact", "source_type": "confirmed",
            "proof_status": "confirmed", "method": "GET", "endpoint": "/api/x",
            "vuln_class": "idor", "evidence_refs": ["missing.json"],
        }],
        "intents": [{"intent_id": "old-intent", "status": "pending", "description": "retest"}],
        "negatives": [{"endpoint": "/api/y", "depth_sufficient": True}],
        "dead_ends": [],
        "discovered_endpoints": ["POST /api/refund", "/api/unknown"],
    }
    (tmp_path / "blackboard.json").write_text(json.dumps(legacy), encoding="utf-8")
    store = _store(tmp_path)

    first = store.initialize()
    second = store.load()
    assert first == second
    assert len(second["facts"]) == 1
    assert second["facts"][0]["proof_status"] == "pending"
    assert second["facts"][0]["migration_status"] == "legacy_unvalidated"
    assert len(second["intents"]) >= 1
    assert second["negatives"][0]["depth_sufficient"] is False
    assert second["negatives"][0]["migration_status"] == "legacy_unvalidated"
    assert len(second["inventory"]["surfaces"]) == 1
    assert len(second["inventory"]["unresolved"]) == 1
    assert not second["cell_registry"]


def test_scheduler_excludes_fully_closed_surface_and_puts_intent_target_first():
    bb = {
        "surface_index": {"GET /api/closed": {"tested": True}},
        "facts": [], "negatives": [], "dead_ends": [],
        "intents": [{
            "intent_id": "i-1", "status": "pending", "priority": "high",
            "target_endpoint": "/api/intent", "method": "POST",
        }],
    }
    inventory = ["GET /api/closed", "GET /api/new", "POST /api/intent"]
    graph = {"endpoint_map": {
        "GET /api/closed": {"domains": ["auth"], "value": "high"},
        "GET /api/new": {"domains": ["general"], "value": "low"},
        "POST /api/intent": {"domains": ["txn"], "value": "medium"},
    }}

    scope = compute_run_scope(bb, graph, inventory, ["auth", "txn"], surface_budget=2)
    assert scope["must_test"] == ["POST /api/intent", "GET /api/new"]
    assert "GET /api/closed" not in scope["must_test"]


def test_business_graph_inventory_merge_preserves_observed_metadata():
    graph = BusinessGraph()
    graph.build_from_inventory([{
        "method": "POST", "endpoint": "/api/refund", "params": ["amount"],
        "roles": ["user"], "source": "har", "observed_roles": ["merchant"],
    }])
    graph.update_from_fact({
        "method": "POST", "endpoint": "/api/refund", "params": ["order_id"],
        "vuln_class": "idor", "summary": "confirmed refund ownership bypass",
    })
    graph.build_from_inventory([{
        "method": "POST", "endpoint": "/api/refund", "roles": [], "source": "heuristic",
    }])

    entry = graph.endpoint_map["POST /api/refund"]
    assert "user" in entry["roles"]
    assert "merchant" in entry["observed_roles"]
    assert set(entry["params"]) == {"amount", "order_id"}
    assert entry["last_fact_summary"] == "confirmed refund ownership bypass"
    assert "idor" in entry["confirmed_vuln_classes"]
    assert "idor" not in entry["domains"]


def test_generic_or_incomplete_dead_end_never_closes_project_cell(tmp_path):
    store = _store(tmp_path)
    evidence_dir = tmp_path / "sessions" / "run-1"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "skip.json").write_text("{}", encoding="utf-8")

    state = store.commit_run("run-1", dead_ends=[
        {
            "status": "not_applicable", "reason": "model chose to skip",
            "asset": SCOPE, "method": "GET", "endpoint": "/api/x",
            "param": "", "role_scope": "user", "vuln_class": "xss",
            "evidence_refs": ["skip.json"],
        },
        {
            "status": "not_applicable", "reason_code": "endpoint_removed",
            "refutation": "missing exact role", "asset": SCOPE,
            "method": "GET", "endpoint": "/api/y", "param": "",
            "vuln_class": "xss", "evidence_refs": ["skip.json"],
        },
    ])

    assert state["dead_ends"] == []
    assert state["cell_registry"] == {}
