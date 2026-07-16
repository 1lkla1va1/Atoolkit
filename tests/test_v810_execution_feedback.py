from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from engine.knowledge import load_cards, match_cards, negative_sufficient
from engine.ledger import (
    STATUS_BLOCKED,
    STATUS_EXPLORING,
    STATUS_SHALLOW_NEGATIVE,
    CoverageLedger,
)
from engine.planner import infer_risk_tags, plan_surfaces
from engine.session_gate import evaluate_session_gate
from engine.reporting.validate import validate_run_artifacts
from engine.skill_runtime import (
    DIRECT_QUEUE_LIMIT,
    SkillRuntimeError,
    checkpoint_direct_run,
    initialize_direct_run,
    record_observation,
)
from tests.test_reporting_proof_contract import _idor_fixture
from tests.test_v89_reporting_evidence_binding import _negative_fixture


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def _surface(run_dir: Path, *, param: str, vuln_contains: str, role: str = "") -> dict:
    ledger = CoverageLedger.load(run_dir / "coverage-ledger.json")
    for surface in ledger.surfaces:
        if surface.get("param") != param:
            continue
        if vuln_contains.lower() not in str(surface.get("vuln_class") or "").lower():
            continue
        roles = {str(x).lower() for x in surface.get("roles") or []}
        if role and role.lower() not in roles:
            continue
        return surface
    raise AssertionError((param, vuln_contains, role, ledger.surfaces))


def test_planner_unions_declared_and_deterministic_param_risks():
    tags = infer_risk_tags(
        "product_no",
        "/api/merchant/product-delete.php",
        "product-delete",
        declared_tags=["custom-review"],
        declared_classes=["SQLi"],
    )
    assert {"object-ownership", "idor", "input-validation", "injection"}.issubset(tags)
    assert "custom-review" in tags

    planned = plan_surfaces([{
        "endpoint": "/api/merchant/product-delete.php",
        "method": "POST",
        "params": ["product_no"],
        "roles": ["merchant"],
        "risk_tags": ["sqli", "custom-review"],
    }])
    assert planned
    assert {"sqli", "custom-review", "idor", "input-validation", "injection"}.issubset(
        set(planned[0]["risk_tags"])
    )


def test_knowledge_routing_reads_single_param_risk_tags_and_barriers():
    cards = load_cards()
    surface = {
        "endpoint": "/api/items/remove",
        "method": "POST",
        "param": "product_no",
        "risk_tags": ["idor", "input-validation", "injection"],
        "vuln_class": "SQLi",
    }
    ids = {card["id"] for card in match_cards(surface, cards)}
    assert "input-validation" in ids
    assert "idor-multi-identity" in ids

    blocked = {**surface, "barrier_signals": ["waf_blocked"]}
    ids = {card["id"] for card in match_cards(blocked, cards)}
    assert "waf-bypass" in ids


@pytest.mark.parametrize(
    "signal,preconditions",
    [
        ("waf_blocked", {}),
        ("waf_bypass_exhausted", {}),
        ("session_expired", {"auth_valid": False}),
        ("object_absent", {"object_exists": False}),
        ("empty_dataset", {"data_ready": False}),
        ("format_unresolved", {"request_shape_resolved": False}),
    ],
)
def test_barriers_cannot_be_counted_into_a_deep_negative(signal, preconditions):
    cell = {
        "endpoint": "/api/items/remove",
        "param": "product_no",
        "vuln": "SQLi",
        "risk_tags": ["input-validation", "injection"],
    }
    negative = {
        "vectors": [f"v{i}" for i in range(12)],
        "response_count": 12,
        "evidence_types": [
            "baseline", "boundary_result", "type_result", "per_param_evidence",
            "multi_param_coverage", "multi_payload_family_coverage",
            "second_order_evidence", "blocked_response", "bypass_attempt_1",
            "bypass_attempt_2", "bypass_attempt_3",
        ],
        "identities": ["owner", "peer"],
        "roles": ["merchant"],
        "barrier_signals": [signal],
        "preconditions": preconditions,
    }
    sufficient, missing = negative_sufficient(cell, negative, load_cards())
    assert sufficient is False
    assert any(signal in item for item in missing)


def test_canonical_negative_envelope_with_waf_barrier_cannot_close(tmp_path):
    envelope = _negative_fixture(tmp_path)
    envelope["barrier_signals"] = ["waf_blocked"]
    _write_json(tmp_path / "negative_search.json", envelope)

    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert report["status"] == "incomplete"
    assert "negative_depth_insufficient" in report["closure_gate"]["reasons"]


def test_canonical_negative_derives_explicit_waf_response_barrier(tmp_path):
    envelope = _negative_fixture(tmp_path)
    response = (
        "HTTP/1.1 403 Forbidden\n\n"
        '{"error":"request blocked by WAF","subject":"customer",'
        '"kind":"search-result"}'
    )
    envelope["packets"][0]["response"] = response
    envelope["packets"][0]["response_sha256"] = hashlib.sha256(
        response.encode("utf-8")).hexdigest()
    envelope["packets"][0]["assertions"] = [{
        "target": "response", "relation": "contains", "value": "blocked by WAF",
    }]
    _write_json(tmp_path / "negative_search.json", envelope)

    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert report["status"] == "incomplete"
    assert "negative_depth_insufficient" in report["closure_gate"]["reasons"]


def test_shallow_and_exploring_are_first_class_open_ledger_states(tmp_path):
    ledger = CoverageLedger([
        {
            "surface_id": "shallow", "endpoint": "/api/a", "method": "GET",
            "status": "shallow_negative", "risk_tags": ["input-validation"],
        },
        {
            "surface_id": "exploring", "endpoint": "/api/b", "method": "POST",
            "status": "exploring", "risk_tags": ["idor"],
        },
    ])
    path = tmp_path / "coverage-ledger.json"
    ledger.save(path)
    loaded = CoverageLedger.load(path)

    assert [s["status"] for s in loaded.surfaces] == [
        STATUS_SHALLOW_NEGATIVE, STATUS_EXPLORING,
    ]
    assert loaded.stats()["open"] == 2
    assert len(loaded.next_surfaces()) == 2
    gate = evaluate_session_gate(loaded, evidence_dir=tmp_path, ledger_path=path)
    assert gate["result"] == "incomplete"
    predicates = {item["predicate"] for item in gate["reasons"]}
    assert "shallow_negative_open" in predicates
    assert "exploring_open" in predicates


def test_direct_runtime_routes_waf_negative_to_shallow_and_queue(tmp_path):
    run_dir = tmp_path / "run-waf"
    inventory = tmp_path / "inventory.json"
    _write_json(inventory, {"surfaces": [{
        "endpoint": "/api/merchant/product-delete.php",
        "method": "POST",
        "params": ["product_no"],
        "roles": ["merchant"],
    }]})
    initialized = initialize_direct_run(
        run_dir=run_dir, target="https://t.example/", inventory_path=inventory)
    assert initialized["authority_trusted"] is False
    assert initialized["delivery_eligible"] is False

    surface = _surface(run_dir, param="product_no", vuln_contains="SQLi", role="merchant")
    (run_dir / "evidence" / "blocked.http").parent.mkdir(parents=True)
    (run_dir / "evidence" / "blocked.http").write_text(
        "HTTP/1.1 403 Forbidden\n\nblocked", encoding="utf-8")
    record_observation(run_dir=run_dir, agent_id="input", observation={
        "schema_version": 1,
        "observation_id": "waf-001",
        "surface_id": surface["surface_id"],
        "outcome": "negative",
        "evidence_refs": ["evidence/blocked.http"],
        "negative": {
            "vectors": [f"family-{i}" for i in range(8)],
            "response_count": 8,
            "evidence_types": ["blocked_response"],
            "barrier_signals": ["waf_blocked"],
        },
    })

    checkpoint = checkpoint_direct_run(run_dir)
    current = CoverageLedger.load(run_dir / "coverage-ledger.json").get(surface["surface_id"])
    assert current["status"] == STATUS_SHALLOW_NEGATIVE
    assert "waf-bypass" in current["knowledge_card_ids"]
    assert any(item["surface_id"] == surface["surface_id"]
               for item in checkpoint["execution_queue"])


def test_direct_runtime_accepts_relative_inventory_path(tmp_path, monkeypatch):
    inventory = tmp_path / "relative-inventory.json"
    _write_json(inventory, {"surfaces": [{
        "endpoint": "/api/search", "method": "GET", "params": ["q"],
    }]})
    monkeypatch.chdir(tmp_path)

    initialized = initialize_direct_run(
        run_dir=tmp_path / "run-relative",
        target="https://t.example/",
        inventory_path=Path("relative-inventory.json"),
    )

    assert initialized["coverage"]["total"] > 0
    assert len(initialized["execution_queue"]) <= DIRECT_QUEUE_LIMIT


def test_direct_runtime_turns_empty_object_test_into_recoverable_blocker(tmp_path):
    run_dir = tmp_path / "run-empty"
    inventory = tmp_path / "inventory-empty.json"
    _write_json(inventory, {"surfaces": [{
        "endpoint": "/api/user/balance-records.php",
        "method": "GET",
        "params": ["user_hash"],
        "roles": ["user"],
    }]})
    initialize_direct_run(
        run_dir=run_dir, target="https://t.example/", inventory_path=inventory)
    surface = _surface(run_dir, param="user_hash", vuln_contains="IDOR", role="user")
    evidence = run_dir / "evidence" / "empty.http"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("HTTP/1.1 200 OK\n\n[]", encoding="utf-8")
    record_observation(run_dir=run_dir, agent_id="idor", observation={
        "schema_version": 1,
        "observation_id": "empty-001",
        "surface_id": surface["surface_id"],
        "outcome": "negative",
        "evidence_refs": ["evidence/empty.http"],
        "negative": {
            "vectors": ["owner", "peer", "other-id"],
            "response_count": 3,
            "barrier_signals": ["empty_dataset", "object_absent"],
            "preconditions": {"data_ready": False, "object_exists": False},
        },
    })

    checkpoint_direct_run(run_dir)
    current = CoverageLedger.load(run_dir / "coverage-ledger.json").get(surface["surface_id"])
    assert current["status"] == STATUS_BLOCKED
    assert current["blocker"]["kind"] == "object_absent"
    assert current["blocker"]["recoverable"] is True
    assert any("object" in action.lower() or "data" in action.lower()
               for action in current["next_actions"])


def test_direct_runtime_rejects_escape_and_duplicate_observation_conflict(tmp_path):
    run_dir = tmp_path / "run-safe"
    inventory = tmp_path / "inventory-safe.json"
    _write_json(inventory, {"surfaces": [{
        "endpoint": "/api/search", "method": "GET", "params": ["q"],
    }]})
    initialize_direct_run(
        run_dir=run_dir, target="https://t.example/", inventory_path=inventory)
    surface = _surface(run_dir, param="q", vuln_contains="SQLi")
    outside = tmp_path / "outside.http"
    outside.write_text("HTTP/1.1 200 OK", encoding="utf-8")
    base = {
        "schema_version": 1, "observation_id": "obs-1",
        "surface_id": surface["surface_id"], "outcome": "exploring",
    }
    with pytest.raises(SkillRuntimeError):
        record_observation(
            run_dir=run_dir, agent_id="a",
            observation={**base, "evidence_refs": ["../outside.http"]})

    record_observation(run_dir=run_dir, agent_id="a", observation=base)
    assert record_observation(run_dir=run_dir, agent_id="a", observation=base)["idempotent"] is True
    with pytest.raises(SkillRuntimeError):
        record_observation(
            run_dir=run_dir, agent_id="a",
            observation={**base, "outcome": "blocked", "blocker": "object absent"})


def test_proof_valid_finding_deterministically_overrides_earlier_negative(tmp_path):
    run_dir = tmp_path / "run-proof"
    inventory = tmp_path / "inventory-proof.json"
    _write_json(inventory, {"surfaces": [{
        "endpoint": "/api/orders/{id}", "method": "GET", "params": ["id"],
        "roles": ["unknown"], "risk_tags": ["idor"],
    }]})
    initialize_direct_run(
        run_dir=run_dir, target="https://t.example/", inventory_path=inventory)
    surface = _surface(run_dir, param="id", vuln_contains="IDOR", role="unknown")
    negative_evidence = run_dir / "evidence" / "denied.http"
    negative_evidence.parent.mkdir(parents=True)
    negative_evidence.write_text("HTTP/1.1 403 Forbidden", encoding="utf-8")
    record_observation(run_dir=run_dir, agent_id="idor-a", observation={
        "schema_version": 1, "observation_id": "neg-1",
        "surface_id": surface["surface_id"], "outcome": "negative",
        "evidence_refs": ["evidence/denied.http"],
        "negative": {
            "vectors": ["owner", "peer", "second-object", "write-control"],
            "response_count": 4,
            "evidence_types": [
                "owner_identity", "peer_identity", "object_ownership",
                "access_result", "multi_object_coverage",
            ],
            "identities": ["owner", "peer"], "roles": ["unknown"],
            "preconditions": {
                "auth_valid": True, "object_exists": True,
                "ownership_known": True, "roles_ready": True,
            },
        },
    })
    checkpoint_direct_run(run_dir)

    finding_dir = _idor_fixture(run_dir)
    finding_ref = (finding_dir / "finding.json").relative_to(run_dir).as_posix()
    record_observation(run_dir=run_dir, agent_id="idor-b", observation={
        "schema_version": 1, "observation_id": "pos-1",
        "surface_id": surface["surface_id"], "outcome": "confirmed",
        "evidence_refs": [finding_ref],
    })
    checkpoint = checkpoint_direct_run(run_dir)
    current = CoverageLedger.load(run_dir / "coverage-ledger.json").get(surface["surface_id"])

    assert current["status"] == "confirmed"
    assert current["evidence_ref"] == finding_ref
    assert any(item["surface_id"] == surface["surface_id"]
               and item["resolution"] == "proof_confirmed_overrode_negative"
               for item in checkpoint["conflicts"])


def test_unproven_positive_negative_conflict_stays_exploring(tmp_path):
    run_dir = tmp_path / "run-conflict"
    inventory = tmp_path / "inventory-conflict.json"
    _write_json(inventory, {"surfaces": [{
        "endpoint": "/api/search", "method": "GET", "params": ["q"],
    }]})
    initialize_direct_run(
        run_dir=run_dir, target="https://t.example/", inventory_path=inventory)
    surface = _surface(run_dir, param="q", vuln_contains="SQLi")
    record_observation(run_dir=run_dir, agent_id="a", observation={
        "schema_version": 1, "observation_id": "maybe-pos",
        "surface_id": surface["surface_id"], "outcome": "confirmed",
    })
    record_observation(run_dir=run_dir, agent_id="b", observation={
        "schema_version": 1, "observation_id": "maybe-neg",
        "surface_id": surface["surface_id"], "outcome": "negative",
        "negative": {"vectors": ["one"], "response_count": 0},
    })

    checkpoint = checkpoint_direct_run(run_dir)
    current = CoverageLedger.load(run_dir / "coverage-ledger.json").get(surface["surface_id"])
    assert current["status"] == STATUS_EXPLORING
    assert any(item["surface_id"] == surface["surface_id"]
               and item["resolution"] == "manual_retest_required"
               for item in checkpoint["conflicts"])


def test_markdown_finding_summary_cannot_silently_diverge_from_canonical_truth(tmp_path):
    run_dir = tmp_path / "run-stale-projection"
    inventory = tmp_path / "inventory-stale.json"
    _write_json(inventory, {"surfaces": [{
        "endpoint": "/api/search", "method": "GET", "params": ["q"],
    }]})
    initialize_direct_run(
        run_dir=run_dir, target="https://t.example/", inventory_path=inventory)
    summary = run_dir / "state" / "findings_summary.md"
    summary.parent.mkdir(parents=True, exist_ok=True)
    summary.write_text(
        "| 漏洞名 | 端点 | payload | 严重度 |\n"
        "|---|---|---|---|\n"
        "| stale claim | GET /api/search | q=x | P2 |\n",
        encoding="utf-8",
    )

    checkpoint = checkpoint_direct_run(run_dir)

    assert checkpoint["accepted_findings"] == 0
    assert checkpoint["projection_stale"] is True
    assert checkpoint["report_ready"] is False
