from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.finalize import finalize_run
from engine.ledger import CoverageLedger
from engine.reporting.schema import load_finding
from engine.reporting.validate import (
    ValidationContext,
    validate_finding,
    validate_run_artifacts,
)
from engine.run_authority import create_run_plan, ensure_project_identity, run_plan_path
from engine.runtime_manifest import (
    create_run_manifest,
    validate_manifest_binding,
    verify_run_receipt,
)
from engine.skill_runtime import (
    SkillRuntimeError,
    checkpoint_direct_run,
    initialize_direct_run,
    record_observation,
)
from engine.threat_model import (
    ThreatModelError,
    compile_threat_model,
    derive_threat_coverage,
    validate_threat_plan,
)
from tests.test_v89_delivery_contract import _complete_finding_run
from tests.test_v89_delivery_contract import _manifest as _delivery_manifest
from tests.test_v89_reporting_evidence_binding import _negative_fixture
from tests.test_reporting_proof_contract import _idor_fixture


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def _plan_fixture(root: Path) -> tuple[Path, Path, Path]:
    evidence = root / "recon" / "app.js"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text("fetch('/api/refund', {method: 'POST'})", encoding="utf-8")
    inventory = root / "inventory-input.json"
    _write_json(inventory, {"surfaces": [{
        "endpoint": "/api/refund",
        "method": "POST",
        "body_params": ["order_no", "refund_amount"],
        "roles": ["user"],
    }]})
    feature_graph = root / "feature-input.json"
    channels = {
        name: {"status": "covered", "evidence_refs": ["recon/app.js"]}
        for name in (
            "js_ref", "inline_script", "asset_ref", "page_link",
            "path_inference", "response_body",
        )
    }
    _write_json(feature_graph, {
        "schema_version": 1,
        "target": "https://t.example/",
        "discovery_channels": channels,
        "features": [{
            "feature_id": "refund",
            "name": "Order refund",
            "actors": ["user"],
            "assets": ["account_balance", "order"],
            "objects": ["order", "refund"],
            "states": ["paid", "refunded"],
            "trust_boundaries": ["browser_to_refund_api"],
            "inputs": ["order_no", "refund_amount"],
            "actions": ["request_refund", "read_balance"],
            "apis": [{
                "endpoint": "/api/refund", "method": "POST",
                "params": ["order_no", "refund_amount"], "roles": ["user"],
            }],
        }],
        "unassigned_endpoints": [],
    })
    threat_model = root / "threat-input.json"
    _write_json(threat_model, {
        "schema_version": 1,
        "features": [{
            "feature_id": "refund",
            "coverage_note": {
                "input_surface": "order and refund inputs",
                "behavior_surface": "refund transition and balance readback",
                "depth_strategy": "owner baseline plus state before and after",
            },
            "threats": [{
                "threat_id": "T-refund-overpay",
                "vuln_class": "refund-amount-invariant-bypass",
                "security_invariant": "refund cannot exceed paid amount",
                "attacker": "authenticated_user",
                "asset": "account_balance",
                "preconditions": ["owned_paid_order"],
                "abuse_action": "submit excessive refund amount",
                "expected_secure_result": "server rejects excessive refund",
                "observable_violation": "balance increases above paid amount",
                "reasoning": "client amount changes server-side balance",
                "targets": [{
                    "endpoint": "/api/refund", "method": "POST",
                    "params": ["refund_amount"], "roles": ["user"],
                }],
                "evidence_required": ["state_before", "exploit", "state_after"],
                "unruled_out": ["concurrent_refund"],
            }],
        }],
    })
    return inventory, feature_graph, threat_model


def test_threat_plan_compiles_only_declared_business_threat(tmp_path):
    inventory, feature_graph_path, threat_model_path = _plan_fixture(tmp_path)
    inventory_value = json.loads(inventory.read_text(encoding="utf-8"))
    feature_value = json.loads(feature_graph_path.read_text(encoding="utf-8"))
    threat_value = json.loads(threat_model_path.read_text(encoding="utf-8"))

    plan = validate_threat_plan(
        feature_value, threat_value, inventory_value["surfaces"], run_dir=tmp_path)
    surfaces = compile_threat_model(
        plan, inventory_value["surfaces"], target="https://t.example/")

    assert len(surfaces) == 1
    assert surfaces[0]["feature_id"] == "refund"
    assert surfaces[0]["threat_id"] == "T-refund-overpay"
    assert surfaces[0]["param"] == "refund_amount"
    assert surfaces[0]["vuln_class"] == "refund-amount-invariant-bypass"
    assert surfaces[0]["security_invariant"] == "refund cannot exceed paid amount"


def test_threat_plan_rejects_channel_without_evidence_and_unassigned_endpoint(tmp_path):
    inventory, feature_graph_path, threat_model_path = _plan_fixture(tmp_path)
    inventory_value = json.loads(inventory.read_text(encoding="utf-8"))
    feature_value = json.loads(feature_graph_path.read_text(encoding="utf-8"))
    threat_value = json.loads(threat_model_path.read_text(encoding="utf-8"))
    feature_value["discovery_channels"]["inline_script"]["evidence_refs"] = []
    inventory_value["surfaces"].append({
        "endpoint": "/api/unassigned", "method": "GET", "params": [],
    })

    with pytest.raises(ThreatModelError) as exc:
        validate_threat_plan(
            feature_value, threat_value, inventory_value["surfaces"], run_dir=tmp_path)

    message = str(exc.value)
    assert "inline_script" in message
    assert "/api/unassigned" in message


def test_direct_threat_mode_binds_observations_and_derives_threat_coverage(tmp_path):
    run_dir = tmp_path / "run-threat"
    inventory, feature_graph, threat_model = _plan_fixture(run_dir)
    result = initialize_direct_run(
        run_dir=run_dir,
        target="https://t.example/",
        inventory_path=inventory,
        feature_graph_path=feature_graph,
        threat_model_path=threat_model,
    )

    assert result["planning_mode"] == "threat_model"
    assert result["planning_degraded"] is False
    ledger = CoverageLedger.load(run_dir / "coverage-ledger.json")
    assert len(ledger.surfaces) == 1
    surface = ledger.surfaces[0]
    with pytest.raises(SkillRuntimeError, match="threat_id"):
        record_observation(run_dir=run_dir, agent_id="logic", observation={
            "schema_version": 1,
            "observation_id": "wrong-threat",
            "surface_id": surface["surface_id"],
            "threat_id": "T-other",
            "outcome": "exploring",
        })

    saved = record_observation(run_dir=run_dir, agent_id="logic", observation={
        "schema_version": 1,
        "observation_id": "right-threat",
        "surface_id": surface["surface_id"],
        "outcome": "exploring",
    })
    observation = json.loads((run_dir / saved["path"]).read_text(encoding="utf-8"))
    assert observation["feature_id"] == "refund"
    assert observation["threat_id"] == "T-refund-overpay"

    checkpoint = checkpoint_direct_run(run_dir)
    assert checkpoint["threat_coverage"]["stats"]["threats"] == 1
    assert checkpoint["threat_coverage"]["stats"]["open_threats"] == 1

    ledger = CoverageLedger.load(run_dir / "coverage-ledger.json")
    ledger.surfaces[0]["status"] = "not_vulnerable"
    ledger.save(run_dir / "coverage-ledger.json")
    coverage = derive_threat_coverage(
        ledger.surfaces,
        json.loads((run_dir / "threat-model.json").read_text(encoding="utf-8")),
    )
    assert coverage["stats"]["open_threats"] == 0
    assert coverage["features"][0]["status"] == "closed"


def test_legacy_direct_runtime_is_explicitly_degraded(tmp_path):
    inventory = tmp_path / "inventory.json"
    _write_json(inventory, {"surfaces": [{
        "endpoint": "/api/search", "method": "GET", "params": ["q"],
    }]})
    result = initialize_direct_run(
        run_dir=tmp_path / "run-legacy",
        target="https://t.example/",
        inventory_path=inventory,
    )

    assert result["planning_mode"] == "legacy_risk"
    assert result["planning_degraded"] is True
    assert result["report_ready"] is False


def test_manifest_binds_safe_model_provenance_and_planning_artifacts(tmp_path):
    run = tmp_path / "project" / "sessions" / "run-provenance"
    run.mkdir(parents=True)
    inventory, feature_graph, threat_model = _plan_fixture(run)
    manifest = create_run_manifest(
        run,
        mode="skill",
        project="project",
        session_id=run.name,
        primary_target="https://t.example/",
        authorized_scopes=["https://t.example/"],
        authz="authorized fixture",
        authority_dir=tmp_path / "authority",
        execution_provenance={
            "provider": "openai", "model": "gpt-test", "adapter": "codex",
            "settings": {"temperature": None, "seed": 7},
        },
        planning_mode="threat_model",
        planning_artifacts={
            "feature-graph.json": feature_graph,
            "threat-model.json": threat_model,
        },
        canonical_report_required=True,
    )

    assert manifest["execution_provenance"]["model"] == "gpt-test"
    assert manifest["planning_mode"] == "threat_model"
    assert manifest["canonical_report_required"] is True
    assert validate_manifest_binding(manifest, run_dir=run)["ok"] is True

    feature_graph.write_text("{}", encoding="utf-8")
    check = validate_manifest_binding(manifest, run_dir=run)
    assert check["ok"] is False
    assert any(item["code"] == "planning_artifact_digest_mismatch"
               for item in check["errors"])

    with pytest.raises(ValueError, match="execution_provenance"):
        create_run_manifest(
            tmp_path / "bad-run",
            mode="skill", project="project", session_id="bad-run",
            primary_target="https://t.example/",
            authorized_scopes=["https://t.example/"],
            authz="authorized fixture",
            authority_dir=tmp_path / "bad-authority",
            execution_provenance={"provider": "x", "api_key": "secret"},
        )


def test_finalizer_owns_and_receipt_binds_canonical_report(tmp_path):
    project = tmp_path / "project"
    run = project / "sessions" / "run-canonical-report"
    report = _complete_finding_run(run, canonical_report_required=True)
    assert report["exit_code"] == 0
    (run / "final_report.md").write_text("MODEL AUTHORED GARBAGE", encoding="utf-8")

    delivery = finalize_run(
        run_dir=run,
        project_dir=project,
        authority_dir=project / ".atoolkit",
        allow_empty=False,
        authority_trusted=True,
        authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture",
        primary_target="https://t.example/",
    )

    rendered = (run / "final_report.md").read_text(encoding="utf-8")
    assert "MODEL AUTHORED GARBAGE" not in rendered
    assert "漏洞名称" in rendered
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    assert summary["canonical_report_status"] == "complete"
    assert summary["canonical_report_sha256"]
    receipt = verify_run_receipt(
        run / "run_receipt.json", run_dir=run, authority_dir=project / ".atoolkit")
    assert receipt["delivery_complete"] is True
    assert "final_report" not in receipt["missing_mandatory_artifacts"]
    assert delivery["canonical_report_verified"] is True


def test_checkpoint_rejects_drifted_threat_plan(tmp_path):
    run = tmp_path / "run-drift"
    inventory, feature_graph, threat_model = _plan_fixture(run)
    initialize_direct_run(
        run_dir=run, target="https://t.example/", inventory_path=inventory,
        feature_graph_path=feature_graph, threat_model_path=threat_model,
    )
    (run / "threat-model.json").write_text("{}", encoding="utf-8")

    with pytest.raises(SkillRuntimeError, match="digest mismatch"):
        checkpoint_direct_run(run)


def test_threat_mode_finding_requires_feature_and_threat_binding(tmp_path):
    finding_path = _idor_fixture(tmp_path) / "finding.json"
    finding = load_finding(finding_path)
    context = ValidationContext.from_manifest({
        "primary_target": "https://t.example/",
        "authorized_scopes": ["https://t.example/"],
        "planning_mode": "threat_model",
    })

    result = validate_finding(finding, finding_path, tmp_path, context=context)

    assert result.ok is False
    assert "threat-model finding requires feature_point.feature_id" in result.reasons
    assert "threat-model finding requires claim.threat_id" in result.reasons


def test_validator_recompiles_threat_plan_and_rejects_open_threat(tmp_path):
    project = tmp_path / "project"
    run = project / "sessions" / "run-open-threat"
    inventory, feature_graph, threat_model = _plan_fixture(run)
    initialize_direct_run(
        run_dir=run, target="https://t.example/", inventory_path=inventory,
        feature_graph_path=feature_graph, threat_model_path=threat_model,
    )
    authority = project / ".atoolkit"
    identity = ensure_project_identity(
        authority, project_dir=project, project_name="threat-fixture",
        primary_target="https://t.example/",
    )
    ledger = CoverageLedger.load(run / "coverage-ledger.json")
    create_run_plan(
        authority, project_id=identity["project_id"], session_id=run.name,
        admitted_cells=ledger.surfaces,
    )
    create_run_manifest(
        run, mode="skill", project="threat-fixture", project_id=identity["project_id"],
        session_id=run.name, primary_target="https://t.example/",
        authorized_scopes=["https://t.example/"], authz="authorized fixture",
        authority_dir=authority, run_plan_path=run_plan_path(authority, run.name),
        authorization_assurance="dry_run_no_network",
        planning_mode="threat_model", planning_degraded=False,
        planning_artifacts={
            "feature-graph.json": run / "feature-graph.json",
            "threat-model.json": run / "threat-model.json",
        },
        canonical_report_required=True,
    )

    report = validate_run_artifacts(run, allow_empty=True)

    assert report["closure_gate"]["result"] == "fail"
    assert "threat_coverage_open" in report["closure_gate"]["reasons"]


def test_wrapped_skill_freezes_compiled_threat_cells(tmp_path, monkeypatch):
    from engine import skill_wrapper

    project = tmp_path / "project"
    run = project / "sessions" / "run-wrapped-threat"
    authority = tmp_path / "authority"
    inventory, feature_graph, threat_model = _plan_fixture(run)
    monkeypatch.setattr(skill_wrapper, "_run_agent_process", lambda *_a, **_k: 0)
    monkeypatch.setattr(skill_wrapper, "finalize_run", lambda **_k: {
        "status": "incomplete", "exit_code": 2,
    })

    skill_wrapper.run_wrapped_skill(
        run_dir=run, project_dir=project, authority_dir=authority,
        target="https://t.example/", project_name="wrapped-threat",
        command=["codex", "exec", "-"], inventory_path=inventory,
        feature_graph_path=feature_graph, threat_model_path=threat_model,
        legacy_risk_plan=False,
        execution_provenance={
            "provider": "openai", "model": "gpt-test", "adapter": "codex",
        },
    )

    manifest = json.loads((run / "run_manifest.json").read_text(encoding="utf-8"))
    ledger = CoverageLedger.load(run / "coverage-ledger.json")
    frozen = json.loads(run_plan_path(authority, run.name).read_text(encoding="utf-8"))
    assert manifest["planning_mode"] == "threat_model"
    assert manifest["planning_degraded"] is False
    assert manifest["canonical_report_required"] is True
    assert len(ledger.surfaces) == 1
    assert frozen["admitted_cells"][0]["threat_id"] == "T-refund-overpay"


def test_invalid_run_removes_stale_final_and_draft_reports(tmp_path):
    project = tmp_path / "project"
    run = project / "sessions" / "run-invalid-report"
    _complete_finding_run(run, canonical_report_required=True)
    (run / "final_report.md").write_text("STALE FINAL", encoding="utf-8")
    (run / "draft_report.md").write_text("STALE DRAFT", encoding="utf-8")
    (run / "findings" / "finding_001" / "finding.json").write_text(
        "{invalid", encoding="utf-8")

    delivery = finalize_run(
        run_dir=run, project_dir=project, authority_dir=project / ".atoolkit",
        authority_trusted=True, authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture", primary_target="https://t.example/",
    )

    assert delivery["status"] == "invalid"
    assert not (run / "final_report.md").exists()
    assert not (run / "draft_report.md").exists()


def test_empty_valid_run_gets_explicit_canonical_zero_finding_report(tmp_path):
    project = tmp_path / "project"
    run = project / "sessions" / "run-empty-report"
    run.mkdir(parents=True)
    exact_cell = {
        "asset_id": "https://t.example:443", "endpoint": "/api/search",
        "method": "GET", "param": "q", "actor_role": "user",
        "vuln_class": "sqli", "namespace": "/shop",
        "param_location": "query", "subject_role": "customer",
        "object_kind": "search-result",
    }
    _delivery_manifest(
        run, authorization_assurance="dry_run_no_network",
        canonical_report_required=True, admitted_cells=[exact_cell],
    )
    _negative_fixture(run, create_manifest=False)
    assert validate_run_artifacts(run, allow_empty=True)["status"] == "empty_allowed"

    delivery = finalize_run(
        run_dir=run, project_dir=project, authority_dir=project / ".atoolkit",
        allow_empty=True, authority_trusted=True,
        authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture", primary_target="https://t.example/",
    )

    report = (run / "final_report.md").read_text(encoding="utf-8")
    assert delivery["status"] == "complete"
    assert delivery["canonical_report_verified"] is True
    assert "未发现满足证明合同" in report
