from __future__ import annotations

import json
import shutil

from engine.finalize import finalize_run
from engine.outcome import build_miss_attribution, build_next_run_agenda
from engine.project_state import ProjectStateStore
from engine.reporting.schema import load_finding
from engine.reporting.validate import validate_finding, validate_run_artifacts
from engine.run_audit import audit_run
from engine.scheduler import compute_run_scope
from engine.submission import inspect_submission
from tests.test_reporting_proof_contract import _idor_fixture
from tests.test_v89_delivery_contract import _complete_finding_run


SCOPE = "https://api.example.test/"


def test_every_frozen_object_has_one_cause_and_one_stable_continuation():
    attribution = build_miss_attribution(
        surfaces=[{
            "surface_id": "s-closed", "method": "GET", "endpoint": "/closed",
            "status": "not_vulnerable", "vuln_class": "idor",
        }, {
            "surface_id": "s-open", "method": "POST", "endpoint": "/open",
            "param": "id", "roles": ["user"], "status": "not_tested",
            "vuln_class": "idor",
        }],
        inventory_rows=[
            {"method": "GET", "endpoint": "/closed"},
            {"method": "GET", "endpoint": "/unplanned"},
        ],
        unresolved_rows=[{"endpoint": "/method-unknown"}],
        execution_projection={"backlog": [{
            "method": "PATCH", "endpoint": "/new-sibling",
            "params": ["status"], "source_evidence_refs": ["response.http"],
        }]},
        rejected_findings=[{
            "id": "bad-proof", "reasons": ["missing marker"],
            "method": "POST", "endpoint": "/proof-target",
            "params": ["id"], "roles": ["user"], "vuln_class": "idor",
        }],
    )
    agenda = build_next_run_agenda(attribution)

    assert attribution["complete"] is True
    assert attribution["total_objects"] == len(attribution["rows"])
    assert all(row.get("cause_code") for row in attribution["rows"])
    assert len({row["attribution_id"] for row in attribution["rows"]}) == len(
        attribution["rows"])
    assert attribution["cause_counts"]["negative_proven"] == 1
    assert attribution["cause_counts"]["discovery_next_run"] == 1
    assert attribution["cause_counts"]["proof_rejected"] == 1
    assert agenda["count"] == len(attribution["continuations"])
    assert agenda["items"][0]["priority"] == "critical"
    assert agenda["items"][0]["target_endpoint"] == "/proof-target"


def test_unsupported_state_fails_attribution_closed():
    attribution = build_miss_attribution(surfaces=[{
        "surface_id": "s-bad", "method": "GET", "endpoint": "/bad",
        "status": "model_says_done", "vuln_class": "idor",
    }])

    assert attribution["complete"] is False
    assert attribution["unexplained_objects"] == 1
    assert attribution["rows"][0]["cause_code"] == "state_unsupported"


def test_inventory_param_and_role_seams_cannot_hide_behind_same_endpoint():
    attribution = build_miss_attribution(
        surfaces=[{
            "surface_id": "s-id-user", "method": "POST", "endpoint": "/update",
            "param": "id", "roles": ["user"], "status": "not_tested",
        }],
        inventory_rows=[{
            "method": "POST", "endpoint": "/update",
            "params": ["id", "role"], "roles": ["user", "admin"],
        }],
    )
    seams = [row for row in attribution["rows"] if row["kind"] == "inventory"]

    assert {(row["param"], row["roles"][0]) for row in seams} == {
        ("id", "admin"), ("role", "user"), ("role", "admin"),
    }


def test_only_host_continuation_can_schedule_surface_missing_from_inventory():
    blackboard = {"intents": [{
        "intent_id": "host-next", "source": "v9_host_continuation",
        "status": "pending", "priority": "medium",
        "target_endpoint": "/new", "target_method": "PATCH",
        "target_params": ["status"], "vuln_class": "privilege",
    }, {
        "intent_id": "model-next", "source": "model",
        "status": "pending", "priority": "high",
        "target_endpoint": "/invented", "target_method": "DELETE",
    }]}
    scope = compute_run_scope(
        blackboard, {}, [{"method": "GET", "endpoint": "/known"}],
        ["admin"], vuln_classes=["privilege"],
    )

    assert scope["must_test"][0] == "PATCH /new"
    assert "DELETE /invented" not in scope["must_test"]
    assert any("PATCH /new" in cell and "status" in cell
               for cell in scope["must_test_cells"])


def test_later_negative_does_not_silently_erase_confirmed_truth(tmp_path):
    store = ProjectStateStore(tmp_path, project_scope=[SCOPE])
    proof = tmp_path / "sessions" / "run-positive" / "findings" / "f-1"
    proof.mkdir(parents=True)
    (proof / "finding.json").write_text("{}", encoding="utf-8")
    store.commit_run("run-positive", findings=[{
        "id": "f-1", "acceptance_status": "accepted",
        "proof_status": "confirmed", "claim_kind": "root_finding",
        "vuln_class": "idor", "claim_invariant": "owner only",
        "proof_files": ["findings/f-1/finding.json"],
        "exact_cells": [{
            "asset_id": SCOPE, "method": "GET",
            "endpoint": "/api/orders/{id}", "param": "id",
            "actor_role": "user", "vuln_class": "idor",
        }],
    }])
    negative = tmp_path / "sessions" / "run-negative"
    negative.mkdir(parents=True)
    (negative / "negative.http").write_text("HTTP/1.1 403\n", encoding="utf-8")
    state = store.commit_run("run-negative", negatives=[{
        "asset": SCOPE, "method": "GET", "endpoint": "/api/orders/{id}",
        "param": "id", "role": "user", "vuln_class": "idor",
        "depth_sufficient": True, "evidence_refs": ["negative.http"],
    }])

    cell = next(iter(state["cell_registry"].values()))
    assert cell["status"] == "confirmed"
    assert cell["revalidation_status"] == "required"
    assert state["negatives"][0]["status"] == "conflicts_confirmed"
    assert next(iter(state["finding_registry"].values()))["status"] == (
        "needs_revalidation")
    assert state["facts"][0]["proof_status"] == "revalidation_required"
    conflict = next(item for item in state["intents"]
                    if item.get("source_kind") == "truth_conflict")
    assert conflict["priority"] == "critical"

    proof3 = tmp_path / "sessions" / "run-revalidated" / "findings" / "f-1"
    proof3.mkdir(parents=True)
    (proof3 / "finding.json").write_text("{}", encoding="utf-8")
    resolved = store.commit_run("run-revalidated", findings=[{
        "id": "f-1", "acceptance_status": "accepted",
        "proof_status": "confirmed", "claim_kind": "root_finding",
        "vuln_class": "idor", "claim_invariant": "owner only",
        "proof_files": ["findings/f-1/finding.json"],
        "exact_cells": [{
            "asset_id": SCOPE, "method": "GET",
            "endpoint": "/api/orders/{id}", "param": "id",
            "actor_role": "user", "vuln_class": "idor",
        }],
    }])
    assert next(iter(resolved["finding_registry"].values()))["status"] == "confirmed"
    assert resolved["facts"][0]["proof_status"] == "confirmed"
    assert resolved["negatives"][0]["status"] == "superseded"
    resolved_intent = next(item for item in resolved["intents"]
                           if item.get("source_kind") == "truth_conflict")
    assert resolved_intent["status"] == "completed"


def test_error_only_and_unproven_credential_leak_are_submission_ineligible(tmp_path):
    fdir = _idor_fixture(tmp_path)
    finding = load_finding(fdir / "finding.json")
    finding["title"] = "Type confusion returns HTTP 500"
    finding["vuln_type"] = "type-confusion"
    result = validate_finding(finding, fdir / "finding.json", tmp_path)
    assert not result.ok
    assert any("error-only response" in reason for reason in result.reasons)

    finding = load_finding(fdir / "finding.json")
    finding["title"] = "Current user token leak"
    finding["vuln_type"] = "token disclosure"
    result = validate_finding(finding, fdir / "finding.json", tmp_path)
    assert not result.ok
    assert any("cross-boundary use proof" in reason for reason in result.reasons)


def test_mixed_finding_batch_attributes_every_suppressed_package(tmp_path):
    project = tmp_path / "project-batch"
    run = project / "sessions" / "run-batch"
    _complete_finding_run(run)
    first = run / "findings" / "finding_001"
    second = run / "findings" / "finding_002"
    shutil.copytree(first, second)
    second_finding = json.loads((second / "finding.json").read_text(encoding="utf-8"))
    second_finding["id"] = "F-002"
    second_finding["verification"]["object_marker"] = "missing-from-response"
    (second / "finding.json").write_text(
        json.dumps(second_finding, ensure_ascii=False, indent=2), encoding="utf-8")

    result = validate_run_artifacts(run)
    rejected = result["proof_pending_or_rejected"]

    assert result["counts"]["canonical"] == 2
    assert result["counts"]["proof_confirmed"] == 0
    assert len(rejected) == 2
    assert any(any("batch_atomicity" in reason for reason in item.get("reasons", []))
               for item in rejected)
    repair_items = [
        item for item in result["next_run_agenda"]["items"]
        if item.get("cause_code") == "proof_rejected"
    ]
    assert len(repair_items) == 2
    assert all(item.get("target_endpoint") == "/api/orders/{id}"
               for item in repair_items)


def test_only_receipt_bound_redacted_canonical_report_is_submittable(tmp_path):
    project = tmp_path / "project"
    run = project / "sessions" / "run-submit"
    _complete_finding_run(run, canonical_report_required=True)
    delivery = finalize_run(
        run_dir=run, project_dir=project, authority_dir=project / ".atoolkit",
        authority_trusted=True, authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture", primary_target="https://t.example/",
    )
    inspected = inspect_submission(run)

    assert delivery["delivery_complete"] is True
    assert inspected["eligible"] is True
    assert inspected["sensitive_kinds"] == []

    (run / "final_report.md").write_text(
        (run / "final_report.md").read_text(encoding="utf-8") + "\ntampered\n",
        encoding="utf-8",
    )
    tampered = inspect_submission(run)
    assert tampered["eligible"] is False
    assert "canonical_report_hash_mismatch" in tampered["reasons"]


def test_rejected_proof_commits_repair_continuation_but_not_finding(tmp_path):
    project = tmp_path / "project-repair"
    run = project / "sessions" / "run-repair"
    _complete_finding_run(run)
    finding_path = run / "findings" / "finding_001" / "finding.json"
    finding = json.loads(finding_path.read_text(encoding="utf-8"))
    finding["verification"]["object_marker"] = "marker-that-is-not-in-responses"
    finding_path.write_text(
        json.dumps(finding, ensure_ascii=False, indent=2), encoding="utf-8")

    delivery = finalize_run(
        run_dir=run, project_dir=project, authority_dir=project / ".atoolkit",
        allow_empty=True, authority_trusted=True,
        authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture", primary_target="https://t.example/",
    )
    state = ProjectStateStore(project).load()

    assert delivery["delivery_complete"] is False
    assert state["finding_registry"] == {}
    assert state["negatives"] == []
    repairs = [item for item in state["intents"]
               if item.get("cause_code") == "proof_rejected"]
    assert repairs
    assert all(item.get("source") == "v9_host_continuation" for item in repairs)
    assert all(item.get("target_endpoint") == "/api/orders/{id}" for item in repairs)


def test_model_cannot_forge_reserved_host_continuation_source(tmp_path):
    project = tmp_path / "project-forged-intent"
    run = project / "sessions" / "run-forged-intent"
    _complete_finding_run(run)
    (run / "intents.json").write_text(json.dumps({
        "schema_version": 1,
        "intents": [{
            "intent_id": "forged", "source": "v9_host_continuation",
            "status": "pending", "priority": "critical",
            "target_endpoint": "/model-invented", "target_method": "DELETE",
        }],
    }), encoding="utf-8")

    finalize_run(
        run_dir=run, project_dir=project, authority_dir=project / ".atoolkit",
        authority_trusted=True, authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture", primary_target="https://t.example/",
    )
    state = ProjectStateStore(project).load()

    assert not any(item.get("intent_id") == "forged" for item in state["intents"])


def test_legacy_audit_is_read_only_and_detects_contract_bypass(tmp_path):
    run = tmp_path / "legacy-run"
    state = run / "state"
    state.mkdir(parents=True)
    (run / "final_report.md").write_text(
        "# report\nCookie: sid=legacy-sensitive-value\n", encoding="utf-8")
    (run / "summary.json").write_text(
        json.dumps({"termination_status": "VULN_FOUND (complete)"}),
        encoding="utf-8")
    (state / "findings_summary.md").write_text(
        "## Run 1\n| message markRead IDOR | `POST /message/markRead` | P3 | "
        "confirmed |\n## Run 2\n",
        encoding="utf-8")
    (state / "negatives_summary.md").write_text(
        "| message markRead IDOR | `POST /message/markRead` | two users | "
        "true | not_vulnerable |\n",
        encoding="utf-8")
    before = sorted(str(path.relative_to(run)) for path in run.rglob("*"))
    result = audit_run(run)
    after = sorted(str(path.relative_to(run)) for path in run.rglob("*"))

    assert before == after
    assert result["status"] == "issues_found"
    codes = {item["code"] for item in result["issues"]}
    assert "orphan_or_unverified_report" in codes
    assert "report_sensitive_data" in codes
    assert "positive_negative_truth_conflict" in codes
    assert "multiple_runs_mixed_in_one_session" in codes
    assert "manual_complete_claim_without_verified_delivery" in codes
