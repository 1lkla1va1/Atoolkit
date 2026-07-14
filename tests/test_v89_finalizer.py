from __future__ import annotations

import json
import shutil
from concurrent.futures import ThreadPoolExecutor

import pytest

from engine.finalize import FinalizationError, finalize_run
from engine.reporting.validate import validate_run_artifacts
from engine.run_authority import ensure_project_identity
from engine.runtime_manifest import verify_run_receipt
from tests.test_v89_delivery_contract import _complete_finding_run, _manifest


def _revision(project) -> int:
    path = project / "project_state.json"
    if not path.is_file():
        return 0
    return int(json.loads(path.read_text(encoding="utf-8")).get("revision", 0))


def test_finalize_is_idempotent_and_binds_immutable_commit(tmp_path):
    project = tmp_path / "project"
    run_dir = project / "sessions" / "run-finalize"
    report = _complete_finding_run(run_dir)
    assert report["exit_code"] == 0
    authority = project / ".atoolkit"

    first = finalize_run(
        run_dir=run_dir,
        project_dir=project,
        authority_dir=authority,
        allow_empty=False,
        authority_trusted=True,
        authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture",
        primary_target="https://t.example/",
    )
    revision = _revision(project)
    second = finalize_run(
        run_dir=run_dir,
        project_dir=project,
        authority_dir=authority,
        allow_empty=False,
        authority_trusted=True,
        authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture",
        primary_target="https://t.example/",
    )

    assert first["delivery_complete"] is True
    assert second == first
    assert _revision(project) == revision
    commit = json.loads((run_dir / "project_state_commit.json").read_text(encoding="utf-8"))
    assert commit["state_before_sha256"]
    assert commit["state_after_sha256"]
    assert commit["commit_sha256"]


def test_finalize_recovers_after_project_commit_stage(tmp_path):
    project = tmp_path / "project"
    run_dir = project / "sessions" / "run-crash"
    _complete_finding_run(run_dir)
    authority = project / ".atoolkit"

    with pytest.raises(FinalizationError, match="injected crash"):
        finalize_run(
            run_dir=run_dir,
            project_dir=project,
            authority_dir=authority,
            authority_trusted=True,
            authorization_assurance="dry_run_no_network",
            project_name="delivery-fixture",
            primary_target="https://t.example/",
            crash_after_stage="PROJECT_COMMITTED",
        )
    committed_revision = _revision(project)
    result = finalize_run(
        run_dir=run_dir,
        project_dir=project,
        authority_dir=authority,
        authority_trusted=True,
        authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture",
        primary_target="https://t.example/",
    )

    assert result["delivery_complete"] is True
    assert _revision(project) == committed_revision


def test_zero_finding_closure_failure_does_not_create_project_revision(tmp_path):
    project = tmp_path / "project"
    run_dir = project / "sessions" / "run-incomplete"
    run_dir.mkdir(parents=True)
    _manifest(run_dir)
    authority = project / ".atoolkit"

    result = finalize_run(
        run_dir=run_dir,
        project_dir=project,
        authority_dir=authority,
        allow_empty=True,
        authority_trusted=True,
        authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture",
        primary_target="https://t.example/",
    )

    assert result["delivery_complete"] is False
    assert result["exit_code"] == 2
    assert _revision(project) == 0


def test_unrestricted_and_direct_cli_assurance_never_claim_complete(tmp_path):
    project = tmp_path / "project"
    run_dir = project / "sessions" / "run-egress"
    _complete_finding_run(
        run_dir,
        authorization_assurance="unrestricted_user_accepted",
    )

    result = finalize_run(
        run_dir=run_dir,
        project_dir=project,
        authority_dir=project / ".atoolkit",
        authority_trusted=True,
        authorization_assurance="unrestricted_user_accepted",
        project_name="delivery-fixture",
        primary_target="https://t.example/",
    )

    assert result["integrity_valid"] is True
    assert result["delivery_complete"] is False
    assert result["preexec_enforced"] is False
    assert result["exit_code"] == 2
    receipt = json.loads((run_dir / "run_receipt.json").read_text(encoding="utf-8"))
    assert receipt["delivery_complete"] is False
    verification = verify_run_receipt(
        run_dir / "run_receipt.json", run_dir=run_dir,
        authority_dir=project / ".atoolkit")
    assert verification["integrity_valid"] is True
    assert verification["delivery_complete"] is False


def test_untrusted_authority_never_mutates_cross_run_project_truth(tmp_path):
    project = tmp_path / "project"
    run_dir = project / "sessions" / "run-untrusted"
    _complete_finding_run(run_dir)

    result = finalize_run(
        run_dir=run_dir,
        project_dir=project,
        authority_dir=project / ".atoolkit",
        authority_trusted=False,
        authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture",
        primary_target="https://t.example/",
    )

    assert result["delivery_complete"] is False
    assert _revision(project) == 0
    commit = json.loads(
        (run_dir / "project_state_commit.json").read_text(encoding="utf-8"))
    assert commit["delta"]["project_mutated"] is False


def test_concurrent_finalizers_commit_exactly_once(tmp_path):
    project = tmp_path / "project"
    run_dir = project / "sessions" / "run-concurrent"
    _complete_finding_run(run_dir)

    def finish():
        return finalize_run(
            run_dir=run_dir,
            project_dir=project,
            authority_dir=project / ".atoolkit",
            authority_trusted=True,
            authorization_assurance="dry_run_no_network",
            project_name="delivery-fixture",
            primary_target="https://t.example/",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: finish(), range(2)))

    assert all(result["delivery_complete"] for result in results)
    assert _revision(project) == 1


def test_resume_uses_authority_snapshot_not_mutated_live_run(tmp_path):
    project = tmp_path / "project"
    run_dir = project / "sessions" / "run-snapshot"
    _complete_finding_run(run_dir)
    authority = project / ".atoolkit"

    with pytest.raises(FinalizationError, match="injected crash"):
        finalize_run(
            run_dir=run_dir, project_dir=project, authority_dir=authority,
            authority_trusted=True,
            authorization_assurance="dry_run_no_network",
            project_name="delivery-fixture",
            primary_target="https://t.example/",
            crash_after_stage="GATES_EVALUATED",
        )

    (run_dir / "findings" / "finding_001" / "response_attacker.http").unlink()
    (run_dir / "intents.json").write_text(json.dumps({
        "intents": [{"intent_id": "late", "status": "completed"}],
    }), encoding="utf-8")
    result = finalize_run(
        run_dir=run_dir, project_dir=project, authority_dir=authority,
        authority_trusted=True,
        authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture", primary_target="https://t.example/",
    )

    assert result["delivery_complete"] is True
    state = json.loads((project / "project_state.json").read_text(encoding="utf-8"))
    assert not any(item.get("intent_id") == "late" for item in state["intents"])


def test_crash_after_state_publish_recovers_original_prepared_commit(tmp_path):
    project = tmp_path / "project"
    run_dir = project / "sessions" / "run-applied-crash"
    _complete_finding_run(run_dir)
    authority = project / ".atoolkit"

    with pytest.raises(FinalizationError, match="PROJECT_STATE_APPLIED"):
        finalize_run(
            run_dir=run_dir, project_dir=project, authority_dir=authority,
            authority_trusted=True,
            authorization_assurance="dry_run_no_network",
            project_name="delivery-fixture",
            primary_target="https://t.example/",
            crash_after_stage="PROJECT_STATE_APPLIED",
        )
    assert _revision(project) == 1
    (run_dir / "intents.json").write_text(
        json.dumps({"intents": [{"intent_id": "different"}]}),
        encoding="utf-8")

    result = finalize_run(
        run_dir=run_dir, project_dir=project, authority_dir=authority,
        authority_trusted=True,
        authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture", primary_target="https://t.example/",
    )
    commit = json.loads(
        (run_dir / "project_state_commit.json").read_text(encoding="utf-8"))
    assert result["delivery_complete"] is True
    assert _revision(project) == 1
    assert commit["revision_before"] == 0
    assert commit["revision_after"] == 1
    assert commit["delta"]["state_delta"]["root_findings"] == 1


def test_authority_identity_cannot_finalize_a_different_project_locator(tmp_path):
    project_a = tmp_path / "a" / "delivery-fixture"
    project_b = tmp_path / "b" / "delivery-fixture"
    run_a = project_a / "sessions" / "same-run"
    run_b = project_b / "sessions" / "same-run"
    _complete_finding_run(run_a)
    shutil.copytree(run_a, run_b)
    authority = tmp_path / "authority-a"
    ensure_project_identity(
        authority, project_dir=project_a, project_name="delivery-fixture",
        primary_target="https://t.example/")

    with pytest.raises(ValueError, match="locator mismatch"):
        finalize_run(
            run_dir=run_b, project_dir=project_b, authority_dir=authority,
            authority_trusted=True,
            authorization_assurance="dry_run_no_network",
            project_name="delivery-fixture",
            primary_target="https://t.example/",
        )


def test_snapshot_validation_uses_frozen_historical_project_evidence(tmp_path):
    project = tmp_path / "project"
    first_run = project / "sessions" / "run-history-source"
    _complete_finding_run(first_run)
    finalize_run(
        run_dir=first_run,
        project_dir=project,
        authority_dir=project / ".atoolkit",
        authority_trusted=True,
        authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture",
        primary_target="https://t.example/",
    )
    state = json.loads((project / "project_state.json").read_text(encoding="utf-8"))
    cell = next(
        row for row in state["cell_registry"].values()
        if row.get("status") == "confirmed"
    )
    second_run = project / "sessions" / "run-history-consumer"
    second_run.mkdir(parents=True)
    plan_cell = {
        "asset_id": cell["asset_id"],
        "endpoint": cell["path"],
        "method": cell["method"],
        "param": cell.get("param", ""),
        "actor_role": cell.get("role_scope", "unknown"),
        "vuln_class": cell["vuln_class"],
        "namespace": cell.get("namespace", ""),
        "param_location": cell.get("param_location", ""),
        "subject_role": cell.get("subject_role", ""),
        "object_kind": cell.get("object_kind", ""),
    }
    _manifest(second_run, admitted_cells=[plan_cell])
    inventory = {
        "asset": cell["asset_id"],
        "endpoint": cell["path"],
        "method": cell["method"],
        "params": [cell.get("param", "")],
        "roles": [cell.get("role_scope", "unknown")],
        "vuln_classes": [cell["vuln_class"]],
    }
    surface = {
        **plan_cell,
        "roles": [cell.get("role_scope", "unknown")],
        "status": "confirmed",
        "evidence_ref": str(project / "project_state.json"),
        "in_run_scope": True,
        "risk_tags": ["idor"],
    }
    (second_run / "inventory.json").write_text(
        json.dumps({"endpoints": [inventory]}), encoding="utf-8")
    (second_run / "coverage-ledger.json").write_text(
        json.dumps({"schema_version": 1, "surfaces": [surface]}),
        encoding="utf-8")
    (second_run / "candidate-ledger.json").write_text(
        json.dumps({"schema_version": "1.1", "candidates": []}),
        encoding="utf-8")

    live_validation = validate_run_artifacts(second_run, allow_empty=True)
    result = finalize_run(
        run_dir=second_run,
        project_dir=project,
        authority_dir=project / ".atoolkit",
        allow_empty=True,
        authority_trusted=True,
        authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture",
        primary_target="https://t.example/",
    )

    assert live_validation["closure_gate"]["result"] == "pass"
    assert result["delivery_complete"] is True
