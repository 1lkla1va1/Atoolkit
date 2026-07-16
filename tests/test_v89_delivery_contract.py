from __future__ import annotations

import json
import pathlib
import shutil

import pytest

from engine.reporting.validate import validate_run_artifacts
from engine.runtime_manifest import (
    canonical_json_sha256,
    create_run_manifest,
    sha256_file,
    verify_run_receipt,
    write_run_receipt,
)
from engine.run_authority import (
    create_run_plan,
    ensure_project_identity,
    run_plan_path,
)
from engine.safe_io import (
    UnsafePathError,
    atomic_write_text,
    safe_append_text,
)
from tests.test_reporting_proof_contract import _idor_fixture


def _write(path: pathlib.Path, value: str | dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(value, ensure_ascii=False, indent=2) if isinstance(value, dict) else value
    path.write_text(text, encoding="utf-8")


def _manifest(
    run_dir: pathlib.Path, *, authority_dir: pathlib.Path | None = None,
    authorization_assurance: str = "dry_run_no_network",
    admitted_cells=(),
    canonical_report_required: bool = False,
) -> dict:
    source = run_dir.parent / "source"
    _write(source / "SKILL.md", "---\nversion: 8.9.0\n---\n")
    project = (
        run_dir.parent.parent if run_dir.parent.name == "sessions"
        else run_dir.parent
    )
    authority = authority_dir or project / ".atoolkit"
    identity = ensure_project_identity(
        authority,
        project_dir=project,
        project_name="delivery-fixture",
        primary_target="https://t.example/",
    )
    create_run_plan(
        authority,
        project_id=identity["project_id"],
        session_id=run_dir.name,
        admitted_cells=admitted_cells,
    )
    return create_run_manifest(
        run_dir,
        mode="skill",
        project="delivery-fixture",
        session_id=run_dir.name,
        primary_target="https://t.example/",
        authorized_scopes=["https://t.example/"],
        authz="authorized test fixture",
        instruction_sources=[{
            "kind": "skill",
            "path": source / "SKILL.md",
            "injected": True,
        }],
        source_root=source,
        authority_dir=authority,
        project_id=identity["project_id"],
        run_plan_path=run_plan_path(authority, run_dir.name),
        authorization_assurance=authorization_assurance,
        canonical_report_required=canonical_report_required,
    )


def _complete_finding_run(
    run_dir: pathlib.Path,
    *, authorization_assurance: str = "dry_run_no_network",
    canonical_report_required: bool = False,
) -> dict:
    run_dir.mkdir(parents=True, exist_ok=True)
    _idor_fixture(run_dir)
    _manifest(
        run_dir,
        authorization_assurance=authorization_assurance,
        canonical_report_required=canonical_report_required,
        admitted_cells=[{
            "asset_id": "https://t.example:443",
            "endpoint": "/api/orders/{id}",
            "method": "GET",
            "param": "id",
            "actor_role": "unknown",
            "vuln_class": "idor",
            "namespace": "",
            "param_location": "",
            "subject_role": "",
            "object_kind": "",
        }],
    )
    _write(run_dir / "inventory.json", {
        "endpoints": [{
            "endpoint": "/api/orders/{id}",
            "method": "GET",
            "params": ["id"],
            "roles": ["unknown"],
            "vuln_classes": ["idor"],
        }],
    })
    _write(run_dir / "coverage-ledger.json", {
        "schema_version": 1,
        "surfaces": [{
            "surface_id": "orders-id-unknown",
            "endpoint": "/api/orders/{id}",
            "method": "GET",
            "param": "id",
            "roles": ["unknown"],
            "vuln_class": "idor",
            "status": "confirmed",
            "evidence_ref": "findings/finding_001/finding.json",
            "in_run_scope": True,
            "risk_tags": ["idor"],
        }],
    })
    _write(run_dir / "candidate-ledger.json", {
        "schema_version": "1.1", "candidates": [],
    })
    return validate_run_artifacts(run_dir)


def test_safe_io_replaces_leaf_symlink_and_rejects_parent_symlink(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("sentinel", encoding="utf-8")
    leaf = tmp_path / "leaf.txt"
    leaf.symlink_to(outside)

    atomic_write_text(leaf, "safe", root=tmp_path)

    assert outside.read_text(encoding="utf-8") == "sentinel"
    assert not leaf.is_symlink()
    assert leaf.read_text(encoding="utf-8") == "safe"

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(UnsafePathError):
        atomic_write_text(linked_parent / "result.json", "unsafe", root=tmp_path)
    assert not (real_parent / "result.json").exists()

    append_link = tmp_path / "append.txt"
    append_link.symlink_to(outside)
    with pytest.raises(UnsafePathError):
        safe_append_text(append_link, "mutate", root=tmp_path)
    assert outside.read_text(encoding="utf-8") == "sentinel"


def test_validation_output_does_not_follow_precreated_leaf_symlink(tmp_path):
    run_dir = tmp_path / "run-leaf"
    run_dir.mkdir()
    _manifest(run_dir)
    outside = tmp_path / "outside-validation.json"
    outside.write_text("sentinel", encoding="utf-8")
    (run_dir / "finding_validation.json").symlink_to(outside)

    report = validate_run_artifacts(run_dir, allow_empty=True)

    assert report["status"] == "incomplete"
    assert outside.read_text(encoding="utf-8") == "sentinel"
    assert not (run_dir / "finding_validation.json").is_symlink()


def test_validator_runs_closure_for_findings_and_empty_runs(tmp_path):
    finding_run = tmp_path / "finding-run"
    finding_run.mkdir()
    _idor_fixture(finding_run)
    _manifest(finding_run)

    finding_report = validate_run_artifacts(finding_run)

    assert finding_report["proof_gate"]["result"] == "pass"
    assert finding_report["closure_gate"]["result"] == "fail"
    assert finding_report["status"] == "incomplete_with_findings"
    assert finding_report["exit_code"] == 2

    empty_run = tmp_path / "empty-run"
    empty_run.mkdir()
    _manifest(empty_run)
    empty_report = validate_run_artifacts(empty_run, allow_empty=True)

    assert empty_report["proof_gate"]["result"] == "pass"
    assert empty_report["closure_gate"]["result"] == "fail"
    assert empty_report["status"] == "incomplete"
    assert empty_report["exit_code"] == 2


def test_complete_finding_requires_and_passes_the_same_closure_gate(tmp_path):
    report = _complete_finding_run(tmp_path / "project" / "sessions" / "run-complete")

    assert report["proof_gate"]["result"] == "pass"
    assert report["closure_gate"]["result"] == "pass"
    assert report["status"] == "valid"
    assert report["exit_code"] == 0


def test_manifest_cannot_be_replayed_into_another_run(tmp_path):
    run_a = tmp_path / "run-a"
    run_b = tmp_path / "run-b"
    run_a.mkdir()
    run_b.mkdir()
    _manifest(run_a, authority_dir=tmp_path / "authority-a")
    _idor_fixture(run_b)
    shutil.copyfile(run_a / "run_manifest.json", run_b / "run_manifest.json")

    report = validate_run_artifacts(run_b)

    assert report["status"] == "invalid"
    assert report["exit_code"] == 1
    assert report["proof_gate"]["result"] == "fail"
    assert report["normalized_findings"] == []
    assert any(item.get("code") == "manifest_session_mismatch"
               for item in report["ingestion_errors"])


def test_receipt_uses_immutable_commit_and_survives_live_state_mutation(tmp_path):
    project = tmp_path / "project"
    run_dir = project / "sessions" / "run-receipt"
    validation = _complete_finding_run(run_dir)
    assert validation["exit_code"] == 0
    _write(run_dir / "summary.json", {"status": "complete"})
    live_state = project / "project_state.json"
    _write(live_state, {"schema_version": 1, "revision": 1, "facts": ["first"]})

    receipt = write_run_receipt(
        run_dir / "run_receipt.json",
        manifest_path=run_dir / "run_manifest.json",
        artifacts={
            "summary": run_dir / "summary.json",
            "finding_validation": run_dir / "finding_validation.json",
            "inventory": run_dir / "inventory.json",
            "coverage_ledger": run_dir / "coverage-ledger.json",
            "candidate_ledger": run_dir / "candidate-ledger.json",
            # Compatibility input: writer must snapshot, never bind this path.
            "project_state": live_state,
        },
        project_state_delta={"facts_added": 1},
        authority_trusted=True,
    )

    assert receipt["delivery_complete"] is True
    assert "project_state" not in receipt["artifacts"]
    assert pathlib.Path(receipt["artifacts"]["project_state_commit"]["path"]).name == (
        "project_state_commit.json")
    first = verify_run_receipt(run_dir / "run_receipt.json", run_dir=run_dir)
    assert first["integrity_valid"] is True
    assert first["delivery_complete"] is True

    _write(live_state, {"schema_version": 1, "revision": 2, "facts": ["changed"]})
    second = verify_run_receipt(run_dir / "run_receipt.json", run_dir=run_dir)
    assert second["integrity_valid"] is True
    assert second["delivery_complete"] is True


def test_receipt_completion_requires_trusted_eligible_authority(tmp_path):
    untrusted_run = tmp_path / "project-untrusted" / "sessions" / "run-untrusted"
    validation = _complete_finding_run(untrusted_run)
    assert validation["exit_code"] == 0
    _write(untrusted_run / "summary.json", {"status": "complete"})
    untrusted_state = untrusted_run.parent.parent / "project_state.json"
    _write(untrusted_state, {"schema_version": 2, "revision": 1})
    artifacts = {
        "summary": untrusted_run / "summary.json",
        "finding_validation": untrusted_run / "finding_validation.json",
        "inventory": untrusted_run / "inventory.json",
        "coverage_ledger": untrusted_run / "coverage-ledger.json",
        "candidate_ledger": untrusted_run / "candidate-ledger.json",
        "project_state": untrusted_state,
    }

    untrusted = write_run_receipt(
        untrusted_run / "run_receipt.json",
        manifest_path=untrusted_run / "run_manifest.json",
        artifacts=artifacts,
        project_state_delta={"revision_after": 1},
    )
    untrusted_check = verify_run_receipt(
        untrusted_run / "run_receipt.json", run_dir=untrusted_run)

    assert untrusted["authority_trusted"] is False
    assert untrusted["authorization_assurance"] == "dry_run_no_network"
    assert untrusted["delivery_complete"] is False
    assert untrusted_check["integrity_valid"] is True
    assert untrusted_check["delivery_complete"] is False

    unrestricted_run = (
        tmp_path / "project-unrestricted" / "sessions" / "run-unrestricted")
    validation = _complete_finding_run(
        unrestricted_run,
        authorization_assurance="unrestricted_user_accepted",
    )
    assert validation["exit_code"] == 0
    _write(unrestricted_run / "summary.json", {"status": "complete"})
    unrestricted_state = unrestricted_run.parent.parent / "project_state.json"
    _write(unrestricted_state, {"schema_version": 2, "revision": 1})
    unrestricted_artifacts = {
        "summary": unrestricted_run / "summary.json",
        "finding_validation": unrestricted_run / "finding_validation.json",
        "inventory": unrestricted_run / "inventory.json",
        "coverage_ledger": unrestricted_run / "coverage-ledger.json",
        "candidate_ledger": unrestricted_run / "candidate-ledger.json",
        "project_state": unrestricted_state,
    }

    with pytest.raises(ValueError, match="differs from frozen manifest"):
        write_run_receipt(
            unrestricted_run / "run_receipt.json",
            manifest_path=unrestricted_run / "run_manifest.json",
            artifacts=unrestricted_artifacts,
            authorization_assurance="dry_run_no_network",
            authority_trusted=True,
        )
    unrestricted = write_run_receipt(
        unrestricted_run / "run_receipt.json",
        manifest_path=unrestricted_run / "run_manifest.json",
        artifacts=unrestricted_artifacts,
        project_state_delta={"revision_after": 1},
        authority_trusted=True,
    )
    unrestricted_check = verify_run_receipt(
        unrestricted_run / "run_receipt.json", run_dir=unrestricted_run)

    assert unrestricted["authority_trusted"] is True
    assert unrestricted["authorization_assurance"] == "unrestricted_user_accepted"
    assert unrestricted["delivery_complete"] is False
    assert unrestricted_check["integrity_valid"] is True
    assert unrestricted_check["delivery_complete"] is False


def test_missing_mandatory_artifacts_gets_diagnostic_not_complete_receipt(tmp_path):
    run_dir = tmp_path / "diagnostic-run"
    run_dir.mkdir()
    _manifest(run_dir)
    validation = validate_run_artifacts(run_dir)
    assert validation["status"] == "incomplete"

    receipt = write_run_receipt(
        run_dir / "run_receipt.json",
        manifest_path=run_dir / "run_manifest.json",
        artifacts={"finding_validation": run_dir / "finding_validation.json"},
    )
    verification = verify_run_receipt(run_dir / "run_receipt.json", run_dir=run_dir)

    assert receipt["delivery_complete"] is False
    assert verification["integrity_valid"] is True
    assert verification["delivery_complete"] is False
    assert "summary" in verification["missing_mandatory_artifacts"]
    assert "project_state_commit" in verification["missing_mandatory_artifacts"]


def test_rehashed_session_receipt_cannot_replace_authority_anchor(tmp_path):
    run_dir = tmp_path / "anchored-run"
    run_dir.mkdir()
    _manifest(run_dir)
    validate_run_artifacts(run_dir)
    write_run_receipt(
        run_dir / "run_receipt.json",
        manifest_path=run_dir / "run_manifest.json",
        artifacts={"finding_validation": run_dir / "finding_validation.json"},
    )
    receipt_path = run_dir / "run_receipt.json"
    forged = json.loads(receipt_path.read_text(encoding="utf-8"))
    forged["delivery_complete"] = True
    forged["receipt_sha256"] = ""
    forged["receipt_sha256"] = canonical_json_sha256({
        key: value for key, value in forged.items() if key != "receipt_sha256"
    })
    _write(receipt_path, forged)

    verification = verify_run_receipt(receipt_path, run_dir=run_dir)

    assert verification["integrity_valid"] is False
    assert verification["delivery_complete"] is False
    assert any(item.get("reason") == "receipt_anchor_mismatch"
               for item in verification["mismatches"])


def test_receipt_anchor_conflict_preserves_existing_projections(tmp_path):
    project = tmp_path / "project"
    run_dir = project / "sessions" / "anchor-preserve"
    _complete_finding_run(run_dir)
    _write(run_dir / "summary.json", {"status": "complete"})
    live_state = project / "project_state.json"
    _write(live_state, {"schema_version": 2, "revision": 1})
    artifacts = {
        "summary": run_dir / "summary.json",
        "finding_validation": run_dir / "finding_validation.json",
        "inventory": run_dir / "inventory.json",
        "coverage_ledger": run_dir / "coverage-ledger.json",
        "candidate_ledger": run_dir / "candidate-ledger.json",
        "project_state": live_state,
    }
    write_run_receipt(
        run_dir / "run_receipt.json",
        manifest_path=run_dir / "run_manifest.json",
        artifacts=artifacts,
        project_state_delta={"revision_after": 1},
        authority_trusted=True,
    )
    receipt_before = (run_dir / "run_receipt.json").read_bytes()
    commit_before = (run_dir / "project_state_commit.json").read_bytes()

    _write(live_state, {"schema_version": 2, "revision": 2})
    with pytest.raises(ValueError, match="immutable receipt anchor"):
        write_run_receipt(
            run_dir / "run_receipt.json",
            manifest_path=run_dir / "run_manifest.json",
            artifacts=artifacts,
            project_state_delta={"revision_after": 2},
            authority_trusted=True,
        )

    assert (run_dir / "run_receipt.json").read_bytes() == receipt_before
    assert (run_dir / "project_state_commit.json").read_bytes() == commit_before


def _complete_receipt(run_dir: pathlib.Path) -> dict:
    project = run_dir.parent.parent
    _complete_finding_run(run_dir)
    _write(run_dir / "summary.json", {"status": "complete"})
    live_state = project / "project_state.json"
    _write(live_state, {"schema_version": 2, "revision": 1})
    return write_run_receipt(
        run_dir / "run_receipt.json",
        manifest_path=run_dir / "run_manifest.json",
        artifacts={
            "summary": run_dir / "summary.json",
            "finding_validation": run_dir / "finding_validation.json",
            "inventory": run_dir / "inventory.json",
            "coverage_ledger": run_dir / "coverage-ledger.json",
            "candidate_ledger": run_dir / "candidate-ledger.json",
            "project_state": live_state,
        },
        project_state_delta={"revision_after": 1},
        authority_trusted=True,
    )


def test_receipt_writer_rejects_cross_session_and_project_commit(tmp_path):
    project = tmp_path / "project"
    run_a = project / "sessions" / "commit-a"
    run_b = project / "sessions" / "commit-b"
    _complete_receipt(run_a)
    _complete_finding_run(run_b)
    _write(run_b / "summary.json", {"status": "complete"})
    common = {
        "summary": run_b / "summary.json",
        "finding_validation": run_b / "finding_validation.json",
        "inventory": run_b / "inventory.json",
        "coverage_ledger": run_b / "coverage-ledger.json",
        "candidate_ledger": run_b / "candidate-ledger.json",
    }

    with pytest.raises(ValueError, match="commit_session_mismatch"):
        write_run_receipt(
            run_b / "run_receipt.json",
            manifest_path=run_b / "run_manifest.json",
            artifacts={
                **common,
                "project_state_commit": run_a / "project_state_commit.json",
            },
            authority_trusted=True,
        )

    foreign = json.loads(
        (run_a / "project_state_commit.json").read_text(encoding="utf-8"))
    foreign["session_id"] = run_b.name
    foreign["project_id"] = "proj_foreign"
    foreign["commit_sha256"] = canonical_json_sha256({
        key: value for key, value in foreign.items()
        if key != "commit_sha256"
    })
    foreign_path = run_b / "foreign-project-commit.json"
    _write(foreign_path, foreign)
    with pytest.raises(ValueError, match="commit_project_mismatch"):
        write_run_receipt(
            run_b / "run_receipt.json",
            manifest_path=run_b / "run_manifest.json",
            artifacts={**common, "project_state_commit": foreign_path},
            authority_trusted=True,
        )
    assert not (run_b / "run_receipt.json").exists()


def test_receipt_verifier_rejects_self_consistent_cross_session_commit(tmp_path):
    project = tmp_path / "project"
    run_a = project / "sessions" / "verify-a"
    run_b = project / "sessions" / "verify-b"
    _complete_receipt(run_a)
    receipt = _complete_receipt(run_b)

    commit_path = run_b / "project_state_commit.json"
    shutil.copyfile(run_a / "project_state_commit.json", commit_path)
    receipt["artifacts"]["project_state_commit"].update({
        "sha256": sha256_file(commit_path),
        "size": commit_path.stat().st_size,
    })
    receipt["receipt_sha256"] = canonical_json_sha256({
        key: value for key, value in receipt.items()
        if key != "receipt_sha256"
    })
    _write(run_b / "run_receipt.json", receipt)
    anchor_path = pathlib.Path(receipt["receipt_anchor_path"])
    anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
    anchor["receipt_sha256"] = receipt["receipt_sha256"]
    anchor["project_state_commit_sha256"] = (
        receipt["artifacts"]["project_state_commit"]["sha256"])
    _write(anchor_path, anchor)

    verification = verify_run_receipt(
        run_b / "run_receipt.json",
        run_dir=run_b,
        authority_dir=project / ".atoolkit",
    )

    assert verification["integrity_valid"] is False
    assert verification["delivery_complete"] is False
    assert any(item.get("reason") == "commit_session_mismatch"
               for item in verification["mismatches"])


def test_receipt_verifier_binds_anchor_to_commit_hash(tmp_path):
    run_dir = tmp_path / "project" / "sessions" / "anchor-commit"
    receipt = _complete_receipt(run_dir)
    anchor_path = pathlib.Path(receipt["receipt_anchor_path"])
    anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
    anchor["project_state_commit_sha256"] = "0" * 64
    _write(anchor_path, anchor)

    verification = verify_run_receipt(
        run_dir / "run_receipt.json",
        run_dir=run_dir,
        authority_dir=run_dir.parent.parent / ".atoolkit",
    )

    assert verification["integrity_valid"] is False
    assert any(item.get("reason") == "receipt_anchor_mismatch"
               for item in verification["mismatches"])
