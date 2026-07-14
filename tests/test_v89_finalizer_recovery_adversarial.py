from __future__ import annotations

import json
import os
import pathlib
import shutil

import pytest

from engine import finalize as finalizer
from engine.finalize import FinalizationError, finalize_run
from engine.runtime_manifest import verify_run_receipt
from tests.test_v89_delivery_contract import _complete_finding_run


def _finish(
    run_dir: pathlib.Path,
    project: pathlib.Path,
    **overrides,
):
    arguments = {
        "run_dir": run_dir,
        "project_dir": project,
        "authority_dir": project / ".atoolkit",
        "authority_trusted": True,
        "authorization_assurance": "dry_run_no_network",
        "project_name": "delivery-fixture",
        "primary_target": "https://t.example/",
    }
    arguments.update(overrides)
    return finalize_run(**arguments)


def _read(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "session_id", ["HEAD", "head", "Head", "PROJECT", "project", "Project"])
def test_reserved_session_id_cannot_alias_commit_head_or_project_lock(
    tmp_path: pathlib.Path,
    session_id: str,
) -> None:
    project = tmp_path / "project"
    run_dir = project / "sessions" / session_id
    run_dir.mkdir(parents=True)
    authority = project / ".atoolkit"

    with pytest.raises(FinalizationError, match="reserved"):
        _finish(run_dir, project)

    assert not authority.exists()


@pytest.mark.parametrize(
    "crash_stage", ["PROJECT_PREPARED", "PROJECT_STATE_APPLIED"])
def test_later_session_cannot_overtake_applied_but_unpublished_commit(
    tmp_path: pathlib.Path,
    crash_stage: str,
) -> None:
    """B must recover/order A before it can publish its own project commit."""
    project = tmp_path / "project"
    suffix = crash_stage.lower().replace("_", "-")
    run_a = project / "sessions" / f"run-a-{suffix}"
    run_b = project / "sessions" / f"run-b-after-{suffix}"
    _complete_finding_run(run_a)
    _complete_finding_run(run_b)
    authority = project / ".atoolkit"

    with pytest.raises(FinalizationError, match=crash_stage):
        _finish(run_a, project, crash_after_stage=crash_stage)

    result_b = _finish(run_b, project)

    commit_a_path = authority / "commits" / f"{run_a.name}.json"
    commit_b_path = authority / "commits" / f"{run_b.name}.json"
    assert result_b["delivery_complete"] is True
    assert commit_a_path.is_file(), "B completed while A's applied commit was unpublished"
    assert commit_b_path.is_file()
    commit_a = _read(commit_a_path)
    commit_b = _read(commit_b_path)
    assert commit_b["previous_commit_sha256"] == commit_a["commit_sha256"]
    assert commit_a["revision_after"] == commit_b["revision_before"]


def test_resume_rebuilds_projection_replaced_with_another_sessions_commit(
    tmp_path: pathlib.Path,
) -> None:
    """A valid commit from A is still invalid as B's run-local projection."""
    project = tmp_path / "project"
    run_a = project / "sessions" / "run-a-projection"
    run_b = project / "sessions" / "run-b-projection"
    _complete_finding_run(run_a)
    _complete_finding_run(run_b)
    _finish(run_a, project)

    with pytest.raises(FinalizationError, match="PROJECTIONS_WRITTEN"):
        _finish(run_b, project, crash_after_stage="PROJECTIONS_WRITTEN")
    shutil.copyfile(
        run_a / "project_state_commit.json",
        run_b / "project_state_commit.json",
    )

    result_b = _finish(run_b, project)
    rebuilt = _read(run_b / "project_state_commit.json")
    frozen = _read(project / ".atoolkit" / "commits" / f"{run_b.name}.json")

    assert result_b["delivery_complete"] is True
    assert rebuilt["session_id"] == run_b.name
    assert rebuilt["commit_sha256"] == frozen["commit_sha256"]


def test_new_transaction_does_not_reuse_unjournaled_stale_snapshot_proof(
    tmp_path: pathlib.Path,
) -> None:
    """Files absent from the NEW snapshot record cannot survive from an old tree."""
    project = tmp_path / "project"
    run_dir = project / "sessions" / "run-stale-proof"
    _complete_finding_run(run_dir)
    authority = project / ".atoolkit"

    # Seed the authority snapshot as if an earlier NEW attempt wrote proof
    # bytes but failed before publishing a journal that owned those bytes.
    finalizer._snapshot_inputs(
        run_dir,
        project,
        authority,
        run_dir.name,
        "unjournaled-stale-generation",
    )
    assert not (authority / "finalizations" / f"{run_dir.name}.json").exists()
    shutil.rmtree(run_dir / "findings")

    try:
        result = _finish(run_dir, project)
    except (FinalizationError, ValueError):
        return  # Fail-closed rejection is an acceptable recovery policy.

    assert result["delivery_complete"] is False
    validation = _read(run_dir / "finding_validation.json")
    assert validation.get("normalized_findings") == []


@pytest.mark.parametrize(
    "resume_overrides",
    [
        {"authorization_assurance": "unrestricted_user_accepted"},
        {"authority_trusted": False},
    ],
    ids=["assurance", "authority-trusted"],
)
def test_resume_rejects_changed_trust_inputs_after_receipt_anchor(
    tmp_path: pathlib.Path,
    resume_overrides: dict,
) -> None:
    """Trust inputs are transaction identity, not mutable resume options."""
    project = tmp_path / "project"
    suffix = next(iter(resume_overrides)).replace("_", "-")
    run_dir = project / "sessions" / f"run-resume-{suffix}"
    _complete_finding_run(run_dir)

    with pytest.raises(FinalizationError, match="RECEIPT_ANCHORED"):
        _finish(run_dir, project, crash_after_stage="RECEIPT_ANCHORED")

    with pytest.raises(FinalizationError):
        _finish(run_dir, project, **resume_overrides)


def test_hardlinked_manifest_alias_cannot_forge_delivery_assurance(
    tmp_path: pathlib.Path,
) -> None:
    """A writable alias to an authority inode must fail before journaling."""
    project = tmp_path / "project"
    run_dir = project / "sessions" / "run-hardlink-manifest"
    _complete_finding_run(
        run_dir,
        authorization_assurance="unrestricted_user_accepted",
    )
    authority = project / ".atoolkit"
    authority_manifest = authority / "manifests" / f"{run_dir.name}.json"
    session_manifest = run_dir / "run_manifest.json"
    session_manifest.unlink()
    os.link(authority_manifest, session_manifest)
    forged = _read(session_manifest)
    forged["authorization_assurance"] = "dry_run_no_network"
    forged["preexec_enforced"] = False
    session_manifest.write_text(
        json.dumps(forged, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    assert authority_manifest.stat().st_nlink == 2

    with pytest.raises((FinalizationError, ValueError), match="hard links|unsafe"):
        _finish(
            run_dir,
            project,
            authorization_assurance="dry_run_no_network",
        )

    assert not (authority / "finalizations" / f"{run_dir.name}.json").exists()
    assert not (authority / "commits" / f"{run_dir.name}.json").exists()


@pytest.mark.parametrize("removed", ["target", "head", "latest"])
def test_receipt_verification_requires_reachable_authority_commit_chain(
    tmp_path: pathlib.Path,
    removed: str,
) -> None:
    project = tmp_path / "project"
    run_a = project / "sessions" / f"chain-a-{removed}"
    run_b = project / "sessions" / f"chain-b-{removed}"
    _complete_finding_run(run_a)
    _complete_finding_run(run_b)
    _finish(run_a, project)
    _finish(run_b, project)
    authority = project / ".atoolkit"
    receipt_a = run_a / "run_receipt.json"

    before = verify_run_receipt(
        receipt_a, run_dir=run_a, authority_dir=authority)
    assert before["delivery_complete"] is True

    victim = {
        "target": authority / "commits" / f"{run_a.name}.json",
        "head": authority / "commits" / "HEAD.json",
        "latest": authority / "commits" / f"{run_b.name}.json",
    }[removed]
    victim.unlink()

    after = verify_run_receipt(
        receipt_a, run_dir=run_a, authority_dir=authority)
    assert after["integrity_valid"] is False
    assert after["delivery_complete"] is False
    assert any(
        str(item.get("reason") or "").startswith("authority_commit")
        for item in after["mismatches"]
    )


@pytest.mark.parametrize("removed", ["target", "head", "latest"])
def test_historical_receipt_requires_reachable_anchor_chain(
    tmp_path: pathlib.Path,
    removed: str,
) -> None:
    project = tmp_path / "project"
    run_a = project / "sessions" / f"anchor-a-{removed}"
    run_b = project / "sessions" / f"anchor-b-{removed}"
    _complete_finding_run(run_a)
    _complete_finding_run(run_b)
    _finish(run_a, project)
    _finish(run_b, project)
    authority = project / ".atoolkit"
    receipt_a = run_a / "run_receipt.json"

    before = verify_run_receipt(
        receipt_a, run_dir=run_a, authority_dir=authority)
    assert before["delivery_complete"] is True

    victim = {
        "target": authority / "receipts" / f"{run_a.name}.json",
        "head": authority / "receipts" / "HEAD.json",
        "latest": authority / "receipts" / f"{run_b.name}.json",
    }[removed]
    victim.unlink()

    after = verify_run_receipt(
        receipt_a, run_dir=run_a, authority_dir=authority)
    assert after["integrity_valid"] is False
    assert after["delivery_complete"] is False
    assert any(
        str(item.get("reason") or "").startswith("receipt_anchor")
        for item in after["mismatches"]
    )
