from __future__ import annotations

import hashlib
import json
import os
import stat

import pytest

from engine.project_state import ProjectStateCorrupt, ProjectStateStore


SCOPE = "https://api.example.test/"


def _schema1_bytes(*, marker: str = "original") -> bytes:
    value = {
        "schema_version": 1,
        "revision": 0,
        "project_scope": ["https://api.example.test:443"],
        "merged_run_ids": [],
        "facts": [],
        "intents": [],
        "negatives": [],
        "dead_ends": [],
        "inventory": {"surfaces": {}, "unresolved": {}},
        "cell_registry": {},
        "finding_registry": {},
        "run_history": {},
        "updated_at": "",
        "test_marker": marker,
    }
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _install_schema1(tmp_path, *, marker: str = "original") -> tuple[ProjectStateStore, bytes]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = _schema1_bytes(marker=marker)
    (tmp_path / "project_state.json").write_bytes(source)
    return ProjectStateStore(tmp_path, project_scope=[SCOPE]), source


def test_schema1_migration_creates_exact_private_durable_backup(tmp_path):
    store, source = _install_schema1(tmp_path)

    migrated = store.commit_run("run-migrate", run_summary={"status": "complete"})

    backup = tmp_path / "project_state.pre-v89.schema1.json"
    assert backup.read_bytes() == source
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert migrated["schema_version"] == 3
    assert migrated["migrated_from_schema"] == 1
    assert migrated["schema1_backup_sha256"] == hashlib.sha256(source).hexdigest()


@pytest.mark.parametrize("backup_bytes", [
    b'{"schema_version": 1',
    _schema1_bytes(marker="different-valid-state"),
])
def test_schema1_migration_rejects_truncated_or_mismatched_existing_backup(
    tmp_path, backup_bytes,
):
    store, source = _install_schema1(tmp_path)
    backup = tmp_path / "project_state.pre-v89.schema1.json"
    backup.write_bytes(backup_bytes)
    backup.chmod(0o600)

    with pytest.raises(ProjectStateCorrupt, match="does not match original state"):
        store.commit_run("run-migrate", run_summary={"status": "complete"})

    assert (tmp_path / "project_state.json").read_bytes() == source
    assert backup.read_bytes() == backup_bytes


def test_matching_existing_backup_is_verified_not_replaced(tmp_path):
    store, source = _install_schema1(tmp_path)
    backup = tmp_path / "project_state.pre-v89.schema1.json"
    backup.write_bytes(source)
    backup.chmod(0o600)
    inode_before = backup.stat().st_ino

    store.commit_run("run-migrate", run_summary={"status": "complete"})

    assert backup.stat().st_ino == inode_before
    assert backup.read_bytes() == source


def test_tampered_backup_blocks_later_schema2_commits(tmp_path):
    store, _source = _install_schema1(tmp_path)
    migrated = store.commit_run("run-migrate", run_summary={"status": "complete"})
    state_before = (tmp_path / "project_state.json").read_bytes()
    backup = tmp_path / "project_state.pre-v89.schema1.json"
    backup.write_bytes(b'{"schema_version": 1')
    backup.chmod(0o600)

    with pytest.raises(ProjectStateCorrupt, match="does not match original state"):
        store.commit_run("run-after", run_summary={"status": "complete"})

    assert (tmp_path / "project_state.json").read_bytes() == state_before
    assert store.load()["revision"] == migrated["revision"]


def test_prepared_state_publish_backs_up_real_schema1_before_replace(tmp_path):
    project = tmp_path / "project"
    store, source = _install_schema1(project)
    before = store.preview()
    before_digest = hashlib.sha256(json.dumps(
        before, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), default=str,
    ).encode("utf-8")).hexdigest()

    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "project_state.json").write_text(
        json.dumps(before, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    shadow_store = ProjectStateStore(shadow)
    prepared = shadow_store.commit_run(
        "run-prepared", run_summary={"status": "complete"})

    published = store.commit_prepared_state(
        "run-prepared",
        prepared_state=prepared,
        commit_input_sha256=shadow_store.last_commit["commit_input_sha256"],
        expected_revision=0,
        expected_state_before_sha256=before_digest,
    )

    assert published == prepared
    assert (project / "project_state.pre-v89.schema1.json").read_bytes() == source


def test_schema1_backup_file_fsync_error_aborts_migration_and_is_retryable(
    tmp_path, monkeypatch,
):
    store, source = _install_schema1(tmp_path)
    backup_name = "project_state.pre-v89.schema1.json"
    original_open = os.open
    original_fsync = os.fsync
    backup_fds: set[int] = set()

    def tracking_open(path, flags, mode=0o777):
        fd = original_open(path, flags, mode)
        if os.fspath(path).endswith(backup_name):
            backup_fds.add(fd)
        return fd

    def fail_backup_fsync(fd):
        if fd in backup_fds:
            raise OSError("injected backup fsync failure")
        return original_fsync(fd)

    monkeypatch.setattr(os, "open", tracking_open)
    monkeypatch.setattr(os, "fsync", fail_backup_fsync)
    with pytest.raises(OSError, match="injected backup fsync failure"):
        store.commit_run("run-migrate", run_summary={"status": "complete"})

    assert (tmp_path / "project_state.json").read_bytes() == source
    monkeypatch.setattr(os, "open", original_open)
    monkeypatch.setattr(os, "fsync", original_fsync)
    migrated = store.commit_run("run-migrate", run_summary={"status": "complete"})
    assert migrated["schema_version"] == 3


def test_project_state_directory_fsync_error_is_not_swallowed_and_retry_is_idempotent(
    tmp_path, monkeypatch,
):
    store = ProjectStateStore(tmp_path, project_scope=[SCOPE])
    store.initialize()
    original_fsync = os.fsync

    def fail_directory_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("injected directory fsync failure")
        return original_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_directory_fsync)
    with pytest.raises(OSError, match="injected directory fsync failure"):
        store.commit_run("run-1", run_summary={"status": "complete"})

    monkeypatch.setattr(os, "fsync", original_fsync)
    recovered = store.commit_run("run-1", run_summary={"status": "complete"})
    assert recovered["revision"] == 1
    assert store.last_commit["idempotent"] is True


def test_project_state_hardlink_alias_is_rejected_as_authority_tampering(tmp_path):
    store = ProjectStateStore(tmp_path, project_scope=[SCOPE])
    store.initialize()
    authority = tmp_path / "project_state.json"
    alias = tmp_path / "model-writable-alias.json"
    os.link(authority, alias)

    with pytest.raises(ProjectStateCorrupt, match="multiple hard links"):
        store.load()
