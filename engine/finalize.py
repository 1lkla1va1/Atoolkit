"""Exactly-once finalization for Engine and externally wrapped Skill runs.

This module deliberately separates project truth from delivery projections.
The authority journal is the recovery source: a crash after project commit is
resumed forward and never disguised as an uncommitted run.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import pathlib
import secrets
import stat
from datetime import datetime, timezone
from typing import Any, Iterator

try:  # pragma: no cover - Windows is intentionally fail-closed below
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

try:  # Support both ``python -m engine.finalize`` and direct repo CLI use.
    from .project_state import ProjectStateError, ProjectStateStore, _default_state
    from .data_hygiene import sensitive_kinds
    from .reporting.render_md import render_final_report
    from .reporting.validate import validate_run_artifacts
    from .run_authority import (
        canonical_digest,
        ensure_project_identity,
        validate_session_id,
    )
    from .runtime_manifest import (
        verify_run_receipt,
        write_run_receipt,
    )
    from .safe_io import (
        atomic_write_bytes,
        atomic_write_json,
        create_json_exclusive,
        exclusive_file_lock,
        safe_read_bytes,
        UnsafePathError,
    )
    from .version import __version__
except ImportError:  # pragma: no cover - exercised by subprocess CLI tests
    from project_state import ProjectStateError, ProjectStateStore, _default_state
    from data_hygiene import sensitive_kinds
    from reporting.render_md import render_final_report
    from reporting.validate import validate_run_artifacts
    from run_authority import (
        canonical_digest,
        ensure_project_identity,
        validate_session_id,
    )
    from runtime_manifest import (
        verify_run_receipt,
        write_run_receipt,
    )
    from safe_io import (
        UnsafePathError,
        atomic_write_bytes,
        atomic_write_json,
        create_json_exclusive,
        exclusive_file_lock,
        safe_read_bytes,
    )
    from version import __version__


FINALIZATION_SCHEMA_VERSION = 1
STAGES = (
    "NEW",
    "INPUTS_SNAPSHOTTED",
    "GATES_EVALUATED",
    "PROJECT_PREPARED",
    "PROJECT_COMMITTED",
    "PROJECTIONS_WRITTEN",
    "RECEIPT_ANCHORED",
    "DELIVERY_WRITTEN",
)
_INPUT_FILES = (
    "run_manifest.json",
    "inventory.json",
    "coverage-ledger.json",
    "candidate-ledger.json",
    "dead_ends.json",
    "intents.json",
    "negative_findings.json",
)
_DERIVED_RUN_FILES = {
    "finding_validation.json",
    "miss-attribution.json",
    "next-run-agenda.json",
    "submission_status.json",
    "summary.json",
    "project_state_commit.json",
    "run_receipt.json",
    "delivery_status.json",
    "final_report.md",
    "draft_report.md",
}


class FinalizationError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _read_regular_bytes(
    path: pathlib.Path, *, trusted_root: pathlib.Path | None = None,
) -> bytes:
    """Read a single-link regular leaf through a dirfd-anchored path walk."""
    try:
        return safe_read_bytes(path, root=trusted_root)
    except (OSError, UnsafePathError) as exc:
        raise FinalizationError(f"unsafe snapshot input {path}: {exc}") from exc


def _read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(_read_regular_bytes(path).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FinalizationError(f"invalid JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise FinalizationError(f"JSON must be an object: {path}")
    return value


@contextlib.contextmanager
def _exclusive_lock(path: pathlib.Path) -> Iterator[None]:
    if fcntl is None:
        raise FinalizationError("platform lacks the required finalizer lock primitive")
    try:
        with exclusive_file_lock(path, root=path.parent.parent):
            yield
    except (OSError, UnsafePathError) as exc:
        raise FinalizationError(f"unsafe finalizer lock {path}: {exc}") from exc


def _journal_path(authority: pathlib.Path, session_id: str) -> pathlib.Path:
    return authority / "finalizations" / f"{session_id}.json"


def _write_journal(authority: pathlib.Path, journal: dict[str, Any]) -> None:
    journal["updated_at"] = _now()
    atomic_write_json(
        _journal_path(authority, str(journal["session_id"])), journal, root=authority,
    )


def _stage_index(value: str) -> int:
    try:
        return STAGES.index(value)
    except ValueError as exc:
        raise FinalizationError(f"unknown finalization stage: {value!r}") from exc


def _snapshot_copy(
    source: pathlib.Path,
    destination: pathlib.Path,
    *,
    source_root: pathlib.Path,
    authority: pathlib.Path,
) -> dict[str, Any]:
    payload = _read_regular_bytes(source, trusted_root=source_root)
    atomic_write_bytes(destination, payload, root=authority)
    return {
        "source": str(source),
        "snapshot": str(destination),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }


def _project_evidence_source(
    project: pathlib.Path, ref: str,
) -> tuple[pathlib.Path, pathlib.Path] | None:
    value = str(ref or "").strip()
    if value.startswith("session:"):
        relative = pathlib.Path("sessions") / value[len("session:"):]
    elif value.startswith("project:"):
        relative = pathlib.Path(value[len("project:"):])
    else:
        return None
    source = (project / relative).resolve(strict=False)
    try:
        relative = source.relative_to(project)
    except ValueError as exc:
        raise FinalizationError(f"project evidence escapes project root: {ref}") from exc
    return source, relative


def _snapshot_inputs(
    run_dir: pathlib.Path,
    project: pathlib.Path,
    authority: pathlib.Path,
    session_id: str,
    transaction_id: str,
) -> tuple[
    pathlib.Path,
    pathlib.Path,
    dict[str, dict[str, Any]],
    pathlib.Path,
]:
    """Freeze the complete run proof tree plus referenced project evidence.

    Validation and commit preparation use only this authority-owned mirror.
    Derived finalizer outputs are intentionally excluded and regenerated.
    """
    # Every attempt gets a fresh generation.  An interrupted generation is
    # never reused: only a complete, self-hashed seal can enter the journal.
    generation_id = secrets.token_hex(16)
    generation_root = (
        authority / "snapshot_generations" / session_id / generation_id)
    snapshot_project = generation_root / "input" / project.name
    snapshot_run = snapshot_project / "sessions" / session_id
    records: dict[str, dict[str, Any]] = {}
    for source in sorted(run_dir.rglob("*"), key=lambda item: item.as_posix()):
        relative = source.relative_to(run_dir)
        if (relative.parts
                and relative.parts[0] in {"final_report.md", "draft_report.md"}):
            continue
        try:
            info = source.lstat()
        except OSError as exc:
            raise FinalizationError(f"cannot inspect snapshot input {source}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise FinalizationError(f"snapshot input cannot be a symlink: {source}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise FinalizationError(f"snapshot input is not a regular file: {source}")
        if len(relative.parts) == 1 and relative.name in _DERIVED_RUN_FILES:
            continue
        key = f"run/{relative.as_posix()}"
        records[key] = _snapshot_copy(
            source, snapshot_run / relative,
            source_root=run_dir, authority=authority)

    project_state = project / "project_state.json"
    if project_state.is_file():
        records["project/project_state.json"] = _snapshot_copy(
            project_state, snapshot_project / "project_state.json",
            source_root=project, authority=authority)
        state = _read_json(project_state)
        refs: set[str] = set()
        for collection in (
            (state.get("cell_registry") or {}).values(),
            state.get("negatives") or [], state.get("dead_ends") or [],
        ):
            for item in collection:
                if isinstance(item, dict):
                    refs.update(str(x) for x in (item.get("evidence_refs") or []))
        for ref in sorted(refs):
            located = _project_evidence_source(project, ref)
            if located is None:
                continue
            source, relative = located
            if not source.is_file():
                raise FinalizationError(f"referenced project evidence is missing: {ref}")
            key = f"project/{relative.as_posix()}"
            if key not in records:
                records[key] = _snapshot_copy(
                    source, snapshot_project / relative,
                    source_root=project, authority=authority)
    seal_path = generation_root / "snapshot_seal.json"
    seal: dict[str, Any] = {
        "schema_version": 1,
        "transaction_id": str(transaction_id),
        "session_id": str(session_id),
        "generation_id": generation_id,
        "snapshot_project": str(snapshot_project),
        "snapshot_run": str(snapshot_run),
        "records_sha256": canonical_digest(records),
        "record_count": len(records),
    }
    seal["seal_sha256"] = canonical_digest(seal)
    if not create_json_exclusive(seal_path, seal, root=authority):
        raise FinalizationError("snapshot generation seal already exists")
    return snapshot_project, snapshot_run, records, seal_path


def _verify_snapshot_seal(
    *,
    authority: pathlib.Path,
    journal: dict[str, Any],
) -> tuple[pathlib.Path, pathlib.Path, dict[str, dict[str, Any]]]:
    seal_path = pathlib.Path(str(journal.get("snapshot_seal_path") or ""))
    try:
        seal_path.relative_to(authority)
    except ValueError as exc:
        raise FinalizationError("snapshot seal escapes authority") from exc
    if not seal_path.is_file() or seal_path.is_symlink():
        raise FinalizationError("snapshot generation seal is missing")
    seal = _read_json(seal_path)
    supplied = str(seal.get("seal_sha256") or "")
    canonical = dict(seal)
    canonical.pop("seal_sha256", None)
    if not supplied or supplied != canonical_digest(canonical):
        raise FinalizationError("snapshot generation seal digest mismatch")
    if (str(seal.get("transaction_id") or "")
            != str(journal.get("transaction_id") or "")
            or str(seal.get("session_id") or "")
            != str(journal.get("session_id") or "")):
        raise FinalizationError("snapshot generation seal identity mismatch")
    records = journal.get("input_snapshots") or {}
    if not isinstance(records, dict):
        raise FinalizationError("snapshot record index is invalid")
    if (int(seal.get("record_count", -1)) != len(records)
            or str(seal.get("records_sha256") or "") != canonical_digest(records)):
        raise FinalizationError("snapshot record index differs from sealed generation")
    snapshot_project = pathlib.Path(str(seal.get("snapshot_project") or ""))
    snapshot_run = pathlib.Path(str(seal.get("snapshot_run") or ""))
    if (str(journal.get("snapshot_project") or "") != str(snapshot_project)
            or str(journal.get("snapshot_run") or "") != str(snapshot_run)):
        raise FinalizationError("journal snapshot locator differs from seal")
    for record in records.values():
        if not isinstance(record, dict):
            raise FinalizationError("snapshot record is invalid")
        path = pathlib.Path(str(record.get("snapshot") or ""))
        try:
            path.relative_to(authority)
        except ValueError as exc:
            raise FinalizationError("snapshot record escapes authority") from exc
        payload = _read_regular_bytes(path, trusted_root=authority)
        if (hashlib.sha256(payload).hexdigest() != str(record.get("sha256") or "")
                or len(payload) != int(record.get("size", -1))):
            raise FinalizationError("sealed snapshot record changed")
    return snapshot_project, snapshot_run, records


def _load_list_file(path: pathlib.Path, *keys: str) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    value = _read_json(path)
    rows: Any = None
    for key in keys:
        if isinstance(value.get(key), list):
            rows = value[key]
            break
    if rows is None:
        return []
    return [dict(row) for row in rows if isinstance(row, dict)]


def _finding_inventory(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for finding in findings:
        endpoint = str(finding.get("endpoint") or "").strip()
        method = str(finding.get("method") or "").strip().upper()
        asset = str(finding.get("asset") or finding.get("target") or "").strip()
        if endpoint and method:
            records.append({
                "asset": asset,
                "endpoint": endpoint,
                "method": method,
                "params": list(finding.get("params") or []),
                "roles": list(finding.get("roles") or []),
                "source": "proof_valid_finding",
            })
    return records


def _prepare_commit_record(
    *,
    authority: pathlib.Path,
    session_id: str,
    project_id: str,
    revision_before: int,
    revision_after: int,
    state_before: dict[str, Any],
    state_after: dict[str, Any],
    delta: dict[str, Any],
) -> dict[str, Any]:
    commits = authority / "commits"
    previous_hash = ""
    head_path = commits / "HEAD.json"
    if head_path.is_file():
        previous_hash = str(_read_json(head_path).get("commit_sha256") or "")
    before_path = commits / "snapshots" / f"{session_id}.before.json"
    after_path = commits / "snapshots" / f"{session_id}.after.json"
    atomic_write_json(before_path, state_before, root=authority)
    atomic_write_json(after_path, state_after, root=authority)
    record: dict[str, Any] = {
        "schema_version": 1,
        "session_id": session_id,
        "project_id": project_id,
        "revision_before": revision_before,
        "revision_after": revision_after,
        "state_before_sha256": canonical_digest(state_before),
        "state_after_sha256": canonical_digest(state_after),
        "state_before_snapshot": str(before_path),
        "state_after_snapshot": str(after_path),
        "delta": delta,
        "previous_commit_sha256": previous_hash,
        "committed_at": _now(),
    }
    record["commit_sha256"] = canonical_digest(record)
    record_path = commits / f"{session_id}.json"
    return record


def _publish_commit_record(
    authority: pathlib.Path, record: dict[str, Any],
) -> None:
    """Publish a prepared commit exactly once and advance HEAD idempotently."""
    session_id = str(record.get("session_id") or "")
    if not session_id:
        raise FinalizationError("prepared commit has no session id")
    record_path = authority / "commits" / f"{session_id}.json"
    if not create_json_exclusive(record_path, record, root=authority):
        if _read_json(record_path) != record:
            raise FinalizationError("immutable project commit already differs")
    head_path = authority / "commits" / "HEAD.json"
    if head_path.is_file():
        head = _read_json(head_path)
        if head.get("commit_sha256") == record.get("commit_sha256"):
            return
        if str(head.get("commit_sha256") or "") != str(
                record.get("previous_commit_sha256") or ""):
            raise FinalizationError("project commit HEAD changed after prepare")
    atomic_write_json(head_path, record, root=authority)


def _project_state_or_empty(store: ProjectStateStore) -> dict[str, Any]:
    try:
        return store.load()
    except FileNotFoundError:
        return _default_state(store.project_scope)


def _clean_relative_evidence_ref(
    raw: Any, *, source_run: pathlib.Path, session_id: str,
) -> str | None:
    text = str(raw or "").strip()
    if not text:
        return None
    if text.startswith("project:"):
        return text
    if text.startswith("session:"):
        payload = text[len("session:"):]
        sid, separator, relative = payload.partition("/")
        if not separator or sid != session_id:
            return text
        candidate = pathlib.Path(relative)
    else:
        candidate = pathlib.Path(text)
        if candidate.is_absolute():
            try:
                candidate = candidate.resolve(strict=False).relative_to(source_run)
            except ValueError:
                return None
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    return (
        f"project:.atoolkit/evidence/{session_id}/"
        f"{candidate.as_posix()}"
    )


def _materialize_project_evidence(
    *,
    snapshot_run: pathlib.Path,
    project_dir: pathlib.Path,
    shadow_project: pathlib.Path,
    session_id: str,
    authority: pathlib.Path,
) -> None:
    for source in sorted(snapshot_run.rglob("*"), key=lambda item: item.as_posix()):
        if not source.is_file() or source.is_symlink():
            continue
        relative = source.relative_to(snapshot_run)
        payload = _read_regular_bytes(source, trusted_root=authority)
        project_target = (
            project_dir / ".atoolkit" / "evidence" / session_id / relative)
        atomic_write_bytes(project_target, payload, root=project_dir)
        shadow_target = (
            shadow_project / ".atoolkit" / "evidence" / session_id / relative)
        atomic_write_bytes(shadow_target, payload, root=authority)


def _frozen_commit_input(
    *,
    snapshot_run: pathlib.Path,
    source_run: pathlib.Path,
    session_id: str,
    validation: dict[str, Any],
    closure_pass: bool,
    runtime_summary: dict[str, Any] | None,
    include_findings: bool = True,
    include_continuations: bool = False,
) -> dict[str, Any] | None:
    findings = [
        dict(row) for row in (validation.get("normalized_findings") or [])
        if isinstance(row, dict)
    ] if include_findings else []
    for finding in findings:
        rewritten = [
            ref for ref in (
                _clean_relative_evidence_ref(
                    value, source_run=source_run, session_id=session_id)
                for value in (
                    finding.get("proof_files") or finding.get("evidence_refs") or [])
            ) if ref
        ]
        finding["proof_files"] = rewritten
        finding["evidence_refs"] = rewritten

    continuations = [
        dict(row) for row in (
            (validation.get("next_run_agenda") or {}).get("items") or [])
        if isinstance(row, dict)
    ] if include_continuations else []
    for continuation in continuations:
        continuation["source_run"] = session_id
        continuation["evidence_refs"] = [
            ref for ref in (
                _clean_relative_evidence_ref(
                    value, source_run=source_run, session_id=session_id)
                for value in (continuation.get("evidence_refs") or [])
            ) if ref
        ]

    full_commit = bool(closure_pass and include_findings)
    if full_commit:
        inventory = _load_list_file(
            snapshot_run / "inventory.json", "endpoints", "surfaces")
        negatives = _load_list_file(
            snapshot_run / "negative_findings.json", "negatives")
        dead_ends = _load_list_file(snapshot_run / "dead_ends.json", "dead_ends")
        intents = [
            item for item in _load_list_file(
                snapshot_run / "intents.json", "intents")
            if item.get("source") != "v9_host_continuation"
        ]
        by_id = {str(item.get("intent_id") or ""): item for item in intents}
        for continuation in continuations:
            if str(continuation.get("intent_id") or "") not in by_id:
                intents.append(continuation)
        for row in [*negatives, *dead_ends]:
            refs = list(row.get("evidence_refs") or [])
            if row.get("evidence_ref"):
                refs.append(row["evidence_ref"])
            rewritten = [
                ref for ref in (
                    _clean_relative_evidence_ref(
                        value, source_run=source_run, session_id=session_id)
                    for value in refs
                ) if ref
            ]
            row["evidence_refs"] = rewritten
            if rewritten:
                row["evidence_ref"] = rewritten[0]
        run_status = "complete"
    else:
        inventory, negatives, dead_ends, intents = [], [], [], continuations
        run_status = (
            "incomplete_with_findings" if findings else
            "incomplete_with_continuations" if continuations else "incomplete"
        )
    if not findings and not intents and not full_commit:
        return None
    if full_commit:
        submission_mode = "full"
    elif findings and continuations:
        submission_mode = "proof_roots_and_continuations"
    elif findings:
        submission_mode = "proof_roots"
    else:
        submission_mode = "continuations_only"
    return {
        "inventory": inventory,
        "findings": findings,
        "negatives": negatives,
        "dead_ends": dead_ends,
        "intents": intents,
        "run_summary": {
            **dict(runtime_summary or {}),
            "status": str((runtime_summary or {}).get("status") or run_status),
            "truth_submission_mode": submission_mode,
            "proof_confirmed_findings": len(findings),
            "host_continuations": len(continuations),
            "validation_sha256": validation.get("validation_sha256", ""),
        },
    }


def _prepare_project_truth(
    *,
    authority: pathlib.Path,
    project_dir: pathlib.Path,
    snapshot_run: pathlib.Path,
    source_run: pathlib.Path,
    session_id: str,
    project_id: str,
    validation: dict[str, Any],
    proof_pass: bool,
    continuation_pass: bool,
    closure_pass: bool,
    runtime_summary: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    store = ProjectStateStore(project_dir)
    before = _project_state_or_empty(store)
    revision_before = int(before.get("revision", 0) or 0)
    commit_input = _frozen_commit_input(
        snapshot_run=snapshot_run, source_run=source_run,
        session_id=session_id, validation=validation,
        closure_pass=closure_pass, runtime_summary=runtime_summary,
        include_findings=proof_pass,
        include_continuations=continuation_pass,
    ) if (proof_pass or continuation_pass) else None
    shadow = authority / "prepared" / session_id / "project"
    atomic_write_json(shadow / "project_state.json", before, root=authority)
    if commit_input is not None:
        _materialize_project_evidence(
            snapshot_run=snapshot_run, project_dir=project_dir,
            shadow_project=shadow, session_id=session_id, authority=authority)
        shadow_store = ProjectStateStore(shadow)
        after = shadow_store.commit_run(
            session_id, expected_revision=revision_before, **commit_input)
        meta = dict(shadow_store.last_commit or {})
        revision_after = int(after.get("revision", revision_before) or revision_before)
        mutated = revision_after != revision_before
        state_delta = dict(meta.get("delta") or {})
        commit_input_sha256 = str(meta.get("commit_input_sha256") or "")
    else:
        after = before
        revision_after = revision_before
        mutated = False
        state_delta = {}
        commit_input_sha256 = ""
    delta = {
        "outcome": validation.get("status", "invalid"),
        "proof_pass": proof_pass,
        "closure_pass": closure_pass,
        "finding_ids": [
            str(row.get("id") or "")
            for row in (validation.get("normalized_findings") or [])
            if isinstance(row, dict)
        ],
        "project_mutated": mutated,
        "state_delta": state_delta,
        "commit_input_sha256": commit_input_sha256,
    }
    record = _prepare_commit_record(
        authority=authority, session_id=session_id, project_id=project_id,
        revision_before=revision_before, revision_after=revision_after,
        state_before=before, state_after=after, delta=delta)
    return record, commit_input


def _apply_prepared_project_truth(
    *,
    project_dir: pathlib.Path,
    session_id: str,
    commit: dict[str, Any],
    commit_input: dict[str, Any] | None,
) -> None:
    if not bool((commit.get("delta") or {}).get("project_mutated")):
        return
    store = ProjectStateStore(project_dir)
    current = _project_state_or_empty(store)
    history = (current.get("run_history") or {}).get(session_id) or {}
    expected_input = str(
        (commit.get("delta") or {}).get("commit_input_sha256") or "")
    if history.get("commit_input_sha256") == expected_input:
        if (int(history.get("revision_before", -1))
                != int(commit.get("revision_before", -2))
                or int(history.get("revision_after", -1))
                != int(commit.get("revision_after", -2))):
            raise FinalizationError("applied project history differs from prepared commit")
        return
    if history.get("commit_input_sha256"):
        raise FinalizationError("same session already committed different project truth")
    if commit_input is None:
        raise FinalizationError("prepared project mutation has no frozen input")
    prepared_path = pathlib.Path(str(commit.get("state_after_snapshot") or ""))
    if not prepared_path.is_file():
        raise FinalizationError("prepared project state snapshot is missing")
    prepared_state = _read_json(prepared_path)
    if canonical_digest(prepared_state) != str(
            commit.get("state_after_sha256") or ""):
        raise FinalizationError("prepared project state snapshot digest mismatch")
    try:
        after = store.commit_prepared_state(
            session_id,
            prepared_state=prepared_state,
            commit_input_sha256=expected_input,
            expected_revision=int(commit.get("revision_before", 0) or 0),
            expected_state_before_sha256=str(
                commit.get("state_before_sha256") or ""),
        )
    except ProjectStateError as exc:
        raise FinalizationError(str(exc)) from exc
    if canonical_digest(after) != str(commit.get("state_after_sha256") or ""):
        raise FinalizationError("applied project state differs from prepared snapshot")


def _validate_prepared_commit(
    *,
    authority: pathlib.Path,
    commit: dict[str, Any],
    session_id: str,
    project_id: str,
) -> None:
    if (str(commit.get("session_id") or "") != str(session_id)
            or str(commit.get("project_id") or "") != str(project_id)):
        raise FinalizationError("prepared commit identity mismatch")
    supplied = str(commit.get("commit_sha256") or "")
    canonical = dict(commit)
    canonical.pop("commit_sha256", None)
    if not supplied or supplied != canonical_digest(canonical):
        raise FinalizationError("prepared commit digest mismatch")
    revision_before = int(commit.get("revision_before", -1))
    revision_after = int(commit.get("revision_after", -1))
    mutated = bool((commit.get("delta") or {}).get("project_mutated"))
    if (revision_before < 0
            or revision_after != revision_before + (1 if mutated else 0)):
        raise FinalizationError("prepared commit revision contract mismatch")
    for label in ("before", "after"):
        snapshot = pathlib.Path(str(commit.get(f"state_{label}_snapshot") or ""))
        try:
            snapshot.relative_to(authority)
        except ValueError as exc:
            raise FinalizationError(
                f"prepared {label} snapshot escapes authority") from exc
        value = _read_json(snapshot)
        if canonical_digest(value) != str(
                commit.get(f"state_{label}_sha256") or ""):
            raise FinalizationError(
                f"prepared {label} snapshot digest mismatch")


def _recover_pending_project_transactions(
    *,
    authority: pathlib.Path,
    project_dir: pathlib.Path,
    project_id: str,
) -> None:
    """Finish every prepared project transaction before admitting a new one.

    The project lock is held by the caller.  This prevents a later session
    from advancing project truth/HEAD past an applied-but-unpublished commit.
    Projection and receipt stages remain owned by the original session and
    are resumed when that session is invoked again.
    """
    root = authority / "finalizations"
    if not root.is_dir():
        return
    pending: list[tuple[int, str, pathlib.Path, dict[str, Any]]] = []
    for path in root.glob("*.json"):
        if path.is_symlink() or not path.is_file():
            raise FinalizationError("unsafe finalization journal entry")
        journal = _read_json(path)
        if str(journal.get("project_id") or "") != str(project_id):
            raise FinalizationError("finalization journal project identity mismatch")
        if str(journal.get("stage") or "") != "PROJECT_PREPARED":
            continue
        commit = journal.get("commit") or {}
        if not isinstance(commit, dict):
            raise FinalizationError("pending finalization commit is invalid")
        pending.append((
            int(commit.get("revision_before", -1)),
            str(journal.get("created_at") or ""),
            path,
            journal,
        ))
    for _revision, _created, _path, journal in sorted(pending):
        session_id = str(journal.get("session_id") or "")
        commit = dict(journal.get("commit") or {})
        commit_input_value = journal.get("commit_input")
        commit_input = (
            dict(commit_input_value)
            if isinstance(commit_input_value, dict) else None)
        _validate_prepared_commit(
            authority=authority,
            commit=commit,
            session_id=session_id,
            project_id=project_id,
        )
        _apply_prepared_project_truth(
            project_dir=project_dir,
            session_id=session_id,
            commit=commit,
            commit_input=commit_input,
        )
        _publish_commit_record(authority, commit)
        journal["stage"] = "PROJECT_COMMITTED"
        journal["recovered_pending_commit"] = True
        _write_journal(authority, journal)


def _gate_pass(validation: dict[str, Any], key: str, fallback: bool) -> bool:
    gate = validation.get(key)
    if isinstance(gate, dict):
        return gate.get("result") == "pass"
    return fallback


def _canonical_report_items(
    validation: dict[str, Any],
    *,
    snapshot_run: pathlib.Path,
    authority: pathlib.Path,
) -> list[dict[str, Any]]:
    """Reload only proof-confirmed raw Finding packages from frozen inputs."""
    items: list[dict[str, Any]] = []
    for record in validation.get("proof_confirmed") or []:
        if not isinstance(record, dict):
            raise FinalizationError("proof-confirmed report record is invalid")
        path = pathlib.Path(str(record.get("path") or "")).resolve(strict=False)
        try:
            path.relative_to(snapshot_run)
        except ValueError as exc:
            raise FinalizationError(
                f"proof-confirmed report path escapes snapshot: {path}") from exc
        try:
            finding = json.loads(
                _read_regular_bytes(path, trusted_root=authority).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FinalizationError(
                f"proof-confirmed finding is invalid JSON: {path}: {exc}") from exc
        if not isinstance(finding, dict):
            raise FinalizationError(f"proof-confirmed finding is not an object: {path}")
        items.append({"id": record.get("id"), "path": str(path), "finding": finding})
    return items


def _remove_report_projection(path: pathlib.Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise FinalizationError(f"cannot remove stale report projection {path}: {exc}") from exc


def _restore_canonical_report(
    *,
    run: pathlib.Path,
    authority: pathlib.Path,
    summary: dict[str, Any],
) -> bool:
    """Restore the journal-bound report and reject any changed authority copy."""
    status = str(summary.get("canonical_report_status") or "not_generated")
    report_path_text = str(summary.get("canonical_report_authority_path") or "")
    expected = str(summary.get("canonical_report_sha256") or "")
    _remove_report_projection(run / "final_report.md")
    _remove_report_projection(run / "draft_report.md")
    if status not in {"complete", "draft_incomplete"}:
        return False
    report_path = pathlib.Path(report_path_text)
    try:
        report_path.relative_to(authority)
    except ValueError as exc:
        raise FinalizationError("canonical report authority path escapes authority") from exc
    payload = _read_regular_bytes(report_path, trusted_root=authority)
    actual = hashlib.sha256(payload).hexdigest()
    if not expected or actual != expected:
        raise FinalizationError("canonical report differs from frozen summary")
    destination = run / (
        "final_report.md" if status == "complete" else "draft_report.md")
    atomic_write_bytes(destination, payload, root=run)
    return status == "complete"


def finalize_run(
    *,
    run_dir: str | pathlib.Path,
    project_dir: str | pathlib.Path,
    authority_dir: str | pathlib.Path,
    allow_empty: bool = False,
    authority_trusted: bool = True,
    authorization_assurance: str = "unverified",
    project_name: str = "target",
    primary_target: str = "",
    base_path: str = "/",
    base_path_explicit: bool = False,
    runtime_closure_pass: bool | None = None,
    runtime_summary: dict[str, Any] | None = None,
    crash_after_stage: str = "",
) -> dict[str, Any]:
    """Finalize a stopped run. Re-entry resumes without a second project commit."""
    run = pathlib.Path(run_dir).resolve()
    project = pathlib.Path(project_dir).resolve()
    authority = pathlib.Path(authority_dir).resolve()
    try:
        session_id = validate_session_id(run.name)
    except ValueError as exc:
        raise FinalizationError(str(exc)) from exc
    if authority == run or run in authority.parents:
        raise FinalizationError("authority cannot be inside the model-writable run directory")
    authority.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = authority / "locks" / f"{session_id}.lock"
    project_lock_path = authority / "locks" / "project.lock"
    with _exclusive_lock(lock_path), _exclusive_lock(project_lock_path):
        identity = ensure_project_identity(
            authority,
            project_dir=project,
            project_name=project_name,
            primary_target=primary_target,
            base_path=base_path,
            base_path_explicit=base_path_explicit,
        )
        _recover_pending_project_transactions(
            authority=authority,
            project_dir=project,
            project_id=identity["project_id"],
        )
        finalization_contract = {
            "allow_empty": bool(allow_empty),
            "authority_trusted": bool(authority_trusted),
            "authorization_assurance": str(authorization_assurance),
            "project_name": str(project_name),
            "primary_target": str(primary_target).strip(),
            "base_path": str(base_path or "/"),
            "base_path_explicit": bool(base_path_explicit),
            "runtime_closure_pass": (
                bool(runtime_closure_pass)
                if runtime_closure_pass is not None else None),
            "runtime_summary": dict(runtime_summary or {}),
        }
        journal_path = _journal_path(authority, session_id)
        if journal_path.is_file():
            journal = _read_json(journal_path)
            frozen_contract = journal.get("finalization_contract")
            if frozen_contract != finalization_contract:
                raise FinalizationError(
                    "finalization resume parameters differ from frozen contract")
        else:
            live_manifest = run / "run_manifest.json"
            manifest_sha256 = (
                hashlib.sha256(_read_regular_bytes(
                    live_manifest, trusted_root=run)).hexdigest()
                if live_manifest.is_file() else "")
            journal = {
                "schema_version": FINALIZATION_SCHEMA_VERSION,
                "transaction_id": canonical_digest({
                    "project_id": identity["project_id"],
                    "session_id": session_id,
                    "manifest_sha256": manifest_sha256,
                }),
                "project_id": identity["project_id"],
                "session_id": session_id,
                "manifest_sha256": manifest_sha256,
                "finalization_contract": finalization_contract,
                "stage": "NEW",
                "created_at": _now(),
            }
            _write_journal(authority, journal)
        expected_transaction = canonical_digest({
            "project_id": identity["project_id"],
            "session_id": session_id,
            "manifest_sha256": str(journal.get("manifest_sha256") or ""),
        })
        if (journal.get("transaction_id") != expected_transaction
                or str(journal.get("project_id") or "") != identity["project_id"]):
            raise FinalizationError("finalization journal transaction identity mismatch")

        def advance(stage: str, **values: Any) -> None:
            journal.update(values)
            journal["stage"] = stage
            _write_journal(authority, journal)
            if crash_after_stage == stage:
                raise FinalizationError(f"injected crash after {stage}")

        if _stage_index(journal["stage"]) < _stage_index("INPUTS_SNAPSHOTTED"):
            snapshot_project, snapshot_run, records, seal_path = _snapshot_inputs(
                run, project, authority, session_id,
                str(journal.get("transaction_id") or ""))
            manifest_record = records.get("run/run_manifest.json") or {}
            if (not manifest_record
                    or manifest_record.get("sha256") != journal.get("manifest_sha256")):
                raise FinalizationError("frozen manifest differs from transaction identity")
            advance(
                "INPUTS_SNAPSHOTTED",
                input_snapshots=records,
                snapshot_project=str(snapshot_project),
                snapshot_run=str(snapshot_run),
                snapshot_seal_path=str(seal_path),
            )

        snapshot_project, snapshot_run, _records = _verify_snapshot_seal(
            authority=authority, journal=journal)
        try:
            snapshot_run.relative_to(authority)
            snapshot_project.relative_to(authority)
        except ValueError as exc:
            raise FinalizationError("journal snapshot locator escapes authority") from exc
        if not snapshot_run.is_dir():
            raise FinalizationError("authority input snapshot is missing")
        snapshot_manifest = snapshot_run / "run_manifest.json"
        if (not snapshot_manifest.is_file()
                or hashlib.sha256(_read_regular_bytes(
                    snapshot_manifest, trusted_root=authority)).hexdigest()
                != journal.get("manifest_sha256")):
            raise FinalizationError("authority manifest snapshot is missing or changed")
        manifest_value = _read_json(snapshot_manifest)
        if str(manifest_value.get("authorization_assurance") or "unverified") != str(
                finalization_contract["authorization_assurance"]):
            raise FinalizationError(
                "finalization assurance differs from frozen manifest")
        validation_path = snapshot_run / "finding_validation.json"
        if _stage_index(journal["stage"]) < _stage_index("GATES_EVALUATED"):
            validation = validate_run_artifacts(
                snapshot_run,
                allow_empty=allow_empty,
                output_path=validation_path,
                expected_authority_dir=authority,
                expected_project_id=identity["project_id"],
                expected_project_name=project_name,
                source_run_dir=run,
            )
            advance(
                "GATES_EVALUATED",
                validation=validation,
                validation_sha256=validation.get("validation_sha256", ""),
                runtime_closure_pass=finalization_contract[
                    "runtime_closure_pass"],
                runtime_summary=finalization_contract["runtime_summary"],
            )
        else:
            validation = dict(journal.get("validation") or {})
        if (canonical_digest({
                key: value for key, value in validation.items()
                if key != "validation_sha256"
            }) != str(validation.get("validation_sha256") or "")):
            raise FinalizationError("frozen validation digest is invalid")
        # The journal is the WAL source; restore its authority-owned
        # validation projection before it is used as a receipt artifact.
        atomic_write_json(validation_path, validation, root=authority)

        proof_pass = _gate_pass(
            validation, "proof_gate",
            not validation.get("ingestion_errors") and not validation.get("proof_pending_or_rejected"),
        )
        closure_pass = _gate_pass(
            validation, "closure_gate",
            int(validation.get("exit_code", 3)) == 0,
        )
        frozen_runtime_closure = journal.get("runtime_closure_pass")
        if frozen_runtime_closure is not None:
            closure_pass = bool(closure_pass and frozen_runtime_closure)
        findings = list(validation.get("normalized_findings") or [])
        # Project truth is an authority mutation, not a diagnostic projection.
        # If the parent cannot prove execution containment, retain the frozen
        # evidence for inspection but do not merge it into cross-run truth.
        project_truth_proof_pass = bool(
            proof_pass and finalization_contract["authority_trusted"])
        miss_attribution = dict(validation.get("miss_attribution") or {})
        continuation_pass = bool(
            finalization_contract["authority_trusted"]
            and int(manifest_value.get("outcome_contract_version", 0) or 0) >= 1
            and miss_attribution.get("complete") is True
            and not validation.get("ingestion_errors")
            and validation.get("status") not in {"error", "precondition_missing"}
        )

        if _stage_index(journal["stage"]) < _stage_index("PROJECT_PREPARED"):
            commit, commit_input = _prepare_project_truth(
                authority=authority, project_dir=project,
                snapshot_run=snapshot_run, source_run=run,
                session_id=session_id, project_id=identity["project_id"],
                validation=validation, proof_pass=project_truth_proof_pass,
                continuation_pass=continuation_pass,
                closure_pass=closure_pass,
                runtime_summary=dict(journal.get("runtime_summary") or {}),
            )
            advance(
                "PROJECT_PREPARED", commit=commit,
                commit_input=commit_input,
            )

        if _stage_index(journal["stage"]) < _stage_index("PROJECT_COMMITTED"):
            commit = dict(journal.get("commit") or {})
            commit_input_value = journal.get("commit_input")
            commit_input = (
                dict(commit_input_value)
                if isinstance(commit_input_value, dict) else None)
            _validate_prepared_commit(
                authority=authority,
                commit=commit,
                session_id=session_id,
                project_id=identity["project_id"],
            )
            _apply_prepared_project_truth(
                project_dir=project, session_id=session_id,
                commit=commit, commit_input=commit_input)
            if crash_after_stage == "PROJECT_STATE_APPLIED":
                raise FinalizationError(
                    "injected crash after PROJECT_STATE_APPLIED")
            _publish_commit_record(authority, commit)
            advance("PROJECT_COMMITTED")

        commit = dict(journal.get("commit") or {})
        _validate_prepared_commit(
            authority=authority,
            commit=commit,
            session_id=session_id,
            project_id=identity["project_id"],
        )
        published_commit = authority / "commits" / f"{session_id}.json"
        if not published_commit.is_file() or _read_json(published_commit) != commit:
            raise FinalizationError("published project commit differs from journal")
        commit_projection = run / "project_state_commit.json"
        frozen_assurance = str(
            finalization_contract["authorization_assurance"])
        frozen_trusted = bool(finalization_contract["authority_trusted"])
        if _stage_index(journal["stage"]) < _stage_index("PROJECTIONS_WRITTEN"):
            # Session copies are projections only.  Their bytes always come
            # from the frozen authority inputs/journal.
            summary_status = str(validation.get("status") or "invalid")
            report_items = _canonical_report_items(
                validation, snapshot_run=snapshot_run, authority=authority)
            canonical_report_status = "not_generated"
            canonical_report_path: pathlib.Path | None = None
            if (proof_pass and closure_pass
                    and int(validation.get("exit_code", 3)) == 0):
                canonical_report_status = "complete"
                canonical_report_path = snapshot_run / "final_report.md"
                render_final_report(
                    report_items,
                    canonical_report_path,
                    target_name=str(manifest_value.get("primary_target") or "目标"),
                    status="complete",
                )
            elif proof_pass and report_items:
                canonical_report_status = "draft_incomplete"
                canonical_report_path = snapshot_run / "draft_report.md"
                render_final_report(
                    report_items,
                    canonical_report_path,
                    target_name=str(manifest_value.get("primary_target") or "目标"),
                    status="draft_incomplete",
                    session_gate=validation.get("closure_gate") or {},
                )
            canonical_report_sha256 = (
                hashlib.sha256(_read_regular_bytes(
                    canonical_report_path, trusted_root=authority)).hexdigest()
                if canonical_report_path is not None else "")
            summary = {
                "schema_version": 2,
                "atoolkit_version": __version__,
                "session_id": session_id,
                "project_id": identity["project_id"],
                "status": summary_status,
                "run_complete": closure_pass,
                "project_complete": False,
                "proof_gate": validation.get("proof_gate", {}),
                "closure_gate": validation.get("closure_gate", {}),
                "miss_attribution": {
                    key: value for key, value in (
                        validation.get("miss_attribution") or {}).items()
                    if key not in {"rows", "continuations"}
                },
                "next_run_agenda": {
                    "status": (validation.get("next_run_agenda") or {}).get(
                        "status", "no_work"),
                    "count": int((validation.get("next_run_agenda") or {}).get(
                        "count", 0) or 0),
                },
                "findings": findings,
                "finding_validation_path": str(validation_path),
                "finding_validation_projection_path": str(
                    run / "finding_validation.json"),
                "finding_validation_sha256": validation.get("validation_sha256", ""),
                "project_state_commit_path": str(commit_projection),
                "project_state_commit_sha256": commit.get("commit_sha256", ""),
                "authorization_assurance": frozen_assurance,
                "preexec_enforced": frozen_assurance == "preexec_enforced",
                "authority_trusted": frozen_trusted,
                "base_path": str(manifest_value.get("base_path") or "/"),
                "base_path_explicit": bool(
                    manifest_value.get("base_path_explicit", False)),
                "target_fingerprint": str(
                    manifest_value.get("target_fingerprint") or ""),
                "target_fingerprint_status": str(
                    manifest_value.get("target_fingerprint_status") or "unknown"),
                "run_plan_path": str(manifest_value.get("run_plan_path") or ""),
                "run_plan_sha256": str(
                    manifest_value.get("run_plan_sha256") or ""),
                "planning_mode": str(
                    manifest_value.get("planning_mode") or "legacy_risk"),
                "planning_degraded": bool(manifest_value.get(
                    "planning_degraded",
                    str(manifest_value.get("planning_mode") or "legacy_risk")
                    != "threat_model",
                )),
                "run_phase": str(manifest_value.get("run_phase") or "single"),
                "phase_parent": dict(manifest_value.get("phase_parent") or {}),
                "execution_provenance": dict(
                    manifest_value.get("execution_provenance") or {}),
                "canonical_report_required": bool(
                    manifest_value.get("canonical_report_required")),
                "canonical_report_status": canonical_report_status,
                "canonical_report_authority_path": (
                    str(canonical_report_path) if canonical_report_path else ""),
                "canonical_report_projection_path": (
                    str(run / "final_report.md")
                    if canonical_report_status == "complete" else
                    str(run / "draft_report.md")
                    if canonical_report_status == "draft_incomplete" else ""),
                "canonical_report_sha256": canonical_report_sha256,
            }
            atomic_write_json(run / "finding_validation.json", validation, root=run)
            atomic_write_json(
                run / "miss-attribution.json",
                validation.get("miss_attribution") or {}, root=run)
            atomic_write_json(
                run / "next-run-agenda.json",
                validation.get("next_run_agenda") or {}, root=run)
            atomic_write_json(commit_projection, commit, root=run)
            atomic_write_json(run / "summary.json", summary, root=run)
            advance("PROJECTIONS_WRITTEN", summary=summary)
        else:
            summary = dict(journal.get("summary") or {})

        if (str(summary.get("session_id") or "") != session_id
                or str(summary.get("project_id") or "") != identity["project_id"]
                or str(summary.get("authorization_assurance") or "")
                != frozen_assurance
                or bool(summary.get("authority_trusted")) != frozen_trusted
                or str(summary.get("project_state_commit_sha256") or "")
                != str(commit.get("commit_sha256") or "")):
            raise FinalizationError("frozen delivery summary binding mismatch")
        # Rebuild every model-writable projection on every resume.  A crash
        # after the journal advanced cannot turn a swapped projection into a
        # newly anchored receipt.
        atomic_write_json(run / "finding_validation.json", validation, root=run)
        atomic_write_json(
            run / "miss-attribution.json",
            validation.get("miss_attribution") or {}, root=run)
        atomic_write_json(
            run / "next-run-agenda.json",
            validation.get("next_run_agenda") or {}, root=run)
        atomic_write_json(commit_projection, commit, root=run)
        atomic_write_json(run / "summary.json", summary, root=run)
        canonical_report_complete = _restore_canonical_report(
            run=run, authority=authority, summary=summary)

        receipt_path = run / "run_receipt.json"
        anchor_path = authority / "receipts" / f"{session_id}.json"
        if _stage_index(journal["stage"]) < _stage_index("RECEIPT_ANCHORED"):
            artifacts = {
                "finding_validation": validation_path,
                "miss_attribution": snapshot_run / "miss-attribution.json",
                "next_run_agenda": snapshot_run / "next-run-agenda.json",
                "summary": run / "summary.json",
                "project_state_commit": commit_projection,
            }
            for name in ("inventory.json", "coverage-ledger.json", "candidate-ledger.json"):
                if (snapshot_run / name).is_file():
                    artifacts[name.removesuffix(".json").replace("-", "_")] = (
                        snapshot_run / name)
            if canonical_report_complete:
                artifacts["final_report"] = pathlib.Path(str(
                    summary.get("canonical_report_authority_path") or ""))
            receipt = write_run_receipt(
                receipt_path,
                manifest_path=snapshot_manifest,
                artifacts=artifacts,
                project_state_delta=commit.get("delta") or {},
                authorization_assurance=frozen_assurance,
                authority_trusted=frozen_trusted,
            )
            advance(
                "RECEIPT_ANCHORED", receipt=receipt,
                receipt_anchor_path=str(anchor_path))
        else:
            receipt = dict(journal.get("receipt") or {})
            supplied_receipt = str(receipt.get("receipt_sha256") or "")
            receipt_body = dict(receipt)
            receipt_body.pop("receipt_sha256", None)
            if (str(receipt.get("session_id") or "") != session_id
                    or not supplied_receipt
                    or supplied_receipt != canonical_digest(receipt_body)):
                raise FinalizationError("frozen receipt binding mismatch")
            atomic_write_json(receipt_path, receipt, root=run)

        if _stage_index(journal["stage"]) < _stage_index("DELIVERY_WRITTEN"):
            verification = verify_run_receipt(
                receipt_path, run_dir=run, authority_dir=authority,
            )
            integrity_valid = bool(verification.get("integrity_valid"))
            canonical_report_verified = bool(
                canonical_report_complete
                and "final_report" in (receipt.get("artifacts") or {})
                and "final_report" not in (
                    verification.get("missing_mandatory_artifacts") or [])
                and integrity_valid
            )
            assurance_eligible = frozen_assurance in {
                "preexec_enforced", "dry_run_no_network",
            }
            delivery_complete = bool(
                integrity_valid
                and verification.get("delivery_complete")
                and frozen_trusted
                and assurance_eligible
                and proof_pass
                and closure_pass
                and int(validation.get("exit_code", 3)) == 0
            )
            if delivery_complete:
                status, exit_code = "complete", 0
            elif not proof_pass or int(validation.get("exit_code", 3)) == 1:
                status, exit_code = "invalid", 1
            else:
                status, exit_code = "incomplete", 2
            delivery = {
                "schema_version": 2,
                "status": status,
                "exit_code": exit_code,
                "integrity_valid": integrity_valid,
                "delivery_complete": delivery_complete,
                "authority_trusted": frozen_trusted,
                "authorization_assurance": frozen_assurance,
                "preexec_enforced": frozen_assurance == "preexec_enforced",
                "validation_status": validation.get("status"),
                "proof_pass": proof_pass,
                "closure_pass": closure_pass,
                "attribution_complete": bool(
                    (validation.get("miss_attribution") or {}).get("complete")),
                "next_run_continuations": int(
                    (validation.get("next_run_agenda") or {}).get("count", 0) or 0),
                "receipt_verification": verification,
                "receipt_anchor_path": str(anchor_path),
                "canonical_report_verified": canonical_report_verified,
            }
            atomic_write_json(run / "delivery_status.json", delivery, root=run)
            advance("DELIVERY_WRITTEN", delivery=delivery)
        else:
            delivery = dict(journal.get("delivery") or {})
            if (bool(delivery.get("authority_trusted")) != frozen_trusted
                    or str(delivery.get("authorization_assurance") or "")
                    != frozen_assurance):
                raise FinalizationError("frozen delivery binding mismatch")
            atomic_write_json(run / "delivery_status.json", delivery, root=run)

        local_report = run / "final_report.md"
        report_sensitive_kinds = (
            sensitive_kinds(_read_regular_bytes(
                local_report, trusted_root=run).decode("utf-8", errors="ignore"))
            if local_report.is_file() else []
        )
        submission_eligible = bool(
            delivery.get("delivery_complete")
            and delivery.get("canonical_report_verified")
            and delivery.get("attribution_complete")
            and not report_sensitive_kinds)
        submission = {
            "schema_version": 1,
            "submission_contract_version": int(
                manifest_value.get("submission_contract_version", 0) or 0),
            "status": "eligible" if submission_eligible else "not_eligible",
            "eligible": submission_eligible,
            "session_id": session_id,
            "canonical_report_sha256": str(
                summary.get("canonical_report_sha256") or ""),
            "receipt_sha256": str(receipt.get("receipt_sha256") or ""),
            "sensitive_kinds": report_sensitive_kinds,
            "reasons": [
                reason for condition, reason in (
                    (not delivery.get("delivery_complete"), "delivery_incomplete"),
                    (not delivery.get("canonical_report_verified"),
                     "canonical_report_unverified"),
                    (not delivery.get("attribution_complete"),
                     "miss_attribution_incomplete"),
                    (bool(report_sensitive_kinds), "canonical_report_contains_sensitive_data"),
                ) if condition
            ],
        }
        atomic_write_json(run / "submission_status.json", submission, root=run)

        return delivery


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Atoolkit exactly-once finalizer")
    parser.add_argument("--run-dir", required=True, type=pathlib.Path)
    parser.add_argument("--project-dir", required=True, type=pathlib.Path)
    parser.add_argument("--authority-dir", required=True, type=pathlib.Path)
    parser.add_argument("--allow-empty", action="store_true")
    parser.add_argument("--authorization-assurance", default="unverified",
                        choices=["unverified", "unrestricted_user_accepted",
                                 "dry_run_no_network", "preexec_enforced"])
    parser.add_argument("--project-name", default="target")
    parser.add_argument("--primary-target", required=True)
    parser.add_argument("--base-path", default="/")
    parser.add_argument("--base-path-explicit", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = finalize_run(
            run_dir=args.run_dir,
            project_dir=args.project_dir,
            authority_dir=args.authority_dir,
            allow_empty=args.allow_empty,
            # A loose CLI invocation is self-authorized by definition.  Only
            # the Engine parent or skill_wrapper may call the library with a
            # trusted authority after constraining the agent writable root.
            authority_trusted=False,
            authorization_assurance=args.authorization_assurance,
            project_name=args.project_name,
            primary_target=args.primary_target,
            base_path=args.base_path,
            base_path_explicit=args.base_path_explicit,
        )
    except Exception as exc:  # noqa: BLE001 - CLI maps operational failures to 3
        print(json.dumps({"status": "error", "exit_code": 3,
                          "error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False))
        return 3
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return int(result.get("exit_code", 3))


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["FINALIZATION_SCHEMA_VERSION", "FinalizationError", "finalize_run", "main"]
