"""Host-owned project identity and frozen run-plan helpers for v8.9.

The session directory is model-writable.  Files in this module are intended to
live in the parent/host authority root and are inputs to finalization, not
claims made by the model itself.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Iterable

try:
    from .safe_io import (
        create_json_exclusive,
        exclusive_file_lock,
        safe_append_text,
        safe_read_text,
    )
    from .cell_identity import surface_assets
except ImportError:  # pragma: no cover - direct script fallback
    from safe_io import (
        create_json_exclusive,
        exclusive_file_lock,
        safe_append_text,
        safe_read_text,
    )
    from cell_identity import surface_assets


RUN_PLAN_SCHEMA_VERSION = 1
PROJECT_IDENTITY_SCHEMA_VERSION = 1

_UUID_SEGMENT_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX_SEGMENT_RE = re.compile(r"^[0-9a-fA-F]{12,}$")
_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_RESERVED_SESSION_IDS = frozenset({"head", "project"})


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def validate_session_id(value: str) -> str:
    """Validate one authority path component and reject global-name aliases.

    ``HEAD`` collides with the commit-chain pointer and ``project`` collides
    with the global project lock.  Case-folding is required because the
    default macOS filesystem is case-insensitive.
    """
    session_id = str(value or "").strip()
    if not _SESSION_ID_RE.fullmatch(session_id):
        raise ValueError(
            "session_id must be 1-128 path-safe ASCII characters")
    if session_id.casefold() in _RESERVED_SESSION_IDS:
        raise ValueError(
            f"session_id is reserved by the authority layout: {session_id!r}")
    return session_id


def canonical_method_resolution_key(
    item: dict[str, Any], fallback_asset: str = "",
) -> str:
    """Return the authority identity for an endpoint whose method is unknown.

    The key deliberately excludes method candidates and mutable scope flags.
    Both run-plan creation and final validation must call this function so a
    session-owned inventory file cannot silently shrink the frozen method
    resolution denominator.
    """
    assets = surface_assets(item, fallback_asset)
    asset = assets[0] if len(assets) == 1 else ""
    endpoint = str(item.get("endpoint") or item.get("path") or "").strip()
    endpoint = re.sub(r"^https?://[^/]+", "", endpoint, flags=re.I)
    endpoint = endpoint.split("#", 1)[0]
    path, separator, query = endpoint.partition("?")
    segments: list[str] = []
    for segment in path.split("/"):
        if (segment.isdigit() or _UUID_SEGMENT_RE.fullmatch(segment)
                or _HEX_SEGMENT_RE.fullmatch(segment)
                or (segment.startswith("{") and segment.endswith("}"))):
            segments.append("{}")
        else:
            segments.append(segment)
    normalized = "/".join(segments)
    if separator:
        query = re.sub(
            r"(=)(\d+|[0-9a-fA-F-]{12,})(?=&|$)", r"={}", query)
        normalized = f"{normalized}?{query}"
    return json.dumps({
        "asset": asset,
        "endpoint": normalized,
        "namespace": str(item.get("namespace") or ""),
        "subject_role": str(item.get("subject_role") or "").strip().lower(),
        "object_kind": str(item.get("object_kind") or "").strip().lower(),
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _load_authority_object(path: pathlib.Path, authority: pathlib.Path) -> dict[str, Any]:
    value = json.loads(safe_read_text(path, root=authority))
    if not isinstance(value, dict):
        raise ValueError(f"authority JSON must be an object: {path}")
    return value


def _run_plan_denominator(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in plan.items()
        if key not in {"created_at", "plan_sha256"}
    }


def ensure_project_identity(
    authority_dir: str | pathlib.Path,
    *,
    project_dir: str | pathlib.Path,
    project_name: str,
    primary_target: str,
    base_path: str = "/",
    base_path_explicit: bool = False,
) -> dict[str, Any]:
    """Create or verify a stable authority-owned project identity."""
    authority = pathlib.Path(authority_dir).resolve()
    project = pathlib.Path(project_dir).resolve()
    identity_path = authority / "project_identity.json"
    requested = {
        "project_name": str(project_name),
        "primary_target": str(primary_target).strip(),
        "base_path": str(base_path or "/"),
        "base_path_explicit": bool(base_path_explicit),
    }
    if identity_path.exists():
        identity = _load_authority_object(identity_path, authority)
        embedded = str(identity.get("identity_sha256") or "")
        canonical = dict(identity)
        canonical.pop("identity_sha256", None)
        if not embedded or embedded != canonical_digest(canonical):
            raise ValueError("project identity self-hash mismatch")
        for key, value in requested.items():
            if identity.get(key) != value:
                raise ValueError(
                    f"project identity mismatch for {key}: "
                    f"{identity.get(key)!r} != {value!r}"
                )
        if pathlib.Path(str(identity.get("project_dir_locator") or "")).resolve(
                strict=False) != project:
            raise ValueError(
                "project identity locator mismatch; explicit project rebind is required")
        return identity
    identity = {
        "schema_version": PROJECT_IDENTITY_SCHEMA_VERSION,
        "project_id": f"proj_{secrets.token_hex(16)}",
        **requested,
        # Locator only.  It is deliberately excluded from project_id.
        "project_dir_locator": str(project),
        "created_at": _now(),
    }
    identity["identity_sha256"] = canonical_digest(identity)
    if create_json_exclusive(identity_path, identity, root=authority):
        return identity
    # A concurrent initializer won the create-only race.  Validate and return
    # that stable identity instead of replacing it with a second project id.
    concurrent = _load_authority_object(identity_path, authority)
    for key, value in requested.items():
        if concurrent.get(key) != value:
            raise ValueError(
                f"project identity mismatch for {key}: "
                f"{concurrent.get(key)!r} != {value!r}")
    if pathlib.Path(str(concurrent.get("project_dir_locator") or "")).resolve(
            strict=False) != project:
        raise ValueError(
            "project identity locator mismatch; explicit project rebind is required")
    return concurrent


def create_run_plan(
    authority_dir: str | pathlib.Path,
    *,
    project_id: str,
    session_id: str,
    admitted_cells: Iterable[dict[str, Any] | str],
    method_resolution_items: Iterable[dict[str, Any]] = (),
    candidate_baseline: Iterable[dict[str, Any] | str] = (),
    budget: dict[str, Any] | None = None,
    identity_version: int = 2,
) -> dict[str, Any]:
    """Freeze this run's closure denominator before the model starts."""
    session_id = validate_session_id(session_id)
    authority = pathlib.Path(authority_dir).resolve()
    path = authority / "run_plans" / f"{session_id}.json"
    plan: dict[str, Any] = {
        "schema_version": RUN_PLAN_SCHEMA_VERSION,
        "project_id": str(project_id),
        "session_id": str(session_id),
        "identity_version": int(identity_version),
        "admitted_cells": list(admitted_cells),
        "method_resolution_items": list(method_resolution_items),
        "candidate_baseline": list(candidate_baseline),
        "budget": dict(budget or {}),
        "created_at": _now(),
    }
    plan["plan_sha256"] = canonical_digest(plan)
    # Publish only after a complete private inode has been written and fsynced.
    # This is create-only: a replay or concurrent initializer can never replace
    # the denominator selected by the first publisher.
    if create_json_exclusive(path, plan, root=authority):
        return plan
    existing = _load_authority_object(path, authority)
    expected_hash = canonical_digest({
        key: value for key, value in existing.items() if key != "plan_sha256"
    })
    if existing.get("plan_sha256") != expected_hash:
        raise ValueError("immutable run plan self-hash mismatch")
    if _run_plan_denominator(existing) != _run_plan_denominator(plan):
        raise ValueError("immutable run plan mismatch")
    return existing


def append_monotonic_event(
    authority_dir: str | pathlib.Path,
    *,
    session_id: str,
    stream: str,
    event: dict[str, Any],
) -> dict[str, Any]:
    """Append a hash-chained discovery/candidate/scope event."""
    session_id = validate_session_id(session_id)
    if stream not in {"discovery", "candidate", "scope_amendment", "failure"}:
        raise ValueError(f"unsupported authority event stream: {stream}")
    authority = pathlib.Path(authority_dir).resolve()
    path = authority / "events" / session_id / f"{stream}.jsonl"
    lock_path = authority / "event_locks" / session_id / f"{stream}.lock"
    # Reading the tail, choosing the sequence/hash and appending the record are
    # one critical section across both threads and processes.
    with exclusive_file_lock(lock_path, root=authority):
        previous = ""
        sequence = 1
        try:
            lines = safe_read_text(path, root=authority).splitlines()
        except FileNotFoundError:
            lines = []
        if lines:
            tail = json.loads(lines[-1])
            previous = str(tail.get("event_sha256") or "")
            sequence = int(tail.get("sequence", 0) or 0) + 1
        record: dict[str, Any] = {
            "schema_version": 1,
            "session_id": str(session_id),
            "stream": stream,
            "sequence": sequence,
            "previous_event_sha256": previous,
            "event": dict(event),
            "created_at": _now(),
        }
        record["event_sha256"] = canonical_digest(record)
        safe_append_text(
            path,
            json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n",
            root=authority,
        )
        return record


def run_plan_path(authority_dir: str | pathlib.Path, session_id: str) -> pathlib.Path:
    session_id = validate_session_id(session_id)
    return pathlib.Path(authority_dir).resolve() / "run_plans" / f"{session_id}.json"


def record_target_fingerprint(
    authority_dir: str | pathlib.Path,
    *,
    project_id: str,
    session_id: str,
    fingerprint: str,
) -> dict[str, Any]:
    """Record and compare a deployment fingerprint without changing truth.

    v8.9 deliberately reports ``changed_unapplied`` rather than automatically
    staling historical cells; that state transition remains a v8.9.1 task.
    """
    session_id = validate_session_id(session_id)
    value = str(fingerprint or "").strip()
    if not value:
        return {"status": "unknown", "fingerprint": "", "previous": ""}
    authority = pathlib.Path(authority_dir).resolve()
    root = authority / "target_fingerprints"
    path = root / f"{session_id}.json"
    if path.is_file():
        existing = _load_authority_object(path, authority)
        if (existing.get("project_id") != project_id
                or existing.get("session_id") != session_id
                or existing.get("fingerprint") != value):
            raise ValueError("immutable target fingerprint record mismatch")
        return existing
    prior_records: list[dict[str, Any]] = []
    if root.is_dir():
        for candidate in root.glob("*.json"):
            if candidate.name == path.name or candidate.is_symlink():
                continue
            try:
                item = _load_authority_object(candidate, authority)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if item.get("project_id") == project_id and item.get("fingerprint"):
                prior_records.append(item)
    prior_records.sort(
        key=lambda item: (str(item.get("created_at") or ""),
                          str(item.get("session_id") or "")))
    previous = str(prior_records[-1].get("fingerprint") or "") if prior_records else ""
    status = (
        "first_recorded" if not previous else
        "same" if previous == value else
        "changed_unapplied"
    )
    record: dict[str, Any] = {
        "schema_version": 1,
        "project_id": project_id,
        "session_id": session_id,
        "fingerprint": value,
        "previous": previous,
        "status": status,
        "created_at": _now(),
    }
    record["record_sha256"] = canonical_digest(record)
    if not create_json_exclusive(path, record, root=authority):
        concurrent = _load_authority_object(path, authority)
        if (concurrent.get("project_id") != project_id
                or concurrent.get("session_id") != session_id
                or concurrent.get("fingerprint") != value):
            raise ValueError("immutable target fingerprint record mismatch")
        return concurrent
    return record


__all__ = [
    "PROJECT_IDENTITY_SCHEMA_VERSION",
    "RUN_PLAN_SCHEMA_VERSION",
    "append_monotonic_event",
    "canonical_digest",
    "canonical_method_resolution_key",
    "create_run_plan",
    "ensure_project_identity",
    "record_target_fingerprint",
    "run_plan_path",
    "validate_session_id",
]
