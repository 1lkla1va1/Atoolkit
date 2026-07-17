"""Deterministic runtime provenance helpers for Atoolkit runs.

The manifest is local provenance, not a cryptographic signature.  Callers may
place the authoritative copy outside the model-writable session directory via
``authority_dir`` while retaining an identical session copy for portability.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import secrets
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Iterable

try:
    from .host_policy import authorization_scope_from_url, normalize_authorized_scopes
    from .safe_io import (
        atomic_write_json,
        create_json_exclusive,
        ensure_directory,
        exclusive_file_lock,
        safe_read_bytes,
        UnsafePathError,
    )
    from .run_authority import validate_session_id
    from .version import __version__
except ImportError:  # pragma: no cover - direct script fallback
    from host_policy import authorization_scope_from_url, normalize_authorized_scopes
    from safe_io import (
        atomic_write_json,
        create_json_exclusive,
        ensure_directory,
        exclusive_file_lock,
        safe_read_bytes,
        UnsafePathError,
    )
    from run_authority import validate_session_id
    from version import __version__


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(str(value).encode("utf-8"))


def sha256_file(path: str | pathlib.Path) -> str:
    """Hash one single-link regular file without following path aliases.

    Runtime provenance files are security boundaries, not generic content
    inputs.  A multiply-linked authority inode can otherwise be linked into a
    model-writable run and modified through that alias while both pathname
    copies still compare equal.
    """
    return hashlib.sha256(safe_read_bytes(path)).hexdigest()


def canonical_json_sha256(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return sha256_bytes(payload)


def _atomic_write_json(path: pathlib.Path, value: dict[str, Any]) -> pathlib.Path:
    # Kept as a private compatibility wrapper for older callers in this file.
    return atomic_write_json(path, value)


def _absolute_lexical(path: str | pathlib.Path) -> pathlib.Path:
    value = pathlib.Path(path).expanduser()
    if not value.is_absolute():
        value = pathlib.Path.cwd() / value
    return pathlib.Path(os.path.abspath(os.fspath(value)))


def load_manifest(path: str | pathlib.Path) -> dict[str, Any]:
    manifest_path = pathlib.Path(path)
    value: Any = None
    for attempt in range(51):
        try:
            value = json.loads(safe_read_bytes(manifest_path).decode("utf-8"))
            break
        except UnsafePathError as exc:
            # Atomic no-clobber publication briefly has link count 2, while a
            # concurrent atomic replacement can leave an already-open inode at
            # link count 0.  Retry only this bounded publication window;
            # persistent hard links remain a hard failure.
            if "multiple hard links" not in str(exc) or attempt >= 50:
                raise ValueError(
                    f"invalid runtime manifest {manifest_path}: {exc}") from exc
            time.sleep(0.002)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid runtime manifest {manifest_path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"runtime manifest must be an object: {manifest_path}")
    return value


def _run_git(source_root: pathlib.Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip()


def _source_files(source_root: pathlib.Path) -> list[pathlib.Path]:
    listed = _run_git(
        source_root, "ls-files", "--cached", "--others", "--exclude-standard",
    )
    if listed:
        candidates = [source_root / line for line in listed.splitlines() if line.strip()]
    else:
        candidates = list(source_root.rglob("*"))
    excluded = {".git", "runs", "__pycache__", ".pytest_cache"}
    return sorted(
        (path for path in candidates
         if path.is_file() and not any(part in excluded for part in path.relative_to(source_root).parts)),
        key=lambda path: path.relative_to(source_root).as_posix(),
    )


def source_tree_sha256(source_root: str | pathlib.Path) -> str:
    root = pathlib.Path(source_root).resolve()
    digest = hashlib.sha256()
    for path in _source_files(root):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        try:
            content_digest = bytes.fromhex(sha256_file(path))
        except (OSError, ValueError):
            continue
        digest.update(content_digest)
    return digest.hexdigest()


def _instruction_records(
    values: Iterable[dict[str, Any]] | None,
    source_root: pathlib.Path,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for value in values or []:
        raw_path = pathlib.Path(str(value.get("path") or "")).expanduser()
        path = raw_path if raw_path.is_absolute() else source_root / raw_path
        resolved = path.resolve(strict=False)
        record = {
            "kind": str(value.get("kind") or "instruction"),
            "path": str(resolved),
            "exists": resolved.is_file(),
            "sha256": sha256_file(resolved) if resolved.is_file() else "",
            "injected": bool(value.get("injected", False)),
        }
        if value.get("injected_sha256"):
            record["injected_sha256"] = str(value["injected_sha256"])
            record["file_matches_injected"] = (
                bool(record["sha256"])
                and record["sha256"] == record["injected_sha256"])
        records.append(record)
    return records


_MANIFEST_BASE_IDENTITY_FIELDS = (
    "mode",
    "project",
    "session_id",
    "primary_target",
    "authorized_scopes",
    "authz_sha256",
)
_MANIFEST_V2_IDENTITY_FIELDS = _MANIFEST_BASE_IDENTITY_FIELDS + (
    "project_id",
    "base_path",
    "base_path_explicit",
    "allow_paths",
    "deny_paths",
    "authorization_assurance",
    "target_fingerprint",
    "target_fingerprint_status",
    "run_plan_path",
    "run_plan_sha256",
)
_MANIFEST_V3_IDENTITY_FIELDS = _MANIFEST_V2_IDENTITY_FIELDS + (
    "execution_provenance",
    "planning_mode",
    "planning_degraded",
    "planning_artifacts",
    "canonical_report_required",
)
_MANIFEST_V4_IDENTITY_FIELDS = _MANIFEST_V3_IDENTITY_FIELDS + (
    "run_phase",
    "phase_parent",
)


def _assert_manifest_request_identity(
    existing: dict[str, Any], requested: dict[str, Any],
) -> None:
    """Require a replay/concurrent publisher to name the same stable run.

    Source revision, source-tree hash, instructions and timestamps deliberately
    remain properties of the first authority winner.  A recovery after an
    authority-only publish must project those frozen bytes even if the source
    tree changed before the parent restarted.
    """
    try:
        schema_version = int(existing.get("schema_version") or 0)
    except (TypeError, ValueError):
        schema_version = 0
    fields = (
        _MANIFEST_V4_IDENTITY_FIELDS
        if schema_version >= 4 else
        _MANIFEST_V3_IDENTITY_FIELDS
        if schema_version >= 3 else
        _MANIFEST_V2_IDENTITY_FIELDS
        if schema_version >= 2 else
        tuple(
            field for field in _MANIFEST_V2_IDENTITY_FIELDS
            if field in _MANIFEST_BASE_IDENTITY_FIELDS or field in existing
        )
    )
    mismatched = {
        field: {
            "existing": existing.get(field),
            "requested": requested.get(field),
        }
        for field in fields
        if existing.get(field) != requested.get(field)
    }
    if mismatched:
        raise ValueError(
            f"immutable runtime manifest identity mismatch: {mismatched}")


def validate_manifest_binding(
    manifest: dict[str, Any],
    *,
    run_dir: str | pathlib.Path,
    manifest_path: str | pathlib.Path | None = None,
    authority_dir: str | pathlib.Path | None = None,
) -> dict[str, Any]:
    """Validate run/session/authority identity without trusting session paths.

    Schema-1 manifests remain readable, but every schema uses the session-id
    and authority filename binding that prevents copying run A's manifest into
    run B.  Schema 2 additionally binds a random, authority-owned identity.
    """
    errors: list[dict[str, Any]] = []
    run_base = _absolute_lexical(run_dir)
    session_id = str(manifest.get("session_id") or "").strip()
    if not session_id or session_id != run_base.name:
        errors.append({
            "code": "manifest_session_mismatch",
            "expected": run_base.name,
            "actual": session_id,
            "reason": "manifest session_id must equal run directory name",
        })
    elif session_id:
        try:
            validate_session_id(session_id)
        except ValueError as exc:
            errors.append({
                "code": "manifest_session_reserved",
                "actual": session_id,
                "reason": str(exc),
            })

    session_manifest = (
        _absolute_lexical(manifest_path)
        if manifest_path is not None else run_base / "run_manifest.json"
    )
    authority_text = str(manifest.get("authority_path") or "").strip()
    authority_path = (
        _absolute_lexical(authority_text)
        if authority_text and pathlib.Path(authority_text).expanduser().is_absolute()
        else None
    )
    authority_manifest: dict[str, Any] | None = None
    if authority_path is None:
        errors.append({
            "code": "invalid_manifest_authority",
            "reason": "authority_path must be an absolute path",
        })
    else:
        try:
            authority_path.relative_to(run_base)
        except ValueError:
            pass
        else:
            errors.append({
                "code": "self_authorized_manifest",
                "reason": "authority manifest must be outside the run directory",
            })
        if authority_path == session_manifest:
            errors.append({
                "code": "self_authorized_manifest",
                "reason": "authority manifest cannot be the session projection",
            })
        expected_name = f"{session_id}.json" if session_id else ""
        if (authority_path.parent.name != "manifests"
                or not expected_name or authority_path.name != expected_name):
            errors.append({
                "code": "manifest_authority_binding_mismatch",
                "path": str(authority_path),
                "reason": "authority manifest path is not bound to this session",
            })
        if authority_dir is not None:
            expected_root = _absolute_lexical(authority_dir)
            if authority_path.parent.parent != expected_root:
                errors.append({
                    "code": "manifest_authority_root_mismatch",
                    "expected": str(expected_root),
                    "actual": str(authority_path.parent.parent),
                    "reason": "authority manifest is outside the requested authority root",
                })
        if not authority_path.is_file():
            errors.append({
                "code": "missing_manifest_authority",
                "path": str(authority_path),
                "reason": "authoritative manifest copy is missing",
            })
        else:
            try:
                authority_manifest = load_manifest(authority_path)
            except ValueError as exc:
                errors.append({
                    "code": "invalid_manifest_authority",
                    "path": str(authority_path),
                    "reason": str(exc),
                })
            else:
                if authority_manifest != manifest:
                    errors.append({
                        "code": "manifest_authority_mismatch",
                        "path": str(authority_path),
                        "reason": "session and authority manifests differ",
                    })

    try:
        schema_version = int(manifest.get("schema_version") or 0)
    except (TypeError, ValueError):
        schema_version = 0
        errors.append({
            "code": "invalid_manifest_schema_version",
            "reason": "manifest schema_version must be an integer",
        })
    authority_id = str(manifest.get("authority_id") or "").strip()
    identity_path: pathlib.Path | None = None
    if schema_version >= 2:
        identity_text = str(manifest.get("authority_identity_path") or "").strip()
        if authority_path is not None:
            expected_identity_path = authority_path.parent.parent / "authority_identity.json"
        else:
            expected_identity_path = None
        if not authority_id or not identity_text or not pathlib.Path(identity_text).is_absolute():
            errors.append({
                "code": "manifest_authority_identity_missing",
                "reason": "schema-2 manifest requires an authority identity",
            })
        else:
            identity_path = _absolute_lexical(identity_text)
            if expected_identity_path is None or identity_path != expected_identity_path:
                errors.append({
                    "code": "manifest_authority_identity_mismatch",
                    "reason": "authority identity path is not bound to authority_path",
                })
            if not identity_path.is_file():
                errors.append({
                    "code": "manifest_authority_identity_missing",
                    "path": str(identity_path),
                    "reason": "authority identity file is missing",
                })
            else:
                try:
                    identity = load_manifest(identity_path)
                except ValueError as exc:
                    errors.append({
                        "code": "manifest_authority_identity_invalid",
                        "path": str(identity_path),
                        "reason": str(exc),
                    })
                else:
                    if str(identity.get("authority_id") or "") != authority_id:
                        errors.append({
                            "code": "manifest_authority_identity_mismatch",
                            "path": str(identity_path),
                            "reason": "manifest authority_id differs from authority anchor",
                        })

    # A v8.9 run plan is an authority-owned closure denominator, not a
    # session-provided locator.  When present, bind its canonical location,
    # digest, project and session to the manifest so copying or editing either
    # side fails before proof/closure validation.
    run_plan_text = str(manifest.get("run_plan_path") or "").strip()
    run_plan_digest = str(manifest.get("run_plan_sha256") or "").strip()
    if run_plan_text:
        run_plan = _absolute_lexical(run_plan_text)
        expected_plan = (
            authority_path.parent.parent / "run_plans" / f"{session_id}.json"
            if authority_path is not None and session_id else None
        )
        if expected_plan is None or run_plan != expected_plan:
            errors.append({
                "code": "run_plan_binding_mismatch",
                "path": str(run_plan),
                "reason": "run plan path is not bound to authority/session",
            })
        elif not run_plan.is_file() or run_plan.is_symlink():
            errors.append({
                "code": "run_plan_missing",
                "path": str(run_plan),
                "reason": "authority run plan is missing or unsafe",
            })
        else:
            try:
                plan = load_manifest(run_plan)
            except ValueError as exc:
                errors.append({
                    "code": "run_plan_invalid", "path": str(run_plan),
                    "reason": str(exc),
                })
            else:
                try:
                    actual_digest = sha256_file(run_plan)
                except (OSError, ValueError) as exc:
                    actual_digest = ""
                    errors.append({
                        "code": "run_plan_unsafe",
                        "path": str(run_plan),
                        "reason": str(exc),
                    })
                if not run_plan_digest or actual_digest != run_plan_digest:
                    errors.append({
                        "code": "run_plan_digest_mismatch",
                        "expected": run_plan_digest,
                        "actual": actual_digest,
                        "reason": "authority run plan differs from manifest binding",
                    })
                if str(plan.get("session_id") or "") != session_id:
                    errors.append({
                        "code": "run_plan_session_mismatch",
                        "reason": "run plan session differs from manifest",
                    })
                project_id = str(manifest.get("project_id") or "")
                if not project_id or str(plan.get("project_id") or "") != project_id:
                    errors.append({
                        "code": "run_plan_project_mismatch",
                        "reason": "run plan project differs from manifest",
                    })
                embedded = str(plan.get("plan_sha256") or "")
                canonical_plan = dict(plan)
                canonical_plan.pop("plan_sha256", None)
                if not embedded or embedded != canonical_json_sha256(canonical_plan):
                    errors.append({
                        "code": "run_plan_self_hash_mismatch",
                        "reason": "run plan canonical digest is invalid",
                    })
    elif run_plan_digest:
        errors.append({
            "code": "run_plan_binding_mismatch",
            "reason": "run_plan_sha256 exists without run_plan_path",
        })

    planning_artifacts = manifest.get("planning_artifacts") or {}
    if not isinstance(planning_artifacts, dict):
        errors.append({
            "code": "planning_artifacts_invalid",
            "reason": "planning_artifacts must be an object",
        })
    else:
        for name, raw_record in sorted(planning_artifacts.items()):
            if not isinstance(raw_record, dict):
                errors.append({
                    "code": "planning_artifact_invalid",
                    "artifact": str(name),
                    "reason": "planning artifact record must be an object",
                })
                continue
            relative = pathlib.Path(str(raw_record.get("path") or ""))
            expected_digest = str(raw_record.get("sha256") or "")
            if (not relative.parts or relative.is_absolute()
                    or ".." in relative.parts):
                errors.append({
                    "code": "planning_artifact_path_invalid",
                    "artifact": str(name),
                    "path": str(relative),
                    "reason": "planning artifact must stay inside the run directory",
                })
                continue
            path = run_base / relative
            try:
                payload = safe_read_bytes(path, root=run_base)
            except (OSError, ValueError) as exc:
                errors.append({
                    "code": "planning_artifact_missing",
                    "artifact": str(name),
                    "path": str(path),
                    "reason": str(exc),
                })
                continue
            actual_digest = sha256_bytes(payload)
            if not expected_digest or actual_digest != expected_digest:
                errors.append({
                    "code": "planning_artifact_digest_mismatch",
                    "artifact": str(name),
                    "path": str(path),
                    "expected": expected_digest,
                    "actual": actual_digest,
                    "reason": "planning artifact differs from the frozen manifest",
                })

    run_phase = str(manifest.get("run_phase") or "single").strip().lower()
    planning_mode = str(
        manifest.get("planning_mode") or "legacy_risk").strip().lower()
    phase_parent = manifest.get("phase_parent") or {}
    if run_phase not in {"single", "planning", "attack"}:
        errors.append({
            "code": "run_phase_invalid",
            "reason": f"unsupported run_phase: {run_phase!r}",
        })
    if run_phase == "planning" and planning_mode != "threat_discovery":
        errors.append({
            "code": "planning_phase_mode_mismatch",
            "reason": "planning phase requires threat_discovery mode",
        })
    if planning_mode == "threat_discovery" and run_phase != "planning":
        errors.append({
            "code": "planning_phase_mode_mismatch",
            "reason": "threat_discovery mode requires planning phase",
        })
    parent_required = run_phase == "attack" and planning_mode == "threat_model"
    if parent_required and not isinstance(phase_parent, dict):
        errors.append({
            "code": "phase_parent_invalid",
            "reason": "two-stage attack requires a phase_parent object",
        })
        phase_parent = {}
    if parent_required:
        parent_session = str(phase_parent.get("session_id") or "").strip()
        parent_path_text = str(phase_parent.get("manifest_path") or "").strip()
        parent_digest = str(phase_parent.get("manifest_sha256") or "").strip()
        expected_session = f"{session_id}.planning"
        if parent_session != expected_session:
            errors.append({
                "code": "phase_parent_session_mismatch",
                "expected": expected_session,
                "actual": parent_session,
            })
        parent_path = _absolute_lexical(parent_path_text) if parent_path_text else None
        expected_parent = (
            authority_path.parent / f"{expected_session}.json"
            if authority_path is not None and session_id else None)
        if parent_path is None or expected_parent is None or parent_path != expected_parent:
            errors.append({
                "code": "phase_parent_path_mismatch",
                "expected": str(expected_parent or ""),
                "actual": str(parent_path or ""),
            })
        elif not parent_path.is_file() or parent_path.is_symlink():
            errors.append({
                "code": "phase_parent_missing",
                "path": str(parent_path),
            })
        else:
            try:
                payload = safe_read_bytes(
                    parent_path, root=parent_path.parent.parent)
                parent = json.loads(payload.decode("utf-8"))
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                errors.append({
                    "code": "phase_parent_invalid",
                    "path": str(parent_path),
                    "reason": str(exc),
                })
            else:
                actual = sha256_bytes(payload)
                if not parent_digest or parent_digest != actual:
                    errors.append({
                        "code": "phase_parent_digest_mismatch",
                        "expected": parent_digest,
                        "actual": actual,
                    })
                comparisons = {
                    "project_id": manifest.get("project_id"),
                    "primary_target": manifest.get("primary_target"),
                    "authorized_scopes": manifest.get("authorized_scopes"),
                    "base_path": manifest.get("base_path"),
                    "base_path_explicit": manifest.get("base_path_explicit"),
                    "allow_paths": manifest.get("allow_paths"),
                    "deny_paths": manifest.get("deny_paths"),
                    "authority_id": manifest.get("authority_id"),
                    "execution_provenance": manifest.get("execution_provenance"),
                }
                for field, expected in comparisons.items():
                    if parent.get(field) != expected:
                        errors.append({
                            "code": "phase_parent_identity_mismatch",
                            "field": field,
                        })
                if str(parent.get("run_phase") or "") != "planning":
                    errors.append({
                        "code": "phase_parent_not_planning",
                        "reason": "parent manifest is not a planning phase",
                    })
                if str(parent.get("planning_mode") or "") != "threat_discovery":
                    errors.append({
                        "code": "phase_parent_not_planning",
                        "reason": "parent manifest is not threat_discovery mode",
                    })
                if str(parent.get("authority_path") or "") != str(parent_path):
                    errors.append({
                        "code": "phase_parent_authority_mismatch",
                    })
                if (str(parent.get("run_phase") or "") == "planning"
                        and str(parent.get("planning_mode") or "")
                        == "threat_discovery"):
                    # Finalizer validates an immutable snapshot of the Attack
                    # run, where the Planning sibling is intentionally absent.
                    # Derive the live Planning session from the authority root,
                    # never from the caller-controlled snapshot location.
                    planning_run = (
                        authority_path.parent.parent.parent
                        / "sessions" / expected_session)
                    parent_binding = validate_manifest_binding(
                        parent, run_dir=planning_run)
                    for parent_error in parent_binding.get("errors") or []:
                        errors.append({
                            "code": "phase_parent_binding_invalid",
                            "parent_error": parent_error,
                        })
    elif phase_parent:
        errors.append({
            "code": "phase_parent_unexpected",
            "reason": "phase_parent is only valid for two-stage threat attacks",
        })

    return {
        "ok": not errors,
        "errors": errors,
        "authority_path": str(authority_path) if authority_path else "",
        "authority_manifest": authority_manifest,
        "authority_id": authority_id,
        "authority_identity_path": str(identity_path) if identity_path else "",
    }


_PROVENANCE_FIELDS = frozenset({"provider", "model", "adapter", "settings"})
_PROVENANCE_SETTING_FIELDS = frozenset({
    "temperature", "top_p", "seed", "reasoning_effort", "max_tokens",
})


def _normalize_execution_provenance(value: dict[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("execution_provenance must be an object")
    unknown = set(value) - _PROVENANCE_FIELDS
    if unknown:
        raise ValueError(
            f"execution_provenance contains forbidden fields: {sorted(unknown)}")
    settings = value.get("settings") or {}
    if not isinstance(settings, dict):
        raise ValueError("execution_provenance.settings must be an object")
    unknown_settings = set(settings) - _PROVENANCE_SETTING_FIELDS
    if unknown_settings:
        raise ValueError(
            "execution_provenance.settings contains forbidden fields: "
            f"{sorted(unknown_settings)}")
    normalized_settings: dict[str, Any] = {}
    for key, raw in sorted(settings.items()):
        if raw is not None and not isinstance(raw, (str, int, float, bool)):
            raise ValueError(
                f"execution_provenance.settings.{key} must be a scalar or null")
        normalized_settings[str(key)] = raw
    return {
        key: str(value.get(key) or "").strip()
        for key in ("provider", "model", "adapter")
        if str(value.get(key) or "").strip()
    } | ({"settings": normalized_settings} if settings else {})


def _planning_artifact_records(
    run_base: pathlib.Path,
    artifacts: dict[str, str | pathlib.Path],
) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for raw_name, raw_path in sorted(artifacts.items()):
        name = str(raw_name or "").strip()
        if (not name or pathlib.Path(name).name != name
                or name in {".", ".."}):
            raise ValueError(f"invalid planning artifact name: {name!r}")
        path = _absolute_lexical(raw_path)
        try:
            relative = path.relative_to(run_base)
        except ValueError as exc:
            raise ValueError(
                f"planning artifact must stay inside run directory: {path}") from exc
        try:
            payload = safe_read_bytes(path, root=run_base)
        except (OSError, ValueError) as exc:
            raise ValueError(f"invalid planning artifact {path}: {exc}") from exc
        records[name] = {
            "path": relative.as_posix(),
            "sha256": sha256_bytes(payload),
            "size": len(payload),
        }
    return records


def create_run_manifest(
    run_dir: str | pathlib.Path,
    *,
    mode: str,
    project: str,
    session_id: str,
    primary_target: str,
    authorized_scopes: list[str] | tuple[str, ...],
    authz: str = "",
    instruction_sources: Iterable[dict[str, Any]] | None = None,
    source_root: str | pathlib.Path | None = None,
    authority_dir: str | pathlib.Path | None = None,
    project_id: str = "",
    base_path: str = "/",
    base_path_explicit: bool = False,
    allow_paths: Iterable[str] | None = None,
    deny_paths: Iterable[str] | None = None,
    authorization_assurance: str = "unverified",
    target_fingerprint: str = "",
    target_fingerprint_status: str = "",
    run_plan_path: str | pathlib.Path | None = None,
    execution_provenance: dict[str, Any] | None = None,
    planning_mode: str = "legacy_risk",
    planning_degraded: bool | None = None,
    planning_artifacts: dict[str, str | pathlib.Path] | None = None,
    canonical_report_required: bool = False,
    run_phase: str = "single",
    phase_parent: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create the immutable-start provenance record and write it atomically."""
    run_base = _absolute_lexical(run_dir)
    session_id = validate_session_id(session_id)
    if not session_id or session_id != run_base.name:
        raise ValueError(
            "runtime manifest session_id must equal the run directory name: "
            f"{session_id!r} != {run_base.name!r}")
    ensure_directory(run_base)
    primary_scope = authorization_scope_from_url(primary_target)
    if not primary_scope:
        raise ValueError("primary_target must be an absolute HTTP(S) URL")
    scopes = normalize_authorized_scopes([
        primary_scope, *list(authorized_scopes or []),
    ])
    if not scopes:
        raise ValueError("authorized_scopes must contain at least the primary target")
    provenance = _normalize_execution_provenance(execution_provenance)
    normalized_planning_mode = str(planning_mode or "legacy_risk").strip()
    if normalized_planning_mode not in {
            "legacy_risk", "threat_model", "threat_discovery"}:
        raise ValueError(f"invalid planning_mode: {normalized_planning_mode!r}")
    normalized_phase = str(run_phase or "single").strip().lower()
    if normalized_phase not in {"single", "planning", "attack"}:
        raise ValueError(f"invalid run_phase: {normalized_phase!r}")
    if normalized_phase == "planning" and normalized_planning_mode != "threat_discovery":
        raise ValueError("planning phase requires planning_mode=threat_discovery")
    if normalized_planning_mode == "threat_discovery" and normalized_phase != "planning":
        raise ValueError("threat_discovery planning requires run_phase=planning")
    artifact_bindings = _planning_artifact_records(
        run_base, planning_artifacts or {})
    degraded = (
        normalized_planning_mode != "threat_model"
        if planning_degraded is None else bool(planning_degraded))
    if normalized_planning_mode == "threat_model" and degraded:
        raise ValueError("threat_model planning cannot be marked degraded")
    if normalized_planning_mode == "threat_model":
        missing_plan = {"feature-graph.json", "threat-model.json"} - set(artifact_bindings)
        if missing_plan:
            raise ValueError(
                f"threat_model planning requires frozen artifacts: {sorted(missing_plan)}")
    normalized_parent: dict[str, Any] = {}
    if phase_parent:
        if not isinstance(phase_parent, dict):
            raise ValueError("phase_parent must be an object")
        parent_session = str(phase_parent.get("session_id") or "").strip()
        parent_path_text = str(phase_parent.get("manifest_path") or "").strip()
        requested_parent_digest = str(
            phase_parent.get("manifest_sha256") or "").strip()
        if not parent_session or not parent_path_text:
            raise ValueError("phase_parent requires session_id and manifest_path")
        parent_path = _absolute_lexical(parent_path_text)
        if not parent_path.is_file() or parent_path.is_symlink():
            raise ValueError("phase_parent manifest is missing or unsafe")
        actual_parent_digest = sha256_file(parent_path)
        if (requested_parent_digest
                and requested_parent_digest != actual_parent_digest):
            raise ValueError("phase_parent manifest digest mismatch")
        normalized_parent = {
            "session_id": parent_session,
            "manifest_path": str(parent_path),
            "manifest_sha256": actual_parent_digest,
        }
    if normalized_phase == "attack" and normalized_planning_mode == "threat_model":
        if not normalized_parent:
            raise ValueError("two-stage threat attack requires phase_parent")
    elif normalized_parent:
        raise ValueError("phase_parent is only valid for a threat-model attack phase")
    requested_plan = (
        str(_absolute_lexical(run_plan_path)) if run_plan_path else "")
    requested: dict[str, Any] = {
        "mode": str(mode),
        "project": str(project),
        "project_id": str(project_id),
        "session_id": session_id,
        "primary_target": str(primary_target).strip(),
        "authorized_scopes": scopes,
        "base_path": str(base_path or "/"),
        "base_path_explicit": bool(base_path_explicit),
        "allow_paths": [str(value) for value in (allow_paths or [])],
        "deny_paths": [str(value) for value in (deny_paths or [])],
        "authorization_assurance": str(
            authorization_assurance or "unverified"),
        "target_fingerprint": str(target_fingerprint or ""),
        "target_fingerprint_status": (
            str(target_fingerprint_status)
            if str(target_fingerprint_status or "") else
            "recorded" if str(target_fingerprint or "") else "unknown"),
        "run_plan_path": requested_plan,
        "run_plan_sha256": (
            sha256_file(requested_plan) if requested_plan else ""),
        "execution_provenance": provenance,
        "planning_mode": normalized_planning_mode,
        "planning_degraded": degraded,
        "planning_artifacts": artifact_bindings,
        "canonical_report_required": bool(canonical_report_required),
        "run_phase": normalized_phase,
        "phase_parent": normalized_parent,
        "authz_sha256": sha256_text(authz),
    }
    manifest_path = run_base / "run_manifest.json"
    if manifest_path.is_file():
        existing = load_manifest(manifest_path)
        _assert_manifest_request_identity(existing, requested)
        binding = validate_manifest_binding(
            existing, run_dir=run_base, manifest_path=manifest_path,
            authority_dir=authority_dir,
        )
        if not binding["ok"]:
            raise ValueError(
                f"immutable runtime manifest authority is invalid: {binding['errors']}")
        return existing
    source = pathlib.Path(source_root or pathlib.Path(__file__).resolve().parents[1]).resolve()

    revision = _run_git(source, "rev-parse", "HEAD") or "unknown"
    git_status = _run_git(source, "status", "--porcelain=v1")
    if authority_dir is None:
        project_dir = (run_base.parent.parent
                       if run_base.parent.name == "sessions" else run_base.parent)
        authority_base = project_dir / ".atoolkit"
    else:
        authority_base = _absolute_lexical(authority_dir)
    ensure_directory(authority_base)
    identity_path = authority_base / "authority_identity.json"
    identity = {
        "schema_version": 1,
        "authority_id": secrets.token_hex(32),
        "created_at": _utc_now(),
    }
    if not create_json_exclusive(identity_path, identity, root=authority_base):
        identity = load_manifest(identity_path)
    authority_id = str(identity.get("authority_id") or "").strip()
    if not authority_id:
        raise ValueError("authority identity is missing authority_id")
    authority_path = authority_base / "manifests" / f"{session_id}.json"
    try:
        authority_path.resolve(strict=False).relative_to(run_base)
    except ValueError:
        pass
    else:
        raise ValueError("authority manifest must be outside the model-writable run directory")
    manifest: dict[str, Any] = {
        "schema_version": 4,
        "atoolkit_version": __version__,
        "source_revision": revision,
        "source_dirty": bool(git_status),
        "source_tree_sha256": source_tree_sha256(source),
        **requested,
        "preexec_enforced": (
            requested["authorization_assurance"] == "preexec_enforced"),
        "instruction_sources": _instruction_records(instruction_sources, source),
        "reporting_schema_version": 2,
        "project_state_schema_version": 2,
        "authority_path": str(authority_path),
        "authority_id": authority_id,
        "authority_identity_path": str(identity_path),
        "created_at": _utc_now(),
    }
    # The authority copy is the winner, never a replaceable projection.  A
    # complete private inode is fsynced before create-only publication.  A
    # concurrent/recovery loser must project the winner's exact bytes.
    if create_json_exclusive(authority_path, manifest, root=authority_base):
        winner = manifest
    else:
        winner = load_manifest(authority_path)
        _assert_manifest_request_identity(winner, requested)
    if manifest_path.is_file():
        session_value = load_manifest(manifest_path)
        if session_value != winner:
            raise ValueError(
                "immutable runtime manifest authority/session mismatch")
    elif authority_path != manifest_path:
        _atomic_write_json(manifest_path, winner)
    if load_manifest(manifest_path) != winner:
        raise ValueError("runtime manifest projection differs from authority winner")
    binding = validate_manifest_binding(
        winner, run_dir=run_base, manifest_path=manifest_path,
        authority_dir=authority_base,
    )
    if not binding["ok"]:  # pragma: no cover - defensive postcondition
        raise ValueError(f"runtime manifest binding failed: {binding['errors']}")
    return winner


MANDATORY_DELIVERY_ARTIFACTS = frozenset({
    "summary",
    "finding_validation",
    "inventory",
    "coverage_ledger",
    "candidate_ledger",
    "project_state_commit",
})


def mandatory_delivery_artifacts(manifest: dict[str, Any] | None = None) -> frozenset[str]:
    required = set(MANDATORY_DELIVERY_ARTIFACTS)
    if bool((manifest or {}).get("canonical_report_required")):
        required.add("final_report")
    return frozenset(required)


def _canonical_self_hash(value: dict[str, Any], field: str) -> str:
    payload = dict(value)
    payload.pop(field, None)
    return canonical_json_sha256(payload)


def _read_json_object(path: pathlib.Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(safe_read_bytes(path).decode("utf-8"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return value


def _build_project_state_commit(
    *,
    manifest: dict[str, Any],
    project_state_path: pathlib.Path | None,
    project_state_delta: dict[str, Any] | None,
) -> dict[str, Any]:
    state_after: dict[str, Any] | None = None
    source_sha256 = ""
    if project_state_path is not None:
        if not project_state_path.is_file():
            raise ValueError(f"project state artifact does not exist: {project_state_path}")
        state_after = _read_json_object(project_state_path, label="project state")
        source_sha256 = sha256_file(project_state_path)
    delta = dict(project_state_delta or {})
    commit: dict[str, Any] = {
        "schema_version": 1,
        "project": str(manifest.get("project") or ""),
        "project_id": str(manifest.get("project_id") or ""),
        "session_id": str(manifest.get("session_id") or ""),
        "authority_id": str(manifest.get("authority_id") or ""),
        "delta": delta,
        "delta_sha256": canonical_json_sha256(delta),
        "state_after": state_after,
        "state_after_sha256": (
            canonical_json_sha256(state_after) if state_after is not None else ""
        ),
        "source_project_state_sha256": source_sha256,
        "snapshot_complete": state_after is not None,
        # Stable across an idempotent receipt retry for the same run.
        "committed_at": str(manifest.get("created_at") or ""),
    }
    commit["commit_sha256"] = _canonical_self_hash(commit, "commit_sha256")
    return commit


def _write_project_state_commit(
    path: pathlib.Path,
    *,
    manifest: dict[str, Any],
    project_state_path: pathlib.Path | None,
    project_state_delta: dict[str, Any] | None,
) -> dict[str, Any]:
    commit = _build_project_state_commit(
        manifest=manifest,
        project_state_path=project_state_path,
        project_state_delta=project_state_delta,
    )
    atomic_write_json(path, commit, root=path.parent)
    return commit


def _validation_outcome(artifacts: dict[str, dict[str, Any]]) -> dict[str, Any]:
    record = artifacts.get("finding_validation")
    if not record:
        return {}
    path = pathlib.Path(str(record.get("path") or ""))
    if not path.is_file():
        return {}
    try:
        value = _read_json_object(path, label="finding validation")
    except ValueError:
        return {}
    return {
        "status": str(value.get("status") or ""),
        "exit_code": value.get("exit_code"),
        "proof_gate": value.get("proof_gate") or {},
        "closure_gate": value.get("closure_gate") or value.get("empty_gate") or {},
    }


def _outcome_is_deliverable(outcome: dict[str, Any]) -> bool:
    return bool(
        outcome.get("status") in {"valid", "empty_allowed"}
        and int(outcome.get("exit_code", -1)) == 0
        and (outcome.get("proof_gate") or {}).get("result") == "pass"
        and (outcome.get("closure_gate") or {}).get("result") == "pass"
    )


def write_run_receipt(
    output_path: str | pathlib.Path,
    *,
    manifest_path: str | pathlib.Path,
    artifacts: dict[str, str | pathlib.Path],
    project_state_delta: dict[str, Any] | None = None,
    authorization_assurance: str | None = None,
    authority_trusted: bool = False,
) -> dict[str, Any]:
    """Bind delivery artifacts to authority without binding mutable live state.

    The call signature is unchanged.  A legacy ``project_state`` artifact is
    converted into an immutable, run-local ``project_state_commit`` snapshot;
    the live ``project_state.json`` is never included in the receipt.
    Incomplete artifact sets still receive a diagnostic receipt, but cannot be
    reported as ``delivery_complete``.
    """
    session_manifest = _absolute_lexical(manifest_path)
    if not session_manifest.is_file():
        raise ValueError(f"manifest does not exist: {session_manifest}")
    manifest = load_manifest(session_manifest)
    manifest_assurance = str(
        manifest.get("authorization_assurance") or "unverified")
    assurance = str(authorization_assurance or manifest_assurance)
    if assurance != manifest_assurance:
        raise ValueError(
            "receipt authorization assurance differs from frozen manifest: "
            f"{assurance!r} != {manifest_assurance!r}")
    assurance_eligible = assurance in {"preexec_enforced", "dry_run_no_network"}
    run_base = session_manifest.parent
    binding = validate_manifest_binding(
        manifest, run_dir=run_base, manifest_path=session_manifest)
    if not binding["ok"]:
        raise ValueError(f"manifest authority binding failed: {binding['errors']}")
    manifest_file = pathlib.Path(str(binding["authority_path"]))
    authority_base = manifest_file.parent.parent

    output = _absolute_lexical(output_path)
    prepared_artifacts = dict(artifacts)
    live_project_state = prepared_artifacts.pop("project_state", None)
    generated_commit: tuple[pathlib.Path, dict[str, Any], bytes] | None = None
    if "project_state_commit" not in prepared_artifacts and (
        live_project_state is not None or project_state_delta is not None
    ):
        commit_path = output.parent / "project_state_commit.json"
        commit_value = _build_project_state_commit(
            manifest=manifest,
            project_state_path=(
                _absolute_lexical(live_project_state)
                if live_project_state is not None else None
            ),
            project_state_delta=project_state_delta,
        )
        commit_payload = (
            json.dumps(
                commit_value, ensure_ascii=False, indent=2, sort_keys=True,
            ) + "\n"
        ).encode("utf-8")
        generated_commit = (commit_path, commit_value, commit_payload)
        prepared_artifacts["project_state_commit"] = commit_path

    artifact_records: dict[str, dict[str, Any]] = {}
    for name, raw_path in sorted(prepared_artifacts.items()):
        path = _absolute_lexical(raw_path)
        if (generated_commit is not None
                and str(name) == "project_state_commit"
                and path == generated_commit[0]):
            artifact_records[str(name)] = {
                "path": str(path),
                "sha256": sha256_bytes(generated_commit[2]),
                "size": len(generated_commit[2]),
            }
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"receipt artifact does not exist: {path}")
        if str(name) == "project_state" or path.name == "project_state.json":
            raise ValueError("receipt must bind project_state_commit, not live project_state.json")
        payload = safe_read_bytes(path)
        artifact_records[str(name)] = {
            "path": str(path),
            "sha256": sha256_bytes(payload),
            "size": len(payload),
        }

    mandatory = mandatory_delivery_artifacts(manifest)
    missing = sorted(mandatory - set(artifact_records))
    outcome = _validation_outcome(artifact_records)
    commit_snapshot_complete = False
    commit_integrity_valid = False
    commit_value: dict[str, Any] = {}
    authority_chain_required = False
    authority_chain_valid = True
    authority_commit_path = pathlib.Path()
    authority_head_path = authority_base / "commits" / "HEAD.json"
    authority_commit_sha256 = ""
    commit_record = artifact_records.get("project_state_commit")
    if commit_record:
        expected_commit = {
            "expected_session_id": str(manifest.get("session_id") or ""),
            "expected_project_id": str(manifest.get("project_id") or ""),
            "expected_project": str(manifest.get("project") or ""),
            "expected_authority_id": str(manifest.get("authority_id") or ""),
        }
        if generated_commit is not None:
            commit_value = dict(generated_commit[1])
            commit_integrity_valid, commit_errors, commit_snapshot_complete = (
                _verify_project_state_commit_value(
                    commit_value, path=generated_commit[0],
                    **expected_commit,
                )
            )
        else:
            commit_value = _read_json_object(
                pathlib.Path(commit_record["path"]),
                label="project state commit",
            )
            commit_integrity_valid, commit_errors, commit_snapshot_complete = (
                _verify_project_state_commit_value(
                    commit_value,
                    path=pathlib.Path(commit_record["path"]),
                    **expected_commit,
                )
            )
        binding_reasons = {
            "commit_session_mismatch",
            "commit_project_mismatch",
            "commit_project_id_missing",
        }
        if any(item.get("reason") in binding_reasons for item in commit_errors):
            raise ValueError(
                f"project state commit binding mismatch: {commit_errors}")
        authority_commit_sha256 = str(commit_value.get("commit_sha256") or "")
        # Transactional finalizer commits use authority-owned before/after
        # snapshots.  Compatibility receipt commits embed state_after directly
        # and remain outside the authority commit chain.
        authority_chain_required = bool(
            commit_value.get("state_before_snapshot")
            or commit_value.get("state_after_snapshot")
        )
        if authority_chain_required:
            authority_commit_path = (
                authority_base / "commits" /
                f"{str(manifest.get('session_id') or '')}.json"
            )
            chain = _verify_authority_commit_chain(
                authority_base,
                target_commit=commit_value,
                expected_project_id=str(manifest.get("project_id") or ""),
                expected_session_id=str(manifest.get("session_id") or ""),
            )
            authority_chain_valid = bool(chain.get("ok"))
            commit_integrity_valid = bool(
                commit_integrity_valid and authority_chain_valid)
    validation_integrity_valid = False
    validation_record = artifact_records.get("finding_validation")
    if validation_record:
        try:
            try:
                from .reporting.validate import verify_validation_artifact
            except ImportError:  # pragma: no cover - direct script fallback
                from reporting.validate import verify_validation_artifact
            validation_value = _read_json_object(
                pathlib.Path(validation_record["path"]),
                label="finding validation")
            validation_base = pathlib.Path(
                str(validation_value.get("run_dir") or run_base)).resolve()
            try:
                validation_base.relative_to(authority_base)
            except ValueError:
                if validation_base != run_base.resolve():
                    raise ValueError(
                        "validation run_dir is outside run and authority roots")
            validation_integrity_valid = bool(verify_validation_artifact(
                validation_value, validation_base).get("ok"))
        except (ImportError, OSError, ValueError, json.JSONDecodeError):
            validation_integrity_valid = False
    delivery_complete = bool(
        not missing
        and commit_integrity_valid
        and commit_snapshot_complete
        and (not authority_chain_required or authority_chain_valid)
        and validation_integrity_valid
        and _outcome_is_deliverable(outcome)
        and bool(authority_trusted)
        and assurance_eligible)

    session_id = str(manifest.get("session_id") or "")
    anchor_path = authority_base / "receipts" / f"{session_id}.json"
    receipt: dict[str, Any] = {
        "schema_version": 2,
        "atoolkit_version": __version__,
        "session_id": session_id,
        "project_id": str(manifest.get("project_id") or ""),
        "run_dir": str(run_base),
        "authority_id": str(manifest.get("authority_id") or ""),
        "manifest_path": str(manifest_file),
        "manifest_sha256": sha256_file(manifest_file),
        "receipt_anchor_path": str(anchor_path),
        "authority_commit_chain_required": authority_chain_required,
        "authority_commit_path": (
            str(authority_commit_path) if authority_chain_required else ""),
        "authority_commit_sha256": authority_commit_sha256,
        "authority_head_path": (
            str(authority_head_path) if authority_chain_required else ""),
        "artifacts": artifact_records,
        "mandatory_artifacts": sorted(mandatory),
        "missing_mandatory_artifacts": missing,
        "validation_outcome": outcome,
        "project_state_delta_sha256": (
            canonical_json_sha256(project_state_delta)
            if project_state_delta is not None else ""
        ),
        "authority_trusted": bool(authority_trusted),
        "authorization_assurance": assurance,
        "preexec_enforced": assurance == "preexec_enforced",
        "delivery_complete": delivery_complete,
        # Use the immutable start timestamp so idempotent retries produce the
        # same receipt and can reuse the authority anchor.
        "created_at": str(manifest.get("created_at") or _utc_now()),
    }
    receipt["receipt_sha256"] = _canonical_self_hash(receipt, "receipt_sha256")

    anchor_base = {
        "schema_version": 2,
        "authority_id": receipt["authority_id"],
        "session_id": session_id,
        "project_id": receipt["project_id"],
        "manifest_sha256": receipt["manifest_sha256"],
        "receipt_sha256": receipt["receipt_sha256"],
        "project_state_commit_sha256": (
            artifact_records.get("project_state_commit", {}).get("sha256", "")),
        "authority_commit_sha256": receipt["authority_commit_sha256"],
        "authority_commit_chain_required": receipt[
            "authority_commit_chain_required"],
        "anchored_at": receipt["created_at"],
    }
    # Decide immutable authority truth before touching any run-local
    # projection.  A conflicting retry therefore cannot destroy the receipt
    # (or compatibility commit snapshot) protected by the existing anchor.
    anchor_head_path = authority_base / "receipts" / "HEAD.json"
    anchor_lock_path = authority_base / "locks" / "receipt-anchor.lock"
    with exclusive_file_lock(anchor_lock_path, root=authority_base):
        if anchor_path.is_file():
            anchor = _read_json_object(anchor_path, label="receipt anchor")
            supplied_anchor = str(anchor.get("anchor_sha256") or "")
            if (not supplied_anchor
                    or _canonical_self_hash(anchor, "anchor_sha256") != supplied_anchor
                    or any(anchor.get(key) != value
                           for key, value in anchor_base.items())):
                raise ValueError(
                    "immutable receipt anchor already exists with different content")
        else:
            previous_anchor_sha256 = ""
            if anchor_head_path.is_file():
                head = _read_json_object(
                    anchor_head_path, label="receipt anchor HEAD")
                previous_anchor_sha256 = str(head.get("anchor_sha256") or "")
                if (not previous_anchor_sha256
                        or _canonical_self_hash(head, "anchor_sha256")
                        != previous_anchor_sha256):
                    raise ValueError("receipt anchor HEAD self-hash mismatch")
            anchor = {
                **anchor_base,
                "previous_anchor_sha256": previous_anchor_sha256,
            }
            anchor["anchor_sha256"] = _canonical_self_hash(
                anchor, "anchor_sha256")
            if not create_json_exclusive(anchor_path, anchor, root=authority_base):
                raise ValueError("receipt anchor publication race")
            atomic_write_json(anchor_head_path, anchor, root=authority_base)
    if generated_commit is not None:
        atomic_write_json(
            generated_commit[0], generated_commit[1],
            root=generated_commit[0].parent,
        )
        if (sha256_file(generated_commit[0])
                != artifact_records["project_state_commit"]["sha256"]):
            raise ValueError("generated project state commit projection differs")
    atomic_write_json(output, receipt, root=output.parent)
    return receipt


def _verify_project_state_commit_value(
    commit: dict[str, Any],
    *,
    path: pathlib.Path,
    expected_session_id: str = "",
    expected_project_id: str = "",
    expected_project: str = "",
    expected_authority_id: str = "",
) -> tuple[bool, list[dict[str, Any]], bool]:
    mismatches: list[dict[str, Any]] = []
    expected = str(commit.get("commit_sha256") or "")
    if not expected or _canonical_self_hash(commit, "commit_sha256") != expected:
        mismatches.append({"path": str(path), "reason": "commit_digest_mismatch"})
    if (expected_session_id
            and str(commit.get("session_id") or "") != expected_session_id):
        mismatches.append({
            "path": str(path),
            "reason": "commit_session_mismatch",
            "expected": expected_session_id,
            "actual": str(commit.get("session_id") or ""),
        })
    if expected_project_id:
        actual_project_id = str(commit.get("project_id") or "")
        if actual_project_id:
            if actual_project_id != expected_project_id:
                mismatches.append({
                    "path": str(path),
                    "reason": "commit_project_mismatch",
                    "expected": expected_project_id,
                    "actual": actual_project_id,
                })
        else:
            # Legacy compatibility commits predate project_id but carry both
            # the authority identity and project name.  Accept that narrower
            # binding only when both frozen values match; all new commits bind
            # project_id directly.
            legacy_bound = bool(
                expected_authority_id
                and expected_project
                and str(commit.get("authority_id") or "") == expected_authority_id
                and str(commit.get("project") or "") == expected_project
            )
            if not legacy_bound:
                mismatches.append({
                    "path": str(path),
                    "reason": "commit_project_id_missing",
                    "expected": expected_project_id,
                })
    delta = commit.get("delta") if isinstance(commit.get("delta"), dict) else {}
    delta_sha = str(commit.get("delta_sha256") or "")
    if delta_sha and canonical_json_sha256(delta) != delta_sha:
        mismatches.append({"path": str(path), "reason": "commit_delta_digest_mismatch"})
    state_after = commit.get("state_after")
    snapshot_complete = isinstance(state_after, dict)
    if isinstance(state_after, dict):
        if canonical_json_sha256(state_after) != str(commit.get("state_after_sha256") or ""):
            mismatches.append({"path": str(path), "reason": "commit_snapshot_digest_mismatch"})
    else:
        # The transactional finalizer stores authority-owned content snapshots
        # by path instead of duplicating the entire project state in the
        # session projection.  Both forms are immutable receipt inputs.
        snapshot_ref = str(commit.get("state_after_snapshot") or "").strip()
        snapshot_path = pathlib.Path(snapshot_ref) if snapshot_ref else None
        if snapshot_path is not None and snapshot_path.is_absolute() and snapshot_path.is_file():
            try:
                snapshot = _read_json_object(snapshot_path, label="project state snapshot")
            except ValueError as exc:
                mismatches.append({"path": str(snapshot_path), "reason": str(exc)})
            else:
                snapshot_complete = True
                if canonical_json_sha256(snapshot) != str(commit.get("state_after_sha256") or ""):
                    mismatches.append({"path": str(snapshot_path),
                                       "reason": "commit_snapshot_digest_mismatch"})
        elif commit.get("state_after_sha256"):
            mismatches.append({"path": str(path), "reason": "commit_snapshot_contract_mismatch"})
    if commit.get("snapshot_complete") is False:
        snapshot_complete = False
    return not mismatches, mismatches, snapshot_complete


def _verify_project_state_commit(
    path: pathlib.Path,
    *,
    expected_session_id: str = "",
    expected_project_id: str = "",
    expected_project: str = "",
    expected_authority_id: str = "",
) -> tuple[bool, list[dict[str, Any]], bool]:
    try:
        commit = _read_json_object(path, label="project state commit")
    except ValueError as exc:
        return False, [{"path": str(path), "reason": str(exc)}], False
    return _verify_project_state_commit_value(
        commit,
        path=path,
        expected_session_id=expected_session_id,
        expected_project_id=expected_project_id,
        expected_project=expected_project,
        expected_authority_id=expected_authority_id,
    )


def _verify_authority_commit_chain(
    authority_base: pathlib.Path,
    *,
    target_commit: dict[str, Any],
    expected_project_id: str,
    expected_session_id: str,
) -> dict[str, Any]:
    """Verify that a transactional commit is immutable and reachable from HEAD.

    A receipt-local commit projection is not authority by itself.  The exact
    record must exist in ``authority/commits/<session>.json`` and the current
    authority HEAD must reach it through a self-hashed, state-continuous chain.
    Older receipts therefore remain valid after HEAD advances, while deleting
    either their record or any later link fails closed.
    """
    authority = _absolute_lexical(authority_base)
    commits_root = authority / "commits"
    mismatches: list[dict[str, Any]] = []
    target_sha256 = str(target_commit.get("commit_sha256") or "")
    expected_target_path = commits_root / f"{expected_session_id}.json"
    index: dict[str, tuple[pathlib.Path, dict[str, Any]]] = {}

    if not commits_root.is_dir() or commits_root.is_symlink():
        return {
            "ok": False,
            "target_reachable": False,
            "mismatches": [{
                "path": str(commits_root),
                "reason": "authority_commit_directory_missing",
            }],
        }

    for path in sorted(commits_root.glob("*.json"), key=lambda item: item.name):
        if path.name == "HEAD.json":
            continue
        try:
            commit = _read_json_object(path, label="authority commit")
        except ValueError as exc:
            mismatches.append({
                "path": str(path),
                "reason": "authority_commit_record_invalid",
                "detail": str(exc),
            })
            continue
        commit_sha256 = str(commit.get("commit_sha256") or "")
        session_id = str(commit.get("session_id") or "")
        try:
            validate_session_id(session_id)
        except ValueError as exc:
            mismatches.append({
                "path": str(path),
                "reason": "authority_commit_session_invalid",
                "detail": str(exc),
            })
        if path.name != f"{session_id}.json":
            mismatches.append({
                "path": str(path),
                "reason": "authority_commit_filename_mismatch",
            })
        if (not commit_sha256
                or _canonical_self_hash(commit, "commit_sha256") != commit_sha256):
            mismatches.append({
                "path": str(path),
                "reason": "authority_commit_digest_mismatch",
            })
        if str(commit.get("project_id") or "") != expected_project_id:
            mismatches.append({
                "path": str(path),
                "reason": "authority_commit_project_mismatch",
            })
        delta = commit.get("delta") if isinstance(commit.get("delta"), dict) else {}
        mutated = bool(delta.get("project_mutated"))
        try:
            revision_before = int(commit.get("revision_before", -1))
            revision_after = int(commit.get("revision_after", -1))
        except (TypeError, ValueError):
            revision_before = revision_after = -1
        if (revision_before < 0
                or revision_after != revision_before + (1 if mutated else 0)):
            mismatches.append({
                "path": str(path),
                "reason": "authority_commit_revision_mismatch",
            })
        for label in ("before", "after"):
            snapshot = pathlib.Path(str(
                commit.get(f"state_{label}_snapshot") or ""))
            try:
                snapshot.relative_to(authority)
            except ValueError:
                mismatches.append({
                    "path": str(snapshot),
                    "reason": "authority_commit_snapshot_outside_authority",
                })
                continue
            try:
                value = _read_json_object(
                    snapshot, label=f"authority {label} state snapshot")
            except ValueError as exc:
                mismatches.append({
                    "path": str(snapshot),
                    "reason": "authority_commit_snapshot_invalid",
                    "detail": str(exc),
                })
                continue
            if canonical_json_sha256(value) != str(
                    commit.get(f"state_{label}_sha256") or ""):
                mismatches.append({
                    "path": str(snapshot),
                    "reason": "authority_commit_snapshot_digest_mismatch",
                })
        if commit_sha256:
            if commit_sha256 in index:
                mismatches.append({
                    "path": str(path),
                    "reason": "authority_commit_duplicate_digest",
                })
            else:
                index[commit_sha256] = (path, commit)

    head_path = commits_root / "HEAD.json"
    try:
        head = _read_json_object(head_path, label="authority commit HEAD")
    except ValueError as exc:
        mismatches.append({
            "path": str(head_path),
            "reason": "authority_commit_head_invalid",
            "detail": str(exc),
        })
        head = {}
    head_sha256 = str(head.get("commit_sha256") or "")
    indexed_head = index.get(head_sha256)
    if (not head_sha256
            or _canonical_self_hash(head, "commit_sha256") != head_sha256
            or indexed_head is None
            or indexed_head[1] != head):
        mismatches.append({
            "path": str(head_path),
            "reason": "authority_commit_head_mismatch",
        })

    target_record = index.get(target_sha256)
    if (not target_sha256 or target_record is None
            or target_record[0] != expected_target_path
            or target_record[1] != target_commit):
        mismatches.append({
            "path": str(expected_target_path),
            "reason": "authority_commit_target_mismatch",
        })

    reachable = False
    current = head if indexed_head is not None else {}
    seen: set[str] = set()
    while current:
        current_sha256 = str(current.get("commit_sha256") or "")
        if not current_sha256 or current_sha256 in seen:
            mismatches.append({
                "path": str(head_path),
                "reason": "authority_commit_chain_cycle",
            })
            break
        seen.add(current_sha256)
        if current_sha256 == target_sha256:
            reachable = True
            break
        previous_sha256 = str(current.get("previous_commit_sha256") or "")
        if not previous_sha256:
            break
        previous_record = index.get(previous_sha256)
        if previous_record is None:
            mismatches.append({
                "path": str(head_path),
                "reason": "authority_commit_chain_missing_link",
                "commit_sha256": previous_sha256,
            })
            break
        previous = previous_record[1]
        try:
            current_revision = int(current.get("revision_before", -1))
            previous_revision = int(previous.get("revision_after", -2))
        except (TypeError, ValueError):
            current_revision, previous_revision = -1, -2
        if (current_revision != previous_revision
                or str(current.get("state_before_sha256") or "")
                != str(previous.get("state_after_sha256") or "")):
            mismatches.append({
                "path": str(previous_record[0]),
                "reason": "authority_commit_chain_state_mismatch",
            })
            break
        current = previous
    if not reachable:
        mismatches.append({
            "path": str(expected_target_path),
            "reason": "authority_commit_not_reachable_from_head",
        })
    return {
        "ok": not mismatches,
        "target_reachable": reachable,
        "head_commit_sha256": head_sha256,
        "target_commit_sha256": target_sha256,
        "mismatches": mismatches,
    }


def _verify_receipt_anchor_chain(
    authority_base: pathlib.Path,
    *,
    target_anchor: dict[str, Any],
    expected_authority_id: str,
    expected_project_id: str,
) -> dict[str, Any]:
    """Verify that an immutable receipt anchor is reachable from anchor HEAD."""
    authority = _absolute_lexical(authority_base)
    receipts_root = authority / "receipts"
    mismatches: list[dict[str, Any]] = []
    index: dict[str, tuple[pathlib.Path, dict[str, Any]]] = {}
    if not receipts_root.is_dir() or receipts_root.is_symlink():
        return {
            "ok": False,
            "target_reachable": False,
            "mismatches": [{
                "path": str(receipts_root),
                "reason": "receipt_anchor_directory_missing",
            }],
        }
    for path in sorted(receipts_root.glob("*.json"), key=lambda item: item.name):
        if path.name == "HEAD.json":
            continue
        try:
            anchor = _read_json_object(path, label="receipt anchor")
        except ValueError as exc:
            mismatches.append({
                "path": str(path), "reason": "receipt_anchor_record_invalid",
                "detail": str(exc),
            })
            continue
        digest = str(anchor.get("anchor_sha256") or "")
        if (not digest
                or _canonical_self_hash(anchor, "anchor_sha256") != digest):
            mismatches.append({
                "path": str(path), "reason": "receipt_anchor_digest_mismatch",
            })
        if str(anchor.get("authority_id") or "") != expected_authority_id:
            mismatches.append({
                "path": str(path), "reason": "receipt_anchor_authority_mismatch",
            })
        if str(anchor.get("project_id") or "") != expected_project_id:
            mismatches.append({
                "path": str(path), "reason": "receipt_anchor_project_mismatch",
            })
        session_id = str(anchor.get("session_id") or "")
        try:
            validate_session_id(session_id)
        except ValueError:
            mismatches.append({
                "path": str(path), "reason": "receipt_anchor_session_invalid",
            })
        if path.name != f"{session_id}.json":
            mismatches.append({
                "path": str(path), "reason": "receipt_anchor_filename_mismatch",
            })
        if digest:
            if digest in index:
                mismatches.append({
                    "path": str(path), "reason": "receipt_anchor_duplicate_digest",
                })
            else:
                index[digest] = (path, anchor)

    head_path = receipts_root / "HEAD.json"
    try:
        head = _read_json_object(head_path, label="receipt anchor HEAD")
    except ValueError as exc:
        mismatches.append({
            "path": str(head_path), "reason": "receipt_anchor_head_invalid",
            "detail": str(exc),
        })
        head = {}
    head_digest = str(head.get("anchor_sha256") or "")
    indexed_head = index.get(head_digest)
    if (not head_digest
            or _canonical_self_hash(head, "anchor_sha256") != head_digest
            or indexed_head is None or indexed_head[1] != head):
        mismatches.append({
            "path": str(head_path), "reason": "receipt_anchor_head_mismatch",
        })

    target_digest = str(target_anchor.get("anchor_sha256") or "")
    target_record = index.get(target_digest)
    reachable = False
    current = head if indexed_head is not None else {}
    seen: set[str] = set()
    while current:
        digest = str(current.get("anchor_sha256") or "")
        if not digest or digest in seen:
            mismatches.append({
                "path": str(head_path), "reason": "receipt_anchor_chain_cycle",
            })
            break
        seen.add(digest)
        if digest == target_digest:
            reachable = True
            break
        previous = str(current.get("previous_anchor_sha256") or "")
        if not previous:
            break
        record = index.get(previous)
        if record is None:
            mismatches.append({
                "path": str(head_path),
                "reason": "receipt_anchor_chain_missing_link",
                "anchor_sha256": previous,
            })
            break
        current = record[1]
    if (not target_digest or target_record is None
            or target_record[1] != target_anchor or not reachable):
        mismatches.append({
            "path": str(receipts_root),
            "reason": "receipt_anchor_not_reachable_from_head",
        })
    return {
        "ok": not mismatches,
        "target_reachable": reachable,
        "head_anchor_sha256": head_digest,
        "target_anchor_sha256": target_digest,
        "mismatches": mismatches,
    }


def verify_run_receipt(
    receipt_path: dict[str, Any] | str | pathlib.Path,
    run_dir: str | pathlib.Path | None = None,
    authority_dir: str | pathlib.Path | None = None,
) -> dict[str, Any]:
    """Verify receipt integrity separately from mandatory delivery completion."""
    receipt_file: pathlib.Path | None = None
    if isinstance(receipt_path, dict):
        receipt = dict(receipt_path)
    else:
        receipt_file = _absolute_lexical(receipt_path)
        receipt = _read_json_object(receipt_file, label="run receipt")
    mismatches: list[dict[str, Any]] = []

    expected_receipt = str(receipt.get("receipt_sha256") or "")
    if not expected_receipt or _canonical_self_hash(receipt, "receipt_sha256") != expected_receipt:
        mismatches.append({"path": str(receipt_file or "<receipt>"),
                           "reason": "receipt_digest_mismatch"})

    base = _absolute_lexical(
        run_dir or receipt.get("run_dir")
        or (receipt_file.parent if receipt_file is not None else pathlib.Path.cwd()))
    manifest_path = pathlib.Path(str(receipt.get("manifest_path") or ""))
    manifest: dict[str, Any] | None = None
    if not manifest_path.is_absolute() or not manifest_path.is_file():
        mismatches.append({"path": str(manifest_path), "reason": "manifest_missing"})
    else:
        try:
            actual = sha256_file(manifest_path)
        except (OSError, ValueError) as exc:
            actual = ""
            mismatches.append({
                "path": str(manifest_path),
                "reason": "manifest_unsafe",
                "detail": str(exc),
            })
        if actual != str(receipt.get("manifest_sha256") or ""):
            mismatches.append({"path": str(manifest_path),
                               "reason": "manifest_digest_mismatch"})
        try:
            manifest = load_manifest(manifest_path)
        except ValueError as exc:
            mismatches.append({"path": str(manifest_path), "reason": str(exc)})
        else:
            binding = validate_manifest_binding(
                manifest, run_dir=base,
                manifest_path=base / "run_manifest.json",
                authority_dir=authority_dir,
            )
            mismatches.extend(binding["errors"])
            if str(receipt.get("session_id") or "") != str(manifest.get("session_id") or ""):
                mismatches.append({"path": str(manifest_path),
                                   "reason": "receipt_session_mismatch"})
            if str(receipt.get("authority_id") or "") != str(manifest.get("authority_id") or ""):
                mismatches.append({"path": str(manifest_path),
                                   "reason": "receipt_authority_mismatch"})
            if ("project_id" in receipt
                    and str(receipt.get("project_id") or "")
                    != str(manifest.get("project_id") or "")):
                mismatches.append({"path": str(manifest_path),
                                   "reason": "receipt_project_mismatch"})

    artifact_records = receipt.get("artifacts") or {}
    if not isinstance(artifact_records, dict):
        artifact_records = {}
        mismatches.append({"path": "<artifacts>", "reason": "artifacts_invalid"})
    commit_snapshot_complete = False
    expected_commit_sha256 = ""
    commit_value: dict[str, Any] = {}
    expected_commit_binding = {
        "expected_session_id": str(
            (manifest or {}).get("session_id") or receipt.get("session_id") or ""),
        "expected_project_id": str((manifest or {}).get("project_id") or ""),
        "expected_project": str((manifest or {}).get("project") or ""),
        "expected_authority_id": str(
            (manifest or {}).get("authority_id") or receipt.get("authority_id") or ""),
    }
    for name, record in sorted(artifact_records.items()):
        if not isinstance(record, dict):
            mismatches.append({"path": str(name), "reason": "artifact_record_invalid"})
            continue
        path = pathlib.Path(str(record.get("path") or ""))
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            mismatches.append({"path": str(path), "reason": "artifact_missing"})
            continue
        if name == "project_state" or path.name == "project_state.json":
            mismatches.append({"path": str(path), "reason": "mutable_project_state_forbidden"})
        try:
            payload = safe_read_bytes(path)
        except (OSError, ValueError) as exc:
            mismatches.append({
                "path": str(path),
                "reason": "artifact_unsafe",
                "detail": str(exc),
            })
            continue
        actual = sha256_bytes(payload)
        if actual != str(record.get("sha256") or ""):
            mismatches.append({"path": str(path), "reason": "artifact_digest_mismatch"})
        if int(record.get("size", -1)) != len(payload):
            mismatches.append({"path": str(path), "reason": "artifact_size_mismatch"})
        if name == "project_state_commit":
            expected_commit_sha256 = str(record.get("sha256") or "")
            try:
                commit_value = json.loads(payload.decode("utf-8"))
                if not isinstance(commit_value, dict):
                    raise ValueError("project state commit must be an object")
            except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
                mismatches.append({
                    "path": str(path),
                    "reason": f"invalid project state commit: {exc}",
                })
            else:
                _ok, commit_errors, commit_snapshot_complete = (
                    _verify_project_state_commit_value(
                        commit_value, path=path, **expected_commit_binding,
                    )
                )
                mismatches.extend(commit_errors)

    transactional_commit = bool(
        commit_value.get("state_before_snapshot")
        or commit_value.get("state_after_snapshot")
    )
    declared_chain_required = bool(
        receipt.get("authority_commit_chain_required"))
    if declared_chain_required != transactional_commit:
        mismatches.append({
            "path": str(receipt_file or "<receipt>"),
            "reason": "authority_commit_chain_requirement_mismatch",
        })
    chain_required = transactional_commit
    authority_chain_valid = not chain_required
    if chain_required:
        if authority_dir is not None:
            authority_base = _absolute_lexical(authority_dir)
        else:
            authority_manifest_path = pathlib.Path(str(
                (manifest or {}).get("authority_path") or ""))
            authority_base = (
                authority_manifest_path.parent.parent
                if authority_manifest_path.is_absolute() else pathlib.Path())
        session_id = str(
            (manifest or {}).get("session_id") or receipt.get("session_id") or "")
        expected_authority_commit = (
            authority_base / "commits" / f"{session_id}.json")
        expected_head = authority_base / "commits" / "HEAD.json"
        receipt_commit_path = pathlib.Path(str(
            receipt.get("authority_commit_path") or ""))
        receipt_head_path = pathlib.Path(str(
            receipt.get("authority_head_path") or ""))
        commit_sha256 = str(commit_value.get("commit_sha256") or "")
        if (not authority_base.is_absolute()
                or receipt_commit_path != expected_authority_commit
                or receipt_head_path != expected_head
                or str(receipt.get("authority_commit_sha256") or "")
                != commit_sha256):
            mismatches.append({
                "path": str(receipt_commit_path),
                "reason": "authority_commit_receipt_binding_mismatch",
            })
        elif not commit_value:
            mismatches.append({
                "path": str(receipt_commit_path),
                "reason": "authority_commit_projection_missing",
            })
        else:
            chain = _verify_authority_commit_chain(
                authority_base,
                target_commit=commit_value,
                expected_project_id=str(
                    (manifest or {}).get("project_id") or
                    receipt.get("project_id") or ""),
                expected_session_id=session_id,
            )
            authority_chain_valid = bool(chain.get("ok"))
            mismatches.extend(chain.get("mismatches") or [])

    try:
        schema_version = int(receipt.get("schema_version") or 0)
    except (TypeError, ValueError):
        schema_version = 0
        mismatches.append({"path": str(receipt_file or "<receipt>"),
                           "reason": "receipt_schema_version_invalid"})
    anchor_valid = False
    anchor_path = pathlib.Path(str(receipt.get("receipt_anchor_path") or ""))
    if schema_version >= 2:
        if not anchor_path.is_absolute() or not anchor_path.is_file():
            mismatches.append({"path": str(anchor_path), "reason": "receipt_anchor_missing"})
        else:
            if authority_dir is not None:
                expected_authority = _absolute_lexical(authority_dir)
                try:
                    anchor_path.relative_to(expected_authority)
                except ValueError:
                    mismatches.append({"path": str(anchor_path),
                                       "reason": "receipt_anchor_authority_mismatch"})
            try:
                anchor = _read_json_object(anchor_path, label="receipt anchor")
            except ValueError as exc:
                mismatches.append({"path": str(anchor_path), "reason": str(exc)})
            else:
                anchor_valid = bool(
                    str(anchor.get("receipt_sha256") or "") == expected_receipt
                    and str(anchor.get("manifest_sha256") or "")
                    == str(receipt.get("manifest_sha256") or "")
                    and str(anchor.get("session_id") or "")
                    == str(receipt.get("session_id") or "")
                    and str(anchor.get("authority_id") or "")
                    == str(receipt.get("authority_id") or "")
                    and str(anchor.get("project_state_commit_sha256") or "")
                    == expected_commit_sha256
                    and str(anchor.get("authority_commit_sha256") or "")
                    == str(receipt.get("authority_commit_sha256") or "")
                    and bool(anchor.get("authority_commit_chain_required"))
                    == chain_required
                    and (
                        "project_id" not in anchor
                        or str(anchor.get("project_id") or "")
                        == str(receipt.get("project_id") or "")
                    )
                )
                if not anchor_valid:
                    mismatches.append({"path": str(anchor_path),
                                       "reason": "receipt_anchor_mismatch"})
                anchor_authority = (
                    _absolute_lexical(authority_dir)
                    if authority_dir is not None else pathlib.Path(str(
                        (manifest or {}).get("authority_path") or ""
                    )).parent.parent
                )
                if anchor_authority.is_absolute():
                    anchor_chain = _verify_receipt_anchor_chain(
                        anchor_authority,
                        target_anchor=anchor,
                        expected_authority_id=str(
                            receipt.get("authority_id") or ""),
                        expected_project_id=str(
                            receipt.get("project_id") or ""),
                    )
                    anchor_valid = bool(
                        anchor_valid and anchor_chain.get("ok"))
                    mismatches.extend(anchor_chain.get("mismatches") or [])
                else:
                    anchor_valid = False
                    mismatches.append({
                        "path": str(anchor_path),
                        "reason": "receipt_anchor_authority_missing",
                    })

    mandatory = set(mandatory_delivery_artifacts(manifest))
    missing = sorted(mandatory - set(artifact_records))
    validation_value: dict[str, Any] = {}
    validation_record = artifact_records.get("finding_validation")
    if isinstance(validation_record, dict):
        path = pathlib.Path(str(validation_record.get("path") or ""))
        if path.is_file():
            try:
                validation_value = _read_json_object(path, label="finding validation")
                try:
                    from .reporting.validate import verify_validation_artifact
                except ImportError:  # pragma: no cover - direct script fallback
                    from reporting.validate import verify_validation_artifact
                validation_base = pathlib.Path(
                    str(validation_value.get("run_dir") or base)).resolve()
                allowed_validation_base = validation_base == base.resolve()
                if authority_dir is not None:
                    try:
                        validation_base.relative_to(
                            _absolute_lexical(authority_dir))
                    except ValueError:
                        pass
                    else:
                        allowed_validation_base = True
                if not allowed_validation_base:
                    mismatches.append({
                        "path": str(validation_base),
                        "reason": "validation_run_dir_binding_mismatch",
                    })
                validation_check = verify_validation_artifact(
                    validation_value, validation_base)
                if not validation_check.get("ok"):
                    mismatches.extend(validation_check.get("mismatches") or [])
            except (ImportError, ValueError, OSError, json.JSONDecodeError) as exc:
                mismatches.append({"path": str(path),
                                   "reason": f"validation_verification_error:{exc}"})

    integrity_valid = not mismatches
    validation_outcome = {
        "status": validation_value.get("status"),
        "exit_code": validation_value.get("exit_code"),
        "proof_gate": validation_value.get("proof_gate") or {},
        "closure_gate": (validation_value.get("closure_gate")
                         or validation_value.get("empty_gate") or {}),
    }
    delivery_complete = bool(
        integrity_valid
        and schema_version >= 2
        and anchor_valid
        and not missing
        and commit_snapshot_complete
        and authority_chain_valid
        and _outcome_is_deliverable(validation_outcome)
        and bool(receipt.get("authority_trusted"))
        and str(receipt.get("authorization_assurance") or "") in {
            "preexec_enforced", "dry_run_no_network"
        }
    )
    if bool(receipt.get("delivery_complete")) != delivery_complete:
        mismatches.append({"path": str(receipt_file or "<receipt>"),
                           "reason": "delivery_projection_mismatch"})
        integrity_valid = False
        delivery_complete = False
    return {
        "ok": integrity_valid,
        "integrity_valid": integrity_valid,
        "delivery_complete": delivery_complete,
        "missing_mandatory_artifacts": missing,
        "mismatches": mismatches,
    }


def _file_check(path: pathlib.Path) -> dict[str, Any]:
    if not path.exists():
        return {"status": "missing", "path": str(path), "sha256": ""}
    if not path.is_file():
        return {"status": "invalid", "path": str(path), "sha256": ""}
    size = path.stat().st_size
    return {
        "status": "empty" if size == 0 else "ok",
        "path": str(path),
        "size": size,
        "sha256": sha256_file(path),
    }


def doctor(
    repo_root: str | pathlib.Path,
    *,
    codex_home: str | pathlib.Path | None = None,
) -> dict[str, Any]:
    """Inspect instruction resolution without changing user configuration."""
    root = pathlib.Path(repo_root).resolve()
    home = pathlib.Path(codex_home or pathlib.Path.home() / ".codex").expanduser().resolve()
    project_agents = _file_check(root / "AGENTS.md")
    compatibility_agents = _file_check(root / "codex" / "AGENTS.md")
    if (project_agents["status"] == compatibility_agents["status"] == "ok"
            and project_agents["sha256"] != compatibility_agents["sha256"]):
        compatibility_agents["status"] = "drift"

    global_agents = _file_check(home / "AGENTS.md")
    header_path = root / "codex" / "_agents_header.md"
    core_path = root / "skill" / "核心技能文件.v3.md"
    agents_source = {
        "status": "missing", "expected_sha256": "",
        "root_matches": False, "compatibility_matches": False,
    }
    if header_path.is_file() and core_path.is_file():
        core_lines = core_path.read_bytes().splitlines(keepends=True)
        expected = header_path.read_bytes() + b"".join(core_lines[1:])
        expected_sha = sha256_bytes(expected)
        agents_source = {
            "status": "ok",
            "expected_sha256": expected_sha,
            "root_matches": project_agents.get("sha256") == expected_sha,
            "compatibility_matches": compatibility_agents.get("sha256") == expected_sha,
        }
        if not (agents_source["root_matches"]
                and agents_source["compatibility_matches"]):
            agents_source["status"] = "drift"

    skill_path = root / "SKILL.md"
    changelog_path = root / "CHANGELOG.md"
    skill_text = skill_path.read_text(encoding="utf-8") if skill_path.is_file() else ""
    changelog_text = (changelog_path.read_text(encoding="utf-8")
                      if changelog_path.is_file() else "")
    skill_match = re.search(r"^version:\s*([^\s]+)\s*$", skill_text, re.M)
    changelog_match = re.search(r"^##\s+([^\s]+)\s+-", changelog_text, re.M)
    versions = {
        "engine": __version__,
        "skill": skill_match.group(1) if skill_match else "",
        "changelog_latest": changelog_match.group(1) if changelog_match else "",
    }
    version_consistency = {
        "status": "ok" if len(set(versions.values())) == 1 and all(versions.values()) else "drift",
        "versions": versions,
    }
    alias = home / "prompts" / "src.md"
    if not alias.exists() and not alias.is_symlink():
        src_alias = {"status": "missing", "path": str(alias), "resolved_path": ""}
    else:
        resolved = alias.resolve(strict=False)
        try:
            resolved.relative_to(root)
            status = "project"
        except ValueError:
            status = "foreign"
        src_alias = {
            "status": status,
            "path": str(alias),
            "resolved_path": str(resolved),
            "symlink": alias.is_symlink(),
        }
    checks = {
        "project_agents": project_agents,
        "compatibility_agents": compatibility_agents,
        "agents_source_consistency": agents_source,
        "version_consistency": version_consistency,
        "global_agents": global_agents,
        "src_alias": src_alias,
    }
    fatal = (
        project_agents["status"] != "ok"
        or compatibility_agents["status"] in {"invalid", "drift"}
        or agents_source["status"] != "ok"
        or version_consistency["status"] != "ok"
    )
    return {
        "schema_version": 1,
        "atoolkit_version": __version__,
        "repo_root": str(root),
        "codex_home": str(home),
        "ok": not fatal,
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Atoolkit runtime provenance utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)
    init_parser = subparsers.add_parser(
        "init-manifest", help="create the pre-network immutable run manifest")
    init_parser.add_argument("--run-dir", required=True, type=pathlib.Path)
    init_parser.add_argument("--mode", choices=["engine", "skill"], default="skill")
    init_parser.add_argument("--project", default="")
    init_parser.add_argument("--session-id", default="")
    init_parser.add_argument("--primary-target", required=True)
    init_parser.add_argument("--allow", action="append", default=[])
    init_parser.add_argument("--authz", default="")
    init_parser.add_argument("--authz-file", type=pathlib.Path)
    init_parser.add_argument("--instruction", action="append", required=True)
    init_parser.add_argument("--source-root", type=pathlib.Path)
    init_parser.add_argument("--authority-dir", type=pathlib.Path)
    init_parser.add_argument("--project-id", default="")
    init_parser.add_argument("--base-path", default="/")
    init_parser.add_argument("--base-path-explicit", action="store_true")
    init_parser.add_argument("--allow-path", action="append", default=[])
    init_parser.add_argument("--deny-path", action="append", default=[])
    init_parser.add_argument(
        "--authorization-assurance", default="unverified",
        choices=["unverified", "unrestricted_user_accepted",
                 "sandbox_network_denied", "dry_run_no_network", "preexec_enforced"],
    )
    init_parser.add_argument("--target-fingerprint", default="")
    init_parser.add_argument("--run-plan", type=pathlib.Path)
    receipt_parser = subparsers.add_parser(
        "receipt", help="bind final artifacts to the immutable start manifest")
    receipt_parser.add_argument("--run-dir", required=True, type=pathlib.Path)
    receipt_parser.add_argument("--manifest", type=pathlib.Path)
    receipt_parser.add_argument("--output", type=pathlib.Path)
    receipt_parser.add_argument(
        "--artifact", action="append", default=[], metavar="NAME=PATH")
    receipt_parser.add_argument("--project-state-delta", type=pathlib.Path)
    doctor_parser = subparsers.add_parser("doctor")
    doctor_parser.add_argument("repo_root", type=pathlib.Path)
    doctor_parser.add_argument("--codex-home", type=pathlib.Path)
    doctor_parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "init-manifest":
        authz = args.authz
        if args.authz_file:
            authz = args.authz_file.read_text(encoding="utf-8")
        run_dir = args.run_dir.resolve()
        authority_dir = args.authority_dir
        if authority_dir is None:
            project_dir = run_dir.parent.parent if run_dir.parent.name == "sessions" else run_dir.parent
            authority_dir = project_dir / ".atoolkit"
        instructions = []
        for value in args.instruction:
            instruction_path = pathlib.Path(value).expanduser()
            if not instruction_path.is_absolute():
                instruction_path = pathlib.Path(args.source_root or pathlib.Path.cwd()) / instruction_path
            if not instruction_path.is_file() or instruction_path.stat().st_size == 0:
                parser.error(f"injected instruction is missing or empty: {instruction_path}")
            instructions.append({
                "kind": "skill_instruction", "path": str(instruction_path),
                "injected": True,
            })
        result = create_run_manifest(
            run_dir,
            mode=args.mode,
            project=args.project or (
                run_dir.parent.parent.name if run_dir.parent.name == "sessions"
                else run_dir.parent.name),
            session_id=args.session_id or run_dir.name,
            primary_target=args.primary_target,
            authorized_scopes=args.allow or [args.primary_target],
            authz=authz,
            instruction_sources=instructions,
            source_root=args.source_root,
            authority_dir=authority_dir,
            project_id=args.project_id,
            base_path=args.base_path,
            base_path_explicit=args.base_path_explicit,
            allow_paths=args.allow_path,
            deny_paths=args.deny_path,
            authorization_assurance=args.authorization_assurance,
            target_fingerprint=args.target_fingerprint,
            run_plan_path=args.run_plan,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.command == "receipt":
        run_dir = args.run_dir.resolve()
        artifacts: dict[str, pathlib.Path] = {}
        for value in args.artifact:
            name, separator, raw_path = value.partition("=")
            if not separator or not name.strip() or not raw_path.strip():
                parser.error("--artifact must use NAME=PATH")
            path = pathlib.Path(raw_path).expanduser()
            artifacts[name.strip()] = path if path.is_absolute() else run_dir / path
        if not artifacts:
            for name, filename in (
                ("summary", "summary.json"),
                ("finding_validation", "finding_validation.json"),
                ("coverage_ledger", "coverage-ledger.json"),
                ("candidate_ledger", "candidate-ledger.json"),
            ):
                path = run_dir / filename
                if path.is_file():
                    artifacts[name] = path
        if not artifacts:
            parser.error("no receipt artifacts found; pass --artifact NAME=PATH")
        delta = None
        if args.project_state_delta:
            delta = json.loads(args.project_state_delta.read_text(encoding="utf-8"))
        result = write_run_receipt(
            args.output or run_dir / "run_receipt.json",
            manifest_path=args.manifest or run_dir / "run_manifest.json",
            artifacts=artifacts,
            project_state_delta=delta,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.command == "doctor":
        result = doctor(args.repo_root, codex_home=args.codex_home)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["ok"] else 1
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "MANDATORY_DELIVERY_ARTIFACTS",
    "canonical_json_sha256",
    "create_run_manifest",
    "doctor",
    "load_manifest",
    "sha256_file",
    "source_tree_sha256",
    "validate_manifest_binding",
    "verify_run_receipt",
    "write_run_receipt",
]
