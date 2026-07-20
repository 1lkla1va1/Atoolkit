"""Host-validated, diagnostic-only continuation input for a new Run.

This module deliberately does not upgrade execution authority.  It only
replays the deterministic agenda emitted by a previous immutable validation
artifact after checking its digest, referenced evidence and target scope.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Any

from .host_policy import is_authorized_url
from .outcome import build_next_run_agenda
from .reporting.validate import verify_validation_artifact
from .safe_io import safe_read_bytes


class ContinuationError(ValueError):
    """The selected prior Run cannot be trusted as continuation input."""


_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def _read_object(path: pathlib.Path, root: pathlib.Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ContinuationError(f"continuation artifact missing or unsafe: {path.name}")
    try:
        raw = safe_read_bytes(path, root=root, max_bytes=2 * 1024 * 1024)
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ContinuationError(f"invalid continuation artifact {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise ContinuationError(f"continuation artifact is not an object: {path.name}")
    return value


def _sha256(path: pathlib.Path, root: pathlib.Path) -> str:
    return hashlib.sha256(safe_read_bytes(path, root=root)).hexdigest()


def load_prior_continuation(
    prior_run: str | pathlib.Path,
    *,
    primary_target: str,
    authorized_scopes: list[str],
) -> dict[str, Any]:
    """Validate and normalize a previous Run's deterministic agenda.

    Returned items remain ``diagnostic_only`` and must be bound into the new
    run manifest.  They may seed inventory/scheduling, but never ProjectState
    truth or submission eligibility by themselves.
    """
    candidate = pathlib.Path(prior_run).expanduser().absolute()
    current = candidate
    while current != current.parent:
        if current.is_symlink():
            raise ContinuationError("--continue-from-run may not traverse a symlink")
        current = current.parent
    root = candidate.resolve()
    if not root.is_dir():
        raise ContinuationError("--continue-from-run must name a regular Run directory")
    validation_path = root / "finding_validation.json"
    attribution_path = root / "miss-attribution.json"
    agenda_path = root / "next-run-agenda.json"
    validation = _read_object(validation_path, root)
    attribution = _read_object(attribution_path, root)
    agenda = _read_object(agenda_path, root)

    integrity = verify_validation_artifact(validation, root)
    if not integrity.get("ok"):
        raise ContinuationError(
            "prior finding_validation integrity failed: "
            + json.dumps(integrity.get("mismatches") or [], ensure_ascii=False))
    if attribution != (validation.get("miss_attribution") or {}):
        raise ContinuationError("miss-attribution does not match finding_validation")
    expected_agenda = build_next_run_agenda(attribution)
    if agenda != expected_agenda or agenda != (validation.get("next_run_agenda") or {}):
        raise ContinuationError("next-run-agenda is not the deterministic validation projection")

    normalized: list[dict[str, Any]] = []
    for position, raw in enumerate(agenda.get("items") or [], start=1):
        if not isinstance(raw, dict):
            raise ContinuationError(f"agenda item {position} is not an object")
        intent_id = str(raw.get("intent_id") or "").strip()
        endpoint = str(raw.get("target_endpoint") or "").strip()
        method = str(raw.get("target_method") or "").strip().upper()
        if not intent_id or not endpoint or method not in _METHODS:
            raise ContinuationError(
                f"agenda item {position} lacks exact intent/endpoint/method identity")
        endpoint_parts = endpoint.split(None, 1)
        embedded_method = (
            endpoint_parts[0].upper()
            if len(endpoint_parts) == 2 and endpoint_parts[0].upper() in _METHODS else "")
        if embedded_method and embedded_method != method:
            raise ContinuationError(
                f"agenda item {position} has conflicting endpoint/method identity")
        target_text = endpoint_parts[1] if embedded_method else endpoint
        if target_text.startswith(("http://", "https://")):
            if not authorized_scopes or not is_authorized_url(target_text, authorized_scopes):
                raise ContinuationError(f"agenda item {position} is outside the new authorization scope")
        elif not target_text.startswith("/"):
            raise ContinuationError(f"agenda item {position} must use an absolute URL path")
        normalized.append({
            **raw,
            "source": "v9_host_continuation",
            "target_method": method,
            "target_endpoint": endpoint,
            "diagnostic_only": True,
            "source_run": root.name,
        })

    return {
        "schema_version": "1.0",
        "trust_level": "diagnostic_only",
        "authority_trusted": False,
        "source_run": root.name,
        "source_run_path": str(root),
        "primary_target": primary_target,
        "source_validation_sha256": _sha256(validation_path, root),
        "source_attribution_sha256": _sha256(attribution_path, root),
        "source_agenda_sha256": _sha256(agenda_path, root),
        "count": len(normalized),
        "items": normalized,
    }


__all__ = ["ContinuationError", "load_prior_continuation"]
