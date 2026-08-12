"""Authoritative observations.json machine truth (v9.2).

Observations are phenomenon-level findings with otherwise valid evidence:
they bypass the batch-atomic gate, never enter ProjectState, and never carry
SRC severity.  This module is the single writer of ``observations.json`` for
both the Direct runtime (``skill_runtime checkpoint/report``) and the
authority finalizer.
"""
from __future__ import annotations

import pathlib
from typing import Any, Iterable

try:
    from ..safe_io import atomic_write_json
except ImportError:  # pragma: no cover - script execution fallback
    from safe_io import atomic_write_json

from .validate import _finding_target_projection

OBSERVATIONS_SCHEMA_VERSION = 1


def _relative(path_text: str, run: pathlib.Path) -> str:
    if not path_text:
        return ""
    try:
        return pathlib.Path(path_text).resolve().relative_to(run).as_posix()
    except ValueError:
        return str(path_text)


def _evidence_refs(finding: dict[str, Any], finding_dir: pathlib.Path,
                   run: pathlib.Path) -> list[str]:
    refs: list[str] = []
    for packet in finding.get("proof_packets") or []:
        if not isinstance(packet, dict):
            continue
        for key in ("request_file", "response_file"):
            ref = packet.get(key)
            if not ref:
                continue
            candidate = (finding_dir / str(ref)).resolve()
            try:
                relative = candidate.relative_to(run).as_posix()
            except ValueError:
                continue
            if candidate.is_file() and relative not in refs:
                refs.append(relative)
    return refs


def observation_record(run_dir: str | pathlib.Path,
                       item: dict[str, Any]) -> dict[str, Any]:
    """Project one validated observation item into its canonical record."""
    run = pathlib.Path(run_dir).resolve()
    finding = item.get("finding") if isinstance(item.get("finding"), dict) else {}
    finding_dir = pathlib.Path(str(item.get("path") or "")).resolve().parent
    projection = _finding_target_projection(finding)
    chain = (
        finding.get("chain_assessment")
        if isinstance(finding.get("chain_assessment"), dict) else {})
    return {
        "id": str(item.get("id") or ""),
        "path": _relative(str(item.get("path") or ""), run),
        "title": str(finding.get("title") or item.get("title") or item.get("id") or ""),
        "phenomenon_classes": [
            str(value) for value in (item.get("phenomenon_classes") or [])],
        "reasons": [str(reason) for reason in (item.get("reasons") or [])],
        "method": projection["method"],
        "endpoint": projection["endpoint"],
        "params": projection["params"],
        "roles": projection["roles"],
        "vuln_class": projection["vuln_class"],
        "threat_id": projection["threat_id"],
        "chain_status": str(chain.get("status") or ""),
        "final_impact": str(chain.get("final_impact") or ""),
        "evidence_refs": _evidence_refs(finding, finding_dir, run),
    }


def build_observation_records(
    run_dir: str | pathlib.Path,
    items: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [observation_record(run_dir, item) for item in items]


def write_observations_json(
    run_dir: str | pathlib.Path,
    items: Iterable[dict[str, Any]],
    *,
    root: str | pathlib.Path | None = None,
) -> pathlib.Path:
    """Write the stable observations.json artifact, even when empty."""
    run = pathlib.Path(run_dir).resolve()
    payload = {
        "schema_version": OBSERVATIONS_SCHEMA_VERSION,
        "observations": build_observation_records(run, items),
    }
    return atomic_write_json(
        run / "observations.json", payload,
        root=pathlib.Path(root).resolve() if root is not None else run,
        reject_leaf_symlink=True)


__all__ = [
    "OBSERVATIONS_SCHEMA_VERSION",
    "build_observation_records",
    "observation_record",
    "write_observations_json",
]
