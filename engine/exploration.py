"""Deterministic evidence gate for the final intuition-exploration phase."""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
from typing import Any

try:
    from .safe_io import safe_read_bytes
except ImportError:  # pragma: no cover - direct engine script fallback
    from safe_io import safe_read_bytes


REQUEST_LINE = re.compile(
    rb"(?:^|\n)(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+(?:\s+HTTP/\S+)?\r?$",
    re.I | re.M,
)
RESPONSE_LINE = re.compile(rb"(?:^|\n)HTTP/\S+\s+\d{3}\b", re.I | re.M)


def validate_intuition_exploration(run_dir: str | pathlib.Path) -> dict[str, Any]:
    """Return a fail-closed validation result for intuition-exploration.json."""
    root = pathlib.Path(run_dir).resolve()
    path = root / "intuition-exploration.json"
    reasons: list[str] = []
    hashes: dict[str, str] = {}
    directions_out: list[dict[str, Any]] = []
    if path.is_symlink() or not path.is_file():
        return {
            "ok": False,
            "path": "intuition-exploration.json",
            "reasons": ["intuition_exploration_artifact_missing"],
            "artifact_hashes": {},
            "directions": [],
        }
    try:
        raw = safe_read_bytes(path, root=root, max_bytes=2 * 1024 * 1024)
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "ok": False,
            "path": "intuition-exploration.json",
            "reasons": [f"intuition_exploration_invalid:{type(exc).__name__}"],
            "artifact_hashes": {},
            "directions": [],
        }
    hashes["intuition-exploration.json"] = hashlib.sha256(raw).hexdigest()
    if not isinstance(value, dict) or str(value.get("schema_version")) not in {"1", "1.0"}:
        reasons.append("intuition_exploration_schema_invalid")
    if not isinstance(value, dict) or value.get("status") != "completed":
        reasons.append("intuition_exploration_not_completed")
    directions = value.get("directions") if isinstance(value, dict) else None
    if not isinstance(directions, list) or not directions:
        reasons.append("intuition_exploration_directions_empty")
        directions = []
    seen_ids: set[str] = set()
    for position, direction in enumerate(directions, start=1):
        item_reasons: list[str] = []
        if not isinstance(direction, dict):
            reasons.append(f"intuition_direction_{position}_invalid")
            continue
        direction_id = str(direction.get("direction_id") or "").strip()
        rationale = str(direction.get("rationale") or "").strip()
        refs = direction.get("evidence_refs") or []
        if not direction_id or direction_id in seen_ids:
            item_reasons.append("direction_id_missing_or_duplicate")
        seen_ids.add(direction_id)
        if not rationale:
            item_reasons.append("rationale_missing")
        if not isinstance(refs, list) or not refs:
            item_reasons.append("evidence_refs_missing")
            refs = []
        has_request = False
        has_response = False
        normalized_refs: list[str] = []
        for ref in refs:
            text = str(ref or "").strip()
            relative = pathlib.Path(text)
            if (not text or relative.is_absolute() or ".." in relative.parts):
                item_reasons.append("evidence_ref_unsafe")
                continue
            evidence = root / relative
            try:
                data = safe_read_bytes(evidence, root=root, max_bytes=2 * 1024 * 1024)
            except (OSError, ValueError):
                item_reasons.append(f"evidence_unreadable:{text}")
                continue
            if not data:
                item_reasons.append(f"evidence_empty:{text}")
                continue
            hashes[text] = hashlib.sha256(data).hexdigest()
            normalized_refs.append(text)
            has_request = has_request or bool(REQUEST_LINE.search(data))
            has_response = has_response or bool(RESPONSE_LINE.search(data))
        if not has_request:
            item_reasons.append("request_evidence_missing")
        if not has_response:
            item_reasons.append("response_evidence_missing")
        if item_reasons:
            reasons.extend(
                f"intuition_direction_{position}:{reason}" for reason in item_reasons)
        directions_out.append({
            "direction_id": direction_id,
            "rationale": rationale,
            "evidence_refs": normalized_refs,
            "ok": not item_reasons,
        })
    return {
        "ok": not reasons,
        "path": "intuition-exploration.json",
        "reasons": reasons,
        "artifact_hashes": hashes,
        "directions": directions_out,
    }


__all__ = ["validate_intuition_exploration"]
