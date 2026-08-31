"""Deterministic identity-requirement declaration (v9.8 W2).

Direct runs have no threat model, so identity prerequisites are derived from
the planner risk-tag vocabulary (``engine/planner.py``) with exact-match rules
only — no substring guessing (design §6 R7).  Engine threat mode converts
``build_identity_readiness()`` output into the same artifact schema.  Both
paths materialize ``<run>/identity-requirements.json`` before the first
network action so a missing identity is visible on day one, not at week six.
"""
from __future__ import annotations

import json
import pathlib
from typing import Any, Iterable

try:
    from .data_hygiene import canonical_credential_sha256
    from .ledger import is_high_value, normalize_status
except ImportError:  # pragma: no cover - script execution fallback
    from data_hygiene import canonical_credential_sha256
    from ledger import is_high_value, normalize_status


IDENTITY_REQUIREMENTS_SCHEMA_VERSION = "1"

# §6 R7 mapping, exact risk-tag match, evaluated in this precedence order.
_PEER_PAIR_TAGS = ("object-ownership", "idor")
_ROLE_PAIR_TAGS = ("privilege", "enum-tamper", "auth-flow", "auth-flow-abuse")
_STATEFUL_OWNER_TAGS = ("amount-tamper", "accounting", "business-logic")
_SINGLE_TAGS = ("redirect-chain", "callback")

_MODE_ORDER = {
    "peer_pair": 0,
    "role_pair": 1,
    "stateful_owner": 2,
    "anonymous_plus_authenticated": 3,
    "single": 4,
}
_COUNT_NEEDED = {
    "peer_pair": 2,
    "role_pair": 2,
    "anonymous_plus_authenticated": 2,
    "stateful_owner": 1,
    "single": 1,
}
_REASON_WHEN_UNMET = {
    "peer_pair": "peer_role_pair_missing",
    "role_pair": "required_role_pair_missing",
    "anonymous_plus_authenticated": "distinct_identity_missing",
    "stateful_owner": "test_owned_object_missing",
    "single": "distinct_identity_missing",
}
_HUMAN_ACTION = {
    "peer_pair": "提供第 2 个同级独立身份的登录态（cookie/token），"
                 "对象对越权测试需要 owner/attacker 两个同角色身份",
    "role_pair": "提供覆盖另一角色的第 2 个独立身份登录态，"
                 "角色差异/认证流测试需要两个不同角色",
    "anonymous_plus_authenticated": "提供 1 个已认证身份的登录态，"
                                    "用于匿名/带态双通道对比",
    "stateful_owner": "提供 1 个拥有自有业务对象（订单/余额/卡券等）的"
                      "属主身份登录态，用于状态依赖测试",
    "single": "提供 1 个已认证身份的登录态（cookie/token）",
}
_TERMINAL = {"confirmed", "not_vulnerable", "not_applicable"}


def _strings(value: Any) -> list[str]:
    if value in (None, "", [], {}):
        return []
    items = value if isinstance(value, (list, tuple, set)) else [value]
    out: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if text and text.lower() not in {seen.lower() for seen in out}:
            out.append(text)
    return out


def _mode_for_tags(risk_tags: Iterable[str]) -> str:
    tags = {str(tag).strip().lower() for tag in risk_tags}
    if tags & set(_PEER_PAIR_TAGS):
        return "peer_pair"
    if tags & set(_ROLE_PAIR_TAGS):
        return "role_pair"
    if tags & set(_STATEFUL_OWNER_TAGS):
        return "stateful_owner"
    if tags & set(_SINGLE_TAGS):
        return "single"
    return "single"


def _role_for_surface(surface: dict[str, Any]) -> str:
    for role in _strings(surface.get("roles")):
        if role.lower() != "anonymous":
            return role
    return "anonymous"


def count_present_identities(run_dir: str | pathlib.Path) -> int:
    """Count distinct credential fingerprints in an existing identities.json.

    Reuses ``canonical_credential_sha256`` so "two labels sharing one cookie"
    still counts as a single identity (Host-side fingerprint semantics).
    A run without identities.json simply has zero present identities.
    """
    run = pathlib.Path(run_dir).resolve()
    path = run / "identities.json"
    if not path.is_file() or path.is_symlink():
        return 0
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return 0
    records = value.get("identities") if isinstance(value, dict) else value
    if isinstance(records, dict):
        records = [
            {"label": label, "headers": headers}
            for label, headers in records.items()
        ]
    fingerprints: set[str] = set()
    for record in records if isinstance(records, list) else []:
        if not isinstance(record, dict):
            continue
        headers = record.get("headers")
        if not isinstance(headers, dict):
            continue
        fingerprint = canonical_credential_sha256(headers)
        if fingerprint:
            fingerprints.add(fingerprint)
    return len(fingerprints)


def derive_identity_requirements(
    surfaces: Iterable[dict[str, Any]],
    *,
    identities_present: int = 0,
) -> dict[str, Any]:
    """Group open cells into deterministic identity requirements.

    Purely anonymous cells (no non-anonymous role) need no credential and
    produce no requirement.  Unmet requirements list their blocked
    ``surface_id`` values in ``blocks_cells``; the caller mirrors that into
    the coverage ledger as ``identity_blocked=true``.
    """
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    high_value_ids: set[str] = set()
    for surface in surfaces:
        if not isinstance(surface, dict):
            continue
        surface_id = str(surface.get("surface_id") or "")
        if not surface_id:
            continue
        if normalize_status(str(surface.get("status") or "")) in _TERMINAL:
            continue
        if is_high_value(surface):
            high_value_ids.add(surface_id)
        role = _role_for_surface(surface)
        mode = _mode_for_tags(surface.get("risk_tags") or [])
        needed = _COUNT_NEEDED[mode]
        # v9.8.1 A0: purely anonymous probing needs no credential regardless
        # of mode — the peer_pair/stateful comparison is carried by the
        # sibling authenticated-role cell expanded from the same endpoint.
        if role == "anonymous":
            needed = 0
        if needed < 1:
            continue
        key = (mode, role)
        group = groups.setdefault(key, {
            "mode": mode,
            "role": role,
            "count_needed": needed,
            "surface_ids": [],
        })
        group["surface_ids"].append(surface_id)

    requirements: list[dict[str, Any]] = []
    for position, key in enumerate(
            sorted(groups, key=lambda item: (
                _MODE_ORDER.get(item[0], 9), item[1])), start=1):
        group = groups[key]
        unmet = identities_present < group["count_needed"]
        requirements.append({
            "requirement_id": f"req-{position:03d}",
            "mode": group["mode"],
            "reason_code": (
                _REASON_WHEN_UNMET[group["mode"]] if unmet else ""),
            "role": group["role"],
            "count_needed": group["count_needed"],
            "count_present": identities_present,
            "blocks_cells": (
                sorted(group["surface_ids"]) if unmet else []),
            "human_action": _HUMAN_ACTION[group["mode"]],
        })
    blocked = [
        cell for requirement in requirements
        for cell in requirement["blocks_cells"]
    ]
    return {
        "schema_version": IDENTITY_REQUIREMENTS_SCHEMA_VERSION,
        "requirements": requirements,
        "summary": {
            "total_requirements": len(requirements),
            "unmet_requirements": sum(
                1 for requirement in requirements
                if requirement["reason_code"]),
            "blocked_cells": len(blocked),
            "blocked_high_value_cells": sum(
                1 for cell in blocked if cell in high_value_ids),
            "identities_present": identities_present,
        },
    }


def requirements_from_identity_readiness(readiness: dict[str, Any]) -> dict[str, Any]:
    """Convert Engine ``build_identity_readiness()`` output to this schema (W2.1).

    The Engine already evaluated each threat's ``identity_requirement``; only
    unmet threats become requirements.  ``blocks_cells`` carries the exact
    ``feature_id/threat_id`` cell identities (Engine cells are threat-bound).
    Engine threat cells are the frozen high-value denominator, so blocked
    cells count as high-value by construction.
    """
    present = int(readiness.get("distinct_credentials", 0) or 0)
    groups: dict[tuple[str, str], list[str]] = {}
    for record in readiness.get("threats") or []:
        if not isinstance(record, dict) or record.get("ready"):
            continue
        mode = str(record.get("mode") or "single").strip().lower()
        if mode not in _COUNT_NEEDED:
            mode = "single"
        reason = str(record.get("reason_code") or "").strip() or (
            _REASON_WHEN_UNMET[mode])
        cell = "/".join([
            str(record.get("feature_id") or ""),
            str(record.get("threat_id") or ""),
        ]).strip("/")
        if not cell:
            continue
        groups.setdefault((mode, reason), []).append(cell)
    requirements: list[dict[str, Any]] = []
    for position, key in enumerate(
            sorted(groups, key=lambda item: (
                _MODE_ORDER.get(item[0], 9), item[1])), start=1):
        mode, reason = key
        cells = sorted(set(groups[key]))
        requirements.append({
            "requirement_id": f"req-{position:03d}",
            "mode": mode,
            "reason_code": reason,
            "role": "",
            "count_needed": _COUNT_NEEDED[mode],
            "count_present": present,
            "blocks_cells": cells,
            "human_action": _HUMAN_ACTION[mode],
        })
    blocked = sum(len(requirement["blocks_cells"]) for requirement in requirements)
    return {
        "schema_version": IDENTITY_REQUIREMENTS_SCHEMA_VERSION,
        "requirements": requirements,
        "summary": {
            "total_requirements": len(requirements),
            "unmet_requirements": len(requirements),
            "blocked_cells": blocked,
            "blocked_high_value_cells": blocked,
            "identities_present": present,
        },
    }


__all__ = [
    "IDENTITY_REQUIREMENTS_SCHEMA_VERSION",
    "count_present_identities",
    "derive_identity_requirements",
    "requirements_from_identity_readiness",
]
