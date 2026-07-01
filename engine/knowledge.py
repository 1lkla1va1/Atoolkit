"""
engine/knowledge.py - lightweight knowledge helpers for coverage decisions.

This module is deliberately defensive: cards describe review dimensions,
evidence expectations, and negative sufficiency rules. They must not carry
concrete attack strings, bypass syntax, or exploit recipes.
"""
from __future__ import annotations

import json
import pathlib
import re
from typing import Any


DEFAULT_MIN_VECTORS = 3

NEGATIVE_WITH_EVIDENCE = "negative_with_evidence"
SHALLOW_NEGATIVE = "shallow_negative"

_DEFAULT_MISSING = "补足至少 3 个独立探测向量，并保留响应证据"
_CARD_DIR = pathlib.Path(__file__).resolve().parent.parent / "knowledge" / "cards"

# Guardrail for the input-validation card. Keep this intentionally conservative:
# the card may name dimensions and evidence classes, but not concrete strings
# that would become an attack-string catalog.
_INPUT_VALIDATION_FORBIDDEN = (
    "<script",
    "../",
    "..\\",
    " union ",
    " select ",
    " or 1=1",
    "sleep(",
    "benchmark(",
    "%27",
    "%3c",
    "${",
    "{{",
    "payload",
    "bypass",
    "绕过编码",
    "绕过正则",
)


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def _norm_text(value: Any) -> str:
    return str(value or "").strip().lower()


def _unique_norm(values: list) -> set[str]:
    return {_norm_text(v) for v in values if _norm_text(v)}


def _string_values(obj: Any) -> list[str]:
    if isinstance(obj, dict):
        out: list[str] = []
        for value in obj.values():
            out.extend(_string_values(value))
        return out
    if isinstance(obj, list):
        out: list[str] = []
        for value in obj:
            out.extend(_string_values(value))
        return out
    if isinstance(obj, str):
        return [obj]
    return []


def _surface(cell_or_surface: dict) -> dict:
    surface = cell_or_surface.get("surface")
    if isinstance(surface, dict):
        return surface
    return cell_or_surface


def _haystack(cell_or_surface: dict) -> str:
    surface = _surface(cell_or_surface)
    chunks: list[str] = []
    for key in ("endpoint", "vuln", "feature", "method", "source"):
        chunks.append(str(cell_or_surface.get(key, "")))
        chunks.append(str(surface.get(key, "")))
    for key in ("params", "needed_roles", "needs"):
        chunks.extend(str(x) for x in _as_list(cell_or_surface.get(key)))
        chunks.extend(str(x) for x in _as_list(surface.get(key)))
    identity_meta = cell_or_surface.get("identity_meta") or surface.get("identity_meta")
    if isinstance(identity_meta, dict):
        chunks.extend(str(x) for x in identity_meta.values())
    elif identity_meta:
        chunks.append(str(identity_meta))
    return " ".join(chunks).lower()


def _match_context(cell_or_surface: dict) -> dict[str, set[str] | str]:
    surface = _surface(cell_or_surface)
    endpoint = " ".join(
        str(x or "")
        for x in (
            cell_or_surface.get("endpoint"),
            surface.get("endpoint"),
            cell_or_surface.get("feature"),
            surface.get("feature"),
            cell_or_surface.get("source"),
            surface.get("source"),
        )
    ).lower()
    params = _unique_norm(_as_list(cell_or_surface.get("params")) + _as_list(surface.get("params")))
    vuln = _norm_text(cell_or_surface.get("vuln") or surface.get("vuln"))
    roles = _unique_norm(_as_list(cell_or_surface.get("needed_roles")) + _as_list(surface.get("needed_roles")))
    identity_meta = cell_or_surface.get("identity_meta") or surface.get("identity_meta")
    if isinstance(identity_meta, dict):
        roles.update(_norm_text(x) for x in identity_meta.values() if _norm_text(x))
    tokens = set(re.findall(r"[a-z0-9_]+|[\u4e00-\u9fff]+", _haystack(cell_or_surface)))
    return {"endpoint": endpoint, "params": params, "vuln": vuln, "roles": roles, "tokens": tokens}


def _has_match(match: dict, ctx: dict[str, set[str] | str]) -> bool:
    endpoint = str(ctx["endpoint"])
    params = ctx["params"]
    vuln = str(ctx["vuln"])
    roles = ctx["roles"]
    tokens = ctx["tokens"]

    if any(_norm_text(x) and _norm_text(x) in endpoint for x in _as_list(match.get("endpoints"))):
        return True
    if any(_norm_text(x) and _norm_text(x) in endpoint for x in _as_list(match.get("features"))):
        return True
    if any(_norm_text(x) in params for x in _as_list(match.get("params"))):
        return True
    if any(_norm_text(x) and (_norm_text(x) == vuln or _norm_text(x) in vuln) for x in _as_list(match.get("vuln_classes"))):
        return True
    if any(_norm_text(x) in tokens for x in _as_list(match.get("keywords"))):
        return True
    if any(_norm_text(x) in roles for x in _as_list(match.get("roles"))):
        return True
    return False


def _validate_card(card: dict, *, source: pathlib.Path | None = None) -> dict:
    if not isinstance(card, dict):
        raise ValueError(f"knowledge card must be an object: {source or '<memory>'}")
    card_id = str(card.get("id") or "").strip()
    if not card_id:
        raise ValueError(f"knowledge card missing id: {source or '<memory>'}")
    for key in ("dimensions", "false_negative_rules", "evidence_required", "negative_sufficiency"):
        if key not in card:
            raise ValueError(f"knowledge card {card_id} missing {key}")

    if card_id == "input-validation":
        joined = "\n".join(_string_values(card)).lower()
        for forbidden in _INPUT_VALIDATION_FORBIDDEN:
            if forbidden in joined:
                raise ValueError(
                    f"input-validation card contains forbidden content {forbidden!r}: {source or '<memory>'}"
                )
    return card


def load_cards(cards_dir: str | pathlib.Path | None = None) -> list[dict]:
    """Load knowledge cards from JSON files, sorted for deterministic prompts."""
    base = pathlib.Path(cards_dir) if cards_dir is not None else _CARD_DIR
    if not base.exists():
        return []
    cards: list[dict] = []
    for path in sorted(base.glob("*.json")):
        card = json.loads(path.read_text(encoding="utf-8"))
        cards.append(_validate_card(card, source=path))
    return cards


def match_cards(cell_or_surface: dict, cards: list[dict] | None = None) -> list[dict]:
    """Return cards whose non-payload trigger metadata matches a cell/surface."""
    if not cell_or_surface:
        return []
    candidates = cards if cards is not None else load_cards()
    ctx = _match_context(cell_or_surface)
    matched: list[dict] = []
    for card in candidates:
        card = _validate_card(card)
        match = card.get("match") or {}
        if _has_match(match, ctx):
            matched.append(card)
    return matched


def _requirements(cell: dict, cards: list[dict] | None) -> tuple[int, int, set[str], int, set[str], list[str]]:
    min_vectors = DEFAULT_MIN_VECTORS
    min_response_count = 1
    required_evidence_types: set[str] = set()
    min_identities = 0
    required_roles: set[str] = set()
    labels: list[str] = []

    for card in match_cards(cell, cards) if cards else []:
        labels.append(str(card.get("title") or card.get("id")))
        suff = card.get("negative_sufficiency") or {}
        min_vectors = max(min_vectors, int(suff.get("min_vectors", 0) or 0))
        min_response_count = max(min_response_count, int(suff.get("min_response_count", 0) or 0))
        required_evidence_types.update(_norm_text(x) for x in _as_list(suff.get("required_evidence_types")))
        min_identities = max(min_identities, int(suff.get("min_identities", 0) or 0))
        required_roles.update(_norm_text(x) for x in _as_list(suff.get("required_roles")))
    required_evidence_types.discard("")
    required_roles.discard("")
    return min_vectors, min_response_count, required_evidence_types, min_identities, required_roles, labels


def negative_sufficient(
    cell: dict,
    negative_obj: dict,
    cards: list[dict] | None = None,
) -> tuple[bool, list[str]]:
    """Decide whether negative evidence is sufficient to close a matrix cell.

    Phase 1 default: at least DEFAULT_MIN_VECTORS independent vectors and one
    response evidence marker. Phase 2 cards can raise requirements, but never
    lower the default.
    """
    vectors = _unique_norm(_as_list(negative_obj.get("vectors")))
    response_count = int(negative_obj.get("response_count", 0) or 0)
    evidence_types = _unique_norm(_as_list(negative_obj.get("evidence_types")))
    identities = _unique_norm(_as_list(negative_obj.get("identities")))
    roles = _unique_norm(_as_list(negative_obj.get("roles")))

    min_vectors, min_response_count, required_evidence_types, min_identities, required_roles, labels = _requirements(
        cell or {}, cards
    )

    missing: list[str] = []
    if len(vectors) < min_vectors:
        missing.append(f"补足至少 {min_vectors} 个独立探测向量")
    if response_count < min_response_count:
        missing.append(f"保留至少 {min_response_count} 份响应证据")
    lack_evidence = sorted(required_evidence_types - evidence_types)
    if lack_evidence:
        missing.append("补充证据类型: " + "、".join(lack_evidence))
    if min_identities and len(identities) < min_identities:
        missing.append(f"补足至少 {min_identities} 个已授权身份的对照证据")
    lack_roles = sorted(required_roles - roles)
    if lack_roles:
        missing.append("补充授权角色证据: " + "、".join(lack_roles))

    if missing:
        if not labels:
            return False, [_DEFAULT_MISSING]
        return False, missing
    return True, []


def resolve_negative_state(
    cell: dict,
    negative_obj: dict,
    cards: list[dict] | None = None,
) -> tuple[str, list[str]]:
    sufficient, missing = negative_sufficient(cell, negative_obj, cards)
    if sufficient:
        return NEGATIVE_WITH_EVIDENCE, []
    return SHALLOW_NEGATIVE, missing


def render_skill_hint(cards: list[dict] | None = None) -> str:
    """Render a compact, payload-free hint block for matched cards."""
    selected = cards or []
    if not selected:
        return ""
    lines = ["## 知识卡提示（只含测试维度与证据要求，不含具体攻击字符串）"]
    for card in selected:
        card = _validate_card(card)
        title = card.get("title") or card.get("id")
        dimensions = "；".join(str(x) for x in _as_list(card.get("dimensions"))[:4])
        evidence = "；".join(str(x) for x in _as_list(card.get("evidence_required"))[:4])
        suff = card.get("negative_sufficiency") or {}
        min_vectors = suff.get("min_vectors", DEFAULT_MIN_VECTORS)
        min_response_count = suff.get("min_response_count", 1)
        lines.append(f"- {title}: 维度={dimensions}；证据={evidence}；阴性闭合≥{min_vectors}向量/{min_response_count}响应")
    return "\n".join(lines)


__all__ = [
    "DEFAULT_MIN_VECTORS",
    "NEGATIVE_WITH_EVIDENCE",
    "SHALLOW_NEGATIVE",
    "load_cards",
    "match_cards",
    "negative_sufficient",
    "resolve_negative_state",
    "render_skill_hint",
]
