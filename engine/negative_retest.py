"""Cross-stage diversity contract for input-validation negative evidence."""
from __future__ import annotations

import re
from typing import Any, Iterable

try:
    from .vuln_classes import norm_vc
except ImportError:  # pragma: no cover - direct engine script fallback
    from vuln_classes import norm_vc


_INPUT_FAMILIES = {"sqli", "xss", "rce", "ssrf", "file", "redirect"}


def is_input_validation_cell(cell: dict[str, Any]) -> bool:
    family = norm_vc(str(
        cell.get("vuln_class") or cell.get("vuln") or cell.get("legacy_vuln") or ""))
    tags = " ".join(str(value).lower() for value in cell.get("risk_tags") or [])
    return family in _INPUT_FAMILIES or bool(re.search(
        r"(?:input|inject|upload|file|redirect|ssrf|xss|sqli|command)", tags))


def packet_families(packet: dict[str, Any]) -> tuple[str, str]:
    """Derive encoding/strategy families without trusting a vector count."""
    vector = str(packet.get("vector") or "").strip().lower()
    encoding = str(packet.get("encoding_family") or packet.get("encoding") or "").strip().lower()
    strategy = str(packet.get("strategy_family") or packet.get("strategy") or "").strip().lower()
    combined = " ".join((vector, encoding, strategy))
    if not encoding:
        if "double" in combined and ("url" in combined or "%25" in combined):
            encoding = "double_url"
        elif "unicode" in combined or "\\u" in combined or "%u" in combined:
            encoding = "unicode"
        elif "multipart" in combined:
            encoding = "multipart"
        elif "json" in combined:
            encoding = "json"
        elif "form" in combined:
            encoding = "form"
        elif "hpp" in combined or "parameter pollution" in combined:
            encoding = "hpp"
        elif "url" in combined or re.search(r"%[0-9a-f]{2}", combined):
            encoding = "url"
        else:
            encoding = "raw"
    if not strategy:
        patterns = (
            ("boolean", r"bool|true.?false"),
            ("time", r"time|sleep|delay|benchmark"),
            ("error", r"error|extractvalue|updatexml"),
            ("union", r"union"),
            ("stacked", r"stacked|multi.?statement"),
            ("stored", r"stored|persist|post.?get"),
            ("reflected", r"reflect"),
            ("dom", r"\bdom\b"),
            ("path_traversal", r"traversal|dot.?dot|path"),
            ("command", r"command|shell|rce"),
            ("parser_confusion", r"type|parser|array|hpp|multipart"),
        )
        strategy = next((name for name, pattern in patterns
                         if re.search(pattern, combined)), "generic")
    return re.sub(r"[^a-z0-9_]+", "_", encoding).strip("_") or "raw", re.sub(
        r"[^a-z0-9_]+", "_", strategy).strip("_") or "generic"


def families_from_packets(packets: Iterable[dict[str, Any]]) -> tuple[list[str], list[str]]:
    encodings: set[str] = set()
    strategies: set[str] = set()
    for packet in packets:
        if not isinstance(packet, dict):
            continue
        encoding, strategy = packet_families(packet)
        encodings.add(encoding)
        strategies.add(strategy)
    return sorted(encodings), sorted(strategies)


def has_cross_stage_diversity(
    current: dict[str, Any], prior: dict[str, Any],
) -> tuple[bool, list[str]]:
    """Require at least one new encoding family and one new strategy family."""
    current_enc = set(current.get("encoding_families") or [])
    current_strat = set(current.get("strategy_families") or [])
    prior_enc = set(prior.get("negative_encoding_families")
                    or prior.get("encoding_families") or [])
    prior_strat = set(prior.get("negative_strategy_families")
                      or prior.get("strategy_families") or [])
    reasons: list[str] = []
    if prior_enc:
        if not current_enc - prior_enc:
            reasons.append("cross_stage_negative_encoding_not_new")
    elif len(current_enc) < 2:
        reasons.append("cross_stage_negative_encoding_diversity_unproven")
    if prior_strat:
        if not current_strat - prior_strat:
            reasons.append("cross_stage_negative_strategy_not_new")
    elif len(current_strat) < 2:
        reasons.append("cross_stage_negative_strategy_diversity_unproven")
    return not reasons, reasons


__all__ = [
    "families_from_packets", "has_cross_stage_diversity",
    "is_input_validation_cell", "packet_families",
]
