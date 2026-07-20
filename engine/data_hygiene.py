"""Deterministic secret/PII minimization for planning and report projections.

Raw HTTP proof remains untouched in its restricted evidence packet.  This
module protects model planning inputs and human-facing projections, where raw
credentials are never required.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any


_HEADER = re.compile(
    r"(?im)^(?P<prefix>[ \t]*(?:Cookie|Set-Cookie|Authorization|X-Api-Key|"
    r"X-Auth-Token|Proxy-Authorization)[ \t]*:[ \t]*)(?P<value>[^\r\n]+)"
)
_BEARER = re.compile(r"(?i)\bBearer[ \t]+(?P<value>[A-Za-z0-9._~+\-/=]{8,})")
_KEYED = re.compile(
    r"(?i)(?P<prefix>(?<![A-Za-z0-9_])[\"']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"csrf[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret|"
    r"session(?:[_-]?id)?|cookie|token|secret|credential|signature|sign)"
    r"[\"']?[ \t]*[:=][ \t]*[\"']?)"
    r"(?P<value>[^\"'\s,;&}\]]{6,})"
)
_EMAIL = re.compile(r"(?i)(?<![A-Z0-9._%+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![A-Z0-9.-])")
_CN_PHONE = re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)")

# Detection is intentionally independent from the redaction expressions.  A
# regression in replacement syntax must not simultaneously blind the scanner.
_DETECT_AUTH_HEADER = re.compile(
    r"(?im)^(?![^\r\n]*<redacted:)\s*(?:cookie|set-cookie|authorization|proxy-authorization|"
    r"x-api-key|x-auth-token)\s*:\s*(?!<redacted:)[^\r\n]{4,}$")
_DETECT_BEARER = re.compile(
    r"(?i)\bbearer\s+(?!<redacted:)[a-z0-9._~+\-/=]{8,}")
_DETECT_SECRET_ASSIGNMENT = re.compile(
    r"(?im)^(?![^\r\n]*<redacted:)[^\r\n]*?(?<![a-z0-9_])(?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"csrf[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret|"
    r"session(?:[_-]?id)?|token|secret|credential|signature)"
    r"\s*[\"']?\s*[:=]\s*[\"']?(?!<redacted:)[^\s\"',;&}\]]{6,}")
_DETECT_EMAIL = re.compile(
    r"(?i)(?<![a-z0-9._%+-])[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}"
    r"(?![a-z0-9.-])")
_DETECT_CN_PHONE = re.compile(r"(?<!\d)(?:\+?86[ -]?)?1[3-9][0-9]{9}(?!\d)")
_DETECT_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."
    r"[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])")
_DETECT_QUERY_SECRET = re.compile(
    r"(?i)[?&](?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|session)="
    r"(?!<redacted:)[^&#\s]{6,}")


def _placeholder(kind: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"<redacted:{kind}:{digest}>"


def redact_text(text: str) -> tuple[str, dict[str, int]]:
    """Redact high-confidence secrets and common PII with stable placeholders."""
    value = str(text or "")
    counts: dict[str, int] = {}

    def replace_group(match: re.Match[str], kind: str, *, keep_prefix: bool = True) -> str:
        raw = match.group("value")
        if "<redacted:" in raw:
            return match.group(0)
        counts[kind] = counts.get(kind, 0) + 1
        prefix = match.groupdict().get("prefix", "") if keep_prefix else ""
        return f"{prefix}{_placeholder(kind, raw)}"

    value = _HEADER.sub(lambda match: replace_group(match, "auth_header"), value)
    value = _BEARER.sub(
        lambda match: "Bearer " + replace_group(
            match, "bearer", keep_prefix=False),
        value,
    )
    value = _KEYED.sub(lambda match: replace_group(match, "secret"), value)

    def replace_plain(match: re.Match[str], kind: str) -> str:
        raw = match.group(0)
        # Do not repeatedly redact our own placeholders.
        if raw.startswith("<redacted:"):
            return raw
        counts[kind] = counts.get(kind, 0) + 1
        return _placeholder(kind, raw)

    value = _EMAIL.sub(lambda match: replace_plain(match, "email"), value)
    value = _CN_PHONE.sub(lambda match: replace_plain(match, "phone"), value)
    return value, counts


def sensitive_kinds(text: str) -> list[str]:
    """Return only finding kinds, never the sensitive values themselves."""
    value = str(text or "")
    kinds: set[str] = set()
    if _DETECT_AUTH_HEADER.search(value):
        kinds.add("auth_header")
    if _DETECT_BEARER.search(value):
        kinds.add("bearer")
    if _DETECT_SECRET_ASSIGNMENT.search(value):
        kinds.add("secret")
    if _DETECT_EMAIL.search(value):
        kinds.add("email")
    if _DETECT_CN_PHONE.search(value):
        kinds.add("phone")
    if _DETECT_JWT.search(value) or _DETECT_QUERY_SECRET.search(value):
        kinds.add("secret")
    return sorted(kinds)


def redact_json_value(value: Any) -> tuple[Any, dict[str, int]]:
    """Recursively redact JSON string values while preserving its structure."""
    totals: dict[str, int] = {}

    def add(counts: dict[str, int]) -> None:
        for kind, count in counts.items():
            totals[kind] = totals.get(kind, 0) + count

    def walk(item: Any) -> Any:
        if isinstance(item, str):
            redacted, counts = redact_text(item)
            add(counts)
            return redacted
        if isinstance(item, list):
            return [walk(child) for child in item]
        if isinstance(item, dict):
            return {str(key): walk(child) for key, child in item.items()}
        return item

    return walk(value), totals


def canonical_credential_sha256(headers: dict[str, str]) -> str:
    """Hash one credential context without persisting its raw header values."""
    normalized = {
        str(key).strip().lower(): str(value).strip()
        for key, value in headers.items() if str(key).strip() and str(value).strip()
    }
    payload = json.dumps(
        normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest() if normalized else ""


__all__ = [
    "canonical_credential_sha256",
    "redact_json_value",
    "redact_text",
    "sensitive_kinds",
]
