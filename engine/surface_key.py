"""Canonical surface key helpers for Atoolkit v8.6.

All modules (scheduler, business_graph, orchestrator) must use these helpers
to normalize surface identifiers to a single canonical form so that budget
accounting, deduplication, and cross-run inheritance are consistent.

Frozen contract:
    surface_key      = "METHOD /path"                    (e.g. "POST /api/refund")
    surface_cell     = "METHOD /path :: param × class"  (budget unit)

The ``:: param`` segment is omitted when a surface has no known parameter.
"""
from __future__ import annotations

import re

_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

_SCHEME_HOST_RE = re.compile(r'^https?://[^/]+', re.IGNORECASE)

# Separator used in surface_cell keys. A non-ASCII multiplication sign avoids
# collisions with endpoint paths or vuln class names that may contain '-'.
_CELL_SEP = " × "


def _strip_host(path: str) -> str:
    """Strip scheme://host:port prefix, leaving only the path."""
    return _SCHEME_HOST_RE.sub('', path)


def canonical_surface_key(item, default_method: str = "GET") -> str:
    """Normalize any surface representation to ``"METHOD /path"``.

    Accepts:
        "/api/refund"
        "GET /api/refund"
        {"endpoint": "/api/refund", "method": "GET"}
        {"endpoint": "GET /api/refund"}
        {"path": "/api/refund", "method": "POST"}
        {"url": "https://t.example/api/refund", "method": "GET"}
    """
    method = default_method.upper()
    path = ""

    if isinstance(item, dict):
        # Method may come from explicit "method" key, or be embedded in
        # "endpoint"/"url" as a "METHOD /path" string.
        m = (item.get("method") or "").strip()
        ep = (item.get("endpoint") or item.get("path") or item.get("url") or "").strip()
        if m and m.upper() in _HTTP_METHODS:
            method = m.upper()
        if ep:
            # Strip a leading "METHOD " prefix from ep so we don't double it
            # when both explicit method and embedded-method endpoint are present.
            parts = ep.strip().split(None, 1)
            if len(parts) == 2 and parts[0].upper() in _HTTP_METHODS:
                method = parts[0].upper()
                ep = parts[1]
        path = ep
    elif isinstance(item, str):
        s = item.strip()
        parts = s.split(None, 1)
        if len(parts) == 2 and parts[0].upper() in _HTTP_METHODS:
            method = parts[0].upper()
            path = parts[1]
        else:
            path = s
    else:
        path = str(item).strip()

    path = _strip_host(path).strip()
    if not path:
        return ""
    return f"{method} {path}"


def canonical_cell_key(surface_key: str, vuln_class: str, param: str = "") -> str:
    """Build a parameter-aware surface-cell key.

    ``surface_key`` may be a bare path (no method prefix); it is canonicalized
    first so callers do not need to pre-normalize.
    """
    sk = canonical_surface_key(surface_key)
    vc = (vuln_class or "").strip()
    param_part = f" :: {str(param).strip()}" if str(param or "").strip() else ""
    return f"{sk}{param_part}{_CELL_SEP}{vc}"


def is_canonical(key: str) -> bool:
    """Return True if *key* is in canonical ``"METHOD /path"`` form."""
    if not key or not isinstance(key, str):
        return False
    parts = key.split(None, 1)
    if len(parts) != 2:
        return False
    method, path = parts[0].upper(), parts[1]
    if method not in _HTTP_METHODS:
        return False
    if not path.startswith("/"):
        return False
    return True
