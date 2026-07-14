"""Canonical v8.9 coverage-cell identity.

Runtime coverage and cross-run project truth must use the same identity.  The
minimum identity is the origin asset, request method/path/parameter, actor
role and vulnerability class.  Optional dimensions are retained as metadata
so the schema can grow without changing the compatibility key used by v8.8.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable
from urllib.parse import urlparse

try:
    from .project_state import canonical_asset, canonical_project_cell_key
except ImportError:  # pragma: no cover - script execution fallback
    from project_state import canonical_asset, canonical_project_cell_key


CELL_IDENTITY_VERSION = 2
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def _as_list(value: Any) -> list[Any]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _dedupe(values: Iterable[Any], *, lower: bool = False) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        normalized = text.lower() if lower else text
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(normalized)
    return sorted(out, key=str.lower)


def _absolute_url(value: Any) -> str:
    text = str(value or "").strip()
    parts = text.split(None, 1)
    if len(parts) == 2 and parts[0].upper() in _METHODS:
        text = parts[1].strip()
    parsed = urlparse(text)
    return text if parsed.scheme in {"http", "https"} and parsed.hostname else ""


def surface_assets(surface: dict[str, Any] | None, fallback_asset: str = "") -> list[str]:
    """Return exact canonical assets for a surface.

    An explicit asset field is authoritative.  If it is present but invalid,
    no fallback is used; silently assigning such a surface to another origin
    would corrupt project truth.
    """
    item = surface if isinstance(surface, dict) else {}
    explicit_present = any(key in item for key in ("assets", "asset", "asset_id"))
    raw_assets = (
        _as_list(item.get("assets"))
        + _as_list(item.get("asset"))
        + _as_list(item.get("asset_id"))
    )
    assets = _dedupe(canonical_asset(value) for value in raw_assets)
    if explicit_present:
        return assets

    for key in ("endpoint", "path", "url", "target"):
        absolute = _absolute_url(item.get(key))
        if absolute:
            asset = canonical_asset(absolute)
            return [asset] if asset else []
    fallback = canonical_asset(fallback_asset)
    return [fallback] if fallback else []


def surface_actor_roles(surface: dict[str, Any] | None) -> list[str]:
    """Expand every declared actor role, retaining ``unknown`` for old data."""
    item = surface if isinstance(surface, dict) else {}
    values: list[Any] = []
    for key in (
        "actor_roles", "actor_role", "role_scopes", "role_scope",
        "roles", "role", "affected_roles", "affected_role", "observed_roles",
        "needed_roles",
    ):
        values.extend(_as_list(item.get(key)))
    return _dedupe(values, lower=True) or ["unknown"]


@dataclass(frozen=True)
class CellIdentity:
    asset_id: str
    method: str
    path: str
    param: str = ""
    actor_role: str = "unknown"
    vuln_class: str = ""
    namespace: str = ""
    param_location: str = ""
    subject_role: str = ""
    object_kind: str = ""
    identity_version: int = CELL_IDENTITY_VERSION

    @classmethod
    def from_parts(
        cls,
        asset: str,
        *,
        method: str,
        path: str,
        param: str = "",
        actor_role: str = "unknown",
        vuln_class: str = "",
        **metadata: Any,
    ) -> "CellIdentity":
        return cls(
            asset_id=canonical_asset(asset),
            method=str(method or "GET").strip().upper() or "GET",
            path=str(path or "").strip(),
            param=str(param or "").strip(),
            actor_role=str(actor_role or "unknown").strip().lower() or "unknown",
            vuln_class=str(vuln_class or "").strip(),
            namespace=str(metadata.get("namespace") or "").strip(),
            param_location=str(metadata.get("param_location") or "").strip().lower(),
            subject_role=str(metadata.get("subject_role") or "").strip().lower(),
            object_kind=str(metadata.get("object_kind") or "").strip().lower(),
        )

    @property
    def key(self) -> str:
        return canonical_project_cell_key(
            self.asset_id,
            method=self.method,
            path=self.path,
            param=self.param,
            role_scope=self.actor_role,
            vuln_class=self.vuln_class,
            namespace=self.namespace,
            param_location=self.param_location,
            subject_role=self.subject_role,
            object_kind=self.object_kind,
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["cell_key"] = self.key
        data["role_scope"] = self.actor_role
        return data


def runtime_cell_key(
    asset: str,
    *,
    method: str,
    path: str,
    param: str = "",
    actor_role: str = "unknown",
    vuln_class: str = "",
    namespace: str = "",
    param_location: str = "",
    subject_role: str = "",
    object_kind: str = "",
) -> str:
    """Backward-compatible function form of :class:`CellIdentity`."""
    return CellIdentity.from_parts(
        asset,
        method=method,
        path=path,
        param=param,
        actor_role=actor_role,
        vuln_class=vuln_class,
        namespace=namespace,
        param_location=param_location,
        subject_role=subject_role,
        object_kind=object_kind,
    ).key


canonical_runtime_cell_key = runtime_cell_key


__all__ = [
    "CELL_IDENTITY_VERSION", "CellIdentity", "canonical_runtime_cell_key",
    "runtime_cell_key", "surface_actor_roles", "surface_assets",
]
