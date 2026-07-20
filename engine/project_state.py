"""Authoritative cross-run project state for Atoolkit v8.8.

The legacy ``blackboard.json`` remains an import/compatibility view.  New
cross-run truth is committed through :class:`ProjectStateStore` so inventory,
coverage cells, root findings and run history cannot drift independently.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Iterator
from urllib.parse import parse_qsl, urlparse

try:  # pragma: no cover - Windows fallback is covered by the thread lock
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

try:
    from .surface_key import canonical_surface_key
    from .vuln_classes import exact_vc, norm_vc
except ImportError:  # pragma: no cover
    from surface_key import canonical_surface_key
    from vuln_classes import exact_vc, norm_vc


PROJECT_STATE_SCHEMA_VERSION = 3
DEAD_END_REASON_CODES = {
    "endpoint_removed",
    "feature_disabled",
    "method_not_supported",
    "parameter_not_consumed",
    "role_not_applicable",
    "vulnerability_class_not_applicable",
}


class ProjectStateError(RuntimeError):
    pass


class ProjectStateCorrupt(ProjectStateError):
    pass


_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX_RE = re.compile(r"^[0-9a-f]{12,}$", re.I)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_id(prefix: str, value: str) -> str:
    return f"{prefix}_{hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]}"


def _sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _evidence_path(project_dir: pathlib.Path, run_id: str, ref: str) -> pathlib.Path | None:
    text = str(ref or "").strip()
    if not text:
        return None
    if text.startswith("session:"):
        payload = text[len("session:"):]
        sid, separator, relative = payload.partition("/")
        if not separator or not sid or not relative:
            return None
        path = project_dir / "sessions" / sid / relative
    elif text.startswith("project:"):
        path = project_dir / text[len("project:"):]
    else:
        raw = pathlib.Path(text)
        path = raw if raw.is_absolute() else project_dir / "sessions" / run_id / raw
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(project_dir.resolve())
    except ValueError:
        return None
    return resolved


def verify_project_evidence(
    project_dir: str | pathlib.Path,
    refs: list[str],
    hashes: dict[str, str],
) -> bool:
    root = pathlib.Path(project_dir).resolve()
    if not refs or not hashes:
        return False
    for ref in refs:
        path = _evidence_path(root, "", ref)
        if path is None or not path.is_file():
            return False
        expected = str(hashes.get(ref) or "")
        if not expected or _sha256_file(path) != expected:
            return False
    return True


def canonical_asset(value: str) -> str:
    text = str(value or "").strip()
    parsed = urlparse(text if "://" in text else f"https://{text}")
    hostname = parsed.hostname or ""
    if (parsed.scheme not in {"http", "https"} or not hostname
            or any(ch.isspace() for ch in hostname)):
        return ""
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return ""
    return f"{parsed.scheme.lower()}://{hostname.lower()}:{port}"


def _path_from(value: str) -> str:
    text = str(value or "").strip()
    parts = text.split(None, 1)
    if len(parts) == 2 and parts[0].upper() in _METHODS:
        text = parts[1]
    parsed = urlparse(text)
    path = parsed.path if parsed.scheme and parsed.netloc else text.split("?", 1)[0].split("#", 1)[0]
    path = re.sub(r"/{2,}", "/", path or "/")
    return path if path.startswith("/") else "/" + path


def _method_and_path(item: dict[str, Any]) -> tuple[str, str]:
    endpoint = str(item.get("endpoint") or item.get("path") or item.get("target") or "").strip()
    method = str(item.get("method") or "").upper().strip()
    parts = endpoint.split(None, 1)
    if len(parts) == 2 and parts[0].upper() in _METHODS:
        method, endpoint = parts[0].upper(), parts[1]
    return (method if method in _METHODS else "", _path_from(endpoint))


def _asset_from_target(value: Any) -> str:
    text = str(value or "").strip()
    parts = text.split(None, 1)
    if len(parts) == 2 and parts[0].upper() in _METHODS:
        text = parts[1].strip()
    return canonical_asset(text) if "://" in text else ""


def _asset_from(item: dict[str, Any], fallback: str = "") -> str:
    explicit_present = any(key in item for key in ("assets", "asset", "asset_id"))
    explicit_values = _as_list(item.get("assets")) + _as_list(
        item.get("asset")) + _as_list(item.get("asset_id"))
    for value in explicit_values:
        asset = canonical_asset(str(value or ""))
        if asset:
            return asset
    if explicit_present:
        return ""
    target = str(item.get("target") or item.get("endpoint") or "")
    if "://" in target:
        return _asset_from_target(target)
    return canonical_asset(fallback)


def _as_list(value: Any) -> list[Any]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _assets_from(item: dict[str, Any], fallback: str = "") -> list[str]:
    explicit_present = any(key in item for key in ("assets", "asset", "asset_id"))
    raw = (_as_list(item.get("assets")) + _as_list(item.get("asset"))
           + _as_list(item.get("asset_id")))
    assets: list[str] = []
    for value in raw:
        asset = canonical_asset(str(value or ""))
        if asset and asset not in assets:
            assets.append(asset)
    if explicit_present:
        return assets
    target = str(item.get("target") or item.get("endpoint") or "")
    if "://" in target:
        asset = _asset_from_target(target)
        return [asset] if asset else []
    asset = canonical_asset(fallback)
    return [asset] if asset else []


def _params_from(item: dict[str, Any], *, default_empty: bool = False) -> list[str]:
    values = _as_list(item.get("param")) + _as_list(item.get("params"))
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in out:
            out.append(text)
    return out or ([""] if default_empty else [])


def _roles_from(item: dict[str, Any]) -> list[str]:
    values: list[Any] = []
    for key in ("affected_roles", "affected_role", "role_scopes", "role_scope",
                "roles", "role", "actor_roles", "actor_role", "observed_roles"):
        values.extend(_as_list(item.get(key)))
    out: list[str] = []
    for value in values:
        role = str(value or "").strip().lower()
        if role and role not in out:
            out.append(role)
    return out or ["unknown"]


def _identity_dimensions(item: dict[str, Any]) -> dict[str, str]:
    return {
        "namespace": str(item.get("namespace") or "").strip(),
        "param_location": str(item.get("param_location") or "").strip().lower(),
        "subject_role": str(item.get("subject_role") or "").strip().lower(),
        "object_kind": str(item.get("object_kind") or "").strip().lower(),
    }


def _root_cause_from(item: dict[str, Any]) -> str:
    """Return the stable root-cause invariant used for cross-run dedupe.

    Normalized findings retain the machine-checked claim invariant separately
    from ``root_cause`` (which older normalizers often populated with only the
    vulnerability class).  Prefer the invariant fields so a parameter rename
    cannot create a second root finding and two distinct causes do not collapse
    merely because they share an endpoint and class.
    """
    claim = item.get("claim") if isinstance(item.get("claim"), dict) else {}
    for value in (
        item.get("root_cause_invariant"),
        item.get("claim_invariant"),
        claim.get("invariant"),
        item.get("root_cause"),
        item.get("vuln_class"),
        item.get("class"),
        item.get("vuln_type"),
    ):
        text = re.sub(r"\s+", " ", str(value or "").strip())
        if text:
            return text
    return "unknown-root-cause"


def _param_locations_from(item: dict[str, Any]) -> dict[str, str]:
    locations: dict[str, str] = {}
    singular_location = str(item.get("param_location") or "").strip().lower()
    if singular_location:
        for param in _params_from(item):
            locations[param] = singular_location
    for key, location in (
        ("query_params", "query"), ("body_params", "body"),
        ("form_params", "form"), ("path_params", "path"),
    ):
        for value in _as_list(item.get(key)):
            if isinstance(value, dict):
                name = str(
                    value.get("name") or value.get("key")
                    or value.get("param") or "").strip()
                actual = str(value.get("location") or value.get("in") or location).lower()
            else:
                name = str(value or "").strip()
                actual = location
            if name:
                locations[name] = actual
    endpoint = str(item.get("endpoint") or item.get("path") or item.get("target") or "")
    parsed = urlparse(endpoint.split(None, 1)[-1])
    query_names = {name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    for param in _params_from(item):
        if param in locations:
            continue
        if re.search(rf"\{{{re.escape(param)}\}}|:{re.escape(param)}(?:/|$)", endpoint):
            locations[param] = "path"
        elif param in query_names:
            locations[param] = "query"
    return locations


def _resolved_identity(
    state: dict[str, Any], item: dict[str, Any], *,
    asset: str, method: str, path: str, param: str,
) -> tuple[dict[str, str], str]:
    dimensions = _identity_dimensions(item)
    if not param:
        return dimensions, _template_path(path)
    original = str(item.get("endpoint") or item.get("target") or item.get("path") or "")
    if re.search(rf"\{{{re.escape(param)}\}}|:{re.escape(param)}(?:/|$)", original):
        dimensions["param_location"] = "path"
        return dimensions, _template_path(
            path, param=param, param_location="path")
    parsed = urlparse(original.split(None, 1)[-1])
    if any(key == param for key, _ in parse_qsl(
            parsed.query, keep_blank_values=True)):
        dimensions["param_location"] = "query"
        return dimensions, _template_path(path)
    if dimensions["param_location"] and dimensions["param_location"] != "path":
        return dimensions, _template_path(path)
    inventory_surfaces = list(
        (state.get("inventory", {}).get("surfaces", {}) or {}).values())
    known_cells = list((state.get("cell_registry") or {}).values())
    matching_surfaces: list[dict[str, Any]] = []
    for surface in [*inventory_surfaces, *known_cells]:
        if not isinstance(surface, dict):
            continue
        surface_params = _params_from(surface, default_empty=True)
        if (surface.get("asset_id") != asset
                or str(surface.get("method") or "") != method
                or param not in surface_params):
            continue
        if any(
            dimensions[name]
            and str(surface.get(name) or "").strip().lower()
            != dimensions[name].lower()
            for name in ("namespace", "subject_role", "object_kind")
        ):
            continue
        schema_path = str(surface.get("path") or "")
        if (_path_from(schema_path) == _path_from(path)
                or _template_matches(schema_path, path)):
            matching_surfaces.append(surface)
    known_locations = {
        str(
            (surface.get("param_locations") or {}).get(param)
            or surface.get("param_location") or ""
        ).lower()
        for surface in matching_surfaces
        if str(
            (surface.get("param_locations") or {}).get(param)
            or surface.get("param_location") or ""
        ).strip()
    }
    explicit_path_schema = any(
        re.search(
            rf"(?:\{{{re.escape(param)}\}}|:{re.escape(param)}(?:/|$))",
            str(surface.get("path") or ""), re.IGNORECASE)
        for surface in matching_surfaces
    )
    if len(known_locations) == 1:
        dimensions["param_location"] = next(iter(known_locations))
    elif explicit_path_schema:
        dimensions["param_location"] = "path"
    schema_templates = {
        _explicit_template_path(str(surface.get("path") or ""))
        for surface in matching_surfaces
        if "{" in _explicit_template_path(str(surface.get("path") or ""))
    }
    canonical_path = (
        next(iter(schema_templates)) if len(schema_templates) == 1
        else _template_path(
            path, param=param,
            param_location=dimensions.get("param_location", ""))
    )
    return dimensions, canonical_path


def _single_scope_fallback(state: dict[str, Any]) -> str:
    scopes = [canonical_asset(x) for x in (state.get("project_scope") or [])]
    scopes = [x for x in scopes if x]
    return scopes[0] if len(set(scopes)) == 1 else ""


def _explicit_template_path(path: str) -> str:
    """Normalize only path templates that are explicit in source data."""
    out: list[str] = []
    for segment in _path_from(path).split("/"):
        if re.fullmatch(r"\{[^/{}]+\}", segment):
            out.append("{id}")
        elif re.fullmatch(r":[A-Za-z_][A-Za-z0-9_]*", segment):
            out.append("{id}")
        else:
            out.append(segment)
    return "/".join(out)


def _template_path(
    path: str, *, param: str = "", param_location: str = "",
) -> str:
    """Return a conservative endpoint template.

    Numeric/UUID/hex literals are not object identifiers by themselves: a
    fixed route such as ``/reports/2024`` must remain distinct from
    ``/reports/2025``.  A concrete segment is templated only when the schema
    explicitly says that this parameter lives in the path, and only when one
    candidate segment exists so the parameter-to-segment mapping is
    unambiguous.  Already-declared ``{name}``/``:name`` templates are retained
    in canonical ``{id}`` form; the parameter name remains a separate cell
    dimension.
    """
    normalized = _explicit_template_path(path)
    if str(param_location or "").strip().lower() != "path":
        return normalized
    name = str(param or "").strip()
    if not name or "{" in normalized:
        return normalized
    segments = normalized.split("/")
    candidates = [
        index for index, segment in enumerate(segments)
        if (segment.isdigit() or _UUID_RE.fullmatch(segment)
            or _HEX_RE.fullmatch(segment))
    ]
    if len(candidates) == 1:
        segments[candidates[0]] = "{id}"
    return "/".join(segments)


def _template_matches(template: str, concrete: str) -> bool:
    """Match an explicit endpoint template without guessing object segments."""
    template_parts = _explicit_template_path(template).split("/")
    concrete_parts = _path_from(concrete).split("/")
    if len(template_parts) != len(concrete_parts):
        return False
    return all(
        bool(value) if re.fullmatch(r"\{[^/{}]+\}", expected)
        else expected == value
        for expected, value in zip(template_parts, concrete_parts)
    )


def _canonical_row_path(
    path: str, param: str, dimensions: dict[str, str],
) -> str:
    return _template_path(
        path, param=param,
        param_location=str(dimensions.get("param_location") or ""))


def _dimensioned_inventory_key(
    base: str, *, namespace: str = "", subject_role: str = "",
    object_kind: str = "",
) -> str:
    """Keep app/subject/object variants distinct in project inventory."""
    dimensions = {
        "namespace": str(namespace or "").strip(),
        "subject_role": str(subject_role or "").strip().lower(),
        "object_kind": str(object_kind or "").strip().lower(),
    }
    if not any(dimensions.values()):
        return base
    encoded = json.dumps(
        dimensions, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    suffix = hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:20]
    return f"{base} :: inventory-v2:{suffix}"


def canonical_project_surface_key(
    asset: str, method: str, path: str, *, namespace: str = "",
    subject_role: str = "", object_kind: str = "",
) -> str:
    asset_id = canonical_asset(asset)
    surface = canonical_surface_key({"method": method, "endpoint": _path_from(path)})
    base = f"{asset_id} :: {surface}" if asset_id and surface else ""
    return _dimensioned_inventory_key(
        base, namespace=namespace, subject_role=subject_role,
        object_kind=object_kind) if base else ""


def canonical_project_cell_key(
    asset: str,
    *,
    method: str,
    path: str,
    param: str = "",
    role_scope: str = "unknown",
    vuln_class: str = "",
    namespace: str = "",
    param_location: str = "",
    subject_role: str = "",
    object_kind: str = "",
) -> str:
    surface = canonical_project_surface_key(
        asset, method,
        _template_path(
            path, param=param, param_location=param_location),
    )
    role = str(role_scope or "unknown").strip().lower() or "unknown"
    vc = exact_vc(vuln_class)
    base = f"{surface} :: {str(param or '').strip()} @ {role} × {vc}"
    dimensions = {
        "namespace": str(namespace or "").strip(),
        "param_location": str(param_location or "").strip().lower(),
        "subject_role": str(subject_role or "").strip().lower(),
        "object_kind": str(object_kind or "").strip().lower(),
    }
    # Preserve the readable v8.8 form when no new dimension is known.  Once a
    # dimension is attested, append a collision-resistant canonical digest so
    # query/body, app namespace, subject and object cells cannot alias.
    if not any(dimensions.values()):
        return base
    encoded = json.dumps(
        dimensions, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    suffix = hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:20]
    return f"{base} :: v2:{suffix}"


def finding_fingerprint(finding: dict[str, Any], *, fallback_asset: str = "") -> str:
    method, path = _method_and_path(finding)
    asset = _asset_from(finding, fallback_asset)
    roles = sorted(_roles_from(finding))
    access = finding.get("authorization_context") or {}
    if not isinstance(access, dict):
        access = {}
    boundary = str(access.get("expected_access") or finding.get("access_boundary") or "").strip().lower()
    dimensions = _identity_dimensions(finding)
    finding_params = _params_from(finding)
    path_param = finding_params[0] if len(finding_params) == 1 else ""
    path_param_location = dimensions.get("param_location", "")
    # Parameter name/location belongs to exact coverage, not root-finding
    # identity.  The same missing guard can be reached through path and query
    # aliases without becoming two vulnerabilities.
    dimensions.pop("param_location", None)
    identity = {
        "asset": asset,
        "method": method,
        "path": _template_path(
            path, param=path_param,
            param_location=path_param_location),
        "root_cause": _root_cause_from(finding).casefold(),
        # A root is role-scoped; preserve all explicitly affected roles only
        # for legacy callers that have not yet projected an exact row.
        "role": roles[0],
        "access_boundary": boundary,
        **dimensions,
    }
    if len(roles) > 1:
        identity["roles"] = roles
    raw = json.dumps(
        identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _default_state(scopes: list[str] | None = None) -> dict[str, Any]:
    canonical_scopes = [
        x for x in (canonical_asset(v) for v in (scopes or [])) if x
    ]
    return {
        "schema_version": PROJECT_STATE_SCHEMA_VERSION,
        "revision": 0,
        "project_scope": list(dict.fromkeys(canonical_scopes)),
        "merged_run_ids": [],
        "facts": [],
        "intents": [],
        "negatives": [],
        "dead_ends": [],
        "inventory": {"surfaces": {}, "unresolved": {}},
        "cell_registry": {},
        "finding_registry": {},
        "run_history": {},
        "updated_at": "",
    }


def _merge_unique(dst: list[Any], values: list[Any]) -> None:
    for value in values:
        if value not in dst:
            dst.append(value)


def _authority_project_scopes(project_dir: pathlib.Path) -> list[str]:
    """Read the immutable project target from the nearest authority identity.

    Finalization prepares project truth in an authority-owned shadow directory,
    so the identity may live either directly below ``project/.atoolkit`` or in
    an ancestor named ``.atoolkit``.  Only a self-hash-valid identity is trusted.
    """
    candidates = [project_dir / ".atoolkit" / "project_identity.json"]
    for parent in (project_dir, *project_dir.parents):
        if parent.name == ".atoolkit":
            candidates.append(parent / "project_identity.json")
    for path in dict.fromkeys(candidates):
        try:
            if path.is_symlink() or not path.is_file():
                continue
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                continue
            supplied = str(value.get("identity_sha256") or "")
            canonical = dict(value)
            canonical.pop("identity_sha256", None)
            digest = hashlib.sha256(json.dumps(
                canonical, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")).hexdigest()
            if not supplied or supplied != digest:
                continue
            asset = canonical_asset(str(value.get("primary_target") or ""))
            if asset:
                return [asset]
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            continue
    return []


class ProjectStateStore:
    """Single-writer, revisioned JSON store for a target project."""

    def __init__(self, project_dir: str | pathlib.Path, *, project_scope: list[str] | None = None):
        self.project_dir = pathlib.Path(project_dir).resolve()
        self.path = self.project_dir / "project_state.json"
        self.lock_path = self.project_dir / ".project_state.lock"
        declared = [
            asset for asset in (
                canonical_asset(value) for value in (project_scope or []))
            if asset
        ]
        self.project_scope = list(dict.fromkeys([
            *declared, *_authority_project_scopes(self.project_dir),
        ]))
        # Backward-compatible commit metadata channel.  commit_run() continues
        # to return the state object while callers that need CAS/idempotence
        # details can inspect this field.
        self.last_commit: dict[str, Any] = {}

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        self.project_dir.mkdir(parents=True, exist_ok=True)
        key = str(self.project_dir)
        with _LOCKS_GUARD:
            lock = _LOCKS.setdefault(key, threading.RLock())
        with lock:
            with self.lock_path.open("a+b") as handle:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    if fcntl is not None:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _read_state_bytes_unlocked(self) -> bytes:
        """Read the authority leaf through one verified file descriptor.

        A model-writable session can hard-link a parent-owned file and mutate
        the shared inode through its alias.  Cross-run truth therefore accepts
        only a regular, singly-linked leaf opened without following symlinks.
        """
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise ProjectStateCorrupt(f"cannot open project state safely: {exc}") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ProjectStateCorrupt("project state is not a regular file")
            if info.st_nlink != 1:
                raise ProjectStateCorrupt("project state has multiple hard links")
            return self._read_fd_fully(fd)
        except OSError as exc:
            raise ProjectStateCorrupt(f"cannot read project state: {exc}") from exc
        finally:
            os.close(fd)

    def _read_unlocked(self) -> dict[str, Any]:
        try:
            raw = self._read_state_bytes_unlocked()
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ProjectStateCorrupt(f"cannot read project state: {exc}") from exc
        if not isinstance(data, dict):
            raise ProjectStateCorrupt("project state must be an object")
        version = data.get("schema_version")
        if version in {1, 2}:
            for record in (data.get("cell_registry") or {}).values():
                if isinstance(record, dict):
                    record.setdefault("identity_version", int(version))
                    record.setdefault("legacy_status", record.get("status", ""))
                    record["status"] = "stale_requires_retest"
                    record["migration_status"] = (
                        "legacy_semantic_group_retest_required")
            data["schema_version"] = PROJECT_STATE_SCHEMA_VERSION
            data["migrated_from_schema"] = int(version)
            data.setdefault("migrated_at", "")
            data[f"schema{version}_backup_sha256"] = hashlib.sha256(raw).hexdigest()
        elif version != PROJECT_STATE_SCHEMA_VERSION:
            raise ProjectStateCorrupt(f"unsupported project state schema: {version!r}")
        for key, expected in (
            ("inventory", dict), ("cell_registry", dict),
            ("finding_registry", dict), ("run_history", dict),
            ("facts", list), ("intents", list), ("negatives", list),
            ("dead_ends", list),
        ):
            if not isinstance(data.get(key), expected):
                raise ProjectStateCorrupt(f"invalid project state field: {key}")
        return data

    def load(self) -> dict[str, Any]:
        with self._locked():
            return self._read_unlocked()

    def preview(self) -> dict[str, Any]:
        """Return current/default project truth without writing or migrating.

        Runtime planning is a reader.  Creation, legacy import publication and
        schema migration become durable only inside an explicit commit/finalizer
        transaction.
        """
        with self._locked():
            if self.path.exists():
                return self._read_unlocked()
            state = _default_state(self.project_scope)
            legacy = self.project_dir / "blackboard.json"
            if legacy.exists():
                try:
                    raw = json.loads(legacy.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise ProjectStateCorrupt(
                        f"cannot preview legacy blackboard: {exc}") from exc
                self._import_legacy(state, raw)
            return state

    def _fsync_directory(self) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        dir_fd = os.open(self.project_dir, flags)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    @staticmethod
    def _read_fd_fully(fd: int) -> bytes:
        chunks: list[bytes] = []
        while True:
            try:
                chunk = os.read(fd, 1024 * 1024)
            except InterruptedError:
                continue
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)

    def _verify_schema1_backup(
        self, backup: pathlib.Path, expected_sha256: str,
    ) -> None:
        try:
            info = os.lstat(backup)
        except FileNotFoundError:
            raise ProjectStateCorrupt("schema1 migration backup is missing") from None
        if not stat.S_ISREG(info.st_mode):
            raise ProjectStateCorrupt("schema1 migration backup is not a regular file")
        if info.st_nlink != 1:
            raise ProjectStateCorrupt(
                "schema1 migration backup has multiple hard links")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ProjectStateCorrupt("schema1 migration backup is not private")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(backup, flags)
        try:
            opened_info = os.fstat(fd)
            if (not stat.S_ISREG(opened_info.st_mode)
                    or opened_info.st_nlink != 1
                    or (opened_info.st_dev, opened_info.st_ino)
                    != (info.st_dev, info.st_ino)):
                raise ProjectStateCorrupt(
                    "schema1 migration backup changed during verification")
            backup_bytes = self._read_fd_fully(fd)
            if hashlib.sha256(backup_bytes).hexdigest() != expected_sha256:
                raise ProjectStateCorrupt(
                    "schema1 migration backup does not match original state")
            try:
                backup_value = json.loads(backup_bytes.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise ProjectStateCorrupt(
                    f"schema1 migration backup is corrupt: {exc}") from exc
            if (not isinstance(backup_value, dict)
                    or backup_value.get("schema_version") != 1):
                raise ProjectStateCorrupt(
                    "schema1 migration backup is not schema version 1")
            # Re-establish durability before trusting a backup left by an
            # interrupted attempt.  Errors are part of the commit result.
            os.fsync(fd)
        finally:
            os.close(fd)
        self._fsync_directory()

    def _ensure_schema1_backup(self, migrated_state: dict[str, Any]) -> None:
        """Create or verify the immutable pre-v8.9 schema-1 snapshot.

        The original bytes, not a re-serialized object, are preserved.  A
        pre-existing backup is accepted only when it is a private regular
        file with the exact digest recorded by schema migration.
        """
        expected = str(migrated_state.get("schema1_backup_sha256") or "")
        backup = self.project_dir / "project_state.pre-v89.schema1.json"
        try:
            raw_source = self._read_state_bytes_unlocked()
        except FileNotFoundError:
            raw_source = b""
        try:
            source_value = json.loads(raw_source.decode("utf-8")) if raw_source else {}
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ProjectStateCorrupt(f"cannot verify schema1 source: {exc}") from exc
        source_is_schema1 = (
            isinstance(source_value, dict) and source_value.get("schema_version") == 1)
        if source_is_schema1:
            source_digest = hashlib.sha256(raw_source).hexdigest()
            if not expected or source_digest != expected:
                raise ProjectStateCorrupt(
                    "schema1 migration source digest changed during commit")
        elif not backup.exists():
            # Prepared-state shadow stores intentionally contain the migrated
            # schema-2 projection but no legacy file.  No migration is being
            # published from that directory, so there is nothing to back up.
            return
        elif not expected:
            raise ProjectStateCorrupt(
                "cannot authenticate existing schema1 migration backup")

        if backup.exists():
            self._verify_schema1_backup(backup, expected)
            return
        if not source_is_schema1:
            return

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(backup, flags, 0o600)
        except FileExistsError:
            self._verify_schema1_backup(backup, expected)
            return
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(raw_source)
            while view:
                try:
                    written = os.write(fd, view)
                except InterruptedError:
                    continue
                if written <= 0:
                    raise OSError("short write while creating schema1 migration backup")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        self._fsync_directory()

    def _ensure_schema2_backup(self, migrated_state: dict[str, Any]) -> None:
        """Preserve the exact pre-v9.1 schema-2 bytes before publishing v3."""
        expected = str(migrated_state.get("schema2_backup_sha256") or "")
        backup = self.project_dir / "project_state.pre-v91.schema2.json"
        try:
            raw_source = self._read_state_bytes_unlocked()
        except FileNotFoundError:
            raw_source = b""
        try:
            source_value = json.loads(raw_source.decode("utf-8")) if raw_source else {}
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ProjectStateCorrupt(f"cannot verify schema2 source: {exc}") from exc
        source_is_schema2 = (
            isinstance(source_value, dict) and source_value.get("schema_version") == 2)
        if source_is_schema2:
            if not expected or hashlib.sha256(raw_source).hexdigest() != expected:
                raise ProjectStateCorrupt(
                    "schema2 migration source digest changed during commit")
        elif not backup.exists():
            return
        if backup.exists():
            info = os.lstat(backup)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ProjectStateCorrupt("schema2 migration backup is unsafe")
            fd = os.open(backup, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(fd)
                payload = self._read_fd_fully(fd)
                if ((opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
                        or hashlib.sha256(payload).hexdigest() != expected):
                    raise ProjectStateCorrupt("schema2 migration backup is invalid")
            finally:
                os.close(fd)
            return
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(backup, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(raw_source)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short write while creating schema2 migration backup")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        self._fsync_directory()

    def _atomic_write(self, data: dict[str, Any]) -> None:
        payload = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        fd, tmp_name = tempfile.mkstemp(prefix=".project_state.", suffix=".tmp", dir=self.project_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
            self._fsync_directory()
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def initialize(self) -> dict[str, Any]:
        with self._locked():
            if self.path.exists():
                return self._read_unlocked()
            state = _default_state(self.project_scope)
            legacy = self.project_dir / "blackboard.json"
            if legacy.exists():
                try:
                    raw = json.loads(legacy.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise ProjectStateCorrupt(f"cannot import legacy blackboard: {exc}") from exc
                backup = self.project_dir / "blackboard.pre-v88.backup.json"
                if not backup.exists():
                    shutil.copy2(legacy, backup)
                self._import_legacy(state, raw)
            state["updated_at"] = _now()
            self._atomic_write(state)
            return state

    def _import_legacy(self, state: dict[str, Any], legacy: dict[str, Any]) -> None:
        fallback = (
            canonical_asset(self.project_scope[0])
            if len({canonical_asset(x) for x in self.project_scope if canonical_asset(x)}) == 1
            else ""
        )
        for fact in legacy.get("facts") or []:
            if not isinstance(fact, dict):
                continue
            migrated = dict(fact)
            refs = list(migrated.get("evidence_refs") or [])
            if migrated.get("source_type") == "confirmed":
                migrated["proof_status"] = "pending"
                migrated["migration_status"] = "legacy_unvalidated"
                intent_key = json.dumps({"fact": migrated.get("fact_id"), "kind": "revalidation"}, sort_keys=True)
                state["intents"].append({
                    "intent_id": _stable_id("intent", intent_key),
                    "source_fact_id": migrated.get("fact_id", ""),
                    "source": "revalidation", "status": "pending", "priority": "high",
                    "description": f"revalidate legacy fact {migrated.get('fact_id', '')}".strip(),
                    "target_endpoint": migrated.get("endpoint", ""),
                    "method": migrated.get("method", ""),
                })
            state["facts"].append(migrated)
        for intent in legacy.get("intents") or []:
            if isinstance(intent, dict) and intent not in state["intents"]:
                state["intents"].append(dict(intent))
        for item in legacy.get("discovered_endpoints") or []:
            record = {"asset": fallback, "endpoint": item, "source": "legacy_blackboard"}
            self._merge_inventory(state, record, "legacy")
        # Legacy negatives/dead ends remain navigational hints only.  Missing
        # role/evidence fields must not close v8.8 project cells.
        state["negatives"] = [
            {**dict(x), "depth_sufficient": False,
             "migration_status": "legacy_unvalidated"}
            for x in (legacy.get("negatives") or []) if isinstance(x, dict)
        ]
        state["dead_ends"] = [
            {**dict(x), "migration_status": "legacy_unvalidated"}
            for x in (legacy.get("dead_ends") or []) if isinstance(x, dict)
        ]

    def _extend_project_scope(
        self, state: dict[str, Any], records: list[dict[str, Any]],
    ) -> None:
        scopes = state.setdefault("project_scope", [])
        for raw in self.project_scope:
            asset = canonical_asset(raw)
            if asset and asset not in scopes:
                scopes.append(asset)
        for record in records:
            # Scope expansion is explicit only.  Relative paths never inherit
            # whichever asset happens to appear first in a multi-asset project.
            for asset in _assets_from(record, ""):
                if asset and asset not in scopes:
                    scopes.append(asset)

    def _merge_inventory(self, state: dict[str, Any], item: dict[str, Any], run_id: str) -> None:
        fallback = _single_scope_fallback(state)
        assets = _assets_from(item, fallback)
        if len(assets) > 1:
            for asset_id in assets:
                expanded = {
                    key: value for key, value in item.items()
                    if key not in {"assets", "asset", "asset_id"}
                }
                expanded["asset_id"] = asset_id
                self._merge_inventory(state, expanded, run_id)
            return
        asset = assets[0] if assets else ""
        method, path = _method_and_path(item)
        if not asset or not path:
            return
        dimensions = _identity_dimensions(item)
        inventory_dimensions = {
            key: dimensions[key]
            for key in ("namespace", "subject_role", "object_kind")
        }
        inv = state["inventory"]
        unresolved_key = _dimensioned_inventory_key(
            f"{asset} :: {path}", **inventory_dimensions)
        if not method:
            rec = inv["unresolved"].setdefault(unresolved_key, {
                "asset_id": asset, "path": path, "method_candidates": [],
                **inventory_dimensions,
                "sources": [], "seen_in_runs": [], "first_seen": _now(),
            })
            source = str(item.get("source") or "unknown")
            _merge_unique(rec["sources"], [source])
            _merge_unique(rec["seen_in_runs"], [run_id])
            rec["last_seen"] = _now()
            intent_key = json.dumps({
                "asset": asset, "path": path, "kind": "method_resolution",
                **inventory_dimensions,
            }, sort_keys=True)
            intent_id = _stable_id("intent", intent_key)
            if not any(x.get("intent_id") == intent_id for x in state["intents"]):
                state["intents"].append({
                    "intent_id": intent_id,
                    "source": "method_resolution",
                    "status": "pending",
                    "priority": "high",
                    "description": f"resolve observed HTTP method for {path}",
                    "target_endpoint": path,
                    "target_method": "",
                    "asset_id": asset,
                    **inventory_dimensions,
                })
            return
        key = canonical_project_surface_key(
            asset, method, path, **inventory_dimensions)
        rec = inv["surfaces"].setdefault(key, {
            "asset_id": asset, "method": method, "path": path,
            **inventory_dimensions,
            "params": [], "param_locations": {},
            "roles": [], "risk_tags": [], "sources": [],
            "seen_in_runs": [], "first_seen": _now(),
        })
        params = _params_from(item)
        param_locations = _param_locations_from(item)
        role_keys = {"affected_roles", "affected_role", "role_scopes", "role_scope",
                     "roles", "role", "actor_roles", "actor_role", "observed_roles"}
        roles = _roles_from(item) if any(key in item for key in role_keys) else []
        risk_tags = [str(x).strip() for x in _as_list(item.get("risk_tags"))
                     if str(x).strip()]
        _merge_unique(rec["params"], params)
        rec.setdefault("param_locations", {}).update(param_locations)
        _merge_unique(rec["roles"], roles)
        _merge_unique(rec["risk_tags"], risk_tags)
        source = str(item.get("source") or "unknown")
        _merge_unique(rec["sources"], [source])
        promoted = inv["unresolved"].pop(unresolved_key, None)
        if promoted:
            _merge_unique(rec["sources"], promoted.get("sources", []))
            _merge_unique(rec["seen_in_runs"], promoted.get("seen_in_runs", []))
            for intent in state["intents"]:
                if (intent.get("source") == "method_resolution"
                        and intent.get("asset_id") == asset
                        and _path_from(intent.get("target_endpoint", "")) == path
                        and all(
                            str(intent.get(name) or "").strip().lower()
                            == inventory_dimensions[name].lower()
                            for name in inventory_dimensions
                        )
                        and intent.get("status") == "pending"):
                    intent["status"] = "completed"
                    intent["target_method"] = method
                    intent["outcome_summary"] = f"observed {method} {path}"
                    intent["resolved_at"] = _now()
        _merge_unique(rec["seen_in_runs"], [run_id])
        rec["last_seen"] = _now()

    def _attest_evidence(
        self, run_id: str, refs: list[Any],
    ) -> tuple[list[str], dict[str, str]] | None:
        normalized: list[str] = []
        hashes: dict[str, str] = {}
        for raw_ref in refs:
            raw = str(raw_ref or "").strip()
            path = _evidence_path(self.project_dir, run_id, raw)
            if path is None or not path.is_file():
                return None
            if raw.startswith(("session:", "project:")):
                ref = raw
            else:
                try:
                    relative = path.relative_to(
                        (self.project_dir / "sessions" / run_id).resolve()).as_posix()
                    ref = f"session:{run_id}/{relative}"
                except ValueError:
                    relative = path.relative_to(self.project_dir).as_posix()
                    ref = f"project:{relative}"
            if ref not in normalized:
                normalized.append(ref)
                hashes[ref] = _sha256_file(path)
        return (normalized, hashes) if normalized else None

    def _merge_negative(self, state: dict[str, Any], neg: dict[str, Any], run_id: str) -> None:
        if not neg.get("depth_sufficient"):
            return
        attested = self._attest_evidence(
            run_id, list(neg.get("evidence_refs") or []))
        if attested is None:
            return
        evidence_refs, evidence_hashes = attested
        fallback = _single_scope_fallback(state)
        assets = _assets_from(neg, fallback)
        if len(assets) > 1:
            for asset_id in assets:
                expanded = {
                    key: value for key, value in neg.items()
                    if key not in {"assets", "asset", "asset_id"}
                }
                expanded["asset_id"] = asset_id
                self._merge_negative(state, expanded, run_id)
            return
        asset = assets[0] if assets else ""
        method, path = _method_and_path(neg)
        roles = _roles_from(neg)
        params = _params_from(neg, default_empty=True)
        vc = str(neg.get("vuln_class") or neg.get("vuln") or "")
        if not asset or not method or not vc:
            return
        if asset not in set(state.get("project_scope") or []):
            # Negative evidence is project truth, never scope authority.
            return
        for role in roles:
            for param in params:
                dimensions, canonical_path = _resolved_identity(
                    state, neg, asset=asset, method=method, path=path, param=param)
                key = canonical_project_cell_key(
                    asset, method=method, path=canonical_path, param=param,
                    role_scope=role, vuln_class=vc,
                    **dimensions)
                item = {
                    **neg, "cell_key": key, "asset_id": asset, "method": method,
                    "endpoint": canonical_path, "param": param, "role_scope": role,
                    "vuln_class": exact_vc(vc), "vuln_family": norm_vc(vc),
                    "source_run": run_id,
                    **dimensions,
                    "status": "active", "evidence_refs": evidence_refs,
                    "evidence_hashes": evidence_hashes,
                }
                existing = next(
                    (x for x in state["negatives"] if x.get("cell_key") == key), None)
                prior = state["cell_registry"].get(key)
                if prior and prior.get("status") == "confirmed":
                    item.update({
                        "status": "conflicts_confirmed",
                        "conflicts_with_finding_id": prior.get(
                            "canonical_finding_id", ""),
                        "conflict_detected_at": _now(),
                    })
                if existing:
                    existing.update(item)
                else:
                    state["negatives"].append(item)
                if prior and prior.get("status") == "confirmed":
                    canonical_id = str(prior.get("canonical_finding_id") or "")
                    prior.update({
                        "revalidation_status": "required",
                        "conflicting_negative_run": run_id,
                        "conflicting_negative_evidence_refs": evidence_refs,
                        "updated_at": _now(),
                    })
                    for record in state.get("finding_registry", {}).values():
                        if record.get("canonical_finding_id") == canonical_id:
                            record["status"] = "needs_revalidation"
                            record["revalidation_reason"] = (
                                "later canonical negative conflicts with confirmed cell")
                            record["conflicting_run"] = run_id
                    for fact in state.get("facts", []):
                        if fact.get("canonical_finding_id") == canonical_id:
                            fact["proof_status"] = "revalidation_required"
                            fact["conflicting_run"] = run_id
                    intent_identity = f"{key}|{canonical_id}|truth_conflict"
                    intent_id = _stable_id("intent", intent_identity)
                    if not any(
                            row.get("intent_id") == intent_id
                            for row in state.get("intents", [])):
                        state["intents"].append({
                            "intent_id": intent_id,
                            "source": "v9_host_continuation",
                            "source_kind": "truth_conflict",
                            "source_finding_id": canonical_id,
                            "source_surface_id": key,
                            "cause_code": "truth_conflict",
                            "description": (
                                "revalidate the exact cell with the original positive "
                                "and later negative controls before submission"),
                            "priority": "critical",
                            "status": "pending",
                            "target_endpoint": canonical_path,
                            "target_method": method,
                            "target_params": [param] if param else [],
                            "target_roles": [role] if role else [],
                            "vuln_class": exact_vc(vc),
                            "vuln_family": norm_vc(vc),
                            "evidence_refs": list(dict.fromkeys(
                                list(prior.get("evidence_refs") or [])
                                + evidence_refs)),
                        })
                else:
                    state["cell_registry"][key] = {
                        "cell_key": key, "asset_id": asset, "method": method,
                        "path": canonical_path,
                        "param": param,
                        "role_scope": role, "vuln_class": exact_vc(vc),
                        "vuln_family": norm_vc(vc),
                        **dimensions,
                        "status": "not_vulnerable", "source_run": run_id,
                        "evidence_refs": evidence_refs,
                        "evidence_hashes": evidence_hashes,
                        "negative_vectors": list(neg.get("vectors") or []),
                        "negative_encoding_families": list(
                            neg.get("encoding_families") or []),
                        "negative_strategy_families": list(
                            neg.get("strategy_families") or []),
                        "updated_at": _now(),
                    }

    def _finding_rows(
        self, state: dict[str, Any], finding: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Project a confirmed finding onto explicit exact cells.

        New normalized findings always carry ``exact_cells``.  The flattened
        fallback exists only for older direct callers; it is never mixed with
        exact rows, which prevents a multi-API finding from becoming an
        assets×endpoint×param×role Cartesian product.
        """
        fallback = _single_scope_fallback(state)
        top_asset = _asset_from(finding, fallback)
        top_vc = str(finding.get("vuln_class") or finding.get("class")
                     or finding.get("vuln_type") or "")
        exact = [
            row for row in (finding.get("exact_cells") or [])
            if isinstance(row, dict)
        ]
        rows: list[dict[str, Any]] = []
        if exact:
            for row in exact:
                if "param" not in row:
                    continue
                asset = _asset_from(row, top_asset)
                method, path = _method_and_path(row)
                role_values = _roles_from(row)
                role = role_values[0] if len(role_values) == 1 else ""
                param = str(row.get("param") or "").strip()
                vc = str(row.get("vuln_class") or row.get("class")
                         or row.get("vuln") or top_vc)
                if not asset or method not in _METHODS or not path or not role or not vc:
                    continue
                dimensions, canonical_path = _resolved_identity(
                    state, row, asset=asset, method=method, path=path, param=param)
                rows.append({
                    "asset_id": asset, "method": method, "path": canonical_path,
                    "param": param, "role_scope": role, "vuln_class": vc,
                    **dimensions,
                })
            return rows

        assets = _assets_from(finding, fallback)
        method, path = _method_and_path(finding)
        if len(assets) != 1 or method not in _METHODS or not path or not top_vc:
            return []
        asset = assets[0]
        for role in _roles_from(finding):
            for param in _params_from(finding, default_empty=True):
                dimensions, canonical_path = _resolved_identity(
                    state, finding, asset=asset, method=method,
                    path=path, param=param)
                rows.append({
                    "asset_id": asset, "method": method, "path": canonical_path,
                    "param": param, "role_scope": role,
                    "vuln_class": top_vc, **dimensions,
                })
        return rows

    @staticmethod
    def _project_finding_to_row(
        finding: dict[str, Any], row: dict[str, Any],
    ) -> dict[str, Any]:
        projected = {
            key: value for key, value in finding.items()
            if key not in {
                "assets", "asset", "asset_id", "endpoint", "endpoints",
                "path", "target", "method", "methods", "param", "params",
                "affected_roles", "affected_role", "role_scopes", "role_scope",
                "roles", "role", "actor_roles", "actor_role", "observed_roles",
                "namespace", "param_location", "subject_role", "object_kind",
                "exact_cells",
            }
        }
        projected.update({
            "asset_id": row["asset_id"],
            "endpoint": row["path"],
            "method": row["method"],
            "param": row["param"],
            "params": [row["param"]],
            "affected_role": row["role_scope"],
            "affected_roles": [row["role_scope"]],
            "vuln_class": row["vuln_class"],
            "namespace": row.get("namespace", ""),
            "param_location": row.get("param_location", ""),
            "subject_role": row.get("subject_role", ""),
            "object_kind": row.get("object_kind", ""),
        })
        return projected

    def _merge_finding(self, state: dict[str, Any], finding: dict[str, Any], run_id: str) -> None:
        if not (finding.get("acceptance_status") == "accepted"
                and finding.get("proof_status") == "confirmed"
                and finding.get("claim_kind") == "root_finding"):
            return
        attested = self._attest_evidence(
            run_id, list(finding.get("proof_files") or finding.get("evidence_refs") or []))
        if attested is None:
            return
        evidence_refs, evidence_hashes = attested
        allowed_assets = {
            canonical_asset(value) for value in (state.get("project_scope") or [])
            if canonical_asset(value)
        }
        for row in self._finding_rows(state, finding):
            asset = row["asset_id"]
            if asset not in allowed_assets:
                # A finding is evidence inside an already-authorized project;
                # it is never authority to enlarge the project boundary.
                continue
            method = row["method"]
            path = row["path"]
            param = row["param"]
            role = row["role_scope"]
            vc = row["vuln_class"]
            dimensions = {
                key: str(row.get(key) or "")
                for key in ("namespace", "param_location", "subject_role", "object_kind")
            }
            root_dimensions = {
                key: value for key, value in dimensions.items()
                if key != "param_location"
            }
            projected = self._project_finding_to_row(finding, row)
            fingerprint = finding_fingerprint(projected, fallback_asset=asset)
            canonical_id = _stable_id("root", fingerprint)
            key = canonical_project_cell_key(
                asset, method=method, path=path, param=param,
                role_scope=role, vuln_class=vc, **dimensions)

            registry = state["finding_registry"]
            record = registry.setdefault(fingerprint, {
                "fingerprint": fingerprint,
                "canonical_finding_id": canonical_id,
                "root_cause": _root_cause_from(projected),
                "asset_id": asset,
                "method": method,
                "path": _canonical_row_path(path, param, dimensions),
                "role_scope": role,
                **root_dimensions,
                "first_seen": _now(), "last_seen": "", "seen_in_runs": [],
                "observations": [], "status": "confirmed",
            })
            record["status"] = "confirmed"
            record.pop("revalidation_reason", None)
            record.pop("conflicting_run", None)
            _merge_unique(record["seen_in_runs"], [run_id])
            observation = next((
                item for item in record["observations"]
                if item.get("run_id") == run_id
                and item.get("finding_id") == finding.get("id", "")
                and item.get("evidence_refs") == evidence_refs
            ), None)
            if observation is None:
                observation = {
                    "run_id": run_id, "finding_id": finding.get("id", ""),
                    "evidence_refs": evidence_refs,
                    "evidence_hashes": evidence_hashes,
                    "exact_cell_keys": [],
                }
                record["observations"].append(observation)
            _merge_unique(observation.setdefault("exact_cell_keys", []), [key])
            record["last_seen"] = _now()

            for neg in state["negatives"]:
                if (neg.get("cell_key") == key
                        and neg.get("status") in {"active", "conflicts_confirmed"}):
                    neg["status"] = "superseded"
                    neg["superseded_by_finding_id"] = canonical_id
            for intent in state.get("intents", []):
                if (intent.get("source_kind") == "truth_conflict"
                        and intent.get("source_surface_id") == key
                        and intent.get("status") == "pending"):
                    intent["status"] = "completed"
                    intent["outcome_summary"] = (
                        "exact cell revalidated by a new proof-confirmed finding")
                    intent["resolved_at"] = _now()
            state["cell_registry"][key] = {
                "cell_key": key, "asset_id": asset, "method": method,
                "path": _canonical_row_path(path, param, dimensions),
                "param": param,
                "role_scope": role, "vuln_class": exact_vc(vc),
                "vuln_family": norm_vc(vc),
                **dimensions,
                "status": "confirmed", "source_run": run_id,
                "canonical_finding_id": canonical_id,
                "evidence_refs": evidence_refs,
                "evidence_hashes": evidence_hashes,
                "updated_at": _now(),
            }

            fact = {
                "fact_id": _stable_id("fact", fingerprint),
                "canonical_finding_id": canonical_id, "source_type": "confirmed",
                "proof_status": "confirmed", "asset_id": asset,
                "endpoint": _canonical_row_path(path, param, dimensions),
                "method": method,
                "params": [param] if param else [], "affected_role": role,
                "affected_roles": [role], "vuln_class": exact_vc(vc),
                "vuln_family": norm_vc(vc),
                **root_dimensions,
                "param_locations": (
                    {param: dimensions["param_location"]}
                    if param and dimensions["param_location"] else {}),
                "summary": finding.get("title") or finding.get("primary_impact") or "",
                "root_cause": _root_cause_from(projected),
                "evidence_refs": evidence_refs,
                "evidence_hashes": evidence_hashes,
                "source_run": run_id,
            }
            existing_fact = next((
                item for item in state["facts"]
                if item.get("canonical_finding_id") == canonical_id
            ), None)
            if existing_fact:
                params = list(existing_fact.get("params") or [])
                _merge_unique(params, fact["params"])
                param_locations = dict(existing_fact.get("param_locations") or {})
                param_locations.update(fact["param_locations"])
                existing_fact.update(fact)
                existing_fact["params"] = params
                existing_fact["param_locations"] = param_locations
            else:
                state["facts"].append(fact)

    def _merge_dead_end(
        self, state: dict[str, Any], dead_end: dict[str, Any], run_id: str,
    ) -> None:
        """Persist only an exact, evidence-attested not-applicable cell.

        A generic model SKIP, a budget decision, or a recoverable blocker does
        not satisfy this contract and therefore cannot suppress later runs.
        """
        if str(dead_end.get("status") or "") != "not_applicable":
            return
        reason_code = str(dead_end.get("reason_code") or "").strip()
        refutation = str(dead_end.get("refutation") or "").strip()
        if reason_code not in DEAD_END_REASON_CODES or not refutation:
            return
        declared_run = str(dead_end.get("source_run") or run_id).strip()
        if declared_run != run_id:
            return
        if not (dead_end.get("asset") or dead_end.get("asset_id")):
            return
        if "param" not in dead_end:
            return
        asset = _asset_from(dead_end)
        method, path = _method_and_path(dead_end)
        role = str(dead_end.get("role_scope") or dead_end.get("role") or "").strip().lower()
        vc = str(dead_end.get("vuln_class") or dead_end.get("class") or "").strip()
        if not asset or method not in _METHODS or not path or not role or not vc:
            return
        refs = list(dead_end.get("evidence_refs") or [])
        if not refs and dead_end.get("evidence_ref"):
            refs = [dead_end["evidence_ref"]]
        attested = self._attest_evidence(run_id, refs)
        if attested is None:
            return
        evidence_refs, evidence_hashes = attested
        if asset not in set(state.get("project_scope") or []):
            # A dead-end may close an authorized cell but cannot authorize a
            # new origin by itself.
            return
        dimensions, canonical_path = _resolved_identity(
            state, dead_end, asset=asset, method=method, path=path,
            param=str(dead_end.get("param") or ""))
        key = canonical_project_cell_key(
            asset, method=method, path=canonical_path,
            param=str(dead_end.get("param") or ""),
            role_scope=role, vuln_class=vc,
            **dimensions,
        )
        prior = state["cell_registry"].get(key)
        if prior and prior.get("status") == "confirmed":
            return
        record = {
            **dead_end,
            "cell_key": key,
            "asset_id": asset,
            "method": method,
            "endpoint": canonical_path,
            "param": str(dead_end.get("param") or ""),
            "role_scope": role,
            "vuln_class": exact_vc(vc), "vuln_family": norm_vc(vc),
            **dimensions,
            "status": "not_applicable",
            "reason_code": reason_code,
            "refutation": refutation,
            "source_run": run_id,
            "evidence_refs": evidence_refs,
            "evidence_hashes": evidence_hashes,
        }
        existing = next(
            (item for item in state["dead_ends"] if item.get("cell_key") == key), None)
        if existing:
            existing.update(record)
        else:
            state["dead_ends"].append(record)
        state["cell_registry"][key] = {
            "cell_key": key,
            "asset_id": asset,
            "method": method,
            "path": canonical_path,
            "param": str(dead_end.get("param") or ""),
            "role_scope": role,
            "vuln_class": exact_vc(vc), "vuln_family": norm_vc(vc),
            **dimensions,
            "status": "not_applicable",
            "reason_code": reason_code,
            "refutation": refutation,
            "source_run": run_id,
            "evidence_refs": evidence_refs,
            "evidence_hashes": evidence_hashes,
            "updated_at": _now(),
        }

    def commit_run(
        self,
        run_id: str,
        *,
        inventory: list[dict[str, Any] | str] | None = None,
        findings: list[dict[str, Any]] | None = None,
        negatives: list[dict[str, Any]] | None = None,
        intents: list[dict[str, Any]] | None = None,
        dead_ends: list[dict[str, Any]] | None = None,
        run_summary: dict[str, Any] | None = None,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        inventory_records = [
            ({"endpoint": item} if isinstance(item, str) else dict(item))
            for item in (inventory or [])
        ]
        finding_records = [dict(item) for item in (findings or [])]
        negative_records = [dict(item) for item in (negatives or [])]
        intent_records = None if intents is None else [dict(item) for item in intents]
        dead_end_records = [dict(item) for item in (dead_ends or [])]
        summary_record = dict(run_summary or {})
        commit_payload = {
            "run_id": str(run_id),
            "inventory": inventory_records,
            "findings": finding_records,
            "negatives": negative_records,
            "intents": intent_records,
            "dead_ends": dead_end_records,
            "run_summary": summary_record,
        }
        commit_sha256 = hashlib.sha256(json.dumps(
            commit_payload, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), default=str,
        ).encode("utf-8")).hexdigest()

        def _counts(value: dict[str, Any]) -> dict[str, int]:
            inventory_value = value.get("inventory") or {}
            return {
                "project_scope": len(value.get("project_scope") or []),
                "inventory_surfaces": len(inventory_value.get("surfaces") or {}),
                "inventory_unresolved": len(inventory_value.get("unresolved") or {}),
                "root_findings": len(value.get("finding_registry") or {}),
                "coverage_cells": len(value.get("cell_registry") or {}),
                "facts": len(value.get("facts") or []),
                "negatives": len(value.get("negatives") or []),
                "dead_ends": len(value.get("dead_ends") or []),
                "intents": len(value.get("intents") or []),
            }

        with self._locked():
            if self.path.exists():
                state = self._read_unlocked()
            else:
                state = _default_state(self.project_scope)
                legacy = self.project_dir / "blackboard.json"
                if legacy.exists():
                    try:
                        raw = json.loads(legacy.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError) as exc:
                        raise ProjectStateCorrupt(f"cannot import legacy blackboard: {exc}") from exc
                    self._import_legacy(state, raw)
            revision_before = int(state.get("revision", 0) or 0)
            history = (state.get("run_history") or {}).get(run_id) or {}
            if history.get("commit_input_sha256") == commit_sha256:
                delta = {key: 0 for key in _counts(state)}
                self.last_commit = {
                    "run_id": run_id,
                    "idempotent": True,
                    "commit_input_sha256": commit_sha256,
                    "revision_before": revision_before,
                    "revision_after": revision_before,
                    "delta": delta,
                }
                return state
            if history.get("commit_input_sha256"):
                raise ProjectStateError(
                    "same run_id cannot be committed with different input: "
                    f"{run_id}")
            if (expected_revision is not None
                    and int(expected_revision) != revision_before):
                raise ProjectStateError(
                    f"project state revision conflict: expected {expected_revision}, "
                    f"found {revision_before}")

            before_counts = _counts(state)
            self._extend_project_scope(
                state,
                inventory_records,
            )
            for record in inventory_records:
                self._merge_inventory(state, record, run_id)
            for neg in negative_records:
                self._merge_negative(state, neg, run_id)
            for dead_end in dead_end_records:
                self._merge_dead_end(state, dead_end, run_id)
            for finding in finding_records:
                self._merge_finding(state, finding, run_id)
            if intent_records is not None:
                by_id = {str(i.get("intent_id")): i for i in state["intents"] if i.get("intent_id")}
                for intent in intent_records:
                    iid = str(intent.get("intent_id") or _stable_id("intent", json.dumps(intent, sort_keys=True)))
                    copy = dict(intent); copy["intent_id"] = iid
                    if iid in by_id:
                        frozen_status = by_id[iid].get("status")
                        by_id[iid].update(copy)
                        if frozen_status in {"completed", "abandoned", "superseded"}:
                            by_id[iid]["status"] = frozen_status
                    else:
                        state["intents"].append(copy); by_id[iid] = copy
            if run_id not in state["merged_run_ids"]:
                state["merged_run_ids"].append(run_id)
            revision_after = revision_before + 1
            after_counts = _counts(state)
            delta = {
                key: after_counts[key] - before_counts.get(key, 0)
                for key in after_counts
            }
            history = state["run_history"].setdefault(run_id, {"run_id": run_id})
            history.update(summary_record)
            history["commit_input_sha256"] = commit_sha256
            history["revision_before"] = revision_before
            history["revision_after"] = revision_after
            history["delta"] = delta
            history["updated_at"] = _now()
            state["revision"] = revision_after
            state["updated_at"] = _now()
            if state.get("migrated_from_schema") == 1:
                self._ensure_schema1_backup(state)
            elif state.get("migrated_from_schema") == 2:
                self._ensure_schema2_backup(state)
            self._atomic_write(state)
            self.last_commit = {
                "run_id": run_id,
                "idempotent": False,
                "commit_input_sha256": commit_sha256,
                "revision_before": revision_before,
                "revision_after": revision_after,
                "delta": delta,
            }
            return state

    def commit_prepared_state(
        self,
        run_id: str,
        *,
        prepared_state: dict[str, Any],
        commit_input_sha256: str,
        expected_revision: int,
        expected_state_before_sha256: str,
    ) -> dict[str, Any]:
        """CAS-publish an authority-prepared deterministic state snapshot.

        The finalizer computes the complete after-state before its WAL reaches
        PROJECT_PREPARED.  Publishing those exact bytes avoids a second merge
        (and its timestamps) creating a state different from the immutable
        commit record.
        """
        def digest(value: dict[str, Any]) -> str:
            return hashlib.sha256(json.dumps(
                value, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"), default=str,
            ).encode("utf-8")).hexdigest()

        candidate = json.loads(json.dumps(prepared_state, ensure_ascii=False))
        with self._locked():
            if self.path.exists():
                current = self._read_unlocked()
            else:
                current = _default_state(self.project_scope)
            revision = int(current.get("revision", 0) or 0)
            history = (current.get("run_history") or {}).get(run_id) or {}
            if history.get("commit_input_sha256") == commit_input_sha256:
                self.last_commit = {
                    "run_id": run_id, "idempotent": True,
                    "commit_input_sha256": commit_input_sha256,
                    "revision_before": revision, "revision_after": revision,
                    "delta": {key: 0 for key in (
                        "project_scope", "inventory_surfaces",
                        "inventory_unresolved", "root_findings",
                        "coverage_cells", "facts", "negatives",
                        "dead_ends", "intents")},
                }
                return current
            if history.get("commit_input_sha256"):
                raise ProjectStateError(
                    f"same run_id cannot publish different prepared input: {run_id}")
            if revision != int(expected_revision):
                raise ProjectStateError(
                    f"project state revision conflict: expected {expected_revision}, "
                    f"found {revision}")
            if digest(current) != str(expected_state_before_sha256):
                raise ProjectStateError("project state before-snapshot digest mismatch")
            prepared_history = (candidate.get("run_history") or {}).get(run_id) or {}
            if (prepared_history.get("commit_input_sha256") != commit_input_sha256
                    or int(prepared_history.get("revision_before", -1)) != revision
                    or int(candidate.get("revision", -1)) != revision + 1):
                raise ProjectStateError("prepared project state contract mismatch")
            if candidate.get("migrated_from_schema") == 1:
                self._ensure_schema1_backup(candidate)
            elif candidate.get("migrated_from_schema") == 2:
                self._ensure_schema2_backup(candidate)
            self._atomic_write(candidate)
            self.last_commit = {
                "run_id": run_id, "idempotent": False,
                "commit_input_sha256": commit_input_sha256,
                "revision_before": revision,
                "revision_after": int(candidate.get("revision", revision + 1)),
                "delta": dict(prepared_history.get("delta") or {}),
            }
            return candidate

    def inventory_records(self) -> list[dict[str, Any]]:
        state = self.preview()
        return [dict(x) for x in state["inventory"]["surfaces"].values()]

    def blackboard_view(self, *, include_revalidation: bool = True) -> dict[str, Any]:
        state = self.preview()
        intents = state["intents"]
        if not include_revalidation:
            # The legacy compatibility view cannot represent migration trust
            # metadata.  Keep revalidation work authoritative in project_state
            # and out of old consumers that would count it as a new exploit
            # intent.
            intents = [x for x in intents if x.get("source") != "revalidation"]
        return {
            "schema_version": "2.0", "facts": state["facts"],
            "intents": intents, "negatives": state["negatives"],
            "dead_ends": state["dead_ends"],
            "discovered_endpoints": [
                f"{x['method']} {x['path']}" for x in state["inventory"]["surfaces"].values()
            ],
            "merged_run_ids": state["merged_run_ids"],
            "total_runs": len(state["merged_run_ids"]),
        }


__all__ = [
    "PROJECT_STATE_SCHEMA_VERSION", "DEAD_END_REASON_CODES",
    "ProjectStateCorrupt", "ProjectStateError",
    "ProjectStateStore", "canonical_asset", "canonical_project_cell_key",
    "canonical_project_surface_key", "finding_fingerprint", "verify_project_evidence",
]
