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
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Iterator
from urllib.parse import urlparse

try:  # pragma: no cover - Windows fallback is covered by the thread lock
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

try:
    from .surface_key import canonical_surface_key
    from .vuln_classes import norm_vc
except ImportError:  # pragma: no cover
    from surface_key import canonical_surface_key
    from vuln_classes import norm_vc


PROJECT_STATE_SCHEMA_VERSION = 1
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
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}:{port}"


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


def _asset_from(item: dict[str, Any], fallback: str = "") -> str:
    explicit = str(item.get("asset") or item.get("asset_id") or "").strip()
    if explicit:
        return canonical_asset(explicit)
    target = str(item.get("target") or item.get("endpoint") or "")
    if "://" in target:
        return canonical_asset(target)
    return canonical_asset(fallback)


def _template_path(path: str) -> str:
    out: list[str] = []
    for segment in _path_from(path).split("/"):
        if (segment.isdigit() or _UUID_RE.fullmatch(segment)
                or _HEX_RE.fullmatch(segment)):
            out.append("{id}")
        else:
            out.append(segment)
    return "/".join(out)


def canonical_project_surface_key(asset: str, method: str, path: str) -> str:
    asset_id = canonical_asset(asset)
    surface = canonical_surface_key({"method": method, "endpoint": _path_from(path)})
    return f"{asset_id} :: {surface}" if asset_id and surface else ""


def canonical_project_cell_key(
    asset: str,
    *,
    method: str,
    path: str,
    param: str = "",
    role_scope: str = "unknown",
    vuln_class: str = "",
) -> str:
    surface = canonical_project_surface_key(asset, method, _template_path(path))
    role = str(role_scope or "unknown").strip().lower() or "unknown"
    vc = norm_vc(vuln_class)
    return f"{surface} :: {str(param or '').strip()} @ {role} × {vc}"


def finding_fingerprint(finding: dict[str, Any], *, fallback_asset: str = "") -> str:
    method, path = _method_and_path(finding)
    asset = _asset_from(finding, fallback_asset)
    params = sorted({str(x).strip().lower() for x in (finding.get("params") or []) if str(x).strip()})
    role = str(finding.get("affected_role") or finding.get("role") or "unknown").strip().lower()
    access = finding.get("authorization_context") or {}
    if not isinstance(access, dict):
        access = {}
    boundary = str(access.get("expected_access") or finding.get("access_boundary") or "").strip().lower()
    raw = json.dumps({
        "asset": asset,
        "method": method,
        "path": _template_path(path),
        "vuln": norm_vc(str(finding.get("vuln_class") or finding.get("class") or finding.get("vuln_type") or "")),
        "params": params,
        "role": role or "unknown",
        "access_boundary": boundary,
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _default_state(scopes: list[str] | None = None) -> dict[str, Any]:
    return {
        "schema_version": PROJECT_STATE_SCHEMA_VERSION,
        "revision": 0,
        "project_scope": [x for x in (canonical_asset(v) for v in (scopes or [])) if x],
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


class ProjectStateStore:
    """Single-writer, revisioned JSON store for a target project."""

    def __init__(self, project_dir: str | pathlib.Path, *, project_scope: list[str] | None = None):
        self.project_dir = pathlib.Path(project_dir).resolve()
        self.path = self.project_dir / "project_state.json"
        self.lock_path = self.project_dir / ".project_state.lock"
        self.project_scope = project_scope or []

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

    def _read_unlocked(self) -> dict[str, Any]:
        if not self.path.exists():
            raise FileNotFoundError(self.path)
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProjectStateCorrupt(f"cannot read project state: {exc}") from exc
        if not isinstance(data, dict):
            raise ProjectStateCorrupt("project state must be an object")
        version = data.get("schema_version")
        if version != PROJECT_STATE_SCHEMA_VERSION:
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

    def _atomic_write(self, data: dict[str, Any]) -> None:
        payload = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        fd, tmp_name = tempfile.mkstemp(prefix=".project_state.", suffix=".tmp", dir=self.project_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
            try:
                dir_fd = os.open(self.project_dir, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
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
        fallback = self.project_scope[0] if self.project_scope else ""
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

    def _merge_inventory(self, state: dict[str, Any], item: dict[str, Any], run_id: str) -> None:
        fallback = state.get("project_scope", [""])[0] if state.get("project_scope") else ""
        asset = _asset_from(item, fallback)
        method, path = _method_and_path(item)
        if not asset or not path:
            return
        inv = state["inventory"]
        unresolved_key = f"{asset} :: {path}"
        if not method:
            rec = inv["unresolved"].setdefault(unresolved_key, {
                "asset_id": asset, "path": path, "method_candidates": [],
                "sources": [], "seen_in_runs": [], "first_seen": _now(),
            })
            source = str(item.get("source") or "unknown")
            _merge_unique(rec["sources"], [source])
            _merge_unique(rec["seen_in_runs"], [run_id])
            rec["last_seen"] = _now()
            intent_key = json.dumps({
                "asset": asset, "path": path, "kind": "method_resolution",
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
                })
            return
        key = canonical_project_surface_key(asset, method, path)
        rec = inv["surfaces"].setdefault(key, {
            "asset_id": asset, "method": method, "path": path,
            "params": [], "roles": [], "risk_tags": [], "sources": [],
            "seen_in_runs": [], "first_seen": _now(),
        })
        for field in ("params", "roles", "risk_tags"):
            values = item.get(field) or []
            if isinstance(values, str):
                values = [values]
            _merge_unique(rec[field], [str(x) for x in values if str(x)])
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
        fallback = state.get("project_scope", [""])[0] if state.get("project_scope") else ""
        asset = _asset_from(neg, fallback)
        method, path = _method_and_path(neg)
        role = str(neg.get("role") or neg.get("role_scope") or "unknown")
        vc = str(neg.get("vuln_class") or neg.get("vuln") or "")
        if not asset or not method or not vc:
            return
        key = canonical_project_cell_key(
            asset, method=method, path=path, param=str(neg.get("param") or ""),
            role_scope=role, vuln_class=vc)
        item = {
            **neg, "cell_key": key, "asset_id": asset, "method": method,
            "endpoint": path, "role_scope": role.lower(), "vuln_class": norm_vc(vc),
            "source_run": run_id, "status": "active",
            "evidence_refs": evidence_refs,
            "evidence_hashes": evidence_hashes,
        }
        existing = next((x for x in state["negatives"] if x.get("cell_key") == key), None)
        if existing:
            existing.update(item)
        else:
            state["negatives"].append(item)
        prior = state["cell_registry"].get(key)
        if not prior or prior.get("status") != "confirmed":
            state["cell_registry"][key] = {
                "cell_key": key, "asset_id": asset, "method": method,
                "path": _template_path(path), "param": str(neg.get("param") or ""),
                "role_scope": role.lower(), "vuln_class": norm_vc(vc),
                "status": "not_vulnerable", "source_run": run_id,
                "evidence_refs": evidence_refs,
                "evidence_hashes": evidence_hashes,
                "updated_at": _now(),
            }

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
        fallback = state.get("project_scope", [""])[0] if state.get("project_scope") else ""
        fingerprint = finding_fingerprint(finding, fallback_asset=fallback)
        canonical_id = _stable_id("root", fingerprint)
        registry = state["finding_registry"]
        record = registry.setdefault(fingerprint, {
            "fingerprint": fingerprint, "canonical_finding_id": canonical_id,
            "first_seen": _now(), "last_seen": "", "seen_in_runs": [],
            "observations": [], "status": "confirmed",
        })
        _merge_unique(record["seen_in_runs"], [run_id])
        observation = {
            "run_id": run_id, "finding_id": finding.get("id", ""),
            "evidence_refs": evidence_refs,
            "evidence_hashes": evidence_hashes,
        }
        if observation not in record["observations"]:
            record["observations"].append(observation)
        record["last_seen"] = _now()

        method, path = _method_and_path(finding)
        asset = _asset_from(finding, fallback)
        role = str(finding.get("affected_role") or finding.get("role") or "unknown").lower()
        vc = str(finding.get("vuln_class") or finding.get("class") or finding.get("vuln_type") or "")
        params = list(finding.get("params") or [""])
        for param in params:
            key = canonical_project_cell_key(
                asset, method=method, path=path, param=str(param or ""),
                role_scope=role, vuln_class=vc)
            for neg in state["negatives"]:
                if neg.get("cell_key") == key and neg.get("status") == "active":
                    neg["status"] = "superseded"
                    neg["superseded_by_finding_id"] = canonical_id
            state["cell_registry"][key] = {
                "cell_key": key, "asset_id": asset, "method": method,
                "path": _template_path(path), "param": str(param or ""),
                "role_scope": role, "vuln_class": norm_vc(vc),
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
            "endpoint": path, "method": method,
            "params": params, "affected_role": role, "vuln_class": norm_vc(vc),
            "summary": finding.get("title") or finding.get("primary_impact") or "",
            "root_cause": (
                finding.get("root_cause") or finding.get("root_cause_invariant")
                or finding.get("title") or finding.get("primary_impact") or ""
            ),
            "evidence_refs": evidence_refs,
            "evidence_hashes": evidence_hashes,
            "source_run": run_id,
        }
        existing_fact = next((x for x in state["facts"] if x.get("canonical_finding_id") == canonical_id), None)
        if existing_fact:
            existing_fact.update(fact)
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
        key = canonical_project_cell_key(
            asset, method=method, path=path,
            param=str(dead_end.get("param") or ""),
            role_scope=role, vuln_class=vc,
        )
        prior = state["cell_registry"].get(key)
        if prior and prior.get("status") == "confirmed":
            return
        record = {
            **dead_end,
            "cell_key": key,
            "asset_id": asset,
            "method": method,
            "endpoint": _template_path(path),
            "param": str(dead_end.get("param") or ""),
            "role_scope": role,
            "vuln_class": norm_vc(vc),
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
            "path": _template_path(path),
            "param": str(dead_end.get("param") or ""),
            "role_scope": role,
            "vuln_class": norm_vc(vc),
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
    ) -> dict[str, Any]:
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
            for item in inventory or []:
                record = {"endpoint": item} if isinstance(item, str) else dict(item)
                self._merge_inventory(state, record, run_id)
            for neg in negatives or []:
                self._merge_negative(state, dict(neg), run_id)
            for dead_end in dead_ends or []:
                self._merge_dead_end(state, dict(dead_end), run_id)
            for finding in findings or []:
                self._merge_finding(state, dict(finding), run_id)
            if intents is not None:
                by_id = {str(i.get("intent_id")): i for i in state["intents"] if i.get("intent_id")}
                for intent in intents:
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
            history = state["run_history"].setdefault(run_id, {"run_id": run_id})
            history.update(dict(run_summary or {}))
            history["updated_at"] = _now()
            state["revision"] = int(state.get("revision", 0) or 0) + 1
            state["updated_at"] = _now()
            self._atomic_write(state)
            return state

    def inventory_records(self) -> list[dict[str, Any]]:
        state = self.load()
        return [dict(x) for x in state["inventory"]["surfaces"].values()]

    def blackboard_view(self, *, include_revalidation: bool = True) -> dict[str, Any]:
        state = self.load()
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
