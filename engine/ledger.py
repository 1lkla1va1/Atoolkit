"""
Authoritative coverage ledger.

This module owns the endpoint/method/param/role/risk-tag surface schema and
can migrate the legacy CognitiveState.matrix from state.json into
coverage-ledger.json.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlsplit

try:
    from .planner import HIGH_VALUE_TAGS, infer_risk_tags, make_surface_id, plan_surfaces
except ImportError:  # pragma: no cover - script execution fallback
    from planner import HIGH_VALUE_TAGS, infer_risk_tags, make_surface_id, plan_surfaces


STATUS_NOT_TESTED = "not_tested"
STATUS_CONFIRMED = "confirmed"
STATUS_NOT_VULNERABLE = "not_vulnerable"
STATUS_BLOCKED = "blocked"
STATUS_NOT_APPLICABLE = "not_applicable"

VALID_STATUSES = {
    STATUS_NOT_TESTED,
    STATUS_CONFIRMED,
    STATUS_NOT_VULNERABLE,
    STATUS_BLOCKED,
    STATUS_NOT_APPLICABLE,
}

LEGACY_STATUS_MAP = {
    "untested": STATUS_NOT_TESTED,
    "positive": STATUS_CONFIRMED,
    "negative_with_evidence": STATUS_NOT_VULNERABLE,
    "shallow_negative": STATUS_NOT_TESTED,
    "skipped": STATUS_NOT_APPLICABLE,
    "negative": STATUS_NOT_VULNERABLE,
    "confirmed": STATUS_CONFIRMED,
    "not_vulnerable": STATUS_NOT_VULNERABLE,
    "blocked": STATUS_BLOCKED,
    "not_applicable": STATUS_NOT_APPLICABLE,
    "not_tested": STATUS_NOT_TESTED,
}

VULN_RISK_MAP = {
    "idor": ["object-ownership", "idor"],
    "越权": ["object-ownership", "idor"],
    "未授权": ["auth-flow", "auth-flow-abuse"],
    "认证": ["auth-flow", "auth-flow-abuse"],
    "sqli": ["input-validation", "injection"],
    "sql": ["input-validation", "injection"],
    "xss": ["input-validation"],
    "ssrf": ["ssrf"],
    "文件": ["file-upload", "path-traversal"],
    "上传": ["file-upload"],
    "业务逻辑": ["business-logic"],
    "支付": ["payment", "accounting"],
}


def _as_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return sorted(value)
    return [value]


def _dedupe(values: Iterable[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        key = text.lower()
        if key not in seen:
            seen.add(key)
            out.append(text)
    return out


def _first(value: Any, default: str = "") -> str:
    values = _as_list(value)
    return str(values[0]).strip() if values else default


def _clean_method(value: Any) -> str:
    return (_first(value, "GET") or "GET").upper()


def _roles_from_cell(cell: dict[str, Any]) -> list[str]:
    surface = cell.get("surface") if isinstance(cell.get("surface"), dict) else {}
    return _dedupe(
        _as_list(cell.get("roles"))
        + _as_list(cell.get("needed_roles"))
        + _as_list(surface.get("roles"))
        + _as_list(surface.get("needed_roles"))
    ) or ["unknown"]


def _params_from_cell(cell: dict[str, Any]) -> list[str]:
    surface = cell.get("surface") if isinstance(cell.get("surface"), dict) else {}
    params = _as_list(cell.get("param")) + _as_list(surface.get("param")) + _as_list(surface.get("params"))
    endpoint = str(cell.get("endpoint") or surface.get("endpoint") or "")
    params.extend(key for key, _ in parse_qsl(urlsplit(endpoint).query, keep_blank_values=True))
    return _dedupe(params) or [""]


def _risk_from_vuln(vuln: str, endpoint: str, param: str, feature: str) -> list[str]:
    tags = infer_risk_tags(param, endpoint, feature)
    low = str(vuln or "").lower()
    for needle, mapped in VULN_RISK_MAP.items():
        if needle.lower() in low:
            tags.extend(mapped)
    if not tags and vuln:
        token = re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "-", vuln.lower()).strip("-")
        tags.append(token or "general-review")
    return _dedupe(tags)


def normalize_status(status: str) -> str:
    normalized = LEGACY_STATUS_MAP.get(str(status or "").strip().lower(), STATUS_NOT_TESTED)
    if normalized not in VALID_STATUSES:
        return STATUS_NOT_TESTED
    return normalized


@dataclass
class Surface:
    surface_id: str
    endpoint: str
    method: str
    param: str = ""
    roles: list[str] = field(default_factory=list)
    risk_tags: list[str] = field(default_factory=list)
    feature: str = "default"
    status: str = STATUS_NOT_TESTED
    evidence_ref: str | None = None
    blocker: dict[str, Any] | None = None
    next_actions: list[str] = field(default_factory=list)
    source: str = "manual"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = normalize_status(data["status"])
        return data


class CoverageLedger:
    schema_version = 1

    def __init__(self, surfaces: list[dict[str, Any]] | None = None, metadata: dict[str, Any] | None = None):
        self.metadata = dict(metadata or {})
        self.surfaces: list[dict[str, Any]] = []
        for surface in surfaces or []:
            self.add_surface(surface)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "metadata": self.metadata,
            "surfaces": self.surfaces,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CoverageLedger":
        if "surfaces" in data:
            return cls(data.get("surfaces") or [], metadata=data.get("metadata") or {})
        if "matrix" in data:
            return cls.from_state(data)
        return cls()

    @classmethod
    def load(cls, path: str | pathlib.Path) -> "CoverageLedger":
        data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        ledger = cls.from_dict(data)
        ledger.metadata.setdefault("source_path", str(path))
        return ledger

    @classmethod
    def from_state_json(cls, path: str | pathlib.Path) -> "CoverageLedger":
        data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        ledger = cls.from_state(data)
        ledger.metadata.setdefault("source_path", str(path))
        return ledger

    @classmethod
    def from_state(cls, state: dict[str, Any]) -> "CoverageLedger":
        ledger = cls(metadata={
            "migrated_from": "state.json",
            "sid": state.get("sid") or state.get("project_id") or "",
            "target": state.get("target") or "",
        })
        matrix = state.get("matrix") or {}
        for cell in matrix.values():
            if not isinstance(cell, dict):
                continue
            for surface in surfaces_from_legacy_cell(cell):
                ledger.add_surface(surface)
        return ledger

    @classmethod
    def from_endpoints(cls, endpoints: list[str | dict[str, Any]], metadata: dict[str, Any] | None = None) -> "CoverageLedger":
        return cls(plan_surfaces(endpoints), metadata=metadata)

    def add_surface(self, surface: dict[str, Any] | Surface) -> dict[str, Any]:
        data = surface.to_dict() if isinstance(surface, Surface) else dict(surface)
        data = normalize_surface(data)
        existing = self.get(data["surface_id"])
        if existing:
            merge_surface(existing, data)
            return existing
        self.surfaces.append(data)
        return data

    def get(self, surface_id: str) -> dict[str, Any] | None:
        for surface in self.surfaces:
            if surface.get("surface_id") == surface_id:
                return surface
        return None

    def find(self, *, endpoint: str, method: str | None = None, param: str | None = None,
             risk_tag: str | None = None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for surface in self.surfaces:
            if endpoint and surface.get("endpoint") != endpoint:
                continue
            if method and surface.get("method", "").upper() != method.upper():
                continue
            if param is not None and surface.get("param", "") != param:
                continue
            if risk_tag and risk_tag not in surface.get("risk_tags", []):
                continue
            out.append(surface)
        return out

    def set_status(self, surface_id: str, status: str, *, evidence_ref: str | None = None,
                   blocker: dict[str, Any] | None = None, next_actions: list[str] | None = None) -> dict[str, Any]:
        surface = self.get(surface_id)
        if not surface:
            raise KeyError(surface_id)
        surface["status"] = normalize_status(status)
        if evidence_ref is not None:
            surface["evidence_ref"] = evidence_ref
        if blocker is not None:
            surface["blocker"] = blocker
        if next_actions is not None:
            surface["next_actions"] = list(next_actions)
        return surface

    def stats(self) -> dict[str, int]:
        counts = {status: 0 for status in sorted(VALID_STATUSES)}
        high_value_open = 0
        for surface in self.surfaces:
            status = normalize_status(surface.get("status", STATUS_NOT_TESTED))
            counts[status] = counts.get(status, 0) + 1
            if is_high_value(surface) and status in {STATUS_NOT_TESTED, STATUS_BLOCKED}:
                high_value_open += 1
        counts["total"] = len(self.surfaces)
        counts["closed"] = counts.get(STATUS_CONFIRMED, 0) + counts.get(STATUS_NOT_VULNERABLE, 0) + counts.get(STATUS_NOT_APPLICABLE, 0)
        counts["open"] = counts.get(STATUS_NOT_TESTED, 0) + counts.get(STATUS_BLOCKED, 0)
        counts["high_value_open"] = high_value_open
        return counts

    def next_surfaces(self, n: int = 10, *, high_value_first: bool = True) -> list[dict[str, Any]]:
        candidates = [s for s in self.surfaces if normalize_status(s.get("status")) in {STATUS_NOT_TESTED, STATUS_BLOCKED}]
        if high_value_first:
            candidates.sort(key=lambda s: (0 if is_high_value(s) else 1, s.get("feature", ""), s.get("surface_id", "")))
        return candidates[:n]

    def save(self, path: str | pathlib.Path) -> None:
        pathlib.Path(path).write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")


def normalize_surface(surface: dict[str, Any]) -> dict[str, Any]:
    endpoint = str(surface.get("endpoint") or surface.get("path") or surface.get("url") or "").split("?", 1)[0]
    method = _clean_method(surface.get("method"))
    param = str(surface.get("param") or "").strip()
    roles = _dedupe(_as_list(surface.get("roles"))) or ["unknown"]
    risk_tags = _dedupe(_as_list(surface.get("risk_tags"))) or infer_risk_tags(param, endpoint, surface.get("feature", ""))
    if not risk_tags:
        risk_tags = ["general-review"]
    data = {
        "surface_id": surface.get("surface_id") or make_surface_id(endpoint, method, param, roles, risk_tags),
        "endpoint": endpoint,
        "method": method,
        "param": param,
        "roles": roles,
        "risk_tags": risk_tags,
        "feature": str(surface.get("feature") or "default"),
        "status": normalize_status(surface.get("status", STATUS_NOT_TESTED)),
        "evidence_ref": surface.get("evidence_ref") or surface.get("evidence") or None,
        "blocker": surface.get("blocker"),
        "next_actions": _dedupe(surface.get("next_actions") or []),
        "source": str(surface.get("source") or "manual"),
    }
    for key, value in surface.items():
        if key not in data:
            data[key] = value
    return data


def merge_surface(dst: dict[str, Any], src: dict[str, Any]) -> dict[str, Any]:
    for key in ("roles", "risk_tags", "next_actions"):
        dst[key] = _dedupe(_as_list(dst.get(key)) + _as_list(src.get(key)))
    for key in ("evidence_ref", "blocker", "feature", "source"):
        if not dst.get(key) and src.get(key):
            dst[key] = src[key]
    status_order = {
        STATUS_NOT_TESTED: 0,
        STATUS_BLOCKED: 1,
        STATUS_NOT_APPLICABLE: 2,
        STATUS_NOT_VULNERABLE: 3,
        STATUS_CONFIRMED: 4,
    }
    if status_order.get(src.get("status"), 0) > status_order.get(dst.get("status"), 0):
        dst["status"] = src["status"]
    return dst


def surfaces_from_legacy_cell(cell: dict[str, Any]) -> list[dict[str, Any]]:
    surface_meta = cell.get("surface") if isinstance(cell.get("surface"), dict) else {}
    endpoint = str(cell.get("endpoint") or surface_meta.get("endpoint") or "").strip()
    if not endpoint:
        return []
    method = _clean_method(surface_meta.get("method") or cell.get("method"))
    feature = str(cell.get("feature") or surface_meta.get("feature") or "default")
    status = normalize_status(cell.get("state") or cell.get("status"))
    source = str(surface_meta.get("source") or cell.get("source") or "legacy-matrix")
    roles = _roles_from_cell(cell)
    next_actions = _dedupe(cell.get("next_actions") or [])
    if (cell.get("state") or "").lower() == "shallow_negative" and not next_actions:
        next_actions = ["add sufficient negative evidence and response proof"]
    if cell.get("needs"):
        next_actions.extend(str(x) for x in _as_list(cell.get("needs")))
    blocker = cell.get("blocker")
    evidence_ref = cell.get("evidence") or cell.get("evidence_ref") or None

    surfaces: list[dict[str, Any]] = []
    for param in _params_from_cell(cell):
        risk_tags = _risk_from_vuln(str(cell.get("vuln") or ""), endpoint, param, feature)
        surfaces.append({
            "surface_id": make_surface_id(endpoint, method, param, roles, risk_tags),
            "endpoint": endpoint,
            "method": method,
            "param": param,
            "roles": roles,
            "risk_tags": risk_tags,
            "feature": feature,
            "status": status,
            "evidence_ref": evidence_ref,
            "blocker": blocker,
            "next_actions": next_actions,
            "source": source,
            "legacy_vuln": cell.get("vuln", ""),
            "legacy_reason": cell.get("reason", ""),
        })
    return surfaces


def is_high_value(surface: dict[str, Any]) -> bool:
    tags = {str(x).lower() for x in _as_list(surface.get("risk_tags"))}
    endpoint = str(surface.get("endpoint") or "").lower()
    return bool(tags & HIGH_VALUE_TAGS) or any(x in endpoint for x in ("admin", "pay", "refund", "recharge", "order", "login", "register", "password"))


def derive_coverage(ledger: CoverageLedger | dict[str, Any]) -> dict[str, Any]:
    obj = ledger if isinstance(ledger, CoverageLedger) else CoverageLedger.from_dict(ledger)
    by_feature: dict[str, dict[str, int]] = {}
    for surface in obj.surfaces:
        feature = surface.get("feature") or "default"
        row = by_feature.setdefault(feature, {"total": 0, "closed": 0, "open": 0})
        row["total"] += 1
        if normalize_status(surface.get("status")) in {STATUS_CONFIRMED, STATUS_NOT_VULNERABLE, STATUS_NOT_APPLICABLE}:
            row["closed"] += 1
        else:
            row["open"] += 1
    return {"stats": obj.stats(), "features": by_feature}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create or migrate coverage-ledger.json.")
    parser.add_argument("input", help="coverage-ledger.json, state.json, or endpoint inventory JSON")
    parser.add_argument("-o", "--output", help="Output path. Defaults to coverage-ledger.json beside input.")
    parser.add_argument("--inventory", action="store_true", help="Treat input as endpoint inventory instead of state/ledger")
    args = parser.parse_args(argv)
    path = pathlib.Path(args.input)
    data = json.loads(path.read_text(encoding="utf-8"))
    if args.inventory:
        endpoints = data.get("discovered_apis") if isinstance(data, dict) else data
        ledger = CoverageLedger.from_endpoints(endpoints or [], metadata={"source_path": str(path)})
    else:
        ledger = CoverageLedger.from_dict(data)
    output = pathlib.Path(args.output) if args.output else path.with_name("coverage-ledger.json")
    ledger.save(output)
    print(json.dumps({"output": str(output), "stats": ledger.stats()}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
