"""Validated feature/threat plans and deterministic coverage compilation.

The model is allowed to reason about business behaviour, but it cannot create
coverage by prose alone.  This module validates that reasoning against the
observed inventory and compiles only declared threats into exact ledger cells.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Any, Iterable
from urllib.parse import urlsplit

try:
    from .ledger import (
        STATUS_CONFIRMED,
        STATUS_NOT_APPLICABLE,
        STATUS_NOT_VULNERABLE,
        normalize_status,
    )
    from .planner import extract_param_specs, infer_risk_tags
    from .safe_io import safe_read_bytes
except ImportError:  # pragma: no cover - direct script fallback
    from ledger import (STATUS_CONFIRMED, STATUS_NOT_APPLICABLE,
                        STATUS_NOT_VULNERABLE, normalize_status)
    from planner import extract_param_specs, infer_risk_tags
    from safe_io import safe_read_bytes


class ThreatModelError(ValueError):
    """Raised when a feature/threat plan cannot be bound to observed truth."""


REQUIRED_DISCOVERY_CHANNELS = (
    "js_ref",
    "inline_script",
    "asset_ref",
    "page_link",
    "path_inference",
    "response_body",
)
DISCOVERY_STATUSES = {"covered", "blocked", "not_applicable"}
CODE_DISCOVERY_CHANNELS = {"js_ref", "inline_script", "asset_ref"}
RUNTIME_DISCOVERY_CHANNELS = {"page_link", "path_inference", "response_body"}
IDENTITY_MODES = {
    "single",
    "anonymous_plus_authenticated",
    "peer_pair",
    "role_pair",
    "stateful_owner",
}
TERMINAL_STATUSES = {
    STATUS_CONFIRMED,
    STATUS_NOT_VULNERABLE,
    STATUS_NOT_APPLICABLE,
}


def _as_list(value: Any) -> list[Any]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _strings(value: Any) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in _as_list(value):
        text = str(item or "").strip()
        if text and text.lower() not in seen:
            seen.add(text.lower())
            result.append(text)
    return result


def _endpoint(value: Any) -> str:
    text = str(value or "").strip()
    parts = text.split(None, 1)
    if len(parts) == 2 and parts[0].isalpha():
        text = parts[1]
    parsed = urlsplit(text)
    return parsed.path or text.split("?", 1)[0]


def _normalized_prefix(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "/"
    if not text.startswith("/"):
        text = "/" + text
    return text if text == "/" else text.rstrip("/") + "/"


def _path_in_scope(
    endpoint: str,
    *,
    base_path: str,
    base_path_explicit: bool,
    allow_paths: Iterable[str] | None,
    deny_paths: Iterable[str] | None,
) -> bool:
    path = _endpoint(endpoint)
    normalized = path if path == "/" else path.rstrip("/") + "/"
    denied = [_normalized_prefix(value) for value in (deny_paths or [])]
    if any(normalized.startswith(prefix) for prefix in denied):
        return False
    allowed = [_normalized_prefix(value) for value in (allow_paths or [])]
    if allowed:
        return any(normalized.startswith(prefix) for prefix in allowed)
    if base_path_explicit and _normalized_prefix(base_path) != "/":
        return normalized.startswith(_normalized_prefix(base_path))
    return True


def _default_identity_requirement(threat: dict[str, Any]) -> dict[str, Any]:
    vuln = str(threat.get("vuln_class") or "").lower()
    attacker = str(threat.get("attacker") or "").lower()
    hay = f"{vuln} {attacker}"
    if any(value in hay for value in (
        "idor", "越权", "authorization", "access-control", "access control",
    )):
        mode = "peer_pair"
    elif any(value in hay for value in (
        "unauth", "未授权", "anonymous", "认证绕过", "auth-bypass",
    )):
        mode = "anonymous_plus_authenticated"
    else:
        mode = "single"
    minimum = 2 if mode in {"peer_pair", "role_pair"} else (
        1 if mode in {"anonymous_plus_authenticated", "stateful_owner"} else 0)
    return {
        "mode": mode,
        "roles": [],
        "minimum_distinct_credentials": minimum,
        "reason": "host-derived conservative default",
    }


def _normalize_identity_requirement(
    threat: dict[str, Any], context: str, errors: list[str],
) -> dict[str, Any]:
    raw = threat.get("identity_requirement")
    if raw in (None, ""):
        return _default_identity_requirement(threat)
    if not isinstance(raw, dict):
        errors.append(f"{context}.identity_requirement must be an object")
        return _default_identity_requirement(threat)
    mode = str(raw.get("mode") or "").strip().lower()
    if mode not in IDENTITY_MODES:
        errors.append(f"{context}.identity_requirement.mode is invalid: {mode!r}")
    roles = _strings(raw.get("roles"))
    default_minimum = 2 if mode in {"peer_pair", "role_pair"} else (
        1 if mode in {"anonymous_plus_authenticated", "stateful_owner"} else 0)
    try:
        minimum = int(raw.get("minimum_distinct_credentials", default_minimum))
    except (TypeError, ValueError):
        minimum = -1
    if minimum < default_minimum:
        errors.append(
            f"{context}.identity_requirement.minimum_distinct_credentials "
            f"must be >= {default_minimum} for {mode}")
    if mode == "role_pair" and len(set(role.lower() for role in roles)) < 2:
        errors.append(f"{context}.identity_requirement.role_pair requires two roles")
    reason = str(raw.get("reason") or "").strip()
    if not reason:
        errors.append(f"{context}.identity_requirement.reason is required")
    return {
        **raw,
        "mode": mode,
        "roles": roles,
        "minimum_distinct_credentials": max(minimum, 0),
        "reason": reason,
    }


def _inventory_index(
    inventory_rows: Iterable[dict[str, Any] | str],
) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in inventory_rows:
        if isinstance(raw, str):
            parts = raw.strip().split(None, 1)
            method = parts[0].upper() if len(parts) == 2 else ""
            endpoint = _endpoint(parts[1] if len(parts) == 2 else raw)
            row: dict[str, Any] = {"endpoint": endpoint, "method": method}
        elif isinstance(raw, dict):
            row = dict(raw)
            endpoint = _endpoint(
                row.get("endpoint") or row.get("path") or row.get("url"))
            method = str(row.get("method") or "").strip().upper()
        else:
            continue
        if not endpoint or not method:
            continue
        specs = extract_param_specs(endpoint, row)
        key = (endpoint, method)
        current = index.get(key)
        if current is None:
            index[key] = {
                "row": row,
                "params": {name: location for name, location in specs},
                "roles": _strings(row.get("roles") or row.get("role")),
            }
        else:
            current["params"].update({name: location for name, location in specs})
            current["roles"] = _strings([
                *current.get("roles", []),
                *_strings(row.get("roles") or row.get("role")),
            ])
    return index


def _required_text(value: dict[str, Any], key: str, context: str, errors: list[str]) -> str:
    text = str(value.get(key) or "").strip()
    if not text:
        errors.append(f"{context}.{key} is required")
    return text


def _validate_ref(run_dir: pathlib.Path, ref: Any, context: str, errors: list[str]) -> str:
    text = str(ref or "").strip()
    path = pathlib.Path(text)
    if not text or path.is_absolute() or ".." in path.parts:
        errors.append(f"{context} has unsafe evidence ref: {text!r}")
        return text
    try:
        safe_read_bytes(run_dir / path, root=run_dir)
    except (OSError, ValueError) as exc:
        errors.append(f"{context} evidence ref {text!r} is unreadable: {exc}")
    return path.as_posix()


def validate_threat_plan(
    feature_graph: dict[str, Any],
    threat_model: dict[str, Any],
    inventory_rows: Iterable[dict[str, Any] | str],
    *,
    run_dir: str | pathlib.Path,
    base_path: str = "/",
    base_path_explicit: bool = False,
    allow_paths: Iterable[str] | None = None,
    deny_paths: Iterable[str] | None = None,
    require_discovery_adequacy: bool = True,
) -> dict[str, Any]:
    """Validate model reasoning against inventory and physical discovery evidence."""
    if not isinstance(feature_graph, dict) or not isinstance(threat_model, dict):
        raise ThreatModelError("feature graph and threat model must be objects")
    root = pathlib.Path(run_dir).resolve()
    inventory = _inventory_index(inventory_rows)
    errors: list[str] = []

    channels = feature_graph.get("discovery_channels")
    if not isinstance(channels, dict):
        channels = {}
        errors.append("feature_graph.discovery_channels must be an object")
    normalized_channels: dict[str, dict[str, Any]] = {}
    for name in REQUIRED_DISCOVERY_CHANNELS:
        raw = channels.get(name)
        if not isinstance(raw, dict):
            errors.append(f"discovery channel {name} is missing")
            continue
        status = str(raw.get("status") or "").strip().lower()
        refs = [
            _validate_ref(root, ref, f"discovery channel {name}", errors)
            for ref in _as_list(raw.get("evidence_refs"))
        ]
        reason = str(raw.get("reason") or "").strip()
        if status not in DISCOVERY_STATUSES:
            errors.append(f"discovery channel {name} has invalid status {status!r}")
        if status == "covered" and not refs:
            errors.append(f"discovery channel {name} requires evidence_refs")
        if status in {"blocked", "not_applicable"} and not reason:
            errors.append(f"discovery channel {name} status {status} requires reason")
        normalized_channels[name] = {
            "status": status,
            "evidence_refs": refs,
            **({"reason": reason} if reason else {}),
        }
    if require_discovery_adequacy:
        covered = {
            name for name, item in normalized_channels.items()
            if item.get("status") == "covered"
        }
        if len(covered) < 2:
            errors.append("discovery adequacy requires at least two covered channels")
        if not (covered & CODE_DISCOVERY_CHANNELS):
            errors.append("discovery adequacy requires a code/asset channel")
        if not (covered & RUNTIME_DISCOVERY_CHANNELS):
            errors.append("discovery adequacy requires a navigation/runtime channel")

    raw_features = feature_graph.get("features")
    if not isinstance(raw_features, list) or not raw_features:
        errors.append("feature_graph.features must be a non-empty list")
        raw_features = []
    normalized_features: list[dict[str, Any]] = []
    feature_by_id: dict[str, dict[str, Any]] = {}
    assigned: set[tuple[str, str]] = set()
    for position, raw in enumerate(raw_features):
        context = f"feature[{position}]"
        if not isinstance(raw, dict):
            errors.append(f"{context} must be an object")
            continue
        feature = dict(raw)
        feature_id = _required_text(feature, "feature_id", context, errors)
        _required_text(feature, "name", context, errors)
        if feature_id in feature_by_id:
            errors.append(f"duplicate feature_id {feature_id!r}")
        if not _strings(feature.get("actors")):
            errors.append(f"{context}.actors must not be empty")
        if not (_strings(feature.get("assets")) or _strings(feature.get("objects"))):
            errors.append(f"{context} must declare assets or objects")
        if not _strings(feature.get("actions")):
            errors.append(f"{context}.actions must not be empty")
        apis = feature.get("apis")
        if not isinstance(apis, list) or not apis:
            errors.append(f"{context}.apis must be a non-empty list")
            apis = []
        normalized_apis: list[dict[str, Any]] = []
        for api_pos, raw_api in enumerate(apis):
            api_context = f"{context}.apis[{api_pos}]"
            if not isinstance(raw_api, dict):
                errors.append(f"{api_context} must be an object")
                continue
            endpoint = _endpoint(raw_api.get("endpoint") or raw_api.get("path"))
            method = str(raw_api.get("method") or "").strip().upper()
            key = (endpoint, method)
            observed = inventory.get(key)
            if not endpoint or not method:
                errors.append(f"{api_context} requires endpoint and method")
            elif observed is None:
                errors.append(f"{api_context} {method} {endpoint} is not in inventory")
            elif not _path_in_scope(
                    endpoint, base_path=base_path,
                    base_path_explicit=base_path_explicit,
                    allow_paths=allow_paths, deny_paths=deny_paths):
                errors.append(
                    f"{api_context} {method} {endpoint} is outside frozen path scope")
            params = _strings(raw_api.get("params"))
            if observed is not None:
                missing = sorted(set(params) - set(observed["params"]))
                if missing:
                    errors.append(
                        f"{api_context} params not observed on {method} {endpoint}: {missing}")
                assigned.add(key)
                observed_roles = set(observed.get("roles") or [])
                declared_roles = set(_strings(raw_api.get("roles")))
                if observed_roles and declared_roles - observed_roles:
                    errors.append(
                        f"{api_context} roles not observed on {method} {endpoint}: "
                        f"{sorted(declared_roles - observed_roles)}")
            normalized_apis.append({
                **raw_api,
                "endpoint": endpoint,
                "method": method,
                "params": params,
                "roles": _strings(raw_api.get("roles")),
            })
        feature["feature_id"] = feature_id
        feature["apis"] = normalized_apis
        normalized_features.append(feature)
        if feature_id:
            feature_by_id[feature_id] = feature

    unassigned = feature_graph.get("unassigned_endpoints")
    if not isinstance(unassigned, list):
        errors.append("feature_graph.unassigned_endpoints must be a list")
        unassigned = []
    normalized_unassigned: list[dict[str, str]] = []
    for position, raw in enumerate(unassigned):
        if not isinstance(raw, dict):
            errors.append(f"unassigned_endpoints[{position}] must be an object")
            continue
        endpoint = _endpoint(raw.get("endpoint") or raw.get("path"))
        method = str(raw.get("method") or "").strip().upper()
        reason = str(raw.get("reason") or "").strip()
        key = (endpoint, method)
        if key not in inventory:
            errors.append(f"unassigned endpoint {method} {endpoint} is not in inventory")
        if not reason:
            errors.append(f"unassigned endpoint {method} {endpoint} requires reason")
        if key in assigned:
            errors.append(
                f"endpoint cannot be both assigned and unassigned: {method} {endpoint}")
        assigned.add(key)
        normalized_unassigned.append({
            "endpoint": endpoint, "method": method, "reason": reason,
        })
    for endpoint, method in sorted(set(inventory) - assigned):
        errors.append(f"inventory endpoint is not assigned to a feature: {method} {endpoint}")

    raw_threat_features = threat_model.get("features")
    if not isinstance(raw_threat_features, list):
        errors.append("threat_model.features must be a list")
        raw_threat_features = []
    threat_feature_ids: set[str] = set()
    threat_ids: set[str] = set()
    normalized_threat_features: list[dict[str, Any]] = []
    for position, raw in enumerate(raw_threat_features):
        context = f"threat feature[{position}]"
        if not isinstance(raw, dict):
            errors.append(f"{context} must be an object")
            continue
        item = dict(raw)
        feature_id = _required_text(item, "feature_id", context, errors)
        if feature_id in threat_feature_ids:
            errors.append(f"duplicate threat feature_id {feature_id!r}")
        threat_feature_ids.add(feature_id)
        feature = feature_by_id.get(feature_id)
        if feature is None:
            errors.append(f"{context} references unknown feature_id {feature_id!r}")
        note = item.get("coverage_note")
        if not isinstance(note, dict):
            errors.append(f"{context}.coverage_note must be an object")
            note = {}
        for key in ("input_surface", "behavior_surface", "depth_strategy"):
            _required_text(note, key, f"{context}.coverage_note", errors)
        threats = item.get("threats")
        if not isinstance(threats, list):
            errors.append(f"{context}.threats must be a list")
            threats = []
        if not threats and not str(item.get("no_threat_reason") or "").strip():
            errors.append(f"{context} has no threats and requires no_threat_reason")
        normalized_threats: list[dict[str, Any]] = []
        feature_api_keys = {
            (api["endpoint"], api["method"]): api
            for api in (feature or {}).get("apis", [])
        }
        for threat_pos, raw_threat in enumerate(threats):
            threat_context = f"{context}.threats[{threat_pos}]"
            if not isinstance(raw_threat, dict):
                errors.append(f"{threat_context} must be an object")
                continue
            threat = dict(raw_threat)
            for key in (
                "threat_id", "vuln_class", "security_invariant", "attacker",
                "asset", "abuse_action", "expected_secure_result",
                "observable_violation", "reasoning",
            ):
                _required_text(threat, key, threat_context, errors)
            threat_id = str(threat.get("threat_id") or "").strip()
            if threat_id in threat_ids:
                errors.append(f"duplicate threat_id {threat_id!r}")
            threat_ids.add(threat_id)
            evidence_required = _strings(threat.get("evidence_required"))
            if not evidence_required:
                errors.append(f"{threat_context}.evidence_required must not be empty")
            if not _strings(threat.get("preconditions")):
                errors.append(f"{threat_context}.preconditions must not be empty")
            targets = threat.get("targets")
            if not isinstance(targets, list) or not targets:
                errors.append(f"{threat_context}.targets must be a non-empty list")
                targets = []
            normalized_targets: list[dict[str, Any]] = []
            for target_pos, raw_target in enumerate(targets):
                target_context = f"{threat_context}.targets[{target_pos}]"
                if not isinstance(raw_target, dict):
                    errors.append(f"{target_context} must be an object")
                    continue
                endpoint = _endpoint(raw_target.get("endpoint") or raw_target.get("path"))
                method = str(raw_target.get("method") or "").strip().upper()
                api = feature_api_keys.get((endpoint, method))
                if api is None:
                    errors.append(
                        f"{target_context} {method} {endpoint} is outside feature {feature_id}")
                params = _strings(raw_target.get("params"))
                if api is not None:
                    missing = sorted(set(params) - set(api.get("params") or []))
                    if missing:
                        errors.append(
                            f"{target_context} params outside feature API: {missing}")
                    target_roles = set(_strings(raw_target.get("roles")))
                    api_roles = set(api.get("roles") or [])
                    if api_roles and target_roles - api_roles:
                        errors.append(
                            f"{target_context} roles outside feature API: "
                            f"{sorted(target_roles - api_roles)}")
                normalized_targets.append({
                    **raw_target,
                    "endpoint": endpoint,
                    "method": method,
                    "params": params,
                    "roles": _strings(raw_target.get("roles")),
                })
            threat["threat_id"] = threat_id
            threat["targets"] = normalized_targets
            threat["evidence_required"] = evidence_required
            threat["identity_requirement"] = _normalize_identity_requirement(
                threat, threat_context, errors)
            normalized_threats.append(threat)
        item["feature_id"] = feature_id
        item["coverage_note"] = dict(note)
        item["threats"] = normalized_threats
        normalized_threat_features.append(item)
    missing_threat_features = sorted(set(feature_by_id) - threat_feature_ids)
    if missing_threat_features:
        errors.append(
            f"features missing threat coverage notes: {missing_threat_features}")

    if errors:
        raise ThreatModelError("invalid threat plan:\n- " + "\n- ".join(errors))
    normalized_graph = {
        **feature_graph,
        "schema_version": 1,
        "discovery_channels": normalized_channels,
        "features": normalized_features,
        "unassigned_endpoints": normalized_unassigned,
    }
    normalized_model = {
        **threat_model,
        "schema_version": 1,
        "features": normalized_threat_features,
    }
    return {"feature_graph": normalized_graph, "threat_model": normalized_model}


def _surface_id(parts: Iterable[Any]) -> str:
    raw = "\x1f".join(str(part or "").strip().lower() for part in parts)
    return "tm-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def compile_threat_model(
    plan: dict[str, Any],
    inventory_rows: Iterable[dict[str, Any] | str],
    *,
    target: str,
) -> list[dict[str, Any]]:
    """Compile only explicitly declared threats into exact coverage cells."""
    inventory = _inventory_index(inventory_rows)
    feature_by_id = {
        item["feature_id"]: item
        for item in plan.get("feature_graph", {}).get("features", [])
    }
    surfaces: list[dict[str, Any]] = []
    seen: set[str] = set()
    exact_identities: dict[tuple[str, ...], tuple[str, str]] = {}
    for threat_feature in plan.get("threat_model", {}).get("features", []):
        feature_id = str(threat_feature.get("feature_id") or "")
        feature = feature_by_id.get(feature_id, {})
        for threat in threat_feature.get("threats") or []:
            threat_id = str(threat.get("threat_id") or "")
            vuln_class = str(threat.get("vuln_class") or "")
            for target_spec in threat.get("targets") or []:
                endpoint = _endpoint(target_spec.get("endpoint"))
                method = str(target_spec.get("method") or "").upper()
                observed = inventory.get((endpoint, method), {})
                params = _strings(target_spec.get("params")) or [""]
                roles = _strings(target_spec.get("roles"))
                if not roles:
                    roles = _strings(observed.get("roles")) or _strings(feature.get("actors"))
                roles = roles or ["unknown"]
                for param in params:
                    for role in roles:
                        sid = _surface_id((
                            target, feature_id, threat_id, endpoint, method, param, role,
                        ))
                        if sid in seen:
                            continue
                        seen.add(sid)
                        location = str(observed.get("params", {}).get(param, ""))
                        exact_identity = (
                            str(target).strip().lower(), endpoint.lower(), method.lower(),
                            param.lower(), role.lower(), location.lower(),
                            vuln_class.strip().lower(),
                        )
                        prior = exact_identities.get(exact_identity)
                        if prior is not None and prior != (feature_id, threat_id):
                            raise ThreatModelError(
                                "two threats compile to the same runtime cell; "
                                "use distinct vuln_class values or target dimensions: "
                                f"{prior[0]}/{prior[1]} and {feature_id}/{threat_id}")
                        exact_identities[exact_identity] = (feature_id, threat_id)
                        surfaces.append({
                            "surface_id": sid,
                            "asset_id": str(
                                observed.get("row", {}).get("asset_id")
                                or observed.get("row", {}).get("asset")
                                or target),
                            "protected_asset": str(threat.get("asset") or ""),
                            "endpoint": endpoint,
                            "method": method,
                            "param": param,
                            "param_location": location,
                            "roles": [role],
                            "actor_role": role,
                            "risk_tags": infer_risk_tags(
                                "", endpoint, str(feature.get("name") or feature_id),
                                declared_classes=[vuln_class],
                            ) or ["business-logic"],
                            "feature": str(feature.get("name") or feature_id),
                            "feature_id": feature_id,
                            "threat_id": threat_id,
                            "vuln_class": vuln_class,
                            "security_invariant": str(threat.get("security_invariant") or ""),
                            "expected_secure_result": str(
                                threat.get("expected_secure_result") or ""),
                            "observable_violation": str(threat.get("observable_violation") or ""),
                            "evidence_required": _strings(threat.get("evidence_required")),
                            "identity_requirement": dict(
                                threat.get("identity_requirement") or {"mode": "single"}),
                            "coverage_note": dict(threat_feature.get("coverage_note") or {}),
                            "status": "not_tested",
                            "source": "threat-model-compiler",
                            "in_run_scope": True,
                        })
    return surfaces


def derive_threat_coverage(
    surfaces: Iterable[dict[str, Any]],
    threat_model: dict[str, Any],
) -> dict[str, Any]:
    """Project exact cell state back to threat and feature closure."""
    rows = list(surfaces)
    features: list[dict[str, Any]] = []
    threat_count = 0
    open_threats = 0
    closed_threats = 0
    for feature in threat_model.get("features") or []:
        feature_id = str(feature.get("feature_id") or "")
        projected: list[dict[str, Any]] = []
        for threat in feature.get("threats") or []:
            threat_id = str(threat.get("threat_id") or "")
            threat_count += 1
            cells = [row for row in rows if row.get("threat_id") == threat_id
                     and row.get("feature_id") == feature_id]
            statuses = [normalize_status(row.get("status")) for row in cells]
            closed = bool(cells) and all(status in TERMINAL_STATUSES for status in statuses)
            if closed:
                closed_threats += 1
            else:
                open_threats += 1
            projected.append({
                "threat_id": threat_id,
                "status": "closed" if closed else "open",
                "cells": len(cells),
                "open_cells": sum(status not in TERMINAL_STATUSES for status in statuses),
                "status_counts": {
                    status: statuses.count(status) for status in sorted(set(statuses))
                },
            })
        feature_closed = all(item["status"] == "closed" for item in projected)
        if not projected and str(feature.get("no_threat_reason") or "").strip():
            feature_closed = True
        features.append({
            "feature_id": feature_id,
            "status": "closed" if feature_closed else "open",
            "threats": projected,
        })
    return {
        "schema_version": 1,
        "planning_mode": "threat_model",
        "stats": {
            "features": len(features),
            "open_features": sum(item["status"] == "open" for item in features),
            "threats": threat_count,
            "open_threats": open_threats,
            "closed_threats": closed_threats,
        },
        "features": features,
    }


__all__ = [
    "ThreatModelError",
    "REQUIRED_DISCOVERY_CHANNELS",
    "validate_threat_plan",
    "compile_threat_model",
    "derive_threat_coverage",
]
