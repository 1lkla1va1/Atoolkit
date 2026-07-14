from __future__ import annotations

import json
import pathlib
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit


def _as_path(path: str | pathlib.Path) -> pathlib.Path:
    return pathlib.Path(path).expanduser()


def _inside(child: pathlib.Path, parent: pathlib.Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def load_finding(path: str | pathlib.Path) -> dict[str, Any]:
    finding_path = _as_path(path)
    try:
        data = json.loads(finding_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid finding json {finding_path}: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"cannot read finding json {finding_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"finding json must be an object: {finding_path}")
    data.setdefault("_finding_path", str(finding_path.resolve()))
    return data


def resolve_finding_file(
    finding_dir: str | pathlib.Path,
    ref: str | pathlib.Path | None,
    run_dir: str | pathlib.Path,
) -> pathlib.Path:
    if not ref:
        raise ValueError("empty file reference")
    finding_base = _as_path(finding_dir).resolve()
    run_base = _as_path(run_dir).resolve()
    raw = pathlib.Path(str(ref)).expanduser()
    path = raw if raw.is_absolute() else finding_base / raw
    resolved = path.resolve(strict=False)
    if not _inside(resolved, run_base):
        raise ValueError(f"path escapes run directory: {ref}")
    return resolved


def _rel_to_run(path: pathlib.Path, run_dir: pathlib.Path) -> str:
    try:
        return path.resolve().relative_to(run_dir.resolve()).as_posix()
    except ValueError:
        return str(path)


def _dedupe(values: list[str]) -> list[str]:
    seen, out = set(), []
    for value in values:
        text = str(value or "").strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            out.append(text)
    return out


def _as_list(value: Any) -> list[Any]:
    if value in (None, "", [], {}):
        return []
    return value if isinstance(value, list) else [value]


_ROLE_FIELDS = (
    "actor_roles", "actor_role", "role_scopes", "role_scope", "roles", "role",
    "affected_roles", "affected_role", "observed_roles",
)
_ASSET_FIELDS = ("assets", "asset", "asset_id")


def _declared_values(item: dict[str, Any], fields: tuple[str, ...]) -> list[str]:
    return _dedupe([
        str(value)
        for field in fields
        for value in _as_list(item.get(field))
    ])


def _param_location(endpoint: str, name: str, explicit: str = "") -> str:
    location = str(explicit or "").strip().lower()
    if location:
        return location
    parsed = urlsplit(str(endpoint or ""))
    if re.search(rf"\{{{re.escape(name)}\}}|:{re.escape(name)}(?:/|$)",
                 parsed.path or endpoint, re.IGNORECASE):
        return "path"
    if any(key == name for key, _ in parse_qsl(parsed.query, keep_blank_values=True)):
        return "query"
    return ""


def _api_param_specs(api: dict[str, Any]) -> list[tuple[str, str]]:
    endpoint = str(api.get("path") or "")
    default_location = str(api.get("param_location") or "").strip().lower()
    location_map = api.get("param_locations") if isinstance(
        api.get("param_locations"), dict) else {}
    specs: list[tuple[str, str]] = []

    def add(value: Any, location: str = "") -> None:
        if isinstance(value, dict):
            name = str(value.get("name") or value.get("key")
                       or value.get("param") or "").strip()
            location = str(value.get("location") or value.get("in")
                           or location or "").strip().lower()
        else:
            name = str(value or "").strip()
        if not name:
            return
        mapped = str(location_map.get(name) or location or default_location).strip().lower()
        specs.append((name, _param_location(endpoint, name, mapped)))

    for value in _as_list(api.get("param")) + _as_list(api.get("params")):
        add(value)
    for field, location in (
        ("query_params", "query"), ("body_params", "body"),
        ("form_params", "form"), ("path_params", "path"),
    ):
        for value in _as_list(api.get(field)):
            add(value, location)
    declared_names = {name.lower() for name, _location in specs}
    for value in _as_list(api.get("risk_params")):
        name = str((value.get("name") or value.get("key")
                    or value.get("param") or "") if isinstance(value, dict)
                   else value or "").strip()
        if name.lower() not in declared_names:
            add(value)

    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for name, location in specs:
        key = (name.lower(), location.lower())
        if key not in seen:
            seen.add(key)
            out.append((name, location))
    return out or [("", "")]


def _unique_dimension(rows: list[dict[str, Any]], key: str) -> str:
    values = {str(row.get(key) or "").strip() for row in rows}
    return next(iter(values)) if len(values) == 1 else ""


def normalize_finding(
    finding: dict[str, Any],
    finding_path: str | pathlib.Path,
    run_dir: str | pathlib.Path,
    *,
    exact_cell_bindings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    finding_file = _as_path(finding_path).resolve()
    run_base = _as_path(run_dir).resolve()
    finding_dir = finding_file.parent
    apis = finding.get("apis") or []
    endpoints = _dedupe([str(api.get("path") or "") for api in apis if isinstance(api, dict)])
    methods = _dedupe([str(api.get("method") or "").upper() for api in apis if isinstance(api, dict)])
    params: list[str] = []
    for api in apis:
        if not isinstance(api, dict):
            continue
        params.extend(str(x) for x in (api.get("risk_params") or []))
        for item in api.get("params") or []:
            if isinstance(item, dict):
                params.append(str(item.get("name") or ""))

    finding_roles = _declared_values(finding, _ROLE_FIELDS) or ["unknown"]
    finding_assets = _declared_values(finding, _ASSET_FIELDS)
    if not finding_assets and str(finding.get("target") or "").strip():
        finding_assets = [str(finding["target"]).strip()]
    top_dimensions = {
        key: str(finding.get(key) or "").strip()
        for key in ("namespace", "param_location", "subject_role", "object_kind")
    }
    exact_cells: list[dict[str, Any]] = []
    seen_exact: set[tuple[str, ...]] = set()
    for api in apis:
        if not isinstance(api, dict):
            continue
        endpoint = str(api.get("path") or "").strip()
        method = str(api.get("method") or "").strip().upper()
        api_assets = (_declared_values(api, _ASSET_FIELDS)
                      if any(field in api for field in _ASSET_FIELDS)
                      else finding_assets) or [""]
        api_roles = (_declared_values(api, _ROLE_FIELDS)
                     if any(field in api for field in _ROLE_FIELDS)
                     else finding_roles) or ["unknown"]
        dimensions = {
            key: str(api.get(key) or top_dimensions[key] or "").strip()
            for key in ("namespace", "param_location", "subject_role", "object_kind")
        }
        for param, inferred_location in _api_param_specs(api):
            location = inferred_location or dimensions["param_location"]
            for asset in api_assets:
                for role in api_roles:
                    row = {
                        "asset_id": asset,
                        "endpoint": endpoint,
                        "method": method,
                        "param": param,
                        "actor_role": str(role).strip().lower() or "unknown",
                        "namespace": dimensions["namespace"],
                        "param_location": str(location or "").strip().lower(),
                        "subject_role": dimensions["subject_role"].lower(),
                        "object_kind": dimensions["object_kind"].lower(),
                    }
                    identity = tuple(str(row[key]) for key in (
                        "asset_id", "endpoint", "method", "param", "actor_role",
                        "namespace", "param_location", "subject_role", "object_kind",
                    ))
                    if identity not in seen_exact:
                        seen_exact.add(identity)
                        exact_cells.append(row)

    # The validator supplies this projection only after raw request packets
    # have been matched to every exact cell.  Keeping the binding on the row
    # prevents a later coverage consumer from treating a finding-wide proof
    # file list as evidence for an unrelated API appended to the same finding.
    bindings_by_identity: dict[tuple[str, ...], dict[str, Any]] = {}
    for binding in exact_cell_bindings or []:
        if not isinstance(binding, dict):
            continue
        identity = tuple(str(binding.get(key) or "") for key in (
            "asset_id", "endpoint", "method", "param", "actor_role",
            "namespace", "param_location", "subject_role", "object_kind",
        ))
        bindings_by_identity[identity] = binding
    for row in exact_cells:
        identity = tuple(str(row.get(key) or "") for key in (
            "asset_id", "endpoint", "method", "param", "actor_role",
            "namespace", "param_location", "subject_role", "object_kind",
        ))
        binding = bindings_by_identity.get(identity)
        if binding:
            row["proof_packet_ids"] = _dedupe([
                str(value) for value in binding.get("proof_packet_ids") or []
            ])
            row["proof_files"] = _dedupe([
                str(value) for value in binding.get("proof_files") or []
            ])
    proof_files: list[str] = []

    def add_ref(ref: str | None) -> None:
        if not ref:
            return
        try:
            proof_files.append(_rel_to_run(resolve_finding_file(finding_dir, ref, run_base), run_base))
        except ValueError:
            proof_files.append(str(ref))

    add_ref("finding.json")
    for packet in finding.get("proof_packets") or []:
        if isinstance(packet, dict):
            add_ref(packet.get("request_file"))
            add_ref(packet.get("response_file"))
    poc = finding.get("poc") or {}
    if isinstance(poc, dict):
        add_ref(poc.get("file"))
    source = finding.get("source_proof") or {}
    if isinstance(source, dict):
        add_ref(source.get("constructed_packet_file"))
    crypto = finding.get("crypto_chain") or {}
    if isinstance(crypto, dict):
        for ref in crypto.get("helper_files") or []:
            add_ref(ref)
    verification = finding.get("verification") or {}
    access_expectation = (verification.get("access_expectation")
                          if isinstance(verification, dict) else {}) or {}
    if isinstance(access_expectation, dict):
        for ref in access_expectation.get("proof_refs") or []:
            add_ref(ref)

    role_values = finding_roles
    normalized_roles = _dedupe([
        str(row.get("actor_role") or "") for row in exact_cells
    ]) or _dedupe([str(x) for x in role_values]) or ["unknown"]
    normalized_assets = _dedupe([
        str(row.get("asset_id") or "") for row in exact_cells
    ]) or finding_assets

    claim = finding.get("claim") if isinstance(finding.get("claim"), dict) else {}
    root_cause = str(
        finding.get("root_cause")
        or finding.get("root_cause_invariant")
        or claim.get("invariant")
        or finding.get("vuln_type")
        or ""
    ).strip()
    chain = (finding.get("chain_assessment")
             if isinstance(finding.get("chain_assessment"), dict) else {})
    proven_impacts = [
        item for item in (finding.get("impact_claims") or [])
        if isinstance(item, dict) and item.get("status") == "proven"
    ]

    return {
        "id": finding.get("id") or finding_file.parent.name,
        "title": finding.get("title", ""),
        "severity": finding.get("severity", ""),
        "class": finding.get("vuln_type", ""),
        "vuln_class": finding.get("vuln_type", ""),
        "target": finding.get("target", ""),
        "endpoint": endpoints[0] if endpoints else "",
        "endpoints": endpoints,
        "method": methods[0] if methods else "",
        "methods": methods,
        "params": _dedupe(
            params + [str(row.get("param") or "") for row in exact_cells]),
        "roles": normalized_roles,
        "actor_roles": [str(x).lower() for x in normalized_roles],
        "assets": normalized_assets,
        "asset_id": normalized_assets[0] if normalized_assets else "",
        "namespace": _unique_dimension(exact_cells, "namespace"),
        "param_location": _unique_dimension(exact_cells, "param_location"),
        "subject_role": _unique_dimension(exact_cells, "subject_role"),
        "object_kind": _unique_dimension(exact_cells, "object_kind"),
        "exact_cells": exact_cells,
        "evidence_file": _rel_to_run(finding_file, run_base),
        "proof_files": _dedupe(proof_files),
        "root_cause": root_cause,
        "affected_role": normalized_roles[0],
        "primary_impact": (finding.get("risk") or {}).get("proven_impact", ""),
        "acceptance_status": "accepted",
        "proof_status": "confirmed",
        "claim_kind": claim.get("kind", ""),
        "claim_profile": claim.get("profile", ""),
        "claim_invariant": claim.get("invariant", ""),
        "source_candidate_id": claim.get("source_candidate_id", ""),
        "authorization_context": access_expectation,
        "proven_impact_claims": proven_impacts,
        "chain_status": chain.get("status", "not_tested"),
        "chain_hypothesis": (
            chain if chain.get("status") in {"hypothesis", "partial"} else None
        ),
        "raw_finding_path": _rel_to_run(finding_file, run_base),
    }
