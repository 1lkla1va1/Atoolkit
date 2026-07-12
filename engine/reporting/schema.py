from __future__ import annotations

import json
import pathlib
from typing import Any


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


def normalize_finding(
    finding: dict[str, Any],
    finding_path: str | pathlib.Path,
    run_dir: str | pathlib.Path,
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

    role_values = finding.get("affected_roles") or finding.get("roles") or ["unknown"]
    if isinstance(role_values, str):
        role_values = [role_values]

    claim = finding.get("claim") if isinstance(finding.get("claim"), dict) else {}
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
        "params": _dedupe(params),
        "roles": _dedupe([str(x) for x in role_values]) or ["unknown"],
        "evidence_file": _rel_to_run(finding_file, run_base),
        "proof_files": _dedupe(proof_files),
        "root_cause": finding.get("vuln_type", ""),
        "affected_role": (_dedupe([str(x) for x in role_values]) or ["unknown"])[0],
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
