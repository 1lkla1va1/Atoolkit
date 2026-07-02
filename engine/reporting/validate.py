from __future__ import annotations

import pathlib
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from .schema import normalize_finding, resolve_finding_file

SEVERITIES = {"P1", "P2", "P3"}
SPECULATION = ("可能", "疑似", "理论上", "猜测", "推测", "也许", "或许", "might", "maybe", "probably")
HTTP_START = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP/", re.I | re.M)


@dataclass
class ValidationResult:
    ok: bool
    id: str = ""
    path: str = ""
    reasons: list[str] = field(default_factory=list)
    finding: dict[str, Any] | None = None
    normalized: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        out = {"id": self.id, "path": self.path}
        if self.reasons:
            out["reasons"] = self.reasons
        return out


def _target_allowed(target: str, authorized_hosts: list[str] | None) -> bool:
    if not authorized_hosts:
        return True
    host = urlparse(target).hostname or target
    return any(h == host or host.endswith("." + h) or h in target for h in authorized_hosts)


def _has_proven_language(text: str) -> bool:
    low = str(text or "").lower()
    return bool(low.strip()) and not any(k.lower() in low for k in SPECULATION)


def _exists(finding_dir: pathlib.Path, ref: str | None, run_dir: pathlib.Path, reasons: list[str], label: str) -> pathlib.Path | None:
    if not ref:
        reasons.append(f"missing {label}")
        return None
    try:
        path = resolve_finding_file(finding_dir, ref, run_dir)
    except ValueError as exc:
        reasons.append(f"{label}: {exc}")
        return None
    if not path.exists() or not path.is_file():
        reasons.append(f"missing {label}: {ref}")
        return None
    return path


def _is_parseable_poc(path: pathlib.Path) -> bool:
    text = path.read_text(encoding="utf-8", errors="ignore")
    return "curl " in text or HTTP_START.search(text) is not None


def validate_finding(
    finding: dict[str, Any],
    finding_path: str | pathlib.Path,
    run_dir: str | pathlib.Path,
    authorized_hosts: list[str] | None = None,
) -> ValidationResult:
    finding_file = pathlib.Path(finding_path).resolve()
    finding_dir = finding_file.parent
    run_base = pathlib.Path(run_dir).resolve()
    reasons: list[str] = []
    fid = str(finding.get("id") or finding_dir.name)

    if finding.get("schema_version") != 1:
        reasons.append("schema_version must be 1")
    if str(finding.get("severity", "")).upper() not in SEVERITIES:
        reasons.append("severity must be P1/P2/P3")
    for key in ("title", "vuln_type", "target"):
        if not str(finding.get(key) or "").strip():
            reasons.append(f"missing {key}")
    if finding.get("target") and not _target_allowed(str(finding.get("target")), authorized_hosts):
        reasons.append(f"target out of authorized hosts: {finding.get('target')}")

    risk = finding.get("risk") if isinstance(finding.get("risk"), dict) else {}
    if not _has_proven_language(risk.get("proven_impact", "")):
        reasons.append("risk.proven_impact missing or speculative")
    recommendation = finding.get("recommendation") if isinstance(finding.get("recommendation"), dict) else {}
    if not recommendation.get("summary") and not recommendation.get("details"):
        reasons.append("missing recommendation.summary or recommendation.details")

    feature_point = finding.get("feature_point")
    source_proof = finding.get("source_proof")
    if not feature_point and not source_proof:
        reasons.append("feature_point or source_proof required")

    apis = finding.get("apis")
    if not isinstance(apis, list) or not apis:
        reasons.append("missing apis")
        apis = []
    risk_params: set[str] = set()
    for i, api in enumerate(apis):
        if not isinstance(api, dict):
            reasons.append(f"apis[{i}] must be object")
            continue
        for key in ("method", "path", "purpose"):
            if not str(api.get(key) or "").strip():
                reasons.append(f"missing apis[{i}].{key}")
        params = api.get("risk_params")
        if not isinstance(params, list) or not params:
            reasons.append(f"missing apis[{i}].risk_params")
        else:
            risk_params.update(str(x) for x in params)

    packets = finding.get("proof_packets")
    if not isinstance(packets, list) or not packets:
        reasons.append("missing proof_packets")
        packets = []
    packet_files: set[str] = set()
    for i, packet in enumerate(packets):
        if not isinstance(packet, dict):
            reasons.append(f"proof_packets[{i}] must be object")
            continue
        req = _exists(finding_dir, packet.get("request_file"), run_base, reasons, f"proof_packets[{i}].request_file")
        resp = _exists(finding_dir, packet.get("response_file"), run_base, reasons, f"proof_packets[{i}].response_file")
        if req:
            packet_files.add(req.name)
        if resp:
            packet_files.add(resp.name)
        if not str(packet.get("evidence_summary") or "").strip():
            reasons.append(f"missing proof_packets[{i}].evidence_summary")

    steps = finding.get("manual_burp_replay")
    if not isinstance(steps, list) or len([x for x in steps if str(x).strip()]) < 2:
        reasons.append("manual_burp_replay must contain at least 2 steps")

    poc = finding.get("poc") if isinstance(finding.get("poc"), dict) else {}
    poc_path = _exists(finding_dir, poc.get("file"), run_base, reasons, "poc.file")
    if poc_path and not _is_parseable_poc(poc_path):
        reasons.append("poc.file must contain curl or raw HTTP request")

    if isinstance(source_proof, dict) and source_proof:
        if not source_proof.get("file"):
            reasons.append("missing source_proof.file")
        if not source_proof.get("line") and not source_proof.get("function"):
            reasons.append("source_proof.line or source_proof.function required")
        constructed = _exists(finding_dir, source_proof.get("constructed_packet_file"), run_base, reasons, "source_proof.constructed_packet_file")
        if constructed:
            packet_files.add(constructed.name)
        risk_param = str(source_proof.get("risk_param") or "")
        if risk_param and risk_param not in risk_params:
            explained = any(risk_param in str(packet.get("evidence_summary", "")) for packet in packets if isinstance(packet, dict))
            if not explained:
                reasons.append("source_proof.risk_param not explained by apis or proof packets")

    crypto = finding.get("crypto_chain")
    if isinstance(crypto, dict) and crypto:
        for key in ("algorithm", "key_source", "iv_source"):
            if not crypto.get(key):
                reasons.append(f"missing crypto_chain.{key}")
        discovered = crypto.get("discovered_at") if isinstance(crypto.get("discovered_at"), dict) else {}
        if not discovered.get("file"):
            reasons.append("missing crypto_chain.discovered_at.file")
        helpers = crypto.get("helper_files")
        if not isinstance(helpers, list) or not helpers:
            reasons.append("missing crypto_chain.helper_files")
        else:
            for i, ref in enumerate(helpers):
                _exists(finding_dir, ref, run_base, reasons, f"crypto_chain.helper_files[{i}]")

    normalized = None if reasons else normalize_finding(finding, finding_file, run_base)
    return ValidationResult(
        ok=not reasons,
        id=fid,
        path=str(finding_file),
        reasons=reasons,
        finding=finding if not reasons else None,
        normalized=normalized,
    )


def validate_findings(
    items: list[dict[str, Any]],
    run_dir: str | pathlib.Path,
    authorized_hosts: list[str] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    accepted, rejected = [], []
    for item in items:
        finding = item.get("finding", item)
        path = item.get("path") or finding.get("_finding_path") or ""
        res = validate_finding(finding, path, run_dir, authorized_hosts=authorized_hosts)
        (accepted if res.ok else rejected).append(res.to_dict())
    return {"accepted": accepted, "rejected": rejected}
