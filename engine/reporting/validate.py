from __future__ import annotations

import hashlib
import json
import pathlib
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    from ..host_policy import is_authorized_url, normalize_authorized_scopes
except ImportError:  # pragma: no cover - direct package fallback
    from host_policy import is_authorized_url, normalize_authorized_scopes

from .schema import normalize_finding, resolve_finding_file

SEVERITIES = {"P1", "P2", "P3"}
SPECULATION = ("可能", "疑似", "理论上", "猜测", "推测", "也许", "或许", "might", "maybe", "probably")
HTTP_START = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP/", re.I | re.M)
CHAIN_STATUSES = {"not_tested", "hypothesis", "partial", "proven", "refuted"}
VERIFICATION_TYPES = {
    "authorization_differential",
    "browser_execution",
    "concurrency_state_change",
    "server_side_fetch",
    "file_write_and_retrieval",
    "file_read_differential",
    "business_state_delta",
    "response_differential",
}
CHAIN_ONLY_TYPE = re.compile(r"(?:^|[-_\s])(attack[-_\s]?chain|chain|利用链|影响升级)(?:$|[-_\s])", re.I)
HIGH_IMPACT_CLAIM = re.compile(
    r"(?:\bRCE\b|remote\s+code\s+execution|任意代码执行|服务器接管|主机接管|"
    r"账户接管|管理员接管|\bATO\b|窃取.{0,8}(?:Cookie|Session)|"
    r"大量数据|全量数据|任意目录|任意文件|无限(?:资金|余额|积分))",
    re.I,
)
ABSOLUTE_IMPACT_CLAIM = re.compile(r"(?:无限(?:资金|余额|积分)|任意目录|任意文件|全量数据)", re.I)
AUTH_EXPECTED_ACCESS = {"owner_only", "authenticated_only", "role_restricted", "private"}
AUTH_EXPECTATION_BASES = {
    "same_endpoint_denial",
    "owner_created_private_object",
    "documented_restriction",
    "authenticated_private_view",
}
HTTP_STATUS = re.compile(r"^HTTP/\S+\s+(\d{3})\b", re.I | re.M)
RCE_IMPACT = re.compile(
    r"(?:\bRCE\b|remote\s+code\s+execution|任意代码执行|服务器接管|主机接管)", re.I)
ATO_IMPACT = re.compile(r"(?:账户接管|管理员接管|\bATO\b)", re.I)
SESSION_THEFT_IMPACT = re.compile(r"窃取.{0,8}(?:Cookie|Session)", re.I)
BULK_DATA_IMPACT = re.compile(r"(?:大量数据|全量数据)", re.I)


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


@dataclass(frozen=True)
class ValidationContext:
    """Bind relative finding targets to one attested primary target."""

    primary_target: str = ""
    authorized_scopes: tuple[str, ...] = ()
    manifest: dict[str, Any] | None = None
    manifest_path: pathlib.Path | None = None

    @classmethod
    def from_manifest(
        cls, manifest: dict[str, Any], *, manifest_path: str | pathlib.Path | None = None,
    ) -> "ValidationContext":
        primary = str(manifest.get("primary_target") or "").strip()
        scopes = tuple(normalize_authorized_scopes(list(manifest.get("authorized_scopes") or [])))
        return cls(
            primary_target=primary,
            authorized_scopes=scopes,
            manifest=manifest,
            manifest_path=pathlib.Path(manifest_path).resolve() if manifest_path else None,
        )

    def target_url(self, target: str) -> str:
        text = str(target or "").strip()
        parts = text.split(None, 1)
        if len(parts) == 2 and parts[0].upper() in {
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
        }:
            text = parts[1]
        if urlparse(text).scheme in {"http", "https"}:
            return text
        if not self.primary_target:
            return ""
        return urljoin(self.primary_target.rstrip("/") + "/", text.lstrip("/"))

    def allows(self, target: str) -> bool:
        url = self.target_url(target)
        return bool(url and self.authorized_scopes and is_authorized_url(url, list(self.authorized_scopes)))


def _target_allowed(
    target: str, authorized_hosts: list[str] | None,
    context: ValidationContext | None = None,
) -> bool:
    if context is not None:
        return context.allows(target)
    if not authorized_hosts:
        return True
    text = str(target or "").strip()
    parts = text.split(None, 1)
    if len(parts) == 2 and parts[0].upper() in {
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
    }:
        text = parts[1]
    return is_authorized_url(text, authorized_hosts)


def _request_target_allowed(path: pathlib.Path, context: ValidationContext) -> bool:
    text = path.read_text(encoding="utf-8", errors="ignore")
    first = re.search(
        r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/", text, re.I | re.M)
    if not first:
        # A response-only or non-HTTP helper is validated by its containing
        # proof packet and file contract, not treated as an outbound request.
        return True
    raw_target = first.group(2)
    if urlparse(raw_target).scheme in {"http", "https"}:
        return context.allows(raw_target)
    host_match = re.search(r"^Host:\s*([^\s]+)\s*$", text, re.I | re.M)
    if not host_match:
        return False
    primary = urlparse(context.primary_target)
    scheme = primary.scheme or "https"
    return context.allows(f"{scheme}://{host_match.group(1)}{raw_target}")


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


def _vuln_family(vuln_type: str) -> str:
    """Map report vocabulary to an evidence family, never to an exploit recipe."""
    low = str(vuln_type or "").lower()
    if any(k in low for k in ("idor", "越权", "未授权", "unauth", "authorization", "access-control",
                              "access control", "privilege-escalation", "bac", "认证绕过",
                              "auth-bypass", "auth bypass", "authentication bypass")):
        return "authorization"
    if "xss" in low or "跨站" in low:
        return "xss"
    if any(k in low for k in ("race", "竞态", "concurrency")):
        return "race"
    if "ssrf" in low or "服务端请求伪造" in low:
        return "ssrf"
    if any(k in low for k in ("file-upload", "file upload", "upload", "文件上传")):
        return "file_write"
    if any(k in low for k in ("path-traversal", "path traversal", "路径穿越",
                              "file-read", "file read", "文件读取")):
        return "file_read"
    if any(k in low for k in ("amount", "tamper", "refund", "recharge", "payment",
                              "lottery", "points", "business", "交易", "金额", "退款",
                              "充值", "抽奖", "积分", "支付")):
        return "business"
    return "generic"


def _phase_set(packets: list[dict[str, Any]]) -> set[str]:
    return {
        str(packet.get("phase") or "").strip().lower()
        for packet in packets if isinstance(packet, dict) and packet.get("phase")
    }


def _has_any(phases: set[str], values: set[str]) -> bool:
    return bool(phases & values)


def _read_text(path: pathlib.Path | None) -> str:
    if path is None:
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def _packet_map(
    packets: list[dict[str, Any]], finding_dir: pathlib.Path, run_base: pathlib.Path,
) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for packet in packets:
        if not isinstance(packet, dict):
            continue
        phase = str(packet.get("phase") or "").strip().lower()
        if not phase:
            continue
        try:
            req = resolve_finding_file(finding_dir, packet.get("request_file"), run_base)
            resp = resolve_finding_file(finding_dir, packet.get("response_file"), run_base)
        except (TypeError, ValueError):
            continue
        if not req.is_file() or not resp.is_file():
            continue
        out[phase] = {"packet": packet, "request": req, "response": resp}
    return out


def _auth_fingerprint(request_text: str) -> str:
    values = re.findall(r"^(?:Cookie|Authorization):\s*(.+)$", request_text, re.I | re.M)
    return "\n".join(values).strip()


def _normalized_request_path(request_text: str) -> str:
    match = re.search(
        r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)",
        request_text, re.I | re.M)
    if not match:
        return ""
    target = re.sub(r"^https?://[^/]+", "", match.group(1), flags=re.I)
    path = target.split("?", 1)[0].split("#", 1)[0]
    parts = []
    for part in path.split("/"):
        if (part.isdigit()
                or (part.startswith("{") and part.endswith("}"))
                or re.fullmatch(r"[0-9a-f]{12,}", part, re.I)
                or re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                    r"[0-9a-f]{4}-[0-9a-f]{12}", part, re.I)):
            parts.append("{}")
        else:
            parts.append(part)
    return "/".join(parts)


def _required_high_impact_type(statement: str) -> str:
    if RCE_IMPACT.search(statement):
        return "command_execution"
    if ATO_IMPACT.search(statement):
        return "session_takeover"
    if SESSION_THEFT_IMPACT.search(statement):
        return "session_compromise"
    if BULK_DATA_IMPACT.search(statement):
        return "bulk_data_exposure"
    return ""


def _authorization_mode(vuln_type: str) -> str:
    low = str(vuln_type or "").lower()
    if any(k in low for k in (
        "未授权", "unauth", "认证绕过", "auth-bypass", "auth bypass",
        "authentication bypass",
    )):
        return "anonymous"
    return "object"


def _packet_name_map(
    packets: list[dict[str, Any]], finding_dir: pathlib.Path, run_base: pathlib.Path,
) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for packet in packets:
        if not isinstance(packet, dict):
            continue
        name = str(packet.get("name") or "").strip()
        if not name:
            continue
        try:
            req = resolve_finding_file(finding_dir, packet.get("request_file"), run_base)
            resp = resolve_finding_file(finding_dir, packet.get("response_file"), run_base)
        except (TypeError, ValueError):
            continue
        if req.is_file() and resp.is_file():
            out[name] = {"packet": packet, "request": req, "response": resp}
    return out


def _validate_access_expectation(
    finding: dict[str, Any], verification: dict[str, Any],
    packets: list[dict[str, Any]], finding_dir: pathlib.Path,
    run_base: pathlib.Path, reasons: list[str], mode: str,
) -> None:
    """Require physical evidence that the exposed resource was not public by design."""
    context = verification.get("access_expectation")
    if not isinstance(context, dict):
        reasons.append(
            "authorization finding requires verification.access_expectation; "
            "anonymous/public reachability alone is not a vulnerability")
        return

    expected = str(context.get("expected_access") or "").strip().lower()
    if expected not in AUTH_EXPECTED_ACCESS:
        reasons.append(
            "access_expectation.expected_access must be owner_only/"
            "authenticated_only/role_restricted/private (never public)")
    basis = str(context.get("basis") or "").strip().lower()
    if basis not in AUTH_EXPECTATION_BASES:
        reasons.append(
            "access_expectation.basis must be same_endpoint_denial/"
            "owner_created_private_object/documented_restriction/"
            "authenticated_private_view")

    marker = str(context.get("marker") or "").strip()
    if len(marker) < 4:
        reasons.append("access_expectation.marker must contain at least 4 characters")

    packet_ids = context.get("proof_packet_ids") or []
    if not isinstance(packet_ids, list):
        reasons.append("access_expectation.proof_packet_ids must be a list")
        packet_ids = []
    packet_map = _packet_name_map(packets, finding_dir, run_base)
    selected: list[dict[str, Any]] = []
    for packet_id in packet_ids:
        item = packet_map.get(str(packet_id))
        if item is None:
            reasons.append(
                f"access_expectation references unknown proof packet: {packet_id}")
        else:
            selected.append(item)

    proof_refs = context.get("proof_refs") or []
    if not isinstance(proof_refs, list):
        reasons.append("access_expectation.proof_refs must be a list")
        proof_refs = []
    proof_paths: list[pathlib.Path] = []
    for i, ref in enumerate(proof_refs):
        path = _exists(finding_dir, ref, run_base, reasons,
                       f"access_expectation.proof_refs[{i}]")
        if path:
            proof_paths.append(path)

    evidence_texts = [_read_text(item["response"]) for item in selected]
    evidence_texts.extend(_read_text(path) for path in proof_paths)
    if marker and evidence_texts and not any(marker in text for text in evidence_texts):
        reasons.append("access_expectation.marker not found in its proof evidence")
    if not selected and not proof_paths:
        reasons.append("access_expectation requires physical proof_packet_ids or proof_refs")

    if basis == "same_endpoint_denial":
        statuses = []
        denied_paths = []
        for item in selected:
            match = HTTP_STATUS.search(_read_text(item["response"]))
            if match:
                statuses.append(int(match.group(1)))
            denied_paths.append(
                _normalized_request_path(_read_text(item["request"])))
        if not any(status in {401, 403} for status in statuses):
            reasons.append("same_endpoint_denial basis requires a raw HTTP 401/403 response")
        api_paths = {
            _normalized_request_path(
                f"GET {str(api.get('path') or '')} HTTP/1.1")
            for api in (finding.get("apis") or []) if isinstance(api, dict)
        }
        if not any(path and path in api_paths for path in denied_paths):
            reasons.append(
                "same_endpoint_denial proof must target the same normalized API path")
    elif basis == "owner_created_private_object":
        mutating = False
        for item in selected:
            request = _read_text(item["request"])
            if re.search(r"^(POST|PUT|PATCH)\s+\S+\s+HTTP/", request, re.I | re.M):
                mutating = True
                break
        privacy_marker = str(context.get("privacy_marker") or "").strip()
        if not mutating:
            reasons.append(
                "owner_created_private_object basis requires a POST/PUT/PATCH creation packet")
        if len(privacy_marker) < 4 or not any(
                privacy_marker in text for text in evidence_texts):
            reasons.append(
                "owner_created_private_object requires a privacy_marker present in creation evidence")
    elif basis == "documented_restriction" and not proof_paths:
        reasons.append("documented_restriction basis requires captured proof_refs")

    # Anonymous access needs a separate public-discovery baseline.  This does
    # not by itself prove privacy; it prevents a public page/API listing from
    # being relabeled as an authentication bypass without being checked.
    if mode == "anonymous":
        public_check = context.get("public_exposure_check")
        if not isinstance(public_check, dict):
            reasons.append(
                "unauthorized-access finding requires access_expectation.public_exposure_check")
            return
        if str(public_check.get("classification") or "").lower() != "not_public":
            reasons.append("public_exposure_check.classification must be not_public")
        resource_marker = str(public_check.get("resource_marker") or "").strip()
        if len(resource_marker) < 4:
            reasons.append("public_exposure_check.resource_marker must contain at least 4 characters")
        public_ids = public_check.get("proof_packet_ids") or []
        if not isinstance(public_ids, list) or not public_ids:
            reasons.append("public_exposure_check.proof_packet_ids required")
            public_ids = []
        public_responses: list[str] = []
        for packet_id in public_ids:
            item = packet_map.get(str(packet_id))
            if item is None:
                reasons.append(
                    f"public_exposure_check references unknown proof packet: {packet_id}")
                continue
            phase = str(item["packet"].get("phase") or "").strip().lower()
            if phase != "public_baseline":
                reasons.append(
                    "public_exposure_check packets must use phase=public_baseline")
            public_responses.append(_read_text(item["response"]))
        if resource_marker and any(resource_marker in text for text in public_responses):
            reasons.append(
                "resource appears in the captured public baseline; do not report it as unauthorized")


def _validate_assertions(
    assertions: Any, finding_dir: pathlib.Path, run_base: pathlib.Path,
    reasons: list[str], label: str,
) -> None:
    if not isinstance(assertions, list) or not assertions:
        reasons.append(f"missing {label}")
        return
    for i, assertion in enumerate(assertions):
        if not isinstance(assertion, dict):
            reasons.append(f"{label}[{i}] must be object")
            continue
        path = _exists(finding_dir, assertion.get("file"), run_base, reasons,
                       f"{label}[{i}].file")
        relation = str(assertion.get("relation") or "contains").strip().lower()
        value = str(assertion.get("value") or "")
        if not value or len(value) < 4:
            reasons.append(f"{label}[{i}].value must contain at least 4 characters")
            continue
        if path is None:
            continue
        text = _read_text(path)
        passed = False
        if relation == "contains":
            passed = value in text
        elif relation == "not_contains":
            passed = value not in text
        elif relation == "regex":
            try:
                passed = re.search(value, text, re.M) is not None
            except re.error:
                reasons.append(f"{label}[{i}] invalid regex")
                continue
        else:
            reasons.append(f"{label}[{i}].relation must be contains/not_contains/regex")
            continue
        if not passed:
            reasons.append(f"{label}[{i}] assertion failed")


def _validate_claims(
    finding: dict[str, Any], packets: list[dict[str, Any]], finding_dir: pathlib.Path,
    run_base: pathlib.Path, reasons: list[str],
) -> None:
    claim = finding.get("claim")
    if not isinstance(claim, dict):
        reasons.append("missing claim")
        return
    if claim.get("kind") != "root_finding":
        reasons.append("claim.kind must be root_finding")
    if not str(claim.get("invariant") or "").strip():
        reasons.append("claim.invariant required")
    packet_ids = {
        str(packet.get("name") or "").strip()
        for packet in packets if isinstance(packet, dict) and packet.get("name")
    }
    proof_ids = claim.get("proof_packet_ids")
    if not isinstance(proof_ids, list) or not proof_ids:
        reasons.append("claim.proof_packet_ids required")
    else:
        missing = [str(pid) for pid in proof_ids if str(pid) not in packet_ids]
        if missing:
            reasons.append("claim.proof_packet_ids reference unknown packets: " + ",".join(missing))

    impact_claims = finding.get("impact_claims")
    if not isinstance(impact_claims, list) or not impact_claims:
        reasons.append("missing impact_claims")
        return
    proven_impact = str((finding.get("risk") or {}).get("proven_impact") or "").strip()
    proven_statements: list[str] = []
    for i, impact in enumerate(impact_claims):
        if not isinstance(impact, dict):
            reasons.append(f"impact_claims[{i}] must be object")
            continue
        status = str(impact.get("status") or "").strip().lower()
        if status not in {"proven", "hypothesis", "refuted"}:
            reasons.append(f"impact_claims[{i}].status invalid")
            continue
        statement = str(impact.get("statement") or "").strip()
        if not statement:
            reasons.append(f"impact_claims[{i}].statement required")
            continue
        refs = impact.get("proof_refs") or []
        if not isinstance(refs, list):
            reasons.append(f"impact_claims[{i}].proof_refs must be a list")
            refs = []
        resolved: list[pathlib.Path] = []
        for j, ref in enumerate(refs):
            path = _exists(finding_dir, ref, run_base, reasons,
                           f"impact_claims[{i}].proof_refs[{j}]")
            if path:
                resolved.append(path)
        if status == "proven":
            proven_statements.append(statement)
            if not refs:
                reasons.append(f"impact_claims[{i}] proven status requires proof_refs")
            marker = str(impact.get("marker") or "").strip()
            if not marker or len(marker) < 4:
                reasons.append(f"impact_claims[{i}] proven status requires marker")
            elif resolved and not any(marker in _read_text(path) for path in resolved):
                reasons.append(f"impact_claims[{i}] marker not found in proof_refs")
            required_type = _required_high_impact_type(statement)
            if required_type:
                impact_type = str(impact.get("impact_type") or "").strip().lower()
                if impact_type != required_type:
                    reasons.append(
                        f"impact_claims[{i}] high-impact statement requires "
                        f"impact_type={required_type}")
                if required_type == "command_execution":
                    nonce = str(impact.get("execution_nonce") or "").strip()
                    if len(nonce) < 8 or not any(
                            nonce in _read_text(path) for path in resolved):
                        reasons.append(
                            f"impact_claims[{i}] command execution requires an "
                            "8+ character execution_nonce in proof_refs")
                elif required_type in {"session_takeover", "session_compromise"}:
                    identity_marker = str(impact.get("identity_marker") or "").strip()
                    if len(identity_marker) < 4 or not any(
                            identity_marker in _read_text(path) for path in resolved):
                        reasons.append(
                            f"impact_claims[{i}] session impact requires an "
                            "identity_marker in proof_refs")
                elif required_type == "bulk_data_exposure":
                    try:
                        observed_count = int(impact.get("observed_count", 0) or 0)
                    except (TypeError, ValueError):
                        observed_count = 0
                    if observed_count < 2:
                        reasons.append(
                            f"impact_claims[{i}] bulk data impact requires a finite "
                            "observed_count >= 2")
    if proven_impact and proven_impact not in proven_statements:
        reasons.append("risk.proven_impact must exactly match a proven impact_claim")
    if ABSOLUTE_IMPACT_CLAIM.search(proven_impact):
        reasons.append("absolute impact wording is not a finite observed result")


def _validate_chain(
    finding: dict[str, Any], finding_dir: pathlib.Path, run_base: pathlib.Path,
    reasons: list[str],
) -> None:
    chain = finding.get("chain_assessment")
    if not isinstance(chain, dict):
        reasons.append("missing chain_assessment")
        return
    status = str(chain.get("status") or "").strip().lower()
    if status not in CHAIN_STATUSES:
        reasons.append("chain_assessment.status must be not_tested/hypothesis/partial/proven/refuted")
        return
    blockers = chain.get("blockers")
    if not isinstance(blockers, list):
        reasons.append("chain_assessment.blockers must be a list")
        blockers = []
    proof_refs = chain.get("proof_refs")
    if proof_refs is None:
        proof_refs = []
    if not isinstance(proof_refs, list):
        reasons.append("chain_assessment.proof_refs must be a list")
        proof_refs = []
    for i, ref in enumerate(proof_refs):
        _exists(finding_dir, ref, run_base, reasons, f"chain_assessment.proof_refs[{i}]")
    if status == "proven":
        if blockers:
            reasons.append("proven chain_assessment cannot have blockers")
        if not proof_refs:
            reasons.append("proven chain_assessment requires proof_refs")
        if not str(chain.get("final_impact") or "").strip():
            reasons.append("proven chain_assessment requires final_impact")
    elif chain.get("chain_feasible") is True:
        reasons.append("chain_feasible=true requires chain_assessment.status=proven")


def _validate_verification(
    finding: dict[str, Any], packets: list[dict[str, Any]], finding_dir: pathlib.Path,
    run_base: pathlib.Path, reasons: list[str],
) -> None:
    verification = finding.get("verification")
    if not isinstance(verification, dict):
        reasons.append("missing verification")
        return
    if str(verification.get("status") or "").strip().lower() != "confirmed":
        reasons.append("verification.status must be confirmed")
    evidence_type = str(verification.get("evidence_type") or "").strip().lower()
    if evidence_type not in VERIFICATION_TYPES:
        reasons.append("verification.evidence_type invalid")
    if not _has_proven_language(verification.get("observed_effect", "")):
        reasons.append("verification.observed_effect missing or speculative")

    evidence_files = verification.get("evidence_files") or []
    if not isinstance(evidence_files, list):
        reasons.append("verification.evidence_files must be a list")
        evidence_files = []
    for i, ref in enumerate(evidence_files):
        _exists(finding_dir, ref, run_base, reasons, f"verification.evidence_files[{i}]")

    impact_refs = verification.get("impact_proof_refs") or []
    if not isinstance(impact_refs, list):
        reasons.append("verification.impact_proof_refs must be a list")
        impact_refs = []
    for i, ref in enumerate(impact_refs):
        _exists(finding_dir, ref, run_base, reasons, f"verification.impact_proof_refs[{i}]")
    proven_impact = str((finding.get("risk") or {}).get("proven_impact") or "")
    if HIGH_IMPACT_CLAIM.search(proven_impact) and not impact_refs:
        reasons.append("high-impact claim requires verification.impact_proof_refs")
    _validate_assertions(verification.get("assertions"), finding_dir, run_base,
                         reasons, "verification.assertions")

    phases = _phase_set(packets)
    family = _vuln_family(str(finding.get("vuln_type") or ""))
    expected_type = {
        "authorization": "authorization_differential",
        "xss": "browser_execution",
        "race": "concurrency_state_change",
        "ssrf": "server_side_fetch",
        "file_write": "file_write_and_retrieval",
        "file_read": "file_read_differential",
        "business": "business_state_delta",
        "generic": "response_differential",
    }[family]
    if evidence_type and evidence_type != expected_type:
        reasons.append(f"{family} finding requires verification.evidence_type={expected_type}")

    if family == "authorization":
        mode = _authorization_mode(str(finding.get("vuln_type") or ""))
        control_phases = ({"authenticated_control", "authorized_control", "owner_control"}
                          if mode == "anonymous"
                          else {"owner_control", "authorized_control", "self_control"})
        attack_phases = ({"anonymous_attempt", "unauthenticated_attempt", "bypass_attempt"}
                         if mode == "anonymous"
                         else {"unauthorized_actor", "attacker_attempt", "cross_role_attempt"})
        if not _has_any(phases, control_phases):
            reasons.append("authorization finding requires an owner/authenticated control packet")
        if not _has_any(phases, attack_phases):
            reasons.append("authorization finding requires an explicit unauthorized actor packet")
        identities = verification.get("identities") or []
        objects = verification.get("objects") or []
        if not isinstance(identities, list) or len({str(x) for x in identities if str(x)}) < 2:
            reasons.append("authorization finding requires at least two identities")
        if not isinstance(objects, list) or not [x for x in objects if str(x)]:
            reasons.append("authorization finding requires object/resource ownership labels")
        packet_map = _packet_map(packets, finding_dir, run_base)
        control = next((packet_map[p] for p in control_phases
                        if p in packet_map), None)
        attack = next((packet_map[p] for p in attack_phases
                       if p in packet_map), None)
        marker = str(verification.get("object_marker") or "").strip()
        if not marker or len(marker) < 4:
            reasons.append("authorization finding requires verification.object_marker")
        elif control and attack:
            if marker not in _read_text(control["response"]) or marker not in _read_text(attack["response"]):
                reasons.append("authorization object_marker must appear in control and attacker responses")
            control_auth = _auth_fingerprint(_read_text(control["request"]))
            attack_auth = _auth_fingerprint(_read_text(attack["request"]))
            if mode == "anonymous":
                attack_phase = str(attack["packet"].get("phase") or "").lower()
                if not control_auth:
                    reasons.append("authenticated control request requires credentials")
                if attack_phase in {"anonymous_attempt", "unauthenticated_attempt"} and attack_auth:
                    reasons.append("anonymous attempt must not carry authentication credentials")
                if attack_phase == "bypass_attempt" and (
                        not attack_auth or attack_auth == control_auth):
                    reasons.append("bypass attempt requires distinct invalid/low-privilege credentials")
            elif not control_auth or not attack_auth or control_auth == attack_auth:
                reasons.append("authorization control and attacker requests require distinct credentials")
        _validate_access_expectation(
            finding, verification, packets, finding_dir, run_base, reasons, mode)
    elif family == "xss":
        if not _has_any(phases, {"injection", "stored_input"}) or not _has_any(
                phases, {"victim_render", "browser_trigger"}):
            reasons.append("xss finding requires injection and victim-render packets")
        _exists(finding_dir, verification.get("browser_evidence_file"), run_base, reasons,
                "verification.browser_evidence_file")
        execution_marker = str(verification.get("execution_marker") or "").strip()
        if not execution_marker:
            reasons.append("xss finding requires verification.execution_marker")
        else:
            browser_path = None
            try:
                browser_path = resolve_finding_file(
                    finding_dir, verification.get("browser_evidence_file"), run_base)
            except (TypeError, ValueError):
                pass
            if browser_path and browser_path.exists() and execution_marker not in _read_text(browser_path):
                reasons.append("xss execution_marker not found in browser evidence")
    elif family == "race":
        required = {"state_before", "concurrent_attempt", "state_after"}
        if not required.issubset(phases):
            reasons.append("race finding requires state_before/concurrent_attempt/state_after packets")
        concurrency = verification.get("concurrency")
        successes = 0
        if not isinstance(concurrency, dict):
            reasons.append("race finding requires verification.concurrency")
        else:
            try:
                attempts = int(concurrency.get("attempts", 0) or 0)
                successes = int(concurrency.get("successes", 0) or 0)
            except (TypeError, ValueError):
                attempts = successes = 0
            if attempts < 2 or successes < 2 or successes > attempts:
                reasons.append("race concurrency requires attempts>=2 and 2<=successes<=attempts")
        raw_path = _exists(
            finding_dir, verification.get("raw_concurrency_file"), run_base,
            reasons, "verification.raw_concurrency_file")
        success_marker = str(verification.get("success_marker") or "").strip()
        if len(success_marker) < 4:
            reasons.append("race finding requires verification.success_marker")
        elif raw_path and _read_text(raw_path).count(success_marker) < successes:
            reasons.append(
                "race success count cannot be reproduced from raw_concurrency_file")
    elif family == "ssrf":
        if not _has_any(phases, {"destination_control", "external_control"}) or not _has_any(
                phases, {"server_fetch", "bypass_fetch"}):
            reasons.append("ssrf finding requires destination control and server-fetch packets")
        callback = verification.get("callback_evidence_file")
        marker = str(verification.get("destination_marker") or "").strip()
        if callback:
            _exists(finding_dir, callback, run_base, reasons,
                    "verification.callback_evidence_file")
        elif not marker:
            reasons.append("ssrf finding requires callback evidence or a destination-unique marker")
    elif family == "file_write":
        if not _has_any(phases, {"upload", "write_attempt"}) or not _has_any(
                phases, {"read_back", "location_proof"}):
            reasons.append("file finding requires write and read-back/location-proof packets")
        _exists(finding_dir, verification.get("retrieval_evidence_file"), run_base, reasons,
                "verification.retrieval_evidence_file")
        if not str(verification.get("content_sha256") or "").strip():
            reasons.append("file finding requires verification.content_sha256")
    elif family == "file_read":
        if not _has_any(phases, {"baseline", "blocked_control"}) or not _has_any(
                phases, {"file_read", "traversal_read"}):
            reasons.append("file-read finding requires baseline and file-read packets")
        marker = str(verification.get("file_marker") or "").strip()
        if not marker or len(marker) < 4:
            reasons.append("file-read finding requires verification.file_marker")
        else:
            packet_map = _packet_map(packets, finding_dir, run_base)
            read_phase = next((packet_map[p] for p in ("file_read", "traversal_read")
                               if p in packet_map), None)
            if read_phase and marker not in _read_text(read_phase["response"]):
                reasons.append("file_marker not found in file-read response")
    elif family == "business":
        if not {"state_before", "exploit", "state_after"}.issubset(phases):
            reasons.append("business finding requires state_before/exploit/state_after packets")
        if not str(verification.get("state_delta") or "").strip():
            reasons.append("business finding requires verification.state_delta")
    else:
        if not _has_any(phases, {"control", "baseline"}) or not _has_any(
                phases, {"exploit", "test"}):
            reasons.append("generic finding requires control and exploit packets")


def validate_finding(
    finding: dict[str, Any],
    finding_path: str | pathlib.Path,
    run_dir: str | pathlib.Path,
    authorized_hosts: list[str] | None = None,
    *,
    context: ValidationContext | None = None,
) -> ValidationResult:
    finding_file = pathlib.Path(finding_path).resolve()
    finding_dir = finding_file.parent
    run_base = pathlib.Path(run_dir).resolve()
    reasons: list[str] = []
    fid = str(finding.get("id") or finding_dir.name)

    if str(finding.get("schema_version") or "") not in {"1", "1.0"}:
        reasons.append("schema_version must be 1 or 1.0")
    if str(finding.get("severity", "")).upper() not in SEVERITIES:
        reasons.append("severity must be P1/P2/P3")
    for key in ("title", "vuln_type", "target"):
        if not str(finding.get(key) or "").strip():
            reasons.append(f"missing {key}")
    if CHAIN_ONLY_TYPE.search(str(finding.get("vuln_type") or "")):
        reasons.append("chain/impact escalation is not an independent vulnerability type")
    if finding.get("target") and not _target_allowed(
            str(finding.get("target")), authorized_hosts, context):
        if context is not None and not context.primary_target:
            reasons.append("relative target requires manifest primary_target")
        else:
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
            if context is not None and not _request_target_allowed(req, context):
                reasons.append(
                    f"proof request target out of authorized scopes: {packet.get('request_file')}")
        if resp:
            packet_files.add(resp.name)
        if not str(packet.get("evidence_summary") or "").strip():
            reasons.append(f"missing proof_packets[{i}].evidence_summary")
        if not str(packet.get("phase") or "").strip():
            reasons.append(f"missing proof_packets[{i}].phase")

    _validate_verification(finding, packets, finding_dir, run_base, reasons)
    _validate_chain(finding, finding_dir, run_base, reasons)
    _validate_claims(finding, packets, finding_dir, run_base, reasons)

    poc = finding.get("poc") if isinstance(finding.get("poc"), dict) else {}
    steps = finding.get("manual_burp_replay")
    if not isinstance(steps, list) or len([x for x in steps if str(x).strip()]) < 2:
        steps = poc.get("steps")
    if not isinstance(steps, list) or len([x for x in steps if str(x).strip()]) < 2:
        reasons.append("manual_burp_replay or poc.steps must contain at least 2 steps")

    poc_path = _exists(finding_dir, poc.get("file"), run_base, reasons, "poc.file")
    if poc_path and not _is_parseable_poc(poc_path):
        reasons.append("poc.file must contain curl or raw HTTP request")

    if isinstance(source_proof, dict) and source_proof:
        _exists(finding_dir, source_proof.get("file"), run_base, reasons,
                "source_proof.file")
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
    *,
    context: ValidationContext | None = None,
) -> dict[str, list[dict[str, Any]]]:
    accepted, rejected = [], []
    for item in items:
        finding = item.get("finding", item)
        path = item.get("path") or finding.get("_finding_path") or ""
        res = validate_finding(
            finding, path, run_dir, authorized_hosts=authorized_hosts, context=context)
        (accepted if res.ok else rejected).append(res.to_dict())
    return {"accepted": accepted, "rejected": rejected}


def _sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_digest(value: dict[str, Any]) -> str:
    copy = dict(value)
    copy.pop("validation_sha256", None)
    payload = json.dumps(
        copy, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _empty_run_gate(
    run_dir: pathlib.Path, context: ValidationContext | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    http_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    terminal_statuses = {"confirmed", "not_vulnerable", "not_applicable"}
    project_dir = (run_dir.parent.parent
                   if run_dir.parent.name == "sessions" else run_dir)
    expected_project_state = (project_dir / "project_state.json").resolve(strict=False)
    endpoints: list[Any] = []
    try:
        inventory = json.loads((run_dir / "inventory.json").read_text(encoding="utf-8"))
        endpoints = inventory.get("endpoints") if isinstance(inventory, dict) else inventory
        if not isinstance(endpoints, list) or not endpoints:
            reasons.append("inventory_empty")
        if isinstance(inventory, dict):
            unresolved = inventory.get("unresolved") or []
            if not isinstance(unresolved, list):
                reasons.append("inventory_unresolved_invalid")
            elif unresolved:
                reasons.append("inventory_unresolved_open")
    except (OSError, json.JSONDecodeError):
        reasons.append("inventory_missing_or_invalid")
    ledger_path = run_dir / "coverage-ledger.json"
    surfaces: list[Any] = []
    if not ledger_path.is_file():
        reasons.append("coverage_missing_or_invalid")
    else:
        try:
            ledger_value = json.loads(ledger_path.read_text(encoding="utf-8"))
            surfaces = (ledger_value.get("surfaces")
                        if isinstance(ledger_value, dict) else []) or []
            if not isinstance(surfaces, list) or not surfaces:
                surfaces = []
                reasons.append("coverage_empty")
            else:
                for surface in surfaces:
                    if not isinstance(surface, dict):
                        reasons.append("coverage_surface_invalid")
                        continue
                    method = str(surface.get("method") or "").upper()
                    status = str(surface.get("status") or "").strip().lower()
                    if method not in http_methods:
                        reasons.append("coverage_method_invalid")
                    if status not in terminal_statuses:
                        reasons.append("coverage_not_closed")
                    if status == "confirmed":
                        historical_ok = False
                        evidence_ref = str(surface.get("evidence_ref") or "").strip()
                        evidence_path = pathlib.Path(evidence_ref) if evidence_ref else None
                        if (evidence_path is not None and evidence_path.is_absolute()
                                and evidence_path.name == "project_state.json"
                                and evidence_path.resolve(strict=False) == expected_project_state
                                and evidence_path.is_file()
                                and context is not None):
                            try:
                                try:
                                    from ..project_state import (
                                        canonical_asset,
                                        canonical_project_cell_key,
                                        verify_project_evidence,
                                    )
                                except ImportError:  # pragma: no cover
                                    from project_state import (
                                        canonical_asset,
                                        canonical_project_cell_key,
                                        verify_project_evidence,
                                    )
                                project = json.loads(evidence_path.read_text(encoding="utf-8"))
                                asset = next(iter(project.get("project_scope") or []), "")
                                manifest_asset = canonical_asset(context.primary_target)
                                manifest_project = str(
                                    (context.manifest or {}).get("project") or "").strip()
                                identity_ok = (
                                    bool(asset and manifest_asset)
                                    and canonical_asset(asset) == manifest_asset
                                    and (
                                        run_dir.parent.name != "sessions"
                                        or manifest_project == project_dir.name
                                    )
                                )
                                roles = surface.get("roles") or ["unknown"]
                                vuln_class = str(surface.get("vuln_class")
                                                 or surface.get("legacy_vuln") or "")
                                historical_ok = bool(identity_ok and vuln_class and roles)
                                for role in roles:
                                    key = canonical_project_cell_key(
                                        asset,
                                        method=str(surface.get("method") or ""),
                                        path=str(surface.get("endpoint") or ""),
                                        param=str(surface.get("param") or ""),
                                        role_scope=str(role),
                                        vuln_class=vuln_class,
                                    )
                                    prior = (project.get("cell_registry") or {}).get(key) or {}
                                    if (prior.get("status") != "confirmed"
                                            or not verify_project_evidence(
                                                evidence_path.parent,
                                                list(prior.get("evidence_refs") or []),
                                                dict(prior.get("evidence_hashes") or {}))):
                                        historical_ok = False
                                        break
                            except (OSError, ValueError, json.JSONDecodeError):
                                historical_ok = False
                        if not historical_ok:
                            reasons.append("confirmed_coverage_without_canonical_finding")
                    if (status == "not_applicable"
                            and not str(surface.get("reason") or "").strip()):
                        reasons.append("not_applicable_reason_missing")
                    if status == "not_vulnerable":
                        negative = surface.get("negative")
                        evidence_ref = str(surface.get("evidence_ref") or "").strip()
                        if not isinstance(negative, dict) or not evidence_ref:
                            reasons.append("negative_evidence_missing")
                        else:
                            evidence_path = pathlib.Path(evidence_ref)
                            if not evidence_path.is_absolute():
                                evidence_path = run_dir / evidence_path
                            resolved = evidence_path.resolve(strict=False)
                            project_dir = (run_dir.parent.parent
                                           if run_dir.parent.name == "sessions"
                                           else run_dir)
                            try:
                                resolved.relative_to(project_dir.resolve())
                            except ValueError:
                                reasons.append("negative_evidence_escape")
                            else:
                                if not resolved.is_file():
                                    reasons.append("negative_evidence_missing")
                            try:
                                try:
                                    from ..knowledge import negative_sufficient
                                except ImportError:  # pragma: no cover
                                    from knowledge import negative_sufficient
                                sufficient, _ = negative_sufficient(surface, negative, None)
                                if not sufficient:
                                    reasons.append("negative_depth_insufficient")
                            except Exception:
                                reasons.append("negative_depth_invalid")
        except (OSError, json.JSONDecodeError):
            reasons.append("coverage_missing_or_invalid")
    if isinstance(endpoints, list) and endpoints:
        try:
            try:
                from ..surface_key import canonical_surface_key
            except ImportError:  # pragma: no cover
                from surface_key import canonical_surface_key
            inventory_keys: set[str] = set()
            for item in endpoints:
                if isinstance(item, dict):
                    method = str(item.get("method") or "").upper()
                else:
                    parts = str(item or "").strip().split(None, 1)
                    method = parts[0].upper() if len(parts) == 2 else ""
                if method not in http_methods:
                    reasons.append("inventory_method_unresolved")
                    continue
                key = canonical_surface_key(item)
                if key:
                    inventory_keys.add(key)
            coverage_keys = {
                canonical_surface_key({
                    "endpoint": item.get("endpoint", ""),
                    "method": item.get("method", ""),
                })
                for item in surfaces if isinstance(item, dict)
                and str(item.get("method") or "").upper() in http_methods
            }
            missing_coverage = sorted(inventory_keys - coverage_keys)
            if missing_coverage:
                reasons.append("inventory_coverage_mismatch")
            for item in endpoints:
                if not isinstance(item, dict) or not item.get("method"):
                    continue
                key = canonical_surface_key(item)
                matching = [
                    surface for surface in surfaces if isinstance(surface, dict)
                    and canonical_surface_key({
                        "endpoint": surface.get("endpoint", ""),
                        "method": surface.get("method", ""),
                    }) == key
                ]
                params = item.get("params") or item.get("param") or []
                if isinstance(params, str):
                    params = [params]
                roles = item.get("roles") or []
                if isinstance(roles, str):
                    roles = [roles]
                vuln_classes = item.get("vuln_classes") or item.get("vuln_class") or []
                if isinstance(vuln_classes, str):
                    vuln_classes = [vuln_classes]
                expected_params = ([str(x).strip() for x in params if str(x).strip()]
                                   or [None])
                expected_roles = ([str(x).strip().lower() for x in roles if str(x).strip()]
                                  or [None])
                expected_classes = ([str(x).strip() for x in vuln_classes if str(x).strip()]
                                    or [None])
                mismatch = False
                for param in expected_params:
                    for role in expected_roles:
                        for vuln_class in expected_classes:
                            def _matches_expected(surface: dict[str, Any]) -> bool:
                                if (param is not None
                                        and str(surface.get("param") or "").strip() != param):
                                    return False
                                if role is not None and role not in {
                                    str(x).strip().lower()
                                    for x in (surface.get("roles") or [])
                                }:
                                    return False
                                if vuln_class is not None:
                                    actual = str(surface.get("vuln_class")
                                                 or surface.get("legacy_vuln") or "")
                                    if actual.strip().lower() != vuln_class.lower():
                                        return False
                                return True
                            if not any(_matches_expected(surface) for surface in matching):
                                mismatch = True
                                break
                        if mismatch:
                            break
                    if mismatch:
                        break
                if mismatch:
                    reasons.append("inventory_exact_cell_coverage_mismatch")
            if any(isinstance(item, dict) and item.get("in_run_scope") is False
                   for item in surfaces):
                reasons.append("coverage_out_of_run")
        except (TypeError, ValueError):
            reasons.append("inventory_coverage_invalid")
    try:
        candidates = json.loads((run_dir / "candidate-ledger.json").read_text(encoding="utf-8"))
        if (not isinstance(candidates, dict)
                or str(candidates.get("schema_version") or "") != "1.1"
                or "candidates" not in candidates
                or not isinstance(candidates.get("candidates"), list)
                or any(not isinstance(row, dict) for row in candidates.get("candidates", []))):
            rows = []
            reasons.append("candidate_ledger_invalid")
        else:
            rows = candidates["candidates"]
        if any(str(row.get("status") or "") in {"proof_ready", "confirmed"}
               for row in rows if isinstance(row, dict)):
            reasons.append("proof_ready_candidate_open")
    except FileNotFoundError:
        rows = []
        reasons.append("candidate_ledger_missing")
    except json.JSONDecodeError:
        rows = []
        reasons.append("candidate_ledger_invalid")
    session_gate: dict[str, Any] = {"result": "error", "reasons": []}
    if ledger_path.is_file():
        try:
            try:
                from ..session_gate import evaluate_session_gate
            except ImportError:  # pragma: no cover
                from session_gate import evaluate_session_gate
            session_gate = evaluate_session_gate(
                ledger_path,
                evidence_dir=run_dir,
                ledger_path=ledger_path,
                inventory_path=run_dir / "inventory.json",
                candidates=rows or None,
                finding_candidate_ids=set(),
            )
        except Exception as exc:
            reasons.append(f"session_gate_error:{type(exc).__name__}:{exc}")
        else:
            if session_gate.get("result") != "pass":
                reasons.append(f"session_gate:{session_gate.get('result')}")
            stats = session_gate.get("stats") or {}
            if (int(stats.get("in_scope_total", 0) or 0) <= 0
                    or int(stats.get("in_scope_open", 0) or 0) != 0
                    or int(stats.get("in_scope_closed", 0) or 0)
                    != int(stats.get("in_scope_total", 0) or 0)):
                reasons.append("coverage_in_scope_incomplete")
    return {
        "result": "pass" if not reasons and session_gate.get("result") == "pass" else "fail",
        "reasons": reasons,
        "session_gate": session_gate,
    }


def _manifest_context(
    run_dir: pathlib.Path, allowed_hosts: list[str] | None = None,
) -> tuple[ValidationContext | None, pathlib.Path | None, list[dict[str, Any]]]:
    manifest_path = run_dir / "run_manifest.json"
    errors: list[dict[str, Any]] = []
    if not manifest_path.is_file():
        errors.append({
            "code": "missing_manifest",
            "reason": "run_manifest.json is required before finding validation",
        })
        return None, None, errors
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append({"code": "invalid_manifest", "reason": str(exc)})
        return None, manifest_path, errors
    required = {
        "schema_version", "atoolkit_version", "source_revision",
        "source_tree_sha256", "mode", "project", "session_id",
        "primary_target", "authorized_scopes", "authz_sha256",
        "instruction_sources", "authority_path", "created_at",
    }
    missing = sorted(required - set(manifest))
    if missing:
        errors.append({
            "code": "manifest_fields_missing", "fields": missing,
            "reason": "runtime manifest is incomplete",
        })
    authority_text = str(manifest.get("authority_path") or "").strip()
    authority_path = pathlib.Path(authority_text).expanduser() if authority_text else None
    context_manifest = manifest
    context_manifest_path = manifest_path
    if authority_path is None or not authority_path.is_absolute():
        errors.append({
            "code": "invalid_manifest_authority",
            "reason": "authority_path must be an absolute path",
        })
    elif authority_path.resolve(strict=False) == manifest_path.resolve():
        errors.append({
            "code": "self_authorized_manifest",
            "reason": "authority manifest must be outside the writable run directory",
        })
    else:
        if not authority_path.is_file():
            errors.append({
                "code": "missing_manifest_authority",
                "path": str(authority_path),
                "reason": "authoritative manifest copy is missing",
            })
        else:
            try:
                authority = json.loads(authority_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                errors.append({
                    "code": "invalid_manifest_authority", "path": str(authority_path),
                    "reason": str(exc),
                })
            else:
                context_manifest = authority
                context_manifest_path = authority_path
                if authority != manifest:
                    errors.append({
                        "code": "manifest_authority_mismatch",
                        "path": str(authority_path),
                        "reason": "session and authority manifests differ",
                    })
    context = ValidationContext.from_manifest(
        context_manifest, manifest_path=context_manifest_path)
    if allowed_hosts:
        requested = tuple(normalize_authorized_scopes(allowed_hosts))
        unattested = [scope for scope in requested if scope not in context.authorized_scopes]
        if unattested:
            errors.append({
                "code": "allow_scope_not_in_manifest",
                "scopes": unattested,
                "reason": "post-run validation cannot broaden pre-network authorization",
            })
    return context, manifest_path, errors


def validate_run_artifacts(
    run_dir: str | pathlib.Path,
    *,
    allowed_hosts: list[str] | None = None,
    allow_empty: bool = False,
    output_path: str | pathlib.Path | None = None,
) -> dict[str, Any]:
    """Single library entry point used by both CLI and orchestrator."""
    from .collect import collect_structured_findings
    try:
        from ..enforce import ACCEPTED, guardian_check_finding
        from ..version import __version__
    except ImportError:  # pragma: no cover
        from enforce import ACCEPTED, guardian_check_finding
        from version import __version__

    base = pathlib.Path(run_dir).resolve()
    context, manifest_path, preflight_errors = _manifest_context(base, allowed_hosts)
    collected = collect_structured_findings(
        base,
        authorized_hosts=(allowed_hosts or None) if context is None else None,
        context=context,
    )
    ingestion_errors = [*preflight_errors, *list(collected.get("ingestion_errors") or [])]
    rejected = list(collected.get("rejected") or [])
    confirmed: list[dict[str, Any]] = []
    normalized_confirmed: list[dict[str, Any]] = []
    accepted_paths: set[str] = set()
    for item in collected.get("accepted") or []:
        path = pathlib.Path(item.get("path") or "")
        # Scope was already validated with ValidationContext.  Passing the
        # legacy host list again would incorrectly reject relative targets.
        verdict = guardian_check_finding(item.get("finding") or {}, path.parent)
        if verdict.result == ACCEPTED:
            confirmed.append({"id": item.get("id"), "path": str(path)})
            accepted_paths.add(str(path.resolve()))
        else:
            rejected.append({
                "id": item.get("id"), "path": str(path),
                "reasons": [f"guardian:{verdict.result}:L{verdict.level}:{verdict.reason}"],
            })
    for normalized in collected.get("normalized") or []:
        ref = str(normalized.get("raw_finding_path") or normalized.get("evidence_file") or "")
        if str((base / ref).resolve()) in accepted_paths:
            normalized_confirmed.append(normalized)

    # Manifest provenance is a run-level prerequisite.  Never emit a
    # proof-confirmed registry input when it is absent, incomplete or differs
    # from the authority copy, even if an individual finding packet parses.
    if preflight_errors:
        confirmed = []
        normalized_confirmed = []

    artifact_hashes: dict[str, str] = {}
    if manifest_path and manifest_path.is_file():
        artifact_hashes[manifest_path.relative_to(base).as_posix()] = _sha256_file(manifest_path)
    for normalized in normalized_confirmed:
        for ref in normalized.get("proof_files") or []:
            path = (base / str(ref)).resolve()
            try:
                relative = path.relative_to(base).as_posix()
            except ValueError:
                ingestion_errors.append({"code": "proof_path_escape", "path": str(path)})
                continue
            if path.is_file():
                artifact_hashes[relative] = _sha256_file(path)
            else:
                ingestion_errors.append({"code": "proof_file_missing", "path": relative})

    canonical_count = int((collected.get("counts") or {}).get("canonical", 0) or 0)
    empty_gate = None
    precondition_missing = any(
        item.get("code") == "missing_manifest" for item in preflight_errors)
    if precondition_missing:
        status, exit_code = "precondition_missing", 2
    elif canonical_count == 0 and not rejected and not ingestion_errors:
        if allow_empty:
            empty_gate = _empty_run_gate(base, context=context)
            status = "empty_allowed" if empty_gate["result"] == "pass" else "empty_input"
            exit_code = 0 if empty_gate["result"] == "pass" else 2
        else:
            status, exit_code = "empty_input", 2
    elif rejected or ingestion_errors:
        status, exit_code = "invalid", 1
    else:
        status, exit_code = "valid", 0

    counts = {
        **(collected.get("counts") or {}),
        "proof_confirmed": len(confirmed),
        "rejected": len(rejected),
        "ingestion_errors": len(ingestion_errors),
    }
    result: dict[str, Any] = {
        "schema_version": 2,
        "tool_version": __version__,
        "run_dir": str(base),
        "status": status,
        "exit_code": exit_code,
        "manifest_path": str(manifest_path) if manifest_path else "",
        "manifest_sha256": _sha256_file(manifest_path) if manifest_path and manifest_path.is_file() else "",
        "authority_manifest_path": (
            str(context.manifest_path) if context and context.manifest_path else ""),
        "authority_manifest_sha256": (
            _sha256_file(context.manifest_path)
            if context and context.manifest_path and context.manifest_path.is_file() else ""),
        "discovery": collected.get("discovery") or {},
        "proof_confirmed": confirmed,
        "normalized_findings": normalized_confirmed,
        "proof_pending_or_rejected": rejected,
        "ingestion_errors": ingestion_errors,
        "warnings": list(collected.get("warnings") or []),
        "artifact_hashes": artifact_hashes,
        "counts": counts,
    }
    if empty_gate is not None:
        result["empty_gate"] = empty_gate
    result["validation_sha256"] = _canonical_digest(result)
    output = pathlib.Path(output_path) if output_path else base / "finding_validation.json"
    if not output.is_absolute():
        output = base / output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def verify_validation_artifact(
    artifact: dict[str, Any] | str | pathlib.Path,
    run_dir: str | pathlib.Path,
) -> dict[str, Any]:
    if isinstance(artifact, (str, pathlib.Path)):
        report = json.loads(pathlib.Path(artifact).read_text(encoding="utf-8"))
    else:
        report = artifact
    base = pathlib.Path(run_dir).resolve()
    mismatches: list[dict[str, str]] = []
    for ref, expected in (report.get("artifact_hashes") or {}).items():
        path = (base / str(ref)).resolve()
        try:
            path.relative_to(base)
        except ValueError:
            mismatches.append({"path": str(ref), "reason": "path_escape"})
            continue
        actual = _sha256_file(path) if path.is_file() else ""
        if actual != expected:
            mismatches.append({"path": str(ref), "expected": str(expected), "actual": actual})
    authority_ref = str(report.get("authority_manifest_path") or "").strip()
    authority_expected = str(report.get("authority_manifest_sha256") or "").strip()
    if authority_ref or authority_expected:
        authority_path = pathlib.Path(authority_ref)
        authority_actual = (_sha256_file(authority_path)
                            if authority_path.is_absolute() and authority_path.is_file() else "")
        if not authority_expected or authority_actual != authority_expected:
            mismatches.append({
                "path": authority_ref or "<authority_manifest>",
                "expected": authority_expected,
                "actual": authority_actual,
            })
    expected_digest = str(report.get("validation_sha256") or "")
    if expected_digest and _canonical_digest(report) != expected_digest:
        mismatches.append({"path": "<validation>", "reason": "validation_digest_mismatch"})
    return {"ok": not mismatches, "mismatches": mismatches}


def main(argv: list[str] | None = None) -> int:
    """Validate a run directory for Skill Mode/CI without invoking a model."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Validate proof-confirmed root findings in an Atoolkit run directory.")
    parser.add_argument("run_dir", type=pathlib.Path)
    parser.add_argument("--allow", action="append", default=[], dest="allowed_hosts")
    parser.add_argument("--allow-empty", action="store_true")
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        result = validate_run_artifacts(
            args.run_dir,
            allowed_hosts=args.allowed_hosts or None,
            allow_empty=args.allow_empty,
            output_path=args.output,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        payload = {"schema_version": 2, "status": "error", "exit_code": 3,
                   "reason": f"{type(exc).__name__}: {exc}"}
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 3
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return int(result["exit_code"])


if __name__ == "__main__":  # pragma: no cover - CLI exercised by self-check/CI
    raise SystemExit(main())
