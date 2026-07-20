from __future__ import annotations

import hashlib
import json
import pathlib
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse, urlsplit

try:
    from ..dynamic_execution import (
        EXECUTION_CONTRACT_VERSION,
        DynamicExecutionError,
        build_execution_projection,
        load_authority_execution_events,
        normalize_execution_event,
        projection_matches_files,
        rejected_finding_surface_ids,
    )
    from ..host_policy import is_authorized_url, normalize_authorized_scopes
    from ..exploration import validate_intuition_exploration
    from ..ledger import CoverageLedger
    from ..outcome import build_miss_attribution, build_next_run_agenda
    from ..negative_retest import (families_from_packets,
                                   has_cross_stage_diversity,
                                   is_input_validation_cell)
    from ..run_authority import canonical_method_resolution_key
    from ..runtime_manifest import validate_manifest_binding
    from ..safe_io import atomic_write_json, safe_read_bytes, safe_read_text
except ImportError:  # pragma: no cover - direct package fallback
    from dynamic_execution import (EXECUTION_CONTRACT_VERSION,
                                   DynamicExecutionError,
                                   build_execution_projection,
                                   load_authority_execution_events,
                                   normalize_execution_event,
                                   projection_matches_files,
                                   rejected_finding_surface_ids)
    from host_policy import is_authorized_url, normalize_authorized_scopes
    from exploration import validate_intuition_exploration
    from ledger import CoverageLedger
    from outcome import build_miss_attribution, build_next_run_agenda
    from negative_retest import (families_from_packets,
                                 has_cross_stage_diversity,
                                 is_input_validation_cell)
    from run_authority import canonical_method_resolution_key
    from runtime_manifest import validate_manifest_binding
    from safe_io import atomic_write_json, safe_read_bytes, safe_read_text

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
    "cross_site_state_change",
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
SUBMISSION_NOISE_ROOT = re.compile(
    r"(?:\bCORS\b|source\s*map|sourcemap|\.map\b|x-frame-options|\bCSP\b|"
    r"\bHSTS\b|安全响应?头|版本号|中间件指纹|self[- ]?xss|"
    r"\bSSL\b|\bTLS\b|目录列举|报错堆栈|stack\s*trace)", re.I)
RATE_LIMIT_ROOT = re.compile(
    r"(?:rate[- ]?limit|限频|速率限制|频率限制)", re.I)
OPEN_REDIRECT_ROOT = re.compile(
    r"(?:open[- ]?redirect|开放重定向|任意跳转)", re.I)
ERROR_ONLY_ROOT = re.compile(
    r"(?:type\s*confusion|类型混淆|unhandled\s+exception|未处理异常|"
    r"\b500\b|internal\s+server\s+error|报错)", re.I)
CREDENTIAL_LEAK_ROOT = re.compile(
    r"(?:(?:token|cookie|api[-_ ]?key|credential|session|凭据|令牌|密钥|会话)"
    r".{0,20}(?:leak|expos|disclos|泄露|暴露)|"
    r"(?:leak|expos|disclos|泄露|暴露).{0,20}"
    r"(?:token|cookie|api[-_ ]?key|credential|session|凭据|令牌|密钥|会话))",
    re.I,
)


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
        if isinstance(self.finding, dict):
            out.update(_finding_target_projection(self.finding))
        return out


def _finding_target_projection(finding: dict[str, Any]) -> dict[str, Any]:
    """Return non-secret scheduling identity for a rejected proof package."""
    apis = [
        item for item in (finding.get("apis") or [])
        if isinstance(item, dict)
    ]
    primary = apis[0] if apis else {}
    params: list[str] = []
    for value in primary.get("risk_params") or []:
        text = str(value or "").strip()
        if text and text not in params:
            params.append(text)
    for value in primary.get("params") or []:
        text = str(value.get("name") if isinstance(value, dict) else value).strip()
        if text and text not in params:
            params.append(text)
    roles: list[str] = []
    for key in (
        "actor_roles", "affected_roles", "role_scopes", "roles",
        "actor_role", "affected_role", "role_scope", "role",
    ):
        value = finding.get(key)
        values = value if isinstance(value, list) else [value]
        for item in values:
            text = str(item or "").strip().lower()
            if text and text not in roles:
                roles.append(text)
    feature = (
        finding.get("feature_point")
        if isinstance(finding.get("feature_point"), dict) else {})
    claim = (
        finding.get("claim")
        if isinstance(finding.get("claim"), dict) else {})
    return {
        "method": str(primary.get("method") or "").strip().upper(),
        "endpoint": str(primary.get("path") or "").strip(),
        "params": params,
        "roles": roles,
        "vuln_class": str(finding.get("vuln_type") or "").strip(),
        "feature_id": str(feature.get("feature_id") or "").strip(),
        "threat_id": str(
            claim.get("threat_id") or finding.get("threat_id") or "").strip(),
    }


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
        return False
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
    if "csrf" in low or "cross-site request forgery" in low or "跨站请求伪造" in low:
        return "csrf"
    if "xss" in low or "跨站脚本" in low:
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


def _validate_submission_policy(
    finding: dict[str, Any], packets: list[dict[str, Any]],
    finding_dir: pathlib.Path, run_base: pathlib.Path, reasons: list[str],
) -> None:
    """Reject phenomenon-only roots before they can become SRC truth.

    Structured proof may show that a response changed while still failing to
    show a security boundary break.  These rules encode the repository's
    report policy independently of model wording and Markdown rendering.
    """
    risk = finding.get("risk") if isinstance(finding.get("risk"), dict) else {}
    verification = (
        finding.get("verification")
        if isinstance(finding.get("verification"), dict) else {})
    chain = (
        finding.get("chain_assessment")
        if isinstance(finding.get("chain_assessment"), dict) else {})
    text = "\n".join(str(value or "") for value in (
        finding.get("title"), finding.get("vuln_type"),
        risk.get("summary"), risk.get("proven_impact"),
    ))
    if SUBMISSION_NOISE_ROOT.search(text):
        reasons.append("submission_policy: phenomenon-only noise root is not SRC eligible")
    if RATE_LIMIT_ROOT.search(text) and str(chain.get("status") or "") != "proven":
        reasons.append(
            "submission_policy: rate-limit weakness requires a proven downstream security result")
    if OPEN_REDIRECT_ROOT.search(text) and str(chain.get("status") or "") != "proven":
        reasons.append(
            "submission_policy: open redirect requires a proven downstream security result")
    if ERROR_ONLY_ROOT.search(text):
        boundary = verification.get("security_boundary")
        if not isinstance(boundary, dict):
            reasons.append(
                "submission_policy: error-only response requires a proven security_boundary result")
        else:
            kind = str(boundary.get("kind") or "").strip().lower()
            refs = boundary.get("proof_refs") or []
            marker = str(boundary.get("marker") or "").strip()
            if (kind not in {"data_read", "state_change", "code_execution",
                             "authorization_bypass", "trusted_secret_use"}
                    or not isinstance(refs, list) or not refs or len(marker) < 4):
                reasons.append(
                    "submission_policy: security_boundary requires kind, proof_refs and marker")
            else:
                resolved = [
                    _exists(finding_dir, ref, run_base, reasons,
                            f"verification.security_boundary.proof_refs[{index}]")
                    for index, ref in enumerate(refs)
                ]
                if not any(path and marker in _read_text(path) for path in resolved):
                    reasons.append(
                        "submission_policy: security_boundary marker not found in proof_refs")
    if CREDENTIAL_LEAK_ROOT.search(text):
        boundary = verification.get("credential_boundary")
        if not isinstance(boundary, dict):
            reasons.append(
                "submission_policy: credential exposure requires cross-boundary use proof")
        else:
            status = str(boundary.get("status") or "").strip().lower()
            refs = boundary.get("proof_packet_ids") or []
            marker = str(boundary.get("outcome_marker") or "").strip()
            if (status not in {"cross_boundary_use_proven",
                               "privileged_credential_exposed"}
                    or not isinstance(refs, list) or not refs or len(marker) < 4):
                reasons.append(
                    "submission_policy: credential_boundary proof is incomplete")
            else:
                packet_map = _packet_name_map(
                    packets, finding_dir, run_base)
                if any(str(ref) not in packet_map for ref in refs):
                    reasons.append(
                        "submission_policy: credential_boundary references unknown proof packets")
                elif not any(
                        marker in _read_text(packet_map[str(ref)]["response"])
                        for ref in refs):
                    reasons.append(
                        "submission_policy: credential outcome_marker not found in proof responses")
                if status == "cross_boundary_use_proven":
                    source_identity = str(
                        boundary.get("source_identity") or "").strip()
                    consumer_identity = str(
                        boundary.get("consumer_identity") or "").strip()
                    if (not source_identity or not consumer_identity
                            or source_identity == consumer_identity):
                        reasons.append(
                            "submission_policy: cross-boundary credential use requires distinct identities")
                elif not str(boundary.get("privilege_scope") or "").strip():
                    reasons.append(
                        "submission_policy: privileged credential exposure requires privilege_scope")


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
        "csrf": "cross_site_state_change",
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
    elif family == "csrf":
        required = {"state_before", "cross_site_request", "state_after"}
        if not required.issubset(phases):
            reasons.append(
                "csrf finding requires state_before/cross_site_request/state_after packets")
        state_delta = str(verification.get("state_delta") or "").strip()
        if not state_delta:
            reasons.append("csrf finding requires verification.state_delta")
        packet_map = _packet_map(packets, finding_dir, run_base)
        before = packet_map.get("state_before")
        after = packet_map.get("state_after")
        before_marker = str(
            verification.get("state_before_marker") or "").strip()
        after_marker = str(
            verification.get("state_after_marker") or "").strip()
        if len(before_marker) < 4 or len(after_marker) < 4:
            reasons.append("csrf finding requires before/after state markers")
        elif before_marker == after_marker:
            reasons.append("csrf before/after state markers must differ")
        else:
            if before and before_marker not in _read_text(before["response"]):
                reasons.append("csrf state_before_marker not found in response")
            if after and after_marker not in _read_text(after["response"]):
                reasons.append("csrf state_after_marker not found in response")
        cross_site = packet_map.get("cross_site_request")
        initiator = _exists(
            finding_dir, verification.get("cross_site_initiator_file"),
            run_base, reasons, "verification.cross_site_initiator_file")
        if initiator:
            initiator_text = _read_text(initiator)
            if not re.search(
                r"<(?:form|img)\b|\bfetch\s*\(|\bXMLHttpRequest\b|"
                r"\bwindow\.location\b",
                initiator_text, re.I,
            ):
                reasons.append(
                    "csrf cross_site_initiator_file must contain an executable "
                    "browser request primitive")
        if cross_site is not None:
            request_text = _read_text(cross_site["request"])
            origin_match = re.search(
                r"^Origin:\s*(https?://[^\s]+)\s*$", request_text, re.I | re.M)
            referer_match = re.search(
                r"^Referer:\s*(https?://[^\s]+)\s*$", request_text, re.I | re.M)
            host_match = re.search(
                r"^Host:\s*([^\s]+)\s*$", request_text, re.I | re.M)
            source_match = origin_match or referer_match
            if not source_match or not host_match:
                reasons.append(
                    "csrf cross-site request requires Origin/Referer and Host headers")
            elif urlsplit(source_match.group(1)).netloc.lower() == host_match.group(1).lower():
                reasons.append("csrf Origin/Referer must differ from the target Host")
            if not re.search(r"^Cookie:\s*\S+", request_text, re.I | re.M):
                reasons.append("csrf cross-site request must prove victim session cookies were sent")
    else:
        if not _has_any(phases, {"control", "baseline"}) or not _has_any(
                phases, {"exploit", "test"}):
            reasons.append("generic finding requires control and exploit packets")


def _canonical_asset(value: str) -> str:
    try:
        try:
            from ..project_state import canonical_asset
        except ImportError:  # pragma: no cover
            from project_state import canonical_asset
        return canonical_asset(value)
    except ImportError:  # pragma: no cover - standalone defensive fallback
        parsed = urlparse(str(value or ""))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return f"{parsed.scheme}://{parsed.hostname.lower()}:{port}"


def _request_components(
    request_text: str,
    *,
    context: ValidationContext | None,
    finding_target: str,
) -> dict[str, Any]:
    match = re.search(
        r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/",
        request_text, re.I | re.M)
    if not match:
        return {}
    method, raw_target = match.group(1).upper(), match.group(2)
    parsed = urlsplit(raw_target)
    host = parsed.netloc
    scheme = parsed.scheme.lower()
    if not host:
        host_match = re.search(r"^Host:\s*([^\s]+)\s*$", request_text, re.I | re.M)
        host = host_match.group(1) if host_match else ""
        if context is not None:
            scheme = urlparse(context.primary_target).scheme or "https"
        else:
            scheme = urlparse(str(finding_target or "")).scheme or "https"
    path = parsed.path or "/"
    query = parsed.query
    asset = _canonical_asset(f"{scheme}://{host}") if host else ""
    body = re.split(r"\r?\n\r?\n", request_text, maxsplit=1)
    header_block = body[0]
    headers: dict[str, str] = {}
    for header_match in re.finditer(
            r"^([!#$%&'*+.^_`|~0-9A-Za-z-]+):\s*([^\r\n]*)$",
            header_block, re.M):
        headers[header_match.group(1).lower()] = header_match.group(2).strip()
    return {
        "method": method,
        "path": path,
        "query": query,
        "asset_id": asset,
        "body": body[1] if len(body) == 2 else "",
        "headers": headers,
    }


def _json_parameter_names(value: Any) -> set[str]:
    names: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            names.add(str(key))
            names.update(_json_parameter_names(nested))
    elif isinstance(value, list):
        for nested in value:
            names.update(_json_parameter_names(nested))
    return names


def _body_parameter_names(components: dict[str, Any]) -> tuple[str, set[str]]:
    headers = components.get("headers")
    content_type = str(
        headers.get("content-type") if isinstance(headers, dict) else ""
    ).split(";", 1)[0].strip().lower()
    body = str(components.get("body") or "")
    if content_type == "application/json" or content_type.endswith("+json"):
        try:
            return "json", _json_parameter_names(json.loads(body))
        except (json.JSONDecodeError, TypeError, ValueError):
            return "json", set()
    if content_type == "application/x-www-form-urlencoded":
        return "form", {
            key for key, _value in parse_qsl(body, keep_blank_values=True)
        }
    if content_type == "multipart/form-data":
        return "multipart", {
            match.group(1)
            for match in re.finditer(
                r'^Content-Disposition:[^\r\n]*\bname="([^"\r\n]+)"',
                body, re.I | re.M)
        }
    return "", set()


def _request_contains_param(components: dict[str, Any], cell: dict[str, Any]) -> bool:
    name = str(cell.get("param") or "").strip()
    if not name:
        return True
    location = str(cell.get("param_location") or "").strip().lower()
    endpoint = str(cell.get("endpoint") or "")
    path_bound = bool(re.search(
        rf"(?:\{{{re.escape(name)}\}}|:{re.escape(name)}(?:/|$))",
        urlsplit(endpoint).path or endpoint, re.I))
    query_bound = any(
        key == name for key, _value in parse_qsl(
            components.get("query", ""), keep_blank_values=True))
    body_kind, body_names = _body_parameter_names(components)
    body_bound = name in body_names
    if location == "path":
        return path_bound
    if location == "query":
        return query_bound
    if location == "body":
        return body_bound
    if location in {"form", "json", "multipart"}:
        return body_kind == location and body_bound
    return path_bound or query_bound or body_bound


def _semantic_cell_tuple(cell: dict[str, Any]) -> tuple[str, ...]:
    return (
        _canonical_asset(str(cell.get("asset_id") or cell.get("asset") or "")),
        str(cell.get("endpoint") or cell.get("path") or "").strip(),
        str(cell.get("method") or "").strip().upper(),
        str(cell.get("param") or "").strip(),
        str(cell.get("actor_role") or cell.get("role_scope") or "unknown").strip().lower(),
        str(cell.get("namespace") or "").strip(),
        str(cell.get("param_location") or "").strip().lower(),
        str(cell.get("subject_role") or "").strip().lower(),
        str(cell.get("object_kind") or "").strip().lower(),
    )


def _packet_declared_cells(packet: dict[str, Any]) -> list[dict[str, Any]]:
    rows = packet.get("exact_cells")
    if rows is None and isinstance(packet.get("exact_cell"), dict):
        rows = [packet["exact_cell"]]
    return [row for row in (rows or []) if isinstance(row, dict)]


def _cell_request_path(cell: dict[str, Any]) -> str:
    """Resolve a namespace-relative endpoint to its physical HTTP path."""
    endpoint_text = str(cell.get("endpoint") or cell.get("path") or "").strip()
    endpoint = urlsplit(endpoint_text).path or endpoint_text.split("?", 1)[0] or "/"
    if not endpoint.startswith("/"):
        endpoint = f"/{endpoint}"
    namespace_text = str(cell.get("namespace") or "").strip()
    namespace = urlsplit(namespace_text).path or namespace_text.split("?", 1)[0]
    namespace = f"/{namespace.strip('/')}" if namespace.strip("/") else ""
    if not namespace:
        return endpoint
    # Absolute or already-resolved endpoint forms must not receive a second
    # namespace prefix.
    if endpoint == namespace or endpoint.startswith(f"{namespace}/"):
        return endpoint
    return f"{namespace}{endpoint}"


def _cell_matches_raw_request(
    cell: dict[str, Any], components: dict[str, str],
) -> bool:
    if not components:
        return False
    if str(cell.get("method") or "").upper() != components.get("method"):
        return False
    endpoint = _cell_request_path(cell)
    request_path = components.get("path", "")
    if not (
        _template_path_matches(endpoint, request_path)
        or _template_path_matches(request_path, endpoint)
    ):
        return False
    asset = _canonical_asset(str(cell.get("asset_id") or ""))
    if asset and asset != components.get("asset_id"):
        return False
    return _request_contains_param(components, cell)


def _api_authorization_targets(
    api: dict[str, Any], finding: dict[str, Any], context: ValidationContext | None,
) -> list[str]:
    path = str(api.get("path") or "").strip()
    parsed_path = urlparse(path)
    targets: list[str] = []
    absolute_path = bool(
        parsed_path.scheme in {"http", "https"} and parsed_path.hostname)
    if absolute_path:
        targets.append(path)
    explicit = []
    explicit_present = any(key in api for key in ("assets", "asset", "asset_id"))
    for key in ("assets", "asset", "asset_id"):
        value = api.get(key)
        explicit.extend(value if isinstance(value, list) else [value] if value else [])
    if explicit_present and not explicit:
        targets.append("")
        return targets
    if explicit:
        relative_path = (
            (parsed_path.path or "/")
            + (f"?{parsed_path.query}" if parsed_path.query else "")
        ) if absolute_path else path
        for value in explicit:
            text = str(value or "").strip()
            parsed = urlparse(text)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                targets.append("")
            else:
                base = f"{parsed.scheme}://{parsed.netloc}/"
                targets.append(urljoin(base, relative_path.lstrip("/")))
        return targets
    if absolute_path:
        return targets
    if context is not None and context.primary_target:
        return [urljoin(context.primary_target.rstrip("/") + "/", path.lstrip("/"))]
    top = str(finding.get("target") or "").strip()
    parts = top.split(None, 1)
    if len(parts) == 2 and parts[0].upper() in {
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
    }:
        top = parts[1]
    parsed = urlparse(top)
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        return [urljoin(f"{parsed.scheme}://{parsed.netloc}/", path.lstrip("/"))]
    return [path]


def _inventory_item_authorized(
    item: Any, context: ValidationContext | None,
) -> bool:
    if context is None:
        return True
    if isinstance(item, str):
        text = item.strip()
        parts = text.split(None, 1)
        if (len(parts) == 2 and parts[0].upper() in {
                "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}):
            text = parts[1]
        parsed = urlparse(text)
        return not (
            parsed.scheme in {"http", "https"} and parsed.hostname
        ) or context.allows(text)
    if not isinstance(item, dict):
        return False
    endpoint = str(item.get("endpoint") or item.get("path") or "").strip()
    endpoint_parts = endpoint.split(None, 1)
    if (len(endpoint_parts) == 2 and endpoint_parts[0].upper() in {
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}):
        endpoint = endpoint_parts[1]
    parsed_endpoint = urlparse(endpoint)
    if (parsed_endpoint.scheme in {"http", "https"}
            and parsed_endpoint.hostname
            and not context.allows(endpoint)):
        return False
    explicit_present = any(
        key in item for key in ("assets", "asset", "asset_id"))
    explicit: list[Any] = []
    for key in ("assets", "asset", "asset_id"):
        value = item.get(key)
        explicit.extend(value if isinstance(value, list) else [value] if value else [])
    if explicit_present and not explicit:
        return False
    relative_target = (
        (parsed_endpoint.path or "/")
        + (f"?{parsed_endpoint.query}" if parsed_endpoint.query else "")
    ) if parsed_endpoint.scheme else endpoint
    for value in explicit:
        parsed_asset = urlparse(str(value or "").strip())
        if parsed_asset.scheme not in {"http", "https"} or not parsed_asset.hostname:
            return False
        base = f"{parsed_asset.scheme}://{parsed_asset.netloc}/"
        target = urljoin(base, str(relative_target or "/").lstrip("/"))
        if not context.allows(target):
            return False
    return True


def _validate_api_proof_bindings(
    finding: dict[str, Any], finding_file: pathlib.Path, run_base: pathlib.Path,
    packets: list[dict[str, Any]], reasons: list[str],
    *, authorized_hosts: list[str] | None, context: ValidationContext | None,
) -> list[dict[str, Any]]:
    """Bind every declared API/exact cell to a matching raw request packet."""
    finding_dir = finding_file.parent
    packet_records: dict[str, dict[str, Any]] = {}
    for index, packet in enumerate(packets):
        if not isinstance(packet, dict):
            continue
        name = str(packet.get("name") or "").strip()
        if not name:
            reasons.append(f"proof_packets[{index}].name required for exact-cell binding")
            continue
        if name in packet_records:
            reasons.append(f"duplicate proof packet name: {name}")
            continue
        try:
            request = resolve_finding_file(
                finding_dir, packet.get("request_file"), run_base)
            response = resolve_finding_file(
                finding_dir, packet.get("response_file"), run_base)
        except (TypeError, ValueError):
            continue
        if not request.is_file() or not response.is_file():
            continue
        request_text = _read_text(request)
        response_text = _read_text(response)
        packet_records[name] = {
            "packet": packet,
            "request": request,
            "response": response,
            "components": _request_components(
                request_text, context=context,
                finding_target=str(finding.get("target") or "")),
            "has_response": HTTP_STATUS.search(response_text) is not None,
            "request_text": request_text,
            "response_text": response_text,
        }

    merged: dict[tuple[str, ...], dict[str, Any]] = {}
    for api_index, api in enumerate(finding.get("apis") or []):
        if not isinstance(api, dict):
            continue
        for target in _api_authorization_targets(api, finding, context):
            if not target or not _target_allowed(target, authorized_hosts, context):
                reasons.append(
                    f"apis[{api_index}] target out of authorized scopes: {target or '<invalid asset>'}")
        declared_ids = api.get("proof_packet_ids")
        if declared_ids is not None and not isinstance(declared_ids, list):
            reasons.append(f"apis[{api_index}].proof_packet_ids must be a list")
            declared_ids = []
        if declared_ids is not None and not declared_ids:
            reasons.append(f"apis[{api_index}].proof_packet_ids cannot be empty")
        allowed_ids = {
            str(value) for value in (
                packet_records.keys() if declared_ids is None else declared_ids)
        }
        unknown_ids = sorted(allowed_ids - set(packet_records))
        if unknown_ids:
            reasons.append(
                f"apis[{api_index}].proof_packet_ids reference unknown packets: "
                + ",".join(unknown_ids))

        # Reuse the canonical schema expansion, but isolate this API so an
        # unrelated sibling API cannot lend it rows or packets.
        one_api = dict(finding)
        one_api["apis"] = [api]
        api_cells = normalize_finding(
            one_api, finding_file, run_base).get("exact_cells") or []
        for cell in api_cells:
            raw_candidates: list[tuple[str, dict[str, Any]]] = []
            for packet_id in sorted(allowed_ids):
                record = packet_records.get(packet_id)
                if (record is not None and record["has_response"]
                        and _cell_matches_raw_request(cell, record["components"])):
                    raw_candidates.append((packet_id, record))

            bound: list[tuple[str, dict[str, Any]]] = []
            for packet_id, record in raw_candidates:
                declared_cells = _packet_declared_cells(record["packet"])
                if declared_cells:
                    if (any(_semantic_cell_tuple(row) == _semantic_cell_tuple(cell)
                            for row in declared_cells)
                            and _identity_assertions_pass(
                                cell,
                                record["packet"].get("identity_assertions"),
                                record["request_text"], record["response_text"],
                            )):
                        bound.append((packet_id, record))
                    continue
                # Raw HTTP can distinguish method/path/host/param/location.  If
                # it still matches several semantic cells (role/namespace/
                # subject/object), the packet must explicitly name its cell.
                raw_matches = [
                    row for row in api_cells
                    if _cell_matches_raw_request(row, record["components"])
                ]
                if len({_semantic_cell_tuple(row) for row in raw_matches}) == 1:
                    bound.append((packet_id, record))
            if not bound:
                reasons.append(
                    f"apis[{api_index}] exact cell has no raw METHOD/path/Host proof binding: "
                    f"{cell.get('method')} {cell.get('endpoint')} param={cell.get('param')!r} "
                    f"actor={cell.get('actor_role')!r}")
                continue
            identity = _semantic_cell_tuple(cell)
            item = merged.setdefault(identity, {**cell, "proof_packet_ids": [], "proof_files": []})
            for packet_id, record in bound:
                if packet_id not in item["proof_packet_ids"]:
                    item["proof_packet_ids"].append(packet_id)
                for proof_path in (record["request"], record["response"]):
                    relative = proof_path.resolve().relative_to(run_base).as_posix()
                    if relative not in item["proof_files"]:
                        item["proof_files"].append(relative)
    return list(merged.values())


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
    if str(((context.manifest if context else {}) or {}).get(
            "planning_mode") or "") == "threat_model":
        if not isinstance(feature_point, dict) or not str(
                feature_point.get("feature_id") or "").strip():
            reasons.append("threat-model finding requires feature_point.feature_id")
        claim = finding.get("claim") if isinstance(finding.get("claim"), dict) else {}
        if not str(claim.get("threat_id") or "").strip():
            reasons.append("threat-model finding requires claim.threat_id")

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

    exact_cell_bindings = _validate_api_proof_bindings(
        finding, finding_file, run_base, packets, reasons,
        authorized_hosts=authorized_hosts, context=context,
    )

    _validate_verification(finding, packets, finding_dir, run_base, reasons)
    _validate_chain(finding, finding_dir, run_base, reasons)
    _validate_claims(finding, packets, finding_dir, run_base, reasons)
    _validate_submission_policy(
        finding, packets, finding_dir, run_base, reasons)

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

    normalized = None if reasons else normalize_finding(
        finding, finding_file, run_base,
        exact_cell_bindings=exact_cell_bindings,
    )
    return ValidationResult(
        ok=not reasons,
        id=fid,
        path=str(finding_file),
        reasons=reasons,
        finding=finding,
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


def _template_path_matches(template: str, concrete: str) -> bool:
    """Conservatively match ``/x/{id}`` coverage paths to concrete findings."""
    if template == concrete:
        return True
    escaped = re.escape(str(template or ""))
    pattern = re.sub(r"\\\{[^{}]+\\\}", r"[^/]+", escaped)
    return bool(pattern and re.fullmatch(pattern, str(concrete or "")))


def _surface_has_current_finding(
    surface: dict[str, Any],
    findings: list[dict[str, Any]],
    run_dir: pathlib.Path,
    source_run_dir: pathlib.Path | None = None,
) -> bool:
    evidence_ref = str(surface.get("evidence_ref") or "").strip()
    if not evidence_ref:
        return False
    evidence_path = pathlib.Path(evidence_ref)
    if evidence_path.is_absolute() and source_run_dir is not None:
        try:
            relative = evidence_path.resolve(strict=False).relative_to(
                source_run_dir.resolve())
        except ValueError:
            return False
        evidence_path = run_dir / relative
    elif not evidence_path.is_absolute():
        evidence_path = run_dir / evidence_path
    evidence_path = evidence_path.resolve(strict=False)
    try:
        evidence_relative = evidence_path.relative_to(run_dir.resolve()).as_posix()
    except ValueError:
        return False

    try:
        try:
            from ..project_state import canonical_asset
        except ImportError:  # pragma: no cover
            from project_state import canonical_asset
    except ImportError:  # pragma: no cover - defensive for standalone tooling
        canonical_asset = lambda value: str(value or "").strip()  # type: ignore[assignment]

    def values(value: Any) -> list[Any]:
        if value in (None, "", [], {}):
            return []
        return value if isinstance(value, list) else [value]

    surface_method = str(surface.get("method") or "").upper()
    surface_endpoint = str(surface.get("endpoint") or "").split("?", 1)[0]
    surface_param = str(surface.get("param") or "").strip()
    surface_asset = canonical_asset(str(
        surface.get("asset_id") or surface.get("asset") or ""))
    explicit_surface_role = surface.get("actor_role") or surface.get("role_scope")
    surface_roles = {
        str(role).strip().lower() for role in values(
            surface.get("actor_roles")
            or ([explicit_surface_role] if explicit_surface_role else None)
            or surface.get("roles") or ["unknown"])
        if str(role).strip()
    }
    surface_dimensions = {
        "namespace": str(surface.get("namespace") or "").strip(),
        "param_location": str(surface.get("param_location") or "").strip().lower(),
        "subject_role": str(surface.get("subject_role") or "").strip().lower(),
        "object_kind": str(surface.get("object_kind") or "").strip().lower(),
    }
    surface_class = str(
        surface.get("vuln_class") or surface.get("legacy_vuln") or "").strip().lower()
    surface_feature_id = str(surface.get("feature_id") or "").strip()
    surface_threat_id = str(surface.get("threat_id") or "").strip()
    for finding in findings:
        proof_refs = {str(ref) for ref in finding.get("proof_files") or []}
        if evidence_relative not in proof_refs:
            continue
        finding_class = str(
            finding.get("vuln_class") or finding.get("class") or "").strip().lower()
        if surface_class and finding_class and surface_class != finding_class:
            continue
        if (surface_feature_id
                and str(finding.get("feature_id") or "").strip() != surface_feature_id):
            continue
        if (surface_threat_id
                and str(finding.get("threat_id") or "").strip() != surface_threat_id):
            continue

        rows = [row for row in finding.get("exact_cells") or []
                if isinstance(row, dict)]
        if not rows:
            assets = values(finding.get("assets") or [
                finding.get("asset_id") or finding.get("asset") or finding.get("target") or ""]
            )
            methods = values(finding.get("methods") or [finding.get("method") or ""])
            endpoints = values(finding.get("endpoints") or [finding.get("endpoint") or ""])
            params = values(finding.get("params") or [finding.get("param") or ""])
            roles = values(finding.get("actor_roles") or finding.get("roles") or [
                finding.get("actor_role") or finding.get("affected_role") or "unknown"])
            rows = [{
                "asset_id": asset, "method": method, "endpoint": endpoint,
                "param": param, "actor_role": role,
                "namespace": finding.get("namespace") or "",
                "param_location": finding.get("param_location") or "",
                "subject_role": finding.get("subject_role") or "",
                "object_kind": finding.get("object_kind") or "",
            } for asset in assets for method in methods for endpoint in endpoints
              for param in params for role in roles]

        compatible: set[tuple[str, ...]] = set()
        for row in rows:
            row_method = str(row.get("method") or "").strip().upper()
            row_endpoint = str(
                row.get("endpoint") or row.get("path") or "").split("?", 1)[0]
            row_param = str(row.get("param") or "").strip()
            row_role = str(
                row.get("actor_role") or row.get("role_scope") or "unknown").strip().lower()
            row_asset = canonical_asset(str(
                row.get("asset_id") or row.get("asset") or ""))
            row_dimensions = {
                "namespace": str(row.get("namespace") or "").strip(),
                "param_location": str(row.get("param_location") or "").strip().lower(),
                "subject_role": str(row.get("subject_role") or "").strip().lower(),
                "object_kind": str(row.get("object_kind") or "").strip().lower(),
            }
            if surface_method and row_method != surface_method:
                continue
            if surface_endpoint and not (
                _template_path_matches(surface_endpoint, row_endpoint)
                or _template_path_matches(row_endpoint, surface_endpoint)
            ):
                continue
            if row_param != surface_param:
                continue
            if surface_roles and row_role not in surface_roles:
                continue
            if surface_asset and row_asset != surface_asset:
                continue
            if any(surface_dimensions[key]
                   and row_dimensions[key] != surface_dimensions[key]
                   for key in surface_dimensions):
                continue
            compatible.add((
                row_asset, row_method, row_endpoint, row_param, row_role,
                row_dimensions["namespace"], row_dimensions["param_location"],
                row_dimensions["subject_role"], row_dimensions["object_kind"],
            ))
        # Legacy surfaces may omit a newer dimension, but only a single exact
        # finding identity may satisfy that projection.  This keeps old runs
        # readable without letting one proof close path/query or app variants.
        if len(compatible) == 1:
            return True
    return False


def _exact_cell_keys(row: dict[str, Any], fallback_asset: str = "") -> set[str]:
    """Project runtime/plan rows onto the same v8.9 exact-cell identity."""
    try:
        try:
            from ..project_state import canonical_asset, canonical_project_cell_key
        except ImportError:  # pragma: no cover
            from project_state import canonical_asset, canonical_project_cell_key
        asset = canonical_asset(
            str(row.get("asset_id") or row.get("asset") or fallback_asset or ""))
        method = str(row.get("method") or "").strip().upper()
        path = str(row.get("endpoint") or row.get("path") or "").strip()
        vuln_class = str(
            row.get("vuln_class") or row.get("legacy_vuln")
            or row.get("class") or row.get("vuln") or "").strip()
        param = str(row.get("param") or "").strip()
        roles = row.get("actor_roles") or row.get("roles") or [
            row.get("actor_role") or row.get("role_scope") or "unknown"]
        if isinstance(roles, str):
            roles = [roles]
        if not asset or not method or not path or not vuln_class:
            return set()
        return {
            canonical_project_cell_key(
                asset,
                method=method,
                path=path,
                param=param,
                role_scope=str(role or "unknown"),
                vuln_class=vuln_class,
                namespace=str(row.get("namespace") or ""),
                param_location=str(row.get("param_location") or ""),
                subject_role=str(row.get("subject_role") or ""),
                object_kind=str(row.get("object_kind") or ""),
            )
            for role in roles
        }
    except (TypeError, ValueError):
        return set()


def _authority_plan_gate(
    context: ValidationContext | None,
    surfaces: list[Any],
) -> tuple[list[str], dict[str, Any]]:
    """Ensure session JSON cannot shrink the authority-frozen denominator."""
    manifest = context.manifest if context is not None else {}
    plan_text = str((manifest or {}).get("run_plan_path") or "").strip()
    project_id = str((manifest or {}).get("project_id") or "").strip()
    if not plan_text:
        return (["authority_run_plan_missing"] if project_id else []), {
            "required": bool(project_id), "planned": 0, "present": 0, "closed": 0,
        }
    try:
        plan = json.loads(safe_read_text(pathlib.Path(plan_text)))
    except (OSError, ValueError, json.JSONDecodeError):
        return ["authority_run_plan_invalid"], {
            "required": True, "planned": 0, "present": 0, "closed": 0,
        }
    rows = plan.get("admitted_cells") if isinstance(plan, dict) else None
    if not isinstance(rows, list):
        return ["authority_run_plan_invalid"], {
            "required": True, "planned": 0, "present": 0, "closed": 0,
        }
    fallback_asset = str((manifest or {}).get("primary_target") or "")
    planned: set[str] = set()
    reasons: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            reasons.append("authority_run_plan_cell_invalid")
            continue
        keys = _exact_cell_keys(row, fallback_asset)
        if not keys:
            reasons.append("authority_run_plan_cell_invalid")
            continue
        declared = str(row.get("cell_key") or "")
        if declared and declared not in keys:
            reasons.append("authority_run_plan_cell_key_mismatch")
        planned.update(keys)
    method_items = plan.get("method_resolution_items") if isinstance(plan, dict) else None
    if not isinstance(method_items, list) or any(
            not isinstance(item, dict) for item in method_items):
        reasons.append("authority_method_plan_invalid")
        method_items = []
    permitted_amendment_sources = {
        canonical_method_resolution_key(item, fallback_asset)
        for item in method_items
        if item.get("in_run_scope") is True
    }
    budget = plan.get("budget") if isinstance(plan, dict) else {}
    if not isinstance(budget, dict):
        reasons.append("authority_run_plan_budget_invalid")
        budget = {}
    try:
        surface_budget = int(budget.get("surface_budget", 0) or 0)
        allowed_cell_count = int(
            budget.get("allowed_cell_count", len(planned)) or 0)
    except (TypeError, ValueError):
        reasons.append("authority_run_plan_budget_invalid")
        surface_budget = allowed_cell_count = 0
    if allowed_cell_count != len(planned):
        reasons.append("authority_run_plan_allowed_count_mismatch")
    if surface_budget > 0 and (
            len(planned) > surface_budget or allowed_cell_count > surface_budget):
        reasons.append("authority_run_plan_budget_exceeded")
    in_scope_method_items = sum(
        1 for item in method_items if item.get("in_run_scope") is True)
    if (surface_budget > 0
            and len(planned) + in_scope_method_items > surface_budget):
        reasons.append("authority_method_plan_budget_exceeded")
    amendment_capacity = (
        max(0, surface_budget - allowed_cell_count)
        if surface_budget > 0 else None)
    amendment_cells: set[str] = set()
    authority_path_text = str((manifest or {}).get("authority_path") or "")
    if authority_path_text:
        authority_root = pathlib.Path(authority_path_text).parent.parent
        amendments = (
            authority_root / "events" /
            str((manifest or {}).get("session_id") or "") /
            "scope_amendment.jsonl"
        )
        if amendments.is_symlink():
            reasons.append("authority_scope_event_chain_invalid")
        elif amendments.is_file():
            previous = ""
            expected_sequence = 1
            try:
                for line in safe_read_text(amendments).splitlines():
                    record = json.loads(line)
                    supplied = str(record.get("event_sha256") or "")
                    canonical = dict(record)
                    canonical.pop("event_sha256", None)
                    if (int(record.get("sequence", 0) or 0) != expected_sequence
                            or str(record.get("previous_event_sha256") or "") != previous
                            or supplied != hashlib.sha256(json.dumps(
                                canonical, ensure_ascii=False, sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")).hexdigest()):
                        reasons.append("authority_scope_event_chain_invalid")
                        break
                    event = record.get("event") or {}
                    keys = _exact_cell_keys(event, fallback_asset)
                    if not keys:
                        reasons.append("authority_scope_event_cell_invalid")
                    else:
                        declared = str(event.get("cell_key") or "")
                        if declared and declared not in keys:
                            reasons.append("authority_scope_event_cell_key_mismatch")
                        source_key = canonical_method_resolution_key(
                            event, fallback_asset)
                        if source_key not in permitted_amendment_sources:
                            reasons.append(
                                "authority_scope_event_not_from_frozen_method_item")
                        elif (amendment_capacity is not None
                              and len(amendment_cells | keys) > amendment_capacity):
                            # Each frozen unresolved item consumes one unit of
                            # the pre-network surface budget.  A model-visible
                            # discovery stream cannot fan that item out into an
                            # unbounded denominator after the plan is frozen.
                            reasons.append("authority_scope_event_budget_exceeded")
                        else:
                            amendment_cells.update(keys)
                            planned.update(keys)
                    previous = supplied
                    expected_sequence += 1
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                reasons.append("authority_scope_event_chain_invalid")
    present: set[str] = set()
    closed: set[str] = set()
    terminal = {"confirmed", "not_vulnerable", "not_applicable"}
    for surface in surfaces:
        if not isinstance(surface, dict) or surface.get("in_run_scope") is False:
            continue
        keys = _exact_cell_keys(surface, fallback_asset)
        present.update(keys)
        if str(surface.get("status") or "").strip().lower() in terminal:
            closed.update(keys)
    if planned - present:
        reasons.append("authority_run_plan_cells_missing")
    if planned - closed:
        reasons.append("authority_run_plan_cells_open")
    return reasons, {
        "required": True,
        "planned": len(planned),
        "present": len(planned & present),
        "closed": len(planned & closed),
        "missing": sorted(planned - present),
        "open": sorted(planned - closed),
    }


def _authority_candidate_gate(context: ValidationContext | None) -> list[str]:
    manifest = context.manifest if context is not None else {}
    plan_text = str((manifest or {}).get("run_plan_path") or "").strip()
    if not plan_text:
        return []
    try:
        plan = json.loads(safe_read_text(pathlib.Path(plan_text)))
    except (OSError, ValueError, json.JSONDecodeError):
        return ["authority_candidate_state_invalid"]
    latest: dict[str, str] = {}
    for item in plan.get("candidate_baseline") or []:
        if isinstance(item, dict) and item.get("candidate_id"):
            latest[str(item["candidate_id"])] = str(item.get("status") or "")
    authority_path = str((manifest or {}).get("authority_path") or "")
    if authority_path:
        event_path = (
            pathlib.Path(authority_path).parent.parent / "events" /
            str((manifest or {}).get("session_id") or "") / "candidate.jsonl"
        )
        if event_path.is_symlink():
            return ["authority_candidate_event_chain_invalid"]
        if event_path.is_file():
            previous = ""
            sequence = 1
            try:
                for line in safe_read_text(event_path).splitlines():
                    record = json.loads(line)
                    supplied = str(record.get("event_sha256") or "")
                    canonical = dict(record)
                    canonical.pop("event_sha256", None)
                    digest = hashlib.sha256(json.dumps(
                        canonical, ensure_ascii=False, sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")).hexdigest()
                    if (int(record.get("sequence", 0) or 0) != sequence
                            or str(record.get("previous_event_sha256") or "") != previous
                            or supplied != digest):
                        return ["authority_candidate_event_chain_invalid"]
                    candidate = ((record.get("event") or {}).get("candidate") or {})
                    candidate_id = str(candidate.get("candidate_id") or "")
                    if not candidate_id:
                        return ["authority_candidate_event_invalid"]
                    latest[candidate_id] = str(candidate.get("status") or "")
                    previous = supplied
                    sequence += 1
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                return ["authority_candidate_event_chain_invalid"]
    if any(status in {"proof_ready", "confirmed"} for status in latest.values()):
        return ["authority_proof_ready_candidate_open"]
    return []


def _authority_method_resolution_gate(
    context: ValidationContext | None,
    endpoints: list[Any],
    unresolved: list[Any],
) -> list[str]:
    """Bind unknown-method backlog closure to the immutable run plan.

    Out-of-budget hints remain project backlog and do not block this run.  A
    planned hint may disappear from ``inventory.unresolved`` only after the
    parent-owned discovery event chain attests a concrete HTTP method and the
    resolved row is present in inventory.
    """
    manifest = context.manifest if context is not None else {}
    plan_text = str((manifest or {}).get("run_plan_path") or "").strip()
    fallback_asset = str((manifest or {}).get("primary_target") or "")
    if not plan_text:
        # Legacy sessions have no authority denominator, so no session-owned
        # in_run_scope=false flag is trusted to suppress unresolved work.
        return ["inventory_unresolved_open"] if unresolved else []
    try:
        plan = json.loads(safe_read_text(pathlib.Path(plan_text)))
    except (OSError, ValueError, json.JSONDecodeError):
        return ["authority_method_plan_invalid"]
    rows = plan.get("method_resolution_items") if isinstance(plan, dict) else None
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        return ["authority_method_plan_invalid"]

    reasons: list[str] = []

    def _key(row: dict[str, Any]) -> str:
        return canonical_method_resolution_key(row, fallback_asset)

    planned_keys = {_key(row) for row in rows}
    if len(planned_keys) != len(rows):
        reasons.append("authority_method_plan_duplicate")
    for row in rows:
        try:
            identity = json.loads(_key(row))
        except json.JSONDecodeError:
            identity = {}
        if (not identity.get("asset") or not identity.get("endpoint")
                or row.get("in_run_scope") is not True):
            reasons.append("authority_method_plan_invalid")

    unresolved_keys: set[str] = set()
    for row in unresolved:
        if not isinstance(row, dict):
            reasons.append("inventory_unresolved_invalid")
            continue
        key = _key(row)
        unresolved_keys.add(key)
        expected_scope = key in planned_keys
        if row.get("in_run_scope") is not expected_scope:
            reasons.append("authority_method_scope_mismatch")

    endpoint_keys = {
        _key(row) for row in endpoints
        if isinstance(row, dict)
        and str(row.get("method") or "").strip().upper() in {
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
        }
    }

    attested_resolved: set[str] = set()
    authority_path = str((manifest or {}).get("authority_path") or "")
    if authority_path:
        event_path = (
            pathlib.Path(authority_path).parent.parent / "events" /
            str((manifest or {}).get("session_id") or "") / "discovery.jsonl"
        )
        if event_path.is_symlink():
            reasons.append("authority_discovery_event_chain_invalid")
        elif event_path.is_file():
            previous = ""
            sequence = 1
            try:
                for line in safe_read_text(event_path).splitlines():
                    record = json.loads(line)
                    supplied = str(record.get("event_sha256") or "")
                    canonical = dict(record)
                    canonical.pop("event_sha256", None)
                    digest = hashlib.sha256(json.dumps(
                        canonical, ensure_ascii=False, sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")).hexdigest()
                    if (int(record.get("sequence", 0) or 0) != sequence
                            or str(record.get("previous_event_sha256") or "") != previous
                            or supplied != digest):
                        reasons.append("authority_discovery_event_chain_invalid")
                        break
                    event = record.get("event") or {}
                    surface = event.get("surface") if isinstance(event, dict) else None
                    if isinstance(surface, dict) and str(
                            surface.get("method") or "").strip().upper() in {
                                "GET", "POST", "PUT", "PATCH", "DELETE",
                                "HEAD", "OPTIONS",
                            }:
                        attested_resolved.add(_key(surface))
                    previous = supplied
                    sequence += 1
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                reasons.append("authority_discovery_event_chain_invalid")

    for key in planned_keys:
        if key in unresolved_keys:
            reasons.append("inventory_unresolved_open")
        elif key not in endpoint_keys:
            reasons.append("authority_method_item_missing")
        elif key not in attested_resolved:
            reasons.append("authority_method_resolution_unattested")
    return reasons


_EVIDENCE_CELL_DIMENSIONS = {
    "namespace", "param_location", "subject_role", "object_kind",
}


def _evidence_cell_complete(cell: dict[str, Any]) -> bool:
    return bool(
        isinstance(cell, dict)
        and (cell.get("asset_id") or cell.get("asset"))
        and str(cell.get("method") or "").upper() in {
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
        }
        and (cell.get("endpoint") or cell.get("path"))
        and "param" in cell
        and any(key in cell for key in ("actor_role", "role_scope", "role"))
        and any(key in cell for key in ("vuln_class", "class", "vuln"))
        and _EVIDENCE_CELL_DIMENSIONS.issubset(cell)
    )


def _inline_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _machine_assertion_passes(
    assertion: dict[str, Any], request_text: str, response_text: str,
) -> bool:
    target = str(assertion.get("target") or assertion.get("file") or "").strip().lower()
    if target in {"request", "request_file", "request.http"}:
        text = request_text
    elif target in {"response", "response_file", "response.http"}:
        text = response_text
    else:
        return False
    relation = str(assertion.get("relation") or "contains").strip().lower()
    value = str(assertion.get("value") or "")
    if len(value) < 4:
        return False
    if relation == "contains":
        return value in text
    if relation == "not_contains":
        return value not in text
    if relation == "regex":
        try:
            return re.search(value, text, re.M) is not None
        except re.error:
            return False
    return False


def _identity_assertions_pass(
    cell: dict[str, Any], assertions: Any,
    request_text: str, response_text: str,
) -> bool:
    if not isinstance(assertions, dict):
        assertions = {}
    required = {
        "actor_role": str(
            cell.get("actor_role") or cell.get("role_scope") or "unknown"
        ).strip().lower(),
        "subject_role": str(cell.get("subject_role") or "").strip().lower(),
        "object_kind": str(cell.get("object_kind") or "").strip().lower(),
    }
    if required["actor_role"] in {"", "unknown", "anonymous", "anon"}:
        required["actor_role"] = ""
    for dimension, value in required.items():
        if not value:
            continue
        assertion = assertions.get(dimension)
        if not isinstance(assertion, dict):
            return False
        marker = str(assertion.get("value") or "").strip().lower()
        if value not in marker:
            return False
        if not _machine_assertion_passes(
                assertion, request_text, response_text):
            return False
    return True


def _load_packet_text(
    packet: dict[str, Any], key: str, envelope_path: pathlib.Path,
    allowed_root: pathlib.Path,
) -> tuple[str, pathlib.Path | None]:
    inline = packet.get(key)
    if isinstance(inline, str) and inline:
        return inline, None
    ref = str(packet.get(f"{key}_file") or "").strip()
    if not ref:
        return "", None
    raw = pathlib.Path(ref)
    candidate = raw if raw.is_absolute() else envelope_path.parent / raw
    current = candidate
    while current != allowed_root and current != current.parent:
        if current.is_symlink():
            return "", None
        current = current.parent
    try:
        path = resolve_finding_file(envelope_path.parent, ref, allowed_root)
    except ValueError:
        return "", None
    if path.is_symlink() or not path.is_file():
        return "", None
    return _read_text(path), path


def _validate_evidence_envelope(
    envelope_path: pathlib.Path,
    expected_cell: dict[str, Any],
    *,
    expected_kind: str,
    allowed_root: pathlib.Path,
    context: ValidationContext | None,
) -> tuple[bool, dict[str, Any], dict[str, str]]:
    """Verify a portable negative/dead-end evidence packet.

    The envelope carries raw HTTP (inline or by safe relative reference), exact
    cell identity, SHA-256 bindings and executable assertions.  Counts and
    vector labels are derived from validated packets; ledger prose is ignored.
    """
    try:
        document = envelope_path.read_text(encoding="utf-8")
    except OSError:
        return False, {}, {}
    try:
        envelope = json.loads(document)
    except json.JSONDecodeError:
        # Engine Mode already harvests negative_*.md.  A marked JSON block lets
        # that established channel carry the same strict portable contract;
        # surrounding prose/frontmatter never enters the trusted object.
        match = re.search(
            r"<machine_evidence>\s*(\{.*?\})\s*</machine_evidence>",
            document, re.S)
        if not match:
            return False, {}, {}
        try:
            envelope = json.loads(match.group(1))
        except json.JSONDecodeError:
            return False, {}, {}
    if (not isinstance(envelope, dict)
            or str(envelope.get("schema_version") or "") not in {"1", "1.0"}
            or str(envelope.get("kind") or "") != expected_kind):
        return False, {}, {}
    exact_cell = envelope.get("exact_cell")
    if not isinstance(exact_cell, dict) or not _evidence_cell_complete(exact_cell):
        return False, {}, {}
    expected_keys = _exact_cell_keys(expected_cell, "")
    envelope_keys = _exact_cell_keys(exact_cell, "")
    if not expected_keys or envelope_keys != expected_keys:
        return False, {}, {}
    packets = envelope.get("packets")
    if not isinstance(packets, list) or not packets:
        return False, {}, {}

    vectors: set[str] = set()
    request_hashes: set[str] = set()
    response_hashes: set[str] = set()
    artifacts: dict[str, str] = {}
    barrier_signals = {
        str(value or "").strip().lower()
        for value in (envelope.get("barrier_signals") or [])
        if str(value or "").strip()
    }
    preconditions = (
        dict(envelope.get("preconditions"))
        if isinstance(envelope.get("preconditions"), dict) else {}
    )
    encoding_families, strategy_families = families_from_packets(packets)
    try:
        relative_envelope = envelope_path.resolve().relative_to(
            allowed_root.resolve()).as_posix()
    except ValueError:
        return False, {}, {}
    artifacts[relative_envelope] = _sha256_file(envelope_path)

    for packet in packets:
        if not isinstance(packet, dict):
            return False, {}, {}
        packet_cell = packet.get("exact_cell") or exact_cell
        if (not isinstance(packet_cell, dict)
                or not _evidence_cell_complete(packet_cell)
                or _exact_cell_keys(packet_cell, "") != expected_keys):
            return False, {}, {}
        request_text, request_path = _load_packet_text(
            packet, "request", envelope_path, allowed_root)
        response_text, response_path = _load_packet_text(
            packet, "response", envelope_path, allowed_root)
        request_hash = str(packet.get("request_sha256") or "").strip().lower()
        response_hash = str(packet.get("response_sha256") or "").strip().lower()
        if (not request_text or not response_text
                or not re.fullmatch(r"[0-9a-f]{64}", request_hash)
                or not re.fullmatch(r"[0-9a-f]{64}", response_hash)
                or _inline_sha256(request_text) != request_hash
                or _inline_sha256(response_text) != response_hash):
            return False, {}, {}
        components = _request_components(
            request_text, context=context,
            finding_target=str(exact_cell.get("asset_id") or exact_cell.get("asset") or ""))
        if (not _cell_matches_raw_request(exact_cell, components)
                or HTTP_STATUS.search(response_text) is None):
            return False, {}, {}
        if context is not None:
            target = f"{components.get('asset_id')}{components.get('path')}"
            if not context.allows(target):
                return False, {}, {}
        vector = str(packet.get("vector") or "").strip().lower()
        assertions = packet.get("assertions")
        if (not vector or not isinstance(assertions, list) or not assertions
                or any(not isinstance(item, dict)
                       or not _machine_assertion_passes(
                           item, request_text, response_text)
                       for item in assertions)):
            return False, {}, {}
        identity_assertions = (
            packet.get("identity_assertions")
            if packet.get("identity_assertions") is not None
            else envelope.get("identity_assertions")
        )
        if not _identity_assertions_pass(
                exact_cell, identity_assertions, request_text, response_text):
            return False, {}, {}
        vectors.add(vector)
        response_lower = response_text.lower()
        if re.search(
            r"(?:\bwaf\b|blocked\s+by|illegal\s+keyword|"
            r"检测到非法关键字|请求被拦截|非法关键字)",
            response_lower,
        ):
            barrier_signals.add("waf_blocked")
        if re.search(
            r"(?:session\s+expired|login\s+required|auth(?:entication)?\s+required|"
            r"请先登录|登录已过期|会话已过期)",
            response_lower,
        ):
            barrier_signals.add("session_expired")
        request_hashes.add(request_hash)
        response_hashes.add(response_hash)
        for physical in (request_path, response_path):
            if physical is not None:
                relative = physical.resolve().relative_to(
                    allowed_root.resolve()).as_posix()
                artifacts[relative] = _sha256_file(physical)

    return True, {
        # A copied request cannot manufacture another independent vector.
        "vectors": sorted(vectors) if len(vectors) == len(request_hashes) else [],
        "response_count": len(response_hashes),
        "evidence_types": list(envelope.get("evidence_types") or []),
        "identities": list(envelope.get("identities") or []),
        "roles": list(envelope.get("roles") or []),
        "barrier_signals": sorted(barrier_signals),
        "preconditions": preconditions,
        "encoding_families": encoding_families,
        "strategy_families": strategy_families,
    }, artifacts


def _project_evidence_path(
    project_dir: pathlib.Path, ref: str,
) -> pathlib.Path | None:
    text = str(ref or "").strip()
    if text.startswith("session:"):
        payload = text[len("session:"):]
        session_id, separator, relative = payload.partition("/")
        if (not separator or not session_id or ".." in pathlib.Path(relative).parts):
            return None
        candidate = project_dir / "sessions" / session_id / relative
    elif text.startswith("project:"):
        relative = text[len("project:"):]
        if not relative or ".." in pathlib.Path(relative).parts:
            return None
        candidate = project_dir / relative
    else:
        return None
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(project_dir.resolve())
    except (OSError, ValueError):
        return None
    current = candidate
    while current != project_dir and current != current.parent:
        if current.is_symlink():
            return None
        current = current.parent
    return resolved if resolved.is_file() else None


def _validate_project_evidence_envelopes(
    project_dir: pathlib.Path,
    refs: list[Any],
    expected_cell: dict[str, Any],
    *,
    expected_kind: str,
    context: ValidationContext | None,
) -> tuple[bool, dict[str, Any]]:
    vectors: set[str] = set()
    response_count = 0
    evidence_types: set[str] = set()
    identities: set[str] = set()
    roles: set[str] = set()
    barrier_signals: set[str] = set()
    preconditions: dict[str, bool] = {}
    encoding_families: set[str] = set()
    strategy_families: set[str] = set()
    if not refs:
        return False, {}
    for ref in refs:
        path = _project_evidence_path(project_dir, str(ref or ""))
        if path is None:
            return False, {}
        ok, derived, _artifacts = _validate_evidence_envelope(
            path, expected_cell, expected_kind=expected_kind,
            allowed_root=project_dir, context=context)
        if not ok:
            return False, {}
        vectors.update(str(value) for value in derived.get("vectors") or [])
        response_count += int(derived.get("response_count", 0) or 0)
        evidence_types.update(
            str(value) for value in derived.get("evidence_types") or [])
        identities.update(str(value) for value in derived.get("identities") or [])
        roles.update(str(value) for value in derived.get("roles") or [])
        barrier_signals.update(
            str(value) for value in derived.get("barrier_signals") or [])
        encoding_families.update(
            str(value) for value in derived.get("encoding_families") or [])
        strategy_families.update(
            str(value) for value in derived.get("strategy_families") or [])
        for key, value in (derived.get("preconditions") or {}).items():
            preconditions[str(key)] = (
                value is True and preconditions.get(str(key), True))
    return True, {
        "vectors": sorted(vectors), "response_count": response_count,
        "evidence_types": sorted(evidence_types),
        "identities": sorted(identities), "roles": sorted(roles),
        "barrier_signals": sorted(barrier_signals),
        "preconditions": preconditions,
        "encoding_families": sorted(encoding_families),
        "strategy_families": sorted(strategy_families),
    }


def _validated_dead_end_keys(
    run_dir: pathlib.Path,
    context: ValidationContext | None,
) -> tuple[set[str], list[str], dict[str, str]]:
    """Validate evidence-attested exact-cell ``not_applicable`` packets."""
    path = run_dir / "dead_ends.json"
    if not path.exists():
        return set(), [], {}
    if path.is_symlink() or not path.is_file():
        return set(), ["dead_end_contract_invalid"], {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set(), ["dead_end_contract_invalid"], {}
    rows = value.get("dead_ends") if isinstance(value, dict) else value
    if not isinstance(rows, list):
        return set(), ["dead_end_contract_invalid"], {}
    try:
        try:
            from ..project_state import DEAD_END_REASON_CODES, canonical_asset
        except ImportError:  # pragma: no cover
            from project_state import DEAD_END_REASON_CODES, canonical_asset
    except ImportError:  # pragma: no cover - standalone defensive fallback
        return set(), ["dead_end_contract_invalid"], {}

    expected_run = str(
        ((context.manifest or {}).get("session_id") if context else "")
        or run_dir.name
    )
    root = run_dir.resolve()
    valid_keys: set[str] = set()
    reasons: list[str] = []
    artifact_hashes: dict[str, str] = {}
    dimension_fields = {
        "namespace", "param_location", "subject_role", "object_kind",
    }
    for row in rows:
        if not isinstance(row, dict):
            reasons.append("dead_end_contract_invalid")
            continue
        reason_code = str(row.get("reason_code") or "").strip()
        role_present = any(
            key in row for key in ("role_scope", "role", "actor_role"))
        vuln_present = any(
            key in row for key in ("vuln_class", "class", "vuln"))
        asset_text = str(row.get("asset_id") or row.get("asset") or "").strip()
        method = str(row.get("method") or "").strip().upper()
        endpoint = str(row.get("endpoint") or row.get("path") or "").strip()
        if (str(row.get("status") or "").strip() != "not_applicable"
                or reason_code not in DEAD_END_REASON_CODES
                or not str(row.get("refutation") or "").strip()
                or str(row.get("source_run") or "").strip() != expected_run
                or not asset_text or not canonical_asset(asset_text)
                or method not in {
                    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
                }
                or not endpoint or "param" not in row
                or not role_present or not vuln_present
                or not dimension_fields.issubset(row)):
            reasons.append("dead_end_contract_invalid")
            continue
        refs = list(row.get("evidence_refs") or [])
        if row.get("evidence_ref"):
            refs.append(row["evidence_ref"])
        refs = list(dict.fromkeys(str(ref or "").strip() for ref in refs if str(ref or "").strip()))
        if not refs:
            reasons.append("dead_end_evidence_missing")
            continue
        evidence_ok = True
        for ref in refs:
            relative = ref
            if ref.startswith("session:"):
                payload = ref[len("session:"):]
                sid, separator, relative = payload.partition("/")
                if not separator or sid != expected_run:
                    evidence_ok = False
                    break
            elif ref.startswith("project:") or pathlib.Path(ref).is_absolute():
                evidence_ok = False
                break
            if ".." in pathlib.Path(relative).parts:
                evidence_ok = False
                break
            candidate = run_dir / relative
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(root)
            except (OSError, ValueError):
                evidence_ok = False
                break
            current = candidate
            while current != run_dir and current != current.parent:
                if current.is_symlink():
                    evidence_ok = False
                    break
                current = current.parent
            if not evidence_ok or not resolved.is_file():
                evidence_ok = False
                break
            envelope_ok, _derived, artifacts = _validate_evidence_envelope(
                resolved, row, expected_kind="dead_end_evidence",
                allowed_root=run_dir, context=context)
            if not envelope_ok:
                evidence_ok = False
                break
            artifact_hashes.update(artifacts)
        if not evidence_ok:
            reasons.append("dead_end_evidence_invalid")
            continue
        keys = _exact_cell_keys(row, "")
        if not keys:
            reasons.append("dead_end_exact_cell_invalid")
            continue
        valid_keys.update(keys)
    return valid_keys, reasons, artifact_hashes


def _threat_model_closure_gate(
    run_dir: pathlib.Path,
    *,
    context: ValidationContext | None,
    inventory_rows: list[Any],
    surfaces: list[Any],
    normalized_findings: list[dict[str, Any]],
) -> tuple[list[str], dict[str, str], dict[str, Any]]:
    manifest = (context.manifest if context else None) or {}
    if str(manifest.get("planning_mode") or "legacy_risk") != "threat_model":
        return [], {}, {}
    reasons: list[str] = []
    hashes: dict[str, str] = {}
    stats: dict[str, Any] = {}
    graph_path = run_dir / "feature-graph.json"
    model_path = run_dir / "threat-model.json"
    coverage_path = run_dir / "threat-coverage.json"
    values: dict[str, dict[str, Any]] = {}
    for name, path in (
        ("feature-graph.json", graph_path),
        ("threat-model.json", model_path),
        ("threat-coverage.json", coverage_path),
    ):
        try:
            payload = safe_read_bytes(path, root=run_dir)
            value = json.loads(payload.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("must be an object")
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            reasons.append(f"threat_artifact_missing_or_invalid:{name}:{exc}")
            continue
        values[name] = value
        hashes[name] = hashlib.sha256(payload).hexdigest()
    if set(values) != {
            "feature-graph.json", "threat-model.json", "threat-coverage.json"}:
        return reasons, hashes, stats
    try:
        try:
            from ..threat_model import (
                compile_threat_model,
                derive_threat_coverage,
                validate_threat_plan,
            )
        except ImportError:  # pragma: no cover
            from threat_model import (compile_threat_model,
                                      derive_threat_coverage,
                                      validate_threat_plan)
        plan = validate_threat_plan(
            values["feature-graph.json"],
            values["threat-model.json"],
            inventory_rows,
            run_dir=run_dir,
            base_path=str(manifest.get("base_path") or "/"),
            base_path_explicit=bool(manifest.get("base_path_explicit")),
            allow_paths=list(manifest.get("allow_paths") or []),
            deny_paths=list(manifest.get("deny_paths") or []),
            require_discovery_adequacy=True,
        )
        expected = compile_threat_model(
            plan,
            inventory_rows,
            target=str(manifest.get("primary_target") or ""),
        )
    except Exception as exc:  # noqa: BLE001 - gate converts all plan errors
        reasons.append(f"threat_plan_invalid:{type(exc).__name__}:{exc}")
        return reasons, hashes, stats

    actual = [row for row in surfaces if isinstance(row, dict)]
    expected_by_id = {str(row.get("surface_id") or ""): row for row in expected}
    actual_by_id = {str(row.get("surface_id") or ""): row for row in actual}
    if (len(expected_by_id) != len(expected)
            or len(actual_by_id) != len(actual)
            or set(expected_by_id) != set(actual_by_id)):
        reasons.append("threat_compiled_cell_set_mismatch")
    dimensions = (
        "feature_id", "threat_id", "endpoint", "method", "param",
        "param_location", "actor_role", "vuln_class", "security_invariant",
        "observable_violation",
    )
    for surface_id in sorted(set(expected_by_id) & set(actual_by_id)):
        expected_row = expected_by_id[surface_id]
        actual_row = actual_by_id[surface_id]
        if any(
            str(actual_row.get(key) or "").strip().lower()
            != str(expected_row.get(key) or "").strip().lower()
            for key in dimensions
        ):
            reasons.append("threat_compiled_cell_identity_mismatch")
            break

    identity_path = run_dir / "identity-readiness.json"
    identity_required = (
        str(manifest.get("run_phase") or "single") == "attack"
        or "identity-readiness.json" in (manifest.get("planning_artifacts") or {})
    )
    try:
        identity_value = json.loads(
            safe_read_bytes(identity_path, root=run_dir).decode("utf-8"))
        if not isinstance(identity_value, dict):
            raise ValueError("identity-readiness must be an object")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        identity_value = {}
        if identity_required:
            reasons.append(f"identity_readiness_missing_or_invalid:{exc}")
    readiness = {
        (str(item.get("feature_id") or ""), str(item.get("threat_id") or "")): item
        for item in identity_value.get("threats", [])
        if isinstance(item, dict)
    }
    terminal = {"confirmed", "not_vulnerable", "not_applicable"}
    for surface_id, expected_row in expected_by_id.items():
        pair = (
            str(expected_row.get("feature_id") or ""),
            str(expected_row.get("threat_id") or ""),
        )
        requirement = expected_row.get("identity_requirement") or {}
        minimum = int(requirement.get("minimum_distinct_credentials", 0) or 0)
        mode = str(requirement.get("mode") or "single")
        readiness_item = readiness.get(pair)
        if readiness_item is None:
            if minimum > 0 or mode != "single":
                reasons.append("identity_readiness_threat_missing")
            continue
        actual_row = actual_by_id.get(surface_id) or {}
        if (not readiness_item.get("ready")
                and str(actual_row.get("status") or "") in terminal):
            reasons.append("identity_unready_threat_closed")
            break

    plan_path = pathlib.Path(str(manifest.get("run_plan_path") or ""))
    try:
        plan_payload = safe_read_bytes(
            plan_path, root=plan_path.parent.parent)
        run_plan = json.loads(plan_payload.decode("utf-8"))
        admitted = run_plan.get("admitted_cells") if isinstance(run_plan, dict) else None
        if not isinstance(admitted, list):
            raise ValueError("admitted_cells must be a list")
        frozen_identities = {
            (
                str(row.get("surface_id") or ""),
                str(row.get("feature_id") or ""),
                str(row.get("threat_id") or ""),
            )
            for row in admitted if isinstance(row, dict)
        }
        expected_identities = {
            (
                str(row.get("surface_id") or ""),
                str(row.get("feature_id") or ""),
                str(row.get("threat_id") or ""),
            )
            for row in expected
        }
        if frozen_identities != expected_identities:
            reasons.append("threat_run_plan_mismatch")
        admitted_by_surface = {
            str(row.get("surface_id") or ""): row
            for row in admitted if isinstance(row, dict)
        }
        for surface_id, expected_row in expected_by_id.items():
            frozen_row = admitted_by_surface.get(surface_id) or {}
            pair = (
                str(expected_row.get("feature_id") or ""),
                str(expected_row.get("threat_id") or ""),
            )
            ready_item = readiness.get(pair) or {}
            if (frozen_row.get("identity_requirement") or {}) != (
                    expected_row.get("identity_requirement") or {}):
                reasons.append("threat_run_plan_identity_requirement_mismatch")
                break
            if frozen_row.get("identity_ready") is not ready_item.get("ready"):
                reasons.append("threat_run_plan_identity_readiness_mismatch")
                break
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        reasons.append(f"threat_run_plan_invalid:{exc}")

    derived = derive_threat_coverage(actual, values["threat-model.json"])
    stats = dict(derived.get("stats") or {})
    if derived != values["threat-coverage.json"]:
        reasons.append("threat_coverage_projection_mismatch")
    if (int(stats.get("open_threats", 0) or 0) != 0
            or int(stats.get("open_features", 0) or 0) != 0):
        reasons.append("threat_coverage_open")
    if int(stats.get("threats", 0) or 0) != sum(
        len(item.get("threats") or [])
        for item in values["threat-model.json"].get("features") or []
        if isinstance(item, dict)
    ):
        reasons.append("threat_coverage_count_mismatch")

    declared_pairs = {
        (str(feature.get("feature_id") or ""), str(threat.get("threat_id") or ""))
        for feature in values["threat-model.json"].get("features") or []
        if isinstance(feature, dict)
        for threat in feature.get("threats") or []
        if isinstance(threat, dict)
    }
    confirmed_pairs = {
        (str(row.get("feature_id") or ""), str(row.get("threat_id") or ""))
        for row in actual if str(row.get("status") or "") == "confirmed"
    }
    for finding in normalized_findings:
        pair = (
            str(finding.get("feature_id") or ""),
            str(finding.get("threat_id") or ""),
        )
        if pair not in declared_pairs or pair not in confirmed_pairs:
            reasons.append("finding_threat_binding_mismatch")
            break
    return reasons, hashes, stats


def _run_closure_gate(
    run_dir: pathlib.Path,
    context: ValidationContext | None = None,
    *,
    normalized_findings: list[dict[str, Any]] | None = None,
    rejected_findings: list[dict[str, Any]] | None = None,
    source_run_dir: pathlib.Path | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    http_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    terminal_statuses = {"confirmed", "not_vulnerable", "not_applicable"}
    project_dir = (run_dir.parent.parent
                   if run_dir.parent.name == "sessions" else run_dir)
    expected_project_state = (project_dir / "project_state.json").resolve(strict=False)
    source_run = (source_run_dir or run_dir).resolve()
    source_project_dir = (
        source_run.parent.parent
        if source_run.parent.name == "sessions" else source_run
    )
    declared_project_state = (
        source_project_dir / "project_state.json").resolve(strict=False)
    dead_end_keys, dead_end_reasons, closure_artifact_hashes = (
        _validated_dead_end_keys(run_dir, context))
    reasons.extend(dead_end_reasons)
    endpoints: list[Any] = []
    unresolved: list[Any] = []
    try:
        inventory = json.loads((run_dir / "inventory.json").read_text(encoding="utf-8"))
        endpoints = inventory.get("endpoints") if isinstance(inventory, dict) else inventory
        if not isinstance(endpoints, list) or not endpoints:
            reasons.append("inventory_empty")
        if isinstance(inventory, dict):
            unresolved = inventory.get("unresolved") or []
            if not isinstance(unresolved, list):
                reasons.append("inventory_unresolved_invalid")
                unresolved = []
    except (OSError, json.JSONDecodeError):
        reasons.append("inventory_missing_or_invalid")
    if any(
        not _inventory_item_authorized(item, context)
        for item in [
            *(endpoints if isinstance(endpoints, list) else []),
            *(unresolved if isinstance(unresolved, list) else []),
        ]
    ):
        reasons.append("inventory_asset_out_of_scope")
    ledger_path = run_dir / "coverage-ledger.json"
    surfaces: list[Any] = []
    ledger_value: dict[str, Any] = {}
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
                    if surface.get("in_run_scope") is False:
                        continue
                    if status not in terminal_statuses:
                        reasons.append("coverage_not_closed")
                    if status == "confirmed":
                        current_ok = _surface_has_current_finding(
                            surface, normalized_findings or [], run_dir,
                            source_run_dir=source_run)
                        historical_ok = False
                        evidence_ref = str(surface.get("evidence_ref") or "").strip()
                        evidence_path = pathlib.Path(evidence_ref) if evidence_ref else None
                        if (evidence_path is not None and evidence_path.is_absolute()
                                and evidence_path.name == "project_state.json"
                                and evidence_path.resolve(strict=False) == declared_project_state
                                and expected_project_state.is_file()
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
                                project = json.loads(expected_project_state.read_text(
                                    encoding="utf-8"))
                                asset = next(iter(project.get("project_scope") or []), "")
                                manifest_asset = canonical_asset(context.primary_target)
                                identity_ok = (
                                    bool(asset and manifest_asset)
                                    and canonical_asset(asset) == manifest_asset
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
                                        namespace=str(surface.get("namespace") or ""),
                                        param_location=str(
                                            surface.get("param_location") or ""),
                                        subject_role=str(
                                            surface.get("subject_role") or ""),
                                        object_kind=str(
                                            surface.get("object_kind") or ""),
                                    )
                                    prior = (project.get("cell_registry") or {}).get(key) or {}
                                    if (prior.get("status") != "confirmed"
                                            or not verify_project_evidence(
                                                expected_project_state.parent,
                                                list(prior.get("evidence_refs") or []),
                                                dict(prior.get("evidence_hashes") or {}))):
                                        historical_ok = False
                                        break
                            except (OSError, ValueError, json.JSONDecodeError):
                                historical_ok = False
                        if not (current_ok or historical_ok):
                            reasons.append("confirmed_coverage_without_canonical_finding")
                    if status == "not_applicable":
                        if not str(surface.get("reason") or "").strip():
                            reasons.append("not_applicable_reason_missing")
                        surface_keys = _exact_cell_keys(
                            surface,
                            str((context.manifest or {}).get("primary_target") or "")
                            if context else "",
                        )
                        historical_dead_end = False
                        evidence_ref = str(surface.get("evidence_ref") or "").strip()
                        evidence_path = pathlib.Path(evidence_ref) if evidence_ref else None
                        if (surface_keys and evidence_path is not None
                                and evidence_path.is_absolute()
                                and evidence_path.name == "project_state.json"
                                and evidence_path.resolve(strict=False)
                                == declared_project_state
                                and expected_project_state.is_file()
                                and context is not None):
                            try:
                                try:
                                    from ..project_state import (
                                        DEAD_END_REASON_CODES,
                                        canonical_asset,
                                        verify_project_evidence,
                                    )
                                except ImportError:  # pragma: no cover
                                    from project_state import (
                                        DEAD_END_REASON_CODES,
                                        canonical_asset,
                                        verify_project_evidence,
                                    )
                                project = json.loads(expected_project_state.read_text(
                                    encoding="utf-8"))
                                manifest_asset = canonical_asset(context.primary_target)
                                scope_assets = {
                                    canonical_asset(value)
                                    for value in (project.get("project_scope") or [])
                                }
                                historical_dead_end = bool(
                                    manifest_asset and manifest_asset in scope_assets)
                                registry = project.get("cell_registry") or {}
                                for key in surface_keys:
                                    prior = registry.get(key) or {}
                                    if (prior.get("status") != "not_applicable"
                                            or prior.get("reason_code")
                                            not in DEAD_END_REASON_CODES
                                            or not str(prior.get("refutation") or "").strip()
                                            or not verify_project_evidence(
                                                expected_project_state.parent,
                                                list(prior.get("evidence_refs") or []),
                                                dict(prior.get("evidence_hashes") or {}))
                                            or not _validate_project_evidence_envelopes(
                                                expected_project_state.parent,
                                                list(prior.get("evidence_refs") or []),
                                                surface,
                                                expected_kind="dead_end_evidence",
                                                context=context,
                                            )[0]):
                                        historical_dead_end = False
                                        break
                            except (OSError, ValueError, json.JSONDecodeError):
                                historical_dead_end = False
                        if (not surface_keys
                                or (not surface_keys.issubset(dead_end_keys)
                                    and not historical_dead_end)):
                            reasons.append("not_applicable_contract_missing")
                    if status == "not_vulnerable":
                        negative = surface.get("negative")
                        evidence_ref = str(surface.get("evidence_ref") or "").strip()
                        evidence_marker = pathlib.Path(evidence_ref) if evidence_ref else None
                        historical_negative: dict[str, Any] | None = None
                        if (evidence_marker is not None
                                and evidence_marker.is_absolute()
                                and evidence_marker.name == "project_state.json"
                                and evidence_marker.resolve(strict=False)
                                == declared_project_state
                                and expected_project_state.is_file()
                                and context is not None):
                            try:
                                try:
                                    from ..project_state import verify_project_evidence
                                except ImportError:  # pragma: no cover
                                    from project_state import verify_project_evidence
                                project = json.loads(expected_project_state.read_text(
                                    encoding="utf-8"))
                                registry = project.get("cell_registry") or {}
                                surface_keys = _exact_cell_keys(
                                    surface, context.primary_target)
                                combined = {
                                    "vectors": [], "response_count": 0,
                                    "evidence_types": [], "identities": [], "roles": [],
                                    "barrier_signals": [], "preconditions": {},
                                }
                                valid_historical = bool(surface_keys)
                                for key in surface_keys:
                                    prior = registry.get(key) or {}
                                    refs = list(prior.get("evidence_refs") or [])
                                    semantic_ok, derived = (
                                        _validate_project_evidence_envelopes(
                                            expected_project_state.parent, refs, surface,
                                            expected_kind="negative_evidence",
                                            context=context,
                                        ))
                                    if (prior.get("status") != "not_vulnerable"
                                            or not verify_project_evidence(
                                                expected_project_state.parent, refs,
                                                dict(prior.get("evidence_hashes") or {}))
                                            or not semantic_ok):
                                        valid_historical = False
                                        break
                                    for field in (
                                            "vectors", "evidence_types",
                                            "identities", "roles", "barrier_signals"):
                                        combined[field] = list(dict.fromkeys([
                                            *combined[field],
                                            *list(derived.get(field) or []),
                                        ]))
                                    combined["response_count"] += int(
                                        derived.get("response_count", 0) or 0)
                                    for key, value in (derived.get("preconditions") or {}).items():
                                        combined["preconditions"][str(key)] = (
                                            value is True
                                            and combined["preconditions"].get(str(key), True)
                                        )
                                if valid_historical:
                                    historical_negative = combined
                            except (OSError, ValueError, json.JSONDecodeError):
                                historical_negative = None
                        if historical_negative is not None:
                            if is_input_validation_cell(surface):
                                reasons.append(
                                    "cross_stage_input_negative_retest_required")
                                continue
                            try:
                                try:
                                    from ..knowledge import negative_sufficient
                                except ImportError:  # pragma: no cover
                                    from knowledge import negative_sufficient
                                sufficient, _ = negative_sufficient(
                                    surface, historical_negative, None)
                                if not sufficient:
                                    reasons.append("negative_depth_insufficient")
                            except Exception:
                                reasons.append("negative_depth_invalid")
                            continue
                        if not isinstance(negative, dict) or not evidence_ref:
                            reasons.append("negative_evidence_missing")
                        else:
                            evidence_path = pathlib.Path(evidence_ref)
                            if evidence_path.is_absolute():
                                try:
                                    relative = evidence_path.resolve(
                                        strict=False).relative_to(source_project_dir)
                                except ValueError:
                                    reasons.append("negative_evidence_escape")
                                    continue
                                evidence_path = project_dir / relative
                            else:
                                evidence_path = run_dir / evidence_path
                            current_path = evidence_path
                            unsafe_evidence_path = False
                            while (current_path != project_dir
                                   and current_path != current_path.parent):
                                if current_path.is_symlink():
                                    unsafe_evidence_path = True
                                    break
                                current_path = current_path.parent
                            if unsafe_evidence_path:
                                reasons.append("negative_evidence_invalid")
                                continue
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
                                    continue
                            allowed_root = run_dir
                            try:
                                resolved.relative_to(run_dir.resolve())
                            except ValueError:
                                allowed_root = project_dir
                            envelope_ok, derived_negative, artifacts = (
                                _validate_evidence_envelope(
                                    resolved, surface,
                                    expected_kind="negative_evidence",
                                    allowed_root=allowed_root,
                                    context=context,
                                ))
                            if not envelope_ok:
                                reasons.append("negative_evidence_invalid")
                                continue
                            for family_field in (
                                    "encoding_families", "strategy_families"):
                                declared_families = {
                                    str(value).strip().lower()
                                    for value in (negative.get(family_field) or [])
                                    if str(value).strip()
                                }
                                derived_families = {
                                    str(value).strip().lower()
                                    for value in (derived_negative.get(family_field) or [])
                                    if str(value).strip()
                                }
                                if (declared_families
                                        and declared_families != derived_families):
                                    reasons.append(
                                        f"negative_{family_field}_mismatch")
                            if allowed_root == run_dir:
                                closure_artifact_hashes.update(artifacts)
                            try:
                                try:
                                    from ..knowledge import negative_sufficient
                                except ImportError:  # pragma: no cover
                                    from knowledge import negative_sufficient
                                sufficient, _ = negative_sufficient(
                                    surface, derived_negative, None)
                                if not sufficient:
                                    reasons.append("negative_depth_insufficient")
                            except Exception:
                                reasons.append("negative_depth_invalid")
                            prior_negative = surface.get(
                                "cross_stage_prior_negative")
                            if (is_input_validation_cell(surface)
                                    and isinstance(prior_negative, dict)
                                    and prior_negative):
                                diverse, diversity_reasons = has_cross_stage_diversity(
                                    derived_negative, prior_negative)
                                if not diverse:
                                    reasons.extend(diversity_reasons)
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
        except (TypeError, ValueError):
            reasons.append("inventory_coverage_invalid")
    threat_reasons, threat_hashes, threat_stats = _threat_model_closure_gate(
        run_dir,
        context=context,
        inventory_rows=(endpoints if isinstance(endpoints, list) else []),
        surfaces=surfaces,
        normalized_findings=[
            row for row in (normalized_findings or []) if isinstance(row, dict)
        ],
    )
    reasons.extend(threat_reasons)
    closure_artifact_hashes.update(threat_hashes)
    reasons.extend(_authority_method_resolution_gate(
        context,
        endpoints if isinstance(endpoints, list) else [],
        unresolved if isinstance(unresolved, list) else [],
    ))
    plan_reasons, plan_stats = _authority_plan_gate(context, surfaces)
    reasons.extend(plan_reasons)
    execution_stats: dict[str, Any] = {}
    execution_projection: dict[str, Any] = {}
    execution_metadata = (
        ledger_value.get("metadata") if isinstance(ledger_value, dict) else {}) or {}
    if int(execution_metadata.get("execution_contract_version", 0) or 0):
        if int(execution_metadata.get("execution_contract_version", 0) or 0) != (
                EXECUTION_CONTRACT_VERSION):
            reasons.append("execution_contract_version_invalid")
        elif context is None or not isinstance(context.manifest, dict):
            reasons.append("execution_authority_missing")
        else:
            authority_path = pathlib.Path(str(
                context.manifest.get("authority_path") or ""))
            authority_root = authority_path.parent.parent
            session_id = str(context.manifest.get("session_id") or "")
            execution_ledger = CoverageLedger(
                [item for item in surfaces if isinstance(item, dict)],
                metadata=execution_metadata)
            try:
                authority_events = load_authority_execution_events(
                    authority_root, session_id)
                normalized_events: list[dict[str, Any]] = []
                for event in authority_events:
                    normalized = normalize_execution_event(
                        run_dir, execution_ledger, event)
                    if normalized != event:
                        raise DynamicExecutionError(
                            "authority execution event is not canonical")
                    normalized_events.append(normalized)
                    for ref in normalized.get("evidence_refs") or []:
                        evidence_path = (run_dir / str(ref)).resolve()
                        try:
                            relative = evidence_path.relative_to(run_dir).as_posix()
                        except ValueError as exc:
                            raise DynamicExecutionError(
                                "execution evidence escaped run") from exc
                        closure_artifact_hashes[relative] = _sha256_file(
                            evidence_path)
                execution_projection = build_execution_projection(
                    execution_ledger, normalized_events,
                    rejected_surface_ids=rejected_finding_surface_ids(
                        run_dir, execution_ledger, rejected_findings or []))
                execution_stats = dict(execution_projection.get("stats") or {})
                reasons.extend(projection_matches_files(
                    run_dir, execution_projection))
                if int(execution_stats.get("open", 0) or 0) != 0:
                    reasons.append("execution_contract_open")
                for name in (
                    "execution-contracts.json", "execution-progress.json",
                    "execution-queue.json", "execution-backlog.json",
                ):
                    path = run_dir / name
                    if path.is_file():
                        closure_artifact_hashes[name] = _sha256_file(path)
            except (DynamicExecutionError, OSError, ValueError) as exc:
                reasons.append(
                    f"execution_projection_invalid:{type(exc).__name__}:{exc}")
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
    reasons.extend(_authority_candidate_gate(context))
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
                finding_candidate_ids={
                    str(item.get("source_candidate_id") or "")
                    for item in (normalized_findings or [])
                    if str(item.get("source_candidate_id") or "")
                },
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
    miss_attribution = build_miss_attribution(
        surfaces=[item for item in surfaces if isinstance(item, dict)],
        inventory_rows=(endpoints if isinstance(endpoints, list) else []),
        unresolved_rows=(unresolved if isinstance(unresolved, list) else []),
        execution_projection=execution_projection,
        rejected_findings=(rejected_findings or []),
    )
    if not miss_attribution.get("complete"):
        reasons.append("miss_attribution_incomplete")
    return {
        "result": "pass" if not reasons and session_gate.get("result") == "pass" else "fail",
        "reasons": reasons,
        "session_gate": session_gate,
        "authority_plan": plan_stats,
        "threat_coverage": threat_stats,
        "execution": execution_stats,
        "miss_attribution": miss_attribution,
        "artifact_hashes": closure_artifact_hashes,
    }


def _empty_run_gate(
    run_dir: pathlib.Path, context: ValidationContext | None = None,
) -> dict[str, Any]:
    """Backward-compatible alias; all new validation uses the run-wide gate."""
    return _run_closure_gate(run_dir, context=context, normalized_findings=[])


def _manifest_context(
    run_dir: pathlib.Path,
    allowed_hosts: list[str] | None = None,
    *,
    expected_authority_dir: pathlib.Path | None = None,
    expected_project_id: str = "",
    expected_project_name: str = "",
) -> tuple[ValidationContext | None, pathlib.Path | None, list[dict[str, Any]]]:
    manifest_path = run_dir / "run_manifest.json"
    errors: list[dict[str, Any]] = []
    if not manifest_path.is_file():
        errors.append({
            "code": "missing_manifest",
            "reason": "run_manifest.json is required before finding validation",
        })
        return None, None, errors
    if manifest_path.is_symlink():
        errors.append({
            "code": "invalid_manifest",
            "reason": "run_manifest.json cannot be a symlink",
        })
        return None, manifest_path, errors
    try:
        manifest = json.loads(safe_read_text(manifest_path))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
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
    binding = validate_manifest_binding(
        manifest, run_dir=run_dir, manifest_path=manifest_path,
        authority_dir=expected_authority_dir)
    errors.extend(binding.get("errors") or [])
    if expected_project_id and str(manifest.get("project_id") or "") != str(
            expected_project_id):
        errors.append({
            "code": "manifest_project_id_mismatch",
            "expected": str(expected_project_id),
            "actual": str(manifest.get("project_id") or ""),
            "reason": "manifest project_id differs from the finalizer authority",
        })
    if expected_project_name and str(manifest.get("project") or "") != str(
            expected_project_name):
        errors.append({
            "code": "manifest_project_name_mismatch",
            "expected": str(expected_project_name),
            "actual": str(manifest.get("project") or ""),
            "reason": "manifest project differs from the finalizer project",
        })
    authority = binding.get("authority_manifest")
    context_manifest = authority if isinstance(authority, dict) else manifest
    authority_text = str(binding.get("authority_path") or "")
    context_manifest_path = (
        pathlib.Path(authority_text) if authority_text else manifest_path)
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
    expected_authority_dir: str | pathlib.Path | None = None,
    expected_project_id: str = "",
    expected_project_name: str = "",
    source_run_dir: str | pathlib.Path | None = None,
    write_output: bool = True,
    write_sidecars: bool | None = None,
) -> dict[str, Any]:
    """Single library entry point used by both CLI and orchestrator.

    Sidecars follow the validation output only when that output is inside the
    run directory.  An external ``--output`` is diagnostic/read-only by
    default and cannot silently mutate the audited historical run.
    """
    from .collect import collect_structured_findings
    try:
        from ..enforce import ACCEPTED, guardian_check_finding
        from ..version import __version__
    except ImportError:  # pragma: no cover
        from enforce import ACCEPTED, guardian_check_finding
        from version import __version__

    base = pathlib.Path(run_dir).resolve()
    expected_authority = (
        pathlib.Path(expected_authority_dir).resolve()
        if expected_authority_dir is not None else None)
    source_run = (
        pathlib.Path(source_run_dir).resolve()
        if source_run_dir is not None else base)
    context, manifest_path, preflight_errors = _manifest_context(
        base,
        allowed_hosts,
        expected_authority_dir=expected_authority,
        expected_project_id=expected_project_id,
        expected_project_name=expected_project_name,
    )
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
        verdict = guardian_check_finding(
            item.get("finding") or {}, path.parent, context=context)
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
    for closure_name in (
        "inventory.json", "coverage-ledger.json", "candidate-ledger.json",
        "dead_ends.json",
    ):
        closure_path = base / closure_name
        if closure_path.is_file():
            artifact_hashes[closure_name] = _sha256_file(closure_path)
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
    intuition_exploration = validate_intuition_exploration(base)
    if (base / "intuition-exploration.json").is_file():
        artifact_hashes.update(
            {str(ref): str(digest) for ref, digest in
             (intuition_exploration.get("artifact_hashes") or {}).items()})

    # Canonical ingestion is all-or-nothing.  A mixed batch containing one
    # malformed/rejected finding must not expose the remaining rows as project
    # truth merely because they validated individually.  v9 also attributes
    # every otherwise-valid package suppressed by this batch gate; silently
    # clearing ``confirmed`` would lose both its result and repair target.
    if rejected or ingestion_errors:
        rejected_paths = {
            str(pathlib.Path(str(item.get("path") or "")).resolve())
            for item in rejected if item.get("path")
        }
        accepted_by_path = {
            str(pathlib.Path(str(item.get("path") or "")).resolve()): item
            for item in (collected.get("accepted") or []) if item.get("path")
        }
        for candidate in confirmed:
            candidate_path = str(
                pathlib.Path(str(candidate.get("path") or "")).resolve())
            if not candidate_path or candidate_path in rejected_paths:
                continue
            source = accepted_by_path.get(candidate_path) or {}
            row = {
                "id": candidate.get("id"),
                "path": candidate_path,
                "reasons": [
                    "batch_atomicity: another canonical finding or ingestion "
                    "artifact failed validation",
                ],
            }
            if isinstance(source.get("finding"), dict):
                row.update(_finding_target_projection(source["finding"]))
            rejected.append(row)
        confirmed = []
        normalized_confirmed = []

    canonical_count = int((collected.get("counts") or {}).get("canonical", 0) or 0)
    closure_gate = _run_closure_gate(
        base, context=context, normalized_findings=normalized_confirmed,
        rejected_findings=rejected,
        source_run_dir=source_run)
    for ref, digest in (closure_gate.get("artifact_hashes") or {}).items():
        path = (base / str(ref)).resolve()
        try:
            path.relative_to(base)
        except ValueError:
            ingestion_errors.append({
                "code": "closure_evidence_escape", "path": str(ref)})
            continue
        if not path.is_file() or _sha256_file(path) != str(digest):
            ingestion_errors.append({
                "code": "closure_evidence_hash_mismatch", "path": str(ref)})
            continue
        artifact_hashes[str(ref)] = str(digest)
    if ingestion_errors:
        confirmed = []
        normalized_confirmed = []
    proof_reasons: list[dict[str, Any]] = []
    proof_reasons.extend(rejected)
    proof_reasons.extend(ingestion_errors)
    proof_gate = {
        "result": "pass" if not proof_reasons else "fail",
        "reasons": proof_reasons,
        "canonical_count": canonical_count,
        "proof_confirmed_count": len(confirmed),
    }
    precondition_missing = any(
        item.get("code") == "missing_manifest" for item in preflight_errors)
    if precondition_missing:
        status, exit_code = "precondition_missing", 2
    elif rejected or ingestion_errors:
        status, exit_code = "invalid", 1
    elif closure_gate["result"] != "pass":
        status = "incomplete_with_findings" if confirmed else "incomplete"
        exit_code = 2
    elif confirmed:
        status, exit_code = "valid", 0
    elif allow_empty:
        status, exit_code = "empty_allowed", 0
    else:
        status, exit_code = "empty_input", 2

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
        "proof_gate": proof_gate,
        "closure_gate": closure_gate,
        "miss_attribution": closure_gate.get("miss_attribution") or {},
        "intuition_exploration": intuition_exploration,
    }
    result["next_run_agenda"] = build_next_run_agenda(
        result["miss_attribution"])
    # v8.8 callers used empty_gate; retain the projection while making the
    # run-wide closure gate authoritative for both empty and non-empty runs.
    if canonical_count == 0:
        result["empty_gate"] = closure_gate
    result["validation_sha256"] = _canonical_digest(result)
    if write_output:
        output = pathlib.Path(output_path) if output_path else base / "finding_validation.json"
        if not output.is_absolute():
            output = base / output
        atomic_write_json(output, result)
        sidecars_enabled = write_sidecars
        if sidecars_enabled is None:
            try:
                output.resolve(strict=False).relative_to(base)
                sidecars_enabled = True
            except ValueError:
                sidecars_enabled = False
        if sidecars_enabled:
            atomic_write_json(base / "miss-attribution.json", result["miss_attribution"])
            atomic_write_json(base / "next-run-agenda.json", result["next_run_agenda"])
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
        elif authority_path.is_file():
            try:
                authority_manifest = json.loads(safe_read_text(authority_path))
                binding = validate_manifest_binding(
                    authority_manifest,
                    run_dir=base,
                    manifest_path=base / "run_manifest.json",
                )
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                mismatches.append({"path": str(authority_path),
                                   "reason": f"manifest_binding_error:{exc}"})
            else:
                mismatches.extend(binding.get("errors") or [])
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
    parser.add_argument(
        "--write-sidecars", action="store_true",
        help="also persist miss-attribution/next-run-agenda in run_dir",
    )
    args = parser.parse_args(argv)
    try:
        result = validate_run_artifacts(
            args.run_dir,
            allowed_hosts=args.allowed_hosts or None,
            allow_empty=args.allow_empty,
            output_path=args.output,
            write_sidecars=True if args.write_sidecars else None,
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
