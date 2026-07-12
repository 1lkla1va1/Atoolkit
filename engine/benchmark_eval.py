"""
Offline benchmark evaluator for authorized SRC regression suites.

This module deliberately reads only oracle/summary/coverage artifacts passed on
the command line. It is not imported by the orchestrator and must not influence
attack prompts or runtime decisions.
"""
from __future__ import annotations

import argparse
import ast
import csv
import json
import pathlib
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlparse


@dataclass
class OracleCase:
    id: str
    endpoint: str
    method: str = ""
    params: list[str] = field(default_factory=list)
    vuln_class: str = ""
    score: float = 0.0
    roles: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    id: str
    title: str = ""
    endpoints: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    vuln_class: str = ""
    roles: list[str] = field(default_factory=list)
    evidence_file: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class CoverageSurface:
    surface_id: str
    endpoint: str = ""
    method: str = ""
    param: str = ""
    params: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    risk_tags: list[str] = field(default_factory=list)
    vuln_class: str = ""
    status: str = "not_tested"
    reason: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


def _as_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("[") and text.endswith("]"):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    return parsed
            except Exception:
                pass
        return [x.strip() for x in re.split(r"[,;\s]+", text) if x.strip()]
    return [value]


def _lower_set(values: list[Any]) -> set[str]:
    return {str(v).strip().lower() for v in values if str(v).strip()}


def _first(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key]
    return None


def _strip_base(endpoint: str) -> str:
    text = str(endpoint or "").strip()
    if not text:
        return ""
    parsed = urlparse(text)
    if parsed.scheme and parsed.netloc:
        path = parsed.path or "/"
        return f"{path}?{parsed.query}" if parsed.query else path
    match = re.search(r"https?://[^/]+([^\s'\"<>]+)", text)
    if match:
        return _strip_base(match.group(0))
    return text


def _path_without_query(endpoint: str) -> str:
    return _strip_base(endpoint).split("#", 1)[0].split("?", 1)[0].rstrip("/") or "/"


# ── 占位符归一化（镜像 orchestrator._norm_path 的 ID 段折叠语义）──────────────
# 把路径分段里的「ID-like 段」折叠成 {}，使 oracle 抽象行 /api/orders/{id} 与报告
# 具体 id 形态 /api/orders/1001 同格匹配。语义段（detail/list/info/login 等）不折叠
# ——/api/order/detail 不会误命中 /api/orders/{id}。仅作 _endpoint_match 的额外 match
# 路径（OR），不改写 oracle/finding 的真实 endpoint 文案，不影响 exact/endswith。
_BEC_UUID_RE = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
    r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
_BEC_HEXID_RE = re.compile(r'^[0-9a-fA-F]{12,}$')        # 长十六进制 id（mongo ObjectId 等）
_BEC_PLACEHOLDER_RE = re.compile(r'^[\{<].*[\}>]$')      # 已是占位符 {id} / <id>


def _norm_path_placeholders(endpoint: str) -> str:
    """剥 query 后，把路径分段中的 ID-like 段（纯数字 / uuid / 长hex / {..}<..> 占位符）
    折叠成 {}。语义段不折叠，防空端点/语义段误匹配。"""
    path = _path_without_query(endpoint)
    segs: list[str] = []
    for seg in path.split("/"):
        if seg == "":
            segs.append(seg)
            continue
        if (seg.isdigit() or _BEC_UUID_RE.match(seg) or _BEC_HEXID_RE.match(seg)
                or _BEC_PLACEHOLDER_RE.match(seg)):
            segs.append("{}")
        else:
            segs.append(seg)
    return "/".join(segs)


def _endpoint_match(expected: str, observed: str) -> bool:
    exp = _path_without_query(expected)
    obs = _path_without_query(observed)
    if not exp or not obs:
        return False
    if exp == obs:
        return True
    if obs.endswith(exp) or exp.endswith(obs):
        return True
    # 占位符归一匹配：/api/orders/1001 ↔ /api/orders/{id}（ID 段折叠成 {}）。
    return _norm_path_placeholders(expected) == _norm_path_placeholders(observed)


def _extract_endpoint_fragments(text: str) -> list[str]:
    fragments: list[str] = []
    for match in re.finditer(r"(?:https?://[^\s'\"<>]+|/[A-Za-z0-9_./%?=&:+{}-]+)", text or ""):
        fragments.append(_strip_base(match.group(0).rstrip(".,，。)）]】")))
    return fragments


def _params_from_url(url: str) -> list[str]:
    query = urlparse(_strip_base(url)).query
    return [k for k, _ in parse_qsl(query, keep_blank_values=True)]


def _params_from_body(body: Any) -> list[str]:
    if body is None:
        return []
    if isinstance(body, dict):
        return list(body.keys())
    if not isinstance(body, str):
        return []
    text = body.strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return list(parsed.keys())
    except Exception:
        pass
    return [k for k, _ in parse_qsl(text, keep_blank_values=True)]


def _dedupe(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        item = str(value or "").strip()
        if item and item.lower() not in seen:
            seen.add(item.lower())
            out.append(item)
    return out


def _canonical_classes(text: Any) -> set[str]:
    low = str(text or "").lower()
    compact = re.sub(r"\s+", "", low)
    classes: set[str] = set()
    if any(x in compact for x in ("idor", "越权", "归属", "ownership", "cross_role", "跨商户", "对象级")):
        classes.add("idor")
    if any(x in compact for x in ("未授权", "unauth", "config_leak", "config-leak", "ak/sk", "accesskey", "信息泄露", "配置资产")):
        classes.add("information-disclosure")
    if any(x in compact for x in ("ssrf", "服务端请求伪造")):
        classes.add("ssrf")
    if any(x in compact for x in ("race", "并发", "竞争", "重放", "重复入账")):
        classes.add("race-condition")
    if any(x in compact for x in ("未支付", "payment-bypass", "payment_bypass", "callback_sign", "前端签名", "信任前端", "伪造支付")):
        classes.add("payment-bypass")
    if any(x in compact for x in ("amount-tamper", "amount_tamper", "金额篡改", "余额", "积分", "退款")):
        classes.add("amount-tamper")
    if any(x in compact for x in ("auth", "认证", "登录", "注册", "找回", "验证码", "token", "session")):
        classes.add("auth-flow")
    if any(x in compact for x in ("xss", "跨站")):
        classes.add("xss")
    if any(x in compact for x in ("sqli", "sql注入", "sql injection")):
        classes.add("sqli")
    if not classes and compact:
        classes.add(re.sub(r"[^a-z0-9_\-\u4e00-\u9fff]+", "-", compact).strip("-"))
    return classes


def _class_match(expected: str, observed: str) -> bool:
    if not expected:
        return True
    exp = _canonical_classes(expected)
    obs = _canonical_classes(observed)
    return bool(exp & obs) or str(expected).lower() in str(observed).lower()


def _method_match(expected: str, observed: list[str] | str) -> bool:
    if not expected:
        return True
    methods = [observed] if isinstance(observed, str) else observed
    observed_set = {str(x).upper() for x in methods if x}
    return bool(observed_set) and expected.upper() in observed_set


def _params_match(expected: list[str], observed: list[str]) -> bool:
    exp = _lower_set(expected)
    if not exp:
        return True
    obs = _lower_set(observed)
    return exp <= obs


def _roles_match(expected: list[str], observed: list[str]) -> bool:
    exp = _lower_set(expected)
    if not exp:
        return True
    obs = _lower_set(observed)
    return bool(obs) and bool(exp & obs)


class _PhpArrayParser:
    def __init__(self, source: str):
        self.tokens = self._tokenize(source)
        self.i = 0

    @staticmethod
    def _tokenize(source: str) -> list[tuple[str, Any]]:
        source = re.sub(r"<\?(?:php)?|\?>", "", source, flags=re.I)
        source = re.sub(r"//.*?$|#.*?$|/\*.*?\*/", "", source, flags=re.M | re.S)
        tokens: list[tuple[str, Any]] = []
        i = 0
        while i < len(source):
            ch = source[i]
            if ch.isspace():
                i += 1
                continue
            if source.startswith("=>", i):
                tokens.append(("ARROW", "=>"))
                i += 2
                continue
            if ch in "[](),;":
                tokens.append((ch, ch))
                i += 1
                continue
            if ch in ("'", '"'):
                quote = ch
                j = i + 1
                escaped = False
                buf = ""
                while j < len(source):
                    c = source[j]
                    if escaped:
                        buf += "\\" + c
                        escaped = False
                    elif c == "\\":
                        escaped = True
                    elif c == quote:
                        break
                    else:
                        buf += c
                    j += 1
                tokens.append(("STRING", ast.literal_eval(quote + buf + quote)))
                i = j + 1
                continue
            m_num = re.match(r"-?\d+(?:\.\d+)?", source[i:])
            if m_num:
                raw = m_num.group(0)
                tokens.append(("NUMBER", float(raw) if "." in raw else int(raw)))
                i += len(raw)
                continue
            m_ident = re.match(r"[A-Za-z_][A-Za-z0-9_\\]*", source[i:])
            if m_ident:
                raw = m_ident.group(0)
                tokens.append(("IDENT", raw))
                i += len(raw)
                continue
            raise ValueError(f"unsupported PHP token near: {source[i:i + 24]!r}")
        return tokens

    def _peek(self) -> tuple[str, Any] | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def _pop(self, kind: str | None = None) -> tuple[str, Any]:
        token = self._peek()
        if token is None:
            raise ValueError("unexpected end of PHP array")
        if kind is not None and token[0] != kind:
            raise ValueError(f"expected {kind}, got {token[0]}")
        self.i += 1
        return token

    def parse(self) -> Any:
        if self._peek() and self._peek()[1] == "return":
            self._pop()
        value = self._parse_value()
        return value

    def _parse_value(self) -> Any:
        token = self._peek()
        if token is None:
            raise ValueError("missing value")
        kind, value = token
        if kind in ("STRING", "NUMBER"):
            self._pop()
            return value
        if kind == "IDENT":
            low = str(value).lower()
            self._pop()
            if low == "array" and self._peek() and self._peek()[0] == "(":
                return self._parse_array("(", ")")
            if low in ("true", "false"):
                return low == "true"
            if low in ("null", "nil"):
                return None
            return value
        if kind == "[":
            return self._parse_array("[", "]")
        raise ValueError(f"unexpected PHP token {token!r}")

    def _parse_array(self, opener: str, closer: str) -> Any:
        self._pop(opener)
        list_items: list[Any] = []
        dict_items: dict[Any, Any] = {}
        saw_key = False
        index = 0
        while self._peek() and self._peek()[0] != closer:
            first = self._parse_value()
            if self._peek() and self._peek()[0] == "ARROW":
                self._pop("ARROW")
                dict_items[first] = self._parse_value()
                saw_key = True
            else:
                if saw_key:
                    dict_items[index] = first
                else:
                    list_items.append(first)
                index += 1
            if self._peek() and self._peek()[0] == ",":
                self._pop(",")
        self._pop(closer)
        if saw_key:
            for n, item in enumerate(list_items):
                dict_items[n] = item
            return dict_items
        return list_items


def _load_yaml_fallback(text: str) -> Any:
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- "):
            if current:
                rows.append(current)
            current = {}
            stripped = stripped[2:].strip()
        if current is None:
            current = {}
        if ":" in stripped:
            key, value = stripped.split(":", 1)
            current[key.strip()] = _parse_scalar(value.strip())
    if current:
        rows.append(current)
    return rows


def _parse_scalar(value: str) -> Any:
    if value in ("", "null", "NULL", "~"):
        return None
    if value.lower() in ("true", "false"):
        return value.lower() == "true"
    if value.startswith("[") and value.endswith("]"):
        try:
            return json.loads(value)
        except Exception:
            return [x.strip().strip("'\"") for x in value[1:-1].split(",") if x.strip()]
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value.strip("'\"")


def load_structured(path: pathlib.Path) -> Any:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open(newline="", encoding="utf-8") as fh:
            return list(csv.DictReader(fh))
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore

            return yaml.safe_load(text)
        except ModuleNotFoundError:
            return _load_yaml_fallback(text)
    if suffix in (".php", ".inc") or re.search(r"\breturn\b|\barray\s*\(", text):
        try:
            return _PhpArrayParser(text).parse()
        except Exception:
            pass
    return json.loads(text)


def _case_rows(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("cases", "oracle", "vulnerabilities", "findings", "items"):
            value = data.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
        if all(k in data for k in ("endpoint", "class")):
            return [data]
    return []


def load_oracle(path: pathlib.Path) -> list[OracleCase]:
    cases: list[OracleCase] = []
    for index, row in enumerate(_case_rows(load_structured(path)), start=1):
        params = _as_list(_first(row, "params", "param", "parameters"))
        endpoint = str(_first(row, "endpoint", "url", "path", "target") or "")
        params.extend(_params_from_url(endpoint))
        case = OracleCase(
            id=str(_first(row, "id", "case_id", "vuln_id", "name") or f"case-{index:03d}"),
            endpoint=_strip_base(endpoint),
            method=str(_first(row, "method", "http_method") or "").upper(),
            params=_dedupe(params),
            vuln_class=str(_first(row, "class", "vuln_class", "category", "type", "risk_tag") or ""),
            score=float(_first(row, "score", "points", "weight") or 0),
            roles=_dedupe(_as_list(_first(row, "roles", "role"))),
            raw=row,
        )
        cases.append(case)
    return cases


def _walk_requests(obj: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(obj, dict):
        request = obj.get("request")
        if isinstance(request, dict) and request.get("url"):
            found.append(request)
        for value in obj.values():
            found.extend(_walk_requests(value))
    elif isinstance(obj, list):
        for value in obj:
            found.extend(_walk_requests(value))
    return found


def _resolve_evidence(summary_path: pathlib.Path, evidence_file: str) -> pathlib.Path | None:
    if not evidence_file:
        return None
    path = pathlib.Path(evidence_file)
    candidates = [path]
    if not path.is_absolute():
        candidates.append(summary_path.parent / path)
        candidates.append(summary_path.parent.parent / path)
        candidates.append(pathlib.Path.cwd() / path)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _finding_rows(summary: Any) -> list[dict[str, Any]]:
    if isinstance(summary, list):
        return [x for x in summary if isinstance(x, dict)]
    if not isinstance(summary, dict):
        return []
    for key in ("confirmed_vulns", "findings", "vulnerabilities", "reports"):
        value = summary.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
    return []


def load_findings(summary_path: pathlib.Path, *, trust_legacy: bool = False) -> list[Finding]:
    data = load_structured(summary_path)
    findings: list[Finding] = []
    for index, row in enumerate(_finding_rows(data), start=1):
        if not trust_legacy:
            if row.get("acceptance_status") != "accepted":
                continue
            if row.get("proof_status") != "confirmed":
                continue
            if row.get("claim_kind") != "root_finding":
                continue
        evidence_file = str(_first(row, "evidence_file", "evidence", "evidence_path") or "")
        evidence_path = _resolve_evidence(summary_path, evidence_file)
        if not trust_legacy and evidence_path is None:
            continue
        evidence_data: Any = {}
        if evidence_path:
            try:
                evidence_data = json.loads(evidence_path.read_text(encoding="utf-8"))
            except Exception:
                evidence_data = {}

        endpoints = _as_list(row.get("endpoints"))
        methods = _as_list(row.get("methods"))
        params = _as_list(row.get("params"))
        if row.get("method"):
            methods.append(row.get("method"))
        for key in ("endpoint", "url", "path", "target", "access_path"):
            endpoints.extend(_extract_endpoint_fragments(str(row.get(key) or "")))
        for req in _walk_requests(evidence_data):
            url = str(req.get("url") or "")
            endpoints.append(_strip_base(url))
            methods.append(str(req.get("method") or "").upper())
            params.extend(_params_from_url(url))
            params.extend(_params_from_body(req.get("body")))

        title = " ".join(
            str(x or "")
            for x in (
                _first(row, "vuln_type", "title", "name", "description"),
                row.get("feature_id"),
                row.get("feature_name"),
            )
        )
        findings.append(
            Finding(
                id=str(_first(row, "vuln_id", "id", "finding_id") or f"finding-{index:03d}"),
                title=title.strip(),
                endpoints=_dedupe(endpoints),
                methods=_dedupe(methods),
                params=_dedupe(params),
                vuln_class=str(_first(row, "class", "vuln_class", "type", "vuln_type", "category") or title),
                roles=_dedupe(_as_list(row.get("roles") or row.get("role"))),
                evidence_file=evidence_file,
                raw=row,
            )
        )
    return findings


def _normalize_status(status: str) -> str:
    low = str(status or "").strip().lower()
    mapping = {
        "positive": "confirmed",
        "confirmed": "confirmed",
        "negative_with_evidence": "not_vulnerable",
        "not_vulnerable": "not_vulnerable",
        "refuted": "not_vulnerable",
        "shallow_negative": "not_tested",
        "untested": "not_tested",
        "not_tested": "not_tested",
        "blocked": "blocked",
        "skipped": "not_applicable",
        "not_applicable": "not_applicable",
        "n/a": "not_applicable",
    }
    return mapping.get(low, low or "not_tested")


def load_coverage(path: pathlib.Path) -> list[CoverageSurface]:
    data = load_structured(path)
    surfaces: list[CoverageSurface] = []
    if isinstance(data, dict) and isinstance(data.get("surfaces"), list):
        for index, row in enumerate(data["surfaces"], start=1):
            if not isinstance(row, dict):
                continue
            params = _as_list(row.get("params"))
            if row.get("param"):
                params.append(row["param"])
            surfaces.append(
                CoverageSurface(
                    surface_id=str(row.get("surface_id") or row.get("id") or f"surface-{index:03d}"),
                    endpoint=_strip_base(str(row.get("endpoint") or "")),
                    method=str(row.get("method") or "").upper(),
                    param=str(row.get("param") or ""),
                    params=_dedupe(params),
                    roles=_dedupe(_as_list(row.get("roles") or row.get("role"))),
                    risk_tags=_dedupe(_as_list(row.get("risk_tags") or row.get("risk_tag"))),
                    vuln_class=str(row.get("class") or row.get("vuln_class") or ""),
                    status=_normalize_status(str(row.get("status") or "")),
                    reason=str(row.get("reason") or row.get("blocker") or row.get("evidence") or ""),
                    raw=row,
                )
            )
        return surfaces

    if isinstance(data, dict) and isinstance(data.get("features_summary"), list):
        for feature in data["features_summary"]:
            if not isinstance(feature, dict):
                continue
            for result in feature.get("results") or []:
                if not isinstance(result, dict):
                    continue
                text = " ".join(str(x or "") for x in (feature, result))
                endpoints = _extract_endpoint_fragments(text)
                surfaces.append(
                    CoverageSurface(
                        surface_id=f"{feature.get('feature_id', 'feature')}:{result.get('threat_id', '')}",
                        endpoint=endpoints[0] if endpoints else str(feature.get("feature_id") or ""),
                        method=str(result.get("method") or "").upper(),
                        params=_dedupe(_as_list(result.get("params"))),
                        roles=_dedupe(_as_list(result.get("roles"))),
                        risk_tags=_dedupe(_as_list(result.get("risk_tags"))),
                        vuln_class=str(result.get("class") or result.get("threat") or feature.get("feature_id") or ""),
                        status=_normalize_status(str(result.get("status") or "")),
                        reason=str(result.get("reason") or result.get("evidence") or result.get("unruled_out") or ""),
                        raw={"feature": feature, "result": result},
                    )
                )
    return surfaces


def _finding_matches(case: OracleCase, finding: Finding) -> bool:
    if case.endpoint and not any(_endpoint_match(case.endpoint, ep) for ep in finding.endpoints):
        return False
    if not _method_match(case.method, finding.methods):
        return False
    if not _params_match(case.params, finding.params):
        return False
    if not _roles_match(case.roles, finding.roles):
        return False
    return _class_match(case.vuln_class, " ".join([finding.vuln_class, finding.title]))


def _coverage_matches(case: OracleCase, surface: CoverageSurface) -> bool:
    text = " ".join(str(x or "") for x in (surface.surface_id, surface.endpoint, surface.vuln_class, surface.risk_tags, surface.raw))
    endpoint_ok = True
    if case.endpoint and surface.endpoint:
        endpoint_ok = _endpoint_match(case.endpoint, surface.endpoint)
    elif case.endpoint:
        endpoint_ok = any(part.lower() in text.lower() for part in _path_without_query(case.endpoint).split("/") if part)
    if not endpoint_ok:
        return False
    if not _method_match(case.method, surface.method):
        return False
    if not _params_match(case.params, surface.params + ([surface.param] if surface.param else [])):
        param_text = text.lower()
        if not all(param.lower() in param_text for param in case.params):
            return False
    if not _roles_match(case.roles, surface.roles):
        return False
    return _class_match(case.vuln_class, " ".join([surface.vuln_class, " ".join(surface.risk_tags), text]))


def _coverage_attribution(case: OracleCase, surfaces: list[CoverageSurface]) -> dict[str, Any]:
    for surface in surfaces:
        if _coverage_matches(case, surface):
            status = surface.status
            if status == "not_applicable":
                status = "no_surface"
            return {
                "status": status,
                "surface_id": surface.surface_id,
                "reason": surface.reason,
            }
    return {"status": "no_surface", "surface_id": None, "reason": "no matching coverage surface"}


def _case_payload(case: OracleCase) -> dict[str, Any]:
    return {
        "id": case.id,
        "endpoint": case.endpoint,
        "method": case.method,
        "params": case.params,
        "class": case.vuln_class,
        "score": case.score,
        "roles": case.roles,
    }


def _finding_payload(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "title": finding.title,
        "endpoints": finding.endpoints,
        "methods": finding.methods,
        "params": finding.params,
        "class": finding.vuln_class,
        "roles": finding.roles,
        "evidence_file": finding.evidence_file,
    }


def _rate(hit: int, total: int) -> float:
    return round(hit / total, 4) if total else 1.0


def _score_rate(hit: float, total: float) -> float:
    return round(hit / total, 4) if total else 1.0


def _group_metrics(cases: list[OracleCase], hit_ids: set[str], key_fn) -> dict[str, dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for case in cases:
        keys = key_fn(case)
        for key in keys:
            bucket = buckets.setdefault(str(key or "<none>"), {"oracle_total": 0, "hit": 0, "score_total": 0.0, "score_hit": 0.0})
            bucket["oracle_total"] += 1
            bucket["score_total"] += case.score
            if case.id in hit_ids:
                bucket["hit"] += 1
                bucket["score_hit"] += case.score
    for bucket in buckets.values():
        bucket["miss"] = bucket["oracle_total"] - bucket["hit"]
        bucket["coverage_rate"] = _rate(bucket["hit"], bucket["oracle_total"])
        bucket["score_rate"] = _score_rate(bucket["score_hit"], bucket["score_total"])
    return dict(sorted(buckets.items()))


def evaluate(oracle: list[OracleCase], findings: list[Finding], coverage: list[CoverageSurface]) -> dict[str, Any]:
    hits: list[dict[str, Any]] = []
    misses: list[dict[str, Any]] = []
    duplicates: list[dict[str, Any]] = []
    matched_finding_ids: set[str] = set()
    hit_case_ids: set[str] = set()
    total_score = 0.0

    for case in oracle:
        matches = [
            finding for finding in findings
            if finding.id not in matched_finding_ids and _finding_matches(case, finding)
        ]
        if matches:
            primary = matches[0]
            matched_finding_ids.add(primary.id)
            hit_case_ids.add(case.id)
            total_score += case.score
            hits.append({"oracle": _case_payload(case), "finding": _finding_payload(primary)})
            for dup in matches[1:]:
                matched_finding_ids.add(dup.id)
                duplicates.append({"oracle_id": case.id, "finding": _finding_payload(dup)})
        else:
            misses.append({"oracle": _case_payload(case), "attribution": _coverage_attribution(case, coverage)})

    extra_findings = [_finding_payload(finding) for finding in findings if finding.id not in matched_finding_ids]
    score_total = sum(case.score for case in oracle)
    return {
        "hits": hits,
        "misses": misses,
        "duplicates": duplicates,
        "extra_findings": extra_findings,
        "total_score": total_score,
        "max_score": score_total,
        "score_rate": _score_rate(total_score, score_total),
        "coverage_by_class": _group_metrics(oracle, hit_case_ids, lambda c: sorted(_canonical_classes(c.vuln_class))),
        "coverage_by_endpoint": _group_metrics(oracle, hit_case_ids, lambda c: [_path_without_query(c.endpoint)]),
        "coverage_by_param": _group_metrics(oracle, hit_case_ids, lambda c: c.params or ["<none>"]),
        "coverage_by_role": _group_metrics(oracle, hit_case_ids, lambda c: c.roles or ["<none>"]),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline oracle/summary/coverage benchmark evaluator.")
    parser.add_argument("--oracle", required=True, type=pathlib.Path, help="Oracle file: JSON/YAML/CSV/PHP array.")
    parser.add_argument("--summary", required=True, type=pathlib.Path, help="Run summary.json or equivalent.")
    parser.add_argument("--coverage", required=True, type=pathlib.Path, help="coverage-ledger.json or legacy coverage.json.")
    parser.add_argument("--compact", action="store_true", help="Emit compact JSON.")
    parser.add_argument("--trust-legacy", action="store_true",
                        help="Allow pre-proof-contract summaries (unsafe compatibility mode).")
    args = parser.parse_args(argv)

    oracle = load_oracle(args.oracle)
    findings = load_findings(args.summary, trust_legacy=args.trust_legacy)
    coverage = load_coverage(args.coverage)
    result = evaluate(oracle, findings, coverage)
    result["meta"] = {
        "oracle_cases": len(oracle),
        "findings": len(findings),
        "coverage_surfaces": len(coverage),
    }
    json.dump(result, sys.stdout, ensure_ascii=False, indent=None if args.compact else 2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
