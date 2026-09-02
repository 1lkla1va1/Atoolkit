"""engine/reverify.py —— 证据复验执行器（v10.1 跨 Run 复利解锁）。

信任根 = 证据可重放（replay），不是可声明：finding 附幂等回查请求 + 期望
标记，本模块经 ``engine.verify`` 的真实重放原语（_guard scope 门 + 幂等限
制 + Host 头一致性，verify.py 零改动）重新取数，marker 特异度门 + 全类差
分基线匹配后给出四分类：

  - match     复验吻合（含基线不命中），可升格进 ProjectState；
  - mismatch  响应与期望不符（含基线命中 marker——公开可达/非越权信号）；
  - barrier   会话过期/连接失败/5xx/预算耗尽等可恢复阻塞；
  - blocked   scope 门拦截（零网络请求）。

信任分级如实声明（方案 §1/§8）：Direct 通道的输入与产物全部位于 agent 可
写目录，evidence_reverified 是幻觉过滤器，不是完整性边界；重放由 agent
运行的未修改 engine 代码执行，防"模型幻觉/手滑污染真值"，不防主动伪造。
"""
from __future__ import annotations

import json
import re
import time
import pathlib
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlsplit

try:
    from . import verify as _verify
    from .throttle import HostThrottle
except ImportError:  # pragma: no cover - direct script execution
    import verify as _verify  # type: ignore
    from throttle import HostThrottle  # type: ignore

# Marker 特异度探针集（方案 §3.1.3）：以 marker 为 pattern、探针为 subject
# 逐一 re.search，命中任意探针 → 恒真/弱模式，拒收。差分基线才是主防线。
MARKER_PROBES = ("", "ok", "success", "true", "status", "200", "error", "null", "{}")
# urllib_transport 响应 body 截断口径（verify.py:182 read(65536)）。
BODY_TRUNCATE_BYTES = 65536
# 幂等回查方法白名单（与 verify.IDEMPOTENT 一致；schema 层二次钉死）。
IDEMPOTENT_METHODS = ("GET", "HEAD", "OPTIONS")
REPLAY_KIND = "readback"
DEFAULT_MAX_AGE_HOURS = 72
# 复验成本闸（方案 §2.5）：每 Run 预算（含差分基线请求）。
DEFAULT_BUDGET_PER_RUN = 50
DEFAULT_RPS = 1.0

REASONS = {
    "missing_replay": "finding 无 verification.replay 段（无需复验）",
    "invalid_replay": "replay 段结构非法",
    "marker_refused": "marker 未命中原始 proof 响应或命中探针集",
    "rate_budget": "reverify 预算耗尽（barrier:rate_budget）",
    "transport_error": "连接失败/超时/5xx",
    "session_expired": "401 会话过期",
    "forbidden": "403 且无对照端点佐证",
    "guard_denied": "scope/幂等门拦截（零请求）",
    "expectation_mismatch": "回查响应与期望不符",
    "baseline_hit": "差分基线身份命中 required_markers（公开可达/非越权信号）",
    "unparsable_request": "request_file 无法解析出请求",
    "baseline_inconclusive": "差分基线不可判定（预算耗尽/传输失败/5xx）：禁止未经基线升格",
}


class ReverifyBudget:
    """Per-run reverify budget; every replayed request (incl. baseline) counts."""

    def __init__(self, limit: int = DEFAULT_BUDGET_PER_RUN) -> None:
        self.limit = int(limit)
        self.used = 0

    @property
    def exhausted(self) -> bool:
        return self.used >= self.limit

    def spend(self, count: int = 1) -> bool:
        """Try to reserve ``count`` request slots; False when over budget."""
        if self.used + count > self.limit:
            return False
        self.used += count
        return True


@dataclass
class ReverifyOutcome:
    outcome: str                       # match | mismatch | barrier | blocked
    reason: str = ""
    evidence_ref: str = ""
    latency_ms: int = 0
    baseline_outcome: str | None = None
    requests: int = 0

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "outcome": self.outcome,
            "reason": self.reason,
            "evidence_ref": self.evidence_ref,
            "latency_ms": self.latency_ms,
        }
        if self.baseline_outcome is not None:
            data["baseline_outcome"] = self.baseline_outcome
        return data


def _subject(body: str) -> str:
    """Same truncation semantics as urllib_transport's 64KB response body."""
    if isinstance(body, bytes):
        return body[:BODY_TRUNCATE_BYTES].decode("utf-8", "ignore")
    return str(body or "")[:BODY_TRUNCATE_BYTES]


def _compile_markers(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [str(value) for value in values if str(value)]


def marker_matches(marker: str, subject: str) -> bool:
    """Pinned match direction: ``re.search(marker, subject)``, no extra flags."""
    try:
        return re.search(marker, subject) is not None
    except re.error:
        return False


def probe_rejects(marker: str) -> bool:
    """True when the marker matches any fixed probe subject (恒真/弱模式)."""
    return any(marker_matches(marker, probe) for probe in MARKER_PROBES)


def load_identities(run_dir: str | pathlib.Path) -> dict[str, dict[str, str]]:
    """Read ``<run>/identities.json`` into {label: {Header: Value}}.

    Accepts both ``{"identities": {label: headers}}`` and
    ``{"identities": [{"label": ..., "headers": {...}}]}`` layouts, matching
    ``identity_requirements.count_present_identities``.
    """
    path = pathlib.Path(run_dir) / "identities.json"
    if not path.is_file() or path.is_symlink():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    records = value.get("identities") if isinstance(value, dict) else value
    out: dict[str, dict[str, str]] = {}
    if isinstance(records, dict):
        for label, headers in records.items():
            if isinstance(headers, dict):
                out[str(label)] = {
                    str(k): str(v) for k, v in headers.items()}
    elif isinstance(records, list):
        for record in records:
            if isinstance(record, dict) and record.get("headers"):
                out[str(record.get("label") or "")] = {
                    str(k): str(v)
                    for k, v in record["headers"].items()}
    return out


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).netloc or "").lower()
    except ValueError:
        return ""


def reverify_finding(
    finding: dict[str, Any],
    finding_dir: str | pathlib.Path,
    *,
    identities: dict[str, dict[str, str]],
    authorized_scopes: list[str],
    evidence_sink: Callable[[str, str], str],
    budget: ReverifyBudget,
    rps: float = DEFAULT_RPS,
    transport: Callable[[_verify.Request], _verify.Response] | None = None,
    clock: Callable[[], float] = time.time,
    throttle: HostThrottle | None = None,
) -> dict[str, Any]:
    """Replay one finding's idempotent readback and classify the outcome.

    ``evidence_sink(request_text, response_text) -> evidence_ref`` is provided
    by the caller: it persists the replay packet under
    ``<project_dir>/sessions/<sid>/findings/<finding_id>/`` and registers the
    hash into the current artifact set.  ``transport``/``clock``/``throttle``
    are test seams; production uses ``verify.urllib_transport``.
    """
    started = clock()
    finding_dir = pathlib.Path(finding_dir)
    verification = (
        finding.get("verification")
        if isinstance(finding.get("verification"), dict) else {})
    replay_spec = (
        verification.get("replay")
        if isinstance(verification.get("replay"), dict) else None)
    fid = str(finding.get("id") or finding_dir.name)
    if not replay_spec:
        return ReverifyOutcome(
            "blocked", REASONS["missing_replay"]).__dict__ | {"finding_id": fid}
    # ---- schema-level replay gate (mirrors validate.py; defense in depth) --
    request_file = str(replay_spec.get("request_file") or "").strip()
    identity_label = str(replay_spec.get("identity") or "").strip()
    # 场景 6（§3.6.6）：baseline_identity 缺失 → 拒收（全类差分基线是主防线，
    # 不允许静默默认）；显式 "anon" 不在 identities.json 时按空 auth（真匿名）。
    baseline_label = str(replay_spec.get("baseline_identity") or "").strip()
    expectation = (
        replay_spec.get("expectation")
        if isinstance(replay_spec.get("expectation"), dict) else {})
    expected_status = expectation.get("status")
    required_markers = _compile_markers(expectation.get("required_markers"))
    absent_markers = _compile_markers(expectation.get("absent_markers"))
    control_url = str(replay_spec.get("control_url") or "").strip()
    throttler = throttle or HostThrottle(rps=rps)
    transport = transport or _verify.urllib_transport

    def fail(outcome: str, reason: str) -> dict[str, Any]:
        data = ReverifyOutcome(outcome, reason).__dict__
        data["finding_id"] = fid
        return data

    if str(replay_spec.get("kind") or "") != REPLAY_KIND:
        return fail("blocked", REASONS["invalid_replay"] + ": kind!=readback")
    if not request_file or not identity_label:
        return fail("blocked", REASONS["invalid_replay"] + ": request_file/identity required")
    if not baseline_label:
        return fail("blocked", REASONS["invalid_replay"] + ": baseline_identity 必填（全类差分基线）")
    if identity_label not in identities:
        return fail("blocked", REASONS["invalid_replay"] + f": identity {identity_label!r} 不在 identities.json")
    if not required_markers:
        return fail("blocked", REASONS["invalid_replay"] + ": required_markers 必须 ≥1")
    for marker in [*required_markers, *absent_markers]:
        if probe_rejects(marker):
            return fail("blocked", REASONS["marker_refused"] + f": 弱模式 {marker!r}")
        try:
            re.compile(marker)
        except re.error as exc:
            return fail("blocked", REASONS["invalid_replay"] + f": marker 编译失败 {exc}")
        # 去转义长度门（镜像 validate.py:1044-1049，防御纵深——继承复验路径
        # 不经过 validate 层，Gate-B P2 补齐）
        literal = re.sub(r"\\[dDwWsSbBAZ]", "", marker).replace("\\", "")
        literal = re.sub(r"[.*+?\[\]()|^${}]", "", literal)
        if len(literal.strip()) < 4:
            return fail("blocked", REASONS["marker_refused"] + f": 去转义字面长度<4 {marker!r}")
    request_path = finding_dir / request_file
    if not request_path.is_file():
        return fail("blocked", REASONS["invalid_replay"] + f": request_file 缺失 {request_file}")
    try:
        request = _verify.extract_poc_from_file(request_path)
    except OSError:
        request = None
    if request is None or not request.url:
        return fail("blocked", REASONS["unparsable_request"])
    if request.method.upper() not in _verify.IDEMPOTENT:
        return fail("blocked", REASONS["guard_denied"] + f": 非幂等方法 {request.method}")
    auth = identities.get(identity_label) or {}
    baseline_auth = identities.get(baseline_label, {})
    if baseline_label == identity_label:
        return fail("blocked", REASONS["invalid_replay"] + ": baseline_identity 不得与 identity 相同")

    def do_replay(req: _verify.Request) -> tuple[_verify.Response, bool]:
        """One guarded replay with budget + throttle + exactly-one retry.

        Returns (response, retried).  Budget counts every request incl. the
        retry and the differential baseline.
        """
        retried = False
        while True:
            if not budget.spend(1):
                return _verify.Response(0, {}, "<rate_budget>"), retried
            throttler.throttle(_host_of(req.url))
            resp = _verify.replay(req, transport, authorized_scopes)
            if (resp.status == 0 or resp.status >= 500) and not retried:
                retried = True
                continue
            return resp, retried

    # ---- replay the readback with the attack identity ----------------------
    try:
        response, _retried = do_replay(request.with_identity(auth))
    except PermissionError as exc:
        return fail("blocked", f"{REASONS['guard_denied']}: {exc}")
    body = _subject(response.body)

    def sink(response_value: _verify.Response, extra: str = "") -> str:
        packet = (
            f"{request.method} {request.url}\n"
            + "".join(f"{k}: {v}\n" for k, v in sorted(request.headers.items()))
            + "\n"
            + f"HTTP {response_value.status}\n{response_value.body}\n"
            + extra)
        return evidence_sink(packet)

    if response.status == 0 and body == "<rate_budget>":
        return fail("barrier", REASONS["rate_budget"])
    if response.status == 0:
        evidence_ref = sink(response)
        return ReverifyOutcome(
            "barrier", f"{REASONS['transport_error']}: {body[:120]}",
            evidence_ref=evidence_ref,
            latency_ms=int((clock() - started) * 1000),
            requests=budget.used).__dict__ | {"finding_id": fid}
    if response.status >= 500:
        evidence_ref = sink(response)
        return ReverifyOutcome(
            "barrier", f"{REASONS['transport_error']}: HTTP {response.status}",
            evidence_ref=evidence_ref,
            latency_ms=int((clock() - started) * 1000),
            requests=budget.used).__dict__ | {"finding_id": fid}
    if response.status == 401:
        evidence_ref = sink(response)
        return ReverifyOutcome(
            "barrier", REASONS["session_expired"],
            evidence_ref=evidence_ref,
            latency_ms=int((clock() - started) * 1000),
            requests=budget.used).__dict__ | {"finding_id": fid}
    if response.status == 403:
        if control_url and _host_of(control_url) == _host_of(request.url):
            try:
                control_resp, _ = do_replay(
                    request.with_url(control_url).with_identity(auth))
            except PermissionError:
                control_resp = None
            if control_resp is not None and 200 <= control_resp.status < 300:
                evidence_ref = sink(response, f"\ncontrol {control_url} -> HTTP {control_resp.status}\n")
                return ReverifyOutcome(
                    "mismatch",
                    "403 + 对照端点同身份可达 → 授权结果变化（非环境阻塞）",
                    evidence_ref=evidence_ref,
                    latency_ms=int((clock() - started) * 1000),
                    requests=budget.used).__dict__ | {"finding_id": fid}
        evidence_ref = sink(response)
        return ReverifyOutcome(
            "barrier", REASONS["forbidden"],
            evidence_ref=evidence_ref,
            latency_ms=int((clock() - started) * 1000),
            requests=budget.used).__dict__ | {"finding_id": fid}

    # ---- expectation matching --------------------------------------------
    marker_hits = [m for m in required_markers if not marker_matches(m, body)]
    status_ok = (
        expected_status is None
        or int(expected_status) == response.status)
    absent_ok = not any(marker_matches(m, body) for m in absent_markers)
    if not (status_ok and not marker_hits and absent_ok):
        detail = []
        if not status_ok:
            detail.append(f"HTTP {response.status} != {expected_status}")
        if marker_hits:
            detail.append(f"required_markers 未命中: {marker_hits}")
        if not absent_ok:
            detail.append("absent_markers 命中")
        evidence_ref = sink(response)
        return ReverifyOutcome(
            "mismatch", f"{REASONS['expectation_mismatch']}: " + "; ".join(detail),
            evidence_ref=evidence_ref,
            latency_ms=int((clock() - started) * 1000),
            requests=budget.used).__dict__ | {"finding_id": fid}

    # ---- all-class differential baseline (Gate-A R2 P1-11) ---------------
    try:
        baseline_resp, _ = do_replay(request.with_identity(baseline_auth))
    except PermissionError as exc:
        return fail("blocked", f"{REASONS['guard_denied']}: baseline {exc}")
    if baseline_resp.status == 0 or baseline_resp.status >= 500:
        # Gate-B P1：基线拿到 <rate_budget> 哨兵或传输失败时，marker 必然不命中，
        # 不检查即静默升格——主防线被跳过。基线不可判定 = barrier，禁止升格。
        return ReverifyOutcome(
            "barrier", REASONS["baseline_inconclusive"],
            baseline_outcome="barrier",
            latency_ms=int((clock() - started) * 1000),
            requests=budget.used).__dict__ | {"finding_id": fid}
    baseline_body = _subject(baseline_resp.body)
    baseline_hits = [m for m in required_markers if marker_matches(m, baseline_body)]
    baseline_note = (
        f"baseline[{baseline_label}] HTTP {baseline_resp.status}")
    if baseline_hits:
        evidence_ref = sink(
            response, f"\n{baseline_note} markers 命中 {baseline_hits}\n")
        return ReverifyOutcome(
            "mismatch", REASONS["baseline_hit"] + f" ({baseline_hits})",
            evidence_ref=evidence_ref,
            baseline_outcome="mismatch",
            latency_ms=int((clock() - started) * 1000),
            requests=budget.used).__dict__ | {"finding_id": fid}
    evidence_ref = sink(response, f"\n{baseline_note} 无 marker 命中\n")
    return ReverifyOutcome(
        "match", "回查吻合且基线不命中",
        evidence_ref=evidence_ref,
        baseline_outcome="match",
        latency_ms=int((clock() - started) * 1000),
        requests=budget.used).__dict__ | {"finding_id": fid}


__all__ = [
    "BODY_TRUNCATE_BYTES", "DEFAULT_BUDGET_PER_RUN", "DEFAULT_MAX_AGE_HOURS",
    "IDEMPOTENT_METHODS", "MARKER_PROBES", "REASONS", "REPLAY_KIND",
    "ReverifyBudget", "ReverifyOutcome", "load_identities",
    "marker_matches", "probe_rejects", "reverify_finding",
]
