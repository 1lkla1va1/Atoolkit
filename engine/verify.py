"""
engine/verify.py —— 确定性 PoC 重放验证层（与模型无关）。

定位：Guardian(enforce.py) 管"报告质量"，verify 管"漏洞真假"。
  - 启发式由模型给方向，确定性由本层落实（符号执行×模糊测试的确定性一侧）。
  - 越权/IDOR 的"已证明" = 换另一身份/另一对象ID 重放，拿到了不该拿到的数据。
  - 纯重放 + 对比，无模型参与：confirmed / refuted / inconclusive 三态。

安全红线（硬编码）：
  - 只对授权 host 重放（authorized_hosts 白名单），越界拒绝。
  - 默认只重放幂等方法(GET/HEAD)；非幂等(POST/PUT/DELETE)需显式 allow_mutating=True，
    避免"为验证而下单/改数据"，对齐"不做破坏性操作"。
"""
from __future__ import annotations
import re, shlex, time, urllib.request, urllib.error
from dataclasses import dataclass, field
from typing import Callable

CONFIRMED = "confirmed"
REFUTED = "refuted"
INCONCLUSIVE = "inconclusive"
IDEMPOTENT = {"GET", "HEAD", "OPTIONS"}


@dataclass
class Request:
    method: str = "GET"
    url: str = ""
    headers: dict = field(default_factory=dict)
    body: str | None = None

    AUTH_HEADERS = ("cookie", "authorization", "x-api-key", "x-auth-token", "token")

    def with_identity(self, auth: dict) -> "Request":
        """换身份：先剥离 base 的认证头，再套用该身份的（空 auth = 真匿名）。"""
        clean = {k: v for k, v in self.headers.items() if k.lower() not in self.AUTH_HEADERS}
        return Request(self.method, self.url, {**clean, **auth}, self.body)

    def with_headers(self, extra: dict) -> "Request":
        return Request(self.method, self.url, {**self.headers, **extra}, self.body)

    def with_url(self, url: str) -> "Request":
        return Request(self.method, url, dict(self.headers), self.body)


@dataclass
class Response:
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    elapsed_ms: int = 0


@dataclass
class VerifyResult:
    result: str                      # confirmed | refuted | inconclusive
    reason: str
    evidence: list = field(default_factory=list)   # [(label, status, snippet)]


Transport = Callable[[Request], Response]


# ── PoC 解析：从报告/原始包里抽出请求 ────────────────────────────────────
def parse_curl(cmd: str) -> Request:
    """解析常见 curl 形态：curl -X POST 'url' -H 'K: V' --data '...'"""
    toks = shlex.split(cmd.replace("\\\n", " "))
    method, url, headers, body = None, "", {}, None
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in ("-X", "--request"): method = toks[i + 1]; i += 2; continue
        if t in ("-H", "--header"):
            k, _, v = toks[i + 1].partition(":"); headers[k.strip()] = v.strip(); i += 2; continue
        if t in ("-d", "--data", "--data-raw", "--data-binary"): body = toks[i + 1]; i += 2; continue
        if t in ("-b", "--cookie"): headers["Cookie"] = toks[i + 1]; i += 2; continue
        if t == "curl": i += 1; continue
        if t.startswith("http"): url = t
        i += 1
    return Request(method or ("POST" if body else "GET"), url, headers, body)


def extract_poc(report_md: str) -> Request | None:
    """从报告的代码块里取第一条 curl 或 HTTP 原始包。"""
    for block in re.findall(r"```(?:\w+)?\n(.*?)```", report_md, re.S):
        if "curl" in block:
            line = " ".join(l.strip() for l in block.splitlines() if l.strip() and not l.startswith("HTTP/"))
            return parse_curl(line)
        m = re.match(r"(GET|POST|PUT|DELETE)\s+(\S+)\s+HTTP", block)
        if m:                                            # 原始 HTTP 包
            req = Request(m.group(1), m.group(2))
            for hl in re.findall(r"^([A-Za-z-]+):\s*(.+)$", block, re.M):
                req.headers[hl[0]] = hl[1].strip()
            host = req.headers.get("Host", "")
            if host and req.url.startswith("/"): req.url = "https://" + host + req.url
            return req
    return None


def extract_poc_from_file(path: str | pathlib.Path) -> Request | None:
    """从 curl 脚本或 raw HTTP 文件中抽出第一条请求。"""
    import pathlib as _pathlib

    text = _pathlib.Path(path).read_text(encoding="utf-8", errors="ignore")
    if "curl" in text:
        lines = []
        capture = False
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if "curl" in stripped:
                capture = True
            if capture:
                lines.append(stripped.rstrip("\\").strip())
                if not stripped.endswith("\\"):
                    break
        if lines:
            return parse_curl(" ".join(lines))
    m = re.search(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/", text, re.I | re.M)
    if not m:
        return None
    req = Request(m.group(1).upper(), m.group(2))
    for header, value in re.findall(r"^([A-Za-z-]+):\s*(.+)$", text, re.M):
        req.headers[header] = value.strip()
    host = req.headers.get("Host", "")
    if host and req.url.startswith("/"):
        req.url = "https://" + host + req.url
    sep = "\r\n\r\n" if "\r\n\r\n" in text else "\n\n"
    if sep in text and req.method.upper() not in ("GET", "HEAD", "OPTIONS"):
        req.body = text.split(sep, 1)[1]
    return req


def extract_poc_from_finding(finding: dict, finding_dir: str | pathlib.Path) -> Request | None:
    """优先从 finding.poc.file 抽 PoC，失败时回退 proof_packets[].request_file。"""
    import pathlib as _pathlib

    fdir = _pathlib.Path(finding_dir).resolve()
    run_dir = fdir.parents[1] if fdir.parent.name == "findings" and len(fdir.parents) > 1 else fdir.parent
    try:
        from engine.reporting.schema import resolve_finding_file
    except ImportError:
        from reporting.schema import resolve_finding_file

    poc = finding.get("poc") if isinstance(finding.get("poc"), dict) else {}
    if poc.get("file"):
        req = extract_poc_from_file(resolve_finding_file(fdir, poc.get("file"), run_dir))
        if req:
            return req
    for packet in finding.get("proof_packets") or []:
        if isinstance(packet, dict) and packet.get("request_file"):
            req = extract_poc_from_file(resolve_finding_file(fdir, packet.get("request_file"), run_dir))
            if req:
                return req
    return None


# ── Transport：真实(urllib) 与 测试(mock)────────────────────────────────
def urllib_transport(req: Request) -> Response:
    t0 = time.time()
    r = urllib.request.Request(req.url, method=req.method,
                               data=req.body.encode() if req.body else None,
                               headers=req.headers)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            body = resp.read(65536).decode("utf-8", "ignore")
            return Response(resp.status, dict(resp.headers), body, int((time.time() - t0) * 1000))
    except urllib.error.HTTPError as e:
        return Response(e.code, dict(e.headers), e.read(8192).decode("utf-8", "ignore"),
                        int((time.time() - t0) * 1000))
    except Exception as e:
        return Response(0, {}, f"<transport error: {e}>", int((time.time() - t0) * 1000))


def _host(url: str) -> str:
    m = re.match(r"https?://([^/:]+)", url); return m.group(1) if m else ""


def _guard(req: Request, authorized_hosts: list[str], allow_mutating: bool):
    if not any(h in _host(req.url) for h in authorized_hosts):
        raise PermissionError(f"越权: {req.url} 不在授权白名单")
    if req.method.upper() not in IDEMPOTENT and not allow_mutating:
        raise PermissionError(f"非幂等方法 {req.method} 默认禁止自动重放（allow_mutating=True 才放行）")


# ── 验证策略 ────────────────────────────────────────────────────────────
def replay(req: Request, transport: Transport, authorized_hosts: list[str],
           allow_mutating: bool = False) -> Response:
    _guard(req, authorized_hosts, allow_mutating)
    return transport(req)


def verify_idor(req: Request, identities: dict, victim_marker: str,
                transport: Transport, authorized_hosts: list[str],
                allow_mutating: bool = False) -> VerifyResult:
    """换多身份重放同一请求。非属主身份拿到了 victim_marker → 确认越权。
    identities: {label: {Header:Value}}（如 {'owner':{...},'attacker_B':{...},'guest':{}})"""
    ev, leaked = [], []
    for label, auth in identities.items():
        resp = replay(req.with_identity(auth), transport, authorized_hosts, allow_mutating)
        seen = victim_marker in resp.body
        ev.append((label, resp.status, ("命中受害者数据" if seen else resp.body[:60])))
        if label != "owner" and resp.status == 200 and seen:
            leaked.append(label)
    if leaked:
        return VerifyResult(CONFIRMED, f"非属主身份 {leaked} 读到受害者数据 → 越权成立", ev)
    if any(s == 200 and "命中" in d for _, s, d in ev):
        return VerifyResult(INCONCLUSIVE, "仅属主可读，未证明越权（符合预期）", ev)
    return VerifyResult(REFUTED, "无身份读到受害者数据 → 未复现", ev)


def verify_id_tamper(req: Request, id_param: str, id_values: list[str],
                     owner_marker_fn: Callable[[str], bool],
                     transport: Transport, authorized_hosts: list[str],
                     allow_mutating: bool = False) -> VerifyResult:
    """遍历对象ID(3-5个)。返回了非自己ID的有效数据 → 确认 IDOR。"""
    ev, hits = [], []
    for v in id_values:
        url = re.sub(rf"({re.escape(id_param)}[=/])[^/&?]+", rf"\g<1>{v}", req.url)
        resp = replay(req.with_url(url), transport, authorized_hosts, allow_mutating)
        other = resp.status == 200 and owner_marker_fn(resp.body)
        ev.append((f"{id_param}={v}", resp.status, "返回他人数据" if other else resp.body[:50]))
        if other: hits.append(v)
    if len(hits) >= 2:
        return VerifyResult(CONFIRMED, f"遍历 {id_param} 命中 {len(hits)} 条他人数据 → IDOR 成立", ev)
    if hits:
        return VerifyResult(INCONCLUSIVE, f"仅 1 条命中，建议加测样本", ev)
    return VerifyResult(REFUTED, "遍历无他人数据返回 → 未复现", ev)


# ── 自检：mock transport 演示 confirmed vs refuted（无需联网）──────────────
if __name__ == "__main__":
    AUTH = ["t.example"]
    base = Request("GET", "https://t.example/api/orders/1001",
                   {"Cookie": "session=OWNER"})

    def vulnerable(req: Request) -> Response:        # 不校验归属：谁来都给 A 的数据
        return Response(200, {}, '{"order":1001,"用户":"A","收货地址":"北京..."}')

    def secure(req: Request) -> Response:            # 严格校验：非属主 403
        ck = req.headers.get("Cookie", "")
        if "OWNER" in ck: return Response(200, {}, '{"order":1001,"用户":"A"}')
        return Response(403, {}, '{"error":"forbidden"}')

    ids = {"owner": {"Cookie": "session=OWNER"},
           "attacker_B": {"Cookie": "session=B"},
           "guest": {}}

    print("=== verify_idor 对【有漏洞】端点 ===")
    r1 = verify_idor(base, ids, victim_marker='"用户":"A"', transport=vulnerable, authorized_hosts=AUTH)
    print(f"  [{r1.result}] {r1.reason}")
    for label, st, snip in r1.evidence: print(f"    {label:12} HTTP {st}  {snip}")

    print("=== verify_idor 对【安全】端点 ===")
    r2 = verify_idor(base, ids, victim_marker='"用户":"A"', transport=secure, authorized_hosts=AUTH)
    print(f"  [{r2.result}] {r2.reason}")

    print("=== verify_id_tamper 遍历对象ID（有漏洞）===")
    r3 = verify_id_tamper(base, "orders/", ["1002", "1003", "1004"],
                          owner_marker_fn=lambda b: '"用户"' in b,
                          transport=vulnerable, authorized_hosts=AUTH)
    print(f"  [{r3.result}] {r3.reason}")

    print("=== 越权 host 防护 ===")
    try:
        replay(Request("GET", "https://evil.com/x"), secure, AUTH)
    except PermissionError as e:
        print(f"  拦截: {e}")

    print("=== 从报告抽 PoC 再验证 ===")
    report = ("---\nseverity: P1\n---\n```\ncurl 'https://t.example/api/orders/1001' "
              "-H 'Cookie: session=OWNER'\nHTTP/1.1 200\n```")
    req = extract_poc(report)
    print(f"  解析: {req.method} {req.url}  headers={list(req.headers)}")
