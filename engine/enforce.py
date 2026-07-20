"""
engine/enforce.py —— 外部强制层（纯代码，模型碰不到）。

核心 = Guardian 八级报告质检门（借鉴 TianTi 客户端 Agent 的 Guardian 设计）：
  - 确定性规则 > Prompt 祈祷：质量标准写进代码，不寄望模型自觉。
  - 短路检测：首个命中即返回，三种判定 accepted / demoted / rejected。
  - demoted 不丢弃：降级保留进 ledger，可重验升级，防误杀真洞。

把核心技能文件 v2 的"软约束"翻译成"硬判定"：
  垃圾洞清单 / 七问验证门 / 报告格式≥200字 / 现象≠结果 / 物理证据>声明。

另含 §5 其它强制原语：危险命令拦截、授权 host 校验、终态十二条裁定（节选）。
全部与模型无关：换任何模型，本文件零改动。
"""
from __future__ import annotations
import re
import pathlib
from dataclasses import dataclass, field

try:
    from .host_policy import is_authorized_url
except ImportError:  # pragma: no cover - direct script execution
    from host_policy import is_authorized_url

# ── 判定结果 ────────────────────────────────────────────────────────────
ACCEPTED = "accepted"   # 全过 → 进漏洞统计
DEMOTED  = "demoted"    # 降级为 phenomenon（保留，不丢弃，可重验升级）
REJECTED = "rejected"   # 入库但报告层过滤


@dataclass
class Verdict:
    result: str            # accepted | demoted | rejected
    level: int             # 命中的级别 0..8（8=全过）
    reason: str
    severity: str = ""     # 解析出的等级


# ── 关键词/正则（可随实战迭代，等同 v2 垃圾洞清单的代码化）─────────────────
GARBAGE_TITLE = [          # L1 垃圾洞清单：标题/类型命中即 rejected
    "cors", "sourcemap", ".map", "x-frame-options", "csp", "hsts",
    "安全头", "安全响应头", "版本号", "指纹", "self-xss", "self xss",
    "ssl", "tls", "限频", "rate limit", "rate-limit", "速率限制",
    "目录列举", "目录遍历列举", "默认页", "报错堆栈", "堆栈泄露",
]

SPECULATION = [            # L5 投机措辞 → rejected
    "可能", "疑似", "也许", "或许", "理论上", "猜测", "估计", "大概",
    "应该能", "应该可以", "应当可", "推测", "怀疑",
    "might", "maybe", "probably", "could be", "should be", "appears to", "seems",
]
CONDITIONAL = [            # L6 假设/条件投机（前提未实际发生）→ demoted
    "如果", "假如", "假设", "倘若", "前提是", "前提为", "若能", "一旦",
    "in theory", "if exploited", "可被用于",
]

RESULT_VERBS = [           # L7 结果动词：报告必须出现至少一个（现象≠结果）
    "越权", "未授权访问", "读取了", "写入了", "删除了", "执行了", "提取了",
    "接管", "伪造了", "绕过了", "泄露了", "篡改了", "获取了", "下单成功",
    "支付成功", "提现", "dump", "命令执行", "任意文件", "rce", "0元", "0 元",
    # —— 补全各漏洞类的「已证明结果」措辞，避免真洞被 L7 误降级 ——
    "ssrf", "代为访问", "访问了内网", "请求伪造", "回显了", "探测到内网", "打到内网",  # SSRF
    "读到了", "下载了", "路径穿越", "目录穿越", "任意文件读取", "穿越读取", "/etc/passwd",  # 文件读/穿越
    "脚本执行", "弹窗", "alert(", "未转义", "注入了脚本", "存储型xss", "反射型xss", "xss",  # XSS
    "注入成功", "盲注", "拖库", "查询出", "sql注入", "布尔盲注", "时间盲注",            # SQLi
    "跨站伪造", "csrf",                                                          # CSRF
    "上传了", "webshell", "getshell", "落地访问", "解析执行", "上传成功",            # 上传
]
PHENOMENON_VERBS = ["发现", "暴露", "存在一个", "可访问到", "检测到", "疑似存在"]

POC_MARKERS = [            # L3 可执行 PoC 标记
    "curl ", "http/1.1", "http/2", "\nget ", "\npost ", "\nput ", "\ndelete ",
    "authorization:", "cookie:", "x-forwarded", "->", "```",
]
RESPONSE_MARKERS = ["响应", "http/1.1 2", "http/1.1 3", "http/1.1 4", "http/1.1 5",
                    "< http", "status", "set-cookie", "返回包", "response"]

MIN_BODY_CHARS = 200       # L2 报告格式：正文 ≥ 200 字
MIN_DESC_CHARS = 30        # 单段描述过短阈值（TianTi 同源）


# ── 报告解析 ────────────────────────────────────────────────────────────
def _parse(report: str) -> dict:
    """从 v2 报告 markdown 抽 frontmatter + 正文。"""
    fm = {}
    m = re.match(r"\s*---\s*\n(.*?)\n---\s*\n(.*)$", report, re.S)
    body = report
    if m:
        for line in m.group(1).splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                fm[k.strip().lower()] = v.strip()
        body = m.group(2)
    return {"fm": fm, "body": body, "low": report.lower()}


def _has(text: str, kws) -> str | None:
    for k in kws:
        if k in text:
            return k
    return None


# ── Guardian 八级短路质检门 ──────────────────────────────────────────────
def guardian_check(report: str, evidence_dir: str | None = None,
                   authorized_hosts: list[str] | None = None) -> Verdict:
    """对一份候选报告做八级短路检测。首个命中即返回。"""
    p = _parse(report)
    fm, body, low = p["fm"], p["body"], p["low"]
    title = fm.get("title", "")
    target = fm.get("target", "")
    sev = (fm.get("severity", "") or "").upper()

    # L1 垃圾洞清单（标题/类型）→ rejected
    hit = _has((title + " " + fm.get("type", "")).lower(), GARBAGE_TITLE)
    if hit:
        return Verdict(REJECTED, 1, f"垃圾洞清单命中: {hit}", sev)

    # L2 结构/格式：等级∈P1-3、有标题、正文≥200字 → 否则 rejected
    if sev not in ("P1", "P2", "P3"):
        return Verdict(REJECTED, 2, f"severity 非 P1/P2/P3: {sev or '缺失'}", sev)
    if not title:
        return Verdict(REJECTED, 2, "缺标题", sev)
    if not target:
        return Verdict(REJECTED, 2, "缺 target", sev)
    if len(re.sub(r"\s", "", body)) < MIN_BODY_CHARS:
        return Verdict(REJECTED, 2, f"正文 < {MIN_BODY_CHARS} 字", sev)

    # L3 可执行 PoC（curl/HTTP/命令）缺失 → demoted（七问门#2）
    if not _has(low, POC_MARKERS):
        return Verdict(DEMOTED, 3, "无可执行 PoC（curl/HTTP/命令）", sev)

    # L4 落盘证据缺失（物理证据 > 声明）→ demoted
    if not _has(low, RESPONSE_MARKERS):
        return Verdict(DEMOTED, 4, "报告无响应/返回包证据", sev)
    if evidence_dir:
        ed = pathlib.Path(evidence_dir)
        if not ed.exists() or not any(ed.iterdir()):
            return Verdict(DEMOTED, 4, f"证据目录空: {evidence_dir}", sev)

    # L5 投机措辞 → rejected。Legacy Markdown 没有结构化的 root/impact/
    # chain 边界，因此不能允许把“可能接管”等下游推断藏在影响段里。
    claim = (title + "\n" + body).lower()
    hit = _has(claim, SPECULATION)
    if hit:
        return Verdict(REJECTED, 5, f"投机措辞(论断区): {hit}", sev)

    # L6 假设/条件投机（前提未实际发生）→ demoted（七问门#3「需假设→不报」）
    hit = _has(low, CONDITIONAL)
    if hit:
        return Verdict(DEMOTED, 6, f"条件句投机(前提未发生): {hit}", sev)

    # L7 现象 ≠ 结果：必须出现结果动词，否则 demoted 为 phenomenon
    if not _has(low, [v.lower() for v in RESULT_VERBS]):
        ph = _has(low, PHENOMENON_VERBS)
        return Verdict(DEMOTED, 7, f"只是现象，无结果动词{f'(命中现象词:{ph})' if ph else ''}", sev)

    # L8 授权范围（可选硬校验）+ 全通过
    if authorized_hosts and target:
        if not is_authorized_url(target, authorized_hosts):
            return Verdict(REJECTED, 8, f"目标越权: {target} 不在授权白名单", sev)
    return Verdict(ACCEPTED, 8, "全部通过", sev)


def triage(reports: list[str], **kw) -> dict:
    """对一批报告分流。demoted/rejected 不丢弃，全部留档（可重验升级）。"""
    ledger = {ACCEPTED: [], DEMOTED: [], REJECTED: []}
    for r in reports:
        v = guardian_check(r, **kw)
        ledger[v.result].append((v, r))
    return ledger


def _clip_text(path: pathlib.Path, limit: int = 1600) -> str:
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    return text if len(text) <= limit else text[:limit].rstrip() + "\n... truncated"


def guardian_check_finding(
    finding: dict,
    finding_dir: str | pathlib.Path,
    authorized_hosts: list[str] | None = None,
    *,
    context=None,
) -> Verdict:
    """Validate a structured finding, then reuse Guardian on a Markdown excerpt."""
    fdir = pathlib.Path(finding_dir).resolve()
    run_dir = fdir.parents[1] if fdir.parent.name == "findings" and len(fdir.parents) > 1 else fdir.parent
    try:
        from engine.reporting.validate import validate_finding
        from engine.reporting.schema import resolve_finding_file
    except ImportError:
        from reporting.validate import validate_finding
        from reporting.schema import resolve_finding_file

    finding_path = fdir / "finding.json"
    validation = validate_finding(
        finding, finding_path, run_dir,
        authorized_hosts=authorized_hosts, context=context)
    sev = str(finding.get("severity") or "").upper()
    if not validation.ok:
        return Verdict(REJECTED, 2, "structured finding invalid: " + "; ".join(validation.reasons), sev)

    risk = finding.get("risk") or {}
    poc = finding.get("poc") or {}
    blocks: list[str] = [
        "---",
        f"severity: {sev}",
        f"title: {finding.get('title', '')}",
        f"target: {finding.get('target', '')}",
        f"type: {finding.get('vuln_type', '')}",
        "---",
        "## 漏洞描述",
        str(risk.get("summary", "")),
        "## 影响范围",
        "已证明影响：" + str(risk.get("proven_impact", "")),
        "该 finding 已通过结构化证据校验，包含请求包、响应包、手工 Burp 复测步骤和可执行 PoC。",
    ]
    if poc.get("file"):
        poc_path = resolve_finding_file(fdir, poc.get("file"), run_dir)
        blocks.extend(["## PoC", "```", _clip_text(poc_path), "```"])
    for packet in finding.get("proof_packets") or []:
        if not isinstance(packet, dict):
            continue
        blocks.append("## 响应证据")
        blocks.append(str(packet.get("evidence_summary") or ""))
        for key in ("request_file", "response_file"):
            if packet.get(key):
                path = resolve_finding_file(fdir, packet.get(key), run_dir)
                blocks.extend(["```", _clip_text(path), "```"])
    blocks.append("## 复测步骤")
    for step in finding.get("manual_burp_replay") or []:
        blocks.append(f"- {step}")
    excerpt = "\n".join(blocks)
    return guardian_check(excerpt, evidence_dir=str(fdir), authorized_hosts=authorized_hosts)


# ── §5 危险动作分级闸（治本：判「执行的命令」，不判模型叙述/抓回的数据）──────
# 判别轴 = 动作(读/建/改删) × 归属(自有/他人) × 可逆性，而非 SQL 关键词本身。
# 三档：allow 自动放行 / confirm 暂停人工确认 / block 灾难必杀（借鉴 bug bounty
#   RoE「demonstrate, don't damage」+ agent 安全「gate the action not the narration,
#   pause don't kill」）。
# ⚠ 说明：codex exec 是流式「事后」输出——命中 confirm/block 时该条其实已执行。
#   本闸是「熔断器」：拦在这一条、阻断后续级联破坏，并把现场交人工；真正的「执行前」
#   拦截要靠 codex 沙箱/审批，网络型改删沙箱管不到，故此层兜底。
ALLOW, CONFIRM, BLOCK = "allow", "confirm", "block"

HARD_BLOCK = [                       # 永远不是合法 PoC：整表/整库/宿主级毁灭 → 必杀
    r"rm\s+-rf\s+/", r"\bmkfs\b", r":\(\)\s*\{.*\};:",
    r">\s*/dev/sd", r"dd\s+if=.*of=/dev",
    r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b", r"\bTRUNCATE\b",
]
_MUT_HTTP = re.compile(r"(?:-X|--request)[=\s]+(?:DELETE|PUT|PATCH)\b", re.I)
_MUT_SQL  = re.compile(r"\b(?:UPDATE|DELETE|INSERT|REPLACE|ALTER|GRANT|MERGE)\b", re.I)
_STACKED  = re.compile(r";\s*(?:UPDATE|DELETE|INSERT|DROP|ALTER|TRUNCATE|GRANT)\b", re.I)
_BULK     = re.compile(r"(?:batch|bulk|delete[-_]?all|/admin/|mass[-_]?)", re.I)
_SAFE_SQL = re.compile(r"\b(?:SELECT|SLEEP|BENCHMARK|PG_SLEEP|WAITFOR|@@version|VERSION\(|CURRENT_USER)\b", re.I)
# 只有「真发请求 / 真连库」的命令才可能造成实际改删；本地只读检索(rg/grep/…)里出现
# UPDATE/delete-all 等只是被搜索的内容，不能据此熔断。区分动作而非叙述。
_NET_CMD  = re.compile(r"\b(?:curl|wget|xh|httpie|nc|ncat|netcat|telnet|sqlmap|ab|wrk|lwp-request)\b", re.I)
_DB_CLIENT= re.compile(r"\b(?:mysql|mariadb|psql|mongo|mongosh|sqlite3|redis-cli|sqlplus|sqlcmd)\b", re.I)
# codex 实际执行的命令形如 `/bin/zsh -lc '...'`；只从这类行抽命令，数据/叙述一律忽略。
_EXEC_LINE = re.compile(r"(?:bash|zsh|sh)\s+-l?c\s+(['\"])(.+?)\1", re.S)
_ID_PATH  = re.compile(r"/(\d{1,12})(?=[/?\s'\"]|$)")
_ID_UUID  = re.compile(r"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b", re.I)
_ID_PARAM = re.compile(r"[?&](?:id|uid|user_id|order_id)=([\w-]+)", re.I)


def extract_executed_cmds(text: str) -> list[str]:
    """从 codex 流里抽「真正执行过的」命令串（只认 shell -c 调用）。
    这就是 #6 的治本点：`/api/projects` 响应数据里的 'DROP TABLE' 不在 -c 调用里 → 不会被抽到。"""
    return [m.group(2) for m in _EXEC_LINE.finditer(text)]


def _ids_in(cmd: str) -> set[str]:
    return set(_ID_PATH.findall(cmd)) | set(_ID_UUID.findall(cmd)) | set(_ID_PARAM.findall(cmd))


def classify_action(cmd: str, owned_ids: set[str] | None = None) -> tuple[str, str]:
    """对「一条已执行命令」分级 → (allow|confirm|block, 原因)。
    owned_ids：本会话自有对象 id 集合；改删类若目标全在其中则自动放行（你说的「插/改自己的没事」）。"""
    owned = set(owned_ids or ())
    for pat in HARD_BLOCK:
        if re.search(pat, cmd, re.I):
            return (BLOCK, f"灾难性操作: {pat}")
    # 既非网络请求也非 DB 客户端 → 本地只读/检索(rg/grep/find/cat/sed…)，关键词只是检索内容 → 放行
    if not _NET_CMD.search(cmd) and not _DB_CLIENT.search(cmd):
        return (ALLOW, "本地只读/检索命令(无网络·DB 客户端)")
    reason = None
    if _STACKED.search(cmd):                                 reason = "堆叠写查询"
    elif _BULK.search(cmd):                                  reason = "批量/管理操作"
    elif _MUT_HTTP.search(cmd):                              reason = "改/删 HTTP 方法(PUT/PATCH/DELETE)"
    # 裸 UPDATE/DELETE 关键词只在「DB 客户端命令」里才当写类 SQL；HTTP 层的写靠方法(_MUT_HTTP)
    # 与堆叠查询(_STACKED)判，避免把 URL 路径名(如 /api/update-bug-status 的 GET)误判成写。
    elif _DB_CLIENT.search(cmd) and _MUT_SQL.search(cmd) and not _SAFE_SQL.search(cmd):
                                                            reason = "DB 客户端写类 SQL(UPDATE/DELETE/INSERT/ALTER)"
    if reason:
        ids = _ids_in(cmd)
        if ids and ids <= owned:        # 目标全是自有对象 → 自动放行
            return (ALLOW, f"{reason}，但目标均为自有对象 {sorted(ids)}")
        foreign = ids - owned
        tail = f"含非自有 id {sorted(foreign)}" if foreign else "目标未知/无 id"
        return (CONFIRM, f"{reason}；{tail}")
    return (ALLOW, "只读/无害(读取·时间盲注·单条新建)")


def hits_danger(text: str) -> str | None:
    """向后兼容：只对「已执行命令」里的灾难性操作返回命中（不再误伤数据/叙述）。"""
    for cmd in extract_executed_cmds(text):
        for pat in HARD_BLOCK:
            if re.search(pat, cmd, re.I):
                return pat
    return None


def is_authorized_host(url: str, authorized_hosts: list[str]) -> bool:
    """授权 host 校验：出站发包前调用，越界即拦（铁律）。"""
    return is_authorized_url(url, authorized_hosts)


def finalize(marker: str | None, has_valid_report: bool) -> str:
    """终态十二条决策规则（节选）：物理证据可推翻模型声明。"""
    if marker == "VULN_FOUND" and not has_valid_report:
        return DEMOTED if False else "low_roi"          # 声明却无报告 → 降级
    if marker in ("LOW_ROI", "NEED_INPUT") and has_valid_report:
        return "vuln_found"                              # 有证据 → 升级
    if marker is None and has_valid_report:
        return "vuln_found"                              # 无标记有证据 → 补救
    return (marker or "error").lower()


# ── 自检（运行 `python3 engine/enforce.py` 看八级是否如预期）──────────────
if __name__ == "__main__":
    samples = {
        "垃圾洞(CORS)": "---\nseverity: P3\ntitle: CORS 配置不当\ntype: CORS\n---\n" + "x" * 250,
        "无PoC": "---\nseverity: P2\ntitle: 订单越权\ntype: 越权\n---\n" + "通过遍历订单ID越权读取了其他用户订单。" * 10,
        "投机措辞": "---\nseverity: P1\ntitle: 可能的SQL注入\ntype: 注入\n---\nsort 参数可能存在注入，理论上能 dump 数据。\ncurl 'http://t/api?sort=id'\n响应 200" + "占位" * 80,
        "只是现象": "---\nseverity: P2\ntitle: 暴露内部API\ntype: 信息\n---\n发现了一个内部 API 路径 /admin/users，接口可访问到。\ncurl http://t/admin/users\n响应 200。" + "该接口暴露在外网且无明显鉴权提示。" * 12,
        "合格(越权)": "---\nseverity: P1\ntitle: 订单IDOR越权读取\ntarget: https://t.example\ntype: 越权\n---\n换用 B 账号 Cookie 越权读取了 A 用户订单，提取了收货地址与金额。\n```\ncurl 'https://t.example/api/orders/1001' -H 'Cookie: B'\nHTTP/1.1 200 ... 返回了 A 的订单\n```" + "证据" * 80,
        "拒绝(下游影响仍是推断)": "---\nseverity: P1\ntitle: 未授权访问 get-users 泄露明文密码\ntarget: https://t.example\ntype: 未授权访问\n---\n## 漏洞描述\n未授权请求读取了用户记录。\n## 影响范围\n可能造成账户接管。\n## 复现\n```\ncurl 'https://t.example/api/get-users'\nHTTP/1.1 200 ... 返回了记录\n```" + "证据" * 80,
    }
    for name, rep in samples.items():
        v = guardian_check(rep, authorized_hosts=["t.example"])
        print(f"[{v.result:8}] L{v.level}  {name:14} → {v.reason}")

    print("\n=== 危险动作分级闸自检（gate the action, not the narration）===")
    owned = {"1001", "660a06f7-07f7-4692-9d1c-780106896e3a"}     # 本会话自有对象 id
    gate_cases = [
        # (名称, 流片段, 期望档)  —— 流片段含 `-c '...'` 才算「已执行命令」
        ("数据里出现 DROP TABLE(非命令)", '{"not_accepted_vulns":["DROP TABLE users; --"]}', ALLOW),
        ("执行: 只读 GET",               "/bin/zsh -lc 'curl -s http://t/api/orders/1001'", ALLOW),
        ("执行: 时间盲注(只读证明)",      "/bin/zsh -lc \"curl 'http://t/api?id=1 AND SLEEP(5)'\"", ALLOW),
        ("执行: 单条新建 POST",          "/bin/zsh -lc 'curl -X POST http://t/api/orders -d @x.json'", ALLOW),
        ("执行: 删自有订单 1001",        "/bin/zsh -lc 'curl -X DELETE http://t/api/orders/1001'", ALLOW),
        ("执行: 删他人订单 2002",        "/bin/zsh -lc 'curl -X DELETE http://t/api/orders/2002'", CONFIRM),
        ("执行: 改他人资料 PUT",         "/bin/zsh -lc 'curl -X PUT http://t/api/users/9 -d x'", CONFIRM),
        ("执行: 批量删除",               "/bin/zsh -lc 'curl http://t/api/admin/delete-all'", CONFIRM),
        ("执行: 整表 DROP(必杀)",        "/bin/zsh -lc 'mysql -e \"DROP TABLE users\"'", BLOCK),
        ("执行: rm -rf /(必杀)",         "/bin/zsh -lc 'rm -rf /'", BLOCK),
        # 回归:本地 rg 检索 pattern 含 update-bug-status/update_tax_info → 不是写,放行(live turn-0 误杀根因)
        ("recon: rg 含SQL关键词(只读检索)", "/bin/zsh -lc 'rg -n \"update-bug-status|update_tax_info\" .'", ALLOW),
        # 回归:GET 一个名字里含 update 的端点 → 无写方法、非 DB 客户端 → 放行(不被路径名误判)
        ("执行: GET 含update的端点路径",   "/bin/zsh -lc 'curl -s http://t/api/update-bug-status'", ALLOW),
        # DB 客户端真写 UPDATE → 仍 CONFIRM(保护未削弱)
        ("执行: mysql UPDATE 他人",       "/bin/zsh -lc 'mysql -e \"UPDATE users SET role=1 WHERE id=9\"'", CONFIRM),
    ]
    ok = True
    for name, stream, want in gate_cases:
        cmds = extract_executed_cmds(stream)
        got, why = (ALLOW, "无已执行命令") if not cmds else classify_action(cmds[0], owned)
        flag = "✓" if got == want else "✗ 期望 " + want
        ok = ok and got == want
        print(f"[{got:7}] {name:24} → {why}   {flag}")
    print("gate 自检:", "全部通过 ✓" if ok else "有用例未通过 ✗")
