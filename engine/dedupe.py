"""
engine/dedupe.py —— finding 按根因聚合（skill §6）。

Guardian 判单份报告是否可报；本模块把 accepted 报告按
``finding_key = endpoint + root_cause + affected_role`` 聚合，使同一端点、同一根因、
同一受影响角色的多份表现不重复计为多个独立高危发现。不同表现写入 ``facets``。

设计约束（与 orchestrator 一致）：
  - 纯确定性、与模型无关：只读报告 frontmatter 与正文路径，不判手法。
  - 聚合只影响「计数/排序」，不影响单份报告的成立性（成立性由 Guardian 定）。
  - 不导入 orchestrator（避免循环依赖），endpoint 归一化在本文件内自洽。
"""
from __future__ import annotations
import re
from typing import Any


# 严重度排序：P1 最高。聚合后取最高严重度作 finding 的 severity。
_SEV_RANK = {"P1": 3, "P2": 2, "P3": 1}

# ── endpoint 归一化（确定性，与 orchestrator._norm_path 同意图但自洽）──────────
# 把具体 id 段折叠成 {}，使 /api/orders/1001 与 /api/orders/{id} 视作同一端点。
# 只归一「行键」用于聚合比对，不改写报告里的真实 endpoint 文案。
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _norm_endpoint(ep: str) -> str:
    """剥 scheme://host，折叠数字/uuid/{id} 段为 {}，丢 query —— 用作聚合行键。"""
    ep = re.sub(r"^https?://[^/]+", "", (ep or "").strip())
    ep = ep.split("#", 1)[0]
    path = ep.split("?", 1)[0]
    segs = []
    for seg in path.split("/"):
        if seg == "":
            segs.append(seg)
            continue
        if (seg.isdigit() or _UUID_RE.match(seg)
                or (seg.startswith("{") and seg.endswith("}"))):
            segs.append("{}")
        else:
            segs.append(seg)
    return "/".join(segs)


def _parse(report_md: str) -> tuple[dict, str]:
    """报告 markdown → (frontmatter, body)。无 frontmatter 则 body=全文。"""
    fm: dict[str, str] = {}
    m = re.match(r"\s*---\s*\n(.*?)\n---\s*\n(.*)$", report_md, re.S)
    body = report_md
    if m:
        for line in m.group(1).splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                fm[k.strip().lower()] = v.strip()
        body = m.group(2)
    return fm, body


def _endpoint_of(fm: dict, body: str) -> str:
    """endpoint 权威（可读原样，不折叠 id 段）：frontmatter target/endpoint
    （剥 host 后含路径才采信），否则正文首个 /路径 兜底。归一化另由 _norm_endpoint 做。"""
    tgt = re.sub(r"^https?://[^/]+", "",
                 (fm.get("target") or fm.get("endpoint") or "").strip())
    if tgt and not re.search(r"/[\w\-]", tgt):    # 站点根(无路径段)不算 endpoint
        tgt = ""
    if not tgt:
        m = re.search(r"(/[\w\-./{}]+)", body or "")
        tgt = m.group(1).strip() if m else ""
    return tgt


def _root_cause_of(fm: dict) -> str:
    """根因 ≈ 漏洞类（type/class/vuln_class），去空白。缺则 'unknown'。"""
    rc = re.sub(r"\s+", "",
                (fm.get("type") or fm.get("vuln_class") or fm.get("class") or "").strip())
    return rc or "unknown"


def _role_of(fm: dict) -> str:
    """受影响角色：frontmatter affected_role/role/roles（取首个），缺则 'default'。"""
    for key in ("affected_role", "role", "roles"):
        v = (fm.get(key) or "").strip()
        if v:
            return re.split(r"[,，;；]", v)[0].strip()
    return "default"


def _short_desc(fm: dict, body: str) -> str:
    """每份报告的短描述（写进 facets）：优先 title，否则正文首段。"""
    title = (fm.get("title") or "").strip()
    if title:
        return title
    for line in (body or "").splitlines():
        s = line.strip()
        if s:
            return s[:80]
    return ""


def _value_tier(root_cause: str) -> int:
    """价值排序档（只影响返回顺序，不影响成立性）：
      1 认证绕过 → 2 支付/余额 → 3 对象级授权 → 4 输入验证/文件/跳转 → 5 低价值信息暴露。"""
    rc = re.sub(r"\s+", "", (root_cause or "")).lower()
    if any(k in rc for k in ("认证", "auth", "登录", "注册", "找回", "验证码",
                             "token", "session", "枚举")):
        return 1
    if any(k in rc for k in ("支付", "余额", "退款", "payment", "refund", "金额",
                             "amount", "recharge", "积分", "points", "优惠", "coupon",
                             "balance", "抽奖", "lottery")):
        return 2
    if any(k in rc for k in ("越权", "idor", "bac", "对象", "ownership", "未授权", "unauth")):
        return 3
    if any(k in rc for k in ("信息泄露", "信息暴露", "配置", "sourcemap",
                             "指纹", "fingerprint", "infoleak")):
        return 5
    return 4   # sqli/xss/ssrf/rce/文件/上传/穿越/跳转/redirect/csrf/输入校验/业务逻辑/默认


def aggregate_findings(reports: list[str]) -> list[dict]:
    """按 ``finding_key = endpoint + root_cause + affected_role`` 聚合 accepted 报告。

    - 多份表现写 ``facets``（每份报告的短描述，去重保序）。
    - ``primary_impact`` 取最高严重度报告的 impact（frontmatter ``impact``，缺则取其短描述）。
    - ``severity`` 取聚合内最高严重度。同根因多 facet 不重复计入 critical 计数
      （消费方按 findings 列表计数即可，accepted 仍原样保留不丢信息）。
    - 返回顺序按价值档升序、同档严重度降序；排序不影响成立性。
    """
    buckets: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for rep in reports or []:
        fm, body = _parse(rep)
        endpoint = _endpoint_of(fm, body)             # 可读原样（用于展示）
        key_ep = _norm_endpoint(endpoint)             # 归一化（用于聚合键）
        root_cause = _root_cause_of(fm)
        role = _role_of(fm)
        key = f"{key_ep}|{root_cause}|{role}"
        sev = (fm.get("severity") or "").upper()
        desc = _short_desc(fm, body)
        impact = (fm.get("impact") or desc)
        if key not in buckets:
            buckets[key] = {
                "finding_key": key,
                "endpoint": endpoint,
                "root_cause": root_cause,
                "affected_role": role,
                "facets": [],
                "severity": "",
                "primary_impact": "",
                "report_count": 0,
                "_best_rank": -1,        # 最高严重度档（内部用）
                "_best_impact": "",      # 最高严重度对应的 impact（内部用）
            }
            order.append(key)
        b = buckets[key]
        if desc and desc not in b["facets"]:
            b["facets"].append(desc)
        rank = _SEV_RANK.get(sev, 0)
        if rank > b["_best_rank"]:
            b["_best_rank"] = rank
            b["_best_impact"] = impact
            b["severity"] = sev
        b["report_count"] += 1

    out: list[dict[str, Any]] = []
    for key in order:
        b = buckets[key]
        b["primary_impact"] = b.pop("_best_impact")
        b.pop("_best_rank", None)
        out.append(b)
    out.sort(key=lambda f: (_value_tier(f["root_cause"]),
                            -_SEV_RANK.get(f.get("severity", ""), 0),
                            f["finding_key"]))
    return out


__all__ = ["aggregate_findings"]
