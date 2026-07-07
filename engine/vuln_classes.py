"""
engine/vuln_classes.py - Single source of truth for vuln_class normalization.

Before v8.5.1, vuln_class normalization was scattered across three places:
  1. orchestrator.VULN_SYNONYMS + _norm_vuln()  -> coverage matrix
  2. orchestrator._chainable_vuln               -> chain_feasible inference
  3. graph.IntentRuleEngine._rules()            -> Intent generation (hardcoded strings)

Each maintained its own string sets, never in sync. This module unifies them
into one table + one function.
"""

from __future__ import annotations
import re


# ---------------------------------------------------------------------------
# Synonym table (single mapping)
# ---------------------------------------------------------------------------
# Key: lowercase, whitespace-squashed vuln_class input
# Value: semantic group canonical name (lowercase English)

VULN_SYNONYMS: dict[str, str] = {
    # -- idor --
    "越权": "idor", "idor": "idor", "bac": "idor",
    "业务逻辑越权": "idor", "水平越权": "idor", "垂直越权": "idor",
    "越权访问": "idor", "brokenaccesscontrol": "idor",
    "对象级授权缺失": "idor",
    "privilege-escalation": "idor",
    "horizontal-privilege-escalation": "idor",
    "vertical-privilege-escalation": "idor",
    # -- auth --
    "auth-bypass": "auth", "captcha-bypass": "auth",
    "auth-flow-abuse": "auth",
    "验证码绕过": "auth", "认证绕过": "auth", "认证绕过/枚举": "auth",
    "枚举": "auth", "暴力破解": "auth",
    # -- sqli --
    "sql注入": "sqli", "sqli": "sqli", "sql": "sqli",
    "sql-injection": "sqli",
    # -- xss --
    "xss": "xss", "存储型xss": "xss", "stored-xss": "xss",
    "反射型xss": "xss", "reflected-xss": "xss",
    "domxss": "xss", "dom-xss": "xss", "跨站脚本": "xss",
    # -- ssrf --
    "ssrf": "ssrf", "服务端请求伪造": "ssrf",
    "server-side-request-forgery": "ssrf",
    # -- business --
    "amount-tamper": "business", "金额篡改": "business",
    "退款滥用": "business", "recharge": "business",
    "充值伪造": "business", "refund": "business",
    "payment": "business", "accounting": "business",
    "business-logic": "business", "业务逻辑": "business",
    "积分绕过": "business", "points": "business",
    "balance": "business", "余额": "business",
    "coupon": "business", "lottery": "business",
    # -- rce --
    "rce": "rce", "命令执行": "rce", "代码执行": "rce",
    "命令执行/rce": "rce",
    # -- info-leak --
    "信息泄露": "info-leak", "敏感信息泄露": "info-leak",
    "未授权访问": "info-leak", "未授权": "info-leak",
    "未授权内网访问": "info-leak",
    "info-disclosure": "info-leak", "information-leak": "info-leak",
    "log-exposure": "info-leak", "泄露": "info-leak",
    # -- file --
    "任意文件上传": "file", "文件上传": "file", "上传": "file",
    "文件读取": "file", "路径穿越": "file", "目录穿越": "file",
    "文件读取/穿越": "file", "path-traversal": "file",
    # -- csrf --
    "csrf": "csrf",
}

# Coverage matrix column name aliases (semantic group -> matrix column)
MATRIX_ALIASES: dict[str, str] = {
    "idor": "越权/IDOR",
    "auth": "认证绕过/枚举",
    "sqli": "SQLi",
    "xss": "XSS",
    "ssrf": "SSRF",
    "business": "业务逻辑",
    "rce": "命令执行/RCE",
    "info-leak": "未授权访问",
    "file": "文件读取/穿越",
    "csrf": "CSRF",
}

# Semantic group keywords (for substring fallback matching)
VULN_GROUP_KEYWORDS: dict[str, tuple[str, ...]] = {
    "idor": ("idor", "越权", "bac", "authorization", "access-control",
             "privilege", "权限"),
    "auth": ("auth", "认证", "验证", "captcha", "验证码", "session",
             "brute", "暴力"),
    "sqli": ("sqli", "sql", "注入", "injection"),
    "xss": ("xss", "跨站", "script", "反射"),
    "ssrf": ("ssrf", "服务端", "server-side"),
    "business": ("amount", "金额", "refund", "退款", "recharge", "充值",
                 "payment", "支付", "points", "积分", "balance", "余额",
                 "coupon", "lottery", "order", "transaction"),
    "rce": ("rce", "命令执行", "代码执行", "command", "exec"),
    "info-leak": ("泄露", "leak", "disclosure", "信息", "exposure",
                  "敏感"),
    "file": ("文件", "file", "upload", "上传", "traversal", "穿越",
             "download", "下载"),
    "csrf": ("csrf", "cross-site-request"),
}

# Groups that support chain exploitation
CHAINABLE_GROUPS: frozenset[str] = frozenset({
    "auth", "business", "idor", "sqli", "rce",
})


# ---------------------------------------------------------------------------
# Normalization functions
# ---------------------------------------------------------------------------

def _squash_ws(s: str) -> str:
    """Remove all whitespace."""
    return re.sub(r'\s+', '', s or "")


def norm_vc(vc: str) -> str:
    """Normalize any vuln_class string to semantic group canonical name.

    Priority:
    1. Exact match in VULN_SYNONYMS (squashed + lowered)
    2. Split by '/', check each segment
    3. Substring match against VULN_GROUP_KEYWORDS
    4. Fallback: return lowered squashed original
    """
    if not vc:
        return ""
    raw = _squash_ws(vc)
    raw_lower = raw.lower()

    # 1. Exact match
    if raw_lower in VULN_SYNONYMS:
        return VULN_SYNONYMS[raw_lower]

    # 2. Split by /
    for seg in raw.split("/"):
        seg = seg.strip().lower()
        if seg and seg in VULN_SYNONYMS:
            return VULN_SYNONYMS[seg]

    # 3. Substring match
    for group, keywords in VULN_GROUP_KEYWORDS.items():
        for kw in keywords:
            if kw in raw_lower:
                return group

    # 4. Fallback
    return raw_lower


def norm_vc_matrix(vc: str) -> str:
    """Normalize to coverage matrix column name."""
    canonical = norm_vc(vc)
    return MATRIX_ALIASES.get(canonical, canonical)


def norm_vc_candidates(vc: str) -> list[str]:
    """Return all normalization candidates (for coverage matrix _find_cell).

    Compatible with original _norm_vuln() behavior: handles 'A / B' compound
    notation, returns all possible canonical names.
    """
    raw = _squash_ws(vc)
    cands: list[str] = []

    if raw:
        c = norm_vc(raw)
        cands.append(c)
        mc = MATRIX_ALIASES.get(c, "")
        if mc:
            cands.append(mc)
        if raw not in cands:
            cands.append(raw)

    for seg in raw.split("/"):
        seg = seg.strip()
        if not seg:
            continue
        c = norm_vc(seg)
        if c not in cands:
            cands.append(c)
        mc = MATRIX_ALIASES.get(c, "")
        if mc and mc not in cands:
            cands.append(mc)

    return cands


def vc_matches(vc: str, group: str) -> bool:
    """Check if vuln_class belongs to a semantic group."""
    return norm_vc(vc) == group


def is_chainable(vc: str) -> bool:
    """Check if vuln_class supports chain exploitation."""
    return norm_vc(vc) in CHAINABLE_GROUPS
