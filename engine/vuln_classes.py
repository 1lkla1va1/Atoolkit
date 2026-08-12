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

# Exact coverage identity aliases.  Unlike ``VULN_SYNONYMS`` these aliases do
# not collapse sibling security boundaries merely because they share a
# knowledge-routing family.
EXACT_VULN_ALIASES: dict[str, str] = {
    "xss": "xss", "跨站脚本": "xss",
    "越权/idor": "idor", "认证绕过/枚举": "auth",
    "命令执行/rce": "rce", "文件读取/穿越": "file",
    "存储型xss": "stored-xss", "stored-xss": "stored-xss",
    "反射型xss": "reflected-xss", "reflected-xss": "reflected-xss",
    "domxss": "dom-xss", "dom-xss": "dom-xss",
    "idor": "idor", "越权": "idor", "业务逻辑越权": "idor",
    "对象级授权缺失": "idor", "bac": "idor",
    "水平越权": "horizontal-idor",
    "horizontal-privilege-escalation": "horizontal-idor",
    "垂直越权": "vertical-idor",
    "vertical-privilege-escalation": "vertical-idor",
    "privilege-escalation": "vertical-idor",
    "sql注入": "sqli", "sql-injection": "sqli", "sql": "sqli", "sqli": "sqli",
    "认证绕过": "auth-bypass", "auth-bypass": "auth-bypass",
    "验证码绕过": "captcha-bypass", "captcha-bypass": "captcha-bypass",
}


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


def exact_vc(vc: str) -> str:
    """Return a stable exact vulnerability-class token for cell identity."""
    raw = _squash_ws(str(vc or "")).lower()
    if not raw:
        return ""
    return EXACT_VULN_ALIASES.get(raw, raw)


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


# ---------------------------------------------------------------------------
# Phenomenon classes (v9.2) — single source for the reporting three-outcome
# gate in reporting/validate.py.  Code constants + contract tests.
# ---------------------------------------------------------------------------
# A "phenomenon" is an observable configuration/signal that is not, by
# itself, a proven security-boundary break.  Findings classified here need a
# proven consequence chain to stay SRC-eligible; otherwise they are demoted
# to run-scoped observations instead of being rejected, so one piece of
# noise can neither poison the batch-atomic gate nor ride into the final
# report.  Classification matches against title + vuln_type + risk.summary +
# risk.proven_impact, so rewording a title alone cannot bypass it.

PHENOMENON_PATTERNS: dict[str, re.Pattern] = {
    "cors_misconfig": re.compile(
        r"\bCORS\b|跨域|access[- ]?control[- ]?allow", re.I),
    "sourcemap_leak": re.compile(
        r"source\s*map|sourcemap|\.map\b", re.I),
    "missing_security_header": re.compile(
        r"x-frame-options|\bCSP\b|\bHSTS\b|安全响应?头", re.I),
    "version_disclosure": re.compile(
        r"版本号|中间件指纹|组件指纹", re.I),
    "self_xss": re.compile(
        r"self[- ]?xss", re.I),
    "ssl_tls_config": re.compile(
        r"\bSSL\b|\bTLS\b|证书过期|混合内容|mixed[- ]?content|"
        r"加密套件|cipher[- ]?suite", re.I),
    "directory_listing": re.compile(
        r"目录列举|directory[- ]?listing", re.I),
    "error_stack": re.compile(
        r"报错堆栈|stack\s*trace|类型混淆|type\s*confusion|未处理异常|"
        r"unhandled\s+exception|internal\s+server\s*error|\b500\b|报错", re.I),
    "rate_limit_absent": re.compile(
        r"rate[- ]?limit|限频|速率限制|频率限制", re.I),
    "open_redirect_unproven": re.compile(
        r"open[- ]?redirect|开放重定向|任意跳转", re.I),
    "weak_crypto": re.compile(
        r"弱算法|弱加密|rsa1[_-]?5|weak[- ]?(?:crypto|cipher|algorithm|"
        r"encryption)|不安全的?(?:加密|哈希)算法|jwt.{0,12}(?:alg|算法)", re.I),
    "public_key_disclosure": re.compile(
        r"公钥|public[- ]?key|jwks", re.I),
    "credential_echo_unproven": re.compile(
        r"(?:(?:token|cookie|api[-_ ]?key|credential|session|凭据|令牌|密钥|会话)"
        r".{0,20}(?:leak|expos|disclos|泄露|暴露|回显)|"
        r"(?:leak|expos|disclos|泄露|暴露|回显).{0,20}"
        r"(?:token|cookie|api[-_ ]?key|credential|session|凭据|令牌|密钥|会话))",
        re.I),
}

# Classes whose consequence proof is a specialized structured gate in
# reporting/validate.py (security_boundary / credential_boundary), not merely
# chain_assessment.status=proven.
PHENOMENON_SPECIAL_PROOF: frozenset = frozenset({
    "error_stack", "credential_echo_unproven",
})
# Every other class (including the historical rate-limit/open-redirect
# conditional gates) is cleared by chain_assessment.status=proven.
PHENOMENON_CHAIN_PROOF: frozenset = frozenset(
    set(PHENOMENON_PATTERNS) - PHENOMENON_SPECIAL_PROOF)

# Security-boundary break kinds that count as a proven consequence.
CONSEQUENCE_BOUNDARY_KINDS: frozenset = frozenset({
    "data_read", "state_change", "code_execution",
    "authorization_bypass", "trusted_secret_use", "fund_change",
})


def classify_phenomenon(text: str) -> list[str]:
    """Return every phenomenon class whose pattern matches ``text``."""
    if not text:
        return []
    return [
        name for name, pattern in PHENOMENON_PATTERNS.items()
        if pattern.search(text)
    ]
