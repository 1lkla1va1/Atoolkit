"""
engine/surface.py —— recon 产物 → 攻击面清单（endpoint/method/param/source/last_seen）。

把 recon 阶段抓回来的 JS / HTML / 响应快照(JSON) / HAR 解析成可直接喂
``planner.plan_surfaces`` 或 ``CoverageLedger.from_endpoints`` 的端点清单。

设计约束（与 planner 一致）：
  - 通用正则，不内置任何靶场路径模式、不内置 payload 列表；只看路径结构。
  - 只抽 endpoint/method/param/source/last_seen；风险标签/角色/feature 由
    planner 的 infer_* helper 统一推断，本模块不重造粒度。
  - param 抽取复用 ``planner.extract_params``（合并 query 串与路径占位 ``{id}``/``:id``），
    使输出与 ledger 的 endpoint-inventory schema 同形。

入口：``bootstrap(recon_dir) -> list[dict]``；
CLI：``python3 -m engine.surface --recon-dir <path>`` 打印 JSON。
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
import json
import pathlib
import posixpath
import re
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import parse_qsl

try:                                  # 支持「包内导入」与「脚本直跑」两种方式
    from .planner import extract_params
except ImportError:  # pragma: no cover
    from planner import extract_params

# source 标签（每条 surface 的来源种类）
SRC_JS = "js"
SRC_HTML = "html"
SRC_TRAFFIC = "traffic"
SRC_HAR = "har"
SRC_MANUAL = "manual"

_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

# ── 通用路径识别（无靶场模式，只看结构）────────────────────────────────────
_API_NEEDLE = "/api/"                                   # 通用 API 路径前缀，非业务名
_PHP_PATH = re.compile(r"^[A-Za-z0-9_][\w./-]*\.php(?:\?[\w=&%.-]*)?$")
_QUERY_PARAM_NAME_RE = re.compile(r"^[A-Za-z_$][\w$.\[\]-]*$")
_BAD_PATH_CHARS = frozenset(" \t\r\n\"'<>|\\^`")        # 路径里不应出现的字符
_STATIC_EXTS = {
    ".css", ".js", ".mjs", ".cjs", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp4", ".webm", ".mp3", ".wav",
}


def _dedupe(values: Iterable[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        s = str(v or "").strip()
        if s and s.lower() not in seen:
            seen.add(s.lower())
            out.append(s)
    return out


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _mtime_iso(path: pathlib.Path) -> str:
    """文件 mtime 的 ISO 串；取不到则用扫描时间。"""
    try:
        return _iso(path.stat().st_mtime)
    except OSError:
        return _iso(datetime.now(tz=timezone.utc).timestamp())


def _split_url(url: str) -> tuple[str, list[str]]:
    """url → (path, query_param_names)。剥 scheme://host 与 fragment；query 拆键。"""
    u = (url or "").strip()
    u = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s\"'<>]+", "", u)   # 剥 scheme://host[:port]
    u = u.split("#", 1)[0]                                          # 剥 fragment
    path, _, query = u.partition("?")
    path = path.strip()
    if path.startswith(("../", "./")):
        path = posixpath.normpath("/" + path)
        if not path.startswith("/"):
            path = "/" + path
    params = [
        k for k, _ in parse_qsl(query, keep_blank_values=True)
        if _QUERY_PARAM_NAME_RE.fullmatch(k)
    ] if query else []
    return path, params


def _is_endpoint_path(path: str) -> bool:
    """结构判别：是否像一个 endpoint 路径（非业务名，只看 / 与段，允许 {id}/:id 占位）。"""
    if not path or len(path) > 2000 or any(c in path for c in _BAD_PATH_CHARS):
        return False
    if path.startswith("/"):
        return any(seg for seg in path.split("/"))                 # 至少一个非空段
    return bool(_PHP_PATH.match(path))                             # 无前导 / 只认 .php 相对路径


def _is_static_asset_path(path: str) -> bool:
    """静态资源不是业务测试 surface；JS 文件会作为 recon 输入单独解析。"""
    clean = path.split("?", 1)[0].split("#", 1)[0].lower()
    return any(clean.endswith(ext) for ext in _STATIC_EXTS)


# 自由文本里的 URL/路径候选 token（P1-3：深测新发现 endpoint hook 用）。
# token 正则可宽松（完整 URL / /路径 / *.php 三种形态都收），过滤交给后段：
# 复用 _split_url 剥 scheme://host/query/fragment、_is_endpoint_path 做结构判别，
# 再用 _API_NEEDLE / _PHP_PATH 收紧到 /api/* 与 *.php 字面量，不内置靶场路径。
_URL_OR_PATH_RE = re.compile(
    r'https?://[^\s"\'<>]+|/[\w\-./{}]+|[\w\-./{}]+\.php(?:\?[\w=&%.-]*)?'
)


# ── JS ────────────────────────────────────────────────────────────────────
# 三种字符串字面量：'...' "..." `...`；反引号模板里的 ${expr} 折叠成 {expr} 占位，
# 使 /api/orders/${id} 与 planner 的 {id} 路径占位同形（extract_params 会抽出来）。
_STR_RE = re.compile(r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"|`((?:[^`\\]|\\.)*)`", re.S)

# Call-site scanners deliberately operate on a same-length mask whose strings
# and comments are blanked.  The original source is then balanced/scanned for
# arguments.  This is still a conservative extractor (not a JavaScript AST),
# but unlike ``[^)]*`` regexes it does not stop at JSON.stringify(...), nested
# object literals, or callbacks.
_SIMPLE_CALL_START_RE = re.compile(r"\b(fetch|jsonPost|request)\s*\(", re.I)
_METHOD_CALL_START_RE = re.compile(
    r"\b(axios|api|client|http)\s*\.\s*(get|post|put|patch|delete|head)\s*\(",
    re.I,
)
_XHR_OPEN_START_RE = re.compile(r"\.\s*open\s*\(", re.I)
_VAR_DECL_RE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=", re.I)
_APPEND_START_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\.\s*append\s*\(", re.I)
_PROPERTY_ASSIGN_RE = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\s*=(?!=)", re.I
)
_FUNCTION_START_RE = re.compile(
    r"\bfunction(?:\s+[A-Za-z_$][\w$]*)?\s*\(", re.I)
_ARROW_BLOCK_RE = re.compile(
    r"(?:\(([^()]*)\)|\b([A-Za-z_$][\w$]*))\s*=>\s*\{", re.S)
_ARROW_EXPR_RE = re.compile(
    r"(?:\(([^()]*)\)|\b([A-Za-z_$][\w$]*))\s*=>\s*(?!\{)", re.S)


class _LexicalScopes:
    """Small conservative brace-scope model for regex-based JS extraction.

    This is deliberately not an AST.  Treating every code brace as a lexical
    scope can lose an uncertain alias, which safely leaves a method unresolved;
    it must never make a declaration from a sibling function visible.
    """

    def __init__(self, mask: str):
        self.starts: list[int] = []
        self.parent: dict[int, int] = {-1: -1}
        self.end: dict[int, int] = {-1: len(mask)}
        stack = [-1]
        for pos, char in enumerate(mask):
            if char == "{":
                self.starts.append(pos)
                self.parent[pos] = stack[-1]
                self.end[pos] = len(mask)
                stack.append(pos)
            elif char == "}" and len(stack) > 1:
                self.end[stack.pop()] = pos

    def at(self, pos: int) -> int:
        index = bisect_right(self.starts, pos) - 1
        if index < 0:
            return -1
        scope = self.starts[index]
        while scope != -1 and not (scope < pos <= self.end.get(scope, -1)):
            scope = self.parent.get(scope, -1)
        return scope

    def visible(self, declaration_scope: int, use_pos: int) -> bool:
        scope = self.at(use_pos)
        while True:
            if scope == declaration_scope:
                return True
            if scope == -1:
                return declaration_scope == -1
            scope = self.parent.get(scope, -1)


class _JSBindings(list[dict[str, Any]]):
    def __init__(self, scopes: _LexicalScopes):
        super().__init__()
        self.scopes = scopes


def _scan_arrow_expression_end(text: str, start: int) -> int:
    """Conservatively bound an expression-bodied arrow's parameter scope."""
    stack: list[str] = []
    quote = ""
    escaped = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    i = start
    while i < len(text):
        char = text[i]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            i += 1
            continue
        if char in "'\"`":
            quote = char
        elif char in pairs:
            stack.append(pairs[char])
        elif stack and char == stack[-1]:
            stack.pop()
        elif not stack and char in ";,\n\r":
            return i
        elif not stack and char in ")]}":
            return i
        i += 1
    return len(text)


def _iter_strings(text: str) -> Iterable[str]:
    for m in _STR_RE.finditer(text):
        for g in m.groups():
            if g is not None:
                yield re.sub(r"\$\{([^}]*)\}", r"{\1}", g)


def _iter_strings_with_line(text: str) -> Iterable[tuple[str, int]]:
    for m in _STR_RE.finditer(text):
        for g in m.groups():
            if g is not None:
                yield re.sub(r"\$\{([^}]*)\}", r"{\1}", g), _line_no(text, m.start())


def _line_no(text: str, pos: int) -> int:
    return text.count("\n", 0, max(0, pos)) + 1


def _object_params(obj: str) -> list[str]:
    inner = obj.strip()
    if inner.startswith("{") and inner.endswith("}"):
        inner = inner[1:-1]
    params: list[str] = []
    for part in _split_top_level(inner):
        token = part.strip()
        if not token:
            continue
        prop = _property_parts(token)
        if prop:
            params.append(prop[0])
            continue
        if token.startswith("..."):
            continue  # spread contents are not statically attributable here
        m = re.match(r"([A-Za-z_$][\w$-]*)\b", token)
        if m and m.group(1) not in {"true", "false", "null", "undefined"}:
            params.append(m.group(1))
    return params


def _mask_js_noncode(text: str) -> str:
    """Return a same-length mask with JS strings/comments replaced by spaces.

    It is intentionally lexer-small: regex literals are not interpreted, but
    quoted/template strings and both comment forms are masked.  That is enough
    to prevent endpoint text and comments from being mistaken for executable
    calls while keeping source offsets stable.
    """
    out = list(text)
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in "'\"`":
            quote = ch
            out[i] = " "
            i += 1
            while i < n:
                out[i] = "\n" if text[i] == "\n" else " "
                if text[i] == "\\":
                    i += 1
                    if i < n:
                        out[i] = "\n" if text[i] == "\n" else " "
                        i += 1
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            out[i] = out[i + 1] = " "
            i += 2
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i < n:
                out[i] = "\n" if text[i] == "\n" else " "
                if text[i:i + 2] == "*/":
                    out[i] = out[i + 1] = " "
                    i += 2
                    break
                i += 1
            continue
        i += 1
    return "".join(out)


def _scan_parenthesized(text: str, open_pos: int) -> tuple[str, int] | None:
    """Read a balanced ``(...)`` expression starting at *open_pos*."""
    if open_pos < 0 or open_pos >= len(text) or text[open_pos] != "(":
        return None
    depth = 0
    quote = ""
    escaped = False
    i = open_pos
    while i < len(text):
        ch = text[i]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "'\"`":
            quote = ch
            i += 1
            continue
        if ch == "/" and i + 1 < len(text) and text[i + 1] == "/":
            end = text.find("\n", i + 2)
            i = len(text) if end < 0 else end
            continue
        if ch == "/" and i + 1 < len(text) and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            i = len(text) if end < 0 else end + 2
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i], i + 1
        i += 1
    return None


def _split_top_level(text: str, delimiter: str = ",") -> list[str]:
    """Split a JS expression at a delimiter outside nested/string contexts."""
    parts: list[str] = []
    start = 0
    stack: list[str] = []
    quote = ""
    escaped = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "'\"`":
            quote = ch
        elif ch in pairs:
            stack.append(pairs[ch])
        elif stack and ch == stack[-1]:
            stack.pop()
        elif not stack and ch == delimiter:
            parts.append(text[start:i].strip())
            start = i + 1
        i += 1
    parts.append(text[start:].strip())
    return parts


def _scan_assignment_expr(text: str, start: int) -> str:
    """Return a declaration RHS through its top-level semicolon."""
    stack: list[str] = []
    quote = ""
    escaped = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    i = start
    while i < len(text):
        ch = text[i]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "'\"`":
            quote = ch
        elif ch in pairs:
            stack.append(pairs[ch])
        elif stack and ch == stack[-1]:
            stack.pop()
        elif ch == ";" and not stack:
            return text[start:i].strip()
        i += 1
    return text[start:].strip()


def _parse_string_prefix(expr: str) -> tuple[str, int] | None:
    """Parse one leading JS string/template literal without evaluating code."""
    value = expr.lstrip()
    offset = len(expr) - len(value)
    if not value or value[0] not in "'\"`":
        return None
    quote = value[0]
    chars: list[str] = []
    i = 1
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            chars.append(nxt if nxt in "'\"`\\/" else "\\" + nxt)
            i += 2
            continue
        if ch == quote:
            result = re.sub(r"\$\{([^}]*)\}", r"{\1}", "".join(chars))
            return result, offset + i + 1
        chars.append(ch)
        i += 1
    return None


def _strip_balanced_outer_parens(expr: str) -> str:
    value = expr.strip()
    while value.startswith("("):
        scanned = _scan_parenthesized(value, 0)
        if not scanned or scanned[1] != len(value):
            break
        value = scanned[0].strip()
    return value


def _top_level_ternary(expr: str) -> tuple[str, str] | None:
    """Return the two branches of a simple top-level ternary expression."""
    stack: list[str] = []
    quote = ""
    escaped = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    qpos = -1
    nested = 0
    i = 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "'\"`":
            quote = ch
        elif ch in pairs:
            stack.append(pairs[ch])
        elif stack and ch == stack[-1]:
            stack.pop()
        elif not stack and ch == "?" and not expr[i:i + 2] in {"?.", "??"}:
            if qpos < 0:
                qpos = i
            else:
                nested += 1
        elif not stack and ch == ":" and qpos >= 0:
            if nested:
                nested -= 1
            else:
                return expr[qpos + 1:i].strip(), expr[i + 1:].strip()
        i += 1
    return None


def _build_js_bindings(text: str) -> _JSBindings:
    """Build position-sensitive local bindings for URL/body/FormData inference."""
    mask = _mask_js_noncode(text)
    scopes = _LexicalScopes(mask)
    bindings = _JSBindings(scopes)

    def add_parameter(name: str, body_open: int) -> None:
        value = str(name or "").strip()
        # Defaults still shadow an outer declaration.  Destructuring is left
        # unresolved because attributing its aliases without an AST is unsafe.
        match = re.match(r"^([A-Za-z_$][\w$]*)\b", value)
        if not match:
            return
        bindings.append({
            "name": match.group(1), "pos": body_open, "expr": "",
            "kind": "parameter", "keys": [], "scope": body_open,
        })

    # Function and block-arrow parameters are declarations too.  Recording
    # them before local assignments makes shadowing explicit: a dynamic
    # parameter wins over a same-named literal/FormData in another scope.
    for match in _FUNCTION_START_RE.finditer(mask):
        open_pos = mask.find("(", match.start(), match.end())
        scanned = _scan_parenthesized(text, open_pos)
        if not scanned:
            continue
        body_open = mask.find("{", scanned[1])
        if body_open < 0 or mask[scanned[1]:body_open].strip():
            continue
        for parameter in _split_top_level(scanned[0]):
            add_parameter(parameter, body_open)
    for match in _ARROW_BLOCK_RE.finditer(mask):
        body_open = mask.rfind("{", match.start(), match.end())
        parameters = match.group(1) if match.group(1) is not None else match.group(2)
        for parameter in _split_top_level(parameters or ""):
            add_parameter(parameter, body_open)
    for match in _ARROW_EXPR_RE.finditer(mask):
        parameters = match.group(1) if match.group(1) is not None else match.group(2)
        visible_until = _scan_arrow_expression_end(text, match.end())
        for parameter in _split_top_level(parameters or ""):
            value = str(parameter or "").strip()
            name = re.match(r"^([A-Za-z_$][\w$]*)\b", value)
            if name:
                bindings.append({
                    "name": name.group(1), "pos": match.start(), "expr": "",
                    "kind": "parameter", "keys": [],
                    "scope": scopes.at(match.start()),
                    "visible_from": match.end(),
                    "visible_until": visible_until,
                })

    for m in _VAR_DECL_RE.finditer(mask):
        expr = _scan_assignment_expr(text, m.end())
        stripped = expr.strip()
        kind = "formdata" if re.match(r"new\s+FormData\s*\(", stripped, re.I) else (
            "object" if stripped.startswith("{") else "value"
        )
        bindings.append({
            "name": m.group(1), "pos": m.start(), "expr": expr,
            "kind": kind, "keys": _object_params(stripped) if kind == "object" else [],
            "scope": scopes.at(m.start()),
        })

    def nearest(name: str, pos: int, kind: str | None = None) -> dict[str, Any] | None:
        binding = _lookup_binding(bindings, name, pos)
        return binding if binding and (kind is None or binding["kind"] == kind) else None

    # Associate append keys with the nearest preceding FormData declaration.
    for m in _APPEND_START_RE.finditer(mask):
        open_pos = mask.find("(", m.start(), m.end())
        scanned = _scan_parenthesized(text, open_pos)
        binding = nearest(m.group(1), m.start(), "formdata")
        if not scanned or not binding:
            continue
        args = _split_top_level(scanned[0])
        key = _parse_string_prefix(args[0])[0] if args and _parse_string_prefix(args[0]) else ""
        if key and key not in binding["keys"]:
            binding["keys"].append(key)

    # Object properties added after declaration (e.g. data.product_no = ...)
    # belong only to the nearest instance, not every same-named object in file.
    for m in _PROPERTY_ASSIGN_RE.finditer(mask):
        binding = nearest(m.group(1), m.start(), "object")
        key = m.group(2)
        if binding and key not in binding["keys"]:
            binding["keys"].append(key)
    return bindings


def _lookup_binding(bindings: list[dict[str, Any]], name: str, pos: int,
                    kind: str | None = None) -> dict[str, Any] | None:
    scopes = getattr(bindings, "scopes", None)
    candidates = [
        b for b in bindings
        if b["name"] == name and b["pos"] < pos
        and (
            ("visible_until" in b
             and int(b.get("visible_from", 0)) <= pos < int(b["visible_until"]))
            or ("visible_until" not in b and (
                scopes is None or scopes.visible(int(b.get("scope", -1)), pos)))
        )
    ]
    binding = max(candidates, key=lambda b: b["pos"]) if candidates else None
    # A nearer parameter or different-kind declaration shadows an outer
    # binding.  Never skip the shadow merely to find a requested kind.
    return binding if binding and (kind is None or binding["kind"] == kind) else None


def _resolve_url_values(expr: str, bindings: list[dict[str, Any]], pos: int,
                        seen: set[tuple[str, int]] | None = None) -> list[str]:
    """Resolve only literals, a local alias, or literal branches of a ternary."""
    value = _strip_balanced_outer_parens(expr)
    ternary = _top_level_ternary(value)
    if ternary:
        return _dedupe(
            _resolve_url_values(ternary[0], bindings, pos, seen)
            + _resolve_url_values(ternary[1], bindings, pos, seen)
        )
    literal = _parse_string_prefix(value)
    if literal:
        # For '/api/x?q=' + encodeURIComponent(q), the literal prefix carries
        # the endpoint and query-key truth; the dynamic value is not evaluated.
        return [literal[0]]
    if re.fullmatch(r"[A-Za-z_$][\w$]*", value):
        binding = _lookup_binding(bindings, value, pos)
        if not binding:
            return []
        token = (binding["name"], binding["pos"])
        seen = set(seen or ())
        if token in seen:
            return []
        seen.add(token)
        return _resolve_url_values(binding["expr"], bindings, binding["pos"] + 1, seen)
    return []


def _resolve_bound_expr(expr: str, bindings: list[dict[str, Any]], pos: int) -> str:
    value = _strip_balanced_outer_parens(expr)
    if re.fullmatch(r"[A-Za-z_$][\w$]*", value):
        binding = _lookup_binding(bindings, value, pos)
        return binding["expr"].strip() if binding else value
    return value


def _property_parts(part: str) -> tuple[str, str] | None:
    stack: list[str] = []
    quote = ""
    escaped = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    for i, ch in enumerate(part):
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in "'\"`":
            quote = ch
        elif ch in pairs:
            stack.append(pairs[ch])
        elif stack and ch == stack[-1]:
            stack.pop()
        elif ch == ":" and not stack:
            raw_key = part[:i].strip()
            parsed = _parse_string_prefix(raw_key)
            key = parsed[0] if parsed and parsed[1] == len(raw_key) else raw_key
            if re.fullmatch(r"[A-Za-z_$][\w$-]*", key):
                return key, part[i + 1:].strip()
            return None
    return None


def _object_property_expr(obj_expr: str, name: str) -> str | None:
    value = _strip_balanced_outer_parens(obj_expr)
    if not (value.startswith("{") and value.endswith("}")):
        return None
    for part in _split_top_level(value[1:-1]):
        prop = _property_parts(part)
        if prop and prop[0].lower() == name.lower():
            return prop[1]
    return None


def _payload_params(expr: str, bindings: list[dict[str, Any]], pos: int) -> list[str]:
    value = _strip_balanced_outer_parens(expr)
    stringify = re.match(r"JSON\s*\.\s*stringify\s*\(", value, re.I)
    if stringify:
        open_pos = value.find("(", stringify.start(), stringify.end())
        scanned = _scan_parenthesized(value, open_pos)
        if scanned:
            args = _split_top_level(scanned[0])
            return _payload_params(args[0], bindings, pos) if args else []
    if re.fullmatch(r"[A-Za-z_$][\w$]*", value):
        binding = _lookup_binding(bindings, value, pos)
        return list(binding.get("keys") or []) if binding and binding["kind"] in {"object", "formdata"} else []
    if value.startswith("{") and value.endswith("}"):
        return _object_params(value)
    literal = _parse_string_prefix(value)
    if literal:
        return [key for key, _ in parse_qsl(literal[0], keep_blank_values=True)]
    return []


def _fetch_contract(options: str, bindings: list[dict[str, Any]], pos: int) -> tuple[str, list[str]]:
    """Return fetch method/body keys without treating option keys as payload."""
    if not options.strip():
        return "GET", []
    value = _resolve_bound_expr(options, bindings, pos)
    if not (value.startswith("{") and value.endswith("}")):
        return "", []  # dynamic options may carry a method; do not invent GET
    method_expr = _object_property_expr(value, "method")
    if method_expr is None:
        method = "GET"
    else:
        method_value = _parse_string_prefix(_resolve_bound_expr(method_expr, bindings, pos))
        candidate = method_value[0].upper() if method_value else ""
        method = candidate if candidate in _HTTP_METHODS else ""
    body_expr = _object_property_expr(value, "body")
    body_params = _payload_params(body_expr, bindings, pos) if body_expr is not None else []
    return method, body_params


def _iter_call_args(text: str, mask: str, pattern: re.Pattern) -> Iterable[tuple[re.Match, list[str]]]:
    for match in pattern.finditer(mask):
        open_pos = mask.find("(", match.start(), match.end())
        scanned = _scan_parenthesized(text, open_pos)
        if scanned:
            yield match, _split_top_level(scanned[0])


def _extract_js(text: str) -> list[tuple[str, str, list[str], int, str, dict[str, list[str]]]]:
    """JS → [(endpoint, method, params), ...]。"""
    out: list[tuple[str, str, list[str], int, str, dict[str, list[str]]]] = []
    mask = _mask_js_noncode(text)
    bindings = _build_js_bindings(text)

    def emit(url_expr: str, method: str, body_params: list[str], pos: int, kind: str) -> None:
        for url in _resolve_url_values(url_expr, bindings, pos):
            path, query_params = _split_url(url)
            if _is_endpoint_path(path):
                out.append((path, method, _dedupe(query_params + body_params),
                            _line_no(text, pos), kind, {
                                "query_params": _dedupe(query_params),
                                "body_params": _dedupe(body_params),
                            }))

    # fetch has a standards-defined GET default only when its options object is
    # absent or statically known not to contain method.  Body comes solely from
    # the ``body`` property; method/headers/body option names are never params.
    for m, args in _iter_call_args(text, mask, _SIMPLE_CALL_START_RE):
        if not args:
            continue
        name = m.group(1)
        if name.lower() == "fetch":
            method, body_params = _fetch_contract(args[1] if len(args) > 1 else "", bindings, m.start())
            emit(args[0], method, body_params, m.start(), "fetch")
        elif name.lower() == "jsonpost":
            body_params = _payload_params(args[1], bindings, m.start()) if len(args) > 1 else []
            emit(args[0], "POST", body_params, m.start(), name)
        else:  # a generic request wrapper has no safe default method
            options = args[1] if len(args) > 1 else ""
            method, body_params = _fetch_contract(options, bindings, m.start()) if options else ("", [])
            emit(args[0], method, body_params, m.start(), name)

    # axios.verb / api.verb / client.verb / http.verb have observed methods.
    for m, args in _iter_call_args(text, mask, _METHOD_CALL_START_RE):
        if not args:
            continue
        owner, verb = m.group(1).lower(), m.group(2).upper()
        body_params: list[str] = []
        if len(args) > 1 and verb in {"POST", "PUT", "PATCH"}:
            body_params = _payload_params(args[1], bindings, m.start())
        elif len(args) > 1 and verb == "DELETE":
            options = _resolve_bound_expr(args[1], bindings, m.start())
            body = _object_property_expr(options, "data")
            body_params = _payload_params(body, bindings, m.start()) if body else []
        emit(args[0], verb, body_params, m.start(), "axios" if owner == "axios" else "api_method")

    # XMLHttpRequest.open(method, url): a dynamic method remains unresolved.
    for m, args in _iter_call_args(text, mask, _XHR_OPEN_START_RE):
        if len(args) < 2:
            continue
        method_literal = _parse_string_prefix(_resolve_bound_expr(args[0], bindings, m.start()))
        candidate = method_literal[0].upper() if method_literal else ""
        emit(args[1], candidate if candidate in _HTTP_METHODS else "", [], m.start(), "xhr_open")

    # Detached string literals are discovery hints only.  Their method is
    # deliberately unresolved; _assemble suppresses them when an observed call
    # for the same endpoint exists.
    for s, line in _iter_strings_with_line(text):
        if _API_NEEDLE in s or _PHP_PATH.match(s):
            path, params = _split_url(s)
            if _is_endpoint_path(path):
                out.append((path, "", params, line, "string_literal", {
                    "query_params": _dedupe(params), "body_params": [],
                }))
    return out


# ── HTML ──────────────────────────────────────────────────────────────────
_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_INPUT_NAME_RE = re.compile(r"<input\b[^>]*\bname\s*=\s*['\"]([^'\"]+)['\"]", re.I)
_TAG_RES: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"<a\b[^>]*>", re.I), "href"),
    (re.compile(r"<(?:script|img|iframe|source|video|audio)\b[^>]*>", re.I), "src"),
    (re.compile(r"<link\b[^>]*>", re.I), "href"),
)
_DATA_SRC_RE = re.compile(r"\bdata-[\w-]*src\s*=\s*['\"]([^'\"]+)['\"]", re.I)


def _attr(attrs: str, name: str) -> str:
    m = re.search(r"\b" + re.escape(name) + r"\s*=\s*(['\"])(.*?)\1", attrs, re.I)
    return (m.group(2) if m else "").strip()


def _extract_html(text: str) -> list[tuple[str, str, list[str], int, str, dict[str, list[str]]]]:
    """HTML → [(endpoint, method, params), ...]。<form> 带 method/input；其余默认 GET。"""
    out: list[tuple[str, str, list[str], int, str, dict[str, list[str]]]] = []
    for fm in _FORM_RE.finditer(text):
        attrs, inner = fm.group(1), fm.group(2)
        action = _attr(attrs, "action")
        if not action:
            continue
        candidate = (_attr(attrs, "method") or "GET").upper()
        method = candidate if candidate in _HTTP_METHODS else ""
        path, qparams = _split_url(action)
        if not _is_endpoint_path(path):
            continue
        inputs = _INPUT_NAME_RE.findall(inner)
        query_params = _dedupe(qparams + inputs) if method == "GET" else _dedupe(qparams)
        form_params = [] if method == "GET" else _dedupe(inputs)
        out.append((path, method, _dedupe(qparams + inputs), _line_no(text, fm.start()), "form", {
            "query_params": query_params, "form_params": form_params,
        }))
    for tag_re, attr_name in _TAG_RES:
        for tm in tag_re.finditer(text):
            url = _attr(tm.group(0), attr_name)
            if not url:
                continue
            path, params = _split_url(url)
            if _is_endpoint_path(path) and not _is_static_asset_path(path):
                out.append((path, "GET", params, _line_no(text, tm.start()), attr_name, {
                    "query_params": _dedupe(params),
                }))
    for m in _DATA_SRC_RE.finditer(text):
        path, params = _split_url(m.group(1))
        if _is_endpoint_path(path) and not _is_static_asset_path(path):
            out.append((path, "GET", params, _line_no(text, m.start()), "data-src", {
                "query_params": _dedupe(params),
            }))
    return out


# ── JSON 响应快照 / HAR ───────────────────────────────────────────────────
def _walk_json_paths(
    node: Any,
    out: list[tuple[str, str, list[str], int, str, dict[str, list[str]]]],
) -> None:
    """递归走 JSON 树，收集值字符串里出现的 /api/* 与 *.php 路径。"""
    if isinstance(node, dict):
        for v in node.values():
            _walk_json_paths(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk_json_paths(v, out)
    elif isinstance(node, str):
        if _API_NEEDLE in node or _PHP_PATH.match(node):
            path, params = _split_url(node)
            if _is_endpoint_path(path):
                # A URL in an arbitrary JSON value is a discovery hint, not an
                # observed browser request.  Defaulting it to GET creates a
                # phantom coverage cell.
                out.append((path, "", params, 0, "json_string", {
                    "query_params": _dedupe(params),
                }))


def _extract_har(data: dict[str, Any]) -> list[tuple[str, str, list[str], int, str, dict[str, list[str]]]]:
    """HAR → [(endpoint, method, params), ...]。取 log.entries[].request 的 method+url。"""
    out: list[tuple[str, str, list[str], int, str, dict[str, list[str]]]] = []
    for entry in (data.get("log") or {}).get("entries") or []:
        req = entry.get("request") or {}
        # HAR normally requires request.method.  Malformed/partial snapshots do
        # not gain an invented GET method.
        candidate = str(req.get("method") or "").upper()
        method = candidate if candidate in _HTTP_METHODS else ""
        url = str(req.get("url") or "")
        if not url:
            continue
        path, params = _split_url(url)
        if _is_endpoint_path(path):
            out.append((path, method, params, 0, "har_request", {
                "query_params": _dedupe(params),
            }))
    return out


# ── 装配 ──────────────────────────────────────────────────────────────────
def _assemble(
    raw: list[tuple[str, str, list[str], dict[str, list[str]], str, str, str, int, str]],
) -> list[dict[str, Any]]:
    """去重 + 复用 planner.extract_params 合并 query/占位 → ledger-ready 端点清单。

    每条输出：{endpoint, method, params, source, last_seen}，schema 与
    ``CoverageLedger.from_endpoints`` / ``planner.plan_surfaces`` 的入参同形。
    """
    by_key: dict[tuple, dict[str, Any]] = {}
    for ep, method, params, locations, source, last_seen, source_file, source_line, source_kind in raw:
        # 复用 planner.extract_params：把 query 串键 + 路径占位 {id}/:id 统一抽出来
        params = extract_params(ep, {"params": _dedupe(params)})
        query_params = _dedupe(locations.get("query_params") or [])
        body_params = _dedupe(locations.get("body_params") or [])
        form_params = _dedupe(locations.get("form_params") or [])
        path_params: list[str] = []
        for names in re.findall(r"{([^{}]+)}|:([A-Za-z_][A-Za-z0-9_]*)", ep.split("?", 1)[0]):
            path_params.extend(name for name in names if name)
        path_params = _dedupe(path_params)
        normalized_method = str(method or "").upper()
        provenance = {
            "source": source,
            "source_file": source_file,
            "source_line": source_line,
            "source_kind": source_kind,
            "method": normalized_method,
            "method_confidence": "observed" if normalized_method else "unresolved",
        }
        key = (
            ep, normalized_method, tuple(params), tuple(query_params),
            tuple(body_params), tuple(form_params), tuple(path_params),
        )
        if key in by_key:
            rec = by_key[key]
            if last_seen > rec["last_seen"]:    # 同面多次出现 → 取较新 last_seen
                rec["last_seen"] = last_seen
            if provenance not in rec["provenance"]:
                rec["provenance"].append(provenance)
        else:
            by_key[key] = {
                "endpoint": ep,
                "method": normalized_method,
                "params": params,
                "query_params": query_params,
                "body_params": body_params,
                "form_params": form_params,
                "path_params": path_params,
                "source": source,
                "source_file": source_file,
                "source_line": source_line,
                "source_kind": source_kind,
                "method_confidence": "observed" if normalized_method else "unresolved",
                "provenance": [provenance],
                "last_seen": last_seen,
            }

    records = list(by_key.values())
    observed_endpoints = {rec["endpoint"] for rec in records if rec["method"]}
    unresolved_by_endpoint: dict[str, list[dict[str, Any]]] = {}
    for rec in records:
        if not rec["method"] and rec["endpoint"] in observed_endpoints:
            unresolved_by_endpoint.setdefault(rec["endpoint"], []).extend(rec["provenance"])

    # Once a method has been observed in a real call/form/HAR request, detached
    # string/JSON hints for that same endpoint are provenance only—not extra
    # method="" cells and never phantom GET cells.
    assembled: list[dict[str, Any]] = []
    for rec in records:
        if not rec["method"] and rec["endpoint"] in observed_endpoints:
            continue
        suppressed = unresolved_by_endpoint.get(rec["endpoint"], [])
        if rec["method"] and suppressed:
            rec["suppressed_unresolved_provenance"] = suppressed
        assembled.append(rec)
    return assembled


def _looks_like_js(text: str) -> bool:
    return bool(re.search(r"\b(fetch|axios|XMLHttpRequest|jsonPost|request)\s*\(|\b(?:api|client|http)\s*\.\s*(?:get|post|put|patch|delete)\s*\(", text, re.I))


def _looks_like_html(text: str) -> bool:
    return bool(re.search(r"<(?:html|form|script|a|link|iframe|img)\b", text, re.I))


def bootstrap(recon_dir: pathlib.Path) -> list[dict[str, Any]]:
    """扫 recon 产物目录 → 端点清单（每条带 endpoint/method/params/source/last_seen）。

    支持的产物：``*.js`` / ``*.html`` / ``*.json``(响应快照或 HAR 结构) / ``*.har``。
    输出可直接喂 ``planner.plan_surfaces`` 或 ``CoverageLedger.from_endpoints``。
    目录不存在或为空 → 返回空清单（由调用方决定是否拒绝空启动）。
    """
    recon_dir = pathlib.Path(recon_dir)
    if not recon_dir.is_dir():
        return []
    raw: list[
        tuple[str, str, list[str], dict[str, list[str]], str, str, str, int, str]
    ] = []
    for path in sorted(recon_dir.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        last_seen = _mtime_iso(path)
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        source_file = str(path)
        parsed_structured = False
        if suffix in (".js", ".mjs", ".cjs") or _looks_like_js(text):
            for ep, m, p, line, kind, locations in _extract_js(text):
                raw.append((ep, m, p, locations, SRC_JS, last_seen, source_file, line, kind))
        if suffix in (".html", ".htm") or _looks_like_html(text):
            for ep, m, p, line, kind, locations in _extract_html(text):
                raw.append((ep, m, p, locations, SRC_HTML, last_seen, source_file, line, kind))
        if suffix == ".har":
            parsed_structured = True
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
            for ep, m, p, line, kind, locations in _extract_har(data):
                raw.append((ep, m, p, locations, SRC_HAR, last_seen, source_file, line, kind))
        if suffix == ".json" and not parsed_structured:
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict) and (data.get("log") or {}).get("entries"):
                for ep, m, p, line, kind, locations in _extract_har(data):  # .json 实为 HAR 结构
                    raw.append((ep, m, p, locations, SRC_HAR, last_seen, source_file, line, kind))
            else:
                walked: list[
                    tuple[str, str, list[str], int, str, dict[str, list[str]]]
                ] = []
                _walk_json_paths(data, walked)                # 响应快照里的 /api/* 字符串
                for ep, m, p, line, kind, locations in walked:
                    raw.append((ep, m, p, locations, SRC_TRAFFIC, last_seen, source_file, line, kind))
    return _assemble(raw)


def extract_endpoint_paths(text: str) -> list[str]:
    """从自由文本（模型回复）抽 endpoint 路径候选，去重保序。

    复用 ``_split_url`` 剥 scheme://host/query/fragment、``_is_endpoint_path`` 做结构判别，
    再收紧到 ``/api/*`` 与 ``*.php`` 字面量（不内置任何靶场路径模式）。供 orchestrator
    的「深测中新发现 endpoint」hook 与 inventory 比对用——只抽结构化路径，不抽叙述里的
    普通词。空文本/无候选 → 空清单。
    """
    out: list[str] = []
    seen: set[str] = set()
    for m in _URL_OR_PATH_RE.finditer(text or ""):
        path, _params = _split_url(m.group(0))
        if not _is_endpoint_path(path):
            continue
        # 收紧到 /api/* 与 *.php 字面量（不内置靶场路径）：
        #   - *.php（含或不含 /api/ 前缀）一律收；
        #   - /api/* 要求 /api/ 后有非空段，避免把散文里裸出现的 "/api/" 当 endpoint；
        #   - 其余单段 / 路径（如 /home、/search）不收，降低噪声。
        if _PHP_PATH.match(path):
            pass
        elif _API_NEEDLE in path:
            after = path.split("/api/", 1)[1]
            if not after or not any(seg for seg in after.split("/")):
                continue
        else:
            continue
        key = path.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out


def is_saturated(inventory: list[dict[str, Any]], n: int = 3) -> bool:
    """连续 n 个来源不再新增 endpoint → 视为 discovery 饱和（diminishing returns）。

    inventory: 端点台账（list[dict]，每条含 ``source``/``endpoint``；与 inventory.json 的
    ``endpoints`` 同形）。按来源**首次出现顺序**处理，累计已见 endpoint 集合；一旦出现
    n 个连续来源各贡献 0 个新 endpoint，即判定饱和。来源种类不足 n 时不饱和（证据不足，
    应继续 discover）。空台账/无 endpoint 的台账不饱和。

    用法：discovery 阶段每追加一个来源后调用；饱和后才进深测。orchestrator 无明确
    discovery/深测分阶时，把结果记进 inventory.json 的 ``saturation_reached`` 标志。
    """
    source_order: list[str] = []
    per_source_new: dict[str, int] = {}
    seen_eps: set[str] = set()
    for rec in inventory or []:
        if not isinstance(rec, dict):
            continue
        src = str(rec.get("source") or "")
        ep = str(rec.get("endpoint") or "").split("?", 1)[0]
        if src not in per_source_new:
            per_source_new[src] = 0
            source_order.append(src)
        if ep and ep not in seen_eps:
            seen_eps.add(ep)
            per_source_new[src] += 1
    if len(source_order) < n:
        return False
    streak = 0
    for src in source_order:
        if per_source_new[src] == 0:
            streak += 1
            if streak >= n:
                return True
        else:
            streak = 0
    return False


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="解析 recon 产物 → 攻击面清单(endpoint/method/param/source/last_seen)")
    ap.add_argument("--recon-dir", required=True, help="recon 产物目录")
    args = ap.parse_args(argv)
    surfaces = bootstrap(pathlib.Path(args.recon_dir))
    print(json.dumps(surfaces, ensure_ascii=False, indent=2))
    return 0


def _selftest() -> None:
    """Self-test for is_saturated / extract_endpoint_paths (v4.1 P1-3)."""
    print("=== surface self-test: is_saturated / extract_endpoint_paths (v4.1 P1-3) ===")

    # is_saturated: 连续 3 源无新增 → True（js/html 各有新增，traffic/har/manual 全重复）
    inv_sat = [
        {"endpoint": "/api/a", "source": "js"},
        {"endpoint": "/api/b", "source": "js"},
        {"endpoint": "/api/c", "source": "html"},
        {"endpoint": "/api/a", "source": "traffic"},   # 重复 → 0 新增
        {"endpoint": "/api/b", "source": "har"},        # 重复 → 0 新增
        {"endpoint": "/api/c", "source": "manual"},     # 重复 → 0 新增（连续 3 源无新增）
    ]
    assert is_saturated(inv_sat, n=3) is True, "连续 3 源(traffic/har/manual)无新增应饱和"

    # 仍有新增 → False（traffic 贡献 /api/d，streak 重置，末尾仅 2 源无新增 < 3）
    inv_unsat = [
        {"endpoint": "/api/a", "source": "js"},
        {"endpoint": "/api/b", "source": "html"},
        {"endpoint": "/api/d", "source": "traffic"},   # 新增 → streak 清零
        {"endpoint": "/api/a", "source": "har"},        # 0 新增
        {"endpoint": "/api/b", "source": "manual"},     # 0 新增（streak=2 < 3）
    ]
    assert is_saturated(inv_unsat, n=3) is False, "traffic 仍有新增 → 不饱和"

    # 来源种类 < n → 不饱和（证据不足）
    assert is_saturated([{"endpoint": "/api/a", "source": "js"}], n=3) is False
    # 空台账 → 不饱和
    assert is_saturated([], n=3) is False
    print("  ✅ is_saturated: 连续3源无新增→True / 仍有新增→False / 来源<n→False / 空→False")

    # extract_endpoint_paths: 从模型回复式文本抽路径
    text = (
        "已落盘 report.md，换 3 个 ID 重放 /api/orders/1001 均成功越权。\n"
        "CELL: /api/orders/{id} | 越权/IDOR | PASS | 已出报告\n"
        "另见 https://t.example/api/users/8f3e-uuid-aaaa/info 与 login.php?next=/home\n"
        "证据见 report_idor.md（.md 文件名，应被忽略）与 /home（无 /api/，应被忽略）"
    )
    paths = extract_endpoint_paths(text)
    assert "/api/orders/1001" in paths, f"应抽出 /api/orders/1001，实得 {paths}"
    assert "/api/orders/{id}" in paths, f"应抽出 /api/orders/{{id}}，实得 {paths}"
    assert "/api/users/8f3e-uuid-aaaa/info" in paths, f"应剥 host 抽 /api/users/.../info，实得 {paths}"
    assert "login.php" in paths, f"应抽出 login.php，实得 {paths}"
    assert "report_idor.md" not in paths, ".md 文件名不应被当 endpoint"
    assert "/home" not in paths, "无 /api/ 前缀的普通路径不应被抽（收紧到 /api/* 与 *.php）"
    assert "/api/" not in paths and "/api" not in paths, "散文里裸出现的 /api/ 不应被当 endpoint"
    print(f"  ✅ extract_endpoint_paths: 抽出 {paths}")
    print("✅ all surface self-test cases passed")


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        _selftest()
    else:
        raise SystemExit(main())
