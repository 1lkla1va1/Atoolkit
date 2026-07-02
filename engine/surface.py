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

# ── 通用路径识别（无靶场模式，只看结构）────────────────────────────────────
_API_NEEDLE = "/api/"                                   # 通用 API 路径前缀，非业务名
_PHP_PATH = re.compile(r"^[A-Za-z0-9_][\w./-]*\.php(?:\?[\w=&%.-]*)?$")
_BAD_PATH_CHARS = frozenset(" \t\r\n\"'<>|\\^`")        # 路径里不应出现的字符


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
    params = [k for k, _ in parse_qsl(query, keep_blank_values=True)] if query else []
    return path, params


def _is_endpoint_path(path: str) -> bool:
    """结构判别：是否像一个 endpoint 路径（非业务名，只看 / 与段，允许 {id}/:id 占位）。"""
    if not path or len(path) > 2000 or any(c in path for c in _BAD_PATH_CHARS):
        return False
    if path.startswith("/"):
        return any(seg for seg in path.split("/"))                 # 至少一个非空段
    return bool(_PHP_PATH.match(path))                             # 无前导 / 只认 .php 相对路径


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
_URL_ARG = r"(?:'([^'\\]*(?:\\.[^'\\]*)*)'|\"([^\"\\]*(?:\\.[^\"\\]*)*)\"|`([^`\\]*(?:\\.[^`\\]*)*)`|([A-Za-z_$][\w$]*))"
_ASSIGN_RE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(['\"`])([^'\"`]+?)\2", re.I)
_FETCH_RE = re.compile(r"\bfetch\s*\(\s*" + _URL_ARG + r"([^)]*)\)", re.I | re.S)
_AXIOS_RE = re.compile(
    r"\baxios\s*\.\s*(get|post|put|patch|delete|head)\s*\(\s*" + _URL_ARG + r"([^)]*)\)",
    re.I | re.S)
_API_METHOD_RE = re.compile(
    r"\b(?:api|client|http)\s*\.\s*(get|post|put|patch|delete|head)\s*\(\s*" + _URL_ARG + r"([^)]*)\)",
    re.I | re.S)
_WRAPPER_RE = re.compile(
    r"\b(jsonPost|request)\s*\(\s*" + _URL_ARG + r"([^)]*)\)",
    re.I | re.S)
_XHR_OPEN_RE = re.compile(r"\.open\s*\(\s*['\"](\w+)['\"]\s*,\s*" + _URL_ARG, re.I | re.S)
_FETCH_METHOD_RE = re.compile(r"\bmethod\s*:\s*['\"`](\w+)['\"`]", re.I)


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


def _var_map(text: str) -> dict[str, str]:
    return {m.group(1): re.sub(r"\$\{([^}]*)\}", r"{\1}", m.group(3))
            for m in _ASSIGN_RE.finditer(text)}


def _url_from_match(m: re.Match, vars: dict[str, str], first_group: int = 1) -> str:
    for idx in range(first_group, first_group + 3):
        literal = m.group(idx)
        if literal is not None:
            return re.sub(r"\$\{([^}]*)\}", r"{\1}", literal)
    var_name = m.group(first_group + 3)
    return vars.get(var_name or "", "")


def _object_params(obj: str) -> list[str]:
    inner = obj.strip()
    if inner.startswith("{") and inner.endswith("}"):
        inner = inner[1:-1]
    params: list[str] = []
    for part in inner.split(","):
        token = part.strip()
        if not token:
            continue
        m = re.match(r"([A-Za-z_$][\w$-]*)\s*:", token)
        if m:
            params.append(m.group(1))
            continue
        m = re.match(r"([A-Za-z_$][\w$-]*)\b", token)
        if m and m.group(1) not in {"true", "false", "null", "undefined"}:
            params.append(m.group(1))
    return params


def _data_params(rest: str) -> list[str]:
    """从 axios 第二实参（data）抽 body param：对象字面量 → key；query 串 → 键。"""
    rest = rest.lstrip(" ,")
    body_m = re.search(r"\bbody\s*:\s*(?:JSON\.stringify\s*\()?\s*(\{[^{}]*\})", rest, re.I | re.S)
    if body_m:
        return _object_params(body_m.group(1))
    stringify_m = re.search(r"JSON\.stringify\s*\(\s*(\{[^{}]*\})", rest, re.I | re.S)
    if stringify_m:
        return _object_params(stringify_m.group(1))
    if rest.startswith("{"):
        m = re.match(r"(\{[^{}]*\})", rest, re.S)
        return _object_params(m.group(1) if m else rest)
    for q in ("'", '"', "`"):
        if rest.startswith(q):
            end = rest.find(q, 1)
            if end > 0:
                return [k for k, _ in parse_qsl(rest[1:end], keep_blank_values=True)]
            break
    return []


def _extract_js(text: str) -> list[tuple[str, str, list[str], int, str]]:
    """JS → [(endpoint, method, params), ...]。"""
    out: list[tuple[str, str, list[str], int, str]] = []
    vars = _var_map(text)
    # fetch(url[, opts])：method 默认 GET，opts 里 method: 则取之
    for m in _FETCH_RE.finditer(text):
        url, rest = _url_from_match(m, vars), m.group(5)
        method = "GET"
        mm = _FETCH_METHOD_RE.search(rest)
        if mm:
            method = mm.group(1).upper()
        path, params = _split_url(url)
        params = params + _data_params(rest)
        if _is_endpoint_path(path):
            out.append((path, method, params, _line_no(text, m.start()), "fetch"))
    # axios.verb(url[, data])
    for m in _AXIOS_RE.finditer(text):
        verb, url, rest = m.group(1).upper(), _url_from_match(m, vars, 2), m.group(6)
        path, params = _split_url(url)
        params = params + _data_params(rest)
        if _is_endpoint_path(path):
            out.append((path, verb, params, _line_no(text, m.start()), "axios"))
    # api.post(url, data) / client.get(url)
    for m in _API_METHOD_RE.finditer(text):
        verb, url, rest = m.group(1).upper(), _url_from_match(m, vars, 2), m.group(6)
        path, params = _split_url(url)
        params = params + _data_params(rest)
        if _is_endpoint_path(path):
            out.append((path, verb, params, _line_no(text, m.start()), "api_method"))
    # jsonPost(url, body) / request(url, opts)
    for m in _WRAPPER_RE.finditer(text):
        name, url, rest = m.group(1), _url_from_match(m, vars, 2), m.group(6)
        method = "POST" if name.lower() == "jsonpost" else "GET"
        mm = _FETCH_METHOD_RE.search(rest)
        if mm:
            method = mm.group(1).upper()
        path, params = _split_url(url)
        params = params + _data_params(rest)
        if _is_endpoint_path(path):
            out.append((path, method, params, _line_no(text, m.start()), name))
    # XMLHttpRequest.open(method, url)
    for m in _XHR_OPEN_RE.finditer(text):
        method, url = m.group(1).upper(), _url_from_match(m, vars, 2)
        path, params = _split_url(url)
        if _is_endpoint_path(path):
            out.append((path, method, params, _line_no(text, m.start()), "xhr_open"))
    # 字符串字面量里的 /api/* 与 *.php 路径（无调用上下文 → GET）
    for s, line in _iter_strings_with_line(text):
        if _API_NEEDLE in s or _PHP_PATH.match(s):
            path, params = _split_url(s)
            if _is_endpoint_path(path):
                out.append((path, "GET", params, line, "string_literal"))
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


def _extract_html(text: str) -> list[tuple[str, str, list[str], int, str]]:
    """HTML → [(endpoint, method, params), ...]。<form> 带 method/input；其余默认 GET。"""
    out: list[tuple[str, str, list[str], int, str]] = []
    for fm in _FORM_RE.finditer(text):
        attrs, inner = fm.group(1), fm.group(2)
        action = _attr(attrs, "action")
        if not action:
            continue
        method = (_attr(attrs, "method") or "GET").upper()
        path, qparams = _split_url(action)
        if not _is_endpoint_path(path):
            continue
        inputs = _INPUT_NAME_RE.findall(inner)
        out.append((path, method, _dedupe(qparams + inputs), _line_no(text, fm.start()), "form"))
    for tag_re, attr_name in _TAG_RES:
        for tm in tag_re.finditer(text):
            url = _attr(tm.group(0), attr_name)
            if not url:
                continue
            path, params = _split_url(url)
            if _is_endpoint_path(path):
                out.append((path, "GET", params, _line_no(text, tm.start()), attr_name))
    for m in _DATA_SRC_RE.finditer(text):
        path, params = _split_url(m.group(1))
        if _is_endpoint_path(path):
            out.append((path, "GET", params, _line_no(text, m.start()), "data-src"))
    return out


# ── JSON 响应快照 / HAR ───────────────────────────────────────────────────
def _walk_json_paths(node: Any, out: list[tuple[str, str, list[str], int, str]]) -> None:
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
                out.append((path, "GET", params, 0, "json_string"))


def _extract_har(data: dict[str, Any]) -> list[tuple[str, str, list[str], int, str]]:
    """HAR → [(endpoint, method, params), ...]。取 log.entries[].request 的 method+url。"""
    out: list[tuple[str, str, list[str], int, str]] = []
    for entry in (data.get("log") or {}).get("entries") or []:
        req = entry.get("request") or {}
        method = str(req.get("method") or "GET").upper()
        url = str(req.get("url") or "")
        if not url:
            continue
        path, params = _split_url(url)
        if _is_endpoint_path(path):
            out.append((path, method, params, 0, "har_request"))
    return out


# ── 装配 ──────────────────────────────────────────────────────────────────
def _assemble(raw: list[tuple[str, str, list[str], str, str, str, int, str]]) -> list[dict[str, Any]]:
    """去重 + 复用 planner.extract_params 合并 query/占位 → ledger-ready 端点清单。

    每条输出：{endpoint, method, params, source, last_seen}，schema 与
    ``CoverageLedger.from_endpoints`` / ``planner.plan_surfaces`` 的入参同形。
    """
    by_key: dict[tuple, dict[str, Any]] = {}
    for ep, method, params, source, last_seen, source_file, source_line, source_kind in raw:
        # 复用 planner.extract_params：把 query 串键 + 路径占位 {id}/:id 统一抽出来
        params = extract_params(ep, {"params": _dedupe(params)})
        key = (ep, method.upper(), tuple(params))
        if key in by_key:
            rec = by_key[key]
            if last_seen > rec["last_seen"]:    # 同面多次出现 → 取较新 last_seen
                rec["last_seen"] = last_seen
            # source 保留首次（单 token），不混合
        else:
            by_key[key] = {
                "endpoint": ep,
                "method": method.upper(),
                "params": params,
                "source": source,
                "source_file": source_file,
                "source_line": source_line,
                "source_kind": source_kind,
                "last_seen": last_seen,
            }
    return list(by_key.values())


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
    raw: list[tuple[str, str, list[str], str, str, str, int, str]] = []
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
            for ep, m, p, line, kind in _extract_js(text):
                raw.append((ep, m, p, SRC_JS, last_seen, source_file, line, kind))
        if suffix in (".html", ".htm") or _looks_like_html(text):
            for ep, m, p, line, kind in _extract_html(text):
                raw.append((ep, m, p, SRC_HTML, last_seen, source_file, line, kind))
        if suffix == ".har":
            parsed_structured = True
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
            for ep, m, p, line, kind in _extract_har(data):
                raw.append((ep, m, p, SRC_HAR, last_seen, source_file, line, kind))
        if suffix == ".json" and not parsed_structured:
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict) and (data.get("log") or {}).get("entries"):
                for ep, m, p, line, kind in _extract_har(data):           # .json 实为 HAR 结构
                    raw.append((ep, m, p, SRC_HAR, last_seen, source_file, line, kind))
            else:
                walked: list[tuple[str, str, list[str], int, str]] = []
                _walk_json_paths(data, walked)                # 响应快照里的 /api/* 字符串
                for ep, m, p, line, kind in walked:
                    raw.append((ep, m, p, SRC_TRAFFIC, last_seen, source_file, line, kind))
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
