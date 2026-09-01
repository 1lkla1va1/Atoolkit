"""主动源：种子页 → 提取 ``<script src>`` / ``<link href>`` / ``<a href>`` → 下载快照。

深度 ≤2：seed 为深度 0，其页面链接为深度 1，最深抓到深度 2。去重按 URL 归一化
（小写 scheme/netloc、去默认端口、去 fragment）。快照文件名哈希取**最初请求的
URL**（重定向链第一跳）。候选 URL 逐个过 scope 门（代码门禁，非提示词纪律）；
不在册即跳过并记审计行 + ``skipped_out_of_scope`` 计数。页数受 ``max_pages``、
落盘字节受 ``max_total_bytes`` 约束。
"""
from __future__ import annotations

import html as _html
import re
import urllib.parse
from collections import deque

from .emit import ReconWriter
from .fetch import AuditLog, Fetcher, log_skip

PAGE_DEPTH_LIMIT = 2

_ATTR_SCRIPT_SRC = re.compile(r"<script\b[^>]*?\bsrc\s*=\s*['\"]([^'\"]*)['\"]", re.I)
_ATTR_LINK_HREF = re.compile(r"<link\b[^>]*?\bhref\s*=\s*['\"]([^'\"]*)['\"]", re.I)
_ATTR_A_HREF = re.compile(r"<a\b[^>]*?\bhref\s*=\s*['\"]([^'\"]*)['\"]", re.I)

_SKIP_PREFIXES = ("#", "javascript:", "mailto:", "data:", "tel:", "ftp:")


def is_js_url(url: str) -> bool:
    return urllib.parse.urlsplit(url).path.lower().endswith(".js")


def resolve_url(base_url: str, raw: str) -> str:
    """相对/绝对 href/src → 绝对 http(s) URL；非抓取目标（锚点/mailto 等）返回空串。

    base_url 由调用方传 fetch 结果的 ``final_url``（重定向落点），不是原始请求 URL。
    """
    value = _html.unescape(str(raw or "").strip())
    if not value or value.lower().startswith(_SKIP_PREFIXES):
        return ""
    resolved = urllib.parse.urljoin(base_url, value)
    split = urllib.parse.urlsplit(resolved)
    if split.scheme not in ("http", "https") or not split.hostname:
        return ""
    return urllib.parse.urlunsplit(
        (split.scheme.lower(), split.netloc, split.path or "/", split.query, ""))


def normalize_url(url: str) -> str:
    """crawl 去重键：小写 scheme/netloc、去默认端口、去 fragment，保留 path+query。"""
    split = urllib.parse.urlsplit(url)
    scheme = split.scheme.lower()
    netloc = split.netloc.lower()
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    return urllib.parse.urlunsplit((scheme, netloc, split.path or "/", split.query, ""))


def extract_candidates(base_url: str, text: str) -> tuple[list[str], list[str]]:
    """HTML → (js 候选, 页面候选)。``<link href>`` 只认 ``.js`` 结尾（CSS/图标不抓）。"""
    js_candidates: list[str] = []
    page_candidates: list[str] = []
    for match in _ATTR_SCRIPT_SRC.finditer(text):
        resolved = resolve_url(base_url, match.group(1))
        if resolved:
            js_candidates.append(resolved)
    for match in _ATTR_LINK_HREF.finditer(text):
        resolved = resolve_url(base_url, match.group(1))
        if resolved and is_js_url(resolved):
            js_candidates.append(resolved)
    for match in _ATTR_A_HREF.finditer(text):
        resolved = resolve_url(base_url, match.group(1))
        if resolved:
            page_candidates.append(resolved)
    return js_candidates, page_candidates


def crawl(
    seeds: list[str],
    *,
    fetcher: Fetcher,
    scope_gate,
    audit: AuditLog,
    writer: ReconWriter,
    summary: dict,
    max_pages: int,
    max_total_bytes: int,
) -> None:
    """BFS 抓取种子页与链接页（深度 ≤2）+ JS 快照。结果写入 writer/summary。"""
    seen: set[str] = set()
    queue: deque[tuple[str, int]] = deque()
    for seed in seeds:
        key = normalize_url(seed)
        if key not in seen:
            seen.add(key)
            queue.append((seed, 0))

    def _budget_ok() -> bool:
        return writer.total_bytes + fetcher.max_file_bytes <= max_total_bytes

    def _stop(flag: str) -> None:
        if not summary.get("stopped"):
            summary["stopped"] = flag

    def _reject(url: str) -> bool:
        """候选 URL 过 scope 门；不在册记审计 + 计数，返回 True 表示被拒。"""
        if scope_gate(url):
            return False
        summary["skipped_out_of_scope"] += 1
        log_skip(audit, url, "out_of_scope")
        return True

    while queue:
        if not _budget_ok():
            _stop("byte_cap")
            break
        url, depth = queue.popleft()
        if writer.pages >= max_pages:
            _stop("max_pages")
            break

        outcome = fetcher.fetch(url, scope_gate)
        if outcome.error:
            if outcome.error in ("out_of_scope", "redirect_out_of_scope"):
                summary["skipped_out_of_scope"] += 1
            else:
                summary["errors"].append({"url": url, "error": outcome.error})
            continue
        if not outcome.body:
            continue

        if is_js_url(url):
            writer.js_snapshot(outcome.url, outcome.body)
            continue
        writer.page_snapshot(outcome.url, outcome.body)

        text = outcome.body.decode("utf-8", errors="ignore")
        # P2-2：相对链接解析基准必须用 final_url（重定向后落点）——
        # seed 经 in-scope 302 落到 /login/ 时，页内相对链接要按跳转后
        # 路径解析，否则产出错误候选（被 scope 门兜底不出界，但漏抓/错抓）。
        js_candidates, page_candidates = extract_candidates(outcome.final_url, text)

        budget_dead = False
        for candidate in js_candidates:
            key = normalize_url(candidate)
            if key in seen:
                continue
            seen.add(key)
            if _reject(candidate):
                continue
            if not _budget_ok():
                _stop("byte_cap")
                budget_dead = True
                break
            js_outcome = fetcher.fetch(candidate, scope_gate)
            if js_outcome.error:
                if js_outcome.error in ("out_of_scope", "redirect_out_of_scope"):
                    summary["skipped_out_of_scope"] += 1
                else:
                    summary["errors"].append(
                        {"url": candidate, "error": js_outcome.error})
                continue
            if js_outcome.body:
                writer.js_snapshot(js_outcome.url, js_outcome.body)
        if budget_dead:
            break

        # 页面链接入队：seed=0，其链接=1，最深抓到深度 2。
        if depth < PAGE_DEPTH_LIMIT:
            for candidate in page_candidates:
                key = normalize_url(candidate)
                if key in seen:
                    continue
                seen.add(key)
                if _reject(candidate):
                    continue
                queue.append((candidate, depth + 1))
