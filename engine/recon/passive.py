"""被动源（默认关）：crt.sh 子域 + web.archive.org CDX 历史 URL。

只允许访问硬编码的 ``PASSIVE_HOSTS`` 白名单域名；在册门注入的是白名单而非
``authorized_scopes``（被动源自身的 302 才不会被 scope 门误杀）。每个出站请求
同样走 fetch.py 的限速/审计/重定向手动跟随。

产出纪律：crt.sh 子域只进摘要（是否回灌 scope 由人决定后走 ``skill_runtime
scope --add``，采集器不自动扩 scope）；wayback URL 按 host 分组写
``historical/<host>.urls.json``，只保留在册 host 的 URL（其余丢弃计数）。
"""
from __future__ import annotations

import json
import urllib.parse

from ..host_policy import hostname_from_url, parse_authorized_scope
from .emit import ReconWriter, host_of_url
from .fetch import AuditLog, Fetcher, FetchOutcome, log_skip

PASSIVE_HOSTS = ("crt.sh", "web.archive.org")

WAYBACK_LIMIT = 5000


def passive_gate(url: str) -> bool:
    """被动源在册门：URL 的 host 必须精确命中白名单（子域也不放行）。"""
    return hostname_from_url(url) in PASSIVE_HOSTS


def _apex_of(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def fetch_crtsh_subdomains(fetcher: Fetcher, target_host: str) -> tuple[list[str], str | None]:
    """``crt.sh`` 证书透明度子域列表（去重排序，只进摘要）。"""
    apex = _apex_of(target_host)
    url = (f"https://crt.sh/?q=%25.{urllib.parse.quote(apex)}"
           f"&output=json")
    outcome = fetcher.fetch(url, passive_gate, scope_label="passive")
    if outcome.error:
        return [], outcome.error
    try:
        data = json.loads(outcome.body.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return [], "crtsh_invalid_json"
    subdomains: set[str] = set()
    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            for key in ("name_value", "common_name"):
                value = entry.get(key)
                if not isinstance(value, str):
                    continue
                for line in value.splitlines():
                    name = line.strip().lower().lstrip("*.")
                    if name.endswith("." + apex):
                        subdomains.add(name)
    return sorted(subdomains), None


def _scope_hosts(authorized_scopes: list[str]) -> list[tuple[str, bool]]:
    """从 scope 列表解析 (host, include_subdomains)，供 wayback 在册 host 判定。"""
    hosts: list[tuple[str, bool]] = []
    for raw in authorized_scopes or []:
        scope = parse_authorized_scope(str(raw))
        if scope:
            hosts.append((scope.host, scope.include_subdomains))
    return hosts


def _host_in_scope(host: str, scope_hosts: list[tuple[str, bool]]) -> bool:
    for scope_host, include_subdomains in scope_hosts:
        if host == scope_host:
            return True
        if include_subdomains and host.endswith("." + scope_host):
            return True
    return False


def fetch_wayback_urls(
    fetcher: Fetcher,
    target_host: str,
    authorized_scopes: list[str],
) -> tuple[list[str], int, str | None]:
    """wayback CDX 历史 URL：只保留在册 host 的 URL，返回 (urls, skipped, error)。"""
    apex = _apex_of(target_host)
    url = (f"https://web.archive.org/cdx/search/cdx?url="
           f"{urllib.parse.quote(apex)}/*&output=json&collapse=urlkey"
           f"&limit={WAYBACK_LIMIT}")
    outcome = fetcher.fetch(url, passive_gate, scope_label="passive")
    if outcome.error:
        return [], 0, outcome.error
    try:
        data = json.loads(outcome.body.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return [], 0, "wayback_invalid_json"
    # CDX JSON 行格式：[urlkey, timestamp, original, mimetype, ...]，首行为表头。
    rows = data[1:] if isinstance(data, list) and data and isinstance(data[0], list) else []
    scope_hosts = _scope_hosts(authorized_scopes)
    kept: list[str] = []
    skipped = 0
    for row in rows:
        if not isinstance(row, list) or len(row) < 3 or not isinstance(row[2], str):
            continue
        candidate = row[2].strip()
        host = hostname_from_url(candidate)
        if not host:
            continue
        if not _host_in_scope(host, scope_hosts):
            skipped += 1
            log_skip(fetcher.audit, candidate, "out_of_scope", scope="passive")
            continue
        kept.append(candidate)
    return kept, skipped, None


def run_passive_sources(
    *,
    fetcher: Fetcher,
    audit: AuditLog,
    writer: ReconWriter,
    summary: dict,
    target_host: str,
    authorized_scopes: list[str],
) -> None:
    """crt.sh + wayback（默认关，``--passive`` 显式开启才调用）。"""
    subdomains, cr_error = fetch_crtsh_subdomains(fetcher, target_host)
    if cr_error:
        summary["errors"].append({"url": f"crt.sh/?q={target_host}", "error": cr_error})
    if subdomains:
        summary["subdomains"] = subdomains

    urls, skipped, wb_error = fetch_wayback_urls(
        fetcher, target_host, authorized_scopes)
    if wb_error:
        summary["errors"].append(
            {"url": f"web.archive.org/cdx?url={target_host}", "error": wb_error})
    summary["skipped_out_of_scope"] += skipped
    by_host: dict[str, list[str]] = {}
    for url in urls:
        by_host.setdefault(host_of_url(url), []).append(url)
    for host in sorted(by_host):
        writer.historical(host, by_host[host])
    summary["historical_urls"] = len(urls)
