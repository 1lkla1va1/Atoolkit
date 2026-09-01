"""编排器：``collect_recon(seeds, authorized_scopes, out_dir, ...) -> dict 摘要``。

入口校验 fail closed：``seeds`` 中任何 URL 不过 ``is_authorized_url`` → 直接抛
``ValueError``，一个请求都不发。主动源（crawl.py）+ 可选被动源（passive.py，默认
关）→ ``emit.ReconWriter`` 落盘 → ``recon-summary.jsonl``（返回值 + 输入参数回显，
单行 JSON）。
"""
from __future__ import annotations

import pathlib

from ..host_policy import hostname_from_url, is_authorized_url
from . import crawl as crawl_module
from . import passive as passive_module
from .emit import ReconWriter
from .fetch import AuditLog, Fetcher


def collect_recon(
    seeds: list[str],
    authorized_scopes: list[str],
    out_dir: pathlib.Path,
    *,
    passive: bool = False,
    max_pages: int = 200,
    rps: float = 2.0,
    max_file_bytes: int = 2 * 1024 * 1024,
    max_total_bytes: int = 50 * 1024 * 1024,
    timeout: float = 15.0,
) -> dict:
    """采集 recon 原料并落盘 recon_dir 契约布局；返回摘要 dict。"""
    seed_list = [str(item).strip() for item in (seeds or []) if str(item).strip()]
    if not seed_list:
        raise ValueError("collect_recon: seeds 不能为空")
    scopes = [str(item) for item in (authorized_scopes or [])]
    # fail closed：任何一个 seed 不在册 → 一个请求都不发。
    for seed in seed_list:
        if not is_authorized_url(seed, scopes):
            raise ValueError(f"seed out of authorized scope: {seed!r}")

    audit = AuditLog()
    writer = ReconWriter(out_dir)
    fetcher = Fetcher(audit=audit, rps=rps, max_file_bytes=max_file_bytes,
                      timeout=timeout)

    def gate(url: str) -> bool:
        return is_authorized_url(url, scopes)

    summary: dict = {
        "pages": 0,
        "js": 0,
        "skipped_out_of_scope": 0,
        "errors": [],
        "stopped": None,
        "seeds": seed_list,
        "authorized_scopes": scopes,
        "passive_enabled": bool(passive),
        "max_pages": int(max_pages),
        "rps": float(rps),
        "max_file_bytes": int(max_file_bytes),
        "max_total_bytes": int(max_total_bytes),
        "timeout": float(timeout),
        "subdomains": [],
        "historical_urls": 0,
    }
    crawl_module.crawl(
        seed_list, fetcher=fetcher, scope_gate=gate, audit=audit, writer=writer,
        summary=summary, max_pages=int(max_pages),
        max_total_bytes=int(max_total_bytes))
    summary["pages"] = writer.pages
    summary["js"] = writer.js
    if passive:
        target_host = hostname_from_url(seed_list[0]) or seed_list[0]
        passive_module.run_passive_sources(
            fetcher=fetcher, audit=audit, writer=writer, summary=summary,
            target_host=target_host, authorized_scopes=scopes)
    writer.write_audit(audit.rows)
    result = dict(summary)
    result["total_bytes_written"] = writer.total_bytes
    result["audit_rows"] = len(audit.rows)
    result["out_dir"] = str(out_dir)
    writer.write_summary(result)
    return result
