"""recon_dir 落盘布局 + 审计 + 摘要（布局契约必须被 surface.bootstrap 原样消费）。

``<out_dir>/`` 布局：
  - ``pages/<host>/<sha256[:16]>.html``   HTML 快照
  - ``js/<host>/<sha256[:16]>.js``        JS 快照
  - ``historical/<host>.urls.json``       被动源历史 URL（唯一有意的 .json：
                                          URL 字符串数组，bootstrap 当发现提示消费）
  - ``_recon_audit.jsonl``                每个出站请求一行审计
  - ``recon-summary.jsonl``               摘要 + 输入参数回显（单行 JSON）

元文件一律 ``.jsonl``（bootstrap 只结构化消费 ``.json``/``.har``/``.js``/``.html``）：
若摘要/审计用 ``.json``，其中出现的 ``/api/`` 字符串会被收成幻影发现提示。
所有写入走 ``safe_io.atomic_write_bytes``；文件名只含 sha256 十六进制与固定扩展名
（URL 不进入文件系统路径）；``<host>`` = netloc 小写（含端口）。
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import urllib.parse

from ..safe_io import atomic_write_bytes, ensure_directory

AUDIT_NAME = "_recon_audit.jsonl"
SUMMARY_NAME = "recon-summary.jsonl"

# netloc 允许进入目录名的字符（含 IPv6 括号与端口冒号）；其余替换为下划线。
_HOST_SAFE = re.compile(r"[^0-9a-z.\[\]:-]+")

AUDIT_FIELDS = ("ts", "url", "scope", "action", "status", "bytes", "truncated",
                "reason")


def sanitize_host(value: str) -> str:
    return _HOST_SAFE.sub("_", str(value or "").strip().lower()) or "unknown"


def host_of_url(url: str) -> str:
    return sanitize_host(urllib.parse.urlsplit(url).netloc)


def snapshot_name(url: str, ext: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16] + ext


class ReconWriter:
    """recon 产物写入器：统计 pages/js/total_bytes 供摘要与限额使用。"""

    def __init__(self, out_dir: str | pathlib.Path) -> None:
        self.out_dir = pathlib.Path(out_dir)
        ensure_directory(self.out_dir)
        self.pages = 0
        self.js = 0
        self.total_bytes = 0

    def page_snapshot(self, url: str, body: bytes) -> pathlib.Path:
        path = self.out_dir / "pages" / host_of_url(url) / snapshot_name(url, ".html")
        atomic_write_bytes(path, bytes(body))
        self.pages += 1
        self.total_bytes += len(body)
        return path

    def js_snapshot(self, url: str, body: bytes) -> pathlib.Path:
        path = self.out_dir / "js" / host_of_url(url) / snapshot_name(url, ".js")
        atomic_write_bytes(path, bytes(body))
        self.js += 1
        self.total_bytes += len(body)
        return path

    def historical(self, host: str, urls: list[str]) -> pathlib.Path:
        path = self.out_dir / "historical" / f"{sanitize_host(host)}.urls.json"
        payload = json.dumps(list(urls), ensure_ascii=False).encode("utf-8")
        atomic_write_bytes(path, payload)
        self.total_bytes += len(payload)
        return path

    def write_audit(self, rows: list[dict]) -> pathlib.Path:
        payload = "".join(
            json.dumps(row, ensure_ascii=False) + "\n" for row in rows
        ).encode("utf-8")
        return atomic_write_bytes(self.out_dir / AUDIT_NAME, payload)

    def write_summary(self, value: dict) -> pathlib.Path:
        payload = (json.dumps(value, ensure_ascii=False) + "\n").encode("utf-8")
        return atomic_write_bytes(self.out_dir / SUMMARY_NAME, payload)
