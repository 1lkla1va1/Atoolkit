"""限速 GET 客户端：token bucket per host；urllib 标准库；大小上限。

安全关键（v10.0 Gate-A P0-1）：禁止 urllib 自动跟随重定向——301/302/303/307/308
一律被 ``_RedirectBlocker`` 拦截为 HTTPError，由 :meth:`Fetcher.fetch` 手动跟随：
``Location`` 先 ``urljoin`` 解析为绝对 URL，再过注入的 scope 门，在册才继续跟随、
不在册记审计行（``reason: redirect_out_of_scope``）后放弃该链；跟随上限 5 跳，
每一跳都重新过门并独立计时。环境代理显式禁用（``ProxyHandler({})``），出站不
引流到未审计路径。

scope 门以函数注入，不硬编码：主动源注入 ``is_authorized_url`` 闭包；被动源注入
PASSIVE_HOSTS 白名单（见 passive.py）。
"""
from __future__ import annotations

import datetime as _dt
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

try:
    from ..throttle import HostThrottle
except ImportError:  # pragma: no cover - direct script execution
    from throttle import HostThrottle

REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECT_HOPS = 5
USER_AGENT = "Atoolkit-Recon/10.0"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass
class FetchOutcome:
    """一次 fetch 的结果：原始 URL / 最终 URL / 状态 / 截断后 body / 错误。"""

    url: str                      # 最初请求的 URL（重定向链第一跳）
    final_url: str = ""
    status: int | None = None
    body: bytes = b""
    truncated: bool = False
    error: str | None = None
    hops: int = 0
    redirect_chain: list[str] = field(default_factory=list)


class AuditLog:
    """出站请求审计：每个请求（含重定向跳与 skip）一行。"""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(
        self,
        *,
        url: str,
        scope: str,
        action: str,
        status: int | None,
        bytes_: int,
        truncated: bool = False,
        reason: str = "",
        **extra: object,
    ) -> None:
        row: dict = {
            "ts": _now_iso(),
            "url": url,
            "scope": scope,
            "action": action,
            "status": status,
            "bytes": bytes_,
            "truncated": truncated,
            "reason": reason,
        }
        row.update(extra)
        self.rows.append(row)


def log_skip(audit: AuditLog, url: str, reason: str, *, scope: str = "out") -> None:
    """记一行 skip 审计（候选被门禁拒绝，未发请求）。"""
    audit.add(url=url, scope=scope, action="skip", status=None, bytes_=0,
              truncated=False, reason=reason)


class _RedirectBlocker(urllib.request.HTTPRedirectHandler):
    """拦截一切重定向：redirect_request 返回 None → 上层抛 HTTPError，手动跟随。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _is_timeout(exc: object) -> bool:
    if isinstance(exc, urllib.error.URLError):
        return _is_timeout(exc.reason)
    return isinstance(exc, TimeoutError)  # 含 socket.timeout（3.10+ 同名）


class Fetcher:
    """串行限速 GET 客户端。按 host 维护请求间隔 ≥ 1/rps（含重定向每一跳）。"""

    def __init__(
        self,
        *,
        audit: AuditLog,
        rps: float = 2.0,
        max_file_bytes: int = 2 * 1024 * 1024,
        timeout: float = 15.0,
    ) -> None:
        self.audit = audit
        self.rps = float(rps)
        # v10.1 P2-7: throttle 原语提取为 engine/throttle.py 共享实现（reverify
        # 同源复用），本类保留既有行为：per-host 间隔 ≥ 1/rps（含重定向每一跳）。
        self._throttler = HostThrottle(rps=self.rps)
        self.max_file_bytes = int(max_file_bytes)
        self.timeout = float(timeout)
        # 禁用环境代理：urllib 默认读 http_proxy/https_proxy，会把出站引流到
        # 未审计路径；本工具不允许。
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _RedirectBlocker())

    def _throttle(self, host_key: str) -> None:
        self._throttler.throttle(host_key)

    def fetch(self, url: str, scope_gate, *, scope_label: str = "in") -> FetchOutcome:
        """GET 一个 URL；重定向逐跳手动跟随并逐跳过门。

        超时允许恰好 1 次重试；非 2xx/3xx 不重试，记 errors（由调用方从
        ``outcome.error`` 收集）。响应超过 max_file_bytes 截断并标 truncated。
        """
        outcome = FetchOutcome(url=url, final_url=url)
        current = url
        hops = 0
        while True:
            split = urllib.parse.urlsplit(current)
            if split.scheme not in ("http", "https") or not split.hostname:
                outcome.error = "unparsable_url"
                log_skip(self.audit, current, "unparsable_url", scope="out")
                return outcome
            if not scope_gate(current):
                # 每一跳都重新过门：首跳不在册 = out_of_scope，
                # 重定向跳不在册 = redirect_out_of_scope。
                reason = "redirect_out_of_scope" if hops else "out_of_scope"
                outcome.error = reason
                log_skip(self.audit, current, reason, scope="out")
                return outcome
            self._throttle(split.netloc.lower())

            request = urllib.request.Request(
                current, method="GET", headers={"User-Agent": USER_AGENT})
            status: int | None = None
            body = b""
            final_url = current
            redirect_location: str | None = None
            error: str | None = None
            attempt = 0
            while True:
                try:
                    with self.opener.open(request, timeout=self.timeout) as response:
                        status = int(response.getcode() or 0)
                        final_url = response.geturl() or current
                        body = response.read(self.max_file_bytes + 1)
                    break
                except urllib.error.HTTPError as exc:
                    code = int(exc.code)
                    status = code
                    if code in REDIRECT_CODES:
                        redirect_location = exc.headers.get("Location") or ""
                        error = "redirect"
                    else:
                        error = f"http_{code}"
                    exc.close()
                    break
                except urllib.error.URLError as exc:
                    if _is_timeout(exc) and attempt == 0:
                        attempt += 1
                        self.audit.add(url=current, scope=scope_label,
                                       action="fetch", status=None, bytes_=0,
                                       truncated=False, reason="timeout_retry")
                        continue
                    error = f"urlerror:{exc.reason}"
                    break
                except TimeoutError:
                    if attempt == 0:
                        attempt += 1
                        self.audit.add(url=current, scope=scope_label,
                                       action="fetch", status=None, bytes_=0,
                                       truncated=False, reason="timeout_retry")
                        continue
                    error = "timeout"
                    break
                except OSError as exc:  # URLError 已在上方捕获，这里兜连接层错误
                    error = f"oserror:{exc}"
                    break

            if error == "redirect":
                self.audit.add(url=current, scope=scope_label, action="fetch",
                               status=status, bytes_=0, truncated=False,
                               reason="redirect")
                if not redirect_location:
                    outcome.error = "redirect_no_location"
                    outcome.hops = hops
                    return outcome
                if hops >= MAX_REDIRECT_HOPS:
                    # 已跟随 5 跳后仍遇到重定向 → 放弃该链并记审计行。
                    outcome.error = "redirect_hop_limit"
                    outcome.hops = hops
                    log_skip(self.audit, current, "redirect_hop_limit",
                             scope=scope_label)
                    return outcome
                hops += 1
                current = urllib.parse.urljoin(current, redirect_location)
                outcome.redirect_chain.append(current)
                outcome.final_url = current
                continue

            outcome.hops = hops
            if error:
                outcome.error = error
                outcome.status = status
                self.audit.add(url=current, scope=scope_label, action="fetch",
                               status=status, bytes_=0, truncated=False,
                               reason=error, original_url=outcome.url,
                               final_url=final_url)
                return outcome

            truncated = len(body) > self.max_file_bytes
            if truncated:
                body = body[: self.max_file_bytes]
            outcome.status = status
            outcome.body = body
            outcome.truncated = truncated
            outcome.final_url = final_url
            self.audit.add(url=current, scope=scope_label, action="fetch",
                           status=status, bytes_=len(body), truncated=truncated,
                           reason="", original_url=outcome.url,
                           final_url=final_url)
            return outcome
