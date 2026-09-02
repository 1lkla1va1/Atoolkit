"""共享限速原语（v10.1 方案 §3.2 / Gate-A P2-7）。

从 ``engine/recon/fetch.py`` 的 ``_throttle`` 逻辑原样提取：按 host 维护
单调时钟上的最近请求时间，保证相邻请求间隔 ≥ 1/rps。recon 与
reverify 双方 import 同一实现，禁止平行造第二套限速。
"""
from __future__ import annotations

import time


class HostThrottle:
    """Per-host serial rate limiter: gap between same-host calls ≥ 1/rps."""

    def __init__(self, *, rps: float = 2.0) -> None:
        self.rps = float(rps)
        self._min_interval = (1.0 / self.rps) if self.rps > 0 else 0.0
        self._last_request: dict[str, float] = {}

    def throttle(self, host_key: str, *, now: float | None = None) -> None:
        """Block until ``host_key`` may be hit again; injectable clock for tests."""
        current = time.monotonic() if now is None else float(now)
        last = self._last_request.get(host_key)
        if last is not None and self._min_interval > 0:
            wait = self._min_interval - (current - last)
            if wait > 0:
                if now is None:
                    time.sleep(wait)
                    current = time.monotonic()
                else:
                    current = current + wait
        self._last_request[host_key] = current


__all__ = ["HostThrottle"]
