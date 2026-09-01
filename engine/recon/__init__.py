"""Atoolkit v10.0 侦察输入自动化层（recon 采集器）。

只产原料，不做判断：采集器把种子页 / JS 快照 / 被动源历史 URL 落盘成
``engine.surface.bootstrap`` 可直接消费的 recon_dir 布局；风险标签、角色推断、
攻击面建模由 surface/bootstrap 与规划层负责，本包不碰。

安全边界（代码门禁，非提示词纪律）：
  - 每个发往目标侧的请求在 dispatch 前过注入的 scope 门（主动源 =
    ``host_policy.is_authorized_url``；被动源 = PASSIVE_HOSTS 白名单）；
  - 重定向禁止自动跟随，逐跳手动解析 + 逐跳过门；
  - 只发 GET、按 host 限速、大小/总量/页数上限；
  - 禁用环境代理（``ProxyHandler({})``），出站不引流到未审计路径。

入口：``collect_recon(seeds, authorized_scopes, out_dir, ...)``（见 collect.py）。
"""
from . import crawl as crawl_module
from . import emit as emit_module
from . import fetch as fetch_module
from . import passive as passive_module
from .collect import collect_recon
from .fetch import AuditLog, Fetcher, FetchOutcome

__all__ = [
    "AuditLog",
    "Fetcher",
    "FetchOutcome",
    "collect_recon",
    "crawl_module",
    "emit_module",
    "fetch_module",
    "passive_module",
]
