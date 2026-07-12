# Changelog

## 8.7.0 - 2026-07-12

- Finding 统一为 root/impact/chain 证明合同；链式假设不再进入 accepted、严重度或 benchmark。
- 新增类级证据门、机器断言与 Skill Mode 离线验证 CLI；Guardian 拒绝/复验失败会回滚 Coverage positive。
- Coverage Cell 升级为 `METHOD /path :: param × vuln_class`，修复多参数、GET/POST、漏洞类串证据。
- Benchmark 只消费 accepted + proof-confirmed root finding；修复 method/params/roles 丢失、缺字段通配和 Ledger 造分。
- 新高价值 root cause 优先于旧 finding 扩散；纯文本 SPREAD 不再获得深度分，无进展 chain Intent 自动让出队列。
- Legacy Skill Mode facts/negatives 改为未验证迁移并进入复验队列；补强 host scope、会话路径、文件权限、重定向与进程清理。
- 旧 `report_*.md` 降为不计分 legacy candidate；授权类 Finding 新增公开性/访问预期证据门，匿名 200 与公众内容不能再定性为未授权。

## 8.6.1 - 2026-07-10

- 统一 BusinessGraph、Scheduler、CognitiveState、CoverageLedger 的 `METHOD /path` Surface 身份。
- 恢复 `surface_budget` 为 Surface 数语义，`0` 表示不限制。
- 修复 Intent 的 claimed 悬空、三次 deferred、Fact 归因和结构化结果持久化。
- 修复默认 `sess-*` SID 导致的 Blackboard 跨 Run 写回失败。
- Fact 重编号时同步修正 Intent `source_fact_id`。
- 深阴性支持 method-aware 继承，并在动态发现 Surface 入矩阵后重新应用。
- `domains_covered` 和 `surface_index` 改为 canonical、累计、可驱动下轮域调度的权威状态。
- Engine Mode 升级为加载 `核心技能文件.v3.md`，SKILL 版本升级为 8.6.1。
- `--resume` 可迁移读取旧 `runs/<sid>` 会话；project slug 增加路径安全清洗。
- 新增行为级产品闭环回归测试和完整验收方案。
