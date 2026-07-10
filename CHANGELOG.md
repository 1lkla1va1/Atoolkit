# Changelog

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
