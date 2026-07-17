# Changelog

## 8.12.0 - 2026-07-17

- Engine live+Recon 默认执行 sibling Planning/Attack 两阶段：Planning 固定无目标网络，Attack 只消费 Host 校验和冻结的 threat cells；schema-4 manifest 绑定 parent authority manifest/session/hash。
- 新增有界、no-follow Recon snapshot 与稳定秘密/PII 脱敏；Planning 输入、Feature/Threat 输出和 Canonical 报告不再复制原始 Cookie、Authorization、API Key、Token、手机号或邮箱。
- Threat plan 增加 discovery adequacy、frozen path scope 与 identity requirement；至少覆盖代码/资源和导航/运行两组证据，同源跨模块路径不能自动扩大当前 Run。
- `CognitiveState.seed_threat_cells()` 精确按 compiler row 建格，Threat Mode 不再回退到 endpoint × 默认漏洞类矩阵；运行中新发现只进入下一 Run backlog/Intent。
- 新增 host-owned `identity-readiness.json`：以 credential hash 判断独立身份；重复 Cookie 不算 peer pair，身份/测试对象不足的 threat 保持 open，不能关闭为安全阴性。
- CSRF 改用 `cross_site_state_change` 专用证明合同，强制 before/cross-site/after、不同 Origin、受害者 Cookie 和状态 marker/delta；缺 token 或 token 暴露现象不能进入正式 Finding。
- 多身份原始 header 延迟到 Planning 完成后写入权限收紧的 Attack `identities.json`；readiness 与 Resume 按指纹复算，避免“Host 认为双身份就绪、模型实际拿不到身份”的假就绪。
- Attack manifest 逐个绑定晋升后的 Recon snapshot，终态递归验证 Planning parent artifact；CSRF 另要求可执行跨站发起载体，阻断手工伪造 Origin/Cookie 的假 PoC。
- 明确 Resume 边界：仅允许 finalizer 尚未开始的崩溃恢复；存在 finalization journal 的 sid 已冻结，继续测试必须新开 sid，避免新状态伪装成已锚定快照。
- 新增 v8.12 两阶段 authority、身份去重、scope/adequacy、CSRF 因果门与报告脱敏回归测试；保留显式 legacy/dry-run 兼容并标 degraded。

## 8.11.1 - 2026-07-17

- Patch 版本号 bump 至 8.11.1（version.py 与 SKILL.md frontmatter 同步）。

## 8.11.0 - 2026-07-17

- 新增结构化 `feature-graph.json` / `threat-model.json` 校验与编译器：模型声明业务不变量和可观察突破，机器只把经 inventory/证据校验的 threat 编译为精确 cell；risk tag 降为知识路由。
- 六类 discovery channel 必须绑定 run 内物理证据，resolved endpoint 必须归属 feature；无 threat 的 feature 必须说明理由，target method/param/role 必须与 inventory 一致。
- Direct runtime 支持 threat plan init、observation 的 feature/threat 强绑定、计划漂移检测和 `threat-coverage.json`；旧 planner 显式标为 degraded 且永不 report-ready。
- Wrapped Skill 在 agent 启动前验证 threat artifacts、冻结编译后的 authority run plan；缺少威胁计划时 CLI 仅允许显式 `--legacy-risk-plan` 降级运行。
- Manifest schema 3 冻结 provider/model/adapter 的安全 allowlist、planning mode/artifact hash 与 Canonical 报告要求；Engine v8.11 明确记录仍为 legacy risk 计划。
- Threat Mode Finding 强制绑定 `feature_point.feature_id` 与 `claim.threat_id`；closure gate 重编译计划并核对 frozen plan、ledger、threat coverage 和 Finding 证据映射。
- Shared finalizer 独占报告生成权：完整闭合生成 `final_report.md`，未闭合已证结果生成 `draft_report.md`，无效运行移除两者；正式报告哈希进入 summary、receipt 和 delivery 验证。
- 新增 v8.11 威胁计划、provenance、wrapper freeze、串格防护、invalid/empty Canonical 收口测试，并保持 v8.8/v8.9 authority/finalizer 兼容。

## 8.10.0 - 2026-07-16

- 新增 Direct/QoderWork diagnostic `engine.skill_runtime`，提供 init/observe/checkpoint，按 append-only observation 确定性归并多 agent 状态；不伪造 authority、不改 ProjectState。
- Planner 改为显式风险与参数语义风险并集；每个非空参数独立保留 input-validation/injection，修复对象编号只测 IDOR 而漏注入维。
- 知识卡匹配接通单值 param、risk_tags 与 barrier_signals；当前 cell 只注入命中的紧凑卡提示。
- WAF、会话失效、对象不存在、空数据、角色缺失和格式未解析进入统一实验有效性门；向量数再多也不能闭成 not_vulnerable。
- Coverage ledger 对齐七态合同，`shallow_negative` / `exploring` 成为一等 open 状态，不再折叠为 not_tested 旁路标记。
- Canonical negative evidence envelope 与 Direct checkpoint 共用 barrier/precondition 语义；响应中明确 WAF/登录失效信号会 fail closed。
- 新增 `skill/runtime-hot-path.md`，修正验证码“立即停”与“先测流程绕过”的指令冲突，并要求每 phase/每 10 cell checkpoint。
- 修复 Direct 实测中暴露的 Markdown findings summary 与最终 score/report 分叉：Markdown 保持人类视图，最终报告仍只来自 canonical validation projection。

## 8.9.0 - 2026-07-14

- 修复真实 shop recon 暴露的 phantom GET、三元 URL、fetch body/FormData 参数和 auth-flow 角色错误；不确定 method 保持 unresolved，不再制造覆盖分母。
- 运行时 Cell 身份加入 asset 与精确 role，阻止一个子域/角色的 finding 或 negative 关闭其他子域/角色；普通文本 `SKIP` 不再形成 terminal not-applicable。
- Validator 对有/无 Finding 的所有 Run 统一执行 closure gate；新增 `incomplete_with_findings`，缺 ledger 的合法 Finding 不再把整轮伪装成完成。
- 无效 manifest/proof 不再污染项目真值；ProjectState 保留 singular param、多资产 scope，并使用幂等 revision/CAS 提交。
- 新增 symlink-safe `safe_io`、跨 Session manifest replay 防护、immutable project commit、receipt authority anchor 与独立 verify API。
- 新增带 lock/journal/CAS/恢复的 exactly-once finalizer；Engine 与外部 Wrapped Skill 共用，Direct Skill 明确降级为 untrusted diagnostic。
- 审核确认 POSIX 进程组不能约束 `setsid()` 后代；当前 Codex/wrapper 后端均 fail closed 为 diagnostic，不得改写跨 Run ProjectState，直到接入可证明静默的 cgroup/job/container 监督器。
- 精确预算门禁前移到任何 Cell 变更之前；ProjectState/manifest/receipt/commit 链增加硬链接拒绝、自哈希和可达链验证。
- live Codex backend 默认 fail closed；只有显式接受 unrestricted egress 才启动，并永不声称已做 pre-exec host/path enforcement。
- 新增显式 `--base-path` 与稳定 origin+namespace 项目命名；target 的 `/login/` 等入口路径不会被猜成业务根。
- 新增 legacy Run 保守迁移：旧报告只生成待复验 Intent/open inventory，永不自动升级为 proof-confirmed。

## 8.8.0 - 2026-07-13

- 新增原子、带 revision 的 `project_state.json`，统一跨 Run inventory、角色感知 coverage cell、root finding、negative、Intent 与 run history；旧 Blackboard 降为派生兼容视图。
- 后续 Run 可直接恢复项目业务面与精确未闭格；项目已全闭且无 pending Intent 时不调用模型，避免重复侦察与随机重测。
- Finding 采集改为有界、fail-closed：识别 canonical/legacy/suspicious 布局，重复 ID、畸形 JSON、超限与 legacy 包均显式报错，不再静默漏 ingest。
- 新增 manifest → validation → receipt 交付链：首次模型/网络动作前固化版本、源码、授权和指令指纹，收口绑定验证、覆盖、summary 与项目状态增量哈希。
- 相对 target 绑定 manifest 的 primary target；授权 scope 不再作为相对 URL 基址。空 Finding 默认 exit 2，仅在显式 `--allow-empty` 且 inventory/coverage/candidate 闭环时 exit 0。
- Scheduler/BusinessGraph 保留真实 METHOD/path、参数、角色和来源；Finding 指纹对数字/UUID/长十六进制对象 ID 保守模板化，不用标题或自由文本 invariant 去重。
- 根目录 `AGENTS.md` 成为 Codex 项目指令入口，`codex/AGENTS.md` 保留兼容副本；`--doctor` 只读诊断外部 `/src` 指向，不改用户全局配置。
- 新增 v8.8 fail-closed、跨 Run 真值和 runtime integration 回归测试。

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
