# Changelog

## 9.1.0 - 2026-07-20

- 新增 `--continue-from-run`：重算并校验 prior validation/attribution/agenda，将 diagnostic `continuation-input.json` 绑定进新 Run manifest；不伪造 containment，也不提升 ProjectState/submission authority。
- Cell identity 与 ProjectState 升至 v3/schema 3；exact vulnerability class 与语义家族分离，stored/reflected/DOM XSS、horizontal/vertical IDOR 不再串格，旧 schema cell 迁移为 stale 待复测。
- LOW_ROI 新增物理 `intuition-exploration.json` 双门；跨阶段输入阴性自动重开，并强制新 encoding family + strategy family。
- 敏感数据检测与脱敏 regex 解耦；captcha 在五类绕过方向耗尽前保持 recoverable。
- Finalizer authority 默认 false、无 scope 的 Finding 校验拒绝、unknown method 不再猜 GET；删除 legacy summary 死代码。
- 明确 proof 文件早已由 validator 全量 hash-bound，并新增替换 proof 后校验失败的回归证据。
- 新增 v9.1 完整性修复专项对抗测试；修复前基线和修复后全量套件均实际执行。

## 9.0.1 - 2026-07-20

- Engine 与 Direct CLI 启动前严格绑定当前 workspace `AGENTS.md` 到项目版本；`doctor` 可显式检查工作区漂移和外来 `/src`，避免“代码已升级、实际仍按旧提示手跑”。
- `run.py audit` 要求非空 inventory/coverage、真实持久化且可重算一致的 miss attribution/next-run agenda，并识别人工终态声明；凭据权限扫描扩展到整个 Run。
- Finding validator 的外部 `--output` 默认只写目标文件，不再隐式回写历史 Run；需要归因 sidecar 时必须在 Run 内输出或显式 `--write-sidecars`。
- Direct checkpoint 输出 proof-rejected 明细、proof repair 数量与 finalizer 保留产物违规，任何一项存在都禁止 `report_ready`。
- 增加 v9.0.1 实跑入口、空台账、审计投影、凭据权限、外部验证副作用与通用 Recon 解析回归。

## 9.0.0 - 2026-07-18

- 新增确定性 `miss-attribution.json`：逐一归因 frozen cell、unassigned inventory、unresolved method、dynamic backlog、proof rejection 与批次原子门连带阻断的 Finding；未知状态 fail closed，终结静默遗漏和虚假覆盖率。
- 新增 `next-run-agenda.json` 与 `v9_host_continuation`：trusted finalizer 在不完整 Run 中只提交续航任务，scheduler 可优先恢复有证据的新 discovery，但普通模型 Intent 仍不能绕过 inventory。
- 修复 v8.13 closure 失败即丢弃 backlog/Intent 的跨 Run 断链；后续阴性与 confirmed truth 冲突时改为 Finding/Fact 强制复验，不再静默覆盖。
- Manifest 升级 schema 5，冻结 outcome/submission contract；receipt 强制绑定归因与续航产物。
- 新增 `run.py audit` 历史 Run 只读审计，以及 `run.py submission` 提交资格验证；人工 Markdown、篡改报告、未脱敏报告或无 authority receipt 的报告均不可提交。
- 结构化 Finding 增加垃圾风险门：报错/500/类型混淆必须证明安全边界结果；凭据回显必须证明跨边界使用；单独限频/开放重定向等不得借散文升级。
- Shared finalizer 保持报告唯一写入权，输出 receipt-bound、稳定脱敏的 Canonical report 和 `submission_status.json`。
- 新增 v9 设计、反向审核、结果归因/续航/真值冲突/提交资格/旧 Run 审计回归测试。

## 8.13.0 - 2026-07-17

- 新增 Threat-driven Experiment Contract：逐项保留模型 `evidence_required`，并按身份、认证、交易、持久化输入、注入、SSRF、跳转和文件结果增加确定性最低深度；只约束 frozen threat 内实验，不恢复 endpoint × 漏洞类笛卡尔积。
- Engine Threat Mode 每轮接受 evidence-bound `EXECUTION_EVENT`，Host 以 create-only Run 事件、证据 SHA-256 和 authority hash chain 归并 `execution-contracts/progress/queue/backlog` 四个投影；文本“已测/full”不再计执行进展，接受后替换证据会在最终验证失败。
- 深阴性若仍缺 experiment obligation 会自动回退为 `shallow_negative`；空数据、对象不存在、会话失效、格式未解析、缺角色/挑战和 WAF 进入动态恢复义务，全部恢复证据满足后才确定性解除 active barrier，修复本轮用户枚举、balance records、reset token 与 use_points 的假阴性模式。
- Host 对 IDOR/BOLA 强制双身份与 ownership marker floor，不信任模型误写的 single identity；XSS/SSRF/文件义务改为记录成功或拒绝结果，避免把“必须利用成功”变成阴性闭格前提。
- 动态 queue 按 proof repair、可恢复 blocker、浅阴性、高价值未执行 threat 排序；accepted Finding 仍由原 proof contract 确立，Execution Event 不能直接写 terminal 结论。
- 新 endpoint/param 只进入 `execution-backlog.json` 且固定 `next_run_required`，不修改 v8.12 run plan 或当前 threat denominator。
- Direct/Qoder 新增 pre-network `skill_runtime preflight`，解决 fresh black-box 尚无 inventory 时无法先 init 的启动矛盾；`init/observe/checkpoint` 接入同一 execution contract，但继续固定 untrusted diagnostic。
- Final validation 重算 authority execution chain 和四个投影，检查物理 evidence、open contract 与 ledger 一致性；旧 Run 无 execution version 时保持 legacy 可读且不伪装为 v8.13 验证。
- 新增 v8.12 靶场 35.8% 得分、4 假阴性、11 未测、10/10 proof-invalid Finding 的离线审计，以及 v8.13 设计/反向审核/失败先行回归。

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
