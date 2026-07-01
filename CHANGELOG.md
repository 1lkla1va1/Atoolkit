# CHANGELOG · ai-src-toolkit

记录技能包的版本与后续变动。每次有意义的改动加一行（日期 · 改了什么 · 为什么）。

---

## v3.3 phase2 — 2026-06-30（知识卡接通 + list/detail 阳性闭格）

- 接通知识卡 live loop：`run_session` 启动加载 `knowledge/cards/*.json`，每轮按下一批 open cells 匹配并注入 `render_skill_hint()`；`negative_*.md` 阴性充分性从默认规则升级为按卡提高门槛。
- `negative_*.md` 解析扩展 `evidence_types` / `identities` / `roles`，让知识卡的证据类型、多身份、角色要求能真实参与闭格判定。
- 删除核心技能文件里的外部 skill 死链，改为“声明方向 → 外壳按 endpoint/surface/参数等匹配知识卡注入提示”，并重生成 `codex/AGENTS.md`。
- 修复 list/detail 报告闭格缺口：不改全局 `_norm_path`，仅对带 evidence 的 `positive` 报告启用唯一 sibling fallback，避免 accepted 报告因 `/api/my-bugs` 与 `/api/my-bugs/{id}` 分行而无法闭格；NEG/SKIP 不放宽。
- 自检新增 I 段与 C2 段，覆盖知识卡提示注入、卡增强 negative_sufficiency、list/detail 阳性 fallback 与 NEG 不 fallback。

---

## fix — 2026-06-27（F1 · 采证读盘效率）

修复审计报告 F1（`design/审计报告_效率与回归.md`）：`harvest_evidence` 每轮把工作目录里每个文件全量读盘、且每轮跑两次，成本随 recon 文件大小×轮数线性膨胀。

- `harvest_evidence`：仅对 `.md` 候选 `read_text`，其它文件（大 JS bundle / `.http` 原始包）只记名不读。
- 新增 `count_evidence_files`：每轮「跑模型前」的 `prev` 进展基线改为只数文件不读内容，省掉一次全量 harvest。
- 抽出模块级 `_SETUP_FILES` 单一真相（harvest 与 count 共用，免漂移）。
- 自检新增 F 段：探针实测「4 文件目录含两个 500KB 非 .md，harvest 仅读 308 字节」，焊死大文件不被全量读 + prev 只数不读；A–E 段全绿无回归。

---

## docs — 2026-06-26（迭代审计：效率与回归）

对 v2.0 → v2.7 迭代做严格审计，结论与修复计划归档 `design/审计报告_效率与回归.md`。

- **能力无退化**：矩阵广度 / 断点续测 / 中断抢救 / feature 纵深为净增益，三个自检全绿。
- **发现 6 条**：F1 `harvest_evidence` 每轮把每个文件全量读两遍（随 recon 文件线性膨胀，可修）；F2 `verify_id_tamper` 对路径段 ID 不替换、且被 mock 掩盖（自检照样绿）；F3 熔断收口清零 `turn` 污染 `--resume`；F4 矩阵全量重注入 × 不首洞即停 = 广度换 token 的设计性取舍（需知情）；F5 `finalize` 死分支；F6 中断 `end` 事件 status 与返回值不齐 + adapter 注释漂移。
- **独立复核（对抗式 agent）**：6 条里 5 条定性准确；**F2 下调严重度**——`verify_id_tamper` 路径段本就支持（自检传了错误入参 `'orders/'` + mock 掩盖才显得哑火），且 `run.py` 未接线→零线上影响，**不重写正则**只修自检。F4 确认设计取舍非 bug、F5 只删死分支勿改语义。
- **定稿修复子集（按 ROI）**：F1（采证延迟读盘）必做 → F3（熔断 turn 一致性，唯一真状态 bug）必做 → F5/F6 零风险顺手 → F2 仅修自检 → F4 仅文档。**本条只归档方案，代码修复见下一条。**

---

## docs — 2026-06-25（opencode 集成）

新增**形态 B′ · opencode**：opencode 无 `SKILL.md` 技能系统，但原生读 `AGENTS.md` + 自定义命令，走与 Codex 同一条路。

- 新增 `opencode/USAGE.md`（安装三步 + 与 Codex 差异表 + 最小验收）与 `opencode/opencode.json.example`（`permission` 硬约束地板 + `instructions` + `model`）。
- **复用** `codex/AGENTS.md` 与 `codex/prompts/src.md`（`src.md` 已含 `$ARGUMENTS`，opencode 命令格式直接兼容），不另造副本，保持单一真相。
- 关键差异写明：opencode **没有 Codex 沙箱**，硬约束地板换成 opencode 自己的 `permission`（bash=ask）；「只打授权目标」仍需外壳/出站代理收口。
- README 三形态表加 B′ 行 + 安装节加「B′ · opencode」小节 + 目录地图补 `opencode/`。

---

## v2.7 — 2026-06-25

**可观测性 + 抗中断 + 断点续测**（engine 三处增量，模型/核心技能文件零改动）：

- **事件日志（零 token）**：`orchestrator._log_event` 每轮把 `start/turn/halt/interrupt/end` 事件 append 进 `runs/<sid>/events.jsonl`。纯磁盘，**永不进 `assemble_prompt`** → 对 token 与上下文冗余零影响；补上「做了哪些/从哪轮中断/收口到哪」原先只 print 不落盘的盲区。`events.jsonl` 已加入 `harvest_evidence` 的 SETUP 排除集，不被当证据污染文件计数。
- **中断抢救**：`adapter.run()` 流式包 `try/except`。网络波动/适配器异常断流时，flush 已抓文本 → 采证 → 存盘 → 记 `interrupt` → 走 `_conclude` 把**断前已落盘的报告**过一遍 Guardian，返回 `status="interrupted"`（区别于 error）。已证报告不再因半轮崩溃蒸发。
- **断点续测**：`CognitiveState.load` + `run_session(resume=True)` + `run.py --resume`。载回 `state.json`，`seed_matrix` 幂等保留已闭格，从 `state.turn+1` 续，注入「已闭 X/Y 格，勿重测」指令。
- 自检新增 E 段（`python3 engine/orchestrator.py`）：覆盖事件日志落盘+不污染证据、中断抢救已证报告不丢、续测承接覆盖度三条。

---

## docs — 2026-06-25

重写 `README.md`：以**三种使用形态**（A·ZCode/Claude Code 技能 / B·Codex / C·纯 CLI）为主线，给出各自的安装步骤、会话框触发方式与一次会话标准流程。让"装到哪个 IDE、在会话框怎么调用"一目了然。

---

## v2.6 — 2026-06-24

首次接触真实授权靶场（linglongsec SRC 平台）逼出的改动：**`run.py` 支持 Bearer 鉴权**。

- 真实靶场用 `Authorization: Bearer <JWT>`，原 `run.py` 只接 `--cookie`。新增 `--bearer`（会话凭据）与 `--auth-scheme {cookie,bearer}`（复验身份凭据注入方式）。
- 复验身份按 scheme 构造 `{"Authorization": "Bearer …"}` 或 `{"Cookie": …}`，对接 verify.py 的 AUTH_HEADERS 剥离。
- 实测验证 NEED_INPUT 协议生效：靶场 JWT 为 15min 时效 access token，过期即 `401 Token has expired`，外壳停手要新凭据（不伪造、不自登）。
- 实测验证 L8 越界-host 拦截：报告 host 不在授权列表 → rejected（dry-run 对真 target 复现）。
- 已从靶场 JS 块挖出接口面（越权重点）：get-users/sub-users/approve-user/update-bug-status/system-log/addresses/my-bugs/user-info…

> 待新鲜 token 到位即可对 §9 九条清单实跑。建议提供两个账号 token 以做 verify_idor 水平越权复验。

---

## v2.5 — 2026-06-24

入口脚本：**`run.py`** —— 一条命令把 engine 三件套 + Codex 适配器接成可跑会话。

- 填 `--target/--authz/--cookie` 即起会话；`--identity`+`--victim-marker` 开确定性复验；`--model` 换模型。
- `--dry-run` 用 MockAdapter 不接模型/网络，自检接线（已通过：现象→合格报告→VULN_FOUND→Guardian P1）。
- 只做接线无新逻辑；适配器选择是唯一与模型耦合处（CodexAdapter，换运行时改 1 处）。
- 修：`harvest_evidence` 排除会话输入文件（authz.md/cookies.txt/state.json）不计入证据。
- README 补 run.py 与「模式 B 一条命令」快速开始。

> 至此模式 B 端到端可跑：`python3 run.py …` → 拼装→Codex 执行→危险拦截→证据→Guardian 质检→确定性复验→裁定。
> 剩最后一步：接真实 Codex 对授权靶场跑一遍，对照落地方案 §9 九条验收清单打勾。

---

## v2.4 — 2026-06-24

确定性验证层：**`engine/verify.py`** —— 把"声称的洞"重放证成"已证明的洞"。

- `verify_idor`（换 owner/attacker/guest 多身份重放）、`verify_id_tamper`（遍历对象ID 3-5个）；三态 confirmed/refuted/inconclusive。
- `extract_poc()` 从报告代码块抽 curl / 原始 HTTP 包直接复验，无需人转写。
- 安全红线硬编码：只对授权 host 重放；默认仅幂等方法，非幂等需 allow_mutating（不为验证而下单/改数据）。
- 修复 with_identity 认证头剥离 bug（空 auth=真匿名，安全端点不再误判 confirmed）。
- 接入 orchestrator：`run_session(..., verify_fn=...)` 对 accepted 报告自动复验 → `verified` 字段。
  「已证明的洞 = Guardian accepted 且 verify confirmed」。
- 自检通过（mock transport：有漏洞 confirmed / 安全 inconclusive / 越权 host 拦截）。
- 正式写入落地方案 §6.5；README 补 `verify.py`。

> engine/ 三件套(orchestrator + enforce + verify)齐活，模式 B 主干完整：拼装→执行→拦截→质检→复验→裁定。

---

## v2.3 — 2026-06-24

外壳闭环：**`engine/orchestrator.py` — 模型无关编排 Loop（可运行）**。

- 串起四件套：`ModelAdapter`(接缝) + `enforce`(硬约束) + `CognitiveState`(每轮落盘/重注入) + prompt 拼装。
- 实现：流式 + 危险命令实时拦截、证据采集、状态标记解析、`_conclude()` 用 Guardian 质检 + `finalize()` 按物理证据裁定终态、20min 切向、超轮数熔断重启。
- 内置 `MockAdapter`，`python3 engine/orchestrator.py` 无需真实模型端到端跑通：turn0 现象(无报告) → turn1 合格越权报告 + VULN_FOUND → Guardian P1 accepted → 终态 vuln_found。
- 落地方案 §3 标注已落地；README 目录树补 `orchestrator.py`。
- 待办「补 orchestrator.py 最小可跑版」✅ 完成。模式 B 现已闭环（换 `MockAdapter`→`CodexAdapter` 即接真实模型）。

---

## v2.2 — 2026-06-24

落地外壳首块代码：**`engine/enforce.py` — Guardian 八级报告质检门**（借鉴 TianTi Guardian）。

- 把 v2 软约束代码化为 8 级短路检测（accepted/demoted/rejected），`python3 engine/enforce.py` 自检通过（L1拒/L3降/L5拒/L7降/L8过）。
- **demoted 不丢弃**：降级留档可重验升级，防误杀真洞。
- 同文件提供 `hits_danger()` / `is_authorized_host()` / `finalize()` 等 §5 原语。
- 正式写入 `design/AI_SRC落地实施方案.md` §5.1；README 目录树新增 `engine/`。
- 待办勾掉一项：`enforce.py` Guardian 已落地（`orchestrator.py` 仍待补）。

---

## v2.1 — 2026-06-24

追加第 8 份材料：**《TianTi — 客户端漏洞挖掘 Agent 的设计与实践》（w1th0ut，2025 HackProve 冠军）**，灰盒/客户端视角，与既有 7 份的 Web/SRC 黑盒视角强互补。

- 知识库更新：125→**161 节点 / 134→187 边 / 15→18 社区**（`knowledge-base/graphify-out/`、新语料入 `kb_sources/`、原件 pptx+md 入 `raw-materials/`）。
- 新增跨文档桥接（图谱自动连边）：
  - `Guardian 八级质量门` ≈ `七问验证门` + `垃圾洞清单`
  - `现象→漏洞认知分界` ≈ `现象不是漏洞漏洞是结果` ≈ `状态码 200≠漏洞`（聚成「现象与结果的分界」社区）
  - `共享状态黑板` ≈ `认知状态架构` + `不信任 LLM 工作记忆`（聚成「黑板架构与认知状态」社区）
  - `确定性规则>Prompt祈祷` ≈ `外部验证优先于自检` + `约束维度`
  - `Reflection 陷阱` ≈ `谁来审核审核者`
- 新增独立概念簇：客户端十维攻击面、三原语(Fact/Intent/Hint)、Stigmergy 间接协同、元认知五框架、3 个实战案例(0-click/Electron IPC/1-click RCE)。

---

## v2.0 — 2026-06-24

打包成型，落位 `/Users/1lk/workspace/20-ai/mine/ai-src-toolkit/`。

- **知识库**：6 份材料整合为知识图谱（125 节点 / 134 边 / 15 社区）→ `knowledge-base/graphify-out/`。
- **设计文档**：`AI_SRC挖掘设计思路.md`（理论骨架）、`AI_SRC落地实施方案.md`（模型无关落地 + 9 条验收清单）、`评审导览.md`。
- **核心技能文件 v2**：基于文章/知识库审核现行版，6 处优化（详见 `skill/核心技能文件.审核对照.md`）：
  - ① P1 垃圾洞清单去逐条"除非"软例外（误报反升的血泪教训）
  - ② 补会话 50 轮熔断重启
  - ③ 硬约束打 ⚙ 标记 = 外壳强制（模型无关关键）
  - ④ 速查卡补 3 把激活钥匙 + 决策树补"翻 JS 找隐藏接口"
  - ⑤ 补认知状态对象衔接
  - ⑥ 灵魂金句补"模式匹配 ≠ 因果证明"
- **Codex 集成**：`AGENTS.md`（由 v2 生成）、`/src` 命令、`config.toml.example`、`codex_adapter.py`、`USAGE.md`、`regen_agents.sh`。

### 待办 / 下一步（评审后推进）
- [ ] 评审表决 6 项议题（见 `design/评审导览.md` §4）。
- [ ] 补 `orchestrator.py` 最小可跑版（模式 B 心脏）。
- [ ] 认知状态对象 schema 与现有 `low_priv_*.json` 证据格式打通。
- [ ] host 白名单出站代理（把"只打授权目标"落到网络层）。

---

## v1.x — 既有

- `skill/核心技能文件.md`：线上现行版（边界 + 报告标准，150 行）。
