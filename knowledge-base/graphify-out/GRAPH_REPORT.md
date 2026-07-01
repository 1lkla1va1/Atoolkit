# Graph Report - .  (2026-06-24)

## Corpus Check
- Corpus is ~6,151 words - fits in a single context window. You may not need a graph.

## Summary
- 161 nodes · 187 edges · 18 communities (13 shown, 5 thin omitted)
- Extraction: 72% EXTRACTED · 28% INFERRED · 1% AMBIGUOUS · INFERRED: 52 edges (avg confidence: 0.81)
- Token cost: 18,000 input · 4,200 output

## Community Hubs (Navigation)
- [[_COMMUNITY_核心技能文件与多层验证|核心技能文件与多层验证]]
- [[_COMMUNITY_客户端灰盒挖掘与实战案例|客户端灰盒挖掘与实战案例]]
- [[_COMMUNITY_边界哲学与人控建模|边界哲学与人控建模]]
- [[_COMMUNITY_模型能力形成与约束对齐|模型能力形成与约束对齐]]
- [[_COMMUNITY_元认知与多视角发散|元认知与多视角发散]]
- [[_COMMUNITY_AI审计难点与链上分析|AI审计难点与链上分析]]
- [[_COMMUNITY_Skill路由与定位|Skill路由与定位]]
- [[_COMMUNITY_Loop失效与边界标准|Loop失效与边界标准]]
- [[_COMMUNITY_长程执行与攻击链续接|长程执行与攻击链续接]]
- [[_COMMUNITY_黑板架构与认知状态|黑板架构与认知状态]]
- [[_COMMUNITY_现象与结果的分界|现象与结果的分界]]
- [[_COMMUNITY_模型选型方法论|模型选型方法论]]
- [[_COMMUNITY_对照实验与模型横评|对照实验与模型横评]]
- [[_COMMUNITY_越狱与上下文重构|越狱与上下文重构]]
- [[_COMMUNITY_安全防护机制|安全防护机制]]
- [[_COMMUNITY_业务逻辑漏洞特征|业务逻辑漏洞特征]]
- [[_COMMUNITY_调度与并发控制|调度与并发控制]]
- [[_COMMUNITY_防御进攻对称性|防御进攻对称性]]

## God Nodes (most connected - your core abstractions)
1. `核心技能文件实例` - 8 edges
2. `核心技能文件六大设计准则` - 7 edges
3. `四层能力形成路径` - 6 edges
4. `现象不是漏洞漏洞是结果` - 6 edges
5. `决策树而非固定流程` - 6 edges
6. `防遗忘机制速查卡` - 6 edges
7. `TianTi 客户端漏洞挖掘Agent` - 6 edges
8. `确定性规则>Prompt祈祷` - 6 edges
9. `元认知Metacognition(发散补盲)` - 6 edges
10. `AI审计四大难点` - 5 edges

## Surprising Connections (you probably didn't know these)
- `多模型共识验证` --semantically_similar_to--> `多层验证架构`  [INFERRED] [semantically similar]
  kb_sources/2026_AI驱动的Web3安全攻防实践.txt → kb_sources/如何利用AI获得六位数的漏洞赏金？.article.txt
- `约束引导模型而非自由生成` --semantically_similar_to--> `约束维度压缩输出空间`  [INFERRED] [semantically similar]
  kb_sources/2026_AI驱动的Web3安全攻防实践.txt → kb_sources/也许我们不需要Skill.article.txt
- `防遗忘机制速查卡` --semantically_similar_to--> `不信任LLM工作记忆让系统知道`  [INFERRED] [semantically similar]
  kb_sources/AI辅助漏洞挖掘系统设计指南.txt → kb_sources/2026_AI驱动的Web3安全攻防实践.txt
- `现象不是漏洞漏洞是结果` --semantically_similar_to--> `状态码200不等于业务漏洞`  [INFERRED] [semantically similar]
  kb_sources/AI辅助漏洞挖掘系统设计指南.txt → kb_sources/AI加速逻辑漏洞测试.txt
- `SKILL兜底与激活而非限制` --semantically_similar_to--> `Skill是钥匙杠杆不是咒语`  [INFERRED] [semantically similar]
  kb_sources/AI加速逻辑漏洞测试.txt → kb_sources/也许我们不需要Skill.article.txt

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Web3四层审计架构** — web3_layer1_ast, web3_layer2_rag, web3_layer3_multimodel, web3_layer4_llm_judge [EXTRACTED 1.00]
- **四层能力形成路径** — dongsec_layer1_pretrain_know, dongsec_layer2_sft_distill_understand, dongsec_layer3_verifiable_rl_trial, dongsec_layer4_agentic_action [EXTRACTED 1.00]
- **核心技能文件六大准则** — design_garbage_hole_list, design_phenomenon_not_vuln, design_anti_forget_cheatsheet, design_seven_question_gate, design_decision_tree, design_dont_teach_shark_swim [EXTRACTED 1.00]
- **三原语数据模型** — tianti_fact, tianti_intent, tianti_hint [EXTRACTED 1.00]
- **四类认知任务** — tianti_metacognition, tianti_four_cognitive_tasks, tianti_converge_diverge_separation [EXTRACTED 1.00]
- **三层黑板架构** — tianti_blackboard, tianti_dispatcher_single_writer, tianti_stigmergy [EXTRACTED 1.00]

## Communities (18 total, 5 thin omitted)

### Community 0 - "核心技能文件与多层验证"
Cohesion: 0.11
Nodes (24): 约束的强制执行解析器拦截器计时器, 多层验证架构, 超50轮强制总结重启, 谁来审核审核者, 核心技能文件实例, 报告格式要求, 终止协议状态标记, 防遗忘机制速查卡 (+16 more)

### Community 1 - "客户端灰盒挖掘与实战案例"
Cohesion: 0.12
Nodes (17): 黑盒探索驱动vs灰盒覆盖驱动, 案例1 文件传输0-click RCE(路径遍历+LaunchAgent), 案例3 AI编程客户端1-click RCE(CORS*+零认证+MCP注入), 案例2 Electron IPC命令注入, TianTi 客户端漏洞挖掘Agent, 覆盖驱动(瓶颈是认知不够), 2025 HackProve冠军系统, 多Agent协同三范式(DAG/Swarm/Handoff) (+9 more)

### Community 2 - "边界哲学与人控建模"
Cohesion: 0.13
Nodes (15): AI是能力放大器不是替代品, 人提供方向AI提供执行, 持续迭代核心技能文件, 核心技能文件, 不教鲨鱼游泳payload下沉模型, 铁律危险操作禁令, 核心技能文件六大设计准则, 理解业务建模前置 (+7 more)

### Community 3 - "模型能力形成与约束对齐"
Cohesion: 0.14
Nodes (15): 不束缚AI只设边界, 信任判断力不信任自制力与报告标准, 底层能力迁移钢琴学吉他类比, 四层能力形成路径, Kimi K2.5 PARL/Agent Swarm, 第一层预训练-知道, 第二层SFT专家蒸馏-理解, 第三层可验证环境RL-试错 (+7 more)

### Community 4 - "元认知与多视角发散"
Cohesion: 0.13
Nodes (15): 收敛与发散必须分离, 五个异构创造性框架, 四类认知任务(Bootstrap/Reason/Explore/Metacog), 元认知四要素可执行契约, 元认知Metacognition(发散补盲), code-to-code语义检索, 多模型共识验证, 两阶段输出CoT解耦 (+7 more)

### Community 5 - "AI审计难点与链上分析"
Cohesion: 0.14
Nodes (14): AI驱动的代码审计, 注意力稀释, LLM单次生成审计惰性, 上下文窗口是有限资源, 从喂更多到喂更准, AI审计四大难点, 垃圾进垃圾出(GIGO), 信息分层注意力稀缺 (+6 more)

### Community 6 - "Skill路由与定位"
Cohesion: 0.18
Nodes (12): 决策树末尾SKILL路由, 决策树而非固定流程, BM25(FTS5) SKILL路由, SKILL兜底与激活而非限制, SkillsBench/SWE-Skills-Bench/SkillReducer, 决策路由型Skill案例, 也许我们不需要Skill, 路由维度激活正确知识抽屉 (+4 more)

### Community 7 - "Loop失效与边界标准"
Cohesion: 0.20
Nodes (10): AI SRC系统六位数赏金, 外部验证优先于自检, 实战迭代飞轮效应, Loop观察推理行动反馈, Loop三种失效模式, 六大设计原则, 20分钟无进展换方向, 雪崩效应小错误传播放大 (+2 more)

### Community 8 - "长程执行与攻击链续接"
Cohesion: 0.20
Nodes (10): 真实瓶颈是长程自主执行, Cyber Range全新场景评估, CTF训练数据污染, 长链路逻辑漏洞, chain_id跨任务长攻击链续接, Fact客观发现, Hint人类判断, Intent探索方向 (+2 more)

### Community 9 - "黑板架构与认知状态"
Cohesion: 0.24
Nodes (10): 黑板(唯一记忆存储), Dispatcher唯一写入方(架构红线), 协议层(Dispatcher不直连DB走HTTP API), 共享状态架构(外部化工作记忆), SQLite WAL+幂等迁移, Stigmergy间接协同(只读写黑板), 三层架构(Server/Dispatcher/Worker), 认知状态架构 (+2 more)

### Community 10 - "现象与结果的分界"
Cohesion: 0.60
Nodes (5): 模式匹配vs因果证明, 现象不是漏洞漏洞是结果, 状态码200不等于业务漏洞, 现象→漏洞认知分界, 验证谓词(我做了X观察到Y)

### Community 11 - "模型选型方法论"
Cohesion: 0.67
Nodes (3): 最好的模型是伪命题, 按任务拆解而非全局押注选模型, XBOW

### Community 12 - "对照实验与模型横评"
Cohesion: 0.67
Nodes (3): 无业务建模对照实验, L2商城场景模型横评, redhaze.top靶场

## Ambiguous Edges - Review These
- `AI驱动链上攻击分析` → `案例3 AI编程客户端1-click RCE(CORS*+零认证+MCP注入)`  [AMBIGUOUS]
  kb_sources/客户端漏洞挖掘Agent设计与实践.md · relation: conceptually_related_to

## Knowledge Gaps
- **46 isolated node(s):** `概率采样而非穷尽检查`, `垃圾进垃圾出(GIGO)`, `无法自我验证`, `Layer4 LLM-as-Judge汇总+反思`, `code-to-code语义检索` (+41 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **5 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `AI驱动链上攻击分析` and `案例3 AI编程客户端1-click RCE(CORS*+零认证+MCP注入)`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **Why does `不束缚AI只设边界` connect `模型能力形成与约束对齐` to `现象与结果的分界`, `Loop失效与边界标准`?**
  _High betweenness centrality (0.212) - this node is a cross-community bridge._
- **Why does `决策树而非固定流程` connect `Skill路由与定位` to `核心技能文件与多层验证`, `边界哲学与人控建模`, `Loop失效与边界标准`?**
  _High betweenness centrality (0.178) - this node is a cross-community bridge._
- **Why does `约束引导模型而非自由生成` connect `模型能力形成与约束对齐` to `核心技能文件与多层验证`, `元认知与多视角发散`?**
  _High betweenness centrality (0.170) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `核心技能文件实例` (e.g. with `垃圾洞清单` and `现象不是漏洞漏洞是结果`) actually correct?**
  _`核心技能文件实例` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 4 inferred relationships involving `现象不是漏洞漏洞是结果` (e.g. with `模式匹配vs因果证明` and `核心技能文件实例`) actually correct?**
  _`现象不是漏洞漏洞是结果` has 4 INFERRED edges - model-reasoned connections that need verification._
- **Are the 3 inferred relationships involving `决策树而非固定流程` (e.g. with `BM25(FTS5) SKILL路由` and `决策路由型Skill案例`) actually correct?**
  _`决策树而非固定流程` has 3 INFERRED edges - model-reasoned connections that need verification._