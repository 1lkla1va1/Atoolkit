# AI + SRC 落地实施方案（模型无关）

> 目标：把这套打法**跑通成一个可重复运行的系统**，并且**换任何模型（Claude / GPT / DeepSeek / Qwen / Kimi…）都能用**。
> 配套：`核心技能文件.v2.md`（软约束）、`graphify-out/`（知识库）、`AI_SRC挖掘设计思路.md`（理论骨架）。
> 本文是给评审用的实施方案，含目录布局、模型适配接缝、编排 Loop 可运行骨架、外部强制层、验证层、分阶段路线、验收清单。

---

## 0. 第一性原理：什么叫"模型无关"

> **模型无关 = 把"硬约束 + 状态 + 验证"全部从模型里搬到模型外。模型越弱，外壳承担越多。**

文章给的依据（知识库社区 3/5/6/7）：
- 安全能力是通用 Agent 能力的投影，**没有专门的安全模型**——所以系统不该绑定某个模型的"安全特性"。
- 不同模型只有能力强弱之分（GPT-5.5 全线领先但贵 ~10×，DeepSeek/Qwen 便宜且差距不大）。
- 强模型靠自觉也能跑；**弱模型一定会忘规则、会幻觉洞、会伪完成**。要让"换任何模型都能跑"，唯一办法是**不依赖模型自觉**：
  - 软约束（边界/报告标准/路由）→ 放进核心技能文件，注入 prompt。
  - **硬约束（越界拦截、超时切向、无 PoC 拒收、危险命令拦截、终态裁定）→ 放进外壳代码，模型碰不到。**
  - 状态（认知快照）→ 外部维护，每轮重注入，不靠模型记忆。
  - 验证（PoC 重放）→ 确定性代码，不靠模型自我表扬。

**一句判据**：任何"模型可能忘 / 可能骗 / 后果严重"的规则，都不能只写在 prompt 里。

---

## 1. 系统四件套与职责边界

| 件 | 载体 | 是否与模型耦合 | 职责 |
|---|---|---|---|
| 核心技能文件 | `核心技能文件.v2.md`（文本） | ❌ 无关 | 软约束：边界 + 报告标准 + 决策树 |
| 路由 Skill 库 | HackSkills（文本，触发式） | ❌ 无关 | 激活攻击面灵感（钥匙，非流程） |
| **编排外壳** | 代码（Python） | ⚠️ 仅"模型适配层"耦合 | 拼装 prompt → 调模型 → 解析 → 强制 → 验证 → 状态 → 裁定 |
| 模型 | 任意 LLM/Agent 运行时 | ✅ 唯一可替换件 | 推理与工具调用 |

**关键**：耦合被收敛到**唯一一个接缝**——模型适配层（§2）。换模型 = 换一个适配器，外壳其余部分一行不动。

---

## 2. 模型适配层（唯一与模型耦合的接缝）

定义一个最小接口，任何模型/Agent 运行时实现它即可接入：

```python
# adapters/base.py
from typing import Iterator, Protocol

class ModelAdapter(Protocol):
    """唯一与具体模型耦合的地方。换模型只动这里。"""
    name: str
    def run(self, prompt: str, *, session_id: str) -> Iterator[str]:
        """输入拼装好的完整 prompt；流式吐出模型输出文本。
        运行时本身需具备：能执行 shell/curl（用于发包取证）、能流式返回。
        — 满足这两点的都能接：Claude/Codex/CC CLI、OpenAI/DeepSeek tool-calling 循环、
          Yakit Web Fuzzer AI、Memfit 等。外壳不关心内部怎么实现工具调用。
        """
        ...
```

实现示例（三类典型接法，按你手上资源选其一即可起步）：

```python
# adapters/cli_agent.py —— 包一个已有 Agent CLI（最省事，工具调用现成）
import subprocess
class CliAgentAdapter:
    def __init__(self, cmd, name): self.cmd, self.name = cmd, name   # 如 ["codex","exec"] / ["claude","-p"]
    def run(self, prompt, *, session_id):
        p = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              text=True, bufsize=1)
        p.stdin.write(prompt); p.stdin.close()
        for line in p.stdout: yield line

# adapters/openai_like.py —— 任意 OpenAI 兼容端点（DeepSeek/Qwen/Kimi/本地 vLLM 同一套）
import openai
class OpenAILikeAdapter:
    def __init__(self, base_url, api_key, model, name):
        self.client = openai.OpenAI(base_url=base_url, api_key=api_key)
        self.model, self.name = model, name
    def run(self, prompt, *, session_id):
        # 这里内置一个最小 tool-calling 循环（curl/shell 工具），略；流式 yield 文本
        ...
```

> 结论：**外壳对模型只有一个假设——"能接收 prompt、能执行 curl、能流式输出"**。这三点是所有主流 Agent 运行时的公约数，所以模型无关。

---

## 3. 编排 Loop（可运行骨架，外壳的心脏）

> ✅ **已落地为可运行实现：`engine/orchestrator.py`**（内置 `MockAdapter`，`python3 engine/orchestrator.py` 可无真实模型端到端跑一遍）。
> 含：流式 + 危险命令实时拦截、证据采集、`CognitiveState` 每轮落盘/重注入、状态标记解析、`_conclude()` 用 Guardian 质检 + `finalize()` 按物理证据裁定终态、20min 无进展切向、超轮数熔断重启。下方为其结构骨架。

```python
# orchestrator.py（结构骨架；完整实现见 engine/orchestrator.py）
import re, time, json, pathlib

STATUS_RE = re.compile(r'^(VULN_FOUND|LOW_ROI|NEED_INPUT|ERROR)\s*$', re.M)

def run_session(adapter, target, authz, core_skill_path, workdir,
                max_turns=50, no_progress_timeout=20*60):
    state = CognitiveState(target)                      # §6 外部维护
    workdir = pathlib.Path(workdir); workdir.mkdir(exist_ok=True)
    last_progress = time.time()
    for turn in range(max_turns):
        prompt = assemble_prompt(core_skill_path, authz, target, state)   # §4
        output = []
        for chunk in adapter.run(prompt, session_id=state.sid):
            output.append(chunk)
            # ⚙ 实时危险命令拦截（硬约束，不等模型自觉）
            if hits_danger(chunk):           # rm -rf / DROP TABLE / 越界host …
                kill_and_log(adapter, "DANGER_CMD"); return finalize(state, "ERROR")
        text = "".join(output)

        # ⚙ 外部强制层（§5）——纯代码判定，与模型无关
        evidence = harvest_evidence(workdir)              # 落盘的 curl/响应/报告
        if made_progress(text, evidence): last_progress = time.time()
        state.update(text, evidence)                      # 解析假设/已验证/TODO

        marker = STATUS_RE.search(text)
        if marker:                                        # 模型声明终态
            return finalize(state, marker.group(1), evidence)   # §5 十二条规则裁定

        # ⚙ 20min 无进展 → 注入换方向指令（不靠模型记 20 分钟）
        if time.time() - last_progress > no_progress_timeout:
            state.inject_directive("20min 无进展，立刻切换攻击面，重读速查卡")
            last_progress = time.time()

    # ⚙ 超 50 轮 → 强制总结 + 重启续测（防雪崩）
    summary = force_summarize(adapter, state)
    state.restart_with(summary)
    return finalize(state, "LOW_ROI", harvest_evidence(workdir))   # 或递归续测
```

`finalize` 落地"十二条决策规则"的核心几条（物理证据 > 声明）：

```python
def finalize(state, marker, evidence=None):
    valid = has_valid_report(evidence)     # P1/P2/P3 + 标题 + 正文≥200字 + 含 curl/HTTP
    if marker == "VULN_FOUND" and not valid: marker = "LOW_ROI"   # 声明却无报告→降级
    if marker in ("LOW_ROI","NEED_INPUT") and valid: marker = "VULN_FOUND"  # 有证据→升级
    if marker is None and valid: marker = "VULN_FOUND"            # 无标记有证据→补救
    return {"status": marker, "evidence": evidence, "state": state.snapshot()}
```

---

## 4. Prompt 拼装顺序（每轮重新拼，固定结构）

模型对**头尾**回忆率最高（Lost in the Middle）→ 约束放头尾，易变内容放中间：

```
[1] 授权文档           ← 头部：打消拒答，明确合法边界
[2] 核心技能文件 v2     ← 头部：垃圾洞清单/七问门置顶
[3] 目标信息 + 私有缺陷补充（按目标注入，非主文件）
[4] 认知状态对象（长会话才有；当前假设/已验证/TODO/已落盘证据）
[5] 触发式 Skill（仅当本轮声明了测试方向时按意图检索注入）
[6] 上一轮关键输出摘要（不灌全量历史）
[7] 速查卡再贴一遍      ← 尾部：抗遗忘
```

> 弱模型版本：[2][7] 加粗、缩短、必要时每轮都贴全；强模型版本可精简。**拼装逻辑不变，只调浓度**——这是模型无关的体现。

---

## 5. 外部强制层（纯代码清单，模型碰不到）

| 强制项 | 触发 | 动作 | 对应软约束 |
|---|---|---|---|
| 危险命令拦截 | `rm -rf` / `DROP TABLE` / 越界 host | 实时 kill + 记录 → ERROR | 铁律 |
| 授权范围校验 | 出站 host 不在白名单 | 拦截发包 | 铁律 / 越界即停 |
| 无 PoC 拒收 | "报告"无结构化 curl/HTTP | 拒绝入库 | 七问门 #2 |
| 垃圾洞关键词拦截 | 标题命中清单 | 拒绝入库 | 垃圾洞清单 |
| 20min 无进展计时器 | 无新有效请求 | 注入切向指令 | 速查卡 |
| 会话轮数熔断 | >50 轮 | 强制总结+重启 | 防遗忘 |
| 磁盘自循环 / 配额 | 写入读取子目录 / 临时目录超限 | 拦截 / 终止 | 安全防护 |
| 终态裁定 | 模型给标记 | 十二条规则，证据可翻案 | 终止协议 |

> 这一层是"换任何模型都能跑"的根本保证：模型再弱再幻觉，越界/伪完成/垃圾报告都被代码挡在外面。

### 5.1 Guardian 八级报告质检门（核心，实现见 `engine/enforce.py`）

借鉴 TianTi 客户端 Agent 的 Guardian 设计：**确定性规则 > Prompt 祈祷**——把核心技能文件 v2 的软约束（垃圾洞清单 / 七问门 / 报告格式 / 现象≠结果 / 物理证据>声明）翻译成**代码硬判定**。每份候选报告过八级**短路检测**（首个命中即返回），三种判定：

- **accepted** — 全过，进漏洞统计。
- **demoted** — 降级为 `phenomenon`（severity→info）。**不丢弃**，留档可重验升级（防误杀真洞）。
- **rejected** — 入库留痕，报告层过滤。

| 级 | 检测 | 命中 | 对应 v2 软约束 |
|---|---|---|---|
| L1 | 标题/类型命中垃圾洞清单（CORS/安全头/Self-XSS/SSL/版本号/限频/目录列举…；含"链/配合/RCE"则放行可链式利用） | **rejected** | 垃圾洞清单 |
| L2 | 结构不合格：severity∉{P1,P2,P3} / 缺标题 / 正文<200字 | **rejected** | 报告格式 |
| L3 | 无可执行 PoC（无 curl/HTTP/命令） | **demoted** | 七问门 #2 |
| L4 | 无落盘证据（证据目录空 / 报告无响应包） | **demoted** | 物理证据>声明 |
| L5 | 投机措辞（可能/疑似/理论上/might…） | **rejected** | 七问门 #4「可能不报」 |
| L6 | 假设/条件投机（如果…就/前提是…，且前提未实际发生） | **demoted** | 七问门 #3「需假设→不报」 |
| L7 | 只是现象：无结果动词（越权/读取/执行/提取/绕过/RCE…） | **demoted** | 灵魂金句 + 七问门 #5 |
| L8 | 授权 host 校验 + 全部通过 | **accepted** | 铁律 / 终极放行 |

调用：
```python
from engine.enforce import guardian_check, triage
v = guardian_check(report_md, evidence_dir="runs/sess-001",
                   authorized_hosts=["t.example"])
# v.result ∈ {accepted, demoted, rejected}；v.level 命中级别；v.reason 原因
# 批量分流（demoted/rejected 不丢弃，全部留档可重验）：
ledger = triage(reports, authorized_hosts=["t.example"])
```
自检：`python3 engine/enforce.py` 跑内置 5 个样例，应看到 L1拒 / L3降 / L5拒 / L7降 / L8过。
`enforce.py` 同时提供 §5 其它原语：`hits_danger()`（危险命令拦截）、`is_authorized_host()`（出站校验）、`finalize()`（终态十二条裁定，证据可翻案）。

> **demoted 不丢弃**是与一次性过滤的关键差别：降级的发现留在台账里，补到证据（如后续重放成功）即可重验升级回 vulnerability，避免把"暂时没证据的真洞"误杀。

---

## 6. 认知状态对象（外部维护，每轮重注入）

```json
{
  "sid": "sess-2026xxxx",
  "target": "https://...",
  "phase": "testing|modeling|reporting",
  "hypotheses": [
    {"id":"H1","text":"/mall/orders/{id} 可越权读","status":"verifying|confirmed|refuted","evidence":"poc_h1.txt"}
  ],
  "verified": ["H3:支付回调缺会话校验→伪造paid"],
  "todo": ["换3个供应商ID重放创建商品","sort 参数注入"],
  "evidence_files": ["poc_h1.txt","report_p1_idor.md"],
  "turn": 17, "last_progress_ts": 1750000000
}
```

- 由外壳在每轮 `state.update()` 后写盘；每轮开头完整注入 prompt（§4 的 [4]）。
- 它既是**防失忆机制**，也是**天然 Audit Trail / 复现链证据**——直接喂给报告。
- 弱模型尤其依赖它：模型不需要"记住"20 轮前的假设，系统替它记。

---

## 6.5 确定性验证层（核心，实现见 `engine/verify.py`）

Guardian(§5.1) 管**报告质量**，verify 管**漏洞真假**。一份发现要算"**已证明**"，光报告写得好不够——必须**确定性重放**拿到不该拿到的东西。这是"启发式给方向、确定性落实"的确定性一侧（符号执行×模糊测试）。

- **`verify_idor`**：换多身份（owner / attacker_B / guest）重放同一请求；非属主拿到受害者数据 → `confirmed`。
- **`verify_id_tamper`**：遍历对象 ID（3-5 个）；返回他人有效数据 ≥2 条 → `confirmed`（对齐 v2 速查卡「替换 ID 测 3-5 个」）。
- 三态：`confirmed` / `refuted` / `inconclusive`（安全端点正确地**不会**误判为 confirmed）。
- **PoC 来源**：`extract_poc(report_md)` 从报告代码块里抽 curl / 原始 HTTP 包，直接复验，无需人转写。

安全红线（硬编码在重放层）：
- 只对**授权 host** 重放（白名单），越界 `PermissionError`。
- 默认只重放**幂等方法**(GET/HEAD)；非幂等(POST/PUT/DELETE) 需 `allow_mutating=True` 才放行——避免"为验证而下单/改数据"，对齐红线"不做破坏性操作"。

```python
from engine.verify import verify_idor, extract_poc, urllib_transport
req = extract_poc(accepted_report_md)
r = verify_idor(req, identities={"owner":{"Cookie":"A"},"attacker_B":{"Cookie":"B"}},
                victim_marker='"收货地址"', transport=urllib_transport,
                authorized_hosts=["t.example"])
# r.result ∈ {confirmed, refuted, inconclusive}；r.evidence 每身份的状态码+片段
```

**与编排的衔接**：`run_session(..., verify_fn=...)` 可选地对 Guardian `accepted` 的报告自动复验，结果写进 `verified` 字段——于是"**已证明的洞 = Guardian accepted 且 verify confirmed**"。自检：`python3 engine/verify.py`（无需联网，mock transport 演示 confirmed / inconclusive / host 拦截）。

---

## 7. 目录布局

```
ai-src/
├─ 核心技能文件.v2.md          # 软约束（注入 prompt）
├─ skills/                     # 触发式路由 Skill（HackSkills）
├─ adapters/                   # 模型适配层（唯一耦合）：cli_agent / openai_like / ...
├─ orchestrator.py             # 编排 Loop（§3）
├─ enforce.py                  # 外部强制层（§5，纯代码）
├─ verify.py                   # 确定性验证：PoC 重放
├─ state.py                    # 认知状态对象（§6）
├─ prompt.py                   # 拼装顺序（§4）
├─ runs/<sid>/                 # 每会话隔离：临时目录 + 证据 + 报告 + state.json
└─ reports/                    # 索引后的 P1/P2/P3
```

---

## 8. 分阶段落地（先能跑，再加固）

**阶段一 · 单脚本能跑（1–2 天，先验证模型无关）**
1. 实现 `ModelAdapter` 的 1 个适配器（建议先 `CliAgentAdapter` 包你手上现成的 Agent CLI）。
2. `prompt.py` 拼装 [1][2][3][7]（先不上认知状态）。
3. `orchestrator.py` 最小 Loop：调模型 → 抓 STATUS 标记 → `finalize`。
4. `enforce.py` 先上 3 个最关键硬约束：危险命令拦截 / 无 PoC 拒收 / 授权 host 校验。
5. 跑一个**授权靶场**（如自建 redhaze 类商城），换 2 个模型各跑一遍，确认**同一外壳、换适配器即可**。
   - 产出不是系统，是"对模型行为的理解"：它报了什么不该报的 → 回填垃圾洞清单。

**阶段二 · 状态与验证（3–5 天）**
6. 上认知状态对象（§6）+ 拼装 [4]；上会话轮数熔断 + 20min 计时器。
7. `verify.py` 确定性重放：对每个候选洞自动换 token/ID 重放，对比响应 → 才算"已证明"。
8. 终态十二条规则（§5）完整化。

**阶段三 · 加固与多模型（1–2 周）**
9. 调度器 + 并发（多目标）；磁盘/API/性能防护；报告索引去重 + 通知。
10. 意图触发 Skill 检索（§4 的 [5]）。
11. 双层模型：便宜模型跑量 + 强模型做 Judge 终验（仅对边界/待提交报告）。

---

## 9. 模型无关验收清单（评审用 · 逐条可勾）

- [ ] 换一个模型（如 GPT→DeepSeek）**只改适配器**，`orchestrator/enforce/verify/state/prompt` 零改动。
- [ ] 故意让模型输出 `rm -rf /` / 越界 host → 被 `enforce.py` 拦下，不是靠模型自觉。
- [ ] 模型声明 `VULN_FOUND` 但没落盘有效报告 → 系统降级为 `LOW_ROI`。
- [ ] 模型给一份命中垃圾洞清单标题的"报告" → 被拒收。
- [ ] 模型连续 20min 无新有效请求 → 自动注入换向指令。
- [ ] 会话超 50 轮 → 自动总结 + 重启续测，证据不丢。
- [ ] 长会话第 30 轮，模型仍能复述当前假设/已验证项（因为来自注入的状态对象，不是它的记忆）。
- [ ] 同一目标用强/弱两个模型跑，弱模型**不会**产出越界或垃圾报告（外壳兜住了下限）。
- [ ] 每个 `VULN_FOUND` 都带可直接执行的 curl/HTTP 包，能被 `verify.py` 重放复现。

---

## 10. 一页纸总结

```
软约束（会忘但只降噪）         → 核心技能文件 v2，注入 prompt 头尾
硬约束（会忘且后果严重）       → enforce.py 外部代码强制，模型碰不到   ← 模型无关的根
攻击面灵感（不是规则）         → 触发式 Skill，按意图注入
私有知识（模型不知道）         → 独立补充文件，按目标注入
状态（别靠模型记忆）           → 认知状态对象，外部维护每轮重注入
验证（别靠模型自夸）           → verify.py 确定性重放
模型                          → 唯一可替换件，只经 ModelAdapter 接缝接入
```
> 把"会忘/会骗/后果重"的东西全推到模型外，剩下的交给模型自由推理——这就是换任何模型都跑得通的全部秘密。
