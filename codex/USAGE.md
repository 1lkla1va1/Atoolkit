# 用 Codex 跑这套 SRC 方案 · 安装与调用

> 你已装 `codex-cli 0.131.0`。本目录给出即用文件。**先在本目录确认，再拷到 `~/.codex/`。**
> 实际命令 flag 以 `codex --help` / `codex exec --help` 为准（版本差异）。

---

## 这套东西的运行逻辑（一图）

```
人控前置        ① 走一遍业务 + 拿新鲜 Cookie/Session + 写 authz.md   ← 人做，AI 做不了
   ↓
注入            ② AGENTS.md(=核心技能文件) 每会话自动注入 + /src 拼装目标/Cookie
   ↓
AI 循环         ③ Codex 在 sandbox 里 ReAct：选攻击面→发包→取证→落盘 runs/<sid>/
   ↓
外部强制+验证   ④ sandbox/approval(地板) + 编排外壳(计时器/50轮重启/无PoC拒收/PoC重放)  ← ⚙ 不靠模型自觉
   ↓
终态           ⑤ 最后一行输出 VULN_FOUND/LOW_ROI/NEED_INPUT/ERROR → 外壳按证据裁定
```

Codex 在这套里只扮演 ③ 的"带 shell 的 Agent 运行时"。①是人，②④⑤是外壳——所以换任何模型逻辑不变。

---

## 模式 A：手动 / 半自动（今天就能用，无需写代码）

软约束靠 AGENTS.md，硬约束地板靠 Codex 的 sandbox+approval，循环靠你"继续测试"。

### 1. 装核心技能文件（= AGENTS.md）
二选一：
```bash
# 全局（所有项目共用这套 SRC 约束）
cp codex/AGENTS.md ~/.codex/AGENTS.md

# 或项目级（只在某测试工作目录生效，推荐——和授权范围绑定）
mkdir -p ~/work/src-target && cp codex/AGENTS.md ~/work/src-target/AGENTS.md
```
> Codex 每次会话自动注入 AGENTS.md = 文章说的"启动时加载唯一核心技能文件"。**别再往里塞方法论**，保持 ≤200 行。

### 2. 装 `/src` 自定义命令
```bash
mkdir -p ~/.codex/prompts && cp codex/prompts/src.md ~/.codex/prompts/src.md
```
进入交互式 `codex` 后输入 `/src` 即触发（它会拼装目标/Cookie/业务上下文）。

### 3. 配 sandbox / 模型（硬约束地板）
```bash
# 把 codex/config.toml.example 里需要的键合并进 ~/.codex/config.toml
$EDITOR ~/.codex/config.toml
```
关键三项：`model`（换模型只改这行）、`sandbox_mode = "workspace-write"`、`network_access = true`（SRC 必须联网发包）。

### 4. 起一次会话
```bash
mkdir -p ~/work/src-target/runs/sess-001
printf '# 授权范围\n- 仅限：https://target.example\n' > ~/work/src-target/runs/sess-001/authz.md
cd ~/work/src-target
codex                       # 进交互式
# 然后：/src https://target.example  并按提示粘贴你已拿到的新鲜 Cookie
```
AI 跑完会在最后一行给终态标记；证据落在 `runs/sess-001/`。无进展时你回一句"换个方向/继续测试"推进（钝感人机六轮即可，见文章）。

---

## 模式 B：编排自动化（模型无关平台，对接 orchestrator.py）

把 `codex exec` 包成适配器，由外壳接管计时器/50轮重启/外部强制/PoC重放/认知状态。

```bash
# 适配器已给：codex/codex_adapter.py（包 codex exec，流式回吐）
python3 codex/codex_adapter.py < 一段任务prompt        # 单测适配器
```
对接见 `AI_SRC落地实施方案.md` §2/§3：`orchestrator.run_session(CodexAdapter(...), ...)`。
换模型 = 换 `CodexAdapter` → `OpenAILikeAdapter`，外壳零改动。

---

## 让 Codex"遵循逻辑"的三个抓手（对应 ⚙）

| 抓手 | 谁强制 | 怎么落地 |
|---|---|---|
| 软约束（垃圾洞清单/七问门/决策树） | AGENTS.md 注入 | 模式 A 第 1 步 |
| 硬约束地板（不可碰系统、危险命令拦截、可写区限定） | Codex sandbox + approval | config：`workspace-write` + `on-failure` |
| 编排强制（20min切向/50轮重启/无PoC拒收/PoC重放/终态裁定） | 编排外壳（非模型） | 模式 B / orchestrator.py |

> ⚠️ Codex 沙箱**不做 host 级白名单**：`network_access=true` 是全网放行。授权范围（只打 target）要靠
> 外壳/出站代理收口（`codex_adapter.py` 的 `allow_hosts` 注释处）。别让"只打授权目标"只停留在 AGENTS.md 文字上。

---

## 最小验收（确认真的在遵循）

- [ ] 不带 Cookie 让它测 → 它走未授权/认证绕过分支，而不是瞎测。
- [ ] 让它报一个 CORS/安全头 → 被它按垃圾洞清单拒绝（软约束生效）。
- [ ] 让它 `rm -rf` 或访问授权外 host → 被 sandbox/approval 拦下（硬约束生效）。
- [ ] 报告里必须带可执行 curl，证据在 `runs/<sid>/`（落盘才算数）。
- [ ] 改 `config.toml` 的 `model` 换个模型 → 流程一字不改照跑（模型无关）。

---

## 文件清单（本目录）

| 文件 | 拷到哪 | 作用 |
|---|---|---|
| `AGENTS.md` | `~/.codex/AGENTS.md` 或 项目根 | 核心技能文件（软约束，自动注入） |
| `prompts/src.md` | `~/.codex/prompts/src.md` | `/src` 启动一次授权会话 |
| `config.toml.example` | 合并进 `~/.codex/config.toml` | 模型 + sandbox 地板 |
| `codex_adapter.py` | 留在工程，供 orchestrator 调 | 模式 B 的模型适配器 |
