# ai-src-toolkit

模型无关的 AI 辅助 SRC 漏洞挖掘方案。

核心思路：**把"会忘 / 会骗 / 后果重"的规则搬出模型、放进外壳代码**——软约束注入 prompt，硬约束由外壳/沙箱强制，换任何模型只换一个适配器。

> 仅用于**已授权**的安全测试与教育实验环境。

---

## 支持的工具

| 形态 | 工具 | 软约束注入 | 硬约束地板 |
|---|---|---|---|
| A | Claude Code / ZCode | SKILL.md 技能包 | IDE 权限体系 |
| B | Codex | AGENTS.md 自动注入 | Codex sandbox + approval |
| B′ | opencode | AGENTS.md 自动注入 | opencode permission |
| C | 纯 CLI（模型无关） | run.py 拼装注入 | engine/ 外壳代码 |

---

## 前置条件

- Git
- Python 3.10+（形态 C 需要）
- 已安装对应工具（Claude Code / Codex / opencode 任一）
- 一个**已授权**的测试目标，以及你手动获取的新鲜 Cookie 或 Bearer Token

```bash
git clone https://github.com/1lkla/ai-src-toolkit.git
cd ai-src-toolkit
```

---

## 形态 A · Claude Code / ZCode

Claude Code 和 ZCode 都通过 `SKILL.md` 自动发现技能。把整个仓库放进 skills 目录即可。

### 安装

**全局安装**（所有项目可用）：

```bash
cp -R . ~/.claude/skills/ai-src-toolkit
```

**项目级安装**（推荐，和授权范围绑定）：

```bash
# 在你的测试项目目录下执行
mkdir -p .claude/skills
cp -R /path/to/ai-src-toolkit .claude/skills/ai-src-toolkit
```

安装后重启 Claude Code。验证：输入 `/` 能看到 `ai-src-toolkit` 技能。

### 使用

在会话框输入：

```
/ai-src-toolkit
```

或用自然语言触发：

```
对 https://授权目标 做一次授权 SRC 漏洞挖掘
```

Agent 会自动读取核心技能文件，先问你要**授权范围**和**新鲜凭据**（不给不测），然后按决策树执行。

---

## 形态 B · Codex

Codex 通过 `AGENTS.md` 在每次会话启动时自动注入系统指令。

### 安装

#### 第 1 步：放置 AGENTS.md

**全局**（所有项目共用）：

```bash
cp codex/AGENTS.md ~/.codex/AGENTS.md
```

**项目级**（推荐）：

```bash
# 把 AGENTS.md 放到你的测试工作目录根
cp codex/AGENTS.md ~/work/src-target/AGENTS.md
```

> **AGENTS.md 必须放在 Codex 能发现的位置**：全局放 `~/.codex/AGENTS.md`，项目级放项目根目录。Codex 每次启动会自动读取它作为核心约束。不需要放在本仓库（ai-src-toolkit）目录内。

#### 第 2 步：安装 /src 命令

```bash
mkdir -p ~/.codex/prompts
cp codex/prompts/src.md ~/.codex/prompts/src.md
```

这会注册 `/src` 自定义命令，用于启动一次授权会话。

#### 第 3 步：配置 sandbox 和模型

把示例配置合并进你的 Codex 配置：

```bash
cat codex/config.toml.example    # 先看内容
$EDITOR ~/.codex/config.toml     # 把需要的键合并进去
```

关键三项：

```toml
model = "gpt-5.5-codex"              # 换模型只改这行
sandbox_mode = "workspace-write"      # 只可写工作目录
[sandbox_workspace_write]
network_access = true                 # SRC 必须联网发包
```

### 使用

```bash
# 1. 创建工作目录和授权文件
mkdir -p ~/work/src-target/runs/sess-001
echo '仅限：https://target.example' > ~/work/src-target/runs/sess-001/authz.md

# 2. 进入工作目录，启动 Codex
cd ~/work/src-target
codex

# 3. 在会话框输入（按提示粘贴新鲜 Cookie）
/src https://target.example
```

AI 跑完后最后一行输出终态标记：`VULN_FOUND` / `LOW_ROI` / `NEED_INPUT` / `ERROR`。证据落在 `runs/sess-001/`。

---

## 形态 B′ · opencode

opencode 同样读取 `AGENTS.md`，复用 Codex 的文件，不另造副本。

### 安装

#### 第 1 步：放置 AGENTS.md

```bash
# 全局
cp codex/AGENTS.md ~/.config/opencode/AGENTS.md

# 或项目级（推荐）
cp codex/AGENTS.md ~/work/src-target/AGENTS.md
```

#### 第 2 步：安装 /src 命令

```bash
mkdir -p ~/.config/opencode/command
cp codex/prompts/src.md ~/.config/opencode/command/src.md
```

#### 第 3 步：配置 permission（硬约束地板）

```bash
cat opencode/opencode.json.example   # 先看内容
$EDITOR ~/.config/opencode/opencode.json
```

关键配置：

```json
{
  "permission": {
    "bash": "ask",      // 危险命令需人工确认
    "edit": "allow",    // 允许写证据到 runs/
    "webfetch": "allow" // SRC 必须联网
  }
}
```

### 使用

```bash
cd ~/work/src-target
opencode
# 在会话框输入：
# /src https://授权目标
```

> **与 Codex 的关键差异**：opencode 没有 Codex 沙箱，硬约束靠 `permission` 配置。「只打授权目标」不能只靠 AGENTS.md 文字，仍需外壳或出站代理收口。

---

## 形态 C · 纯 CLI（模型无关编排）

由外壳代码接管计时器、50 轮重启、无 PoC 拒收、PoC 确定性复验。不依赖任何 IDE。

### 安装

无额外安装。确保已 clone 本仓库并有 Python 3.10+。

### 使用

**自检**（不接模型、不联网，验证接线）：

```bash
python3 run.py --dry-run --target https://t.example --authz "demo"
```

**Cookie 鉴权会话**：

```bash
python3 run.py \
  --target https://授权目标 \
  --authz "已授权说明" \
  --cookie 'session=abc123'
```

**Bearer / JWT 鉴权会话**：

```bash
python3 run.py \
  --target https://授权目标 \
  --authz "已授权说明" \
  --bearer 'eyJ...' \
  --auth-scheme bearer
```

**带水平越权确定性复验**（需两个账号）：

```bash
python3 run.py \
  --target https://授权目标 \
  --authz "已授权说明" \
  --identity owner:session=A \
  --identity attacker:session=B \
  --victim-marker '收货地址'
```

**指定攻击面覆盖矩阵**：

```bash
python3 run.py \
  --target https://授权目标 \
  --authz "已授权说明" \
  --cookie 'session=...' \
  --endpoints endpoints.txt       # 每行一个接口路径
  --vuln-class IDOR \
  --vuln-class SQLi
```

全部参数见 `python3 run.py -h`。

### 断点续测

会话中断后（网络断开、进程崩溃等），已落盘的证据不会丢失：

```bash
# 查看中断状态
tail runs/<sid>/events.jsonl

# 从断点继续（复用同一 sid，承接已完成的覆盖格）
python3 run.py --sid <旧sid> --resume \
  --target https://授权目标 --authz "已授权说明" --cookie 'session=新鲜凭据'
```

---

## 一次会话的标准流程

无论哪种形态，流程都是同一套：

```
① 人控前置    走一遍业务 → 拿新鲜 Cookie/Token → 写授权范围       ← 人做
② 注入        核心技能文件自动注入 + 拼装目标/凭据/业务上下文
③ AI 循环     选攻击面 → 发包 → 取证 → 落盘 runs/<sid>/
④ 外部强制    sandbox/approval + 编排外壳(计时器/重启/无PoC拒收)
⑤ 终态裁定    VULN_FOUND / LOW_ROI / NEED_INPUT / ERROR
```

**报告标准**（外壳强制）：
- 垃圾洞直接丢：CORS、sourcemap、缺安全头、无速率限制、指纹、Self-XSS
- 有效报告 = P1/P2/P3 定级 + 可复现 curl/HTTP PoC + 响应证据
- 够证明即止，不做超出取证的进一步利用

---

## 会话产物

所有证据落在 `runs/<sid>/` 下：

| 文件 | 说明 |
|---|---|
| `authz.md` | 授权范围（输入） |
| `cookies.txt` | 凭据（已 gitignore） |
| `state.json` | 进度快照：覆盖矩阵 / 假设 / 轮次 |
| `events.jsonl` | 事件轨迹（纯磁盘，不进 prompt） |
| `report_*.md` | 已证漏洞报告（你要的成果） |
| `negative_*.md` | 阴性留证（已测无利用） |
| `*.http` | 原始请求包 / 证据 |

---

## 目录结构

```
ai-src-toolkit/
├── README.md                 ← 你在这
├── SKILL.md                  ← 形态 A：Claude Code / ZCode 技能定义
├── CHANGELOG.md
├── run.py                    ← 形态 C：CLI 入口
│
├── skill/                    【软约束·注入 prompt】
│   └── 核心技能文件.v2.md      单一真相源（所有形态共用）
│
├── codex/                    【形态 B / B′ 集成文件】
│   ├── AGENTS.md              = 核心技能文件，Codex/opencode 自动注入
│   ├── prompts/src.md         /src 命令定义
│   ├── config.toml.example    Codex 配置示例
│   ├── codex_adapter.py       模型适配器
│   ├── regen_agents.sh        从 v2 重生成 AGENTS.md
│   └── USAGE.md               Codex 详细用法
│
├── opencode/                 【形态 B′ 补充配置】
│   ├── opencode.json.example  permission 配置示例
│   └── USAGE.md               opencode 详细用法
│
├── engine/                   【形态 C·模型无关外壳】
│   ├── orchestrator.py        编排 Loop
│   ├── enforce.py             Guardian 八级质检 + 硬约束
│   └── verify.py              确定性越权复验
│
├── design/                   【设计文档】
├── knowledge-base/           【知识图谱】
└── raw-materials/            【原始材料】
```

---

## 维护约定

- **核心规则变更**：只改 `skill/核心技能文件.v2.md`，然后 `bash codex/regen_agents.sh` 同步 AGENTS.md
- **换模型**：形态 B 改 `~/.codex/config.toml` 的 `model`；形态 C 改 `run.py --model`
- **知识库重建**：新材料放 `raw-materials/` → 抽文本进 `knowledge-base/kb_sources/` → 跑 graphify
- 变动记录在 `CHANGELOG.md`

---

## 红线

- 仅在**已授权**范围内测试；越界立即停止
- 不做破坏性操作 / 横向扩散 / 数据外传
- 遇登录墙停手，由人提供凭据
- 无可复现 PoC 即无报告；只报已证明的结果
- 「只打授权目标」必须靠外壳/出站代理收口，不能只停留在文字约束
