# 用 opencode 跑这套 SRC 方案 · 安装与调用

> opencode 没有 Claude Code 的 `SKILL.md` 技能系统，但**原生读取 `AGENTS.md` + 自定义命令** ——
> 正好对应本包的**形态 B**（软约束注入 + `/src` 命令）。复用已有的 `codex/AGENTS.md` 与
> `codex/prompts/src.md`，**不另造副本**（单一真相：AGENTS.md 仍由 `skill/核心技能文件.v2.md`
> 经 `codex/regen_agents.sh` 生成）。
>
> ⚠ opencode 的配置路径 / 命令机制随版本演进，本文以 `~/.config/opencode/` + `command/*.md` +
> `opencode.json` 的 `permission` 为准，**实际以 `opencode --help` 和当版文档为准**。

---

## 与 Codex 的关键差异（别照搬心智）

| 维度 | Codex（形态 B） | opencode |
|---|---|---|
| 软约束注入 | `~/.codex/AGENTS.md` 自动注入 | `~/.config/opencode/AGENTS.md`（或项目根 `AGENTS.md`）自动注入 |
| `/src` 命令 | `~/.codex/prompts/src.md` | `~/.config/opencode/command/src.md` |
| **硬约束地板** | `config.toml` 的 sandbox + approval | **没有 Codex 沙箱**；用 opencode 自己的 `permission`（bash/edit 设 `ask/deny`） |
| 授权 host 收口 | 沙箱不做 host 白名单 → 需外壳/代理 | **同样不做** → 仍需出站代理或形态 C 收口 |

> 一句话：**软约束（AGENTS.md）平移过来即用；硬约束地板要换成 opencode 的 permission**，
> 且「只打授权目标」永远不能只靠 AGENTS.md 文字（和 Codex 同坑）。

---

## 安装（三步）

```bash
# 0) 先 clone（命令默认在 clone 出来的目录里执行）
git clone https://github.com/1lkla/ai-src-toolkit.git && cd ai-src-toolkit

# 1) 装核心技能文件（= AGENTS.md，opencode 自动注入）—— 二选一
cp codex/AGENTS.md ~/.config/opencode/AGENTS.md            # 全局：所有项目共用 SRC 约束
# 或 项目级（推荐，和授权目录绑定；opencode 自动读项目根 AGENTS.md）：
cp codex/AGENTS.md ~/work/src-target/AGENTS.md

# 2) 装 /src 自定义命令（src.md 已含 $ARGUMENTS 与 description，直接可用）
mkdir -p ~/.config/opencode/command && cp codex/prompts/src.md ~/.config/opencode/command/src.md
# 或 项目级：mkdir -p .opencode/command && cp codex/prompts/src.md .opencode/command/src.md

# 3) 配硬约束地板（opencode 的 permission，替代 Codex 沙箱）
#    把 opencode/opencode.json.example 需要的键合并进你的 ~/.config/opencode/opencode.json
#    （或项目根 opencode.json）
$EDITOR ~/.config/opencode/opencode.json
```

## 起一次会话

```bash
mkdir -p ~/work/src-target/runs/sess-001
printf '# 授权范围\n- 仅限：https://target.example\n' > ~/work/src-target/runs/sess-001/authz.md
cd ~/work/src-target          # 证据会落在这里的 runs/
opencode                      # 进交互式
```
进去后在会话框输入：
```text
/src https://授权目标          ← 启动一次授权会话（自动拼装目标/Cookie/业务上下文）
# 按提示粘贴你已拿到的新鲜 Cookie / Authorization 头
```
AI 跑完最后一行给终态标记（`VULN_FOUND` / `LOW_ROI` / `NEED_INPUT` / `ERROR`），证据落 `runs/<sid>/`。
中断与断点续测见 README「会话产物 · 中断与断点续测」。

---

## 想要编排外壳（计时器/50轮重启/PoC 重放/中断抢救/`--resume`）？走形态 C

`run.py` 模型无关，opencode 装没装都能跑（默认 `CodexAdapter` 包 `codex exec`）：
```bash
python3 run.py --target https://授权目标 --authz "已授权" --cookie 'session=…'
```
若要让外壳驱动 **opencode 而非 Codex**：照 `codex/codex_adapter.py` 写一个 `OpenCodeAdapter`
（包 opencode 的非交互 `opencode run`），换 adapter 一处、外壳零改动。属延伸开发，非安装。

---

## 最小验收（确认真在遵循）

- [ ] 不带 Cookie 让它测 → 走未授权/认证绕过分支，而非瞎测（AGENTS.md 软约束生效）。
- [ ] 让它报一个 CORS/安全头 → 按垃圾洞清单拒绝。
- [ ] 让它 `rm -rf` 或访问授权外 host → 被 opencode `permission` 拦下（硬约束地板生效）。
- [ ] 报告带可执行 curl，证据在 `runs/<sid>/`（落盘才算数）。
