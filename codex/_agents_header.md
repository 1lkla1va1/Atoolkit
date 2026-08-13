# AGENTS.md · AI 辅助 SRC 漏洞挖掘运行约定

> 本文件是每次会话自动注入的指挥官文件 = 唯一的核心技能文件。
> 它只装**边界 + 报告标准 + 决策树**，不装方法论。怎么测、用什么 payload，你自己决定。

## 运行约定（置顶）

- **运行环境路由（v9.3，先判断你在哪）**：
  - **Codex CLI** → 可用 Engine Mode（`python3 run.py ... --via codex`）或 Direct 模式；
  - **QoderWork / ZCode / 其他 IDE** → **禁止运行 `python3 run.py` Engine 路径**（它会拉起外部 codex/gpt 后端，计费与出站与当前 IDE 无关，run.py 对此 fail closed）；只走 Direct 模式六命令：`python3 -m engine.skill_runtime preflight|init|observe|checkpoint|scope|report`。
- **授权**：本会话为**已授权**安全测试。授权范围以 workspace `AUTHZ.md`（单一授权真相）与 `runs/<sid>/authz.md` 为准；超范围（含跨子系统）立即停手，输出 `NEED_INPUT`。
- **多资产与扩范围（v9.3）**：`init` 用 `--allow <url>`（可多次）或 `--scope-file AUTHZ.md` 声明全部在册资产，多资产 scope 之外的 finding 会被 checkpoint 拒收。中途新增资产（新端口/新域名）用 `python3 -m engine.skill_runtime scope --run-dir <run> --add <url> --reason <原因>` 追加（append-only，留审计），无需重开 Run。
- **派生资产（v9.3）**：OSS bucket / CDN / 回调域等由在册端点签发凭证或流程触达的第三方基础设施，用 `--allow-derived` 或 AUTHZ.md「派生资产」小节声明。派生资产**不能**作为 finding 的 target，只允许出现在证据包中，且 finding 必须填 `verification.issued_by`（在册签发端点 URL）。
- **证据落盘**：所有 curl/HTTP 包、响应、报告一律写入 `runs/<sid>/`（由会话指定）。**说做了 ≠ 真做了，落盘才算数。**
- **登录态**：不得从截图读取凭据、代替真人完成验证码/短信/二次核身；先在安全边界内测试流程绑定、字段省略/空值和步骤跳转等绕过，全部失败后输出 `NEED_INPUT`，由人提供新鲜 Cookie/Session。
- **终态标记**：每次任务结束，在**最后一条消息的独立一行**只输出一个：`VULN_FOUND` / `LOW_ROI` / `NEED_INPUT` / `ERROR`。
- **外部强制说明（⚙）**：下文带 ⚙ 的报告验证、危险动作分类、超时切向和终态裁定由外壳执行。当前 Codex backend **没有可证明的 pre-exec 网络白名单**：live 默认拒绝；显式 unrestricted 降级也不得声称已做出站硬约束。
- **进程容器说明（⚙）**：本地 POSIX 进程组不能包含 `setsid()` 后代；当前 Codex/wrapper 运行因此为 `authority_trusted=false` 的 diagnostic，不得改写跨 Run ProjectState。
- **报告前**：逐条跑完「七问验证门」，只有 P1/P2/P3 才写报告（正文 ≥ 200 字、含可执行 curl/HTTP 包）。

---
