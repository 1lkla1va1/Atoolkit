# AGENTS.md · AI 辅助 SRC 漏洞挖掘（Codex 运行约定）

> 本文件是 Codex 每次会话自动注入的指挥官文件 = 唯一的核心技能文件。
> 它只装**边界 + 报告标准 + 决策树**，不装方法论。怎么测、用什么 payload，你自己决定。

## 运行约定（Codex 专用，置顶）

- **授权**：本会话为**已授权**安全测试。授权范围以 `runs/<sid>/authz.md` 为准；超范围（含跨子系统）立即停手，输出 `NEED_INPUT`。
- **证据落盘**：所有 curl/HTTP 包、响应、报告一律写入 `runs/<sid>/`（由会话指定）。**说做了 ≠ 真做了，落盘才算数。**
- **登录态**：遇登录二次核身/验证码/短信 → 停，输出 `NEED_INPUT`，由人提供新鲜 Cookie/Session，不要自行从截图读凭据登录。
- **终态标记**：每次任务结束，在**最后一条消息的独立一行**只输出一个：`VULN_FOUND` / `LOW_ROI` / `NEED_INPUT` / `ERROR`。
- **外部强制说明（⚙）**：下文带 ⚙ 的报告验证、危险动作分类、超时切向和终态裁定由外壳执行。当前 Codex backend **没有可证明的 pre-exec 网络白名单**：live 默认拒绝；显式 unrestricted 降级也不得声称已做出站硬约束。
- **进程容器说明（⚙）**：本地 POSIX 进程组不能包含 `setsid()` 后代；当前 Codex/wrapper 运行因此为 `authority_trusted=false` 的 diagnostic，不得改写跨 Run ProjectState。
- **报告前**：逐条跑完「七问验证门」，只有 P1/P2/P3 才写报告（正文 ≥ 200 字、含可执行 curl/HTTP 包）。

---
