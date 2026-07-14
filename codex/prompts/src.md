---
description: 启动一次授权 SRC 漏洞挖掘会话（人控建模 + AI 执行）
---

# 任务：对授权目标做 SRC 漏洞挖掘

目标 / 范围参数：$ARGUMENTS

## 执行约定

0. 先定位当前 **Atoolkit** 项目根，读取项目根 `AGENTS.md` 和 `SKILL.md`；不得假设全局 `~/.codex/AGENTS.md` 或其他项目的 `/src` 已注入。无法确认 Atoolkit 项目根时终止。
0.1 运行必须由 agent 外部的 `python3 -m engine.skill_wrapper` 在首个动作前创建 authority manifest 与 frozen run plan；只有外部容器/cgroup/job 监督器能证明所有后代已静默时才可信。当前内置 wrapper 和 Direct Skill 都是 diagnostic。初始化失败不得继续。

1. 先**收集流量、理解业务**：走一遍正常业务流，观察登录态/角色/金钱流/权限流；不确定就先产出 Mermaid 时序图理清。
2. 按 AGENTS.md 的**决策树**选攻击面；高价值功能（认证/支付/数据导出/越权）优先。
3. 长链路（跨子系统/多漏洞）先用 **PLAN** 宏观规划再拆 TODO；短链路（单字段/IDOR）直接 **TODO** 边走边测。
4. 每条候选漏洞：**换 3–5 个 ID/账号重放**取证，把 curl/HTTP 包与响应**落盘到本次 session 目录**；canonical finding 只能使用 `findings/finding_<id>/finding.json` 布局。
5. 报告前逐条过**七问验证门**；只报"结果"，命中垃圾洞清单的一律丢弃。
6. 任一方向 **20 分钟无进展 → 换攻击面**；结束时由外部 wrapper 停止 agent 并调用 exactly-once finalizer。不要把 loose reporting/receipt 当作完整交付。最后一行只输出一个终态标记。

## 本会话上下文（人填）

- 授权文档：见 `runs/<sid>/authz.md`
- 登录态 Cookie/Session（人已拿到的新鲜凭据，粘贴或指向文件）：
  ```
  <在此粘贴 Cookie/Authorization 头，或写 runs/<sid>/cookies.txt>
  ```
- 已知业务上下文 / 私有缺陷线索（可选）：
  ```
  <例如：该站套餐 ID 体系特殊；回调域名与主站不同源等>
  ```

开始。先回我一句你选定的首个攻击面和理由，再动手。
