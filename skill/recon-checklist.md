# Phase 0 · 侦察与攻击面建模

> 本文件是 Phase 0 侦察阶段的独立参考文档。在开始任何漏洞测试之前，先执行本流程，
> 系统性枚举目标攻击面，避免遗漏方向。
>
> **核心目标**：用 15 分钟建立完整的攻击面清单（attack_surface_list.md）。
> **适用模式**：Skill Mode / 纯 agent 模式。Engine 模式下由 `orchestrator.py` 自动完成部分枚举。

---

## 0.1 页面与 JS 分析（5 分钟）

**目标**：从前端代码中提取所有可达的 API 端点。

1. 获取关键页面 HTML（首页、登录页、用户首页、商户首页、管理后台首页）
2. 提取所有 `<script src="...">` 引用的 JS 文件路径
3. 分析 JS 文件中的 API 调用：grep `fetch`、`axios`、`ajax`、`.php`、`/api/`，注意动态路径和模板字符串
4. 记录端点清单到 `endpoint_inventory.md`

注意：不要忽略 webpack 打包文件和不同角色加载的不同 JS 文件。SPA 框架的路由配置通常包含所有页面路径。

---

## 0.1.5 非 API 页面与表单扫描（2 分钟）

**目标**：发现不在 JS 中的高价值页面和表单提交路径。

1. 扫描 HTML 中的 `<form action>` 和 `<a href>` 内部路径
2. 检查高价值页面模式：支付/回调类（`pay/*`、`callback/*`）、认证类（`user/reset*`、`auth/*`）、管理类（`admin/config*`）、商户类（`merchant/audit*`）
3. 检查 URL 参数：`redirect`、`return_url`、`callback_url`、`token`、`file`、`page`
4. 用 `[HTML]` 前缀记录到 `endpoint_inventory.md`

注意：不要忽略 `<iframe src>` 和 `<meta http-equiv="refresh">` 中的路径。

---

## 0.2 API 端点枚举（3 分钟）

**目标**：验证端点是否真实可达，并分类。

1. 对每个端点发送匿名请求和认证请求，记录状态码和响应格式
2. 分类为：公开端点（匿名可访问）、需认证端点（401/302/403）、不存在端点（404）、可疑端点
3. 更新 `endpoint_inventory.md`

注意：302 通常是跳转到登录页，403 是权限不足（端点存在但权限不够）。匿名请求返回数据本身就是未授权访问线索。

---

## 0.3 业务流建模（5 分钟）

**目标**：理解业务逻辑，发现参数传递关系和越权路径。

1. 走一遍用户核心流程：注册 → 登录 → 浏览 → 下单 → 支付 → 退款，记录每步 API 端点、参数、响应 ID
2. 走一遍商户流程（如有）：注册 → 审核 → 添加商品 → 管理订单 → 发货
3. 走一遍管理流程（如有）：登录 → 用户列表 → 商户审核 → 数据统计
4. 写入 `business_flow.md`，重点记录**跨流参数传递**（A 接口返回 ID 喂给 B 接口 = IDOR 高产路径）和状态流转

---

## 0.4 攻击面清单生成（2 分钟）

**目标**：合并产出为结构化攻击面清单。

1. 从 `endpoint_inventory.md` + `business_flow.md` 合并
2. 每个 surface 包含：编号（S01...）、endpoint、method、param、role（anon/user/merchant/admin）、risk_tags、status（一律 not_tested）
3. 按优先级分桶：P1 认证验证 → P2 交易支付 → P3 IDOR 越权 → P4 输入验证 → P5 管理商户
4. 写入 `attack_surface_list.md`

注意：每个端点的每个关键参数应有独立 surface 行；同端点不同角色分别列出。

---

## 0.5 完整性检查

对照决策树分支确认无空白方向。特别检查：认证面（注册/登录/找回/验证码）、交易面（支付/退款/订单/积分）、对象参数（user_id/order_no/product_no）、输入参数（keyword/sort/filter/filename）。

有方向无 surface → 回到 0.1 补充 JS 分析，或手动探测常见路径（reset-password / admin/export）、robots.txt、JS 注释路径。

---

## 攻击面完整性门（Phase 0 结束时必检）

```
□ 认证注册面         □ 认证登录面         □ 认证找回面
□ 验证码/captcha 面  □ SMS/邮件验证码面   □ 支付/充值面
□ 退款面             □ 订单面             □ 积分/优惠券/抽奖面
□ 文件上传面         □ 搜索/筛选面        □ 用户资料面
□ 对象详情页         □ 管理面             □ 商户/商家面
□ 支付/回调 HTML 页面                  □ 表单 action 页面
```

每项至少 1 个 surface。某方向无 surface 且目标确实没有 → 标 N/A；不确定 → 继续侦察；确认有但找不到 → 标 NEED_INPUT。全部覆盖 → 通过完整性门，进入测试。

---

## 快速参考：Phase 0 时间分配

| 步骤 | 时间 | 产出 |
|---|---|---|
| 0.1 页面与 JS 分析 | 5 分钟 | endpoint_inventory.md |
| 0.1.5 非 API 页面扫描 | 2 分钟 | 更新 endpoint_inventory.md |
| 0.2 API 端点枚举 | 3 分钟 | 更新 endpoint_inventory.md |
| 0.3 业务流建模 | 5 分钟 | business_flow.md |
| 0.4 攻击面清单生成 | 2 分钟 | attack_surface_list.md |
| 0.5 完整性检查 | — | 通过完整性门或回补 |
| **合计** | **~17 分钟** | **完整攻击面清单** |
