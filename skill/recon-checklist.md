# Phase 0 · 侦察与攻击面建模

> 本文件是 Phase 0 侦察阶段的独立参考文档。在开始任何漏洞测试之前，必须先执行本流程，
> 系统性地枚举目标攻击面，避免遗漏方向。
>
> **核心目标**：用 15 分钟建立完整的攻击面清单（attack_surface_list.md），让后续测试有的放矢。
>
> **适用模式**：Skill Mode / 纯 agent 模式。Engine 模式下由 `orchestrator.py` 自动完成部分枚举。

---

## 0.1 页面与 JS 分析（5 分钟）

**目标**：从前端代码中提取所有可达的 API 端点。

### 操作步骤

1. **获取关键页面 HTML**：逐一请求以下页面，记录响应内容：
   - 首页（`/` 或 `/index.html`）
   - 登录页（`/login`、`/user/login` 等）
   - 用户首页 / 用户中心（`/user/`、`/dashboard/`、`/home/`）
   - 商户首页（如有：`/merchant/`、`/shop/`）
   - 管理后台首页（如有：`/admin/`、`/manage/`）

2. **提取 JS 文件引用**：从每个页面的 HTML 中提取所有 `<script src="...">` 引用的 JS 文件路径。

3. **分析 JS 文件中的 API 调用**：对每个 JS 文件，使用以下方式提取 API 路径：
   - `grep` 关键词：`fetch`、`axios`、`ajax`、`$.get`、`$.post`、`XMLHttpRequest`、`.php`、`/api/`
   - 关注 `url:` 字段、模板字符串中的路径拼接
   - 注意动态路径：如 `` `/api/user/${action}.php` `` 意味着多个端点

4. **记录端点清单**：将提取到的所有路径写入 `endpoint_inventory.md`，格式：

```markdown
## 从 JS 提取的端点

| # | 路径 | 来源 JS 文件 | 行号 | HTTP 方法（推测） |
|---|---|---|---|---|
| 1 | /api/user/login.php | app.js | L42 | POST |
| 2 | /api/user/register.php | app.js | L58 | POST |
| 3 | /api/merchant/product-list.php | merchant.js | L15 | GET |
...
```

### 注意事项

- 不要忽略 webpack 打包后的文件（`app.bundle.js`、`chunk-*.js`）——它们包含大量 API 路径
- 注意 JS 中的条件分支：不同角色（user/merchant/admin）可能加载不同的 JS 文件
- 如果目标使用 SPA 框架（Vue/React），路由配置中通常包含所有页面路径

---

## 0.1.5 非 API 页面与表单扫描（2 分钟，v7.1 新增）

**目标**：发现不在 JS 中的高价值页面和表单提交路径。

### 操作步骤

1. **扫描 HTML 中的表单 action**：对 0.1 获取的每个页面，提取所有 `<form action="...">` 路径
2. **扫描服务端渲染链接**：提取所有 `<a href="...">` 中的内部路径（排除 `#` 和 `javascript:`）
3. **检查常见高价值页面模式**：按路径模式逐一 curl 检查是否存在：
   - 支付/回调类：`pay/*`、`payment/*`、`checkout/*`、`callback/*`
   - 用户认证类：`user/reset*`、`user/verify*`、`user/activate*`、`auth/*`
   - 管理后台类：`admin/config*`、`admin/export*`、`admin/backup*`、`admin/settings*`
   - 商户类：`merchant/audit*`、`merchant/settings*`、`shop/admin/*`
   - 首页入口：`index.php`、`index.html`（可能有 redirect 参数）
4. **检查 URL 参数**：对每个可达页面，检查 URL 中是否接受以下参数：
   - `redirect`、`return_url`、`callback_url`、`next`、`url`
   - `file`、`page`、`path`、`template`
   - `token`、`auth_token`、`code`
5. **记录到 endpoint_inventory.md**：非 API 端点用 `[HTML]` 前缀标记

### 注意事项
- 不要忽略 `<iframe src>` 和 `<meta http-equiv="refresh" content="...">` 中的路径
- 服务端渲染的页面可能不包含 JS 文件，但仍然接受 URL 参数
- 表单的 `action` 属性可能是相对路径，需要拼接完整 URL

---

## 0.2 API 端点枚举（3 分钟）

**目标**：验证 0.1 提取的端点是否真实可达，并分类。

### 操作步骤

1. **逐一 curl 检查可达性**：对 `endpoint_inventory.md` 中的每个路径，发送 HTTP 请求：
   - 无认证请求（匿名访问）
   - 如有登录态，附带 Cookie 再请求一次

2. **记录每个端点的响应特征**：

```markdown
| # | 路径 | 匿名状态码 | 认证状态码 | 响应格式 | 分类 |
|---|---|---|---|---|---|
| 1 | /api/user/login.php | 200 | 200 | JSON | 公开端点 |
| 2 | /api/user/profile.php | 401/302 | 200 | JSON | 需认证端点 |
| 3 | /api/old/deprecated.php | 404 | 404 | HTML | 不存在 |
...
```

3. **端点分类**：
   - **公开端点**：匿名即可访问（登录、注册、验证码、公开查询）
   - **需认证端点**：需要登录态才能访问（个人资料、订单、支付）
   - **不存在端点**：返回 404，从清单中移除
   - **可疑端点**：返回非标准状态码或异常响应，标记待查

### 注意事项

- 401 vs 302 vs 403 的区别很重要：302 通常是跳转到登录页，403 是权限不足（端点存在但你没权限）
- 如果匿名请求返回了数据 → 这本身就是未授权访问的线索
- 不要忽略 OPTIONS 请求——有些端点只接受特定 HTTP 方法

---

## 0.3 业务流建模（5 分钟）

**目标**：理解目标的业务逻辑，发现参数传递关系和潜在的越权路径。

### 操作步骤

1. **走一遍用户核心流程**（使用浏览器或 curl 链）：
   - 注册 → 登录 → 浏览商品 → 下单 → 支付 → 退款
   - 记录每步涉及的 API 端点、请求参数、响应中的关键 ID

2. **走一遍商户流程**（如有商户角色）：
   - 商户注册 → 提交审核 → 审核通过 → 添加商品 → 管理订单 → 发货
   - 记录审核相关的端点和状态流转

3. **走一遍管理流程**（如有管理后台）：
   - 管理员登录 → 用户列表 → 商户审核 → 数据统计
   - 关注管理接口是否暴露了普通用户的数据

4. **绘制业务流图**：写入 `business_flow.md`，格式：

```markdown
## 用户流

注册 (POST /register, phone+password+sms_code)
  → 返回 user_id, token
  → 登录 (POST /login, phone+password+captcha)
    → 返回 token, user_hash
    → 浏览 (GET /product-list, page+category)
      → 下单 (POST /create-order, product_no+quantity+address_id)
        → 返回 order_no
        → 支付 (POST /pay, order_no+pay_method+amount)
          → 退款 (POST /refund, order_no+refund_amount+reason)

## 商户流
...

## 管理流
...

## 跨流参数传递

| 上游接口 | 输出参数 | 下游接口 | 输入参数 | 越权风险 |
|---|---|---|---|---|
| POST /create-order | order_no | POST /refund | order_no | 用他人 order_no 退款 |
| GET /product-list | product_no | POST /create-order | product_no | 篡改不存在的商品 |
...
```

### 注意事项

- 重点关注**跨流参数传递**：A 接口返回的 ID 喂给 B 接口，是 IDOR 的高产路径
- 记录响应中暴露的内部 ID（user_id、order_no、merchant_id）——这些都是潜在的越权参数
- 注意状态流转：审核状态、订单状态、支付状态——状态机漏洞是常见的业务逻辑漏洞

---

## 0.4 攻击面清单生成（2 分钟）

**目标**：将前几步的产出合并为结构化的攻击面清单，按优先级排序。

### 操作步骤

1. **从 `endpoint_inventory.md` + `business_flow.md` 合并生成攻击面清单**

2. **每个 surface 必须包含以下字段**：
   - `#`：编号（S01、S02...）
   - `endpoint`：API 路径
   - `method`：HTTP 方法（GET/POST/PUT/DELETE）
   - `param`：关键参数名
   - `role`：所需角色（anon / user / merchant / admin）
   - `risk_tags`：风险标签（auth-flow / amount-tamper / idor / input-validation 等）
   - `status`：初始状态一律为 `not_tested`

3. **按优先级分桶排序**（与 hint.md 对齐）：
   - Priority 1: Auth & Verification（认证、注册、验证码）
   - Priority 2: Transaction & Payment（支付、充值、退款、积分）
   - Priority 3: IDOR & Privilege（越权、对象级授权）
   - Priority 4: Input Validation（注入、文件上传、SSRF、重定向）
   - Priority 5: Admin & Merchant Panel（管理后台、商户面板）

4. **输出**：写入 `attack_surface_list.md`（格式见下方 §攻击面清单格式）

### 注意事项

- 每个端点的每个关键参数都应该有独立的 surface 行——不要把所有参数塞在一行
- 同一个端点在不同角色下可能有不同的风险，需要分别列出
- 如果 hint.md 指定了特定优先级方向，确保该方向的 surface 排在最前面

---

## 0.5 完整性检查

**目标**：确认攻击面清单没有遗漏重要方向。

### 操作步骤

1. **对照 authz.md 中的测试策略**：确认每个优先级方向都至少有 1 个 surface。

2. **对照核心技能文件的决策树分支**：确认没有空白方向。特别检查：
   - 认证面是否完整（注册 / 登录 / 找回 / 验证码 / SMS）
   - 交易面是否完整（支付 / 退款 / 订单 / 积分 / 优惠券）
   - 对象参数是否都生成了 IDOR surface（user_id / order_no / product_no / merchant_id）
   - 输入类参数是否都生成了注入 surface（keyword / sort / filter / filename）

3. **如果有方向无 surface** → 回到 0.1 补充 JS 分析，或手动探测：
   - 尝试猜测常见路径：`/api/user/reset-password.php`、`/api/admin/export.php`
   - 检查 robots.txt、sitemap.xml 中的隐藏路径
   - 检查 JS 中被注释掉或条件编译的 API 路径

---

## 攻击面清单格式

Phase 0 的最终产物 `attack_surface_list.md` 应使用以下格式：

```markdown
# Attack Surface List · <session_id>

## Priority 1: Auth & Verification
| # | endpoint | method | param | role | risk_tags | status |
|---|---|---|---|---|---|---|
| S01 | /api/user/register.php | POST | captcha,sms_code | anon | auth-flow,captcha-bypass | not_tested |
| S02 | /api/user/login.php | POST | username,password,captcha | anon | auth-flow,enum | not_tested |
| S03 | /api/user/forgot-password.php | POST | phone,sms_code | anon | auth-flow,sms | not_tested |
...

## Priority 2: Transaction & Payment
| # | endpoint | method | param | role | risk_tags | status |
|---|---|---|---|---|---|---|
| S10 | /api/user/refund.php | POST | order_no,refund_amount | user | amount-tamper | not_tested |
...

## Priority 3: IDOR & Privilege
| # | endpoint | method | param | role | risk_tags | status |
|---|---|---|---|---|---|---|
| S20 | /api/user/order-detail.php | GET | order_no | user | idor,object-ownership | not_tested |
...

## Priority 4: Input Validation
| # | endpoint | method | param | role | risk_tags | status |
|---|---|---|---|---|---|---|
| S30 | /api/user/search.php | GET | keyword | user | input-validation,sqli | not_tested |
...

## Priority 5: Admin & Merchant Panel
| # | endpoint | method | param | role | risk_tags | status |
|---|---|---|---|---|---|---|
| S40 | /api/admin/user-list.php | GET | page,keyword | admin | privilege,enum | not_tested |
...
```

**status 字段允许值**：`not_tested` / `confirmed` / `not_vulnerable` / `shallow_negative` / `blocked`

---

## 攻击面完整性门（Phase 0 结束时必检）

Phase 0 结束后，在正式进入测试之前，执行以下完整性检查。
对照清单逐项确认，**每个方向至少有 1 个 surface**：

```
□ 认证注册面 (register/signup)
□ 认证登录面 (login/signin)
□ 认证找回面 (forgot-password/reset-password)
□ 验证码/captcha 面
□ SMS/邮件验证码面
□ 支付/充值面 (pay/recharge/charge)
□ 退款面 (refund/return)
□ 订单面 (order/checkout/cart)
□ 积分/优惠券/抽奖面 (points/coupon/lottery)
□ 文件上传面 (upload/file)
□ 搜索/筛选面 (search/filter/sort)
□ 用户资料面 (profile/account/settings)
□ 对象详情页 (detail/show/view + id/no 参数)
□ 管理面 (admin/dashboard/manage)
□ 商户/商家面 (merchant/shop/store)
□ 支付/回调 HTML 页面 (pay/*/callback/*)（v7.1 新增）
□ 表单 action 页面 (form action 路径)（v7.1 新增）
```

### 处理方式

- **某方向无 surface 但目标确实没有该功能**（如无积分系统）→ 标记为 `N/A`，不阻塞
- **某方向无 surface 且不确定目标是否有该功能** → 继续侦察：
  - 手动探测常见路径
  - 检查 JS 中未加载的模块
  - 检查 robots.txt / sitemap.xml
- **某方向无 surface 且确认目标有该功能但找不到端点** → 标记 `NEED_INPUT`，请求人工协助
- **所有方向均已覆盖** → 通过完整性门，进入正式测试阶段

---

## 快速参考：Phase 0 时间分配

| 步骤 | 时间 | 产出 |
|---|---|---|
| 0.1 页面与 JS 分析 | 5 分钟 | endpoint_inventory.md |
| 0.1.5 非 API 页面与表单扫描（v7.1） | 2 分钟 | 更新 endpoint_inventory.md（[HTML] 前缀） |
| 0.2 API 端点枚举 | 3 分钟 | 更新 endpoint_inventory.md |
| 0.3 业务流建模 | 5 分钟 | business_flow.md |
| 0.4 攻击面清单生成 | 2 分钟 | attack_surface_list.md |
| 0.5 完整性检查 | — | 通过完整性门或回补 |
| **合计** | **~17 分钟** | **完整攻击面清单** |

> Phase 0 的时间投入是值得的：侦察阶段多花 5 分钟，测试阶段可以少浪费 30 分钟。
> 不要跳过 Phase 0 直接开始测试——没有地图的探险只会走弯路。
