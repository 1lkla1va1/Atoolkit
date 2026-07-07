# Skill Mode 按需参考

> 本文件是核心技能文件的按需参考。在需要写 finding/negative 或查阅详细协议时读取。
> 不在启动时加载，由核心文件中的指针引导按需读取。

---

## 开放重定向的"结果"判定

**单独存在 = 现象（不报）：** redirect 参数指向外部 URL，但无其他漏洞可链。

**构成结果（报）的条件——满足任一即可：**
1. 重定向目标页能窃取 token/session（如 redirect 到钓鱼页 + 页面包含登录表单）
2. 重定向可与 OAuth/SSO 回调链式利用，劫持授权码
3. 重定向可绕过 referer 检查（如支付回调的 redirect 被 302 到外站，泄露 sign/token）
4. 重定向可与 SSRF 链式利用（redirect URL 被服务端 fetch 而非浏览器跳转）

**测试 checklist（每个 redirect 参数）：**
- 替换为外部 URL → 是否 302/303 跳转？
- 替换为含 token 的 URL → 跳转后 URL 是否泄露敏感参数？
- 与 OAuth/支付回调组合 → 能否劫持回调？
- 服务端是否 fetch 了 redirect URL → SSRF 链？

---

## 覆盖台账 Markdown 格式

Skill Mode 使用轻量 markdown 覆盖表，在 Phase 0 生成后边走边更新状态列：

```markdown
| # | surface | status | evidence | depth | note |
|---|---|---|---|---|---|
| S01 | POST /register captcha | not_vulnerable | NF-001 | ✓ 5 vectors | captcha 服务端校验有效 |
| S03 | POST /refund amount | confirmed | finding_001 | ✓ 4 vectors | 退款金额无上限校验 |
| S05 | GET /balance-records | shallow_negative | NF-005 | ✗ 数据为空 | 需创建余额记录后重测 |
```

`status` 列只允许：`not_tested / confirmed / not_vulnerable / shallow_negative / blocked / exploring`。
`depth` 列只允许：`✓`（达到 depth floor）或 `✗ <原因>`。
终态时 `not_tested` 的高价值 surface → 终态标 `incomplete`。

**并行模式**：每个 agent 各写一份带前缀的覆盖表（`coverage_auth.md`、`coverage_txn.md` 等），聚合阶段合并去重。

---

## 阴性落盘完整格式

Skill Mode 使用合并文件 `negative_findings.md`，每条阴性为结构化段落：

```markdown
## NF-001: search.php SQLi
- **endpoint:** GET /api/user/search.php
- **param:** keyword
- **vuln:** sql-injection
- **roles:** anonymous, user
- **vectors tested:** classic (3), UNION (2), blind-time (2), blind-bool (2), error (1) = 10 vectors
- **result:** all returned normal results or error pages, no data extraction
- **evidence:** response contained 0 products for injection payloads vs 1 for normal
- **depth_floor_met:** yes (≥3 families, ≥10 vectors)
- **status:** not_vulnerable
- **next_actions:** none
```

**Skill Mode 阴性记录建议：**
- 建议包含 `vectors tested` 描述（已测试的向量类型和数量），便于审计深度
- 建议包含 `depth_floor_met: yes/no`（声明测试深度是否充分）
- 测试深度不充分的标 `status: shallow_negative` + `next_actions`

---

## 存储型漏洞闭环验证协议

对任何接受文本输入并可能持久化的端点（提交审核、创建商品、修改资料、发布评论），POST 后必须执行闭环验证：

| 步骤 | 操作 | 判定标准 |
|---|---|---|
| 1. 注入 | POST 含 XSS/注入 payload 的数据 | 记录 POST 响应（即使为空/200） |
| 2. 读取 | GET 对应资源的展示页面（列表/详情/后台） | 检查 payload 是否出现在响应中 |
| 3. 渲染验证 | 检查 payload 是否被原样渲染（未编码） | `<script>` 或 `onerror=` 原样出现 → confirmed |
| 4. 跨用户验证 | 用另一个身份 GET 该资源 | 跨用户可见 → 存储型 XSS（严重度升级） |

**关键端点清单（必须闭环验证）**：提交审核（submit-audit, audit-description, review-text）、商品描述（product-name, product-description）、用户资料（nickname, bio, address）、评论/反馈（comment, feedback, message）、工单/申诉（ticket-description, appeal-reason）。

**约束：POST 返回空/200 不等于安全。** 必须执行步骤 2-4 才能下阴性结论。如果步骤 2 无法找到展示页面 → 标 `blocked` + `stored_but_unverified`。

---

## 业务逻辑攻击模式库

蒸馏自 WooYun 8,292 案例的 6 种高频攻击模式：

**模式 1 · 竞态条件**（Critical-rate 88%，777 案例）：对积分兑换、优惠券使用、库存扣减、余额转账等"检查-执行"操作，发送 10-100 个并发请求，观察 TOCTOU 窗口——积分余额只检查一次但执行多次扣减、优惠券状态检查和标记使用之间存在时间差、库存扣减和订单确认非原子操作。测试方法：多线程/asyncio 同时发送 N 个相同请求，对比执行结果数 vs 扣减次数。

**模式 2 · 支付回调伪造**（Critical-rate 74.2%，1,227 案例）：对支付回调端点（notify/callback/webhook），测试回调签名是否可伪造、回调参数是否可篡改（trade_status/out_trade_no/total_amount）、回调是否验证来源 IP、回调是否做幂等处理。

**模式 3 · 价格/金额篡改**（Critical-rate 83%，176 案例）：对下单/支付/退款端点，测试客户端提交 price/amount 是否被服务端覆盖、参数污染（`price=299&price=0.01`）、类型混淆（`{"price": "0.01"}` 字符串 vs 数字）、科学记数法（`{"price": 1e-10}`）、NULL 注入（`{"price": null}`）、精度溢出（`{"price": 0.001}`）。

**模式 4 · 密码重置流程绕过**：详见下方"密码重置 4 模式检测"。

**模式 5 · 优惠券/积分滥用**：优惠券叠加（同一订单使用多张互斥优惠券）、优惠券退款（使用优惠券后退款按原价计算）、积分竞态（并发兑换同一积分池）、积分精度（使用 0.1 个积分当最小单位是 1）。

**模式 6 · 响应篡改绕过前端校验**：拦截验证码错误响应 `{"status":"0","msg":"验证码错误"}` → 修改为 `{"status":"1","msg":"成功"}` → 观察前端是否进入下一步（前端信任了响应状态但后端是否在下一步重新验证前置条件）。

---

## 密码重置常见攻击模式（参考）

以下是密码重置/找回流程中常见的 4 种攻击模式，供测试时参考：

- **A · 验证码回显**：发送验证码后检查响应 body/headers/cookie 中是否包含验证码值（严重度：极高，直接泄露）
- **B · 验证码跨用户**：用 A 手机收验证码，在 B 的重置流程中使用 A 的验证码（严重度：高，验证码未绑定用户）
- **C · 步骤跳过**：直接构造重置第 3 步（设置新密码）的请求，跳过第 2 步（验证身份）（严重度：高，流程可跳步）
- **D · 可控目标**：重置请求中修改 username/phone/user_id 参数，观察是否重置了他人密码（严重度：极高，任意用户重置）

**建议测试顺序**：先测 A（最简单，直接看响应），再测 D（影响最大），然后 B 和 C。

---

## 文件上传全参数枚举

文件上传接口的测试不应只关注文件本身（filename/content-type/content）。上传接口的非文件参数也可能存在风险，常见方向包括：

- **分类/目录参数**（`category, dir, folder, module, type`）：测试 `../../../etc`, `..\\..\\..\\windows`, `%2e%2e%2f`, `....//` → 文件被存储到预期目录外
- **文件名参数**（`filename, name, newname, save_name`）：测试 `../../../tmp/shell`, `shell.php%00.jpg`, `shell.phtml` → 路径穿越或扩展名绕过
- **大小/限制参数**（`max_size, size_limit, width, height`）：测试 0, -1, 99999999, 超大值 → 绕过大小限制
- **回调/URL 参数**（`callback, return_url, redirect`）：测试外部URL, `javascript:`, `data:` → SSRF 或重定向
- **元数据参数**（`title, description, alt, tag`）：测试 XSS payload → 元数据被原样渲染

如果只测了 file/filename 而未关注 category/dir/module 等参数，可能会遗漏路径穿越类漏洞。

**WooYun 高频路径穿越向量**：`../../../etc/passwd`（频率最高）、`%2e%2e%2f`（URL编码）、`%252e%252e%252f`（双重URL编码）、`....//`（双点+双斜杠）、`..%5c`（Windows反斜杠）、`%c0%ae%c0%ae/`（UTF-8过度编码）。

---

## WAF 绕过技术参考

当注入 payload 被拦截时，以下是常见的绕过技术分类，供灵感参考：

**判断拦截类型**
- 响应 body 含"关键字/keyword/illegal" → 关键字匹配型
- 403 无特定信息 → IP/频率限制型
- body 被截断或部分替换 → 正则替换型
- 响应正常但 payload 被去除 → 净化型

**按拦截类型的常见绕过方向**
- 关键字匹配型 → 大小写混淆（`uNiOn sElEcT`）→ 注释穿插（`/*!50000union*/ select`）→ 空白替换（`%09`/`%0a`/`%0b`/`%0c`）
- 正则替换型 → 编码绕过（URL/双重URL/Unicode/Hex）→ 函数等价替换（`substr→mid→left+right`、`sleep→benchmark`）
- 净化型 → 双重编码 → 分块传输（`Transfer-Encoding: chunked`）→ 参数污染（HPP）→ Content-Type 切换
- 不确定 → 多种技术组合尝试

**绕过成功判定**
payload 未被拦截且返回正常响应格式 → 在此基础上验证注入是否生效 → 记录绕过方式作为 PoC 一部分。

**进阶绕过维度（传统方法失效时）**

当编码变体、大小写混淆、注释穿插等传统方法全部失败时，说明 WAF 在字符串层面做了充分覆盖。此时需要从更深的维度寻找绕过空间：

- **传输层绕过**：利用 HTTP 协议特性制造 WAF 与后端的解析差异
  - 参数数组化：`id=1' OR 1=1--` → `id[]=1' OR 1=1--`（PHP 接收数组，WAF 可能只检字符串）
  - 参数名污染 (HPP)：`id=1&id=' OR 1=1--`（不同中间件对重复参数的取值规则不同）
  - multipart 解析差异：将 payload 放在 multipart body 的非标准位置
  - Content-Type 切换：同一请求体以 `application/json` / `application/x-www-form-urlencoded` / `multipart/form-data` 分别发送，WAF 可能只解析其中一种

- **解析层绕过**：利用后端引擎与 WAF 的 Unicode/编码规范化时序差
  - Unicode 规范化差异：WAF 看到 `%u0027` (') 放行，后端规范化后得到 `'`
  - 宽字节注入：GBK 环境下 `%df%27` → 后端视为合法宽字符 + `'`，WAF 视为独立字节
  - JSON 嵌套/类型混淆：`{"id": "1 OR 1=1"}` vs `{"id": 1}` vs `{"id": [1, "OR 1=1"]}`
  - 注释嵌套：`/**/UNION/**%0a/SELECT` — WAF 和 DB 对注释边界的理解可能不同

- **逻辑层绕过**：用 WAF 不认识的等价表达式替代已知关键字
  - 算术等价：`OR 1=1` → `OR 2>1` → `OR 3-2=1` → `OR NOT 0`
  - 函数等价：`UNION SELECT` → `UNION ALL SELECT` → `GROUP BY` + `HAVING` 泄露
  - 字符串构造：`'admin'` → `CONCAT('ad','min')` → `CHAR(97,100,109,105,101)`
  - 条件表达：`IF(1=1,a,b)` → `CASE WHEN 1=1 THEN a ELSE b END` → `ELT(1,a,b)`

- **盲注特化策略**：当显注 (UNION/OR/AND) 全部被拦但盲注可能存活时
  - 优先使用布尔盲注：不注入关键字，只观察响应差异（行数/内容/长度变化）
  - 时间盲注作为后备：`SLEEP(5)` 被拦 → `BENCHMARK(10000000,SHA1('a'))` → 条件延迟
  - 基于错误的注入：`extractvalue(1,concat(0x7e,(SELECT ...)))` — 不走 UNION/OR 关键字

**WAF 绕过优先级建议**：传统字符串绕过 → 等价表达式替换 → 传输层/解析层 → 盲注特化。每升一级需要的请求数更多，但绕过的概率也更高。

---

## 链式利用评估框架

每个 CANDIDATE（组件级弱点）在判 confirmed/not_vulnerable 之前，必须回答链式评估三问：

**Q1：这个弱点能链接到什么？**
- 验证码不消耗/可复用 → 暴力破解验证码 → 任意用户注册/密码重置
- 配置文件/密钥泄露 → 伪造 token/签名 → 管理员操作
- SQLi 读数据 → 获取密码 hash → 碰撞登录 → 后台权限
- XSS → 窃取 Cookie → 账户接管 → 进一步操作
- SSRF → 访问内网服务 → 获取元数据(AWS 169.254) → 云凭证窃取
- 竞态条件 → 重复消费积分/优惠券 → 资金损失

**Q2：链式路径中每一步的前置条件是否满足？** 不满足 → 记录为 `next_actions`；可满足 → 执行链式验证。

**Q3：链式利用的最终影响是什么？** 账户接管（ATO）/ 权限提升 / 资金损失 / 数据泄露 / 服务器接管（RCE）。

**chain_assessment 字段格式**：每个 CANDIDATE 必须包含：
- `chain_feasible`: true/false
- `chain_path`: "步骤1→步骤2→最终影响"
- `final_impact`: "..."
- `blockers`: []

---

## Finding 包结构（P1/P2/P3）

```
findings/finding_<id>/
  finding.json
  request_1.http
  response_1.http
  poc.sh
```

`finding.json` 是权威报告输入。Engine Mode 必须包含完整 schema（`engine/reporting/schema.py`）。

**Skill Mode 精简 schema（8 必填 + 3 条件必填）**：

必填：`schema_version`（"1.0"）/ `id` / `title`（结果描述非现象）/ `severity`（P1/P2/P3）/ `vuln_type` / `target`（endpoint+method）/ `risk.proven_impact`（已证明结果）/ `poc`（file+steps）/ `proof_packets`（request/response 文件对）。

条件必填：
- `source_proof`：从 JS/源码构造数据包时，写明文件、行号
- `crypto_chain`：有加密链路时，写明算法、key 来源
- `manual_burp_replay`：P1/P2 选填（Skill Mode 下 agent 无法运行 Burp Suite）

通用规则：
- `risk.proven_impact` 只能写已证明结果，不能写"可能/疑似/理论上"
- `proof_packets[].request_file`、`response_file`、`poc.file` 对应文件必须真实存在

若当前运行环境尚未接入 reporting 模块，可临时写 `report_*.md`，但必须按同等字段完整呈现证据链。


---

## HackerOne 次级参数速查表（按需检索）

> 仅当主参数（id/user_id/keyword/url 等）测试阴性时查阅。
> 数据来源：HackerOne 3319 份高质量报告（resolved + bounty + full visibility），已过滤框架/行业/技术栈专有参数与低频弱语义参数。

**SQLi 次级**（当 keyword/search/id 均阴性时）
hash（哈希查询）, acctid（账户 ID）, regid（注册 ID）, organization_id, post_type

**IDOR 次级**（当 id/user_id/order_id 均阴性时）
target_id, target_type, accounts, group_id, selectedaddressid, time_range

**SSRF 次级**（当 url/image_url 均阴性时）
import_url, callback_url, svg（SVG 文件 SSRF）, protocol（协议切换）

**PathTraversal 次级**（当 filename/category 均阴性时）
filepath, file_path, filepathdownload

**OpenRedirect 次级**（当 redirect/return_url 均阴性时）
redirect_uri（OAuth）, redir, next, return_to, redirect_to, goto, target, response_type, scope, state

**AuthBypass 次级**（当 username/password 均阴性时）
authenticity_token, auth_type, client_id, redirect_uri, _method（HTTP 方法覆盖）, auth_code

---

## 12. Payload 多样性与编码感知

### 为什么同一 payload 在不同格式下结果不同

Web 应用通常有多层输入处理：Web 服务器解码 → 框架预处理 → 应用层验证 → 数据库查询。
每一层可能对特殊字符做不同的处理（解码、转义、截断、过滤）。

常见场景：
- PHP `$_GET`/`$_POST` 自动 URL 解码一次，但 `php://input`（JSON body）不解码
- Apache mod_rewrite 对 URL 路径做一次解码，query string 不解码
- WAF 在解码后的字符串上匹配关键字，但应用层在原始字符串上查询
- JSON body 中的 `\u0027`（单引号 Unicode）可能绕过基于字节匹配的 WAF

### 实战案例

| 场景 | 原始格式 | 结果 | 编码格式 | 结果 |
|------|---------|------|---------|------|
| search.php keyword | `' OR '1'='1` | 空结果（被预处理拦截） | `'+OR+'1'%3D'1` (URL编码) | 返回全部商品 |
| product-delete product_no | `' OR 1=1--` | WAF拦截 | `%27%20OR%201%3D1--` | WAF放行 |
| upload category | `../../../etc` | 字面存储 | `..%2f..%2f..%2fetc` | 路径穿越 |

### 编码变体测试顺序（启发性）

当 payload 无效果时，按以下顺序尝试编码变体，而不是立即切换 payload：
1. 原始格式（直接发送）
2. URL 编码（`%xx`）
3. 双重 URL 编码（`%25xx`）
4. Unicode 转义（`\u00xx`，适用于 JSON body）
5. 混合编码（关键字 URL 编码，非关键字原始）

---

## 13. 支付流程端点追踪

### 为什么容易遗漏支付端点

电商/商城类应用的支付流程通常由多个端点组成，但前端 JS 可能只暴露部分端点
（如 batch 版本隐藏了单条版本，前端跳转隐藏了 API 端点）。

### 完整支付生命周期

```
create-order ──→ pay/index ──→ payment-gateway ──→ callback
    │               │                                │
    │               └── redirect（支付后跳转）         │
    │                                                 │
    └── create-batch-order（批量版本）                 │
                                                      ▼
                              recharge-create ──→ recharge-callback
                                   │
                                   └── balance-pay ──→ single-balance-pay
                                                           │
                                                           ▼
                                                     refund / cancel
```

### 必须检查的端点

每个支付相关端点都必须：
1. 检查是否有单条/批量两个版本（`create-order` vs `create-batch-order`）
2. 检查支付页面（`pay/index.php`）中的 redirect/return_url/callback_url 参数
3. 检查回调接口是否验证签名来源（不能只依赖前端传来的 sign）
4. 检查充值和支付是否共享余额通道（充值漏洞可能影响支付）
5. 检查取消/退款是否在支付完成后仍可执行

### 常见遗漏模式

- `pay/index.php` 的 GET 参数（redirect, sign, order_no）经常被忽略，
  因为前端 JS 可能只使用 POST body
- 单条操作端点（`create-order.php`）在只有批量版本（`create-batch-order.php`）
  的 JS 中不可见，但服务端可能两个都存在
- 支付回调的 `callback_sign` 可能在 create 接口的响应中泄露

---

## 14. Intent 驱动链式利用实战案例

> 以下 3 个案例展示 Fact-Intent Graph 如何将单点发现转化为完整攻击链。
> 每个案例对应一条 IntentRuleEngine 规则，演示从 Fact 生成 Intent 到执行验证的完整流程。

### 案例 1：充值回调签名泄露 → 伪造充值

**触发规则：`info_leak_credential`**（信息泄露 → 凭证利用）

**Fact**
- 来源端点：`GET /api/user/recharge-create.php`
- 发现：响应 JSON 中包含 `callback_sign` 字段（本应只在服务端使用的签名密钥）
- `source_type: info_disclosure`，`vuln_class: info-leak`
- 规则匹配：summary 含 "泄露" + "sign" → 触发 `info_leak_credential`

**Intent 生成**
```json
{
  "source": "escalation",
  "description": "利用泄露的 callback_sign 伪造充值回调（寻找使用该凭证的下游端点）",
  "vuln_class": "privilege-escalation",
  "priority": "high",
  "target_endpoint": ""
}
```
> `target_endpoint` 为空——agent 需自行从业务图谱或端点枚举中发现充值回调端点。

**Action**
1. 从业务图谱 `business_flows` 中找到充值流程：`recharge-create → recharge-callback`
2. 定位 `POST /api/user/recharge-callback.php`
3. 用泄露的 `callback_sign` 构造伪造回调请求：
   ```
   POST /api/user/recharge-callback.php
   trade_no=FAKE001&amount=10000&status=success&sign={泄露的callback_sign}
   ```
4. 发送伪造回调 → 服务端验证签名通过 → 余额增加 10000

**Result**：充值回调被成功伪造，任意金额充值已验证。从 info-leak 升级为 P1 资金漏洞。

**关键教训**：`info_leak_credential` 规则的核心价值是引导 agent **主动寻找使用泄露凭证的下游端点**，而不是停留在"发现了泄露"这一步。泄露本身是 P3，但伪造回调是 P1。

---

### 案例 2：验证码不消耗 → SMS 暴力破解 → 任意密码重置

**触发规则：`auth_chain`**（认证组件弱点 → 链式利用）

**Fact**
- 来源端点：`POST /register.php`（验证码校验）
- 发现：captcha 验证码不消耗——同一个验证码可重复提交多次，服务端不标记已使用
- `source_type: confirmed`，`vuln_class: captcha-bypass`，`chain_feasible: true`
- 规则匹配：confirmed + auth 类 vuln_class + chain_feasible → 触发 `auth_chain`

**Intent 生成**
```json
{
  "source": "chain",
  "description": "链式利用：captcha不消耗→暴力破解SMS码→密码重置",
  "vuln_class": "auth-bypass-chain",
  "priority": "high"
}
```

**Action**
1. 确认密码重置流程：`forgot-password.php` → 发送 SMS 验证码 → 输入验证码 → 设置新密码
2. 用固定 captcha 值反复提交 SMS 验证码猜测请求（6 位数字 = 1,000,000 种组合）
3. 因为 captcha 不消耗，无需每次重新获取验证码，单次请求成本极低
4. 批量发送 `POST /forgot-password.php`，body 中 captcha 固定 + sms_code 从 000000 遍历
5. 命中正确 SMS 码后进入密码重置步骤 → 设置新密码

**Result**：成功重置任意用户密码。从 captcha-bypass（P3）升级为完整 ATO 攻击链（P1）。

**关键教训**：`auth_chain` 规则将**单点认证弱点**（captcha 不消耗）自动升级为**完整认证攻击链**。单独的 captcha 不消耗看似影响有限，但它是暴力破解 SMS 码的关键前置条件——没有这个弱点，每次猜错都需要新 captcha，暴力破解不可行。

---

### 案例 3：WAF 拦截后的 Intent 驱动重测

**触发规则：`waf_bypass_retry`**（WAF 拦截 → 编码变体重试）

**Fact（阴性）**
- 来源端点：`GET /api/user/search.php?keyword=`
- 发现：经典 SQL payload（`' OR '1'='1`、`UNION SELECT`）全部被 WAF 拦截
- `source_type: negative`，summary 含 "WAF 拦截" / "blocked"
- 规则匹配：negative + WAF 关键字 → 触发 `waf_bypass_retry`

**Intent 生成**
```json
{
  "source": "anomaly",
  "description": "WAF 绕过重测：search.php keyword 参数编码变体",
  "vuln_class": "sql-injection",
  "priority": "medium",
  "target_endpoint": "/api/user/search.php",
  "target_params": ["keyword"]
}
```

**Action**
1. 按编码变体优先级顺序重试（参考 §12 Payload 多样性与编码感知）：
   - 原始：`' OR '1'='1` → 403 WAF 拦截
   - URL 编码：`%27%20OR%20%271%27%3D%271` → 403 WAF 拦截
   - 双重 URL 编码：`%2527%2520OR%2520%25271%2527%253D%25271` → 403 WAF 拦截
   - Unicode 转义（JSON body）：`{"keyword": "'\u0020OR\u0020'\u0031'\u003D'\u0031"}` → 403
   - 混合编码（关键字 URL 编码）：`%27 OR '1'='1` → **200 正常响应，返回全部商品**
2. 确认绕过有效 → 进一步验证数据提取能力 → UNION 查询成功

**Result**：URL 编码单引号 + 原始 OR 关键字的组合绕过了 WAF。search.php SQLi 从阴性翻转为 confirmed（P2）。

**关键教训**：`waf_bypass_retry` 规则确保 **WAF 拦截 ≠ "不存在漏洞"**。v8.3 中 WAF 拦截直接标记阴性并跳过；v8.4 的 Intent 机制将"WAF 拦截"视为一个**异常信号**而非终点，驱动 agent 系统性尝试编码变体。很多真实漏洞就藏在 WAF 的解码盲区中。
