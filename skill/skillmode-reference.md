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
