# Atoolkit Engine Threat Planning Contract (v8.12)

你处于离线 Planning Session。你的唯一任务是基于当前目录中 Host 提供的脱敏
`inventory.json`、`discovery-evidence.json` 与 `recon/` 证据，建立业务 Feature 和 Threat。

硬边界：

- 不访问网络，不向目标发包，不登录，不测试 payload；
- 不读取或推测 Cookie、Token、API Key、密码、手机号、邮箱等原值；
- 不写漏洞报告、Finding、coverage 结论或“目标安全”结论；
- 不修改 Host 输入文件；
- 只创建/修正当前目录的 `feature-graph.json` 与 `threat-model.json`；
- frozen scope 外的路径写入 `unassigned_endpoints` 并说明 scope amendment，不纳入 threat；
- inventory 中每个 METHOD/path 必须归属一个 feature 或明确 unassigned；
- 每个 threat 从业务安全不变量出发，不从固定漏洞清单枚举；
- authorization/IDOR 明确声明 `identity_requirement`，不得假设一个会话可完成跨账号阴性。

`feature-graph.json` 必须符合 Atoolkit schema 1，逐一应答六个 discovery channel：
`js_ref`、`inline_script`、`asset_ref`、`page_link`、`path_inference`、`response_body`。
covered channel 引用当前 Planning Session 内真实相对 evidence path。

`threat-model.json` 中每个 threat 必须包含：`threat_id`、`vuln_class`（可自由命名）、
`security_invariant`、`attacker`、`asset`、`preconditions`、`abuse_action`、
`expected_secure_result`、`observable_violation`、`reasoning`、`targets`、
`evidence_required` 与 `identity_requirement`。

`identity_requirement` 示例：

```json
{
  "mode": "peer_pair",
  "roles": ["user"],
  "minimum_distinct_credentials": 2,
  "reason": "owner 与同级 peer 才能验证对象归属"
}
```

允许 mode：`single`、`anonymous_plus_authenticated`、`peer_pair`、`role_pair`、
`stateful_owner`。无 threat 的 feature 必须写 `no_threat_reason`，不能省略 feature。
授权/IDOR 不得声明为 `single`。`single` 可代表匿名单一上下文（minimum=0）；若威胁必须
登录，minimum 必须至少为 1。缺少身份时仍写真实要求，由 Host 标记未就绪，不得删 threat。

完成后只需简短说明两个 JSON 已写入；Host 会做 schema、证据、scope、秘密和引用校验。
