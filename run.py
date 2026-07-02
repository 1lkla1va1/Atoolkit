#!/usr/bin/env python3
"""run.py —— 一条命令起一次授权 SRC 会话。

把 engine 三件套(orchestrator+enforce+verify) + Codex 适配器接成入口。
本文件只做接线，不含新逻辑（逻辑在 engine/ 与 codex/）。

用法：
  # 真实跑（用 Codex）
  python3 run.py --target https://t.example --authz "仅限 https://t.example，已授权" \
      --cookie 'session=...' [--model gpt-5.5-codex] [--allow t2.example] \
      [--identity owner:session=A --identity attacker:session=B --victim-marker '收货地址']

  # 不接模型/网络，自检接线是否通（用 MockAdapter）
  python3 run.py --dry-run --target https://t.example --authz "demo"

换模型：改 --model 即可；换运行时：把 CodexAdapter 换成别的 ModelAdapter（本文件 1 处）。
"""
from __future__ import annotations
import argparse, inspect, sys, time, re, pathlib, json

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from engine.orchestrator import run_session, MockAdapter          # noqa: E402
from engine.verify import (verify_idor, extract_poc, urllib_transport,  # noqa: E402
                           VerifyResult, INCONCLUSIVE,
                           extract_poc_from_finding)


def host_of(url: str) -> str:
    m = re.match(r"https?://([^/:]+)", url)
    return m.group(1) if m else url


def build_verify_fn(identities: dict, victim_marker: str, hosts: list[str]):
    """对 Guardian accepted 的报告做确定性重放复验。无身份/无标记则不复验。"""
    if not identities or not victim_marker:
        return None
    def verify_fn(report_md: str) -> VerifyResult:
        req = extract_poc(report_md)
        if req is None:
            return VerifyResult(INCONCLUSIVE, "报告无可解析 PoC")
        return verify_idor(req, identities, victim_marker, urllib_transport, hosts)
    return verify_fn


def _oracle_hit_str(oracle_path: str, res: dict) -> str:
    """用 engine.benchmark_eval 算 oracle 命中：hit = 有 confirmed surface 命中的 oracle case 数。

    finding 从 coverage-ledger 的 confirmed surface 构造（endpoint 用 seed 行写法，与 oracle 同形），
    而非从 report .md 的具体 id 形态构造——避免 {id} 占位符与 1001 对不上的失配。
    无 ledger / 无 oracle / 解析失败 → 'N/A'。"""
    ledger_path = res.get("coverage_ledger_path")
    if not ledger_path:
        return "N/A"
    try:
        from engine import benchmark_eval as be
        from engine.ledger import CoverageLedger, STATUS_CONFIRMED, normalize_status
        oracle = be.load_oracle(pathlib.Path(oracle_path))
        ledger = CoverageLedger.load(pathlib.Path(ledger_path))
        findings = []
        for s in ledger.surfaces:
            if normalize_status(s.get("status")) != STATUS_CONFIRMED:
                continue
            params = [s["param"]] if s.get("param") else []
            findings.append(be.Finding(
                id=s.get("surface_id") or "",
                title=str(s.get("legacy_vuln") or ""),
                endpoints=[s.get("endpoint", "")] if s.get("endpoint") else [],
                methods=[s.get("method", "")] if s.get("method") else [],
                params=be._dedupe(params),
                vuln_class=str(s.get("legacy_vuln") or ""),
                roles=be._dedupe(s.get("roles") or []),
                evidence_file=s.get("evidence_ref") or "",
                raw=s,
            ))
        coverage = be.load_coverage(pathlib.Path(ledger_path))
        ev = be.evaluate(oracle, findings, coverage)
        return f"{len(ev['hits'])}/{len(oracle)}"
    except Exception as e:                       # oracle 缺失/格式错 → 不阻断收尾打印
        return f"err:{type(e).__name__}"


def _print_open_high_value(res: dict):
    """打印未闭合高价值面清单（每条 endpoint+role+risk_tag），取自 ledger high_value not_tested/blocked。"""
    ledger_path = res.get("coverage_ledger_path")
    if not ledger_path:
        return
    try:
        from engine.ledger import (CoverageLedger, is_high_value,
                                   normalize_status, STATUS_NOT_TESTED, STATUS_BLOCKED)
        ledger = CoverageLedger.load(pathlib.Path(ledger_path))
        hv_open = [s for s in ledger.surfaces
                   if is_high_value(s)
                   and normalize_status(s.get("status")) in (STATUS_NOT_TESTED, STATUS_BLOCKED)]
    except Exception:
        return
    if not hv_open:
        print("未闭合高价值面清单: (无)")
        return
    print(f"未闭合高价值面清单 ({len(hv_open)}):")
    for s in hv_open:
        roles = ",".join(s.get("roles", [])) or "-"
        tags = ",".join(s.get("risk_tags", [])) or "-"
        print(f"  - {s.get('endpoint', '')} | method={s.get('method', 'GET')} "
              f"| role={roles} | risk_tag={tags}")


def _map_finding_for_summary(f: dict, idx: int) -> dict:
    """aggregate_findings 的 finding（root_cause/affected_role 命名）→ summary.json 行，
    补 engine.benchmark_eval.load_findings 期望的键（class/vuln_class/roles/id/endpoint）。
    不改 aggregate_findings 本身的输出，只在这份产物里做字段映射：class=root_cause、
    roles=[affected_role]、id=finding_key。method/params 留空（benchmark_eval 对空 method/params
    取宽容匹配），endpoint 保留 aggregate_findings 的可读原值。"""
    role = f.get("affected_role")
    facets = f.get("facets") or []
    endpoint = f.get("endpoint", "")
    return {
        "id": f.get("finding_key") or f"finding-{idx:03d}",
        "endpoint": endpoint,
        "endpoints": [endpoint] if endpoint else [],
        "method": "",
        "methods": [],
        "params": [],
        "evidence_file": "",
        "class": f.get("root_cause", ""),
        "vuln_class": f.get("root_cause", ""),
        "roles": ([role] if role and role != "default" else []),
        "severity": f.get("severity", ""),
        "title": facets[0] if facets else "",
        # 保留原始聚合信息（不影响 benchmark_eval 读取，仅供溯源）
        "root_cause": f.get("root_cause", ""),
        "affected_role": role,
        "facets": facets,
        "primary_impact": f.get("primary_impact", ""),
        "report_count": f.get("report_count", 0),
        "finding_key": f.get("finding_key", ""),
    }


_SUMMARY_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SUMMARY_HEXID_RE = re.compile(r"^[0-9a-fA-F]{12,}$")


def _norm_summary_endpoint(endpoint: str) -> str:
    endpoint = re.sub(r"^https?://[^/]+", "", str(endpoint or "").strip())
    endpoint = endpoint.split("#", 1)[0].split("?", 1)[0]
    segs = []
    for seg in endpoint.split("/"):
        if not seg:
            segs.append(seg)
        elif (seg.isdigit() or _SUMMARY_UUID_RE.match(seg) or _SUMMARY_HEXID_RE.match(seg)
              or (seg.startswith("{") and seg.endswith("}"))):
            segs.append("{}")
        else:
            segs.append(seg)
    return "/".join(segs)


def _dedupe_keep(values: list) -> list[str]:
    seen, out = set(), []
    for value in values:
        text = str(value or "").strip()
        if text and text.lower() not in seen:
            seen.add(text.lower())
            out.append(text)
    return out


def _summary_findings(res: dict) -> list[dict]:
    rows = [_map_finding_for_summary(f, i) for i, f in enumerate(res.get("findings") or [])]
    rows.extend(dict(f) for f in (res.get("normalized_findings") or []))
    ledger_path = res.get("coverage_ledger_path")
    if not ledger_path:
        return rows
    try:
        from engine.ledger import CoverageLedger, STATUS_CONFIRMED, normalize_status
        ledger = CoverageLedger.load(pathlib.Path(ledger_path))
        confirmed = [s for s in ledger.surfaces
                     if normalize_status(s.get("status")) == STATUS_CONFIRMED]
    except Exception:
        return rows
    for row in rows:
        row_norm = _norm_summary_endpoint(row.get("endpoint", ""))
        matches = [s for s in confirmed
                   if row_norm and _norm_summary_endpoint(s.get("endpoint", "")) == row_norm]
        if not matches:
            continue
        endpoints = _dedupe_keep(row.get("endpoints", []) + [s.get("endpoint", "") for s in matches])
        methods = _dedupe_keep([s.get("method", "") for s in matches])
        params = _dedupe_keep([s.get("param", "") for s in matches])
        evidence_files = _dedupe_keep([s.get("evidence_ref", "") for s in matches])
        row["endpoints"] = endpoints
        if endpoints and not row.get("endpoint"):
            row["endpoint"] = endpoints[0]
        row["methods"] = methods
        row["method"] = methods[0] if methods else ""
        row["params"] = params
        row["evidence_file"] = evidence_files[0] if evidence_files else ""
    return rows


def _summary_status(res: dict) -> str:
    status = str(res.get("status") or "")
    gate = res.get("session_gate") or {}
    if gate.get("result") and gate.get("result") != "pass":
        if status == "vuln_found" or res.get("accepted"):
            return "incomplete_with_findings"
        return "incomplete"
    return status


def _inventory_records_from_endpoint_arg(arg: str) -> tuple[list[str], list[dict]]:
    p = pathlib.Path(arg)
    endpoints: list[str] = []
    records: list[dict] = []
    if p.exists():
        raw_lines = p.read_text(encoding="utf-8").splitlines()
        for line_no, line in enumerate(raw_lines, start=1):
            endpoint = line.strip()
            if not endpoint or endpoint.lstrip().startswith("#"):
                continue
            endpoints.append(endpoint)
            records.append({
                "endpoint": endpoint,
                "method": "GET",
                "source": "endpoints",
                "source_file": str(p.resolve()),
                "source_line": line_no,
                "source_kind": "endpoints_file",
                "last_seen": "",
                "discovered_during_testing": False,
            })
    else:
        for index, endpoint in enumerate([x.strip() for x in arg.replace(",", "\n").splitlines()], start=1):
            if not endpoint or endpoint.lstrip().startswith("#"):
                continue
            endpoints.append(endpoint)
            records.append({
                "endpoint": endpoint,
                "method": "GET",
                "source": "endpoints",
                "source_file": "",
                "source_line": index,
                "source_kind": "cli_endpoints",
                "last_seen": "",
                "discovered_during_testing": False,
            })
    return endpoints, records


def _merge_inventory_records(records: list[dict]) -> list[dict]:
    merged: dict[tuple, dict] = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        key = (
            str(rec.get("endpoint") or ""),
            str(rec.get("method") or "GET").upper(),
            bool(rec.get("discovered_during_testing")),
        )
        if not key[0]:
            continue
        if key not in merged:
            cur = dict(rec)
            cur["method"] = key[1]
            merged[key] = cur
            continue
        cur = merged[key]
        if rec.get("last_seen") and str(rec.get("last_seen")) > str(cur.get("last_seen") or ""):
            cur["last_seen"] = rec["last_seen"]
        for field in ("source_file", "source_kind", "source", "source_line"):
            if not cur.get(field) and rec.get(field):
                cur[field] = rec[field]
    return list(merged.values())


def _run_self_check() -> int:
    """--self-check 自检门：临时生成 fixture 跑断言，不接真实模型/网络。

    三条断言（全过 exit 0，任一失败 exit 1 并打印哪条失败）：
      1. surface.bootstrap(recon_sample) 覆盖 oracle_sample 全部端点。
      2. 浅阴性 ledger（非高价值、无 next_actions 的 shallow_negative 格）→
         session_gate.evaluate_session_gate 返回 incomplete（演示 P0-2）。
      3. 合格报告（target/curl/响应证据）→ enforce.guardian_check accepted。
    纯代码自检，用于抓住 bootstrap→oracle 端点覆盖、浅阴性门、Guardian 质检的回归。
    """
    from engine.surface import bootstrap
    from engine import benchmark_eval as be
    from engine.ledger import CoverageLedger
    from engine.session_gate import evaluate_session_gate, INCOMPLETE
    from engine.enforce import guardian_check, ACCEPTED
    import tempfile, shutil

    def _write_text(path: pathlib.Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _make_self_check_fixtures(base: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        """生成自检所需的最小样例，避免把 fixtures/ 测试数据放进仓库。"""
        recon = base / "recon_sample"
        reporting = base / "reporting" / "basic_idor"
        _write_text(recon / "app.js", (
            "fetch('/api/order/detail?order_no=1');\n"
            "axios.post('/api/user/login', { password: 'redacted' });\n"
        ))
        _write_text(recon / "page.html", """<!doctype html>
<html lang="zh">
<body>
  <form action="/api/user/login" method="POST">
    <input name="password" type="password">
  </form>
  <a href="/api/order/list">order list</a>
</body>
</html>
""")
        _write_text(recon / "traffic.har", json.dumps({
            "log": {
                "version": "1.2",
                "creator": {"name": "atoolkit-self-check", "version": "1.0"},
                "entries": [{
                    "request": {
                        "method": "GET",
                        "url": "https://t.example/api/user/info",
                        "headers": [],
                    },
                    "response": {"status": 200, "statusText": "OK"},
                }],
            }
        }, ensure_ascii=False, indent=2))
        oracle = base / "oracle_sample.json"
        _write_text(oracle, json.dumps([
            {"id": "case-001", "endpoint": "/api/order/detail", "method": "GET",
             "params": ["order_no"], "class": "越权/IDOR", "score": 3.0, "roles": []},
            {"id": "case-002", "endpoint": "/api/user/login", "method": "POST",
             "params": ["password"], "class": "认证", "score": 2.0, "roles": []},
            {"id": "case-003", "endpoint": "/api/order/list", "method": "GET",
             "params": [], "class": "越权/IDOR", "score": 2.0, "roles": []},
            {"id": "case-004", "endpoint": "/api/user/info", "method": "GET",
             "params": [], "class": "信息泄露", "score": 2.0, "roles": []},
            {"id": "case-005", "endpoint": "/api/orders/{id}", "method": "GET",
             "params": [], "class": "越权/IDOR", "score": 3.0, "roles": [],
             "discovered_during_testing": True},
        ], ensure_ascii=False, indent=2))
        _write_text(reporting / "finding.json", json.dumps({
            "schema_version": 1,
            "id": "finding_001",
            "title": "订单详情接口存在水平越权漏洞",
            "severity": "P1",
            "vuln_type": "越权/IDOR",
            "target": "https://t.example",
            "risk": {
                "summary": "攻击者可读取其他用户订单详情。",
                "proven_impact": "实测 B 账号读取到 A 账号订单收货地址与金额。",
            },
            "recommendation": {
                "summary": "服务端按当前登录身份校验订单归属。",
                "details": ["查询订单详情时绑定 current_user_id 与 order_id。"],
            },
            "feature_point": {
                "module": "订单模块",
                "function": "订单详情查询",
                "trigger": "进入订单详情页时触发",
                "trigger_api": "GET /api/order/detail",
                "vulnerable_param": "order_id",
                "statement": "订单模块 -> 订单详情查询，触发 GET /api/order/detail 接口，order_id 参数存在水平越权漏洞。",
            },
            "apis": [{
                "method": "GET",
                "path": "/api/order/detail",
                "purpose": "根据订单 ID 查询订单详情",
                "risk_params": ["order_id"],
                "params": [{"name": "order_id", "location": "query", "risk": "服务端未校验订单归属"}],
            }],
            "proof_packets": [{
                "name": "attacker_read_victim_order",
                "request_file": "request_1.http",
                "response_file": "response_1.http",
                "evidence_summary": "响应中返回受害者订单地址与金额。",
            }],
            "manual_burp_replay": [
                "登录攻击者账号并进入订单详情页面。",
                "使用 Burp Suite 捕获 GET /api/order/detail 请求。",
                "将 order_id 修改为受害者订单 ID。",
                "重放请求后响应中返回受害者订单详情。",
            ],
            "poc": {
                "type": "curl",
                "file": "poc.sh",
                "description": "替换 Cookie 与 order_id 后可复现越权读取。",
            },
            "source_proof": None,
            "crypto_chain": None,
        }, ensure_ascii=False, indent=2))
        _write_text(reporting / "poc.sh", (
            "curl 'https://t.example/api/order/detail?order_id=1001' \\\n"
            "  -H 'Cookie: session=attacker_b' \\\n"
            "  -H 'Accept: application/json'\n"
        ))
        _write_text(reporting / "request_1.http", (
            "GET /api/order/detail?order_id=1001 HTTP/1.1\n"
            "Host: t.example\nCookie: session=attacker_b\nAccept: application/json\n\n"
        ))
        _write_text(reporting / "response_1.http", (
            "HTTP/1.1 200 OK\nContent-Type: application/json\n\n"
            "{\"order_id\":\"1001\",\"owner\":\"victim_a\",\"address\":\"北京市海淀区示例路 1 号\",\"amount\":\"1299.00\"}\n"
        ))
        return recon, oracle, reporting

    fixture_root = pathlib.Path(tempfile.mkdtemp(prefix="atoolkit-selfcheck-"))
    recon_dir, oracle_path, reporting_fixture = _make_self_check_fixtures(fixture_root)
    print("▶ self-check（临时 fixture，不接模型/网络）")

    failures: list[str] = []

    # 断言1：bootstrap(fixture) 覆盖 oracle 全部端点。
    # discovered_during_testing==true 的 case 是测试中发现的面，不期望在 bootstrap 种子里
    # （如 case-005 /api/orders/{id} 是 IDOR 报告中发现的具体端点，非 recon 产物），
    # 跳过这些 case，仅要求 bootstrap 覆盖剩余（种子）端点。
    def _assert1():
        surfaces = bootstrap(recon_dir)
        boot_eps = {s.get("endpoint", "") for s in surfaces}
        assert boot_eps, "bootstrap 未解析出任何端点（fixture 缺失/为空？）"
        oracle = be.load_oracle(oracle_path)
        exempt = [c for c in oracle if c.raw.get("discovered_during_testing")]
        exempt_ids = [c.id for c in exempt]
        checkable = [c for c in oracle if not c.raw.get("discovered_during_testing")]
        missing = [c.endpoint for c in checkable
                   if c.endpoint and c.endpoint not in boot_eps]
        assert not missing, (
            f"bootstrap 未覆盖 oracle 端点 {missing}；bootstrap 端点={sorted(boot_eps)}")
        note = (f"（豁免 {len(exempt)} 个 discovered_during_testing case：{exempt_ids}）"
                if exempt else "")
        print(f"  断言1 ✅ bootstrap 覆盖 oracle {len(checkable)}/{len(oracle)} 端点{note}：{sorted(boot_eps)}")

    # 断言2：浅阴性 ledger（非高价值、无 next_actions）→ session_gate incomplete。
    def _assert2():
        ledger = CoverageLedger(surfaces=[{
            "endpoint": "/api/search",
            "method": "GET", "param": "q", "feature": "search",
            "status": "shallow_negative",   # 非高价值、无 next_actions 的浅阴性格
        }])
        out = evaluate_session_gate(ledger)
        preds = [r.get("predicate") for r in out.get("reasons", [])]
        assert out["result"] == INCOMPLETE, (
            f"浅阴性格应判 incomplete，实得 {out['result']}")
        assert "shallow_negative_open" in preds, (
            f"应命中 shallow_negative_open 谓词，实得 {preds}")
        print(f"  断言2 ✅ 浅阴性格 → {out['result']}（命中 shallow_negative_open，演示 P0-2）")

    # 断言3：合格报告（target/curl/响应证据）→ Guardian accepted。
    def _assert3():
        report = (
            "---\nseverity: P1\ntitle: 订单详情越权读取\ntarget: https://t.example\n"
            "type: 越权/IDOR\n---\n"
            "换用 B 账号 Cookie 越权读取了 A 用户订单详情，提取了收货地址与金额。\n"
            "```\ncurl 'https://t.example/api/order/detail?order_no=1001' -H 'Cookie: B'\n"
            "HTTP/1.1 200 ... 返回了 A 的订单数据\n```\n" + "证据充分。" * 30)
        v = guardian_check(report, authorized_hosts=["t.example"])
        assert v.result == ACCEPTED, (
            f"合格报告应被 Guardian accepted，实得 {v.result}（L{v.level}: {v.reason}）")
        print(f"  断言3 ✅ 合格报告 → Guardian accepted（L{v.level}）")

    # 断言4：surface 内容嗅探 + wrapper + 变量一跳 + 相对路径 + body shorthand 参数。
    def _assert4():
        tmp = pathlib.Path(tempfile.mkdtemp())
        (tmp / "bundle.asset").write_text(
            "const detailUrl = '../api/order/detail.php?order_no=1';\n"
            "fetch(detailUrl, { method: 'POST', body: JSON.stringify({ user_id, status }) });\n"
            "jsonPost('../../api/pay.php', { order_no, amount, status });\n"
            "api.post('../api/refund.php', { refund_amount, order_no });\n",
            encoding="utf-8",
        )
        surfaces = bootstrap(tmp)
        by_ep = {s["endpoint"]: s for s in surfaces}
        by_ep_method = {(s["endpoint"], s["method"]): s for s in surfaces}
        assert "/api/order/detail.php" in by_ep, f"变量 fetch 相对路径未抽出: {surfaces}"
        assert ("/api/pay.php", "POST") in by_ep_method, f"jsonPost 相对路径未抽出: {surfaces}"
        assert ("/api/refund.php", "POST") in by_ep_method, f"api.post 相对路径未抽出: {surfaces}"
        params = set(by_ep_method[("/api/pay.php", "POST")].get("params") or [])
        assert {"order_no", "amount", "status"} <= params, f"body shorthand 参数缺失: {params}"
        src = by_ep_method[("/api/pay.php", "POST")]
        assert src.get("source_file") and src.get("source_line") and src.get("source_kind"), \
            f"source_file/source_line/source_kind 缺失: {src}"
        print("  断言4 ✅ recon 解析 wrapper/变量/相对路径/body 参数/source 元数据")

    # 断言5：有 gate 未通过时 summary 不能写完成态。
    def _assert5():
        status = _summary_status({
            "status": "vuln_found",
            "accepted": ["P1"],
            "session_gate": {"result": "incomplete"},
        })
        assert status == "incomplete_with_findings", f"gate 未过的 summary.status 不应完成: {status}"
        print("  断言5 ✅ session_gate 未 pass 时 summary.status=incomplete_with_findings")

    # 断言6：benchmark_eval 能从 evidence request 提取 method/params。
    def _assert6():
        tmp = pathlib.Path(tempfile.mkdtemp())
        (tmp / "evidence.json").write_text(json.dumps({
            "request": {
                "method": "POST",
                "url": "https://t.example/api/order/detail?order_no=1",
                "body": {"amount": 100, "status": "paid"},
            }
        }, ensure_ascii=False), encoding="utf-8")
        (tmp / "summary.json").write_text(json.dumps({
            "findings": [{
                "id": "f-1",
                "class": "交易篡改",
                "evidence_file": "evidence.json",
            }]
        }, ensure_ascii=False), encoding="utf-8")
        findings = be.load_findings(tmp / "summary.json")
        assert findings and findings[0].methods == ["POST"], f"method 提取失败: {findings}"
        assert {"order_no", "amount", "status"} <= set(findings[0].params), \
            f"params 提取失败: {findings[0].params}"
        print("  断言6 ✅ benchmark 从 evidence request 提取 method/params")

    # 断言7：reporting basic IDOR fixture validate accepted，缺 response 时 rejected。
    def _assert7():
        from engine.reporting.schema import load_finding
        from engine.reporting.validate import validate_finding
        fixture = reporting_fixture
        finding = load_finding(fixture / "finding.json")
        ok = validate_finding(finding, fixture / "finding.json", fixture,
                              authorized_hosts=["t.example"])
        assert ok.ok, f"basic_idor 应 accepted: {ok.reasons}"
        tmp = pathlib.Path(tempfile.mkdtemp())
        dst = tmp / "findings" / "finding_001"
        shutil.copytree(fixture, dst)
        (dst / "response_1.http").unlink()
        bad = load_finding(dst / "finding.json")
        rejected = validate_finding(bad, dst / "finding.json", tmp,
                                    authorized_hosts=["t.example"])
        assert not rejected.ok and any("response_file" in r for r in rejected.reasons), \
            f"缺 response 应 rejected: {rejected.reasons}"
        shutil.rmtree(tmp)
        tmp = pathlib.Path(tempfile.mkdtemp())
        dst = tmp / "findings" / "finding_001"
        shutil.copytree(fixture, dst)
        escaped = load_finding(dst / "finding.json")
        escaped["poc"]["file"] = "../../../outside.sh"
        escape_res = validate_finding(escaped, dst / "finding.json", tmp,
                                      authorized_hosts=["t.example"])
        assert not escape_res.ok and any("escapes run directory" in r for r in escape_res.reasons), \
            f"路径逃逸应 rejected: {escape_res.reasons}"
        print("  断言7 ✅ reporting validate accepted/rejected/path-escape")

    # 断言8：collect/render/normalized mapping + Verify finding PoC helper。
    def _assert8():
        from engine.reporting.collect import collect_structured_findings
        from engine.reporting.render_md import render_final_report
        fixture = reporting_fixture
        tmp = pathlib.Path(tempfile.mkdtemp())
        dst = tmp / "findings" / "finding_001"
        shutil.copytree(fixture, dst)
        collected = collect_structured_findings(tmp, authorized_hosts=["t.example"])
        assert len(collected["accepted"]) == 1, collected
        nf = collected["normalized"][0]
        assert nf["methods"] == ["GET"], nf
        assert "order_id" in nf["params"], nf
        assert nf["evidence_file"] == "findings/finding_001/finding.json", nf
        report_path = render_final_report(collected["accepted"], tmp / "final_report.md", "t.example")
        report = report_path.read_text(encoding="utf-8")
        assert report.startswith("# t.example 授权安全测试报告\n\n## 1. 漏洞名称"), report[:120]
        assert "### 安全风险" in report and "### 漏洞证明" in report, report
        req = extract_poc_from_finding(collected["accepted"][0]["finding"], dst)
        assert req and req.method == "GET" and "order_id=1001" in req.url, req
        print("  断言8 ✅ collect/render/normalized/verify helper")

    # 断言9：_conclude 等价闭环写 final_report_path，gate 未过时 draft_incomplete。
    def _assert9():
        from engine.orchestrator import CognitiveState, harvest_evidence, _conclude
        fixture = reporting_fixture
        tmp = pathlib.Path(tempfile.mkdtemp())
        dst = tmp / "findings" / "finding_001"
        shutil.copytree(fixture, dst)
        state = CognitiveState(sid="selfcheck", target="https://t.example")
        state.seed_matrix(["/api/order/detail"])
        evidence = harvest_evidence(tmp, authorized_hosts=["t.example"])
        state.update("", evidence, maintain_matrix=True)
        out = _conclude("VULN_FOUND", evidence, tmp, state, ["t.example"], 1)
        assert out["structured_findings"]["accepted"] == 1, out
        assert out["final_report_status"] == "draft_incomplete", out
        assert out["final_report_path"] and pathlib.Path(out["final_report_path"]).exists(), out
        summary = {
            "findings": _summary_findings(out),
            "final_report_path": out.get("final_report_path"),
            "final_report_status": out.get("final_report_status"),
            "structured_findings": out.get("structured_findings"),
        }
        (tmp / "summary.json").write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")
        loaded = json.loads((tmp / "summary.json").read_text(encoding="utf-8"))
        assert loaded["final_report_path"] and loaded["final_report_status"] == "draft_incomplete", loaded
        print("  断言9 ✅ _conclude structured finding → draft final_report + summary fields")

    # ── v6.1 §10.4: 6 条新断言（候选台账 / depth floor / 再探测 / proof 保底 / 缺口附录）──
    def _assert10():
        """MockAdapter DIM/CANDIDATE → candidate-ledger.json + surface.candidate_count 回填。"""
        from engine.candidate import CandidateLedger
        from engine.ledger import CoverageLedger
        from engine.knowledge import load_cards
        import tempfile
        cards = load_cards()
        tmp = pathlib.Path(tempfile.mkdtemp())
        cl = CandidateLedger()
        dim_text = (
            "DIM: object-ownership | CANDIDATE: 换 attacker 读取他人订单 | need:owner建单+attacker改单号 | P1 | probe:三步越权\n"
            "DIM: auth-flow-abuse | NONE: 非认证端点\n")
        surface = {"endpoint": "/api/orders/{id}", "method": "GET", "param": "id",
                   "risk_tags": ["object-ownership", "idor"], "feature": "order"}
        ledger = CoverageLedger(surfaces=[surface])
        sid = ledger.surfaces[0]["surface_id"]
        sctx = {"surface_id": sid, "endpoint": "/api/orders/{id}", "method": "GET",
                "param": "id", "depth_floor": 3}
        def _link(sid_, status, depth_score):
            ledger.link_candidate(sid_, status=status, depth_score=depth_score)
        cl.apply(dim_text, turn=0, cards=cards, surface_ctx=sctx, link_callback=_link)
        cl.save(tmp / "candidate-ledger.json")
        # candidate-ledger.json exists with candidates
        assert (tmp / "candidate-ledger.json").exists(), "candidate-ledger.json should exist"
        loaded = CandidateLedger.load(tmp / "candidate-ledger.json")
        active = [c for c in loaded.candidates if c.get("status") != "duplicate"]
        assert len(active) >= 1, f"should have ≥1 active candidate, got {active}"
        # surface.candidate_count backfilled
        surf = ledger.get(sid)
        assert surf and surf.get("candidate_count", 0) >= 1, \
            f"surface candidate_count should be ≥1, got {surf.get('candidate_count') if surf else 'None'}"
        print(f"  断言10 ✅ DIM→candidate-ledger.json({len(active)}候选) + surface.candidate_count={surf['candidate_count']}")

    def _assert11():
        """depth_score < depth_floor → TRIAGE proof_ready 被外壳拒（退回 triaging）。"""
        from engine.candidate import CandidateLedger, PROPOSED, TRIAGING
        from engine.knowledge import load_cards
        cards = load_cards()
        cl = CandidateLedger()
        dim_text = "DIM: object-ownership | CANDIDATE: 越权读他人订单 | P1 | probe:换id\n"
        sctx = {"surface_id": "GET /api/orders/{id} id [user] {object-ownership,idor}",
                "endpoint": "/api/orders/{id}", "method": "GET", "param": "id", "depth_floor": 3}
        cl.apply(dim_text, turn=0, cards=cards, surface_ctx=sctx)
        cid = [c for c in cl.candidates if c.get("status") == PROPOSED][0]["candidate_id"]
        # TRIAGE proof_ready with depth_score=0 → should be rejected
        cl.apply(f"TRIAGE: {cid} | proof_ready | 测试 | evidence.md | ", turn=1, cards=cards)
        cand = cl.get(cid)
        assert cand["status"] == TRIAGING, \
            f"depth_score=0 proof_ready should be rejected→triaging, got {cand['status']}"
        # Now give depth and retry → should pass
        cand["vectors"] = ["v1", "v2", "v3"]
        cand["roles_tested"] = ["owner", "attacker"]
        cand["evidence_refs"] = ["evidence.md"]
        cl.apply(f"TRIAGE: {cid} | proof_ready | 充分 | evidence.md | ", turn=2, cards=cards)
        cand = cl.get(cid)
        assert cand["status"] == "proof_ready", \
            f"depth met proof_ready should pass, got {cand['status']} (score={cand['depth_score']})"
        print(f"  断言11 ✅ depth_floor gate: depth=0→rejected(triaging), depth={cand['depth_score']}→proof_ready")

    def _assert12():
        """阴性 surface 闭环校验不达 floor → 降级 not_tested + negative_depth_not_checked。"""
        from engine.ledger import CoverageLedger
        from engine.session_gate import evaluate_session_gate
        from engine.knowledge import load_cards
        cards = load_cards()
        # not_vulnerable surface with insufficient negative evidence, not checked
        ledger = CoverageLedger(surfaces=[{
            "endpoint": "/api/search", "method": "GET", "param": "q",
            "feature": "search", "status": "not_vulnerable",
            "negative_depth_checked": False,
            "negative": {"vectors": ["baseline"], "response_count": 0},
        }])
        out = evaluate_session_gate(ledger, candidates=[], finding_candidate_ids=set())
        preds = [r.get("predicate") for r in out.get("reasons", [])]
        assert "negative_depth_not_checked" in preds, \
            f"expect negative_depth_not_checked, got {preds}"
        assert out["result"] == "incomplete", f"expect incomplete, got {out['result']}"
        print(f"  断言12 ✅ not_vulnerable + unchecked → negative_depth_not_checked + incomplete")

    def _assert13():
        """reprobe_triggers 命中（新角色到账）→ refuted 候选重开。"""
        from engine.candidate import CandidateLedger, REFUTED, PROPOSED
        cl = CandidateLedger()
        # Create a refuted candidate with new_role trigger
        cl.candidates.append({
            "candidate_id": "cand_001", "surface_id": "x", "endpoint": "/api/admin",
            "status": REFUTED, "depth_score": 0, "depth_floor": 2,
            "reprobe_triggers": [{"type": "new_role", "reason": "需 admin 角色"}],
            "hypothesis": "admin 越权", "vectors": [], "roles_tested": [],
            "objects_tested": [], "evidence_refs": [],
        })
        # Scan with new_roles=["admin"] → should reopen
        hits = cl.reprobe_scan(new_roles=["admin"])
        assert hits, f"reprobe_scan should find a hit, got {hits}"
        cand = cl.get("cand_001")
        assert cand["status"] == PROPOSED, \
            f"refuted candidate should reopen to proposed, got {cand['status']}"
        print(f"  断言13 ✅ reprobe: new_role=admin → refuted→proposed (reopened)")

    def _assert14():
        """proof_ready 候选在工作队列中永远最前（§5 保底）。"""
        from engine.candidate import top_work_queue, PROOF_READY, PROPOSED, TRIAGING
        cands = [
            {"candidate_id": "c1", "status": PROPOSED, "endpoint": "/api/a",
             "depth_score": 0, "depth_floor": 1, "hypothesis": "low value"},
            {"candidate_id": "c2", "status": PROOF_READY, "endpoint": "/api/b",
             "depth_score": 3, "depth_floor": 3, "hypothesis": "ready to prove"},
            {"candidate_id": "c3", "status": TRIAGING, "endpoint": "/api/c",
             "depth_score": 1, "depth_floor": 3, "hypothesis": "still probing"},
        ]
        top = top_work_queue(cands, n=3)
        assert top[0]["candidate_id"] == "c2", \
            f"proof_ready should be first, got {top[0]['candidate_id']}"
        print(f"  断言14 ✅ work_queue: proof_ready(c2) first → {[c['candidate_id'] for c in top]}")

    def _assert15():
        """proof_ready 无 finding → 终态 incomplete + 四类缺口附录④非空。"""
        from engine.candidate import CandidateLedger, compute_coverage_gaps, coverage_gaps_nonempty
        from engine.orchestrator import CognitiveState, _conclude, harvest_evidence
        import tempfile
        tmp = pathlib.Path(tempfile.mkdtemp())
        cl = CandidateLedger(candidates=[{
            "candidate_id": "cand_001", "surface_id": "GET /api/x id [user] {object-ownership,idor}",
            "endpoint": "/api/x", "method": "GET", "status": "proof_ready",
            "depth_score": 3, "depth_floor": 3, "hypothesis": "IDOR",
            "vectors": ["v1","v2","v3"], "roles_tested": ["owner","attacker"],
            "evidence_refs": ["ev.md"], "root_cause": None,
        }])
        state = CognitiveState(sid="selfcheck15", target="https://t.example")
        state.seed_matrix(["/api/x"])
        evidence = harvest_evidence(tmp, authorized_hosts=["t.example"])
        out = _conclude("LOW_ROI", evidence, tmp, state, ["t.example"], 1,
                        candidate_ledger=cl, cards=__import__('engine.knowledge', fromlist=['load_cards']).load_cards())
        # proof_ready without finding → incomplete
        assert out["status"] == "incomplete", \
            f"proof_ready without finding → incomplete, got {out['status']}"
        # coverage_gaps ④ non-empty
        gaps = out.get("coverage_gaps", {})
        assert gaps.get("proof_ready_without_finding"), \
            f"gaps④ should be non-empty, got {gaps.get('proof_ready_without_finding')}"
        assert out.get("coverage_gaps_nonempty"), "coverage_gaps_nonempty should be True"
        print(f"  断言15 ✅ proof_ready无finding → incomplete + gaps④={len(gaps.get('proof_ready_without_finding',[]))}条")

    for name, fn in (("断言1", _assert1), ("断言2", _assert2), ("断言3", _assert3),
                     ("断言4", _assert4), ("断言5", _assert5), ("断言6", _assert6),
                     ("断言7", _assert7), ("断言8", _assert8), ("断言9", _assert9),
                     ("断言10", _assert10), ("断言11", _assert11), ("断言12", _assert12),
                     ("断言13", _assert13), ("断言14", _assert14), ("断言15", _assert15)):
        try:
            fn()
        except AssertionError as exc:
            failures.append(f"{name} 失败: {exc}")
            print(f"  {name} ✗ {exc}", file=sys.stderr)
        except Exception as exc:                       # noqa: BLE001
            failures.append(f"{name} 异常: {type(exc).__name__}: {exc}")
            print(f"  {name} ✗ {type(exc).__name__}: {exc}", file=sys.stderr)

    if failures:
        print(f"\n✗ self-check 失败（{len(failures)} 条）:", file=sys.stderr)
        for fail in failures:
            print(f"  - {fail}", file=sys.stderr)
        shutil.rmtree(fixture_root, ignore_errors=True)
        return 1
    print("✅ self-check 全部通过")
    shutil.rmtree(fixture_root, ignore_errors=True)
    return 0


def main():
    ap = argparse.ArgumentParser(description="起一次授权 SRC 会话（engine 三件套接线）")
    ap.add_argument("--target", default="", help="授权目标 URL")
    ap.add_argument("--authz", default="", help="授权说明文本，或授权文件路径")
    ap.add_argument("--cookie", default="", help="人已拿到的新鲜 Cookie/Session")
    ap.add_argument("--bearer", default="", help="人已拿到的新鲜 Bearer JWT（与 --cookie 二选一）")
    ap.add_argument("--auth-scheme", choices=["cookie", "bearer"], default="cookie",
                    help="--identity 凭据的注入方式：cookie→Cookie 头；bearer→Authorization: Bearer")
    ap.add_argument("--model", default="gpt-5.5-codex", help="模型名（换模型只改这里）")
    ap.add_argument("--allow", action="append", default=[], help="额外授权 host（可多次）")
    ap.add_argument("--identity", action="append", default=[],
                    help="复验身份 label:cred（cookie 模式如 owner:session=A；bearer 模式如 owner:eyJ...；可多次）")
    ap.add_argument("--victim-marker", default="", help="证明越权的受害者数据特征串")
    ap.add_argument("--owned-id", action="append", default=[],
                    help="本会话自有对象 id（可多次）；改删类命中其中即自动放行，否则熔断交人工")
    ap.add_argument("--confirm-policy", choices=["halt", "allow"], default="halt",
                    help="改删他人/未知 id 时：halt=熔断停手交人工(默认)；allow=放行(信任场景)")
    ap.add_argument("--hint", default="", help="攻击面提示(按意图触发)，注入 prompt 的 skill_hint 槽；或提示文件路径")
    ap.add_argument("--endpoints", default="",
                    help="覆盖矩阵的攻击面来源：文件路径(每行一个 endpoint，# 起注释) 或逗号分隔")
    ap.add_argument("--recon-dir", default="",
                    help="recon 产物目录(JS/HTML/JSON/HAR)；由 engine.surface.bootstrap 解析为攻击面，"
                         "喂 planner.plan_surfaces 展开后与 --endpoints 合并")
    ap.add_argument("--ad-hoc", action="store_true",
                    help="显式声明退化单点验证(无 --endpoints/--recon-dir 时放行空启动，退化为首洞即结)")
    ap.add_argument("--vuln-class", action="append", default=[],
                    help="覆盖矩阵的漏洞类(列)，可多次；缺省用引擎内置 OWASP/SRC 主流类")
    ap.add_argument("--enable-auth-flow-column", action="store_true",
                    help="显式启用 auth endpoint 的认证绕过/枚举列；自定义 --vuln-class 时也生效")
    ap.add_argument("--max-turns", type=int, default=50)
    ap.add_argument("--sid", default="", help="会话 ID（默认按时间生成）")
    ap.add_argument("--resume", action="store_true",
                    help="断点续测：复用 --sid 的 runs/<sid>/state.json 承接覆盖进度（无则照常新开）")
    ap.add_argument("--dry-run", action="store_true", help="用 MockAdapter，不接模型/网络")
    ap.add_argument("--self-check", action="store_true",
                    help="自检门：临时生成 fixture 跑断言（不接模型/网络），全过 exit 0、失败 exit 1；"
                         "独立于 --target/--authz，可不带这两参数")
    # v6.1 §10.3 flags
    ap.add_argument("--loop-mode", default="recall-first",
                    choices=["recall-first", "coverage-first"],
                    help="v6.1：循环模式。recall-first（默认）优先榨干候选；coverage-first 优先覆盖矩阵")
    ap.add_argument("--candidate-top-n", type=int, default=8,
                    help="v6.1：每轮注入候选工作队列上限（§5）")
    ap.add_argument("--adversarial-pass", action="store_true",
                    help="v6.1 §3.3：对抗式补漏 pass（默认关，预算紧时不开）")
    ap.add_argument("--lens", default="",
                    help="v6.1 §3.4：多视角 recall（逗号分隔，如 attacker-A,business-abuser；默认关）")
    ap.add_argument("--proof-budget-floor", type=float, default=0.3,
                    help="v6.1 §5：proof 保底预算下限比例（0-1）")
    ap.add_argument("--no-flow-surfaces", action="store_true",
                    help="v6.1 §9：关闭 flow surface 识别（退化兼容）")
    ap.add_argument("--oracle", default="",
                    help="可选 oracle 文件(JSON/YAML/CSV/PHP array)；存在则用 engine.benchmark_eval "
                         "算 hit/total（oracle 命中 confirmed surface 数）并打印")
    args = ap.parse_args()

    # --self-check：临时生成 fixture 跑断言，不接模型/网络，独立于 --target/--authz。
    if args.self_check:
        return _run_self_check()
    # 非 self-check：--target/--authz 仍为必填（argparse 层已放宽为非 required 以放行 --self-check）。
    if not args.target or not args.authz:
        ap.error("--target 与 --authz 为必填（自检门用 --self-check，可不带这两参数）")

    # 会话目录与落盘（runs/ 已被 .gitignore）
    sid = args.sid or time.strftime("sess-%Y%m%d-%H%M%S")
    wd = ROOT / "runs" / sid
    wd.mkdir(parents=True, exist_ok=True)
    authz = (pathlib.Path(args.authz).read_text(encoding="utf-8")
             if pathlib.Path(args.authz).exists() else args.authz)
    (wd / "authz.md").write_text(authz, encoding="utf-8")
    # 会话凭据：cookie 或 bearer（落盘到 cookies.txt 供模型读取，runs/ 已 gitignore）
    cred = args.bearer or args.cookie
    cred_line = (f"Authorization: Bearer {args.bearer}" if args.bearer
                 else (f"Cookie: {args.cookie}" if args.cookie else ""))
    if cred:
        (wd / "cookies.txt").write_text(cred_line, encoding="utf-8")

    skill = (ROOT / "skill" / "核心技能文件.v2.md").read_text(encoding="utf-8")
    hosts = [host_of(args.target)] + args.allow

    # 覆盖矩阵的攻击面来源（支柱 2）：
    #   ① --endpoints：文件(每行一个，# 注释) 或逗号分隔
    #   ② --recon-dir：recon 产物目录 → engine.surface.bootstrap 解析为端点清单，
    #      再喂 planner.plan_surfaces 展开成 ledger-ready surfaces，与 ① 合并
    endpoints: list[str] = []
    endpoint_inv_records: list[dict] = []
    if args.endpoints:
        endpoints, endpoint_inv_records = _inventory_records_from_endpoint_arg(args.endpoints)
    inventory: list = list(endpoints)  # str（--endpoints）+ dict（recon bootstrap 展开）
    inventory_records: list[dict] = list(endpoint_inv_records)
    from engine.surface import is_saturated
    from engine.planner import plan_surfaces
    if args.recon_dir:
        from engine.surface import bootstrap
        recon_surfaces = bootstrap(pathlib.Path(args.recon_dir))
        if not recon_surfaces:
            print(f"  ⚠ --recon-dir {args.recon_dir} 未解析出任何攻击面", file=sys.stderr)
        # P1-3：落 endpoint 台账 inventory.json（与 coverage-ledger.json 同目录）。
        # bootstrap 时 discovered_during_testing=false；断点续测时保留测试中发现的 endpoint。
        inv_path = wd / "inventory.json"
        existing_discovered = []
        if inv_path.exists():                          # --resume 续测：保留 discovered_during_testing 记录
            try:
                old = json.loads(inv_path.read_text(encoding="utf-8"))
                old_recs = old.get("endpoints") if isinstance(old, dict) else old
                existing_discovered = [r for r in old_recs
                                       if isinstance(r, dict) and r.get("discovered_during_testing")]
            except Exception:
                existing_discovered = []
        inv_records = [
            {
                "endpoint": s.get("endpoint", ""),
                "method": s.get("method", "GET"),
                "source": s.get("source", "manual"),
                "source_file": s.get("source_file", ""),
                "source_line": s.get("source_line", 0),
                "source_kind": s.get("source_kind", s.get("source", "manual")),
                "last_seen": s.get("last_seen", ""),
                "discovered_during_testing": False,
            }
            for s in recon_surfaces
        ] + existing_discovered
        inventory_records.extend(inv_records)
        inventory.extend(plan_surfaces(recon_surfaces))

    # 正式覆盖跑统一落 endpoint 台账：--endpoints-only 也必须有 inventory.json，
    # 这样 session_gate 能解释 endpoint 来源，报告引用未登记面也能被拦住。
    if endpoints or args.recon_dir:
        inv_path = wd / "inventory.json"
        existing_discovered = []
        if inv_path.exists():
            try:
                old = json.loads(inv_path.read_text(encoding="utf-8"))
                old_recs = old.get("endpoints") if isinstance(old, dict) else old
                existing_discovered = [r for r in old_recs
                                       if isinstance(r, dict) and r.get("discovered_during_testing")]
            except Exception:
                existing_discovered = []
        inv_records = _merge_inventory_records(inventory_records + existing_discovered)
        inv_path.write_text(
            json.dumps({"endpoints": inv_records,
                        "saturation_reached": is_saturated(inv_records)},
                       ensure_ascii=False, indent=2), encoding="utf-8")

    # 硬门：正式覆盖跑需 --endpoints 或 --recon-dir；单点验证显式 --ad-hoc
    if not endpoints and not args.recon_dir and not args.ad_hoc:
        print("✗ 拒绝空启动：正式覆盖跑需 --endpoints 或 --recon-dir；单点验证用 --ad-hoc",
              file=sys.stderr)
        sys.exit(2)

    identities = {}
    for spec in args.identity:
        label, _, val = spec.partition(":")
        val = val.strip()
        auth = ({"Authorization": f"Bearer {val}"} if args.auth_scheme == "bearer"
                else {"Cookie": val})
        identities[label.strip()] = auth

    # 适配器：唯一与模型耦合处（换运行时改这里）
    if args.dry_run:
        adapter, verify_fn = MockAdapter(wd), None      # dry-run 不联网复验
    else:
        from codex.codex_adapter import CodexAdapter
        adapter = CodexAdapter(model=args.model, workdir=str(wd), allow_hosts=hosts)
        verify_fn = build_verify_fn(identities, args.victim_marker, hosts)

    target = args.target + (f"\n（本会话凭据见 {wd/'cookies.txt'}，按其中的 header 行原样带上）" if cred else "")

    print(f"▶ 会话 {sid} ｜ 模型 {'mock' if args.dry_run else args.model} ｜ 授权 host {hosts}")
    print(f"  复验: {'开（'+','.join(identities)+'）' if verify_fn else '关'} ｜ 工作目录 {wd}")
    auth_flow_note = " + auth-flow gated" if (args.enable_auth_flow_column or not args.vuln_class) else ""
    if args.recon_dir:
        src_note = "recon" + ("+endpoints" if endpoints else "")
    elif endpoints:
        src_note = "endpoints"
    elif args.ad_hoc:
        src_note = "ad-hoc 退化(首洞即结)"
    else:
        src_note = ""
    print(f"  覆盖矩阵: {len(inventory)} surface × "
          f"{len(args.vuln_class) or '内置'} 类{auth_flow_note} ({src_note})")
    print("─" * 60)
    hint = (pathlib.Path(args.hint).read_text(encoding="utf-8")
            if args.hint and pathlib.Path(args.hint).exists() else args.hint)
    if args.resume and not (wd / "state.json").exists():
        print(f"  ⚠ --resume 但 {wd/'state.json'} 不存在 → 按新会话起（无进度可承接）")
    run_kwargs = {
        "target": target,
        "authz": authz,
        "core_skill": skill,
        "workdir": str(wd),
        "authorized_hosts": hosts,
        "max_turns": args.max_turns,
        "verify_fn": verify_fn,
        "owned_ids": set(args.owned_id),
        "confirm_policy": args.confirm_policy,
        "skill_hint": hint,
        "endpoints": inventory,
        "vuln_classes": (args.vuln_class or None),
        "resume": args.resume,
    }
    if "enable_auth_flow_column" in inspect.signature(run_session).parameters:
        run_kwargs["enable_auth_flow_column"] = (
            True if args.enable_auth_flow_column else None
        )
    # v6.1 §10.3 flags
    run_kwargs["candidate_top_n"] = args.candidate_top_n
    run_kwargs["loop_mode"] = args.loop_mode
    run_kwargs["adversarial_pass"] = args.adversarial_pass
    run_kwargs["proof_budget_floor"] = args.proof_budget_floor
    run_kwargs["no_flow_surfaces"] = args.no_flow_surfaces
    if args.lens:
        run_kwargs["lens"] = [x.strip() for x in args.lens.split(",") if x.strip()]
    res = run_session(adapter, **run_kwargs)
    # 硬门：正式覆盖跑必须同时有 inventory 与 ledger；否则终态强制 incomplete。
    led_stats = (res.get("coverage_ledger") or {}).get("stats") or {}
    inv_missing = not (wd / "inventory.json").exists()
    ledger_path = pathlib.Path(res.get("coverage_ledger_path") or (wd / "coverage-ledger.json"))
    ledger_missing = not ledger_path.exists()
    if (inv_missing or ledger_missing or led_stats.get("total", 0) == 0) and not args.ad_hoc:
        print("✗ 正式覆盖跑缺少 inventory/coverage-ledger 或 surface 数为 0 → 终态强制 incomplete")
        res["status"] = "incomplete"
    # 落 summary.json：结构对齐 engine.benchmark_eval.load_findings（dict 含 findings 键，每条行有 endpoint）。
    # aggregate_findings 用 root_cause/affected_role 命名，benchmark_eval 读 class/roles，故在此产物里补字段映射
    # （不改 aggregate_findings 本身）。落盘失败不阻断收尾打印。
    try:
        summary = {
            "findings": _summary_findings(res),
            "status": _summary_status(res),
            "accepted": res.get("accepted", []),
            "coverage_ledger_path": res.get("coverage_ledger_path"),
            "session_gate": res.get("session_gate"),
            "turn": res.get("turn"),
            "marker": res.get("marker"),
            "final_report_path": res.get("final_report_path"),
            "final_report_status": res.get("final_report_status", "not_generated"),
            "structured_findings": res.get("structured_findings", {"accepted": 0, "rejected": 0}),
        }
        (wd / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as _e:                       # 落盘失败不阻断收尾打印
        print(f"  ⚠ 落 summary.json 失败: {type(_e).__name__}: {_e}", file=sys.stderr)
    print("─" * 60)
    print(f"终态: {res['status']} ｜ 标记: {res.get('marker')} ｜ 轮次: {res['turn']}")
    if "accepted" in res:          # error/needs_confirm 终态返回里没有 Guardian 账本
        print(f"Guardian: accepted={res['accepted']} demoted={res['demoted']} rejected={res['rejected']} "
              f"负向留证={res.get('negatives', 0)}")
        cov = res.get("coverage")
        if cov:
            print(f"覆盖矩阵: 闭合 {cov.get('closed', 0)}/{cov.get('total', 0)} "
                  f"(PASS={cov.get('positive', 0)} "
                  f"NEG={cov.get('negative_with_evidence', 0)} "
                  f"SHALLOW={cov.get('shallow_negative', 0)} "
                  f"SKIP={cov.get('skipped', 0)} "
                  f"未测={cov.get('untested', 0)} "
                  f"OPEN={cov.get('open_risk', 0)} "
                  f"NEEDS={cov.get('needs_account', 0)})")
        led = (res.get("coverage_ledger") or {}).get("stats")
        if led:
            print(f"coverage-ledger: 闭合 {led.get('closed', 0)}/{led.get('total', 0)} "
                  f"(confirmed={led.get('confirmed', 0)} "
                  f"not_vulnerable={led.get('not_vulnerable', 0)} "
                  f"not_applicable={led.get('not_applicable', 0)} "
                  f"not_tested={led.get('not_tested', 0)} "
                  f"blocked={led.get('blocked', 0)} "
                  f"high_value_open={led.get('high_value_open', 0)})")
            if res.get("coverage_ledger_path"):
                print(f"coverage-ledger 文件: {res['coverage_ledger_path']}")
        gate = res.get("session_gate")
        if gate:
            reasons = gate.get("reasons") or []
            first = reasons[0] if reasons else {}
            why = first.get("predicate") or "ok"
            action = first.get("action") or first.get("detail") or ""
            suffix = f" ｜ {why}{(': ' + action) if action else ''}" if reasons else ""
            print(f"session-gate: {gate.get('result')}{suffix} ｜ reasons={len(reasons)}")
        if res.get("final_report_path"):
            print(f"综合报告: {res['final_report_path']} ({res.get('final_report_status')})")
        sat = res.get("saturation_reached")
        if sat is not None:
            print(f"discovery 饱和: {'是（连续来源不再新增 endpoint）' if sat else '否'}")
        # P1-2：报告质量 vs 覆盖完成度 分开打印（accepted/hit=报告质量；其余=覆盖完成度）
        hit_str = _oracle_hit_str(args.oracle, res) if args.oracle else "N/A"
        print(f"摘要: accepted={len(res.get('accepted', []))} hit={hit_str} "
              f"high_value_open={led.get('high_value_open', 0)} "
              f"shallow={(cov or {}).get('shallow_negative', 0)} "
              f"next_actions={res.get('open_next_actions_count', 0)}")
        _print_open_high_value(res)
    elif res.get("reason"):
        print(f"原因: {res['reason']}")
        if res.get("cmd"):
            print(f"暂停命令: {res['cmd']}")
    if res.get("verified"):
        print(f"确定性复验: {res['verified']}")
    if res.get("interrupted"):
        print(f"⚠ 流式中断已抢救（{res.get('error')}）；已落盘证据在 {wd}")
        print(f"  断点续测: python3 run.py --sid {sid} --resume --target {args.target} --authz <...> [--cookie/--bearer ...]")
    print(f"证据/报告/状态/日志: {wd}（事件流见 events.jsonl）")
    return 0 if res["status"] == "vuln_found" else 1


if __name__ == "__main__":
    raise SystemExit(main())
