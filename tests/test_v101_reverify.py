"""v10.1 证据复验信任根 — 方案 §3.6 十三场景 + §6 验收锚定断言。

本地 mock 零外网：单元级复验走注入的 mock transport；端到端 checkpoint
链路的复验流量全部落在 127.0.0.1 的本地 mock HTTP server。
"""
from __future__ import annotations

import json
import pathlib
import re
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engine.project_state import ProjectStateStore
from engine.reporting.validate import validate_finding, validate_run_artifacts
from engine.reverify import (
    ReverifyBudget,
    load_identities,
    probe_rejects,
    reverify_finding,
)
from engine.skill_runtime import checkpoint_direct_run, initialize_direct_run
from engine.verify import Request, Response, _guard
from tests.test_reporting_proof_contract import _idor_fixture

ALLOWED = ["https://t.example/"]

# ── 本地 mock server（零外网）────────────────────────────────────────────
class _MockTarget:
    """127.0.0.1 上的可编程靶端。

    routes: {path: {"auth": (status, body), "anon": (status, body)}}
    带 sid=attacker-b / sid=owner-a cookie 走 auth 分支，否则 anon。
    access_log 记录每次命中的 path。
    """

    def __init__(self, routes: dict[str, dict]):
        self.routes = routes
        self.access_log: list[tuple[str, str]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                cookie = self.headers.get("Cookie", "")
                authed = "sid=" in cookie
                route = outer.routes.get(self.path) or {
                    "auth": (404, '{"error":"not found"}'),
                    "anon": (404, '{"error":"not found"}'),
                }
                status, body = route["auth" if authed else "anon"]
                outer.access_log.append((self.path, "auth" if authed else "anon"))
                payload = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):  # 静默
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def host_header(self) -> str:
        return f"127.0.0.1:{self.port}"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    @property
    def requests(self) -> int:
        return len(self.access_log)

    @classmethod
    def idor_target(cls) -> "_MockTarget":
        """带 marker 的 IDOR 靶：auth 200 含 owner-a 订单，anon 401。"""
        return cls({
            "/api/orders/1001": {
                "auth": (200, '{"order_id":"1001","owner":"owner-a","amount":10}'),
                "anon": (401, '{"error":"unauthorized"}'),
            },
            "/api/orders/2002": {
                "auth": (403, '{"error":"not order owner"}'),
                "anon": (403, '{"error":"not order owner"}'),
            },
            "/api/ping": {
                "auth": (200, '{"ok":"pong-unique-control"}'),
                "anon": (200, '{"ok":"pong-unique-control"}'),
            },
        })


# ── fixtures ─────────────────────────────────────────────────────────────
def _write(path: pathlib.Path, text: str | dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, dict):
        text = json.dumps(text, ensure_ascii=False, indent=2)
    path.write_text(text, encoding="utf-8")


def _identities(run: pathlib.Path, *, extra: dict | None = None) -> None:
    value = {
        "identities": {
            "user_b": {"Cookie": "sid=attacker-b"},
            "owner": {"Cookie": "sid=owner-a"},
            "anon": {},
            **(extra or {}),
        }
    }
    _write(run / "identities.json", json.dumps(value))


def _replay_section(**overrides) -> dict:
    section = {
        "kind": "readback",
        "request_file": "request_attacker.http",
        "identity": "user_b",
        "baseline_identity": "anon",
        "expectation": {
            "status": 200,
            "required_markers": ['"owner":"owner-a"'],
            "absent_markers": [],
        },
        "max_age_hours": 72,
    }
    section.update(overrides)
    return section


def _finding_with_replay(run: pathlib.Path, replay: dict | None, name="finding_001"):
    fdir = _idor_fixture(run)
    finding = json.loads((fdir / "finding.json").read_text(encoding="utf-8"))
    if replay is not None:
        finding["verification"]["replay"] = replay
    _write(fdir / "finding.json", json.dumps(finding, ensure_ascii=False, indent=2))
    return fdir, finding


def _vuln_transport(log: list):
    """IDOR 端点：带 sid cookie 的身份拿到 owner-a 订单；匿名 401。

    与 _MockTarget.idor_target 同语义（transport 注入版，供单元级场景用）。
    """
    def transport(req: Request) -> Response:
        log.append(req)
        if "sid=" not in req.headers.get("Cookie", ""):
            return Response(401, {}, '{"error":"unauthorized"}')
        return Response(200, {}, '{"order_id":"1001","owner":"owner-a","amount":10}')
    return transport


def _fixed_transport(log: list, status: int, body: str):
    def transport(req: Request) -> Response:
        log.append(req)
        return Response(status, {}, body)
    return transport


def _sink_registry():
    registry: dict[str, str] = {}

    def sink(text: str) -> str:
        name = f"replay_{len(registry)}.http"
        registry[name] = text
        return f"findings/finding_001/{name}"

    return registry, sink


# ── 场景 1：Direct 端到端升格（核心） ─────────────────────────────────────
def _prepared_run(tmp_path, name="run-1", target: _MockTarget | None = None):
    """finding 包 + identities + inventory → init → confirmed observation。

    所有 request 文件与 target 都指向本地 mock（零外网）。
    """
    assert target is not None
    run = tmp_path / name
    _finding_with_replay(run, _replay_section())
    _identities(run)
    fdir = run / "findings" / "finding_001"
    for filename in ("request_owner.http", "request_attacker.http"):
        cookie = "sid=owner-a" if "owner" in filename else "sid=attacker-b"
        _write(fdir / filename,
               f"GET {target.base}/api/orders/1001 HTTP/1.1\n"
               f"Host: {target.host_header}\nCookie: {cookie}\n\n")
    _write(fdir / "request_denied.http",
           f"GET {target.base}/api/orders/2002 HTTP/1.1\n"
           f"Host: {target.host_header}\nCookie: sid=attacker-b\n\n")
    _write(fdir / "poc.sh",
           f"curl {target.base}/api/orders/1001 -H 'Cookie: sid=attacker-b'\n")
    finding = json.loads((fdir / "finding.json").read_text())
    finding["target"] = f"{target.base}/api/orders/1001"
    _write(fdir / "finding.json", finding)
    _write(run / "inventory.json", {
        "endpoints": [{
            "endpoint": f"{target.base}/api/orders/1001", "method": "GET",
            "params": ["id"], "roles": ["unknown"], "vuln_classes": ["idor"],
        }],
    })
    initialize_direct_run(
        run_dir=run, target=target.base,
        inventory_path=run / "inventory.json")
    from engine.skill_runtime import record_observation
    ledger_value = json.loads((run / "coverage-ledger.json").read_text())
    surface_id = ledger_value["surfaces"][0]["surface_id"]
    record_observation(run_dir=run, agent_id="agent", observation={
        "schema_version": 1, "observation_id": "obs-1",
        "surface_id": surface_id, "outcome": "confirmed",
        "evidence_refs": ["findings/finding_001/finding.json"],
    })
    return run


def test_s1_direct_end_to_end_promotion(tmp_path):
    target = _MockTarget.idor_target()
    run = _prepared_run(tmp_path, target=target)
    project_dir = tmp_path / "project"
    checkpoint = checkpoint_direct_run(run, project_dir=project_dir)
    promotion = checkpoint["project_promotion"]
    match_rows = [row for row in promotion["findings"] if row.get("outcome") == "match"]
    assert match_rows, promotion
    assert promotion["commit"]["performed"] is True
    assert promotion["trust_basis"] == "evidence_reverified"
    assert promotion["trust_level"] == "hallucination_filter_not_integrity_boundary"

    # finding_validation.json 含 reverify 段（自指摘要覆盖）
    validation = json.loads((run / "finding_validation.json").read_text())
    assert "reverify" in validation
    assert validation["reverify"]["commit"]["performed"] is True

    # project_state 升格记录
    state = json.loads((project_dir / "project_state.json").read_text())
    records = list(state["finding_registry"].values())
    assert records and all(
        record.get("trust_basis") == "evidence_reverified" for record in records)
    assert any(record.get("last_reverified_at") for record in records)
    evidence_ref = records[0].get("evidence_ref", "")
    assert evidence_ref.startswith("findings/")
    # 重放包落盘
    assert (project_dir / "sessions" / run.name / "findings" / "finding_001" /
            evidence_ref.split("/")[-1]).is_file()


# ── 场景 2：mismatch → 不升格、project_state 零写入 ───────────────────────
def test_s2_mismatch_blocks_promotion(tmp_path):
    run = tmp_path / "run-2"
    replay = _replay_section(
        expectation={"status": 200, "required_markers": ['"owner":"someone-else"'],
                     "absent_markers": []})
    _finding_with_replay(run, replay)
    _identities(run)
    log: list = []
    registry, sink = _sink_registry()
    result = reverify_finding(
        json.loads((run / "findings" / "finding_001" / "finding.json").read_text()),
        run / "findings" / "finding_001",
        identities=load_identities(run), authorized_scopes=ALLOWED,
        evidence_sink=sink, budget=ReverifyBudget(),
        transport=_vuln_transport(log))
    assert result["outcome"] == "mismatch"
    assert "required_markers" in result["reason"]

    state = tmp_path / "project" / "project_state.json"
    assert not state.exists()


# ── 场景 3：403 细分 / 401 barrier ───────────────────────────────────────
def test_s3_forbidden_control_and_401(tmp_path):
    run = tmp_path / "run-3"
    _finding_with_replay(run, _replay_section())
    _identities(run)
    finding = json.loads((run / "findings" / "finding_001" / "finding.json").read_text())

    # 3a: 403 + control_url 同身份 2xx → mismatch
    replay = _replay_section(control_url="https://t.example/api/ping")
    finding["verification"]["replay"] = replay
    _write(run / "findings" / "finding_001" / "finding.json",
           json.dumps(finding, ensure_ascii=False))
    log: list = []

    def transport_403_with_open_control(req: Request) -> Response:
        log.append(req)
        if req.url.endswith("/api/ping"):
            return Response(200, {}, '{"ok":"pong-unique"}')
        return Response(403, {}, '{"error":"forbidden"}')

    registry, sink = _sink_registry()
    result = reverify_finding(
        finding, run / "findings" / "finding_001",
        identities=load_identities(run), authorized_scopes=ALLOWED,
        evidence_sink=sink, budget=ReverifyBudget(),
        transport=transport_403_with_open_control)
    assert result["outcome"] == "mismatch"

    # 3b: 无 control_url + 403 → barrier
    log.clear()
    registry, sink = _sink_registry()
    result = reverify_finding(
        finding, run / "findings" / "finding_001",
        identities=load_identities(run), authorized_scopes=ALLOWED,
        evidence_sink=sink, budget=ReverifyBudget(),
        transport=_fixed_transport(log, 403, '{"error":"forbidden"}'))
    assert result["outcome"] == "barrier"

    # 3c: 401 → barrier（会话过期）
    registry, sink = _sink_registry()
    result = reverify_finding(
        finding, run / "findings" / "finding_001",
        identities=load_identities(run), authorized_scopes=ALLOWED,
        evidence_sink=sink, budget=ReverifyBudget(),
        transport=_fixed_transport(log, 401, '{"error":"unauthorized"}'))
    assert result["outcome"] == "barrier"


# ── 场景 4：scope 外 URL → blocked、零请求 ───────────────────────────────
def test_s4_out_of_scope_blocked_zero_requests(tmp_path):
    run = tmp_path / "run-4"
    replay = _replay_section()
    fdir, finding = _finding_with_replay(run, replay)
    # 换成 scope 外 URL
    _write(fdir / "request_attacker.http",
           "GET /api/orders/1001 HTTP/1.1\nHost: evil.example\n\n")
    _identities(run)
    log: list = []
    registry, sink = _sink_registry()
    result = reverify_finding(
        finding, fdir,
        identities=load_identities(run), authorized_scopes=ALLOWED,
        evidence_sink=sink, budget=ReverifyBudget(),
        transport=_vuln_transport(log))
    # _guard 的 PermissionError 在 reverify 内转为 blocked（不冒泡）
    assert result["outcome"] == "blocked"
    assert "guard_denied" in result["reason"] or "越权" in result["reason"]
    assert log == []  # mock 访问日志 0 —— _guard 拒绝发生在 transport 之前


# ── 场景 5：marker 特异度门 ──────────────────────────────────────────────
def test_s5_marker_specificity_gate(tmp_path):
    run = tmp_path / "run-5"
    _finding_with_replay(run, None)
    _identities(run)
    finding = json.loads((run / "findings" / "finding_001" / "finding.json").read_text())

    weak_markers = [".*", ".+", "status", "200", "true", "ok"]
    for marker in weak_markers:
        replay = _replay_section(
            expectation={"status": 200, "required_markers": [marker],
                         "absent_markers": []})
        finding["verification"]["replay"] = replay
        registry, sink = _sink_registry()
        result = reverify_finding(
            finding, run / "findings" / "finding_001",
            identities=load_identities(run), authorized_scopes=ALLOWED,
            evidence_sink=sink, budget=ReverifyBudget(),
            transport=_vuln_transport([]))
        assert result["outcome"] == "blocked", marker
        assert "弱模式" in result["reason"] or "marker" in result["reason"]

    # marker 未命中原始响应 → 拒收（validate 层）
    replay = _replay_section(
        expectation={"status": 200, "required_markers": ['"nope":"never"'],
                     "absent_markers": []})
    finding["verification"]["replay"] = replay
    _write(run / "findings" / "finding_001" / "finding.json",
           json.dumps(finding, ensure_ascii=False))
    res = validate_finding(
        finding, run / "findings" / "finding_001" / "finding.json", run,
        authorized_hosts=ALLOWED)
    assert not res.ok
    assert any("not found in any proof response" in r for r in res.reasons)

    # marker 位于 64KB 截断点之后 → 拒收（口径一致）
    marker = '"tail_marker":"x1y2"'
    padded = "A" * 65600 + marker
    fdir = run / "findings" / "finding_001"
    _write(fdir / "response_attacker.http",
           f"HTTP/1.1 200 OK\n\n{{\"pad\":\"{padded[:1]}\",\"tail_marker\":\"x1y2\"}}")
    # 直接复用 reverify 层截断语义断言：body 截断后 marker 不可见
    from engine.reverify import _subject
    assert marker not in _subject(padded)
    assert marker in padded


# ── 场景 6：全类差分基线 + 信封 marker 攻击 ───────────────────────────────
def test_s6_envelope_marker_baseline_trap(tmp_path):
    run = tmp_path / "run-6"
    _finding_with_replay(run, None)
    _identities(run)
    finding = json.loads((run / "findings" / "finding_001" / "finding.json").read_text())

    # 6a: 缺 baseline_identity → 拒收（validate 层）
    replay = _replay_section()
    replay.pop("baseline_identity")
    finding["verification"]["replay"] = replay
    _write(run / "findings" / "finding_001" / "finding.json",
           json.dumps(finding, ensure_ascii=False))
    res = validate_finding(
        finding, run / "findings" / "finding_001" / "finding.json", run,
        authorized_hosts=ALLOWED)
    assert not res.ok
    assert any("baseline_identity" in r for r in res.reasons)

    # 6b: 信封 marker 攻击 —— 非授权类 finding 用 "code":0 信封 marker，
    # anon 基线也返回相同信封 → 必须被差分基线杀掉（探针集杀不掉该形态）
    replay = _replay_section(
        expectation={"status": 200, "required_markers": ['"code":0'],
                     "absent_markers": []})
    finding["verification"]["replay"] = replay
    _write(run / "findings" / "finding_001" / "finding.json",
           json.dumps(finding, ensure_ascii=False))
    # 探针集确实杀不掉 '"code":0'（证明这是基线防线的价值）
    assert not probe_rejects('"code":0')
    log: list = []

    def envelope_transport(req: Request) -> Response:
        log.append(req)
        cookie = req.headers.get("Cookie", "")
        if "sid=" not in cookie:
            return Response(200, {}, '{"code":0,"msg":"ok"}')  # anon 同信封
        return Response(200, {}, '{"code":0,"msg":"ok"}')

    registry, sink = _sink_registry()
    result = reverify_finding(
        finding, run / "findings" / "finding_001",
        identities=load_identities(run), authorized_scopes=ALLOWED,
        evidence_sink=sink, budget=ReverifyBudget(),
        transport=envelope_transport)
    assert result["outcome"] == "mismatch"
    assert "差分基线" in result["reason"] or "baseline" in result["reason"]

    # 6c: 基线不命中 → 正常 match
    log.clear()

    def real_idor_transport(req: Request) -> Response:
        log.append(req)
        cookie = req.headers.get("Cookie", "")
        if "sid=" not in cookie:
            return Response(401, {}, '{"code":401,"msg":"login required"}')
        return Response(200, {}, '{"order_id":"1001","owner":"owner-a","amount":10}')

    replay = _replay_section()
    finding["verification"]["replay"] = replay
    _write(run / "findings" / "finding_001" / "finding.json",
           json.dumps(finding, ensure_ascii=False))
    registry, sink = _sink_registry()
    result = reverify_finding(
        finding, run / "findings" / "finding_001",
        identities=load_identities(run), authorized_scopes=ALLOWED,
        evidence_sink=sink, budget=ReverifyBudget(),
        transport=real_idor_transport)
    assert result["outcome"] == "match"
    assert result["baseline_outcome"] == "match"


# ── 场景 7：Direct 继承消费 ──────────────────────────────────────────────
def _promoted_project(tmp_path) -> tuple[pathlib.Path, pathlib.Path, _MockTarget]:
    """场景 1 的最小复刻：产出含 evidence_reverified cell 的 project。"""
    target = _MockTarget.idor_target()
    run_src = _prepared_run(tmp_path, "run-src", target=target)
    project = tmp_path / "project"
    checkpoint_direct_run(run_src, project_dir=project)
    return run_src, project, target


def test_s7_inheritance_ttl_and_mismatch(tmp_path):
    run_src, project, target = _promoted_project(tmp_path)

    # 7a: TTL 内免复验继承（第二轮 init --project-dir）
    run2 = tmp_path / "run-2"
    _identities(run2)
    _write(run2 / "inventory.json", {
        "endpoints": [{
            "endpoint": f"{target.base}/api/other", "method": "GET",
            "params": [], "roles": ["any"],
        }],
    })
    requests_before = target.requests
    init2 = initialize_direct_run(
        run_dir=run2, target=target.base,
        inventory_path=run2 / "inventory.json", project_dir=project)
    assert init2["project_inheritance"]["inherited"] >= 1
    # TTL 内免复验：本轮继承没有发出任何复验流量
    assert target.requests == requests_before
    ledger2 = json.loads((run2 / "coverage-ledger.json").read_text())
    inherited = [s for s in ledger2["surfaces"] if s.get("inherited_from_project_state")]
    assert inherited, ledger2["surfaces"]
    surface = inherited[0]
    assert surface["status"] == "confirmed"
    assert surface["in_run_scope"] is False
    assert surface.get("inherited_from_blackboard") is True
    # inventory 行同步注入（P2-d①）
    inv = json.loads((run2 / "inventory.json").read_text())
    assert any(
        row.get("source") == "project_state_inherited"
        for row in inv["endpoints"])

    # 7b: mock 改响应 + 超 TTL → 继承复验 mismatch → 不注入 + revalidation_required
    state_path = project / "project_state.json"
    state = json.loads(state_path.read_text())
    for cell in state["cell_registry"].values():
        if cell.get("trust_basis") == "evidence_reverified":
            cell["last_reverified_at"] = "2020-01-01T00:00:00Z"
    state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2))
    # 靶端对象已删除：auth 分支改 404（回查状态不吻合 → mismatch）
    target.routes["/api/orders/1001"]["auth"] = (404, '{"error":"gone"}')
    run3 = tmp_path / "run-3"
    _identities(run3)
    _write(run3 / "inventory.json", {
        "endpoints": [{
            "endpoint": f"{target.base}/api/other", "method": "GET",
            "params": [], "roles": ["any"],
        }],
    })
    init3 = initialize_direct_run(
        run_dir=run3, target=target.base,
        inventory_path=run3 / "inventory.json", project_dir=project)
    assert init3["project_inheritance"]["inherited"] == 0
    ledger3 = json.loads((run3 / "coverage-ledger.json").read_text())
    assert not [
        s for s in ledger3["surfaces"] if s.get("inherited_from_project_state")]
    inherited_state = json.loads((run3 / "state" / "inherited-reverify.json").read_text())
    mismatched = [row for row in inherited_state["cells"]
                  if row.get("outcome") == "mismatch"]
    assert mismatched, inherited_state
    assert inherited_state["revalidation_required"] >= 1


# ── 场景 8：清除条件（revalidation_history 追加、禁 pop）──────────────────
def test_s8_revalidation_clear_conditions(tmp_path):
    project = tmp_path / "project"
    store = ProjectStateStore(project, project_scope=ALLOWED)
    # 证据文件（attest 按 run_id 解析 sessions/<run_id>/，每个 commit run 都放）
    for run_id in ("run-old", "run-mismatch", "run-clear"):
        ev_dir = project / "sessions" / run_id / "findings" / "finding_001"
        ev_dir.mkdir(parents=True, exist_ok=True)
        (ev_dir / "replay_0.http").write_text(
            "HTTP/1.1 200 OK\n\nbody\n", encoding="utf-8")
    finding = {
        "acceptance_status": "accepted", "proof_status": "confirmed",
        "claim_kind": "root_finding", "id": "finding_001", "title": "x",
        "vuln_class": "idor",
        "target": "https://t.example/api/orders/1001",
        "endpoint": "/api/orders/1001", "method": "GET", "param": "id",
        "affected_roles": ["unknown"],
        "assets": ["https://t.example:443"],
        "proof_files": ["findings/finding_001/replay_0.http"],
        "evidence_refs": ["findings/finding_001/replay_0.http"],
        "reverify": {"outcome": "match", "baseline_outcome": "match",
                     "evidence_ref": "findings/finding_001/replay_0.http",
                     "reverified_at": "2026-01-01T00:00:00Z"},
    }
    store.commit_run("run-old", findings=[dict(finding)],
                     trust_basis="evidence_reverified")
    state_path = project / "project_state.json"
    state = json.loads(state_path.read_text())
    fp = next(iter(state["finding_registry"]))
    # 模拟 v9.0 冲突语义：后续 canonical negative 命中 confirmed cell
    record = state["finding_registry"][fp]
    record["status"] = "needs_revalidation"
    record["revalidation_reason"] = "later canonical negative conflicts"
    record["conflicting_run"] = "run-neg"
    state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2))

    # 2) 条件不满足（outcome=mismatch）→ 保持 revalidation、不 merge 本行
    finding_mismatch = dict(finding)
    finding_mismatch["reverify"] = {
        "outcome": "mismatch", "baseline_outcome": None,
        "evidence_ref": "findings/finding_001/replay_0.http"}
    ProjectStateStore(project, project_scope=ALLOWED).commit_run(
        "run-mismatch", findings=[dict(finding_mismatch)],
        trust_basis="evidence_reverified")
    after = json.loads(state_path.read_text())
    reg = after["finding_registry"][fp]
    assert reg["status"] == "needs_revalidation"  # 未清除
    assert reg["revalidation_reason"] == "later canonical negative conflicts"
    assert reg["conflicting_run"] == "run-neg"
    assert not reg.get("revalidation_history")

    # 3) 条件满足（match + baseline match）→ 清除 + history 追加 + 字段保留
    state = json.loads(state_path.read_text())
    state["run_history"].pop("run-mismatch", None)
    state["merged_run_ids"] = [
        r for r in state["merged_run_ids"] if r != "run-mismatch"]
    state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2))
    ProjectStateStore(project, project_scope=ALLOWED).commit_run(
        "run-clear", findings=[dict(finding)],
        trust_basis="evidence_reverified")
    final = json.loads(state_path.read_text())
    reg = final["finding_registry"][fp]
    assert reg["status"] == "confirmed"
    # 禁 pop：原字段保留
    assert reg["revalidation_reason"] == "later canonical negative conflicts"
    assert reg["conflicting_run"] == "run-neg"
    history = reg.get("revalidation_history") or []
    assert len(history) == 1
    assert history[0]["revalidation_reason"] == "later canonical negative conflicts"
    assert history[0]["conflicting_run"] == "run-neg"
    assert history[0]["cleared_by_run"] == "run-clear"
    assert history[0]["cleared_by"] == "evidence_reverified"


# ── 场景 9：预算 50 ─────────────────────────────────────────────────────
def test_s9_budget_exactly_50(tmp_path):
    run = tmp_path / "run-9"
    _finding_with_replay(run, _replay_section())
    _identities(run)
    finding = json.loads((run / "findings" / "finding_001" / "finding.json").read_text())
    log: list = []
    budget = ReverifyBudget(50)
    # 60 个待复验 finding：第 51 个请求起被预算挡住。
    # 单 finding 消耗 2 请求（回查+基线）→ 25 个 match 后预算耗尽。
    registry, sink = _sink_registry()
    results = []
    for i in range(60):
        result = reverify_finding(
            finding, run / "findings" / "finding_001",
            identities=load_identities(run), authorized_scopes=ALLOWED,
            evidence_sink=sink, budget=budget, transport=_vuln_transport(log),
            throttle=type("T", (), {"throttle": staticmethod(lambda k: None)})())
        results.append(result)
        if result["outcome"] == "barrier" and "预算" in result.get("reason", ""):
            break
    matched = [r for r in results if r["outcome"] == "match"]
    rate_limited = [r for r in results if r["outcome"] == "barrier"
                    and "预算" in r.get("reason", "")]
    assert len(matched) == 25
    assert len(rate_limited) >= 1
    assert budget.used == 50
    assert len(log) == 50  # 计数恰 50（含差分基线）


# ── 场景 10：无 replay 段行为不变 + authority 通道回归 ────────────────────
def test_s10_compatibility_no_replay_and_authority_channel(tmp_path):
    from tests.test_v89_delivery_contract import _complete_finding_run
    from engine.finalize import finalize_run

    # 10a: 无 replay 段的 finding 正常校验通过（既有测试兜底之外再钉一次）
    run = tmp_path / "run-10"
    _finding_with_replay(run, None)
    _identities(run)
    finding = json.loads((run / "findings" / "finding_001" / "finding.json").read_text())
    res = validate_finding(
        finding, run / "findings" / "finding_001" / "finding.json", run,
        authorized_hosts=ALLOWED)
    assert res.ok, res.reasons

    # 10b: authority（MockAdapter 等价物：authority_trusted=True）通道升格
    # 逐字节不变，commit 记 trust_basis=containment（旧通道回归断言）。
    project = tmp_path / "project-a"
    run_dir = project / "sessions" / "run-a"
    _complete_finding_run(run_dir)
    authority = project / ".atoolkit"
    finalize_run(
        run_dir=run_dir, project_dir=project, authority_dir=authority,
        authority_trusted=True,
        authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture",
        primary_target="https://t.example/")
    state = json.loads((project / "project_state.json").read_text())
    cells = [c for c in state["cell_registry"].values() if c["status"] == "confirmed"]
    assert cells
    assert all(c.get("trust_basis") == "containment" for c in cells)


# ── 场景 11：限速实测（注入时钟）──────────────────────────────────────────
def test_s11_throttle_min_interval(tmp_path):
    from engine.throttle import HostThrottle

    run = tmp_path / "run-11"
    _finding_with_replay(run, _replay_section())
    _identities(run)
    finding = json.loads((run / "findings" / "finding_001" / "finding.json").read_text())

    stamps: list[float] = []
    tick = [1000.0]

    def clock() -> float:
        return tick[0]

    class FakeThrottle:
        """注入式节流器：按 1/rps 推进虚拟时钟并记录时间戳。"""
        def __init__(self, rps: float):
            self.min_interval = 1.0 / rps if rps > 0 else 0.0
            self.last = None

        def throttle(self, host_key: str) -> None:
            now = tick[0]
            if self.last is not None and self.min_interval > 0:
                wait = self.min_interval - (now - self.last)
                if wait > 0:
                    tick[0] = now = self.last + self.min_interval
            self.last = now
            stamps.append(now)

    registry, sink = _sink_registry()
    result = reverify_finding(
        finding, run / "findings" / "finding_001",
        identities=load_identities(run), authorized_scopes=ALLOWED,
        evidence_sink=sink, budget=ReverifyBudget(),
        transport=_vuln_transport([]), throttle=FakeThrottle(1.0))
    assert result["outcome"] == "match"
    assert len(stamps) == 2  # 回查 + 基线
    assert stamps[1] - stamps[0] >= 1.0  # 同 host 相邻复验间隔 ≥ 1/rps


# ── 场景 12：重复 checkpoint 语义 ────────────────────────────────────────
def test_s12_repeated_checkpoint_idempotent_and_conflict(tmp_path):
    run, project, target = _promoted_project(tmp_path)

    # 12a: 输入完全相同的重跑 → 幂等返回，不崩溃
    checkpoint_a = checkpoint_direct_run(run, project_dir=project)
    promo_a = checkpoint_a["project_promotion"]
    assert promo_a["commit"]["idempotent"] is True
    assert promo_a["commit"]["performed"] is False
    state_before = json.loads((project / "project_state.json").read_text())
    revision_before = state_before["revision"]

    # 12b: 改 finding 后重跑 → commit_conflict，不崩溃、无二次写入
    fdir = run / "findings" / "finding_001"
    finding = json.loads((fdir / "finding.json").read_text())
    finding["title"] = "篡改后的标题"
    _write(fdir / "finding.json", json.dumps(finding, ensure_ascii=False, indent=2))
    from engine.skill_runtime import record_observation
    # checkpoint 直接重跑（finding 变了 → dir digest 不同）
    checkpoint_b = checkpoint_direct_run(run, project_dir=project)
    promo_b = checkpoint_b["project_promotion"]
    conflicts = [row for row in promo_b["findings"] if row.get("commit_conflict")]
    assert conflicts, promo_b
    assert promo_b["commit"]["conflict"] is True
    state_after = json.loads((project / "project_state.json").read_text())
    assert state_after["revision"] == revision_before  # 无二次写入


# ── 场景 13：commit 可观测性（delta=0 告警）───────────────────────────────
def test_s13_delta_zero_warning(tmp_path):
    """复验 match 但 root_findings 增量为 0 → reverify 段出现告警行。

    构造方式：第一个 run 升格 finding（registry 建立指纹）；第二个 run
    提升同一 finding（同 endpoint/param/role/root_cause → 同指纹去重）——
    复验仍 match 但 root_findings 增量为 0 → 告警（升格结果可查）。
    """
    target = _MockTarget.idor_target()
    project = tmp_path / "project"
    run_a = _prepared_run(tmp_path, "run-13a", target=target)
    first = checkpoint_direct_run(run_a, project_dir=project)
    assert first["project_promotion"]["commit"]["performed"] is True
    assert first["project_promotion"]["commit"]["delta"].get("root_findings") == 1

    run_b = _prepared_run(tmp_path, "run-13b", target=target)
    second = checkpoint_direct_run(run_b, project_dir=project)
    promo = second["project_promotion"]
    assert promo["commit"]["performed"] is True
    matched_rows = [row for row in promo["findings"] if row.get("promoted")]
    assert len(matched_rows) == 1, promo["findings"]
    assert promo["commit"]["delta"].get("root_findings") == 0
    warnings = promo["commit"]["warnings"]
    assert any(w.get("code") == "promotion_not_reflected" for w in warnings), promo


# ── §6.4 锚定断言：authority_trusted 字面量位置钉死 ───────────────────────
def test_s14_authority_trusted_anchor():
    source = (pathlib.Path(__file__).resolve().parents[1]
              / "engine" / "skill_runtime.py").read_text(encoding="utf-8")
    lines = source.splitlines()
    literal_lines = [
        index + 1 for index, line in enumerate(lines)
        if re.search(r'"authority_trusted":\s*False', line)
    ]
    # 基线 7 处字面量（docstring 之外）：6 既有 + 1 处新增（_promote_findings_to_project）
    assert len(literal_lines) == 7, literal_lines
    # 新增的那一处必须位于 _promote_findings_to_project 函数体内
    func_start = next(
        index for index, line in enumerate(lines)
        if line.startswith("def _promote_findings_to_project"))
    func_end = next(
        index for index in range(func_start + 1, len(lines))
        if lines[index].startswith("def "))
    inside = [line for line in literal_lines if func_start < line <= func_end]
    assert len(inside) == 1, (literal_lines, func_start, func_end)
    # 该行前两行内带锚定注释（§6.4 要求带注释）
    assert any(
        "§6.4" in lines[inside[0] - offset]
        for offset in (1, 2, 3)), lines[inside[0] - 3:inside[0]]


# ── §6.3 端到端干跑：CLI exit 0 + 弱模式篡改拒收 ─────────────────────────
def test_s16_cli_end_to_end_and_weak_marker_tamper(tmp_path, capsys):
    from engine.skill_runtime import main as cli_main

    target = _MockTarget.idor_target()
    run = _prepared_run(tmp_path, "run-cli", target=target)
    project = tmp_path / "project"

    rc = cli_main([
        "checkpoint", "--run-dir", str(run), "--project-dir", str(project)])
    assert rc == 0
    validation = json.loads((run / "finding_validation.json").read_text())
    assert "reverify" in validation
    state = json.loads((project / "project_state.json").read_text())
    assert any(
        record.get("trust_basis") == "evidence_reverified"
        for record in state["finding_registry"].values())
    assert (project / "sessions" / run.name / "findings" / "finding_001").is_dir()

    # 篡改 expectation 为弱模式 → schema 门拒收（rejected 段出现记录），
    # project_state 无该 finding 的二次记录。
    fdir = run / "findings" / "finding_001"
    finding = json.loads((fdir / "finding.json").read_text())
    finding["verification"]["replay"]["expectation"]["required_markers"] = ["status"]
    _write(fdir / "finding.json", finding)
    revision_before = json.loads((project / "project_state.json").read_text())["revision"]
    rc2 = cli_main([
        "checkpoint", "--run-dir", str(run), "--project-dir", str(project)])
    assert rc2 == 0
    validation2 = json.loads((run / "finding_validation.json").read_text())
    # 拒收记录：弱模式 marker 拒收出现在 proof_pending_or_rejected
    rejected = validation2["proof_pending_or_rejected"]
    assert any(
        "verification.replay" in str(row.get("reasons") or [])
        and "weak" in json.dumps(row.get("reasons") or [], ensure_ascii=False)
        for row in rejected), rejected
    # project_state 无二次写入（revision 不变）
    assert json.loads((project / "project_state.json").read_text())["revision"] == revision_before


# ── §6.6 throttle 双方 import 断言 ──────────────────────────────────────
def test_s15_throttle_shared_by_recon_and_reverify():
    import engine.recon.fetch as fetch_module
    import engine.reverify as reverify_module
    assert fetch_module.HostThrottle is reverify_module.HostThrottle


# ── Gate-B 修复回归（2026-09-02，审核者修复 + 独立复审）────────────────────
_NOOP_THROTTLE = type("T", (), {"throttle": staticmethod(lambda k: None)})()


def test_s17_baseline_budget_exhausted_is_barrier(tmp_path):
    """Gate-B P1：预算只够攻击身份一次时，基线拿 <rate_budget> 哨兵——
    修复前静默 match（主防线被跳过），修复后必须 barrier 且基线零流量。"""
    run = tmp_path / "run-17"
    fdir, finding = _finding_with_replay(run, _replay_section())
    _identities(run)
    registry, sink = _sink_registry()
    log: list = []
    budget = ReverifyBudget(1)
    result = reverify_finding(
        finding, fdir,
        identities=load_identities(run), authorized_scopes=ALLOWED,
        evidence_sink=sink, budget=budget, transport=_vuln_transport(log),
        throttle=_NOOP_THROTTLE)
    assert result["outcome"] == "barrier"
    assert "基线" in result["reason"]
    assert result.get("baseline_outcome") == "barrier"
    assert len(log) == 1  # 攻击身份一次；基线零流量


def test_s18_baseline_5xx_is_barrier(tmp_path):
    """Gate-B P1 同源：基线 5xx = 基线不可判定（误差页面天然无 marker），
    不得当作差分证据放行。"""
    run = tmp_path / "run-18"
    fdir, finding = _finding_with_replay(run, _replay_section())
    _identities(run)
    registry, sink = _sink_registry()
    log: list = []

    def transport(req: Request) -> Response:
        log.append(req)
        if "sid=" not in req.headers.get("Cookie", ""):
            return Response(503, {}, '{"error":"down"}')
        return Response(200, {}, '{"order_id":"1001","owner":"owner-a","amount":10}')

    result = reverify_finding(
        finding, fdir,
        identities=load_identities(run), authorized_scopes=ALLOWED,
        evidence_sink=sink, budget=ReverifyBudget(50), transport=transport,
        throttle=_NOOP_THROTTLE)
    assert result["outcome"] == "barrier"
    assert result.get("baseline_outcome") == "barrier"


def test_s19_reverify_mirror_length_gate(tmp_path):
    """Gate-B P2：reverify 防御层镜像 validate 的去转义长度门——
    继承复验路径不经过 validate，短字面 marker 必须在这里被拦。"""
    run = tmp_path / "run-19"
    replay = _replay_section()
    replay["expectation"]["required_markers"] = ["ab1"]  # 探针杀不掉、字面 3<4
    fdir, finding = _finding_with_replay(run, replay)
    _identities(run)
    registry, sink = _sink_registry()
    result = reverify_finding(
        finding, fdir,
        identities=load_identities(run), authorized_scopes=ALLOWED,
        evidence_sink=sink, budget=ReverifyBudget(50),
        transport=_vuln_transport([]), throttle=_NOOP_THROTTLE)
    assert result["outcome"] == "blocked"
    assert "长度" in result["reason"]


def test_s20_future_last_reverified_at_forces_reverify(tmp_path):
    """Gate-B P2：伪造/未来的 last_reverified_at（负 age）不得免复验继承——
    必须真实发出继承复验流量（免复验 = 零流量）。"""
    run_src, project, target = _promoted_project(tmp_path)
    state_path = project / "project_state.json"
    state = json.loads(state_path.read_text())
    for cell in state["cell_registry"].values():
        if cell.get("trust_basis") == "evidence_reverified":
            cell["last_reverified_at"] = "2999-01-01T00:00:00Z"  # 未来时间戳
    state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2))
    run2 = tmp_path / "run-20"
    _identities(run2)
    _write(run2 / "inventory.json", {
        "endpoints": [{
            "endpoint": f"{target.base}/api/other", "method": "GET",
            "params": [], "roles": ["any"],
        }],
    })
    requests_before = target.requests
    init2 = initialize_direct_run(
        run_dir=run2, target=target.base,
        inventory_path=run2 / "inventory.json", project_dir=project)
    # 未免复验：继承复验真实发出流量；靶端仍含漏洞 → 复验 match 后继承成立
    assert target.requests > requests_before
    assert init2["project_inheritance"]["inherited"] >= 1
