"""v9.2 发布门合同测试：现象三分类门 + 报告出口收口（Phase A/C）。"""
from __future__ import annotations

import hashlib
import json
import shutil

from engine.finalize import finalize_run
from engine.project_state import ProjectStateStore
from engine.reporting.collect import collect_structured_findings
from engine.reporting.decision import decide_canonical_report, gate_outcomes
from engine.reporting.observations import build_observation_records
from engine.reporting.render_md import render_observation_report
from engine.reporting.schema import load_finding
from engine.reporting.validate import validate_finding, validate_run_artifacts
from engine.skill_runtime import (
    checkpoint_direct_run,
    initialize_direct_run,
    report_direct_run,
)
from tests.test_reporting_proof_contract import _idor_fixture
from tests.test_v88_reporting_fail_closed import _manifest, _write  # noqa: F401 - import check
from tests.test_v89_delivery_contract import _complete_finding_run


ALLOWED = ["https://t.example/"]


def _save(fdir, finding):
    (fdir / "finding.json").write_text(
        json.dumps(finding, ensure_ascii=False, indent=2), encoding="utf-8")


def _cors_mutation(finding):
    """Mutate the valid IDOR fixture into a CORS phenomenon with valid evidence."""
    finding["title"] = "跨域配置不当"
    finding["vuln_type"] = "cors-misconfig"
    finding["risk"]["summary"] = "响应反射 Access-Control-Allow-Origin: * 且允许凭据。"
    finding["verification"]["evidence_type"] = "response_differential"
    finding["proof_packets"][0]["phase"] = "baseline"
    finding["proof_packets"][1]["phase"] = "exploit"
    return finding


def _copy_finding(run_dir, scratch, name):
    src = _idor_fixture(scratch)
    dst = run_dir / "findings" / name
    shutil.copytree(src, dst)
    finding = load_finding(dst / "finding.json")
    finding["id"] = name
    return dst, finding


# ── 发布门 1：现象类无链 → observation；已证后果链 → accepted ─────────────────
def test_phenomenon_classes_demote_without_proven_chain(tmp_path):
    fdir = _idor_fixture(tmp_path / "run-cors")
    run = tmp_path / "run-cors"
    finding = _cors_mutation(load_finding(fdir / "finding.json"))
    _save(fdir, finding)

    result = validate_finding(
        finding, fdir / "finding.json", run, authorized_hosts=ALLOWED)
    assert not result.ok
    assert result.outcome == "observation"
    assert "cors_misconfig" in result.phenomenon_classes

    collected = collect_structured_findings(run, authorized_hosts=ALLOWED)
    assert collected["accepted"] == []
    assert collected["rejected"] == []
    assert len(collected["observations"]) == 1
    assert isinstance(collected["observations"][0]["finding"], dict)

    validation = validate_run_artifacts(
        run, allowed_hosts=ALLOWED, write_output=False)
    assert validation["counts"]["observations"] == 1
    assert len(validation["observations"]) == 1
    # 三分类隔离：observation 不进 rejected、不触发批原子门。
    assert validation["proof_pending_or_rejected"] == []
    assert validation["counts"]["proof_confirmed"] == 0

    # 弱加密 / 公钥盲区类同样走降级。
    for index, (title, expected) in enumerate((
        ("encCerts 接口泄露 RSA1_5 弱算法公钥",
         {"weak_crypto", "public_key_disclosure"}),
        ("JWKS 公钥端点匿名可访问", {"public_key_disclosure"}),
        ("TLS 证书过期与混合内容", {"ssl_tls_config"}),
    )):
        fdir2 = _idor_fixture(tmp_path / f"run-phenomenon-{index}")
        run2 = fdir2.parents[1]
        finding2 = load_finding(fdir2 / "finding.json")
        finding2["title"] = title
        finding2["vuln_type"] = "configuration"
        finding2["verification"]["evidence_type"] = "response_differential"
        finding2["proof_packets"][0]["phase"] = "baseline"
        finding2["proof_packets"][1]["phase"] = "exploit"
        _save(fdir2, finding2)
        result2 = validate_finding(
            finding2, fdir2 / "finding.json", run2, authorized_hosts=ALLOWED)
        assert not result2.ok, title
        assert result2.outcome == "observation", title
        assert expected <= set(result2.phenomenon_classes), title


def test_proven_consequence_chain_keeps_phenomenon_class_accepted(tmp_path):
    fdir = _idor_fixture(tmp_path)
    finding = _cors_mutation(load_finding(fdir / "finding.json"))
    finding["chain_assessment"] = {
        "status": "proven",
        "chain_feasible": True,
        "chain_path": "cors reflection -> victim session read",
        "final_impact": "data_read: attacker reads victim order data cross-origin",
        "blockers": [],
        "proof_refs": ["request_owner.http"],
    }
    _save(fdir, finding)

    result = validate_finding(
        finding, fdir / "finding.json", tmp_path, authorized_hosts=ALLOWED)
    assert result.ok, result.reasons
    assert result.outcome == ""
    assert result.phenomenon_classes == []


# ── 发布门 1 补充：标题改写不能绕过（匹配跨 title/vuln_type/summary/impact）───
def test_title_rewording_cannot_bypass_phenomenon_gate(tmp_path):
    fdir = _idor_fixture(tmp_path)
    finding = load_finding(fdir / "finding.json")
    finding["title"] = "响应头配置不当"  # 标题不含任何现象关键词
    finding["vuln_type"] = "配置缺陷"
    finding["risk"]["summary"] = (
        "服务端响应返回 Access-Control-Allow-Origin: * 并允许携带凭据。")
    finding["verification"]["evidence_type"] = "response_differential"
    finding["proof_packets"][0]["phase"] = "baseline"
    finding["proof_packets"][1]["phase"] = "exploit"
    _save(fdir, finding)

    result = validate_finding(
        finding, fdir / "finding.json", tmp_path, authorized_hosts=ALLOWED)
    assert not result.ok
    assert result.outcome == "observation"
    assert "cors_misconfig" in result.phenomenon_classes


# ── 发布门 2：三分类隔离 + 硬失败仍连坐（防洗白）────────────────────────────
def test_observation_isolated_from_batch_atomic_gate(tmp_path):
    project = tmp_path / "project-batch"
    run = project / "sessions" / "run-batch"
    _complete_finding_run(run)
    fdir, finding = _copy_finding(run, tmp_path / "scratch-cors", "finding_002")
    _save(fdir, _cors_mutation(finding))

    validation = validate_run_artifacts(run, write_output=False)
    assert validation["status"] == "valid"
    assert validation["counts"]["proof_confirmed"] == 1
    assert validation["counts"]["observations"] == 1
    assert validation["proof_gate"]["result"] == "pass"
    assert validation["proof_pending_or_rejected"] == []

    # 硬校验失败的 finding 仍是 rejection 并连坐清空整批；observation 不受影响。
    fdir3, finding3 = _copy_finding(run, tmp_path / "scratch-bad", "finding_003")
    finding3["verification"]["object_marker"] = "missing-from-response"
    _save(fdir3, finding3)

    validation = validate_run_artifacts(run, write_output=False)
    assert validation["counts"]["proof_confirmed"] == 0
    assert validation["counts"]["observations"] == 1
    assert validation["proof_gate"]["result"] == "fail"
    assert any(any("batch_atomicity" in reason for reason in item.get("reasons", []))
               for item in validation["proof_pending_or_rejected"])


# ── 发布门 4a：checkpoint 接 Guardian + observations.json 机器真值 ───────────
def _initialized_direct_run(tmp_path):
    run_dir = tmp_path / "run-direct"
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"surfaces": [{
        "endpoint": "/api/orders/{id}", "method": "GET", "params": ["id"],
    }]}), encoding="utf-8")
    initialize_direct_run(
        run_dir=run_dir, target="https://t.example/", inventory_path=inventory)
    return run_dir


def test_checkpoint_runs_guardian_and_writes_observations_json(tmp_path):
    run_dir = _initialized_direct_run(tmp_path)

    # 空跑也稳定落 observations.json。
    checkpoint = checkpoint_direct_run(run_dir)
    assert checkpoint["finding_validation"]["proof_repair_required"] == 0
    payload = json.loads((run_dir / "observations.json").read_text(encoding="utf-8"))
    assert payload == {"observations": [], "schema_version": 1}

    # collect 阶段降级（CORS 现象类）。
    fdir, finding = _copy_finding(run_dir, tmp_path / "scratch-ck1", "finding_cors")
    _save(fdir, _cors_mutation(finding))
    # Guardian 专属降级：L1 垃圾标题命中一个证据有效的 finding（"默认页" 不在
    # 现象词表，collect 仍 accepted，由 checkpoint 新接的 Guardian 降级）。
    fdir2, finding2 = _copy_finding(run_dir, tmp_path / "scratch-ck2", "finding_default")
    finding2["title"] = "后台默认页泄露订单数据"
    _save(fdir2, finding2)

    checkpoint = checkpoint_direct_run(run_dir)
    assert checkpoint["finding_validation"]["proof_repair_required"] == 0
    assert checkpoint["finding_validation"]["accepted"] == 0
    assert checkpoint["finding_validation"]["observations"] == 2

    payload = json.loads((run_dir / "observations.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert len(payload["observations"]) == 2
    by_id = {item["id"]: item for item in payload["observations"]}
    cors = by_id["finding_cors"]
    assert cors["phenomenon_classes"] == ["cors_misconfig"]
    assert cors["method"] == "GET"
    assert cors["endpoint"] == "/api/orders/{id}"
    assert cors["params"] == ["id"]
    assert cors["vuln_class"] == "cors-misconfig"
    assert cors["chain_status"] == "hypothesis"
    assert cors["evidence_refs"]
    assert all(ref.startswith("findings/finding_cors/") for ref in cors["evidence_refs"])
    guardian_row = by_id["finding_default"]
    assert any(reason.startswith("guardian:rejected:L1:")
               for reason in guardian_row["reasons"])


# ── 发布门 4b：手写报告在 checkpoint 与 report 两个时机都被 quarantine ───────
def test_handwritten_reports_are_quarantined_at_both_times(tmp_path):
    # report 时机：裸目录零 engine 产物也能运行。
    bare = tmp_path / "run-bare"
    bare.mkdir()
    (bare / "final_report.md").write_text("# 手写漏洞报告\n", encoding="utf-8")
    (bare / "observation_report.md").write_text("# 手写观察报告\n", encoding="utf-8")

    result = report_direct_run(bare)
    assert result["decision"] == "not_generated"
    assert result["quarantined"] == ["final_report.md", "observation_report.md"]
    assert not (bare / "final_report.md").exists()
    assert not (bare / "observation_report.md").exists()
    quarantined = sorted((bare / "state" / "quarantine").iterdir())
    assert len(quarantined) == 2
    assert all(".agent." in path.name for path in quarantined)
    status = json.loads((bare / "runtime-status.json").read_text(encoding="utf-8"))
    assert status["rendered_artifacts"] == {}
    payload = json.loads((bare / "observations.json").read_text(encoding="utf-8"))
    assert payload["observations"] == []

    # checkpoint 时机。
    run_dir = _initialized_direct_run(tmp_path)
    (run_dir / "final_report.md").write_text("# 手写漏洞报告\n", encoding="utf-8")
    checkpoint = checkpoint_direct_run(run_dir)
    assert checkpoint["reserved_artifact_violations"] == ["final_report.md"]
    assert not (run_dir / "final_report.md").exists()
    assert list((run_dir / "state" / "quarantine").glob("final_report.md.agent.*.md"))


def test_code_rendered_reports_survive_and_tampered_ones_cycle(tmp_path):
    project = tmp_path / "project-render"
    run = project / "sessions" / "run-render"
    _complete_finding_run(run)
    fdir, finding = _copy_finding(run, tmp_path / "scratch-r", "finding_002")
    _save(fdir, _cors_mutation(finding))

    first = report_direct_run(run)
    assert first["decision"] == "complete"
    assert set(first["rendered_artifacts"]) == {
        "final_report.md", "observation_report.md"}
    status = json.loads((run / "runtime-status.json").read_text(encoding="utf-8"))
    for name, digest in status["rendered_artifacts"].items():
        actual = hashlib.sha256((run / name).read_bytes()).hexdigest()
        assert actual == digest

    # 代码渲染产物 hash 匹配 → 第二次 report 不 quarantine。
    second = report_direct_run(run)
    assert second["quarantined"] == []
    assert (run / "final_report.md").is_file()

    # 人工篡改 → hash 不匹配 → quarantine + 代码重渲染。
    (run / "final_report.md").write_text(
        (run / "final_report.md").read_text(encoding="utf-8") + "手写追加\n",
        encoding="utf-8")
    third = report_direct_run(run)
    assert third["quarantined"] == ["final_report.md"]
    assert list((run / "state" / "quarantine").glob("final_report.md.agent.*.md"))
    status = json.loads((run / "runtime-status.json").read_text(encoding="utf-8"))
    restored = hashlib.sha256((run / "final_report.md").read_bytes()).hexdigest()
    assert status["rendered_artifacts"]["final_report.md"] == restored
    assert "手写追加" not in (run / "final_report.md").read_text(encoding="utf-8")


# ── 发布门 3：三态决策共享函数与 finalizer 逐字节一致 ────────────────────────
def test_decide_canonical_report_matrix_and_finalizer_parity(tmp_path):
    assert decide_canonical_report(
        proof_pass=True, closure_pass=True, exit_code=0,
        report_items=[{"id": "x"}]) == ("complete", "final_report.md")
    assert decide_canonical_report(
        proof_pass=True, closure_pass=True, exit_code=0,
        report_items=[]) == ("complete", "final_report.md")
    assert decide_canonical_report(
        proof_pass=True, closure_pass=False, exit_code=2,
        report_items=[{"id": "x"}]) == ("draft_incomplete", "draft_report.md")
    assert decide_canonical_report(
        proof_pass=True, closure_pass=False, exit_code=2,
        report_items=[]) == ("not_generated", None)
    assert decide_canonical_report(
        proof_pass=False, closure_pass=True, exit_code=0,
        report_items=[{"id": "x"}]) == ("not_generated", None)
    assert decide_canonical_report(
        proof_pass=False, closure_pass=False, exit_code=1,
        report_items=[{"id": "x"}]) == ("not_generated", None)

    project = tmp_path / "project-parity"
    run = project / "sessions" / "run-parity"
    _complete_finding_run(run)
    report = report_direct_run(run)
    validation = validate_run_artifacts(run, write_output=False)
    proof_pass, closure_pass = gate_outcomes(validation)
    finalizer_decision = decide_canonical_report(
        proof_pass=proof_pass,
        closure_pass=closure_pass,
        exit_code=int(validation.get("exit_code", 3)),
        report_items=validation.get("proof_confirmed") or [],
    )
    assert (report["decision"], report["report"] or None) == finalizer_decision
    assert finalizer_decision == ("complete", "final_report.md")

    # legacy_risk/planning_degraded 无特判：closure 失败时同样落到 draft。
    degraded = dict(validation)
    degraded["closure_gate"] = {"result": "fail", "reasons": ["open cells"]}
    degraded["exit_code"] = 2
    proof_pass, closure_pass = gate_outcomes(degraded)
    assert decide_canonical_report(
        proof_pass=proof_pass, closure_pass=closure_pass,
        exit_code=2,
        report_items=validation.get("proof_confirmed") or [],
    ) == ("draft_incomplete", "draft_report.md")


# ── 观察报告渲染器：分组、无严重度标签、含原因与证据 ─────────────────────────
def test_observation_report_renderer(tmp_path):
    run = tmp_path / "run-render-obs"
    fdir, finding = _copy_finding(run, tmp_path / "scratch-o1", "finding_cors")
    _save(fdir, _cors_mutation(finding))
    fdir2, finding2 = _copy_finding(run, tmp_path / "scratch-o2", "finding_tls")
    finding2["title"] = "TLS 证书过期"
    finding2["vuln_type"] = "ssl-config"
    finding2["verification"]["evidence_type"] = "response_differential"
    finding2["proof_packets"][0]["phase"] = "baseline"
    finding2["proof_packets"][1]["phase"] = "exploit"
    finding2["chain_assessment"] = {"status": "", "final_impact": ""}
    _save(fdir2, finding2)

    items = [
        {"id": "finding_tls", "path": str(fdir2 / "finding.json"),
         "finding": finding2, "phenomenon_classes": ["ssl_tls_config"],
         "reasons": ["submission_policy[ssl_tls_config]: no proven chain"]},
        {"id": "finding_cors", "path": str(fdir / "finding.json"),
         "finding": finding, "phenomenon_classes": ["cors_misconfig"],
         "reasons": ["submission_policy[cors_misconfig]: no proven chain"]},
    ]
    records = build_observation_records(run, items)
    out = render_observation_report(records, run / "observation_report.md",
                                    "https://t.example/")
    text = out.read_text(encoding="utf-8")

    assert "P1" not in text and "P2" not in text and "P3" not in text
    assert "观察报告" in text
    assert "现象级发现" in text
    assert "不含 SRC 严重度" in text or "不携带 SRC 严重度" in text
    # 按 phenomenon_class 稳定分组排序：cors_misconfig 在 ssl_tls_config 前。
    assert text.index("现象分类：cors_misconfig") < text.index("现象分类：ssl_tls_config")
    assert "为什么只是现象" in text
    assert "submission_policy[cors_misconfig]" in text
    assert "可能的链式方向：NONE" in text  # finding_tls 无 chain
    assert "hypothesis" in text  # finding_cors 保留 fixture 的 chain_status
    assert "findings/finding_cors/request_owner.http" in text


# ── 发布门 5/6：observation 永不进 ProjectState；finalizer 双产物落盘 ────────
def test_finalizer_renders_observations_but_never_commits_them(tmp_path):
    project = tmp_path / "project"
    run = project / "sessions" / "run-obs"
    _complete_finding_run(run)
    fdir, finding = _copy_finding(run, tmp_path / "scratch-f", "finding_002")
    _save(fdir, _cors_mutation(finding))

    delivery = finalize_run(
        run_dir=run, project_dir=project, authority_dir=project / ".atoolkit",
        authority_trusted=True, authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture", primary_target="https://t.example/",
    )
    assert delivery["delivery_complete"] is True

    payload = json.loads((run / "observations.json").read_text(encoding="utf-8"))
    assert len(payload["observations"]) == 1
    assert payload["observations"][0]["phenomenon_classes"] == ["cors_misconfig"]
    report_text = (run / "observation_report.md").read_text(encoding="utf-8")
    assert "跨域配置不当" in report_text
    assert not any(label in report_text for label in ("P1", "P2", "P3"))
    final_text = (run / "final_report.md").read_text(encoding="utf-8")
    assert "跨域配置不当" not in final_text

    # _prepare_project_truth 只消费 proof_confirmed/normalized_findings：
    # observation 的 id 不得出现在项目真值的任何角落。
    state = ProjectStateStore(project).load()
    assert len(state["finding_registry"]) == 1
    assert "finding_002" not in json.dumps(state, ensure_ascii=False)

    receipt = json.loads((run / "run_receipt.json").read_text(encoding="utf-8"))
    assert "observations" not in json.dumps(receipt.get("artifacts") or {})

    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    assert summary["canonical_report_status"] == "complete"


def test_checkpoint_then_validate_run_artifacts_closure_stays_green(tmp_path):
    """v9.2 workflow regression: checkpoint must not clobber the Host-owned
    execution-queue.json projection shape.  Pre-v9.2 the model-facing queue
    overwrite desynced the file from the closure gate's recomputed projection
    (execution_projection_mismatch) and forced checkpoint → report sequences
    into draft-only outcomes."""
    run = tmp_path / "project" / "sessions" / "run-seq"
    _complete_finding_run(run)
    checkpoint = checkpoint_direct_run(run)
    assert "execution_queue" in checkpoint  # 模型视图仍随 checkpoint 字典返回
    report = validate_run_artifacts(run, write_output=False)
    assert report["closure_gate"]["result"] == "pass", (
        report["closure_gate"].get("reasons"))
    assert report["status"] == "valid"
