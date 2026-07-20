from __future__ import annotations

import json
from pathlib import Path

import pytest
import run as run_entry

from engine.data_hygiene import redact_text
from engine.engine_planning import (
    build_identity_readiness,
    create_planning_session,
    promote_planning_artifacts,
    run_planning_model,
    snapshot_recon_evidence,
)
from engine.orchestrator import CognitiveState
from engine.reporting.render_md import render_final_report
from engine.reporting.schema import load_finding
from engine.reporting.validate import validate_finding
from engine.run_authority import create_run_plan, ensure_project_identity, run_plan_path
from engine.runtime_manifest import (
    create_run_manifest,
    sha256_file,
    validate_manifest_binding,
)
from engine.threat_model import ThreatModelError, compile_threat_model, validate_threat_plan
from tests.test_reporting_proof_contract import _idor_fixture
from tests.test_v811_threat_model_delivery import _plan_fixture


def _load_plan(root: Path):
    inventory, feature_path, threat_path = _plan_fixture(root)
    rows = json.loads(inventory.read_text(encoding="utf-8"))["surfaces"]
    graph = json.loads(feature_path.read_text(encoding="utf-8"))
    model = json.loads(threat_path.read_text(encoding="utf-8"))
    return rows, graph, model


def test_discovery_adequacy_requires_code_and_runtime_groups(tmp_path):
    rows, graph, model = _load_plan(tmp_path)
    for name in ("page_link", "path_inference", "response_body"):
        graph["discovery_channels"][name] = {
            "status": "blocked", "evidence_refs": [], "reason": "not captured",
        }

    with pytest.raises(ThreatModelError, match="navigation/runtime"):
        validate_threat_plan(graph, model, rows, run_dir=tmp_path)


def test_feature_api_outside_frozen_path_scope_is_rejected(tmp_path):
    rows, graph, model = _load_plan(tmp_path)

    with pytest.raises(ThreatModelError, match="outside frozen path scope"):
        validate_threat_plan(
            graph, model, rows, run_dir=tmp_path,
            base_path="/business/", base_path_explicit=True,
        )


def test_threat_cells_do_not_expand_to_default_vulnerability_matrix(tmp_path):
    rows, graph, model = _load_plan(tmp_path)
    plan = validate_threat_plan(graph, model, rows, run_dir=tmp_path)
    compiled = compile_threat_model(plan, rows, target="https://t.example/")
    readiness = build_identity_readiness({}, plan["threat_model"])
    state = CognitiveState("run", "https://t.example/")

    state.seed_threat_cells(compiled, identity_readiness=readiness)

    assert len(state.matrix) == len(compiled) == 1
    cell = next(iter(state.matrix.values()))
    assert cell["vuln"] == "refund-amount-invariant-bypass"
    assert cell["surface"]["feature_id"] == "refund"
    assert cell["surface"]["threat_id"] == "T-refund-overpay"


def test_two_threats_cannot_silently_collapse_into_one_runtime_cell(tmp_path):
    rows, graph, model = _load_plan(tmp_path)
    duplicate = dict(model["features"][0]["threats"][0])
    duplicate["threat_id"] = "T-refund-overpay-second"
    model["features"][0]["threats"].append(duplicate)
    plan = validate_threat_plan(graph, model, rows, run_dir=tmp_path)

    with pytest.raises(ThreatModelError, match="same runtime cell"):
        compile_threat_model(plan, rows, target="https://t.example/")


def test_duplicate_credentials_are_not_two_peer_identities(tmp_path):
    rows, graph, model = _load_plan(tmp_path)
    threat = model["features"][0]["threats"][0]
    threat["identity_requirement"] = {
        "mode": "peer_pair", "roles": ["user"],
        "minimum_distinct_credentials": 2,
        "reason": "owner and peer comparison",
    }
    plan = validate_threat_plan(graph, model, rows, run_dir=tmp_path)

    readiness = build_identity_readiness(
        {"owner": {"Cookie": "sid=same"}, "peer": {"Cookie": "sid=same"}},
        plan["threat_model"],
        roles={"owner": "user", "peer": "user"},
    )

    assert readiness["distinct_credentials"] == 1
    assert readiness["threats"][0]["ready"] is False
    assert readiness["threats"][0]["reason_code"] == "distinct_identity_missing"
    serialized = json.dumps(readiness)
    assert "sid=same" not in serialized


def test_recon_snapshot_redacts_secrets_and_pii_stably(tmp_path):
    recon = tmp_path / "source"
    recon.mkdir()
    raw = (
        "Authorization: Bearer abcdefghijklmnop\n"
        "Cookie: session=owner-secret\n"
        '{"api_key":"key-123456789","email":"person@example.com",'
        '"phone":"13800138000"}'
        "\nhttps://t.example/callback?token=query-secret-123456"
    )
    (recon / "traffic.har").write_text(raw, encoding="utf-8")
    planning = tmp_path / "planning"

    first = snapshot_recon_evidence(recon, planning)
    snapshot = (planning / "recon" / "traffic.har").read_text(encoding="utf-8")
    second_text, _ = redact_text(raw)
    third_text, third_counts = redact_text(second_text)

    assert snapshot == second_text
    assert third_text == second_text
    assert third_counts == {}
    assert "owner-secret" not in snapshot
    assert "key-123456789" not in snapshot
    assert "person@example.com" not in snapshot
    assert "13800138000" not in snapshot
    assert "query-secret-123456" not in snapshot
    assert "<redacted:" in snapshot
    assert first["stats"]["redactions"] >= 5


def test_attack_manifest_is_bound_to_planning_parent(tmp_path):
    project = tmp_path / "project"
    authority = project / ".atoolkit"
    planning = project / "sessions" / "run-1.planning"
    attack = project / "sessions" / "run-1"
    planning.mkdir(parents=True)
    attack.mkdir(parents=True)
    identity = ensure_project_identity(
        authority, project_dir=project, project_name="project",
        primary_target="https://t.example/",
    )
    (planning / "inventory.json").write_text("{}", encoding="utf-8")
    create_run_plan(
        authority, project_id=identity["project_id"], session_id=planning.name,
        admitted_cells=[], budget={"phase": "planning"},
    )
    provenance = {"provider": "openai", "model": "model-x", "adapter": "codex"}
    parent = create_run_manifest(
        planning, mode="engine", project="project",
        project_id=identity["project_id"], session_id=planning.name,
        primary_target="https://t.example/",
        authorized_scopes=["https://t.example/"], authz="authorized",
        authority_dir=authority,
        run_plan_path=run_plan_path(authority, planning.name),
        execution_provenance=provenance,
        planning_mode="threat_discovery", planning_degraded=False,
        planning_artifacts={"inventory.json": planning / "inventory.json"},
        run_phase="planning",
    )
    (attack / "feature-graph.json").write_text("{}", encoding="utf-8")
    (attack / "threat-model.json").write_text("{}", encoding="utf-8")
    create_run_plan(
        authority, project_id=identity["project_id"], session_id=attack.name,
        admitted_cells=[], budget={"phase": "attack"},
    )
    manifest = create_run_manifest(
        attack, mode="engine", project="project",
        project_id=identity["project_id"], session_id=attack.name,
        primary_target="https://t.example/",
        authorized_scopes=["https://t.example/"], authz="authorized",
        authority_dir=authority,
        run_plan_path=run_plan_path(authority, attack.name),
        execution_provenance=provenance,
        planning_mode="threat_model", planning_degraded=False,
        planning_artifacts={
            "feature-graph.json": attack / "feature-graph.json",
            "threat-model.json": attack / "threat-model.json",
        },
        run_phase="attack",
        phase_parent={
            "session_id": planning.name,
            "manifest_path": parent["authority_path"],
            "manifest_sha256": sha256_file(planning / "run_manifest.json"),
        },
    )

    assert validate_manifest_binding(manifest, run_dir=attack)["ok"] is True
    original_inventory = (planning / "inventory.json").read_text(encoding="utf-8")
    (planning / "inventory.json").write_text(
        '{"tampered":true}', encoding="utf-8")
    parent_artifact_check = validate_manifest_binding(manifest, run_dir=attack)
    assert parent_artifact_check["ok"] is False
    assert any(item["code"] == "phase_parent_binding_invalid"
               for item in parent_artifact_check["errors"])
    (planning / "inventory.json").write_text(
        original_inventory, encoding="utf-8")
    assert validate_manifest_binding(manifest, run_dir=attack)["ok"] is True
    Path(parent["authority_path"]).write_text("{}", encoding="utf-8")
    checked = validate_manifest_binding(manifest, run_dir=attack)
    assert checked["ok"] is False
    assert any(item["code"].startswith("phase_parent")
               or item["code"] == "manifest_authority_mismatch"
               for item in checked["errors"])


def test_planning_authority_exists_before_model_and_promotes_validated_plan(tmp_path):
    source = tmp_path / "source"
    inventory_path, feature_path, threat_path = _plan_fixture(source)
    rows = json.loads(inventory_path.read_text(encoding="utf-8"))["surfaces"]
    project = tmp_path / "project"
    planning = project / "sessions" / "run-2.planning"
    attack = project / "sessions" / "run-2"
    authority = project / ".atoolkit"
    identity = ensure_project_identity(
        authority, project_dir=project, project_name="project",
        primary_target="https://t.example/",
    )
    create_planning_session(
        planning_dir=planning,
        project="project",
        project_id=identity["project_id"],
        authority_dir=authority,
        primary_target="https://t.example/",
        authorized_scopes=["https://t.example/"],
        authz="authorized",
        inventory_rows=rows,
        recon_dir=source / "recon",
        instruction_sources=[],
        source_root=Path(__file__).parents[1],
        execution_provenance={
            "provider": "test", "model": "planner", "adapter": "fake",
        },
    )

    class FakePlanningAdapter:
        name = "fake"

        def run(self, _prompt, *, session_id):
            assert session_id == planning.name
            assert (planning / "run_manifest.json").is_file()
            assert run_plan_path(authority, planning.name).is_file()
            manifest = json.loads(
                (planning / "run_manifest.json").read_text(encoding="utf-8"))
            assert manifest["run_phase"] == "planning"
            assert manifest["authorization_assurance"] == "planning_no_network"
            (planning / "feature-graph.json").write_text(
                feature_path.read_text(encoding="utf-8"), encoding="utf-8")
            (planning / "threat-model.json").write_text(
                threat_path.read_text(encoding="utf-8"), encoding="utf-8")
            yield "planned\n"

    result = run_planning_model(
        FakePlanningAdapter(), planning_dir=planning,
        prompt="offline only", inventory_rows=rows,
    )
    lineage = promote_planning_artifacts(planning, attack)

    assert result["status"] == "validated"
    assert lineage["session_id"] == planning.name
    assert (attack / "feature-graph.json").is_file()
    assert (attack / "threat-model.json").is_file()
    manifest = json.loads(
        (planning / "run_manifest.json").read_text(encoding="utf-8"))
    assert validate_manifest_binding(manifest, run_dir=planning)["ok"] is True


def _csrf_finding(run_dir: Path):
    fdir = _idor_fixture(run_dir)
    path = fdir / "finding.json"
    finding = load_finding(path)
    finding["title"] = "跨站请求改变受害者资料"
    finding["vuln_type"] = "CSRF"
    finding["target"] = "https://t.example/api/profile"
    finding["apis"] = [{
        "method": "POST", "path": "/api/profile",
        "purpose": "update profile", "risk_params": ["email"],
    }]
    finding["proof_packets"][0]["phase"] = "state_before"
    finding["proof_packets"][1]["phase"] = "cross_site_request"
    finding["proof_packets"][2]["phase"] = "state_after"
    (fdir / "request_owner.http").write_text(
        "GET /api/profile HTTP/1.1\nHost: t.example\nCookie: sid=victim\n\n",
        encoding="utf-8")
    (fdir / "response_owner.http").write_text(
        'HTTP/1.1 200 OK\n\n{"email":"old@example.test"}', encoding="utf-8")
    (fdir / "request_attacker.http").write_text(
        "POST /api/profile HTTP/1.1\nHost: t.example\n"
        "Origin: https://evil.example\nCookie: sid=victim\n"
        "Content-Type: application/x-www-form-urlencoded\n\n"
        "email=new@example.test",
        encoding="utf-8")
    (fdir / "response_attacker.http").write_text(
        'HTTP/1.1 200 OK\n\n{"updated":true}', encoding="utf-8")
    (fdir / "request_denied.http").write_text(
        "GET /api/profile HTTP/1.1\nHost: t.example\nCookie: sid=victim\n\n",
        encoding="utf-8")
    (fdir / "response_denied.http").write_text(
        'HTTP/1.1 200 OK\n\n{"email":"new@example.test"}', encoding="utf-8")
    (fdir / "csrf-poc.html").write_text(
        '<form action="https://t.example/api/profile" method="POST">'
        '<input name="email" value="new@example.test"></form>'
        '<script>document.forms[0].submit()</script>',
        encoding="utf-8")
    finding["risk"]["proven_impact"] = "跨站请求把受害者邮箱改为攻击者指定值。"
    finding["impact_claims"][0].update({
        "statement": "跨站请求把受害者邮箱改为攻击者指定值。",
        "proof_refs": ["response_denied.http"],
        "marker": "new@example.test",
    })
    finding["verification"].update({
        "evidence_type": "cross_site_state_change",
        "observed_effect": "Cross-site browser request changed the victim profile",
        "state_delta": "email old@example.test -> new@example.test",
        "state_before_marker": "old@example.test",
        "state_after_marker": "new@example.test",
        "cross_site_initiator_file": "csrf-poc.html",
    })
    finding["verification"]["assertions"] = [{
        "file": "response_denied.http", "relation": "contains",
        "value": "new@example.test",
    }]
    finding["claim"]["invariant"] = "another origin cannot change victim profile state"
    path.write_text(json.dumps(finding, ensure_ascii=False, indent=2), encoding="utf-8")
    return fdir, finding


def test_csrf_requires_cross_site_state_change_not_token_phenomenon(tmp_path):
    fdir, finding = _csrf_finding(tmp_path)
    finding["verification"]["evidence_type"] = "response_differential"
    finding["proof_packets"][0]["phase"] = "baseline"
    finding["proof_packets"][1]["phase"] = "test"
    finding["proof_packets"][2]["phase"] = "control"

    result = validate_finding(
        finding, fdir / "finding.json", tmp_path,
        authorized_hosts=["https://t.example/"])

    assert result.ok is False
    assert any("cross_site_state_change" in reason for reason in result.reasons)
    assert any("state_before/cross_site_request/state_after" in reason
               for reason in result.reasons)


def test_real_cross_site_state_change_contract_can_pass(tmp_path):
    fdir, finding = _csrf_finding(tmp_path)

    result = validate_finding(
        finding, fdir / "finding.json", tmp_path,
        authorized_hosts=["https://t.example/"])

    assert result.ok, result.reasons


def test_csrf_rejects_missing_or_non_browser_cross_site_initiator(tmp_path):
    fdir, finding = _csrf_finding(tmp_path)
    finding["verification"].pop("cross_site_initiator_file")

    missing = validate_finding(finding, fdir / "finding.json", tmp_path)

    assert missing.ok is False
    assert any("cross_site_initiator_file" in reason
               for reason in missing.reasons)
    (fdir / "fake-initiator.txt").write_text(
        "curl -H 'Origin: https://evil.example' https://t.example/api/profile",
        encoding="utf-8")
    finding["verification"]["cross_site_initiator_file"] = "fake-initiator.txt"

    forged = validate_finding(finding, fdir / "finding.json", tmp_path)

    assert forged.ok is False
    assert any("browser request primitive" in reason for reason in forged.reasons)


def test_canonical_report_redacts_raw_proof_credentials(tmp_path):
    fdir = _idor_fixture(tmp_path)
    finding = load_finding(fdir / "finding.json")
    finding["risk"]["summary"] += " 联系人 person@example.com / 13800138000。"

    output = render_final_report(
        [{"finding": finding, "path": str(fdir / "finding.json")}],
        tmp_path / "final_report.md",
        target_name="fixture",
    )
    rendered = output.read_text(encoding="utf-8")

    assert "sid=owner-a" not in rendered
    assert "sid=attacker-b" not in rendered
    assert "person@example.com" not in rendered
    assert "13800138000" not in rendered
    assert "<redacted:" in rendered


def test_engine_cli_prebuilt_two_stage_uses_only_compiled_threat_cells(
    tmp_path, monkeypatch,
):
    source = tmp_path / "inputs"
    _inventory, feature_path, threat_path = _plan_fixture(source)
    graph = json.loads(feature_path.read_text(encoding="utf-8"))
    model = json.loads(threat_path.read_text(encoding="utf-8"))
    graph["features"][0]["apis"][0]["params"] = []
    model["features"][0]["threats"][0]["targets"][0]["params"] = []
    model["features"][0]["threats"][0]["identity_requirement"] = {
        "mode": "peer_pair", "roles": ["user"],
        "minimum_distinct_credentials": 2,
        "reason": "owner and peer transaction comparison",
    }
    feature_path.write_text(json.dumps(graph), encoding="utf-8")
    threat_path.write_text(json.dumps(model), encoding="utf-8")

    fake_root = tmp_path / "repo"
    (fake_root / "skill").mkdir(parents=True)
    real_root = Path(__file__).parents[1]
    (fake_root / "skill" / "核心技能文件.v3.md").write_text(
        (real_root / "skill" / "核心技能文件.v3.md").read_text(encoding="utf-8"),
        encoding="utf-8")
    (fake_root / "skill" / "threat-planning.md").write_text(
        (real_root / "skill" / "threat-planning.md").read_text(encoding="utf-8"),
        encoding="utf-8")
    monkeypatch.setattr(run_entry, "ROOT", fake_root)
    monkeypatch.setattr("sys.argv", [
        "run.py", "--dry-run", "--planning-mode", "threat",
        "--target", "https://t.example/", "--authz", "authorized fixture",
        "--recon-dir", str(source / "recon"),
        "--feature-graph", str(feature_path),
        "--threat-model", str(threat_path),
        "--identity", "owner:session=owner-secret",
        "--identity", "peer:session=peer-secret",
        "--identity-role", "owner:user", "--identity-role", "peer:user",
        "--sid", "run-cli", "--project", "cli-project", "--max-turns", "1",
    ])

    exit_code = run_entry.main()

    attack = fake_root / "runs" / "targets" / "cli-project" / "sessions" / "run-cli"
    manifest = json.loads(
        (attack / "run_manifest.json").read_text(encoding="utf-8"))
    ledger = json.loads(
        (attack / "coverage-ledger.json").read_text(encoding="utf-8"))
    validation = json.loads(
        (attack / "finding_validation.json").read_text(encoding="utf-8"))
    readiness_text = (attack / "identity-readiness.json").read_text(
        encoding="utf-8")
    identity_context_text = (attack / "identities.json").read_text(
        encoding="utf-8")
    assert exit_code == 2
    assert manifest["planning_mode"] == "threat_model"
    assert manifest["run_phase"] == "attack"
    assert manifest["phase_parent"]["session_id"] == "run-cli.planning"
    assert any(name.startswith("recon-")
               for name in manifest["planning_artifacts"])
    assert "identities.json" not in manifest["planning_artifacts"]
    assert "owner-secret" not in readiness_text
    assert "peer-secret" not in readiness_text
    assert "owner-secret" in identity_context_text
    assert "peer-secret" in identity_context_text
    assert json.loads(readiness_text)["threats"][0]["ready"] is True
    assert len(ledger["surfaces"]) == 1
    assert ledger["surfaces"][0]["threat_id"] == "T-refund-overpay"
    closure_reasons = validation["closure_gate"]["reasons"]
    assert "threat_compiled_cell_set_mismatch" not in closure_reasons
    assert "threat_run_plan_mismatch" not in closure_reasons

    parent_digest = manifest["phase_parent"]["manifest_sha256"]
    monkeypatch.setattr("sys.argv", [
        "run.py", "--dry-run", "--resume",
        "--target", "https://t.example/", "--authz", "authorized fixture",
        "--sid", "run-cli", "--project", "cli-project", "--max-turns", "1",
    ])

    with pytest.raises(SystemExit) as finalized_resume:
        run_entry.main()

    resumed_manifest = json.loads(
        (attack / "run_manifest.json").read_text(encoding="utf-8"))
    assert finalized_resume.value.code == 2
    assert resumed_manifest["phase_parent"]["manifest_sha256"] == parent_digest
