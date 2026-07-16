from __future__ import annotations

import json
import hashlib
import pathlib
import pytest

from engine.reporting.collect import (
    collect_structured_findings,
    discover_finding_artifacts,
)
from engine.reporting.schema import load_finding
from engine.reporting.validate import (
    ValidationContext,
    main as reporting_main,
    validate_finding,
    validate_run_artifacts,
    verify_validation_artifact,
)
from engine.runtime_manifest import (
    create_run_manifest,
    doctor,
    write_run_receipt,
)
from engine.project_state import ProjectStateStore
from engine.version import __version__
from engine.benchmark_eval import load_findings
from tests.test_reporting_proof_contract import _idor_fixture


def _write(path: pathlib.Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def _manifest(
    run_dir: pathlib.Path, *, target: str = "https://t.example/",
    authority_dir: pathlib.Path | None = None,
) -> dict:
    source_root = run_dir / "source"
    _write(source_root / "SKILL.md", "---\nversion: 8.8.0\n---\n")
    return create_run_manifest(
        run_dir,
        mode="skill",
        project="fixture",
        session_id=run_dir.name,
        primary_target=target,
        authorized_scopes=[target],
        authz="authorized fixture",
        instruction_sources=[{
            "kind": "skill",
            "path": str(source_root / "SKILL.md"),
            "injected": True,
        }],
        source_root=source_root,
        authority_dir=authority_dir,
    )


def test_discovery_is_bounded_and_classifies_known_legacy_layouts(tmp_path):
    _write(tmp_path / "findings/finding_good/finding.json", "{}")
    _write(tmp_path / "findings/finding_flat.json", "{}")
    _write(tmp_path / "evidence/finding_old/finding.json", "{}")
    _write(tmp_path / "findings/a/b/finding_nested.json", "{}")
    _write(tmp_path / "findings/a/b/c/finding_too_deep.json", "{}")

    report = discover_finding_artifacts(tmp_path)

    assert report["counts"] == {
        "discovered": 4,
        "canonical": 1,
        "legacy": 2,
        "suspicious": 1,
    }
    assert {item["layout"] for item in report["artifacts"]} == {
        "canonical", "legacy_flat", "legacy_evidence", "unsupported",
    }
    assert not any("too_deep" in item["relative_path"] for item in report["artifacts"])


def test_duplicate_id_with_different_content_rejects_canonical_copy(tmp_path):
    canonical = tmp_path / "findings/finding_same/finding.json"
    legacy = tmp_path / "findings/finding_same.json"
    _write(canonical, json.dumps({"id": "finding_same", "title": "one"}))
    _write(legacy, json.dumps({"id": "finding_same", "title": "two"}))

    collected = collect_structured_findings(tmp_path)

    assert collected["accepted"] == []
    assert any(
        error["code"] == "duplicate_id_conflict"
        for error in collected["ingestion_errors"]
    )
    assert collected["counts"]["discovered"] == 2


def test_legacy_layout_with_manifest_is_explicitly_rejected(tmp_path):
    _manifest(tmp_path)
    _write(tmp_path / "findings/finding_old.json", json.dumps({
        "id": "finding_old", "title": "legacy",
    }))

    report = validate_run_artifacts(tmp_path)

    assert report["status"] == "invalid"
    assert report["exit_code"] == 1
    assert report["counts"]["legacy"] == 1
    assert report["counts"]["rejected"] == 1


def test_empty_input_is_nonzero_by_default(tmp_path):
    _manifest(tmp_path)

    report = validate_run_artifacts(tmp_path)

    assert report["status"] == "incomplete"
    assert report["exit_code"] == 2
    assert reporting_main([str(tmp_path)]) == 2


def test_canonical_finding_without_manifest_fails_closed(tmp_path):
    _idor_fixture(tmp_path)

    report = validate_run_artifacts(tmp_path)

    assert report["status"] == "precondition_missing"
    assert report["exit_code"] == 2
    assert report["counts"]["proof_confirmed"] == 0
    assert report["normalized_findings"] == []
    assert any(error["code"] == "missing_manifest"
               for error in report["ingestion_errors"])


def test_benchmark_ignores_handwritten_accepted_summary_without_validation(tmp_path):
    _write(tmp_path / "proof.json", "{}")
    _write(tmp_path / "summary.json", json.dumps({
        "findings": [{
            "id": "forged", "endpoint": "/api/refund", "method": "POST",
            "class": "amount-tamper", "evidence_file": "proof.json",
            "acceptance_status": "accepted", "proof_status": "confirmed",
            "claim_kind": "root_finding",
        }],
    }))

    assert load_findings(tmp_path / "summary.json") == []


def test_benchmark_requires_receipt_and_complete_closure_not_summary_rows(tmp_path):
    _idor_fixture(tmp_path)
    _manifest(tmp_path)
    validation = validate_run_artifacts(tmp_path)
    _write(tmp_path / "summary.json", json.dumps({
        "findings": [{
            "id": "forged", "acceptance_status": "accepted",
            "proof_status": "confirmed", "claim_kind": "root_finding",
        }],
        "finding_validation_path": str(tmp_path / "finding_validation.json"),
        "finding_validation_sha256": validation["validation_sha256"],
    }))

    findings = load_findings(tmp_path / "summary.json")

    assert findings == []


def test_allow_empty_requires_and_accepts_a_complete_physical_gate(tmp_path):
    _manifest(tmp_path)
    request = "GET /api/health HTTP/1.1\nHost: t.example\n\n"
    response = 'HTTP/1.1 200 OK\n\n{"status":"ok"}'
    exact_cell = {
        "asset_id": "https://t.example:443", "endpoint": "/api/health",
        "method": "GET", "param": "", "role_scope": "unknown",
        "vuln_class": "information-only", "namespace": "",
        "param_location": "", "subject_role": "", "object_kind": "",
    }
    _write(tmp_path / "negative.json", json.dumps({
        "schema_version": "1.0", "kind": "dead_end_evidence",
        "exact_cell": exact_cell,
        "packets": [{
            "vector": "liveness_probe", "request": request,
            "response": response,
            "request_sha256": hashlib.sha256(request.encode()).hexdigest(),
            "response_sha256": hashlib.sha256(response.encode()).hexdigest(),
            "assertions": [{
                "target": "response", "relation": "contains",
                "value": '"status":"ok"',
            }],
        }],
    }))
    _write(tmp_path / "inventory.json", json.dumps({
        "endpoints": [{"endpoint": "/api/health", "method": "GET"}],
    }))
    _write(tmp_path / "coverage-ledger.json", json.dumps({
        "schema_version": 1,
        "surfaces": [{
            "surface_id": "health",
            "asset_id": "https://t.example:443",
            "endpoint": "/api/health",
            "method": "GET",
            "param": "",
            "roles": ["unknown"],
            "vuln_class": "information-only",
            "namespace": "",
            "param_location": "",
            "subject_role": "",
            "object_kind": "",
            "status": "not_applicable",
            "reason": "health endpoint has no security-sensitive state",
            "in_run_scope": True,
            "risk_tags": ["info"],
        }],
    }))
    _write(tmp_path / "candidate-ledger.json", json.dumps({
        "schema_version": "1.1", "candidates": [],
    }))
    _write(tmp_path / "dead_ends.json", json.dumps({
        "dead_ends": [{
            "status": "not_applicable",
            "reason_code": "vulnerability_class_not_applicable",
            "refutation": "The endpoint exposes only a constant liveness value.",
            "source_run": tmp_path.name,
            "asset_id": "https://t.example:443",
            "endpoint": "/api/health",
            "method": "GET",
            "param": "",
            "role_scope": "unknown",
            "vuln_class": "information-only",
            "namespace": "",
            "param_location": "",
            "subject_role": "",
            "object_kind": "",
            "evidence_refs": ["negative.json"],
        }],
    }))

    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert report["status"] == "empty_allowed"
    assert report["exit_code"] == 0
    assert report["empty_gate"]["result"] == "pass"


def test_not_applicable_reason_without_structured_dead_end_cannot_close(tmp_path):
    _manifest(tmp_path)
    _write(tmp_path / "inventory.json", json.dumps({
        "endpoints": [{"endpoint": "/api/health", "method": "GET"}],
    }))
    _write(tmp_path / "coverage-ledger.json", json.dumps({
        "schema_version": 1,
        "surfaces": [{
            "surface_id": "health",
            "asset_id": "https://t.example:443",
            "endpoint": "/api/health",
            "method": "GET",
            "param": "",
            "roles": ["unknown"],
            "vuln_class": "information-only",
            "namespace": "",
            "param_location": "",
            "subject_role": "",
            "object_kind": "",
            "status": "not_applicable",
            "reason": "self-asserted text only",
            "in_run_scope": True,
        }],
    }))
    _write(tmp_path / "candidate-ledger.json", json.dumps({
        "schema_version": "1.1", "candidates": [],
    }))

    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert report["exit_code"] == 2
    assert "not_applicable_contract_missing" in report["empty_gate"]["reasons"]


def test_allow_empty_rejects_recoverable_blocked_surface(tmp_path):
    _manifest(tmp_path)
    _write(tmp_path / "inventory.json", json.dumps({
        "endpoints": [{"endpoint": "/api/refund", "method": "POST"}],
    }))
    _write(tmp_path / "coverage-ledger.json", json.dumps({
        "schema_version": 1,
        "surfaces": [{
            "surface_id": "refund", "endpoint": "/api/refund",
            "method": "POST", "param": "amount", "status": "blocked",
            "blocker": {"kind": "quota_exhausted"},
            "next_actions": ["create a fresh order"], "in_run_scope": True,
            "risk_tags": ["payment"],
        }],
    }))
    _write(tmp_path / "candidate-ledger.json", json.dumps({
        "schema_version": "1.1", "candidates": [],
    }))

    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert report["exit_code"] == 2
    assert report["empty_gate"]["result"] == "fail"
    assert report["empty_gate"]["session_gate"]["result"] != "pass"


def test_allow_empty_rejects_zero_surface_coverage(tmp_path):
    _manifest(tmp_path)
    _write(tmp_path / "inventory.json", json.dumps({
        "endpoints": [{"endpoint": "/api/health", "method": "GET"}],
    }))
    _write(tmp_path / "coverage-ledger.json", json.dumps({
        "schema_version": 1, "surfaces": [],
    }))
    _write(tmp_path / "candidate-ledger.json", json.dumps({
        "schema_version": "1.1", "candidates": [],
    }))

    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert report["exit_code"] == 2
    assert report["empty_gate"]["result"] == "fail"
    assert "coverage_empty" in report["empty_gate"]["reasons"]


def test_allow_empty_rejects_unrelated_coverage_surface(tmp_path):
    _manifest(tmp_path)
    _write(tmp_path / "inventory.json", json.dumps({
        "endpoints": [{
            "endpoint": "/api/refund", "method": "POST",
            "params": ["amount"], "roles": ["user"],
        }],
    }))
    _write(tmp_path / "coverage-ledger.json", json.dumps({
        "schema_version": 1,
        "surfaces": [{
            "surface_id": "health", "endpoint": "/api/health",
            "method": "GET", "param": "", "roles": ["unknown"],
            "status": "not_applicable", "in_run_scope": True,
            "risk_tags": ["info"],
        }],
    }))
    _write(tmp_path / "candidate-ledger.json", json.dumps({
        "schema_version": "1.1", "candidates": [],
    }))

    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert report["exit_code"] == 2
    assert "inventory_coverage_mismatch" in report["empty_gate"]["reasons"]


def test_allow_empty_requires_every_param_role_cell_combination(tmp_path):
    _manifest(tmp_path)
    _write(tmp_path / "inventory.json", json.dumps({
        "endpoints": [{
            "endpoint": "/api/refund", "method": "POST",
            "params": ["amount", "status"], "roles": ["user", "admin"],
        }],
    }))
    _write(tmp_path / "coverage-ledger.json", json.dumps({
        "schema_version": 1,
        "surfaces": [
            {"surface_id": "amount-user", "endpoint": "/api/refund",
             "method": "POST", "param": "amount", "roles": ["user"],
             "status": "not_applicable", "in_run_scope": True,
             "risk_tags": ["payment"]},
            {"surface_id": "status-admin", "endpoint": "/api/refund",
             "method": "POST", "param": "status", "roles": ["admin"],
             "status": "not_applicable", "in_run_scope": True,
             "risk_tags": ["payment"]},
        ],
    }))
    _write(tmp_path / "candidate-ledger.json", json.dumps({
        "schema_version": "1.1", "candidates": [],
    }))

    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert report["exit_code"] == 2
    assert "inventory_exact_cell_coverage_mismatch" in report["empty_gate"]["reasons"]


@pytest.mark.parametrize("inventory_item", ["/api/health", {"endpoint": "/api/health", "method": "FOO"}])
def test_allow_empty_rejects_unresolved_or_invalid_inventory_method(tmp_path, inventory_item):
    _manifest(tmp_path)
    _write(tmp_path / "inventory.json", json.dumps({"endpoints": [inventory_item]}))
    _write(tmp_path / "coverage-ledger.json", json.dumps({
        "schema_version": 1, "surfaces": [{
            "surface_id": "health", "endpoint": "/api/health", "method": "GET",
            "status": "not_applicable", "reason": "fixture", "in_run_scope": True,
        }],
    }))
    _write(tmp_path / "candidate-ledger.json", json.dumps({"candidates": []}))

    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert report["exit_code"] == 2
    assert "inventory_method_unresolved" in report["empty_gate"]["reasons"]


def test_allow_empty_rejects_separate_unresolved_inventory(tmp_path):
    _manifest(tmp_path)
    _write(tmp_path / "inventory.json", json.dumps({
        "endpoints": [{"endpoint": "/api/health", "method": "GET"}],
        "unresolved": [{"endpoint": "/api/mystery", "method_candidates": []}],
    }))
    _write(tmp_path / "coverage-ledger.json", json.dumps({
        "schema_version": 1, "surfaces": [{
            "surface_id": "health", "endpoint": "/api/health", "method": "GET",
            "status": "not_applicable", "reason": "fixture", "in_run_scope": True,
        }],
    }))
    _write(tmp_path / "candidate-ledger.json", json.dumps({
        "schema_version": "1.1", "candidates": [],
    }))

    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert report["exit_code"] == 2
    assert "inventory_unresolved_open" in report["empty_gate"]["reasons"]


def test_allow_empty_rejects_open_or_unproven_negative_coverage(tmp_path):
    _manifest(tmp_path)
    _write(tmp_path / "inventory.json", json.dumps({
        "endpoints": [{"endpoint": "/api/search", "method": "GET"}],
    }))
    _write(tmp_path / "coverage-ledger.json", json.dumps({
        "schema_version": 1, "surfaces": [{
            "surface_id": "search", "endpoint": "/api/search", "method": "GET",
            "status": "not_vulnerable", "negative_depth_checked": True,
            "in_run_scope": True,
        }],
    }))
    _write(tmp_path / "candidate-ledger.json", json.dumps({"candidates": []}))

    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert report["exit_code"] == 2
    assert "negative_evidence_missing" in report["empty_gate"]["reasons"]


def test_allow_empty_rejects_self_asserted_confirmed_coverage(tmp_path):
    _manifest(tmp_path)
    _write(tmp_path / "fake.json", json.dumps({
        "acceptance_status": "accepted", "proof_status": "confirmed",
        "claim_kind": "root_finding",
    }))
    _write(tmp_path / "inventory.json", json.dumps({
        "endpoints": [{"endpoint": "/api/x", "method": "GET"}],
    }))
    _write(tmp_path / "coverage-ledger.json", json.dumps({
        "schema_version": 1, "surfaces": [{
            "surface_id": "x", "endpoint": "/api/x", "method": "GET",
            "status": "confirmed", "evidence_ref": "fake.json", "in_run_scope": True,
        }],
    }))
    _write(tmp_path / "candidate-ledger.json", json.dumps({
        "schema_version": "1.1", "candidates": [],
    }))

    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert report["exit_code"] == 2
    assert "confirmed_coverage_without_canonical_finding" in report["empty_gate"]["reasons"]


def test_allow_empty_rejects_confirmed_project_state_from_another_project(tmp_path):
    project_a = tmp_path / "project-a"
    proof_dir = project_a / "sessions" / "run-a"
    proof_dir.mkdir(parents=True)
    (proof_dir / "proof.json").write_text("{}", encoding="utf-8")
    ProjectStateStore(project_a, project_scope=["https://a.example/"]).commit_run(
        "run-a",
        inventory=[{
            "asset": "https://a.example/", "method": "GET",
            "endpoint": "/api/x", "roles": ["user"],
        }],
        findings=[{
            "id": "f-a", "acceptance_status": "accepted", "proof_status": "confirmed",
            "claim_kind": "root_finding", "asset": "https://a.example/",
            "endpoint": "/api/x", "method": "GET", "params": [""],
            "affected_role": "user", "vuln_class": "xss", "proof_files": ["proof.json"],
        }],
    )

    run_b = tmp_path / "project-b" / "sessions" / "run-b"
    run_b.mkdir(parents=True)
    _manifest(run_b, target="https://b.example/")
    _write(run_b / "inventory.json", json.dumps({
        "endpoints": [{"endpoint": "/api/x", "method": "GET", "roles": ["user"]}],
    }))
    _write(run_b / "coverage-ledger.json", json.dumps({
        "schema_version": 1, "surfaces": [{
            "surface_id": "x", "endpoint": "/api/x", "method": "GET",
            "param": "", "roles": ["user"], "vuln_class": "xss",
            "status": "confirmed", "in_run_scope": True,
            "evidence_ref": str(project_a / "project_state.json"),
        }],
    }))
    _write(run_b / "candidate-ledger.json", json.dumps({
        "schema_version": "1.1", "candidates": [],
    }))

    report = validate_run_artifacts(run_b, allow_empty=True)

    assert report["exit_code"] == 2
    assert "confirmed_coverage_without_canonical_finding" in report["empty_gate"]["reasons"]


def test_allow_empty_requires_candidate_ledger_schema(tmp_path):
    _manifest(tmp_path)
    _write(tmp_path / "inventory.json", json.dumps({
        "endpoints": [{"endpoint": "/api/health", "method": "GET"}],
    }))
    _write(tmp_path / "coverage-ledger.json", json.dumps({
        "schema_version": 1, "surfaces": [{
            "surface_id": "health", "endpoint": "/api/health", "method": "GET",
            "status": "not_applicable", "reason": "fixture", "in_run_scope": True,
        }],
    }))
    _write(tmp_path / "candidate-ledger.json", "[]")

    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert report["exit_code"] == 2
    assert "candidate_ledger_invalid" in report["empty_gate"]["reasons"]


def test_relative_target_binds_only_to_manifest_primary_target(tmp_path):
    finding_dir = _idor_fixture(tmp_path)
    path = finding_dir / "finding.json"
    finding = load_finding(path)
    finding["target"] = "GET /api/orders/1001"
    _write(path, json.dumps(finding, ensure_ascii=False, indent=2))
    _manifest(tmp_path)

    report = validate_run_artifacts(tmp_path)

    assert report["exit_code"] == 2, report["proof_pending_or_rejected"]
    assert report["proof_gate"]["result"] == "pass"
    assert report["closure_gate"]["result"] == "fail"
    assert report["counts"]["proof_confirmed"] == 1


def test_relative_target_cannot_use_allow_scope_as_an_implicit_base(tmp_path):
    finding_dir = _idor_fixture(tmp_path)
    path = finding_dir / "finding.json"
    finding = load_finding(path)
    finding["target"] = "GET /api/orders/1001"
    context = ValidationContext(
        primary_target="",
        authorized_scopes=("t.example",),
        manifest=None,
    )

    result = validate_finding(finding, path, tmp_path, context=context)

    assert not result.ok
    assert any("primary_target" in reason for reason in result.reasons)


def test_packet_host_is_checked_with_the_same_validation_context(tmp_path):
    finding_dir = _idor_fixture(tmp_path)
    path = finding_dir / "finding.json"
    finding = load_finding(path)
    finding["target"] = "GET /api/orders/1001"
    _write(path, json.dumps(finding, ensure_ascii=False, indent=2))
    _write(
        finding_dir / "request_attacker.http",
        "GET /api/orders/1001 HTTP/1.1\nHost: evil.test\nCookie: sid=attacker-b\n\n",
    )
    manifest = _manifest(tmp_path)
    context = ValidationContext.from_manifest(manifest, manifest_path=tmp_path / "run_manifest.json")

    result = validate_finding(finding, path, tmp_path, context=context)

    assert not result.ok
    assert any("proof request target out of authorized scopes" in reason for reason in result.reasons)


def test_validation_digest_detects_evidence_mutation(tmp_path):
    _idor_fixture(tmp_path)
    _manifest(tmp_path)
    report = validate_run_artifacts(tmp_path)
    assert report["exit_code"] == 2
    assert report["proof_gate"]["result"] == "pass"
    assert verify_validation_artifact(report, tmp_path)["ok"] is True

    _write(tmp_path / "findings/finding_001/response_attacker.http", "changed")

    verification = verify_validation_artifact(report, tmp_path)
    assert verification["ok"] is False
    assert verification["mismatches"]


def test_session_manifest_must_match_authority_copy(tmp_path):
    _idor_fixture(tmp_path)
    _manifest(tmp_path)
    session_path = tmp_path / "run_manifest.json"
    session = json.loads(session_path.read_text(encoding="utf-8"))
    session["primary_target"] = "https://evil.test/"
    _write(session_path, json.dumps(session, ensure_ascii=False, indent=2))

    report = validate_run_artifacts(tmp_path)

    assert report["exit_code"] == 1
    assert report["normalized_findings"] == []
    assert any(error["code"] == "manifest_authority_mismatch"
               for error in report["ingestion_errors"])


def test_validation_verifier_detects_authority_manifest_mutation(tmp_path):
    _idor_fixture(tmp_path)
    manifest = _manifest(tmp_path)
    report = validate_run_artifacts(tmp_path)
    authority_path = pathlib.Path(manifest["authority_path"])
    authority = json.loads(authority_path.read_text(encoding="utf-8"))
    authority["project"] = "mutated"
    _write(authority_path, json.dumps(authority, ensure_ascii=False, indent=2))

    verified = verify_validation_artifact(report, tmp_path)

    assert verified["ok"] is False
    assert any(item["path"] == str(authority_path)
               for item in verified["mismatches"])


def test_manifest_receipt_and_doctor_record_provenance_without_claiming_foreign_src(tmp_path):
    run_dir = tmp_path / "run"
    manifest = _manifest(run_dir)
    assert manifest["atoolkit_version"] == __version__
    assert manifest["source_tree_sha256"]
    assert "authz" not in manifest

    artifact = run_dir / "finding_validation.json"
    _write(artifact, "{}")
    receipt = write_run_receipt(
        run_dir / "run_receipt.json",
        manifest_path=run_dir / "run_manifest.json",
        artifacts={"validation": artifact},
    )
    assert receipt["manifest_sha256"]
    assert receipt["artifacts"]["validation"]["sha256"]

    repo = tmp_path / "repo"
    codex_home = tmp_path / "codex-home"
    _write(repo / "codex/_agents_header.md", "header\n")
    _write(repo / "skill/核心技能文件.v3.md", "# core\nbody\n")
    _write(repo / "AGENTS.md", "header\nbody\n")
    _write(repo / "codex/AGENTS.md", "header\nbody\n")
    _write(repo / "SKILL.md", f"---\nversion: {__version__}\n---\n")
    _write(repo / "CHANGELOG.md", f"# Changelog\n\n## {__version__} - 2026-07-16\n")
    foreign = tmp_path / "foreign/src.md"
    _write(foreign, "foreign")
    (codex_home / "prompts").mkdir(parents=True)
    (codex_home / "prompts/src.md").symlink_to(foreign)

    result = doctor(repo, codex_home=codex_home)
    assert result["checks"]["project_agents"]["status"] == "ok"
    assert result["checks"]["src_alias"]["status"] == "foreign"
    assert result["ok"] is True
