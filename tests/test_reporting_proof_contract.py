from __future__ import annotations

import json

from engine.benchmark_eval import evaluate, load_findings, load_oracle
from engine.enforce import REJECTED, guardian_check_finding
from engine.orchestrator import CognitiveState, harvest_evidence
from engine.reporting.schema import load_finding
from engine.reporting.validate import validate_finding


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _idor_fixture(run_dir):
    fdir = run_dir / "findings" / "finding_001"
    _write(fdir / "request_owner.http",
           "GET /api/orders/1001 HTTP/1.1\nHost: t.example\nCookie: sid=owner-a\n\n")
    _write(fdir / "response_owner.http",
           'HTTP/1.1 200 OK\n\n{"order_id":"1001","owner":"owner-a","amount":10}')
    _write(fdir / "request_attacker.http",
           "GET /api/orders/1001 HTTP/1.1\nHost: t.example\nCookie: sid=attacker-b\n\n")
    _write(fdir / "response_attacker.http",
           'HTTP/1.1 200 OK\n\n{"order_id":"1001","owner":"owner-a","amount":10}')
    _write(fdir / "request_denied.http",
           "GET /api/orders/2002 HTTP/1.1\nHost: t.example\nCookie: sid=attacker-b\n\n")
    _write(fdir / "response_denied.http",
           'HTTP/1.1 403 Forbidden\n\n{"error":"not order owner"}')
    _write(fdir / "poc.sh", "curl https://t.example/api/orders/1001 -H 'Cookie: sid=attacker-b'\n")
    finding = {
        "schema_version": 1,
        "id": "finding_001",
        "title": "攻击者账号可读取所有者订单",
        "severity": "P2",
        "vuln_type": "idor",
        "target": "https://t.example/api/orders/1001",
        "risk": {
            "summary": "订单读取缺少对象归属校验。",
            "proven_impact": "攻击者账号读取到所有者订单金额。",
        },
        "recommendation": {"summary": "按当前身份校验订单归属。"},
        "feature_point": {"module": "orders"},
        "apis": [{
            "method": "GET", "path": "/api/orders/{id}",
            "purpose": "read order", "risk_params": ["id"],
        }],
        "proof_packets": [
            {"name": "owner", "phase": "owner_control",
             "request_file": "request_owner.http", "response_file": "response_owner.http",
             "evidence_summary": "owner baseline for order 1001"},
            {"name": "attacker", "phase": "unauthorized_actor",
             "request_file": "request_attacker.http", "response_file": "response_attacker.http",
             "evidence_summary": "attacker receives the same owned order"},
            {"name": "denied_control", "phase": "access_denied_control",
             "request_file": "request_denied.http", "response_file": "response_denied.http",
             "evidence_summary": "same endpoint enforces ownership for another order"},
        ],
        "verification": {
            "status": "confirmed", "evidence_type": "authorization_differential",
            "observed_effect": "Distinct attacker credentials returned owner-a order 1001",
            "identities": ["owner-a", "attacker-b"],
            "objects": ["order 1001 owned by owner-a"],
            "object_marker": '"order_id":"1001"',
            "access_expectation": {
                "expected_access": "owner_only",
                "basis": "same_endpoint_denial",
                "proof_packet_ids": ["denied_control"],
                "proof_refs": [],
                "marker": "not order owner",
            },
            "evidence_files": ["request_owner.http", "response_owner.http",
                               "request_attacker.http", "response_attacker.http",
                               "request_denied.http", "response_denied.http"],
            "impact_proof_refs": [],
            "assertions": [
                {"file": "response_owner.http", "relation": "contains",
                 "value": '"owner":"owner-a"'},
                {"file": "response_attacker.http", "relation": "contains",
                 "value": '"owner":"owner-a"'},
            ],
        },
        "claim": {
            "kind": "root_finding", "profile": "idor_read",
            "invariant": "only the order owner may read the order",
            "proof_packet_ids": ["owner", "attacker", "denied_control"],
        },
        "impact_claims": [{
            "id": "impact-1", "status": "proven",
            "statement": "攻击者账号读取到所有者订单金额。",
            "proof_refs": ["response_attacker.http"],
            "marker": '"amount":10',
        }],
        "chain_assessment": {
            "status": "hypothesis", "chain_feasible": False,
            "chain_path": "order read -> payment research",
            "final_impact": "payment manipulation", "blockers": ["not tested"],
            "proof_refs": [],
        },
        "manual_burp_replay": ["login as owner and capture baseline",
                               "login as attacker and replay the same object"],
        "poc": {"file": "poc.sh"},
        "source_proof": None,
    }
    _write(fdir / "finding.json", json.dumps(finding, ensure_ascii=False, indent=2))
    return fdir


def test_machine_checked_idor_root_finding_is_valid(tmp_path):
    fdir = _idor_fixture(tmp_path)
    finding = load_finding(fdir / "finding.json")
    result = validate_finding(finding, fdir / "finding.json", tmp_path,
                              authorized_hosts=["t.example"])
    assert result.ok, result.reasons


def test_public_or_unclassified_content_cannot_be_reported_as_authorization_bug(tmp_path):
    fdir = _idor_fixture(tmp_path)
    finding = load_finding(fdir / "finding.json")
    finding["verification"].pop("access_expectation")
    result = validate_finding(finding, fdir / "finding.json", tmp_path)
    assert not result.ok
    assert any("access_expectation" in reason for reason in result.reasons)

    finding = load_finding(fdir / "finding.json")
    finding["verification"]["access_expectation"]["expected_access"] = "public"
    result = validate_finding(finding, fdir / "finding.json", tmp_path)
    assert not result.ok
    assert any("never public" in reason for reason in result.reasons)


def test_unauthorized_access_is_not_allowed_to_fall_back_to_generic_diff(tmp_path):
    fdir = _idor_fixture(tmp_path)
    finding = load_finding(fdir / "finding.json")
    finding["vuln_type"] = "未授权访问 / 信息泄露"
    finding["proof_packets"][0]["phase"] = "authenticated_control"
    finding["proof_packets"][1]["phase"] = "anonymous_attempt"
    _write(fdir / "request_attacker.http",
           "GET /api/orders/1001 HTTP/1.1\nHost: t.example\n\n")
    finding["verification"]["access_expectation"].pop("public_exposure_check", None)
    result = validate_finding(finding, fdir / "finding.json", tmp_path)
    assert not result.ok
    assert any("public_exposure_check" in reason for reason in result.reasons)


def test_chain_escalation_cannot_replace_proven_root_impact(tmp_path):
    fdir = _idor_fixture(tmp_path)
    finding = load_finding(fdir / "finding.json")
    finding["risk"]["proven_impact"] = "管理员账户接管"
    finding["verification"]["impact_proof_refs"] = ["response_attacker.http"]
    result = validate_finding(finding, fdir / "finding.json", tmp_path)
    assert not result.ok
    assert any("proven_impact must exactly match" in reason for reason in result.reasons)


def test_high_impact_claim_requires_class_specific_physical_marker(tmp_path):
    fdir = _idor_fixture(tmp_path)
    finding = load_finding(fdir / "finding.json")
    statement = "RCE was proven on the server"
    finding["risk"]["proven_impact"] = statement
    finding["impact_claims"][0].update({
        "statement": statement,
        "proof_refs": ["response_attacker.http"],
        "marker": '"owner":"owner-a"',
    })
    finding["verification"]["impact_proof_refs"] = ["response_attacker.http"]
    result = validate_finding(finding, fdir / "finding.json", tmp_path)
    assert not result.ok
    assert any("impact_type=command_execution" in reason for reason in result.reasons)
    assert any("execution_nonce" in reason for reason in result.reasons)


def test_denial_basis_must_be_for_the_same_api_path(tmp_path):
    fdir = _idor_fixture(tmp_path)
    _write(fdir / "request_denied.http",
           "GET /api/unrelated/admin HTTP/1.1\nHost: t.example\nCookie: sid=attacker-b\n\n")
    finding = load_finding(fdir / "finding.json")
    result = validate_finding(finding, fdir / "finding.json", tmp_path)
    assert not result.ok
    assert any("same normalized API path" in reason for reason in result.reasons)


def test_race_counts_must_be_reproducible_from_raw_log(tmp_path):
    fdir = _idor_fixture(tmp_path)
    finding = load_finding(fdir / "finding.json")
    finding["vuln_type"] = "race-condition"
    finding["proof_packets"][0]["phase"] = "state_before"
    finding["proof_packets"][1]["phase"] = "concurrent_attempt"
    finding["proof_packets"][2]["phase"] = "state_after"
    _write(fdir / "race.log", "request-1 success\nrequest-2 rejected\n")
    finding["verification"].update({
        "evidence_type": "concurrency_state_change",
        "concurrency": {"attempts": 3, "successes": 2},
        "raw_concurrency_file": "race.log",
        "success_marker": "success",
    })
    result = validate_finding(finding, fdir / "finding.json", tmp_path)
    assert not result.ok
    assert any("cannot be reproduced" in reason for reason in result.reasons)


def test_xss_without_browser_execution_stays_unconfirmed(tmp_path):
    fdir = _idor_fixture(tmp_path)
    finding = load_finding(fdir / "finding.json")
    finding["vuln_type"] = "stored-xss"
    finding["verification"]["evidence_type"] = "browser_execution"
    result = validate_finding(finding, fdir / "finding.json", tmp_path)
    assert not result.ok
    assert any("browser_evidence_file" in reason for reason in result.reasons)


def test_guardian_rejected_structured_finding_cannot_close_cell(tmp_path):
    fdir = _idor_fixture(tmp_path)
    path = fdir / "finding.json"
    finding = load_finding(path)
    finding["vuln_type"] = "CORS"
    finding["title"] = "CORS configuration"
    finding["apis"][0]["risk_params"] = ["origin"]
    finding["verification"].update({
        "evidence_type": "response_differential",
        "object_marker": "",
    })
    finding["proof_packets"][0]["phase"] = "baseline"
    finding["proof_packets"][1]["phase"] = "exploit"
    _write(path, json.dumps(finding, ensure_ascii=False, indent=2))
    verdict = guardian_check_finding(finding, fdir, authorized_hosts=["t.example"])
    assert verdict.result == REJECTED

    evidence = harvest_evidence(tmp_path, authorized_hosts=["t.example"])
    assert evidence["normalized_findings"] == []
    state = CognitiveState("s", "https://t.example", vuln_classes=["CORS"])
    state.seed_matrix([{"endpoint": "/api/orders/{id}", "method": "GET", "params": ["origin"]}])
    state.update("", evidence)
    assert next(iter(state.matrix.values()))["state"] == "untested"


def test_benchmark_ignores_hypothesis_and_requires_exact_method_role(tmp_path):
    _write(tmp_path / "proof.json", "{}")
    summary = {
        "findings": [
            {"id": "hyp", "endpoint": "/api/refund", "method": "POST",
             "params": ["amount"], "roles": ["user"], "class": "amount-tamper",
             "evidence_file": "proof.json", "acceptance_status": "accepted",
             "proof_status": "pending", "claim_kind": "root_finding"},
            {"id": "root", "endpoint": "/api/refund", "method": "POST",
             "params": ["amount"], "roles": ["user"], "class": "amount-tamper",
             "evidence_file": "proof.json", "acceptance_status": "accepted",
             "proof_status": "confirmed", "claim_kind": "root_finding"},
        ]
    }
    _write(tmp_path / "summary.json", json.dumps(summary))
    _write(tmp_path / "oracle.json", json.dumps([{
        "id": "case", "endpoint": "/api/refund", "method": "POST",
        "params": ["amount"], "roles": ["user"], "class": "amount-tamper",
        "score": 100,
    }]))
    findings = load_findings(tmp_path / "summary.json")
    assert [finding.id for finding in findings] == ["root"]
    result = evaluate(load_oracle(tmp_path / "oracle.json"), findings, [])
    assert result["total_score"] == 100
    findings[0].methods = []
    assert evaluate(load_oracle(tmp_path / "oracle.json"), findings, [])["total_score"] == 0
