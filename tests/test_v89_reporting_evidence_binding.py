from __future__ import annotations

import hashlib
import json
import shutil

import pytest

from engine.reporting.collect import collect_structured_findings
from engine.reporting.schema import load_finding, normalize_finding
from engine.reporting.validate import (
    _authority_plan_gate,
    _request_components,
    _request_contains_param,
    validate_finding,
    validate_run_artifacts,
    verify_validation_artifact,
)
from engine.project_state import ProjectStateStore
from engine.orchestrator import harvest_evidence
from engine.run_authority import append_monotonic_event
from tests.test_reporting_proof_contract import _idor_fixture
from tests.test_v88_reporting_fail_closed import _manifest, _write
from tests.test_v89_authority_contract import _bound_manifest, _context


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _negative_fixture(tmp_path, *, create_manifest: bool = True):
    if create_manifest:
        _manifest(tmp_path)
    exact_cell = {
        "asset_id": "https://t.example:443",
        "endpoint": "/api/search",
        "method": "GET",
        "param": "q",
        "actor_role": "user",
        "vuln_class": "sqli",
        "namespace": "/shop",
        "param_location": "query",
        "subject_role": "customer",
        "object_kind": "search-result",
    }
    packets = []
    for vector, value in (("boolean", "alpha"), ("error", "beta"), ("time", "gamma")):
        request = (
            f"GET /shop/api/search?q={value} HTTP/1.1\n"
            "Host: t.example\nCookie: sid=user-a\n\n"
        )
        response = (
            "HTTP/1.1 200 OK\n\n"
            f'{{"result":"empty","probe":"{value}",'
            '"subject":"customer","kind":"search-result"}'
        )
        packets.append({
            "vector": vector,
            "request": request,
            "response": response,
            "request_sha256": _sha(request),
            "response_sha256": _sha(response),
            "assertions": [{
                "target": "response", "relation": "contains",
                "value": '"result":"empty"',
            }],
            "identity_assertions": {
                "actor_role": {
                    "target": "request", "relation": "contains",
                    "value": "sid=user-a",
                },
                "subject_role": {
                    "target": "response", "relation": "contains",
                    "value": '"subject":"customer"',
                },
                "object_kind": {
                    "target": "response", "relation": "contains",
                    "value": '"kind":"search-result"',
                },
            },
        })
    envelope = {
        "schema_version": "1.0",
        "kind": "negative_evidence",
        "exact_cell": exact_cell,
        "evidence_types": ["baseline"],
        "identities": ["user-a"],
        "roles": ["user"],
        "packets": packets,
    }
    _write(tmp_path / "negative_search.json", json.dumps(envelope))
    _write(tmp_path / "inventory.json", json.dumps({
        "endpoints": [{
            "asset_id": exact_cell["asset_id"],
            "endpoint": exact_cell["endpoint"],
            "method": exact_cell["method"],
            "params": [exact_cell["param"]],
            "roles": [exact_cell["actor_role"]],
            "vuln_classes": [exact_cell["vuln_class"]],
        }],
    }))
    _write(tmp_path / "coverage-ledger.json", json.dumps({
        "schema_version": 1,
        "surfaces": [{
            "surface_id": "search-sqli", **exact_cell,
            "roles": ["user"], "status": "not_vulnerable",
            "negative_depth_checked": True, "in_run_scope": True,
            "risk_tags": ["input-validation"],
            "evidence_ref": "negative_search.json",
            # These remain compatibility metadata for session_gate.  The
            # reporting validator derives its own counts from the envelope.
            "negative": {
                "vectors": ["boolean", "error", "time"],
                "response_count": 3,
                "evidence_types": ["baseline"],
                "identities": ["user-a"],
                "roles": ["user"],
            },
        }],
    }))
    _write(tmp_path / "candidate-ledger.json", json.dumps({
        "schema_version": "1.1", "candidates": [],
    }))
    return envelope


def test_every_api_requires_a_matching_raw_request_packet(tmp_path):
    fdir = _idor_fixture(tmp_path)
    path = fdir / "finding.json"
    finding = load_finding(path)
    finding["apis"].append({
        "method": "POST", "path": "/api/admin/delete-all",
        "purpose": "unproven appended API", "risk_params": ["id"],
    })

    result = validate_finding(finding, path, tmp_path)

    assert result.ok is False
    assert any("exact cell has no raw METHOD/path/Host proof binding" in reason
               for reason in result.reasons)


def test_validated_normalized_cell_retains_its_packet_binding(tmp_path):
    fdir = _idor_fixture(tmp_path)
    path = fdir / "finding.json"

    result = validate_finding(load_finding(path), path, tmp_path)

    assert result.ok is True, result.reasons
    cell = result.normalized["exact_cells"][0]
    assert {"owner", "attacker", "denied_control"}.issubset(
        set(cell["proof_packet_ids"]))
    assert "findings/finding_001/request_attacker.http" in cell["proof_files"]
    assert "findings/finding_001/response_attacker.http" in cell["proof_files"]


def test_each_api_asset_is_authorized_not_only_top_level_target(tmp_path):
    fdir = _idor_fixture(tmp_path)
    path = fdir / "finding.json"
    finding = load_finding(path)
    finding["apis"][0]["asset_id"] = "https://outside.example/"

    result = validate_finding(
        finding, path, tmp_path, authorized_hosts=["https://t.example/"])

    assert result.ok is False
    assert any("apis[0] target out of authorized scopes" in reason
               for reason in result.reasons)

    finding = load_finding(path)
    finding["apis"][0]["path"] = "https://t.example/api/orders/{id}"
    finding["apis"][0]["assets"] = ["https://outside.example/"]
    result = validate_finding(
        finding, path, tmp_path, authorized_hosts=["https://t.example/"])
    assert any("apis[0] target out of authorized scopes" in reason
               for reason in result.reasons)


def test_same_id_same_bytes_in_two_canonical_dirs_normalizes_once(tmp_path):
    first = _idor_fixture(tmp_path)
    shutil.copytree(first, tmp_path / "findings" / "finding_shadow")

    collected = collect_structured_findings(tmp_path)

    assert len(collected["accepted"]) == 1
    assert len(collected["normalized"]) == 1
    assert collected["ingestion_errors"] == []
    assert any(item["code"] == "duplicate_id_shadow"
               for item in collected["warnings"])


def test_normalized_root_cause_prefers_structured_invariant(tmp_path):
    fdir = _idor_fixture(tmp_path)
    path = fdir / "finding.json"
    finding = load_finding(path)

    from_claim = normalize_finding(finding, path, tmp_path)
    assert from_claim["root_cause"] == finding["claim"]["invariant"]

    finding["root_cause_invariant"] = "authorization owner check is omitted"
    explicit = normalize_finding(finding, path, tmp_path)
    assert explicit["root_cause"] == "authorization owner check is omitted"

    finding["root_cause"] = "resource lookup is not scoped to current owner"
    strongest = normalize_finding(finding, path, tmp_path)
    assert strongest["root_cause"] == "resource lookup is not scoped to current owner"


def test_negative_closure_is_derived_from_bound_packets_and_hashed(tmp_path):
    _negative_fixture(tmp_path)

    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert report["status"] == "empty_allowed", report["closure_gate"]
    assert report["closure_gate"]["result"] == "pass"
    assert "negative_search.json" in report["artifact_hashes"]
    assert verify_validation_artifact(report, tmp_path)["ok"] is True

    envelope_path = tmp_path / "negative_search.json"
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    envelope["packets"][0]["response"] += "tampered"
    _write(envelope_path, json.dumps(envelope))
    assert verify_validation_artifact(report, tmp_path)["ok"] is False


def test_engine_negative_markdown_can_embed_the_strict_evidence_contract(tmp_path):
    envelope = _negative_fixture(tmp_path)
    markdown = (
        "---\nendpoint: /api/search\nmethod: GET\nparam: q\n"
        "vuln: sqli\nvectors: boolean, error, time\n"
        "evidence_types: baseline\nidentities: user-a\nroles: user\n---\n"
        "<machine_evidence>\n"
        + json.dumps(envelope)
        + "\n</machine_evidence>\n"
    )
    _write(tmp_path / "negative_search.md", markdown)
    ledger_path = tmp_path / "coverage-ledger.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    ledger["surfaces"][0]["evidence_ref"] = "negative_search.md"
    _write(ledger_path, json.dumps(ledger))

    harvested = harvest_evidence(tmp_path)
    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert harvested["negatives"][0]["method"] == "GET"
    assert harvested["negatives"][0]["response_count"] >= 1
    assert report["status"] == "empty_allowed", report["closure_gate"]
    assert "negative_search.md" in report["artifact_hashes"]


def test_self_reported_negative_counts_cannot_replace_bound_packets(tmp_path):
    envelope = _negative_fixture(tmp_path)
    envelope["packets"] = envelope["packets"][:1]
    _write(tmp_path / "negative_search.json", json.dumps(envelope))

    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert report["status"] == "incomplete"
    assert "negative_depth_insufficient" in report["closure_gate"]["reasons"]


def test_negative_envelope_wrong_actor_or_hash_fails_closed(tmp_path):
    envelope = _negative_fixture(tmp_path)
    envelope["exact_cell"]["actor_role"] = "admin"
    envelope["packets"][0]["request_sha256"] = "0" * 64
    _write(tmp_path / "negative_search.json", json.dumps(envelope))

    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert report["status"] == "incomplete"
    assert "negative_evidence_invalid" in report["closure_gate"]["reasons"]


def test_namespace_relative_cell_requires_namespaced_physical_request(tmp_path):
    envelope = _negative_fixture(tmp_path)
    for packet in envelope["packets"]:
        packet["request"] = packet["request"].replace(
            "GET /shop/api/search", "GET /api/search", 1)
        packet["request_sha256"] = _sha(packet["request"])
    _write(tmp_path / "negative_search.json", json.dumps(envelope))

    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert report["status"] == "incomplete"
    assert "negative_evidence_invalid" in report["closure_gate"]["reasons"]


def test_body_param_binding_uses_structured_content_type_keys_only():
    misleading = _request_components(
        'POST /api/order HTTP/1.1\nHost: t.example\n'
        'Content-Type: application/json\n\n{"comment":"id=123"}',
        context=None,
        finding_target="https://t.example/",
    )
    assert not _request_contains_param(
        misleading, {"param": "id", "param_location": "body"})
    assert _request_contains_param(
        misleading, {"param": "comment", "param_location": "json"})

    wrong_type = _request_components(
        'POST /api/order HTTP/1.1\nHost: t.example\n'
        'Content-Type: text/plain\n\nid=123',
        context=None,
        finding_target="https://t.example/",
    )
    assert not _request_contains_param(
        wrong_type, {"param": "id", "param_location": "form"})

    form = _request_components(
        'POST /api/order HTTP/1.1\nHost: t.example\n'
        'Content-Type: application/x-www-form-urlencoded\n\nid=123&note=x',
        context=None,
        finding_target="https://t.example/",
    )
    assert _request_contains_param(
        form, {"param": "id", "param_location": "form"})
    assert not _request_contains_param(
        form, {"param": "id", "param_location": "json"})


def test_historical_dead_end_hash_alone_cannot_close_exact_cell(tmp_path):
    project = tmp_path / "project"
    run1 = project / "sessions" / "run-1"
    run1.mkdir(parents=True)
    _write(run1 / "arbitrary.json", json.dumps({"status": 404}))
    ProjectStateStore(
        project, project_scope=["https://t.example/"]).commit_run(
        "run-1",
        inventory=[{
            "asset": "https://t.example/", "method": "GET",
            "endpoint": "/api/removed", "params": [""], "roles": ["user"],
        }],
        dead_ends=[{
            "status": "not_applicable", "reason_code": "endpoint_removed",
            "refutation": "route returned 404", "asset": "https://t.example/",
            "method": "GET", "endpoint": "/api/removed", "param": "",
            "role_scope": "user", "vuln_class": "idor",
            "evidence_refs": ["arbitrary.json"],
        }],
    )
    run2 = project / "sessions" / "run-2"
    run2.mkdir(parents=True)
    _manifest(run2)
    surface = {
        "surface_id": "removed", "asset_id": "https://t.example:443",
        "method": "GET", "endpoint": "/api/removed", "param": "",
        "actor_role": "user", "roles": ["user"], "vuln_class": "idor",
        "namespace": "", "param_location": "", "subject_role": "",
        "object_kind": "", "status": "not_applicable", "in_run_scope": True,
        "reason": "inherited route removal",
        "evidence_ref": str(project / "project_state.json"),
    }
    _write(run2 / "inventory.json", json.dumps({
        "endpoints": [{
            "asset_id": surface["asset_id"], "method": "GET",
            "endpoint": "/api/removed", "params": [""],
            "roles": ["user"], "vuln_classes": ["idor"],
        }],
    }))
    _write(run2 / "coverage-ledger.json", json.dumps({
        "schema_version": 1, "surfaces": [surface],
    }))
    _write(run2 / "candidate-ledger.json", json.dumps({
        "schema_version": "1.1", "candidates": [],
    }))

    report = validate_run_artifacts(run2, allow_empty=True)

    assert report["status"] == "incomplete"
    assert "not_applicable_contract_missing" in report["closure_gate"]["reasons"]


@pytest.mark.parametrize("inventory_item", [
    {
        "asset_id": "https://outside.example:443",
        "method": "GET", "endpoint": "/api/x",
    },
    {
        "assets": ["https://t.example:443", "https://outside.example:443"],
        "method": "GET", "endpoint": "/api/x",
    },
    {
        "method": "GET", "endpoint": "https://outside.example/api/x",
    },
])
def test_inventory_cannot_expand_manifest_scope_even_when_coverage_is_out(
    tmp_path, inventory_item,
):
    _manifest(tmp_path)
    _write(tmp_path / "inventory.json", json.dumps({
        "endpoints": [inventory_item],
    }))
    _write(tmp_path / "coverage-ledger.json", json.dumps({
        "schema_version": 1,
        "surfaces": [{
            "surface_id": "outside", "method": "GET", "endpoint": "/api/x",
            "status": "not_tested", "in_run_scope": False,
        }],
    }))
    _write(tmp_path / "candidate-ledger.json", json.dumps({
        "schema_version": "1.1", "candidates": [],
    }))

    report = validate_run_artifacts(tmp_path, allow_empty=True)

    assert "inventory_asset_out_of_scope" in report["closure_gate"]["reasons"]


def _amended_cell(endpoint: str, *, vuln_class: str = "idor") -> dict:
    return {
        "asset_id": "https://shop.example:443", "endpoint": endpoint,
        "method": "POST", "param": "", "actor_role": "buyer",
        "vuln_class": vuln_class, "namespace": "", "param_location": "",
        "subject_role": "", "object_kind": "", "status": "not_applicable",
        "in_run_scope": True,
    }


def test_scope_amendment_must_derive_from_frozen_method_item(tmp_path):
    planned = {
        "asset": "https://shop.example:443", "endpoint": "/api/mystery",
        "method": "", "in_run_scope": True,
    }
    _project, run, authority, manifest = _bound_manifest(
        tmp_path, method_resolution_items=[planned],
        budget={"surface_budget": 2, "allowed_cell_count": 1})
    forged = _amended_cell("/api/surprise")
    append_monotonic_event(
        authority, session_id=run.name, stream="scope_amendment", event=forged)

    reasons, stats = _authority_plan_gate(
        _context(run, manifest), [forged])

    assert "authority_scope_event_not_from_frozen_method_item" in reasons
    assert stats["planned"] == 1  # frozen admitted cell only


def test_one_frozen_method_budget_item_cannot_fan_out_cells(tmp_path):
    planned = {
        "asset": "https://shop.example:443", "endpoint": "/api/mystery",
        "method": "", "in_run_scope": True,
    }
    _project, run, authority, manifest = _bound_manifest(
        tmp_path, method_resolution_items=[planned],
        budget={"surface_budget": 2, "allowed_cell_count": 1})
    first = _amended_cell("/api/mystery", vuln_class="idor")
    second = _amended_cell("/api/mystery", vuln_class="sqli")
    for event in (first, second):
        append_monotonic_event(
            authority, session_id=run.name, stream="scope_amendment", event=event)

    reasons, _stats = _authority_plan_gate(
        _context(run, manifest), [first, second])

    assert "authority_scope_event_budget_exceeded" in reasons


def test_frozen_plan_rejects_exact_cells_beyond_declared_budget(tmp_path):
    project, run, authority, manifest = _bound_manifest(
        tmp_path, budget={"surface_budget": 1, "allowed_cell_count": 1})
    plan_path = authority / "run_plans" / f"{run.name}.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    extra = {
        **plan["admitted_cells"][0],
        "param": "other",
        "cell_key": "",
    }
    plan["admitted_cells"].append(extra)
    plan["plan_sha256"] = ""
    plan["plan_sha256"] = __import__(
        "engine.run_authority", fromlist=["canonical_digest"]
    ).canonical_digest(plan)
    _write(plan_path, json.dumps(plan))

    reasons, _stats = _authority_plan_gate(_context(run, manifest), [])

    assert "authority_run_plan_allowed_count_mismatch" in reasons
    assert "authority_run_plan_budget_exceeded" in reasons
