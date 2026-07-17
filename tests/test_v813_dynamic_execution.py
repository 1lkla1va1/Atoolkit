from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.dynamic_execution import (
    DynamicExecutionError,
    build_execution_projection,
    compile_execution_contract,
    load_authority_execution_events,
    parse_execution_event_lines,
    projection_matches_files,
    record_execution_event,
    write_execution_projection,
)
from engine.ledger import CoverageLedger
from engine.orchestrator import (
    CognitiveState,
    NEGATIVE_WITH_EVIDENCE,
    POSITIVE,
    SHALLOW_NEGATIVE,
    _apply_dynamic_execution_gate,
)
from engine.run_authority import append_monotonic_event
from engine.reporting.validate import validate_run_artifacts
from engine.skill_runtime import (
    SkillRuntimeError,
    initialize_direct_run,
    preflight_direct_run,
)
from tests.test_v89_reporting_evidence_binding import _negative_fixture


def _surface(**overrides):
    value = {
        "surface_id": "tm-auth-enum",
        "asset_id": "https://t.example:443",
        "endpoint": "/api/login.php",
        "method": "POST",
        "param": "username",
        "roles": ["anonymous"],
        "risk_tags": ["auth-flow"],
        "vuln_class": "user-enumeration",
        "feature_id": "login",
        "threat_id": "T-enum",
        "security_invariant": "valid and invalid usernames are indistinguishable",
        "observable_violation": "message, timing, or behavior differs",
        "evidence_required": ["valid/invalid differential"],
        "identity_requirement": {"mode": "single"},
        "status": "not_tested",
        "in_run_scope": True,
    }
    value.update(overrides)
    return value


def _ledger(surface=None):
    return CoverageLedger([surface or _surface()], metadata={
        "execution_contract_version": 1,
    })


def _evidence(tmp_path: Path, name: str = "evidence/response.http") -> str:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("HTTP/1.1 200 OK\n\n{}", encoding="utf-8")
    return name


def _event(surface_id: str, refs: list[str], completed: list[str], **extra):
    return {
        "schema_version": 1,
        "event_id": extra.pop("event_id", "ev-1"),
        "surface_id": surface_id,
        "outcome": extra.pop("outcome", "observed"),
        "completed_obligations": completed,
        "evidence_refs": refs,
        "barrier_signals": extra.pop("barrier_signals", []),
        **extra,
    }


def test_user_enumeration_message_only_keeps_timing_and_behavior_open(tmp_path):
    ledger = _ledger()
    ref = _evidence(tmp_path)
    contract = compile_execution_contract(ledger.surfaces[0])
    required = {row["obligation_id"] for row in contract["required_obligations"]}
    assert {"auth-message-channel", "auth-timing-channel",
            "auth-behavior-channel"}.issubset(required)

    result = record_execution_event(
        run_dir=tmp_path, ledger=ledger,
        event=_event("tm-auth-enum", [ref], [
            "valid-baseline", "auth-message-channel",
        ]),
    )
    projection = build_execution_projection(ledger, [result["event"]])
    row = projection["progress"][0]
    missing = {item["obligation_id"] for item in row["missing_obligations"]}

    assert row["execution_status"] == "executing"
    assert {"auth-timing-channel", "auth-behavior-channel"}.issubset(missing)
    assert projection["stats"]["open"] == 1


def test_reset_bypass_requires_independent_families():
    contract = compile_execution_contract(_surface(
        surface_id="tm-reset",
        endpoint="/api/reset-password.php",
        param="auth_token",
        vuln_class="auth_token bypass",
    ))
    required = {row["obligation_id"] for row in contract["required_obligations"]}
    assert {
        "auth-field-omission", "auth-empty-null", "auth-type-shape",
        "auth-step-order", "auth-reuse-binding",
    }.issubset(required)


def test_empty_dataset_adds_data_recovery_and_cannot_close_negative(tmp_path):
    surface = _surface(
        surface_id="tm-balance",
        endpoint="/api/user/balance-records.php",
        param="user_hash",
        vuln_class="IDOR",
        identity_requirement={"mode": "peer_pair"},
        status="not_vulnerable",
    )
    ledger = _ledger(surface)
    ref = _evidence(tmp_path, "evidence/empty.http")
    result = record_execution_event(
        run_dir=tmp_path, ledger=ledger,
        event=_event("tm-balance", [ref], ["valid-baseline"],
                     barrier_signals=["empty_dataset", "object_absent"]),
    )
    projection = build_execution_projection(ledger, [result["event"]])
    row = projection["progress"][0]
    missing = {item["obligation_id"] for item in row["missing_obligations"]}

    assert row["execution_status"] == "blocked_recoverable"
    assert row["closure_allowed"] is False
    assert {"recovery-data-prepared", "retest-after-data-recovery"}.issubset(missing)

    contract = compile_execution_contract(surface)
    recovered = record_execution_event(
        run_dir=tmp_path, ledger=ledger,
        event=_event(
            "tm-balance", [ref],
            [
                *[item["obligation_id"]
                  for item in contract["required_obligations"]],
                "recovery-data-prepared", "retest-after-data-recovery",
            ],
            event_id="ev-recovered",
        ),
    )
    projection = build_execution_projection(
        ledger, [result["event"], recovered["event"]])
    assert projection["progress"][0]["barrier_signals"] == []
    assert projection["progress"][0]["closure_allowed"] is True
    assert projection["stats"]["open"] == 0


def test_transaction_boolean_only_leaves_boundaries_and_state_delta_open(tmp_path):
    surface = _surface(
        surface_id="tm-points",
        endpoint="/api/user/create-batch-order.php",
        param="use_points",
        vuln_class="points value-integrity bypass",
        security_invariant="points and payable amount preserve value",
        observable_violation="payable total or points delta is invalid",
        status="not_vulnerable",
    )
    ledger = _ledger(surface)
    ref = _evidence(tmp_path, "evidence/true-only.http")
    result = record_execution_event(
        run_dir=tmp_path, ledger=ledger,
        event=_event("tm-points", [ref], [
            "valid-baseline", "transaction-valid-control",
        ]),
    )
    projection = build_execution_projection(ledger, [result["event"]])
    row = projection["progress"][0]
    missing = {item["obligation_id"] for item in row["missing_obligations"]}

    assert row["execution_status"] == "needs_followup"
    assert {"transaction-zero-negative", "transaction-large-precision",
            "transaction-type-shape", "transaction-state-delta"}.issubset(missing)


def test_xss_ssrf_and_file_families_compile_result_specific_obligations():
    xss = compile_execution_contract(_surface(
        surface_id="tm-xss", endpoint="/api/submit-audit.php",
        param="shop_name", vuln_class="stored XSS"))
    ssrf = compile_execution_contract(_surface(
        surface_id="tm-ssrf", endpoint="/api/image-preview.php",
        param="url", vuln_class="SSRF"))
    upload = compile_execution_contract(_surface(
        surface_id="tm-file", endpoint="/api/upload.php",
        param="file", vuln_class="file upload bypass"))

    ids = lambda value: {row["obligation_id"]
                         for row in value["required_obligations"]}
    assert {"xss-input-attempt", "xss-render-outcome", "xss-browser-outcome",
            "stored-input-readback", "stored-input-peer-view"}.issubset(ids(xss))
    assert {"fetch-destination-control", "server-side-fetch-outcome"}.issubset(ids(ssrf))
    assert {"file-valid-control", "file-bypass-families",
            "file-retrieval-outcome", "file-nonfile-params"}.issubset(ids(upload))


def test_idor_floor_requires_two_identities_even_if_model_declares_single():
    contract = compile_execution_contract(_surface(
        surface_id="tm-idor", endpoint="/api/order-detail.php",
        param="order_no", vuln_class="IDOR",
        identity_requirement={"mode": "single"},
    ))
    required = {row["obligation_id"] for row in contract["required_obligations"]}
    assert {"owner-control", "alternate-identity-attempt",
            "ownership-or-role-marker"}.issubset(required)


def test_execution_event_rejects_unsafe_or_unbound_claims(tmp_path):
    ledger = _ledger()
    ref = _evidence(tmp_path)
    with pytest.raises(DynamicExecutionError, match="unknown obligations"):
        record_execution_event(
            run_dir=tmp_path, ledger=ledger,
            event=_event("tm-auth-enum", [ref], ["made-up"]),
        )
    with pytest.raises(DynamicExecutionError, match="inside run dir"):
        record_execution_event(
            run_dir=tmp_path, ledger=ledger,
            event=_event("tm-auth-enum", ["../outside.http"], ["valid-baseline"]),
        )
    empty = tmp_path / "evidence" / "empty.http"
    empty.write_bytes(b"")
    with pytest.raises(DynamicExecutionError, match="is empty"):
        record_execution_event(
            run_dir=tmp_path, ledger=ledger,
            event=_event("tm-auth-enum", ["evidence/empty.http"], ["valid-baseline"]),
        )
    (tmp_path / "execution-queue.json").write_text("{}", encoding="utf-8")
    with pytest.raises(DynamicExecutionError, match="control artifact"):
        record_execution_event(
            run_dir=tmp_path, ledger=ledger,
            event=_event(
                "tm-auth-enum", ["execution-queue.json"], ["valid-baseline"]),
        )


def test_execution_event_replay_is_idempotent_and_conflict_is_rejected(tmp_path):
    ledger = _ledger()
    ref = _evidence(tmp_path)
    event = _event("tm-auth-enum", [ref], ["valid-baseline"])
    first = record_execution_event(run_dir=tmp_path, ledger=ledger, event=event)
    second = record_execution_event(run_dir=tmp_path, ledger=ledger, event=event)
    assert first["idempotent"] is False
    assert second["idempotent"] is True
    with pytest.raises(DynamicExecutionError, match="different content"):
        record_execution_event(
            run_dir=tmp_path, ledger=ledger,
            event={**event, "completed_obligations": [
                "valid-baseline", "auth-message-channel",
            ]},
        )


def test_execution_event_hash_binds_evidence_bytes(tmp_path):
    ledger = _ledger()
    ref = _evidence(tmp_path)
    saved = record_execution_event(
        run_dir=tmp_path, ledger=ledger,
        event=_event("tm-auth-enum", [ref], ["valid-baseline"]),
    )["event"]
    assert saved["evidence_sha256"][ref]

    (tmp_path / ref).write_text(
        "HTTP/1.1 200 OK\n\nchanged", encoding="utf-8")
    from engine.dynamic_execution import normalize_execution_event
    assert normalize_execution_event(tmp_path, ledger, saved) != saved


def test_discovery_is_backlog_only_and_does_not_expand_ledger(tmp_path):
    ledger = _ledger()
    ref = _evidence(tmp_path, "evidence/js-path.txt")
    before = [row["surface_id"] for row in ledger.surfaces]
    result = record_execution_event(
        run_dir=tmp_path, ledger=ledger,
        event=_event(
            "tm-auth-enum", [ref], [], outcome="discovery",
            discovered_surfaces=[{
                "method": "POST", "endpoint": "/api/new-action.php",
                "params": ["id"],
            }],
        ),
    )
    projection = write_execution_projection(tmp_path, ledger, [result["event"]])

    assert [row["surface_id"] for row in ledger.surfaces] == before
    assert projection["stats"]["backlog"] == 1
    assert projection["backlog"][0]["disposition"] == "next_run_required"
    assert projection_matches_files(tmp_path, projection) == []


def test_rejected_finding_prioritizes_proof_repair():
    first = _surface(surface_id="tm-a", status="exploring")
    second = _surface(surface_id="tm-b", endpoint="/api/refund.php",
                      param="amount", vuln_class="refund amount bypass")
    projection = build_execution_projection(
        CoverageLedger([first, second]), [], rejected_surface_ids=["tm-b"])
    assert projection["queue"][0]["surface_id"] == "tm-b"
    assert projection["queue"][0]["execution_status"] == "proof_repair"


def test_authority_execution_chain_detects_tamper(tmp_path):
    authority = tmp_path / ".atoolkit"
    event = {"event_id": "e1", "surface_id": "tm-a"}
    append_monotonic_event(
        authority, session_id="run-1", stream="execution", event=event)
    assert load_authority_execution_events(authority, "run-1") == [event]

    path = authority / "events" / "run-1" / "execution.jsonl"
    row = json.loads(path.read_text(encoding="utf-8"))
    row["event"]["surface_id"] = "tampered"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(DynamicExecutionError, match="hash chain"):
        load_authority_execution_events(authority, "run-1")


def test_parse_execution_event_line_is_structured_only():
    events, errors = parse_execution_event_lines(
        'noise\nEXECUTION_EVENT: {"schema_version":1,"event_id":"e1"}\n')
    assert errors == []
    assert events[0]["event_id"] == "e1"
    events, errors = parse_execution_event_lines(
        "EXECUTION_EVENT: {not-json}\n")
    assert events == []
    assert errors


def test_direct_preflight_exists_before_fresh_recon_and_init_reuses_it(tmp_path):
    run = tmp_path / "fresh-run"
    first = preflight_direct_run(run_dir=run, target="https://t.example/")
    second = preflight_direct_run(run_dir=run, target="https://t.example/")

    assert first["phase"] == "recon"
    assert first["runtime_incomplete"] is True
    assert first["idempotent"] is False
    assert second["idempotent"] is True
    assert not (run / "coverage-ledger.json").exists()

    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"surfaces": [{
        "endpoint": "/api/login", "method": "POST", "params": ["username"],
    }]}), encoding="utf-8")
    initialized = initialize_direct_run(
        run_dir=run, target="https://t.example/", inventory_path=inventory)
    assert initialized["execution_contract_version"] == 1
    assert (run / "execution-contracts.json").is_file()


def test_direct_preflight_cannot_be_rebound_to_another_target(tmp_path):
    run = tmp_path / "fresh-run"
    preflight_direct_run(run_dir=run, target="https://t.example/")
    with pytest.raises(SkillRuntimeError, match="different target"):
        preflight_direct_run(run_dir=run, target="https://other.example/")


def test_engine_gate_reopens_negative_but_never_reopens_confirmed():
    state = CognitiveState("run-1", "https://t.example/")
    rows = [
        _surface(surface_id="tm-negative", status="not_tested"),
        _surface(surface_id="tm-positive", endpoint="/api/other",
                 status="not_tested"),
    ]
    state.seed_threat_cells(rows)
    by_id = {
        cell["surface"]["surface_id"]: cell for cell in state.matrix.values()
    }
    by_id["tm-negative"]["state"] = NEGATIVE_WITH_EVIDENCE
    by_id["tm-negative"]["evidence"] = "negative.json"
    by_id["tm-positive"]["state"] = POSITIVE
    by_id["tm-positive"]["evidence"] = "finding.json"
    projection = {
        "progress": [
            {
                "surface_id": "tm-negative", "closure_allowed": False,
                "missing_obligations": [{
                    "obligation_id": "auth-timing-channel",
                    "description": "compare repeated timing",
                }],
            },
            {
                "surface_id": "tm-positive", "closure_allowed": False,
                "missing_obligations": [{
                    "obligation_id": "valid-baseline",
                    "description": "baseline",
                }],
            },
        ],
    }

    reopened = _apply_dynamic_execution_gate(state, projection)

    assert reopened == ["tm-negative"]
    assert by_id["tm-negative"]["state"] == SHALLOW_NEGATIVE
    assert by_id["tm-negative"]["next_actions"] == ["compare repeated timing"]
    assert by_id["tm-positive"]["state"] == POSITIVE


def test_final_validator_recomputes_authority_execution_projection(tmp_path):
    _negative_fixture(tmp_path)
    ledger_path = tmp_path / "coverage-ledger.json"
    ledger_value = json.loads(ledger_path.read_text(encoding="utf-8"))
    ledger_value.setdefault("metadata", {})[
        "execution_contract_version"] = 1
    ledger_path.write_text(json.dumps(ledger_value), encoding="utf-8")
    ledger = CoverageLedger.from_dict(ledger_value)
    contract = compile_execution_contract(ledger.surfaces[0])
    completed = [
        item["obligation_id"] for item in contract["required_obligations"]
    ]
    normalized = record_execution_event(
        run_dir=tmp_path, ledger=ledger,
        event=_event(
            "search-sqli", ["negative_search.json"], completed,
            event_id="final-negative"),
    )["event"]
    manifest = json.loads((tmp_path / "run_manifest.json").read_text(
        encoding="utf-8"))
    authority = Path(manifest["authority_path"]).parent.parent
    append_monotonic_event(
        authority, session_id=manifest["session_id"],
        stream="execution", event=normalized)
    write_execution_projection(tmp_path, ledger, [normalized])

    report = validate_run_artifacts(tmp_path, allow_empty=True)
    assert report["status"] == "empty_allowed", report["closure_gate"]
    assert report["closure_gate"]["execution"]["open"] == 0

    evidence_path = tmp_path / "negative_search.json"
    original_evidence = evidence_path.read_bytes()
    evidence_path.write_bytes(original_evidence + b"\n")
    evidence_tampered = validate_run_artifacts(tmp_path, allow_empty=True)
    assert any(
        reason.startswith("execution_projection_invalid:DynamicExecutionError:")
        for reason in evidence_tampered["closure_gate"]["reasons"]
    )
    evidence_path.write_bytes(original_evidence)

    queue = json.loads((tmp_path / "execution-queue.json").read_text(
        encoding="utf-8"))
    queue["queue"] = [{"forged": True}]
    (tmp_path / "execution-queue.json").write_text(
        json.dumps(queue), encoding="utf-8")
    tampered = validate_run_artifacts(tmp_path, allow_empty=True)
    assert "execution_projection_mismatch:execution-queue.json" in (
        tampered["closure_gate"]["reasons"])
