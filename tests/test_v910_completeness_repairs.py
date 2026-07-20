from __future__ import annotations

import hashlib
import inspect
import json
import pathlib
import re

import pytest

from engine import data_hygiene
from engine.blocker import NEEDS_INPUT, RECOVERABLE, resolve_blocker
from engine.cell_identity import CellIdentity
from engine.continuation import ContinuationError, load_prior_continuation
from engine.exploration import validate_intuition_exploration
from engine.finalize import finalize_run
from engine.ledger import surfaces_from_legacy_cell
from engine.negative_retest import has_cross_stage_diversity
from engine.orchestrator import (CognitiveState, SHALLOW_NEGATIVE,
                                 _apply_project_cells, run_session)
from engine.outcome import build_miss_attribution, build_next_run_agenda
from engine.project_state import (ProjectStateStore,
                                  canonical_project_cell_key)
from engine.reporting.validate import (_canonical_digest, _target_allowed,
                                       validate_run_artifacts,
                                       verify_validation_artifact)
from engine.surface_key import canonical_cell_key, canonical_surface_key
from engine.vuln_classes import exact_vc, norm_vc
from tests.test_v89_delivery_contract import _complete_finding_run


SCOPE = "https://t.example/"


def _write(path: pathlib.Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, (dict, list)):
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    else:
        path.write_text(str(value), encoding="utf-8")


def _prior_run(root: pathlib.Path) -> pathlib.Path:
    run = root / "prior-run"
    run.mkdir(parents=True)
    attribution = build_miss_attribution(surfaces=[{
        "surface_id": "open-1", "method": "POST", "endpoint": "/api/search",
        "param": "q", "roles": ["user"], "status": "not_tested",
        "vuln_class": "SQLi",
    }])
    agenda = build_next_run_agenda(attribution)
    validation = {
        "schema_version": 2,
        "artifact_hashes": {},
        "miss_attribution": attribution,
        "next_run_agenda": agenda,
    }
    validation["validation_sha256"] = _canonical_digest(validation)
    _write(run / "finding_validation.json", validation)
    _write(run / "miss-attribution.json", attribution)
    _write(run / "next-run-agenda.json", agenda)
    return run


def test_exact_cell_identity_does_not_collapse_semantic_siblings():
    assert norm_vc("stored-xss") == norm_vc("reflected-xss") == "xss"
    assert exact_vc("stored-xss") != exact_vc("reflected-xss")
    assert exact_vc("水平越权") != exact_vc("垂直越权")
    stored = canonical_project_cell_key(
        SCOPE, method="POST", path="/comment", param="body",
        role_scope="user", vuln_class="stored-xss")
    reflected = canonical_project_cell_key(
        SCOPE, method="POST", path="/comment", param="body",
        role_scope="user", vuln_class="reflected-xss")
    assert stored != reflected


def test_schema2_cells_migrate_open_instead_of_inheriting_semantic_truth(tmp_path):
    key = canonical_project_cell_key(
        SCOPE, method="POST", path="/comment", param="body",
        role_scope="user", vuln_class="xss")
    state = {
        "schema_version": 2, "revision": 0, "project_scope": [SCOPE],
        "merged_run_ids": [], "facts": [], "intents": [], "negatives": [],
        "dead_ends": [], "inventory": {"surfaces": {}, "unresolved": {}},
        "cell_registry": {key: {"status": "not_vulnerable"}},
        "finding_registry": {}, "run_history": {}, "updated_at": "",
    }
    _write(tmp_path / "project_state.json", state)

    migrated = ProjectStateStore(tmp_path, project_scope=[SCOPE]).load()

    assert migrated["schema_version"] == 3
    assert migrated["migrated_from_schema"] == 2
    assert migrated["cell_registry"][key]["legacy_status"] == "not_vulnerable"
    assert migrated["cell_registry"][key]["status"] == "stale_requires_retest"


def test_unknown_method_is_not_silently_canonicalized_as_get():
    assert canonical_surface_key("/api/mystery") == ""
    assert canonical_cell_key("/api/mystery", "SQLi") == ""
    assert surfaces_from_legacy_cell({
        "endpoint": "/api/mystery", "vuln": "SQLi", "state": "negative",
    }) == []
    with pytest.raises(ValueError, match="explicit HTTP method"):
        CellIdentity.from_parts(
            SCOPE, method="", path="/api/mystery", vuln_class="SQLi")


def test_scope_validation_and_finalizer_defaults_are_fail_closed():
    assert _target_allowed("https://t.example/api", None) is False
    assert _target_allowed("https://t.example/api", [SCOPE]) is True
    default = inspect.signature(finalize_run).parameters["authority_trusted"].default
    assert default is False


def test_sensitive_detector_is_independent_from_redaction_regexes(monkeypatch):
    never = re.compile(r"$^")
    for name in ("_HEADER", "_BEARER", "_KEYED", "_EMAIL", "_CN_PHONE"):
        monkeypatch.setattr(data_hygiene, name, never)
    text = "Authorization: Bearer abcdefghijklmnop\nemail=user@example.test"
    redacted, counts = data_hygiene.redact_text(text)

    assert counts == {}
    assert redacted == text
    assert {"auth_header", "bearer", "email"}.issubset(
        set(data_hygiene.sensitive_kinds(text)))
    assert data_hygiene.sensitive_kinds(
        "Authorization: Bearer <redacted:bearer:0123456789ab>") == []


def test_captcha_is_recoverable_until_five_distinct_directions_are_exhausted():
    assert resolve_blocker("captcha required").category == RECOVERABLE
    four = {"reason": "captcha required", "bypass_attempts": ["a", "b", "c", "d"]}
    assert resolve_blocker(four).category == RECOVERABLE
    five = {**four, "bypass_attempts": ["a", "b", "c", "d", "e"]}
    resolution = resolve_blocker(five)
    assert resolution.category == NEEDS_INPUT
    assert resolution.blocker_type == "captcha_bypass_exhausted"


def test_intuition_exploration_requires_real_request_and_response(tmp_path):
    missing = validate_intuition_exploration(tmp_path)
    assert missing["ok"] is False
    _write(tmp_path / "request.http", "GET /api/profile HTTP/1.1\nHost: t.example\n")
    _write(tmp_path / "response.http", "HTTP/1.1 200 OK\n\n{}")
    _write(tmp_path / "intuition-exploration.json", {
        "schema_version": 1, "status": "completed", "directions": [{
            "direction_id": "cross-role-recheck",
            "rationale": "recheck the most suspicious authorization response",
            "evidence_refs": ["request.http", "response.http"],
        }],
    })

    result = validate_intuition_exploration(tmp_path)

    assert result["ok"] is True
    assert {"request.http", "response.http"}.issubset(result["artifact_hashes"])


def test_continuation_recomputes_agenda_and_rejects_tampering(tmp_path):
    prior = _prior_run(tmp_path)
    loaded = load_prior_continuation(
        prior, primary_target=SCOPE, authorized_scopes=[SCOPE])
    assert loaded["authority_trusted"] is False
    assert loaded["trust_level"] == "diagnostic_only"
    assert loaded["count"] == 1
    assert loaded["items"][0]["target_method"] == "POST"

    agenda_path = prior / "next-run-agenda.json"
    agenda = json.loads(agenda_path.read_text(encoding="utf-8"))
    agenda["items"][0]["target_endpoint"] = "https://outside.example/api"
    _write(agenda_path, agenda)
    with pytest.raises(ContinuationError, match="deterministic validation projection"):
        load_prior_continuation(
            prior, primary_target=SCOPE, authorized_scopes=[SCOPE])


def test_continuation_input_is_bound_into_new_manifest_before_adapter(tmp_path):
    continuation = load_prior_continuation(
        _prior_run(tmp_path), primary_target=SCOPE, authorized_scopes=[SCOPE])
    run = tmp_path / "project" / "sessions" / "new-run"

    class Adapter:
        name = "fixture"
        process_containment_verified = False

        def run(self, prompt, *, session_id):
            manifest = json.loads((run / "run_manifest.json").read_text(encoding="utf-8"))
            assert "continuation-input.json" in manifest["planning_artifacts"]
            assert (run / "continuation-input.json").is_file()
            yield "ERROR\n"

    run_session(
        Adapter(), target=SCOPE, authz="authorized fixture", core_skill="fixture",
        workdir=str(run), authorized_hosts=[SCOPE], max_turns=1, verbose=False,
        endpoints=[{"method": "POST", "endpoint": "/api/search", "params": ["q"],
                    "roles": ["user"], "vuln_class": "SQLi"}],
        vuln_classes=["SQLi"], continuation_input=continuation,
    )


def test_cross_stage_input_negative_is_reopened_and_requires_new_families(tmp_path):
    project = tmp_path / "project"
    evidence = project / "sessions" / "old-run" / "evidence.json"
    _write(evidence, {"proof": True})
    ref = "session:old-run/evidence.json"
    key = canonical_project_cell_key(
        SCOPE, method="POST", path="/api/search", param="q",
        role_scope="user", vuln_class="SQLi")
    project_state = {
        "cell_registry": {key: {
            "status": "not_vulnerable", "source_run": "old-run",
            "evidence_refs": [ref],
            "evidence_hashes": {ref: hashlib.sha256(evidence.read_bytes()).hexdigest()},
            "negative_vectors": ["boolean raw"],
            "negative_encoding_families": ["raw"],
            "negative_strategy_families": ["boolean"],
        }},
    }
    state = CognitiveState(sid="new-run", target=SCOPE, vuln_classes=["SQLi"])
    state.seed_matrix([{
        "asset": SCOPE, "method": "POST", "endpoint": "/api/search",
        "params": ["q"], "roles": ["user"], "risk_tags": ["input-validation"],
    }])

    restored = _apply_project_cells(
        state, project_state, SCOPE, str(project / "project_state.json"))
    cell = next(iter(state.matrix.values()))

    assert restored == 0
    assert cell["state"] == SHALLOW_NEGATIVE
    assert cell["cross_stage_prior_negative"]["negative_encoding_families"] == ["raw"]
    same_ok, same_reasons = has_cross_stage_diversity({
        "encoding_families": ["raw"], "strategy_families": ["boolean"],
    }, cell["cross_stage_prior_negative"])
    new_ok, _ = has_cross_stage_diversity({
        "encoding_families": ["url"], "strategy_families": ["time"],
    }, cell["cross_stage_prior_negative"])
    assert same_ok is False
    assert "cross_stage_negative_encoding_not_new" in same_reasons
    assert new_ok is True


def test_all_accepted_proof_files_are_hash_bound_against_substitution(tmp_path):
    run = tmp_path / "project" / "sessions" / "proof-run"
    report = _complete_finding_run(run)
    assert report["exit_code"] == 0
    proof = run / "findings" / "finding_001" / "response_attacker.http"
    proof.write_text(proof.read_text(encoding="utf-8") + "\nmutated", encoding="utf-8")

    verification = verify_validation_artifact(report, run)

    assert verification["ok"] is False
    assert any(item.get("path", "").endswith("response_attacker.http")
               for item in verification["mismatches"])


def test_redacted_report_is_not_flagged_as_sensitive(tmp_path):
    run = tmp_path / "project" / "sessions" / "report-run"
    _complete_finding_run(run, canonical_report_required=True)
    finalize_run(
        run_dir=run, project_dir=run.parent.parent,
        authority_dir=run.parent.parent / ".atoolkit",
        authority_trusted=True, authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture", primary_target=SCOPE,
    )
    report_text = (run / "final_report.md").read_text(encoding="utf-8")
    assert "<redacted:" in report_text
    assert data_hygiene.sensitive_kinds(report_text) == []
