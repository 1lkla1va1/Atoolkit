from __future__ import annotations

import json
import pathlib

import pytest

from engine.reporting.validate import validate_run_artifacts
from engine.run_audit import audit_run
from engine.skill_runtime import (
    SkillRuntimeError,
    checkpoint_direct_run,
    initialize_direct_run,
    preflight_direct_run,
)
from engine.surface import bootstrap


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def test_direct_cli_preflight_rejects_stale_workspace_agents_before_write(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "AGENTS.md").write_text("stale v8.9\n", encoding="utf-8")
    run = workspace / "runs" / "run-1"

    with pytest.raises(SkillRuntimeError, match="workspace AGENTS.md"):
        preflight_direct_run(
            run_dir=run,
            target="https://t.example/",
            workspace_root=workspace,
            require_instruction_match=True,
        )

    assert not run.exists()


def test_direct_preflight_records_exact_workspace_instruction_binding(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "AGENTS.md").write_bytes((PROJECT_ROOT / "AGENTS.md").read_bytes())

    result = preflight_direct_run(
        run_dir=workspace / "runs" / "run-1",
        target="https://t.example/",
        workspace_root=workspace,
        require_instruction_match=True,
    )

    assert result["schema_version"] == 2
    assert result["instruction_binding"]["status"] == "ok"
    assert result["instruction_binding"]["matches_project"] is True


def test_external_validation_output_does_not_mutate_historical_run(tmp_path):
    run = tmp_path / "historical"
    run.mkdir()
    output = tmp_path / "audit-output" / "validation.json"

    validate_run_artifacts(
        run, allow_empty=True, output_path=output, write_output=True)

    assert output.is_file()
    assert not (run / "miss-attribution.json").exists()
    assert not (run / "next-run-agenda.json").exists()


def test_audit_rejects_vacuum_inventory_and_coverage_even_with_consistent_projection(tmp_path):
    run = tmp_path / "vacuum-run"
    run.mkdir()
    _write_json(run / "inventory.json", {"schema_version": 1, "surfaces": []})
    _write_json(run / "coverage-ledger.json", {"schema_version": 1, "surfaces": []})
    projection = validate_run_artifacts(run, allow_empty=True, write_output=False)
    _write_json(run / "miss-attribution.json", projection["miss_attribution"])
    _write_json(run / "next-run-agenda.json", projection["next_run_agenda"])

    result = audit_run(run)

    assert result["inventory_nonempty"] is False
    assert result["coverage_nonempty"] is False
    assert result["standards"]["no_silent_omission"] is False
    assert result["standards"]["exact_miss_attribution"] is False
    codes = {item["code"] for item in result["issues"]}
    assert {"empty_inventory", "empty_coverage"} <= codes


def test_audit_detects_manual_terminal_claim_in_report_without_summary(tmp_path):
    run = tmp_path / "manual-run"
    run.mkdir()
    (run / "final_report.md").write_text(
        "# 人工报告\n\n全部测试完成，已实现全域覆盖。\n\nVULN_FOUND\n",
        encoding="utf-8",
    )

    result = audit_run(run)

    assert result["manual_complete_claim"] is True
    assert "manual_complete_claim_without_verified_delivery" in {
        item["code"] for item in result["issues"]
    }


def test_audit_scans_whole_run_for_world_readable_credential_material(tmp_path):
    run = tmp_path / "credential-run"
    evidence = run / "evidence"
    evidence.mkdir(parents=True)
    authz = run / "authz.md"
    cookie_jar = evidence / "browser-cookies.txt"
    restricted = run / "identities.json"
    authz.write_text("authorized test account", encoding="utf-8")
    cookie_jar.write_text("Cookie: sid=world-readable-value\n", encoding="utf-8")
    restricted.write_text("Cookie: sid=restricted-value\n", encoding="utf-8")
    authz.chmod(0o644)
    cookie_jar.chmod(0o644)
    restricted.chmod(0o600)

    result = audit_run(run)
    issue = next(item for item in result["issues"]
                 if item["code"] == "credential_material_outside_restricted_identity_store")
    paths = {item["path"] for item in issue["files"]}

    assert "authz.md" in paths
    assert "evidence/browser-cookies.txt" in paths
    assert "identities.json" not in paths


def test_direct_checkpoint_exposes_proof_repair_and_reserved_artifacts(tmp_path):
    run = tmp_path / "direct-run"
    inventory = tmp_path / "inventory.json"
    _write_json(inventory, {"surfaces": [{
        "endpoint": "/api/search", "method": "GET", "params": ["q"],
    }]})
    initialize_direct_run(
        run_dir=run, target="https://t.example/", inventory_path=inventory)
    _write_json(run / "findings" / "finding_bad-proof.json", {"id": "bad-proof"})
    (run / "final_report.md").write_text("manual final\n", encoding="utf-8")

    checkpoint = checkpoint_direct_run(run)

    validation = checkpoint["finding_validation"]
    assert validation["proof_repair_required"] == 1
    assert validation["rejected_items"][0]["id"] == "bad-proof"
    assert "legacy or unsupported" in validation["rejected_items"][0]["reasons"][0]
    assert checkpoint["reserved_artifact_violations"] == ["final_report.md"]
    assert checkpoint["report_ready"] is False


def test_generic_recon_parser_recovers_shop_style_endpoints_and_body_params(tmp_path):
    recon = tmp_path / "recon"
    recon.mkdir()
    (recon / "dashboard.html").write_text(
        """<script>
        fetch('/api/user/balance-records.php?user_hash=' + userHash);
        fetch('/api/user/create-order.php', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({product_no, quantity, order_time, use_points})
        });
        </script>""",
        encoding="utf-8",
    )

    rows = bootstrap(recon)
    by_target = {(row["method"], row["endpoint"]): row for row in rows}

    balance = by_target[("GET", "/api/user/balance-records.php")]
    order = by_target[("POST", "/api/user/create-order.php")]
    assert "user_hash" in balance["params"]
    assert {"product_no", "quantity", "order_time", "use_points"} <= set(order["params"])
