from __future__ import annotations

import json

from engine.benchmark_eval import load_findings
from engine.runtime_manifest import canonical_json_sha256, write_run_receipt
from tests.test_v89_delivery_contract import _complete_finding_run, _write


def _receipted_run(tmp_path):
    project = tmp_path / "project"
    run_dir = project / "sessions" / "run-score"
    validation = _complete_finding_run(run_dir)
    summary = {
        "status": "complete",
        "findings": [],
        "finding_validation_path": str(run_dir / "finding_validation.json"),
        "finding_validation_sha256": validation["validation_sha256"],
        "run_receipt_path": str(run_dir / "run_receipt.json"),
    }
    _write(run_dir / "summary.json", summary)
    _write(project / "project_state.json", {"schema_version": 1, "revision": 1})
    write_run_receipt(
        run_dir / "run_receipt.json",
        manifest_path=run_dir / "run_manifest.json",
        artifacts={
            "summary": run_dir / "summary.json",
            "finding_validation": run_dir / "finding_validation.json",
            "inventory": run_dir / "inventory.json",
            "coverage_ledger": run_dir / "coverage-ledger.json",
            "candidate_ledger": run_dir / "candidate-ledger.json",
            "project_state": project / "project_state.json",
        },
        project_state_delta={"findings_added": 1},
        authority_trusted=True,
    )
    return run_dir


def test_benchmark_replays_canonical_validator_and_receipt(tmp_path):
    run_dir = _receipted_run(tmp_path)

    findings = load_findings(run_dir / "summary.json")

    assert [finding.id for finding in findings] == ["finding_001"]


def test_benchmark_rejects_rewritten_normalized_projection(tmp_path):
    run_dir = _receipted_run(tmp_path)
    validation_path = run_dir / "finding_validation.json"
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    validation["normalized_findings"][0]["endpoint"] = "/api/forged"
    validation["normalized_findings"][0]["vuln_class"] = "ssrf"
    validation.pop("validation_sha256", None)
    validation["validation_sha256"] = canonical_json_sha256(validation)
    _write(validation_path, validation)
    summary_path = run_dir / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["finding_validation_sha256"] = validation["validation_sha256"]
    _write(summary_path, summary)

    assert load_findings(summary_path) == []
