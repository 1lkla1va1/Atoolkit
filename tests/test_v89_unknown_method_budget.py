from __future__ import annotations

import json

from engine.orchestrator import run_session
from engine.project_state import ProjectStateStore
from engine.run_authority import run_plan_path
from engine.reporting.validate import (
    ValidationContext,
    _authority_method_resolution_gate,
)


class _ResponseAdapter:
    name = "unknown-method-budget-fixture"

    def __init__(self, workdir, response: str):
        self.workdir = workdir
        self.response = response
        self.calls = 0

    def run(self, prompt, *, session_id):
        self.calls += 1
        assert (self.workdir / "run_manifest.json").is_file()
        yield self.response


def _run(project, sid: str, adapter: _ResponseAdapter, **kwargs):
    workdir = project / "sessions" / sid
    workdir.mkdir(parents=True, exist_ok=True)
    return run_session(
        adapter,
        target="https://t.example/",
        authz="authorized fixture",
        core_skill="fixture core skill",
        workdir=str(workdir),
        authorized_hosts=["https://t.example/"],
        max_turns=1,
        verbose=False,
        **kwargs,
    )


def _method_gate_reasons(workdir):
    manifest_path = workdir / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    context = ValidationContext.from_manifest(
        manifest, manifest_path=manifest_path)
    inventory = json.loads(
        (workdir / "inventory.json").read_text(encoding="utf-8"))
    return _authority_method_resolution_gate(
        context,
        inventory.get("endpoints") or [],
        inventory.get("unresolved") or [],
    )


def test_empty_matrix_budget_resolves_only_frozen_unknown_method_item(tmp_path):
    project = tmp_path / "target"
    store = ProjectStateStore(
        project, project_scope=["https://t.example/"])
    store.commit_run("seed", inventory=[
        {
            "asset": "https://t.example/",
            "endpoint": "/api/refund-primary",
            "source": "fixture",
        },
        {
            "asset": "https://t.example/",
            "endpoint": "/api/refund-backlog",
            "source": "fixture",
        },
    ])
    workdir = project / "sessions" / "run-budget"
    adapter = _ResponseAdapter(
        workdir,
        "POST /api/refund-primary HTTP/1.1\n"
        "GET /api/refund-backlog HTTP/1.1\n"
        "LOW_ROI\n",
    )

    out = _run(
        project,
        "run-budget",
        adapter,
        endpoints=None,
        vuln_classes=["amount-tamper"],
        surface_budget=1,
    )

    plan = json.loads(run_plan_path(
        project / ".atoolkit", "run-budget").read_text(encoding="utf-8"))
    assert plan["admitted_cells"] == []
    assert len(plan["method_resolution_items"]) == 1
    admitted_endpoint = plan["method_resolution_items"][0]["endpoint"]
    backlog_endpoint = (
        {"/api/refund-primary", "/api/refund-backlog"} - {admitted_endpoint}
    ).pop()

    inventory = json.loads(
        (workdir / "inventory.json").read_text(encoding="utf-8"))
    assert {
        (item["endpoint"], item["method"])
        for item in inventory["endpoints"]
    } == {(admitted_endpoint, "POST" if admitted_endpoint.endswith("primary") else "GET")}
    assert [item["endpoint"] for item in inventory["unresolved"]] == [
        backlog_endpoint]
    assert inventory["unresolved"][0]["method"] == ""
    assert inventory["unresolved"][0]["in_run_scope"] is False
    expected_backlog_method = (
        "POST" if backlog_endpoint.endswith("primary") else "GET")
    assert inventory["unresolved"][0]["method_candidates"] == [
        expected_backlog_method]

    matrix = out["state"]["matrix"]
    assert matrix
    assert {cell["endpoint"] for cell in matrix.values()} == {
        admitted_endpoint}
    assert out["state"]["_budget_active"] is True
    assert len(out["state"]["allowed_cells"]) == 1
    assert set(out["state"]["allowed_cells"]).issubset(matrix)

    amendments_path = (
        project / ".atoolkit" / "events" / "run-budget" /
        "scope_amendment.jsonl")
    amendments = [
        json.loads(line)["event"]
        for line in amendments_path.read_text(encoding="utf-8").splitlines()
    ]
    assert len(amendments) == 1
    assert {item["endpoint"] for item in amendments} == {admitted_endpoint}
    assert _method_gate_reasons(workdir) == []

    # The out-of-budget item remains durable project backlog even though the
    # model happened to mention a concrete method during this run.
    project_backlog = store.load()["inventory"]["unresolved"]
    assert any(item["path"] == backlog_endpoint
               for item in project_backlog.values())


def test_bounded_empty_run_does_not_admit_unplanned_dynamic_endpoint(tmp_path):
    project = tmp_path / "target"
    workdir = project / "sessions" / "run-unplanned"
    adapter = _ResponseAdapter(
        workdir,
        "POST /api/refund-surprise HTTP/1.1\nLOW_ROI\n",
    )

    out = _run(
        project,
        "run-unplanned",
        adapter,
        endpoints=None,
        vuln_classes=["amount-tamper"],
        surface_budget=1,
    )

    plan = json.loads(run_plan_path(
        project / ".atoolkit", "run-unplanned").read_text(encoding="utf-8"))
    assert plan["admitted_cells"] == []
    assert plan["method_resolution_items"] == []
    assert out["state"]["matrix"] == {}
    assert out["state"]["_budget_active"] is True
    assert out["state"]["allowed_cells"] == []

    inventory = json.loads(
        (workdir / "inventory.json").read_text(encoding="utf-8"))
    assert inventory["endpoints"] == []
    assert len(inventory["unresolved"]) == 1
    backlog = inventory["unresolved"][0]
    assert backlog["endpoint"] == "/api/refund-surprise"
    assert backlog["method"] == ""
    assert backlog["method_candidates"] == ["POST"]
    assert backlog["source"] == "discovered_in_testing"
    assert backlog["in_run_scope"] is False
    assert backlog["discovered_during_testing"] is True
    assert backlog["last_seen"]
    assert not (
        project / ".atoolkit" / "events" / "run-unplanned" /
        "scope_amendment.jsonl").exists()
    assert _method_gate_reasons(workdir) == []


def test_explicit_empty_method_is_frozen_unknown_not_implicit_get(tmp_path):
    project = tmp_path / "target"
    workdir = project / "sessions" / "run-explicit-unknown"
    adapter = _ResponseAdapter(
        workdir,
        "POST /api/refund-explicit HTTP/1.1\nLOW_ROI\n",
    )

    out = _run(
        project,
        "run-explicit-unknown",
        adapter,
        endpoints=[{
            "asset": "https://t.example/",
            "endpoint": "/api/refund-explicit",
            "method": "",
            "roles": ["buyer"],
            "source": "explicit-fixture",
        }],
        vuln_classes=["amount-tamper"],
        surface_budget=1,
    )

    plan = json.loads(run_plan_path(
        project / ".atoolkit", "run-explicit-unknown").read_text(
            encoding="utf-8"))
    assert plan["admitted_cells"] == []
    assert len(plan["method_resolution_items"]) == 1
    assert plan["method_resolution_items"][0]["method"] == ""

    inventory = json.loads(
        (workdir / "inventory.json").read_text(encoding="utf-8"))
    assert [(row["endpoint"], row["method"])
            for row in inventory["endpoints"]] == [
                ("/api/refund-explicit", "POST")]
    assert inventory["unresolved"] == []
    assert {cell["method"] for cell in out["state"]["matrix"].values()} == {
        "POST"}
    assert "GET" not in {
        cell["method"] for cell in out["state"]["matrix"].values()}
    assert len(out["state"]["allowed_cells"]) == 1
    assert _method_gate_reasons(workdir) == []


def test_surface_budget_counts_exact_cells_not_endpoint_rows(tmp_path):
    project = tmp_path / "target"
    workdir = project / "sessions" / "run-exact-budget"
    adapter = _ResponseAdapter(workdir, "LOW_ROI\n")

    out = _run(
        project,
        "run-exact-budget",
        adapter,
        endpoints=[{
            "asset": "https://t.example/",
            "endpoint": "/api/refund",
            "method": "POST",
            "params": ["amount", "currency"],
            "roles": ["buyer", "merchant"],
            "risk_tags": ["amount-tamper"],
        }],
        vuln_classes=["amount-tamper"],
        surface_budget=1,
    )

    plan = json.loads(run_plan_path(
        project / ".atoolkit", "run-exact-budget").read_text(
            encoding="utf-8"))
    assert len(out["state"]["matrix"]) == 4
    assert len(out["state"]["allowed_cells"]) == 1
    assert len(plan["admitted_cells"]) == 1
    assert plan["budget"] == {
        "surface_budget": 1,
        "intent_budget": 0,
        "allowed_cell_count": 1,
    }
