from __future__ import annotations

import json
import os
import pathlib

import pytest

import run
from engine.business_graph import BusinessGraph
from engine.candidate import CandidateLedger
from engine.graph import FactIntentGraph
from engine.ledger import CoverageLedger
from engine.orchestrator import CognitiveState, _log_event, _write_session_inventory
from engine.safe_io import UnsafePathError
from engine.scheduler import save_run_scope


_CASES = [
    ("cognitive", "state.json"),
    ("candidate", "candidate-ledger.json"),
    ("coverage", "coverage-ledger.json"),
    ("fact_intent", "fact_intent_graph.json"),
    ("business", "business_graph.json"),
    ("run_scope", "run_scope.json"),
    ("session_inventory", "inventory.json"),
    ("run_inventory", "inventory.json"),
]


def _write_case(kind: str, destination: pathlib.Path) -> dict:
    if kind == "cognitive":
        state = CognitiveState(sid="safe-state", target="https://target.example")
        state.save(destination)
        return json.loads(destination.read_text(encoding="utf-8"))
    if kind == "candidate":
        CandidateLedger(metadata={"sid": "safe-state"}).save(destination)
        return json.loads(destination.read_text(encoding="utf-8"))
    if kind == "coverage":
        CoverageLedger(metadata={"sid": "safe-state"}).save(destination)
        return json.loads(destination.read_text(encoding="utf-8"))
    if kind == "fact_intent":
        graph = FactIntentGraph()
        graph.add_fact({"source_type": "anomaly", "summary": "中文状态"})
        graph.save(destination)
        return json.loads(destination.read_text(encoding="utf-8"))
    if kind == "business":
        graph = BusinessGraph()
        graph.build_from_inventory(["GET /api/orders"])
        graph.export_to_file(destination)
        return json.loads(destination.read_text(encoding="utf-8"))
    if kind == "run_scope":
        save_run_scope(destination.parent, {"target_domains": ["auth"]})
        return json.loads(destination.read_text(encoding="utf-8"))
    if kind == "session_inventory":
        _write_session_inventory(
            destination,
            [{"endpoint": "/api/orders", "method": "GET"}],
            [{"endpoint": "/api/unknown", "method": ""}],
        )
        return json.loads(destination.read_text(encoding="utf-8"))
    if kind == "run_inventory":
        value = {"endpoints": [], "unresolved": [], "saturation_reached": False}
        run._write_runtime_inventory(destination, value, root=destination.parent)
        return json.loads(destination.read_text(encoding="utf-8"))
    raise AssertionError(f"unknown case: {kind}")


@pytest.mark.parametrize(("kind", "filename"), _CASES)
def test_parent_state_writers_preserve_json_and_reject_leaf_symlink(
    kind: str,
    filename: str,
    tmp_path: pathlib.Path,
) -> None:
    normal = tmp_path / "normal" / filename
    normal.parent.mkdir()
    value = _write_case(kind, normal)
    assert isinstance(value, dict)
    assert normal.read_text(encoding="utf-8").startswith("{")

    outside = tmp_path / f"outside-{kind}.json"
    outside.write_text("sentinel", encoding="utf-8")
    linked = tmp_path / f"linked-{kind}" / filename
    linked.parent.mkdir()
    linked.symlink_to(outside)

    with pytest.raises(UnsafePathError, match="symbolic link"):
        _write_case(kind, linked)
    assert outside.read_text(encoding="utf-8") == "sentinel"
    assert linked.is_symlink()


@pytest.mark.parametrize(("kind", "filename"), _CASES)
def test_parent_state_writers_reject_symlinked_parent(
    kind: str,
    filename: str,
    tmp_path: pathlib.Path,
) -> None:
    outside = tmp_path / f"outside-parent-{kind}"
    outside.mkdir()
    linked_parent = tmp_path / f"linked-parent-{kind}"
    linked_parent.symlink_to(outside, target_is_directory=True)

    with pytest.raises(UnsafePathError):
        _write_case(kind, linked_parent / filename)
    assert not (outside / filename).exists()


@pytest.mark.parametrize(("kind", "filename"), _CASES)
def test_parent_state_writers_reject_multiply_linked_leaf(
    kind: str,
    filename: str,
    tmp_path: pathlib.Path,
) -> None:
    outside = tmp_path / f"outside-hardlink-{kind}.json"
    outside.write_text("sentinel", encoding="utf-8")
    linked = tmp_path / f"hardlinked-{kind}" / filename
    linked.parent.mkdir()
    os.link(outside, linked)

    with pytest.raises(UnsafePathError, match="multiple hard links"):
        _write_case(kind, linked)

    assert outside.read_text(encoding="utf-8") == "sentinel"
    assert linked.read_text(encoding="utf-8") == "sentinel"


def test_event_append_does_not_follow_leaf_or_parent_symlink(
    tmp_path: pathlib.Path,
) -> None:
    outside_file = tmp_path / "outside-events.jsonl"
    outside_file.write_text("sentinel\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "events.jsonl").symlink_to(outside_file)

    _log_event(run_dir, {"event": "must-not-escape"})
    assert outside_file.read_text(encoding="utf-8") == "sentinel\n"

    outside_dir = tmp_path / "outside-run"
    outside_dir.mkdir()
    linked_run = tmp_path / "linked-run"
    linked_run.symlink_to(outside_dir, target_is_directory=True)
    _log_event(linked_run, {"event": "must-not-escape-parent"})
    assert not (outside_dir / "events.jsonl").exists()


def test_parent_state_json_keeps_legacy_indentation_and_unicode(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "candidate-ledger.json"
    ledger = CandidateLedger(metadata={"label": "中文"})
    ledger.save(path)
    expected = json.dumps(ledger.to_dict(), ensure_ascii=False, indent=2)
    assert path.read_text(encoding="utf-8") == expected
