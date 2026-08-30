"""v9.8 W1：Direct 模式归因/续航接线回归测试。

设计文档：design/迭代方案/v9.8_难度感知执行与身份供给管线.md §W1 + §6 R5/R6。
- W1.1：checkpoint 尾部复用 validate_run_artifacts 产出归因三件套
  （finding_validation.json + miss-attribution.json + next-run-agenda.json），
  exit_code≠0（precondition_missing/empty_input）不视为 checkpoint 失败。
- W1.2：init --continue-from-run 消费上一 Run 的确定性 agenda，
  只恢复调度（diagnostic-only），不改 ProjectState；
  陈旧哈希时 ContinuationError 必须带自愈指引（R6 逃生门）。
"""
from __future__ import annotations

import json
import pathlib

import pytest

from engine.continuation import ContinuationError
from engine.skill_runtime import (
    checkpoint_direct_run,
    initialize_direct_run,
    record_observation,
)

TARGET = "https://t.example/"
_PRIORITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _init_run_a(tmp_path: pathlib.Path) -> pathlib.Path:
    """ blocked(missing_role) + shallow_negative(waf) + not_tested 的混合 run。"""
    run = tmp_path / "run-a"
    inventory = tmp_path / "inventory-a.json"
    _write_json(inventory, {"surfaces": [
        {"endpoint": "/api/orders", "method": "GET", "params": ["id"],
         "roles": ["user"]},
        {"endpoint": "/api/search", "method": "POST", "params": ["keyword"],
         "roles": ["user"]},
        {"endpoint": "/api/profile", "method": "GET", "params": ["uid"],
         "roles": ["user"]},
    ]})
    initialize_direct_run(run_dir=run, target=TARGET, inventory_path=inventory)
    return run


def _surface_id(run: pathlib.Path, endpoint: str, method: str) -> str:
    ledger = json.loads((run / "coverage-ledger.json").read_text(encoding="utf-8"))
    for surface in ledger["surfaces"]:
        if surface["endpoint"] == endpoint and surface["method"] == method:
            return surface["surface_id"]
    raise AssertionError(f"surface not found: {method} {endpoint}")


def _checkpointed_run_a(tmp_path: pathlib.Path) -> tuple[pathlib.Path, dict]:
    run = _init_run_a(tmp_path)
    record_observation(run_dir=run, agent_id="tester", observation={
        "schema_version": 1,
        "observation_id": "obs-blocked",
        "surface_id": _surface_id(run, "/api/orders", "GET"),
        "outcome": "blocked",
        "barrier_signals": ["missing_role"],
    })
    record_observation(run_dir=run, agent_id="tester", observation={
        "schema_version": 1,
        "observation_id": "obs-waf",
        "surface_id": _surface_id(run, "/api/search", "POST"),
        "outcome": "negative",
        "negative": {"barrier_signals": ["waf_blocked"], "response_count": 1},
    })
    checkpoint = checkpoint_direct_run(run)
    return run, checkpoint


def test_checkpoint_emits_attribution_triplet_without_manifest(tmp_path):
    """无 manifest 的 Direct run：precondition_missing 也照落三件套（§6.1）。"""
    run, checkpoint = _checkpointed_run_a(tmp_path)

    assert not (run / "run_manifest.json").exists()
    for name in ("finding_validation.json", "miss-attribution.json",
                 "next-run-agenda.json"):
        assert (run / name).is_file(), name

    assert checkpoint["attribution_error"] == ""
    summary = checkpoint["attribution_summary"]
    assert summary["status"] == "precondition_missing"
    assert summary["exit_code"] == 2
    # v9.8 W2.4 补 W1 缝隙：init 时所有格均无身份可用（identity_blocked），
    # 无 manifest 的 Direct 归因现在能把它们归为 identity_missing，
    # 不再落入笼统的 prerequisite_blocked/insufficient_depth。
    ledger = json.loads((run / "coverage-ledger.json").read_text(encoding="utf-8"))
    assert summary["cause_counts"].get("identity_missing") == len(
        ledger["surfaces"])
    assert summary["cause_counts"].get("prerequisite_blocked") is None
    assert summary["cause_counts"].get("insufficient_depth") is None
    assert summary["identity_missing"] == len(ledger["surfaces"])
    assert summary["agenda_items"] == len(ledger["surfaces"])

    validation = json.loads(
        (run / "finding_validation.json").read_text(encoding="utf-8"))
    assert validation["miss_attribution"] == json.loads(
        (run / "miss-attribution.json").read_text(encoding="utf-8"))
    assert validation["next_run_agenda"] == json.loads(
        (run / "next-run-agenda.json").read_text(encoding="utf-8"))


def test_continue_from_run_round_trip_consumes_agenda_in_order(tmp_path):
    """run A checkpoint → run B init --continue-from-run：agenda 按优先级入队。"""
    run_a, _ = _checkpointed_run_a(tmp_path)
    agenda = json.loads(
        (run_a / "next-run-agenda.json").read_text(encoding="utf-8"))

    run_b = tmp_path / "run-b"
    result = initialize_direct_run(
        run_dir=run_b, target=TARGET, continue_from_run=run_a)

    assert result["continuation"]["source_run"] == "run-a"
    assert result["continuation"]["items"] == len(agenda["items"])
    assert result["authority_trusted"] is False
    assert result["delivery_eligible"] is False

    bound = json.loads(
        (run_b / "continuation-input.json").read_text(encoding="utf-8"))
    assert bound["diagnostic_only"] is True
    assert bound["trust_level"] == "diagnostic_only"
    assert bound["run_dir"] == str(run_b.resolve())
    ranks = [_PRIORITY_RANK[item["priority"]] for item in bound["items"]]
    assert ranks == sorted(ranks)
    assert bound["items"][0]["priority"] == "high"
    # W2.4：三格均 identity_blocked → 归因 identity_missing（high）。
    assert bound["items"][0]["cause_code"] == "identity_missing"
    assert bound["items"][-1]["cause_code"] == "identity_missing"

    ledger = json.loads(
        (run_b / "coverage-ledger.json").read_text(encoding="utf-8"))
    endpoints = {(s["method"], s["endpoint"]) for s in ledger["surfaces"]}
    assert {("GET", "/api/orders"), ("POST", "/api/search"),
            ("GET", "/api/profile")} <= endpoints


def test_continue_from_run_rejects_stale_hashes_with_self_heal_hint(tmp_path):
    """陈旧哈希陷阱（§6.1 P0）：篡改后报错含自愈指引，重跑 checkpoint 可自愈。"""
    run_a, _ = _checkpointed_run_a(tmp_path)
    ledger_path = run_a / "coverage-ledger.json"
    ledger_path.write_text(
        ledger_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises(ContinuationError,
                       match="checkpoint --run-dir .* 刷新三件套后重试"):
        initialize_direct_run(
            run_dir=tmp_path / "run-c", target=TARGET,
            continue_from_run=run_a)

    # 自愈路径：对 prior run 重跑 checkpoint 刷新三件套后，续跑恢复。
    checkpoint_direct_run(run_a)
    healed = initialize_direct_run(
        run_dir=tmp_path / "run-c", target=TARGET, continue_from_run=run_a)
    agenda = json.loads(
        (run_a / "next-run-agenda.json").read_text(encoding="utf-8"))
    assert healed["continuation"]["items"] == agenda["count"] > 0
