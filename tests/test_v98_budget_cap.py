"""v9.8 W0：预算匹配的分母冻结回归测试。

设计文档：design/迭代方案/v9.8_难度感知执行与身份供给管线.md §W0 + §6 R7。
- init --max-frozen-cells（默认 20）：top-N 高优先级格冻结进
  coverage-ledger，其余进 deferred-pool.json（不进分母、不参与闭合）。
- 终态时 deferred 格逐一归因 execution_not_started 并进入
  next-run-agenda，可被下轮 init --continue-from-run 消费（W1 链路）。
- 防作弊闸：deferred 含高价值格且冻结格执行率 < 80% 时 closure gate
  拒绝 complete（budget_cap_execution_below_floor）。
- 确定性：同一 inventory 两次 init，冻结集与 deferred-pool 逐字节一致。
"""
from __future__ import annotations

import json
import pathlib

from engine.skill_runtime import (
    checkpoint_direct_run,
    initialize_direct_run,
    record_observation,
)

TARGET = "https://t.example/"
_ENDPOINT_COUNT = 25  # > 默认 20 格预算


def _write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _inventory(tmp_path: pathlib.Path, name: str = "inventory.json") -> pathlib.Path:
    # 全部端点命中 "order" → 每个格都是高价值格（is_high_value）。
    path = tmp_path / name
    _write_json(path, {"surfaces": [
        {"endpoint": f"/api/order{index}", "method": "GET", "params": ["id"],
         "roles": ["user"]}
        for index in range(1, _ENDPOINT_COUNT + 1)
    ]})
    return path


def _init(tmp_path: pathlib.Path, name: str, **kwargs) -> pathlib.Path:
    run = tmp_path / name
    initialize_direct_run(
        run_dir=run, target=TARGET,
        inventory_path=_inventory(tmp_path), **kwargs)
    return run


def _load(run: pathlib.Path, name: str) -> dict:
    return json.loads((run / name).read_text(encoding="utf-8"))


def _frozen_ids(run: pathlib.Path) -> list[str]:
    return [surface["surface_id"]
            for surface in _load(run, "coverage-ledger.json")["surfaces"]]


def test_budget_cap_splits_frozen_and_deferred(tmp_path):
    run = _init(tmp_path, "run-split", max_frozen_cells=20)

    frozen = _frozen_ids(run)
    assert len(frozen) == 20
    pool = _load(run, "deferred-pool.json")
    assert pool["deferred_reason"] == "budget_cap"
    assert pool["max_frozen_cells"] == 20
    assert pool["frozen_cells"] == 20
    # seed_matrix 会按 vuln_class 等维度展开，总格数 > 端点数；不写死总数
    assert pool["deferred_cells"] == len(pool["surfaces"]) > 0
    # 完整 surface 身份 + 优先级 + deferred_reason
    for entry in pool["surfaces"]:
        assert entry["deferred_reason"] == "budget_cap"
        assert entry["priority_rank"] > 20
        for field in ("surface_id", "endpoint", "method", "param", "roles",
                      "risk_tags"):
            assert field in entry, field
    # 冻结 ∪ 延后 = 全量，无交集
    deferred_ids = {entry["surface_id"] for entry in pool["surfaces"]}
    assert not deferred_ids & set(frozen)
    assert len(deferred_ids) == pool["deferred_cells"]
    # deferred 格不在执行队列/合同中（本轮不可执行）
    contracts = _load(run, "execution-contracts.json")["contracts"]
    assert len(contracts) == 20


def test_budget_cap_is_byte_deterministic(tmp_path):
    inventory = _inventory(tmp_path)
    run_a = tmp_path / "a" / "run"
    run_b = tmp_path / "b" / "run"
    initialize_direct_run(
        run_dir=run_a, target=TARGET, inventory_path=inventory,
        max_frozen_cells=20)
    initialize_direct_run(
        run_dir=run_b, target=TARGET, inventory_path=inventory,
        max_frozen_cells=20)

    assert (run_a / "deferred-pool.json").read_bytes() == (
        run_b / "deferred-pool.json").read_bytes()
    assert _frozen_ids(run_a) == _frozen_ids(run_b)


def test_no_cap_when_within_budget(tmp_path):
    small = tmp_path / "small-inventory.json"
    _write_json(small, {"surfaces": [
        {"endpoint": "/api/orders", "method": "GET", "params": ["id"],
         "roles": ["user"]},
    ]})
    run = tmp_path / "run-small"
    initialize_direct_run(run_dir=run, target=TARGET, inventory_path=small)

    assert not (run / "deferred-pool.json").exists()
    assert 0 < len(_frozen_ids(run)) <= 20


def test_deferred_cells_attributed_and_agenda_consumable(tmp_path):
    run = _init(tmp_path / "a", "run-cap", max_frozen_cells=20)
    checkpoint = checkpoint_direct_run(run)

    assert checkpoint["attribution_error"] == ""
    attribution = _load(run, "miss-attribution.json")
    pool = _load(run, "deferred-pool.json")
    deferred_ids = {entry["surface_id"] for entry in pool["surfaces"]}
    cell_rows = [row for row in attribution["rows"] if row["kind"] == "cell"]
    # 每个 deferred 格恰好一个归因行，cause=execution_not_started
    deferred_rows = [row for row in cell_rows
                     if row["surface_id"] in deferred_ids]
    assert len(deferred_rows) == len(deferred_ids)
    assert {row["cause_code"] for row in deferred_rows} == {
        "execution_not_started"}
    # closure gate 不把 deferred 格计为未闭合：20 个冻结格各一条，不多不少
    validation = _load(run, "finding_validation.json")
    reasons = validation["closure_gate"]["reasons"]
    assert reasons.count("coverage_not_closed") == 20
    # 防作弊闸：deferred 含高价值格且执行率 0/20 < 80%
    assert "budget_cap_execution_below_floor" in reasons
    budget = validation["closure_gate"]["budget_cap"]
    assert budget["deferred_high_value"] is True
    assert budget["frozen_execution_rate"] == 0.0
    # deferred 高价值格进入 agenda（execution_not_started → medium）
    agenda = _load(run, "next-run-agenda.json")
    deferred_endpoints = {entry["endpoint"] for entry in pool["surfaces"]}
    agenda_endpoints = {item["target_endpoint"] for item in agenda["items"]}
    assert deferred_endpoints <= agenda_endpoints

    # W1 链路：下一轮 init --continue-from-run 消费含 deferred 格的 agenda
    run_b = tmp_path / "b" / "run-next"
    result = initialize_direct_run(
        run_dir=run_b, target=TARGET, continue_from_run=run)
    assert result["continuation"]["items"] == agenda["count"]
    bound = _load(run_b, "continuation-input.json")
    bound_endpoints = {item["target_endpoint"] for item in bound["items"]}
    assert deferred_endpoints <= bound_endpoints


def test_anti_gaming_gate_passes_when_frozen_cells_executed(tmp_path):
    run = _init(tmp_path, "run-worked", max_frozen_cells=20)
    # 全部 20 个冻结格都产生过 execution event（barrier 事件也算执行）
    for index, surface_id in enumerate(_frozen_ids(run)):
        record_observation(run_dir=run, agent_id="tester", observation={
            "schema_version": 1,
            "observation_id": f"obs-waf-{index:02d}",
            "surface_id": surface_id,
            "outcome": "blocked",
            "barrier_signals": ["waf_blocked"],
        })
    checkpoint = checkpoint_direct_run(run)

    assert checkpoint["attribution_error"] == ""
    validation = _load(run, "finding_validation.json")
    reasons = validation["closure_gate"]["reasons"]
    assert "budget_cap_execution_below_floor" not in reasons
    budget = validation["closure_gate"]["budget_cap"]
    assert budget["frozen_cells"] == 20
    assert budget["frozen_executed"] == 20
    assert budget["frozen_execution_rate"] == 1.0
