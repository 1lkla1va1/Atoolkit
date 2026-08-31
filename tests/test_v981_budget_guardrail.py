"""v9.8.1 R1：可达占比护栏回归测试。

设计文档：design/迭代方案/v9.8.1_可达性调度消费端与提交出口收口.md §1.2。
- 分母 = 冻结集（coverage-ledger 内 in_run_scope != False 且非 terminal 的
  开放格）；deferred-pool 条目不得并入（它们同样带 in_run_scope=True）。
- 可达 = 开放且 identity_blocked != True；非身份类 blocked 格不被消费。
- triggered = frozen_cells >= 5 且 reachable_ratio < 0.2；触发时
  recommendation=NEED_INPUT 并附未满足 requirement 的 human_action 去重聚合。
- 插入点在 observation 归并循环之后（MINOR-1）：同次 checkpoint 的确认
  立即反映到分母。护栏是 advisory：不改 status、不进 runtime-status.json。
"""
from __future__ import annotations

import copy
import json
import pathlib

from engine import skill_runtime
from engine.ledger import CoverageLedger
from engine.skill_runtime import (
    checkpoint_direct_run,
    initialize_direct_run,
    record_observation,
)
from tests.test_reporting_proof_contract import _idor_fixture

TARGET = "https://t.example/"


def _write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _inventory(tmp_path: pathlib.Path, rows: list[dict]) -> pathlib.Path:
    path = tmp_path / "inventory.json"
    _write_json(path, {"surfaces": rows})
    return path


def _user_rows(count: int, prefix: str = "/api/order-u") -> list[dict]:
    return [
        {"endpoint": f"{prefix}{index}", "method": "GET", "params": ["id"],
         "roles": ["user"]}
        for index in range(1, count + 1)
    ]


def _anon_rows(count: int, prefix: str = "/api/order-a") -> list[dict]:
    return [
        {"endpoint": f"{prefix}{index}", "method": "GET", "params": ["id"],
         "roles": ["anonymous"]}
        for index in range(1, count + 1)
    ]


def _load(run: pathlib.Path, name: str) -> dict:
    return json.loads((run / name).read_text(encoding="utf-8"))


def _open_frozen(run: pathlib.Path) -> list[dict]:
    terminal = {"confirmed", "not_vulnerable", "not_applicable"}
    return [
        surface for surface in _load(run, "coverage-ledger.json")["surfaces"]
        if surface.get("in_run_scope") is not False
        and str(surface.get("status") or "") not in terminal
    ]


def _guardrail_call(
    tmp_path: pathlib.Path,
    surfaces: list[dict],
    requirements: dict,
) -> tuple[pathlib.Path, CoverageLedger, dict]:
    """Directly invoke the guardrail on a hand-built ledger (no planner)."""
    run = tmp_path / "run"
    run.mkdir(parents=True)
    ledger = CoverageLedger(surfaces, metadata={"sid": "run", "target": TARGET})
    result = skill_runtime._budget_guardrail(run, ledger, requirements)
    return run, ledger, result


def _open_surface(index: int, *, blocked: bool = True) -> dict:
    surface = {
        "surface_id": f"s-{index:03d}",
        "endpoint": f"/api/order{index}", "method": "GET", "param": "id",
        "roles": ["user"], "status": "not_tested", "in_run_scope": True,
    }
    if blocked:
        surface["identity_blocked"] = True
    return surface


def test_guardrail_triggers_on_all_identity_blocked_frozen_set(tmp_path):
    # 6 个全带态高价值端点、0 身份 → 冻结集全部 identity_blocked
    run = tmp_path / "run"
    initialize_direct_run(
        run_dir=run, target=TARGET,
        inventory_path=_inventory(tmp_path, _user_rows(6)))

    checkpoint = checkpoint_direct_run(run)  # 护栏不得阻塞 checkpoint

    guardrail = checkpoint["budget_guardrail"]
    open_frozen = _open_frozen(run)
    assert len(open_frozen) >= 5
    assert all(s.get("identity_blocked") is True for s in open_frozen)
    assert guardrail["frozen_cells"] == len(open_frozen)
    assert guardrail["reachable_cells"] == 0
    assert guardrail["reachable_ratio"] == 0.0
    assert guardrail["floor"] == 0.2
    assert guardrail["min_frozen_for_eval"] == 5
    assert guardrail["triggered"] is True
    assert guardrail["recommendation"] == "NEED_INPUT"
    # human_actions 与 identity-requirements.json 的未满足项一致且非空
    requirements = _load(run, "identity-requirements.json")["requirements"]
    expected = list(dict.fromkeys(
        req["human_action"] for req in requirements if req["reason_code"]))
    assert guardrail["human_actions"] == expected != []
    # 三处输出之二：state/budget-guardrail.json 落盘且与返回值一致
    assert _load(run, "state/budget-guardrail.json") == guardrail
    # 护栏不进入 runtime-status.json 的任何字段
    assert "budget_guardrail" not in _load(run, "runtime-status.json")


def test_guardrail_silent_above_floor(tmp_path):
    # 匿名格占绝大多数（A0 豁免 → 可达），ratio >= floor → 护栏沉默
    run = tmp_path / "run"
    initialize_direct_run(
        run_dir=run, target=TARGET,
        inventory_path=_inventory(
            tmp_path, [*_anon_rows(8), *_user_rows(1)]))

    checkpoint = checkpoint_direct_run(run)

    guardrail = checkpoint["budget_guardrail"]
    open_frozen = _open_frozen(run)
    reachable = [s for s in open_frozen if s.get("identity_blocked") is not True]
    assert len(open_frozen) >= 5
    assert guardrail["frozen_cells"] == len(open_frozen)
    assert guardrail["reachable_cells"] == len(reachable)
    assert len(reachable) / len(open_frozen) >= 0.8
    assert guardrail["triggered"] is False
    assert guardrail["recommendation"] == "ok"


def test_guardrail_min_frozen_floor(tmp_path):
    # 冻结 3 格全 blocked：frozen < 5 下限生效，护栏保持沉默
    _run, _ledger, guardrail = _guardrail_call(
        tmp_path,
        [_open_surface(index) for index in range(3)],
        {"requirements": [{
            "requirement_id": "req-001", "mode": "peer_pair",
            "reason_code": "peer_role_pair_missing", "role": "user",
            "count_needed": 2, "count_present": 0,
            "blocks_cells": ["s-000", "s-001", "s-002"],
            "human_action": "提供第二个身份",
        }]},
    )

    assert guardrail["frozen_cells"] == 3
    assert guardrail["reachable_cells"] == 0
    assert guardrail["reachable_ratio"] == 0.0
    assert guardrail["triggered"] is False
    assert guardrail["recommendation"] == "ok"


def test_guardrail_ratio_reflects_same_checkpoint_confirmation(tmp_path):
    # MINOR-1：插入点在归并循环之后——本 checkpoint 刚确认的 blocked 格
    # 立即从分母剔除（若在身份重算处计算，分母仍是合并前的 open 总数）。
    # 4 行 × 默认 5 漏洞类 = 20 格，恰好在冻结预算内（无 deferred 干扰）。
    run = tmp_path / "run"
    rows = [
        {"endpoint": "/api/orders/{id}", "method": "GET", "params": ["id"],
         "roles": ["unknown"]},
        *_user_rows(2),
        *_anon_rows(1),
    ]
    initialize_direct_run(
        run_dir=run, target=TARGET,
        inventory_path=_inventory(tmp_path, rows))
    before = _open_frozen(run)
    open_before = len(before)
    reachable_before = sum(
        1 for s in before if s.get("identity_blocked") is not True)
    assert open_before >= 5 and reachable_before >= 1
    target_surface = next(
        s for s in before
        if s["endpoint"] == "/api/orders/{id}"
        and s.get("roles") == ["unknown"]
        and "idor" in str(s.get("vuln_class") or "").lower())
    assert target_surface.get("identity_blocked") is True

    finding_dir = _idor_fixture(run)
    record_observation(run_dir=run, agent_id="tester", observation={
        "schema_version": 1, "observation_id": "pos-1",
        "surface_id": target_surface["surface_id"], "outcome": "confirmed",
        "evidence_refs": [
            (finding_dir / "finding.json").relative_to(run).as_posix()],
    })
    checkpoint = checkpoint_direct_run(run)

    confirmed = _load(run, "coverage-ledger.json")["surfaces"]
    current = next(
        s for s in confirmed if s["surface_id"] == target_surface["surface_id"])
    assert current["status"] == "confirmed"
    guardrail = checkpoint["budget_guardrail"]
    # 确认结果同次反映：分母 = open_before - 1，而不是合并前的 open_before
    assert guardrail["frozen_cells"] == open_before - 1
    assert guardrail["reachable_cells"] == reachable_before
    assert guardrail["reachable_ratio"] == round(
        reachable_before / (open_before - 1), 4)


def test_guardrail_does_not_mutate_status_or_ledger(tmp_path):
    # 直接调用：护栏是纯读取，不得改写任何 surface 字段
    surfaces = [
        _open_surface(0), _open_surface(1),
        {**_open_surface(2, blocked=False)},
        {**_open_surface(3), "status": "confirmed"},   # terminal → 不计入
        {**_open_surface(4, blocked=False), "status": "blocked"},  # 非身份阻塞 → 可达
        {**_open_surface(5), "in_run_scope": False},    # 出域 → 不计入
    ]
    run = tmp_path / "run"
    run.mkdir(parents=True)
    ledger = CoverageLedger(
        surfaces, metadata={"sid": "run", "target": TARGET})
    snapshot = copy.deepcopy(ledger.surfaces)
    guardrail = skill_runtime._budget_guardrail(
        run, ledger, {"requirements": []})

    assert guardrail["frozen_cells"] == 4   # 开放且在域：s-000/001/002/004
    assert guardrail["reachable_cells"] == 2  # s-002 + 非身份 blocked 的 s-004
    assert guardrail["triggered"] is False
    assert ledger.surfaces == snapshot
    again = skill_runtime._budget_guardrail(run, ledger, {"requirements": []})
    assert again == guardrail
    assert ledger.surfaces == snapshot
    assert _load(run, "state/budget-guardrail.json") == guardrail


def test_guardrail_checkpoint_is_byte_stable(tmp_path):
    # 快照对比：护栏引入后，空 checkpoint 重写 runtime-status.json 无漂移
    run = tmp_path / "run"
    initialize_direct_run(
        run_dir=run, target=TARGET,
        inventory_path=_inventory(tmp_path, _user_rows(6)))
    checkpoint_direct_run(run)
    first = (run / "runtime-status.json").read_bytes()
    ledger_first = (run / "coverage-ledger.json").read_bytes()

    checkpoint_direct_run(run)

    assert (run / "runtime-status.json").read_bytes() == first
    assert (run / "coverage-ledger.json").read_bytes() == ledger_first


def test_guardrail_human_actions_aggregated_and_deduped(tmp_path):
    requirements = {"requirements": [
        {"requirement_id": "req-001", "mode": "peer_pair",
         "reason_code": "peer_role_pair_missing", "human_action": "供给身份A"},
        {"requirement_id": "req-002", "mode": "peer_pair",
         "reason_code": "peer_role_pair_missing", "human_action": "供给身份A"},
        {"requirement_id": "req-003", "mode": "role_pair",
         "reason_code": "required_role_pair_missing",
         "human_action": "供给身份B"},
        {"requirement_id": "req-004", "mode": "single",
         "reason_code": "", "human_action": "已满足不得出现"},
    ]}
    _run, _ledger, guardrail = _guardrail_call(
        tmp_path,
        [_open_surface(index) for index in range(6)],
        requirements)

    assert guardrail["triggered"] is True
    assert guardrail["human_actions"] == ["供给身份A", "供给身份B"]
