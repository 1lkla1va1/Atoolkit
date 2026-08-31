"""v9.8.1 W4a：identity_blocked 调度消费端回归测试。

设计文档：design/迭代方案/v9.8.1_可达性调度消费端与提交出口收口.md §1.1
（A0 匿名豁免 + 设计 A 冻结序 + 设计 B 排序消费 + 设计 C 闸保持 + §1.1.5 口径）。
- A0：纯匿名格（格级 actor_role=anonymous）无论 mode 一律 needed=0，
  带 id 参数的匿名 idor 格不再陪绑；同端点 user 兄弟格仍 blocked。
- 设计 A：init 先对冻结前全量 planned surfaces 推导身份需求、镜像
  identity_blocked，再冻结；可达性优先于价值，被身份挤出的格进
  deferred-pool 且 deferred_reason=identity_cap，顶层 deferred_reasons
  为计数字典。
- 设计 B：next_surfaces()/execution-queue 排序把 identity_blocked 格排到
  族内可达格之后；标记每次 checkpoint 全量重算，身份到位后排序自动恢复。
- BLOCKER-2：deferred 格归因恒为 execution_not_started（medium），
  不随 identity_blocked 标记漂移；冻结集 blocked 格仍归因
  identity_missing，attribution_summary.identity_missing 只计冻结集。
- MAJOR-1：W0 防作弊闸触发条件不变，新增透明计数
  deferred_identity_blocked_high_value（不参与判定）。
- MAJOR-2：checkpoint 推导输入 = ledger.surfaces + deferred-pool surfaces
  按 surface_id 合并去重，同一身份状态下 init 与 checkpoint 落盘的
  identity-requirements.json 逐字节一致。
"""
from __future__ import annotations

import json
import pathlib

from engine.ledger import CoverageLedger, is_high_value
from engine.skill_runtime import (
    checkpoint_direct_run,
    initialize_direct_run,
)

TARGET = "https://t.example/"


def _write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _write_identities(run: pathlib.Path, count: int = 2) -> None:
    _write_json(run / "identities.json", {
        "schema_version": 1,
        "identities": [
            {"label": f"id-{index}",
             "headers": {"Cookie": f"sid=distinct-{index}"}}
            for index in range(count)
        ],
    })


def _inventory(tmp_path: pathlib.Path, rows: list[dict],
               name: str = "inventory.json") -> pathlib.Path:
    path = tmp_path / name
    _write_json(path, {"surfaces": rows})
    return path


def _stateful_inventory(tmp_path: pathlib.Path, endpoints: int = 25,
                        name: str = "inventory.json") -> pathlib.Path:
    """全高价值全带态（roles=["user"] + id 参数 → peer_pair）病态输入。"""
    return _inventory(tmp_path, [
        {"endpoint": f"/api/order{index}", "method": "GET", "params": ["id"],
         "roles": ["user"]}
        for index in range(1, endpoints + 1)
    ], name)


def _load(run: pathlib.Path, name: str) -> dict:
    return json.loads((run / name).read_text(encoding="utf-8"))


def _frozen(run: pathlib.Path) -> list[dict]:
    return _load(run, "coverage-ledger.json")["surfaces"]


def _blocked_ids(surfaces: list[dict]) -> set[str]:
    return {s["surface_id"] for s in surfaces
            if s.get("identity_blocked") is True}


def test_freeze_prefers_reachable_cells_over_blocked_high_value(tmp_path):
    # 8 个匿名可达端点 + 20 个带态端点，全部高价值；0 身份。
    inventory = _inventory(tmp_path, [
        *({"endpoint": f"/api/order-anon-{index}", "method": "GET",
           "params": ["id"], "roles": ["anonymous"]}
          for index in range(1, 9)),
        *({"endpoint": f"/api/order-user-{index}", "method": "GET",
           "params": ["id"], "roles": ["user"]}
          for index in range(1, 21)),
    ])
    run = tmp_path / "run"
    initialize_direct_run(
        run_dir=run, target=TARGET, inventory_path=inventory,
        max_frozen_cells=20)

    frozen = _frozen(run)
    assert len(frozen) == 20
    # 可达格占满冻结集：20 格全部无 identity_blocked
    assert not _blocked_ids(frozen)
    assert all(surface.get("roles") == ["anonymous"] for surface in frozen)

    pool = _load(run, "deferred-pool.json")
    entries = pool["surfaces"]
    user_entries = [e for e in entries if e.get("roles") == ["user"]]
    anon_entries = [e for e in entries if e.get("roles") == ["anonymous"]]
    # 带态格整批 identity_cap 进 pool；装不下的可达格仍是 budget_cap
    assert user_entries
    assert all(e["deferred_reason"] == "identity_cap" for e in user_entries)
    assert all(e["identity_blocked"] is True for e in user_entries)
    assert all(e["deferred_reason"] == "budget_cap" for e in anon_entries)
    assert len(anon_entries) == sum(
        1 for s in [*frozen, *entries] if s.get("roles") == ["anonymous"]) - 20
    assert pool["deferred_reasons"] == {
        "budget_cap": len(anon_entries),
        "identity_cap": len(user_entries),
    }
    # blocks_cells 覆盖冻结+deferred 全集（本用例冻结集无 blocked）
    artifact = _load(run, "identity-requirements.json")
    blocked = {
        cell for req in artifact["requirements"]
        for cell in req["blocks_cells"]
    }
    assert blocked == {e["surface_id"] for e in user_entries}


def test_freeze_deterministic_with_and_without_identities(tmp_path):
    inventory = _stateful_inventory(tmp_path)
    for label, with_identities in (("plain", False), ("supplied", True)):
        runs = []
        for twin in ("a", "b"):
            run = tmp_path / label / twin / "run"
            run.mkdir(parents=True)
            if with_identities:
                _write_identities(run)
            initialize_direct_run(
                run_dir=run, target=TARGET, inventory_path=inventory,
                max_frozen_cells=20)
            runs.append(run)
        for name in ("deferred-pool.json", "coverage-ledger.json",
                     "identity-requirements.json"):
            assert (runs[0] / name).read_bytes() == (runs[1] / name).read_bytes(), name


def test_anonymous_idor_cells_not_identity_blocked(tmp_path):
    # BLOCKER-3：无显式 roles 的行按 DEFAULT_ROLES 展开 anonymous+user
    # 兄弟格；显式 roles=["anonymous"] 的行只产匿名格。均带 id 参数。
    inventory = _inventory(tmp_path, [
        {"endpoint": "/api/item", "method": "GET", "params": ["id"]},
        {"endpoint": "/api/thing", "method": "GET", "params": ["id"],
         "roles": ["anonymous"]},
    ])
    run = tmp_path / "run"
    initialize_direct_run(run_dir=run, target=TARGET, inventory_path=inventory)

    frozen = _frozen(run)
    anon = [s for s in frozen if s.get("roles") == ["anonymous"]]
    user = [s for s in frozen if s.get("roles") == ["user"]]
    assert anon and user, "DEFAULT_ROLES 双角色展开应同时存在两种格"
    # 匿名 idor 格 0 身份下不 blocked（A0 豁免）；user 兄弟格仍 blocked
    assert not _blocked_ids(anon)
    assert _blocked_ids(user) == {s["surface_id"] for s in user}
    # blocks_cells 与 ledger 标记交叉一致，且不含任何匿名格
    artifact = _load(run, "identity-requirements.json")
    blocked = {
        cell for req in artifact["requirements"]
        for cell in req["blocks_cells"]
    }
    assert blocked == {s["surface_id"] for s in user}
    assert not blocked & {s["surface_id"] for s in anon}


def test_next_surfaces_demotes_identity_blocked_and_recovers(tmp_path):
    inventory = _inventory(tmp_path, [
        {"endpoint": "/api/order-user", "method": "GET", "params": ["id"],
         "roles": ["user"]},
        {"endpoint": "/api/order-anon", "method": "GET", "params": ["id"],
         "roles": ["anonymous"]},
    ])
    run = tmp_path / "run"
    initialize_direct_run(run_dir=run, target=TARGET, inventory_path=inventory)

    ledger = CoverageLedger.load(run / "coverage-ledger.json")
    ordered = ledger.next_surfaces(50)
    assert len(ordered) == len(ledger.surfaces)
    flags = [s.get("identity_blocked") is True for s in ordered]
    assert any(flags), "应存在 identity_blocked 格"
    # 所有可达格排在所有 identity_blocked 格之前（降权是整体性的）
    assert flags == sorted(flags)

    # 预置 2 个独立指纹 + checkpoint → 标记清除、排序恢复原优先级
    _write_identities(run)
    checkpoint_direct_run(run)
    ledger = CoverageLedger.load(run / "coverage-ledger.json")
    assert not _blocked_ids(ledger.surfaces)
    recovered = [s["surface_id"] for s in ledger.next_surfaces(50)]

    def _original_key(s: dict) -> tuple:
        shallow = s.get("negative_depth") == "shallow" or str(
            s.get("status") or "").lower() == "shallow_negative"
        return (
            0 if shallow else 1,
            0 if s.get("next_actions") else 1,
            0 if is_high_value(s) else 1,
            s.get("feature", ""),
            s.get("surface_id", ""),
        )

    expected = [s["surface_id"] for s in sorted(
        ledger.surfaces, key=_original_key)]
    assert recovered == expected


def test_execution_queue_carries_identity_blocked_flag(tmp_path):
    inventory = _inventory(tmp_path, [
        {"endpoint": "/api/order-user", "method": "GET", "params": ["id"],
         "roles": ["user"]},
        {"endpoint": "/api/order-anon", "method": "GET", "params": ["id"],
         "roles": ["anonymous"]},
    ])
    run = tmp_path / "run"
    initialize_direct_run(run_dir=run, target=TARGET, inventory_path=inventory)

    ledger = CoverageLedger.load(run / "coverage-ledger.json")
    flag_by_id = {
        s["surface_id"]: s.get("identity_blocked") is True
        for s in ledger.surfaces
    }
    queue = _load(run, "execution-queue.json")["queue"]
    assert queue
    for row in queue:
        # 队列行携带与 ledger 一致的派生标记
        assert row["identity_blocked"] is flag_by_id[row["surface_id"]]
    # 同一 execution_status 内，blocked 行排在可达行之后
    by_status: dict[str, list[bool]] = {}
    for row in queue:
        by_status.setdefault(row["execution_status"], []).append(
            row["identity_blocked"])
    for flags in by_status.values():
        assert flags == sorted(flags)


def test_pool_rows_attributed_execution_not_started_under_identity_cap(
        tmp_path):
    # BLOCKER-2：全带态 0 身份 run，deferred 格归因不漂移为 identity_missing
    run = tmp_path / "run"
    initialize_direct_run(
        run_dir=run, target=TARGET,
        inventory_path=_stateful_inventory(tmp_path), max_frozen_cells=20)
    checkpoint = checkpoint_direct_run(run)
    assert checkpoint["attribution_error"] == ""

    pool = _load(run, "deferred-pool.json")
    deferred_ids = {e["surface_id"] for e in pool["surfaces"]}
    assert all(e["identity_blocked"] is True for e in pool["surfaces"])
    frozen_surfaces = _frozen(run)
    frozen_ids = {s["surface_id"] for s in frozen_surfaces}
    # 冻结 20 格全部 identity_blocked（0 身份全带态输入）
    assert _blocked_ids(frozen_surfaces) == frozen_ids

    attribution = _load(run, "miss-attribution.json")
    cell_rows = [r for r in attribution["rows"] if r["kind"] == "cell"]
    by_id = {r["surface_id"]: r for r in cell_rows}
    # deferred 格恒为 execution_not_started（不漂移），冻结集 blocked 格仍
    # 归因 identity_missing
    assert {by_id[i]["cause_code"] for i in deferred_ids} == {
        "execution_not_started"}
    assert {by_id[i]["cause_code"] for i in frozen_ids} == {
        "identity_missing"}
    # attribution_summary.identity_missing 只计冻结集
    assert checkpoint["attribution_summary"]["identity_missing"] == len(
        frozen_ids)
    # agenda 优先级：deferred → medium；冻结 blocked → high
    agenda = _load(run, "next-run-agenda.json")
    priority_by_surface = {
        item["source_surface_id"]: item["priority"]
        for item in agenda["items"]
    }
    assert {priority_by_surface[i] for i in deferred_ids} == {"medium"}
    assert {priority_by_surface[i] for i in frozen_ids} == {"high"}


def test_anti_gaming_gate_counts_identity_capped_deferred(tmp_path):
    # MAJOR-1：闸触发条件不变（0 执行事件 → 照常触发），新增透明计数
    run = tmp_path / "run"
    initialize_direct_run(
        run_dir=run, target=TARGET,
        inventory_path=_stateful_inventory(tmp_path), max_frozen_cells=20)
    checkpoint_direct_run(run)

    validation = _load(run, "finding_validation.json")
    reasons = validation["closure_gate"]["reasons"]
    assert "budget_cap_execution_below_floor" in reasons
    pool = _load(run, "deferred-pool.json")
    expected = sum(
        1 for e in pool["surfaces"]
        if e.get("identity_blocked") is True and is_high_value(e))
    budget = validation["closure_gate"]["budget_cap"]
    assert budget["deferred_identity_blocked_high_value"] == expected
    assert expected == len(pool["surfaces"])  # 本 fixture 全部带态高价值
    assert budget["frozen_execution_rate"] == 0.0


def test_identity_requirements_roundtrip_init_checkpoint(tmp_path):
    # MAJOR-2：同一身份状态下 init 与 checkpoint 的 identity-requirements.json
    # 逐字节一致（checkpoint 推导输入 = ledger + deferred-pool 合并去重）
    run = tmp_path / "run"
    initialize_direct_run(
        run_dir=run, target=TARGET,
        inventory_path=_stateful_inventory(tmp_path), max_frozen_cells=20)
    before = (run / "identity-requirements.json").read_bytes()

    checkpoint_direct_run(run)
    after = (run / "identity-requirements.json").read_bytes()
    assert after == before

    # blocks_cells 保持全集口径：覆盖冻结 + deferred 全部格
    artifact = json.loads(after.decode("utf-8"))
    blocked = {
        cell for req in artifact["requirements"]
        for cell in req["blocks_cells"]
    }
    pool = _load(run, "deferred-pool.json")
    full = {s["surface_id"] for s in _frozen(run)} | {
        e["surface_id"] for e in pool["surfaces"]}
    assert blocked == full

    # 身份注入后 checkpoint 重算：集合清空且 pool 标记同步刷新
    _write_identities(run)
    checkpoint_direct_run(run)
    cleared = _load(run, "identity-requirements.json")
    assert cleared["summary"]["blocked_cells"] == 0
    pool_after = _load(run, "deferred-pool.json")
    assert not _blocked_ids(pool_after["surfaces"])
    assert not _blocked_ids(_frozen(run))
