"""v9.8.1 W5a：治理税 instrumentation 回归测试。

设计文档：design/迭代方案/v9.8.1_可达性调度消费端与提交出口收口.md §1.5。
- checkpoint 计时 6 个子相位 + 总时长 + 计数（observations /
  guardian_demotions / rejected）；observe 记单次耗时 + 计数；init 记总时长
  + plan/freeze/identity/projection 子相位。
- ``runtime-metrics.json`` 是跨调用累计的最新快照；``state/metrics.jsonl``
  每次 init/observe/checkpoint 追加一行（跨 checkpoint 历史，只增不改）。
- MAJOR-4：``first_init_at``/``last_checkpoint_at``/``session_span_seconds``
  落盘；治理占比 = (init+observe+checkpoint) total_seconds ÷ span，可从产物
  重算且 ≤ 1（分母含空闲，是下界）；绝对相位耗时独立可读（主判据）。
- best-effort 红线：metrics 写盘失败不得使 checkpoint 失败，异常吞掉并记
  ``metrics_error`` 字段。
"""
from __future__ import annotations

import json
import pathlib

import pytest

from engine.skill_runtime import (
    checkpoint_direct_run,
    initialize_direct_run,
    record_observation,
)

TARGET = "https://t.example/"
CHECKPOINT_PHASES = (
    "checkpoint.ledger_load",
    "checkpoint.identity",
    "checkpoint.finding_collect",
    "checkpoint.guardian_gate",
    "checkpoint.observation_merge",
    "checkpoint.attribution_validate",
)
INIT_PHASES = ("init.plan", "init.freeze", "init.identity", "init.projection")


def _write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _inventory(tmp_path: pathlib.Path, rows: list[dict]) -> pathlib.Path:
    path = tmp_path / "inventory.json"
    _write_json(path, {"surfaces": rows})
    return path


def _rows(count: int) -> list[dict]:
    return [
        {"endpoint": f"/api/order{index}", "method": "GET", "params": ["id"],
         "roles": ["anonymous"]}
        for index in range(1, count + 1)
    ]


def _load(run: pathlib.Path, name: str) -> dict:
    return json.loads((run / name).read_text(encoding="utf-8"))


def _observe(run: pathlib.Path, observation_id: str) -> dict:
    surface_id = _load(run, "coverage-ledger.json")["surfaces"][0]["surface_id"]
    return record_observation(run_dir=run, agent_id="tester", observation={
        "schema_version": 1, "observation_id": observation_id,
        "surface_id": surface_id, "outcome": "exploring",
    })


def _jsonl_lines(run: pathlib.Path) -> list[dict]:
    path = run / "state" / "metrics.jsonl"
    return [
        json.loads(line) for line in
        path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _initialized_run(tmp_path: pathlib.Path) -> pathlib.Path:
    run = tmp_path / "run"
    initialize_direct_run(
        run_dir=run, target=TARGET,
        inventory_path=_inventory(tmp_path, _rows(3)))
    return run


def test_checkpoint_emits_all_phase_keys(tmp_path):
    run = _initialized_run(tmp_path)
    _observe(run, "obs-1")
    checkpoint = checkpoint_direct_run(run)

    assert checkpoint["metrics_error"] == ""
    snapshot = _load(run, "runtime-metrics.json")
    assert snapshot["schema_version"] == 1
    by_phase = snapshot["by_phase"]
    for name in (*CHECKPOINT_PHASES, "checkpoint.total"):
        entry = by_phase[name]
        assert entry["calls"] == 1
        assert entry["total_seconds"] >= 0.0
    counters = by_phase["checkpoint.total"]["counters"]
    assert counters["observations"] == 1
    assert counters["guardian_demotions"] == 0
    assert counters["rejected"] == 0
    assert by_phase["observe.total"]["calls"] == 1
    assert by_phase["observe.total"]["counters"]["observations"] == 1
    assert by_phase["init.total"]["calls"] == 1
    for name in INIT_PHASES:
        assert by_phase[name]["calls"] == 1
        assert by_phase[name]["total_seconds"] >= 0.0


def test_metrics_jsonl_appends_across_checkpoints(tmp_path):
    run = _initialized_run(tmp_path)
    _observe(run, "obs-1")
    checkpoint_direct_run(run)
    checkpoint_direct_run(run)

    lines = _jsonl_lines(run)
    assert [line["event"] for line in lines] == [
        "init", "observe", "checkpoint", "checkpoint"]
    # 快照是累计值：二次 checkpoint 追加而非覆盖
    snapshot = _load(run, "runtime-metrics.json")
    by_phase = snapshot["by_phase"]
    assert by_phase["checkpoint.total"]["calls"] == 2
    assert by_phase["observe.total"]["calls"] == 1
    assert by_phase["init.total"]["calls"] == 1
    # JSONL 每行只带本次调用的相位数据
    for line in lines:
        assert line["phases"]
        assert all(entry["seconds"] >= 0.0 for entry in line["phases"].values())


def test_metrics_failure_does_not_fail_checkpoint(tmp_path):
    run = _initialized_run(tmp_path)
    # 把快照路径占位为目录 → 原子写必然失败，但 checkpoint 不得失败
    (run / "runtime-metrics.json").unlink()
    (run / "runtime-metrics.json").mkdir()

    checkpoint = checkpoint_direct_run(run)

    assert checkpoint["metrics_error"] != ""
    saved = _load(run, "state/checkpoint.json")
    assert saved["metrics_error"] == checkpoint["metrics_error"]
    assert saved["coverage"]["total"] > 0
    # init 时的 JSONL 历史保留，失败的 checkpoint 没有追加新行
    assert len(_jsonl_lines(run)) == 1


def test_session_span_recorded_and_share_computable(tmp_path):
    run = _initialized_run(tmp_path)
    _observe(run, "obs-1")
    checkpoint_direct_run(run)

    snapshot = _load(run, "runtime-metrics.json")
    first = snapshot["first_init_at"]
    last = snapshot["last_checkpoint_at"]
    span = snapshot["session_span_seconds"]
    assert first is not None and last is not None
    assert 0.0 < first <= last
    assert span == pytest.approx(last - first, abs=1e-6)
    assert span > 0.0
    by_phase = snapshot["by_phase"]
    # 治理占比（含空闲下界）可从产物重算且 ≤ 1；分子是三个入口相位各自的
    # 总时长（子相位是 total 的分解，不参与求和）
    governance = sum(
        by_phase[name]["total_seconds"]
        for name in ("init.total", "observe.total", "checkpoint.total"))
    share = governance / span
    assert 0.0 <= share <= 1.0
    # 主判据是绝对相位耗时：独立于占比可读
    assert by_phase["checkpoint.total"]["total_seconds"] >= 0.0
    assert by_phase["observe.total"]["total_seconds"] >= 0.0
    assert by_phase["init.total"]["total_seconds"] >= 0.0
    assert (by_phase["checkpoint.total"]["total_seconds"]
            >= by_phase["checkpoint.observation_merge"]["total_seconds"])
