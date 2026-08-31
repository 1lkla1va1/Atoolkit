"""v9.8.2 W4（MINOR-1）：护栏写盘失败隔离回归测试。

设计文档：design/迭代方案/v9.8.2_哲学归位与框架指纹路由.md §W4（m4 修订）。
- `_budget_guardrail` 尾部写盘包 try/except：失败吞异常、返回 dict 记
  `guardrail_error`（稳定 code，不用异常文本），checkpoint 不被挂起；
  吞掉的 symlink fail-closed 信号写入 runtime-metrics 留痕（不静默）。
- 对称参照：tests/test_v981_runtime_metrics.py 的 metrics 失败不阻塞用例。
"""
from __future__ import annotations

import json
import pathlib

from engine.skill_runtime import (
    checkpoint_direct_run,
    initialize_direct_run,
)

TARGET = "https://t.example/"


def _inventory(tmp_path: pathlib.Path) -> pathlib.Path:
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"surfaces": [
        {"endpoint": f"/api/order{index}", "method": "GET", "params": ["id"],
         "roles": ["user"]}
        for index in range(1, 4)
    ]}, ensure_ascii=False), encoding="utf-8")
    return path


def _load(run: pathlib.Path, name: str) -> dict:
    return json.loads((run / name).read_text(encoding="utf-8"))


def test_guardrail_symlink_write_failure_does_not_hang_checkpoint(tmp_path):
    run = tmp_path / "run"
    initialize_direct_run(
        run_dir=run, target=TARGET, inventory_path=_inventory(tmp_path))
    # 护栏落盘叶子被占位为 symlink → atomic_write_json 的 reject_leaf_symlink
    # fail-closed 触发；护栏是 advisory，checkpoint 不得因此失败。
    state = run / "state"
    state.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "elsewhere.json"
    (state / "budget-guardrail.json").symlink_to(outside)

    checkpoint = checkpoint_direct_run(run)

    guardrail = checkpoint["budget_guardrail"]
    assert guardrail["guardrail_error"] == "budget_guardrail_write_failed"
    assert "frozen_cells" in guardrail  # 计算结果保留，只是落盘失败
    assert not outside.exists()          # 未跟随 symlink 写出
    # 不静默：runtime-metrics 留痕 + state/checkpoint.json 同带稳定 code
    metrics = _load(run, "runtime-metrics.json")
    entry = metrics["by_phase"]["checkpoint.budget_guardrail"]
    assert entry["counters"]["guardrail_write_error"] == 1
    saved = _load(run, "state/checkpoint.json")
    assert saved["budget_guardrail"]["guardrail_error"] == (
        "budget_guardrail_write_failed")
    assert checkpoint["metrics_error"] == ""  # metrics 本身健康


def test_guardrail_write_success_has_no_error_fields(tmp_path):
    run = tmp_path / "run"
    initialize_direct_run(
        run_dir=run, target=TARGET, inventory_path=_inventory(tmp_path))

    checkpoint = checkpoint_direct_run(run)

    guardrail = checkpoint["budget_guardrail"]
    assert "guardrail_error" not in guardrail
    assert _load(run, "state/budget-guardrail.json") == guardrail
    metrics = _load(run, "runtime-metrics.json")
    assert "checkpoint.budget_guardrail" not in metrics["by_phase"]
