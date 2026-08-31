"""v9.8.3 · checkpoint created_data 登记 advisory 回归测试。

- observation 文本含注册/创建类保守关键词信号而 ``state/created_data.md``
  缺失或无有效数据行 → checkpoint 输出 ``created_data_advisory.triggered=True``；
- 登记文件存在有效数据行，或无信号 → advisory 沉默；
- advisory 是纯提醒：不改台账、不进 runtime-status.json、不影响 report_ready；
- 写盘失败只吞 OSError/UnsafePathError（与 _budget_guardrail 同款红线）。
"""
from __future__ import annotations

import json
import pathlib
import re

from engine import skill_runtime
from engine.ledger import CoverageLedger
from engine.skill_runtime import (
    checkpoint_direct_run,
    initialize_direct_run,
    record_observation,
)

TARGET = "https://t.example/"


def _write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _init_run(tmp_path: pathlib.Path, name: str = "run") -> pathlib.Path:
    inventory = tmp_path / f"{name}-inventory.json"
    _write_json(inventory, {"surfaces": [
        {"endpoint": "/api/orders", "method": "GET", "params": ["id"],
         "roles": ["user"]},
    ]})
    run = tmp_path / name
    initialize_direct_run(
        run_dir=run, target=TARGET, inventory_path=inventory)
    return run


def _first_surface_id(run: pathlib.Path) -> str:
    ledger = CoverageLedger.load(run / "coverage-ledger.json")
    return str(ledger.surfaces[0]["surface_id"])


def _register_observation(run: pathlib.Path, note: str) -> None:
    evidence = run / "evidence" / "register.http"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text("HTTP/1.1 200 OK", encoding="utf-8")
    record_observation(run_dir=run, agent_id="tester", observation={
        "schema_version": 1,
        "observation_id": "obs-reg-1",
        "surface_id": _first_surface_id(run),
        "outcome": "exploring",
        "note": note,
        "evidence_refs": ["evidence/register.http"],
    })


def _load(run: pathlib.Path, name: str) -> dict:
    return json.loads((run / name).read_text(encoding="utf-8"))


def test_advisory_silent_without_signals(tmp_path):
    run = _init_run(tmp_path)
    checkpoint = checkpoint_direct_run(run)

    advisory = checkpoint["created_data_advisory"]
    assert advisory["triggered"] is False
    assert advisory["signal_keywords"] == []
    assert advisory["message"] == ""
    # 落盘与返回值一致
    assert _load(run, "state/created-data-advisory.json") == advisory
    # advisory 不进入 runtime-status.json
    assert "created_data_advisory" not in _load(run, "runtime-status.json")


def test_advisory_triggers_on_register_signal_without_ledger(tmp_path):
    run = _init_run(tmp_path)
    _register_observation(run, "自助注册了 2 个同级测试账号用于带态测试")

    checkpoint = checkpoint_direct_run(run)

    advisory = checkpoint["created_data_advisory"]
    assert advisory["triggered"] is True
    assert "注册" in advisory["signal_keywords"]
    assert advisory["registered_rows"] == 0
    assert "created_data.md" in advisory["message"]


def test_advisory_silent_once_created_data_registered(tmp_path):
    run = _init_run(tmp_path)
    _register_observation(run, "register endpoint exercised, account created")
    state = run / "state"
    state.mkdir(exist_ok=True)
    (state / "created_data.md").write_text(
        "| 类型 | 标识 | 明文凭据 | 创建接口 | 请求证据路径 | 创建时间 |\n"
        "|---|---|---|---|---|---|\n"
        "| 账号 | tester01 | pass123 | POST /register | evidence/register.http | 2026-08-31 |\n",
        encoding="utf-8")

    checkpoint = checkpoint_direct_run(run)

    advisory = checkpoint["created_data_advisory"]
    assert advisory["triggered"] is False
    assert advisory["registered_rows"] == 1
    assert advisory["signal_keywords"], "信号仍应被记录"


def test_header_and_separator_rows_do_not_count(tmp_path):
    run = _init_run(tmp_path)
    _register_observation(run, "注册流程测试")
    state = run / "state"
    state.mkdir(exist_ok=True)
    (state / "created_data.md").write_text(
        "# created data\n"
        "| 类型 | 标识 | 明文凭据 |\n"
        "|---|---|---|\n",
        encoding="utf-8")

    checkpoint = checkpoint_direct_run(run)

    advisory = checkpoint["created_data_advisory"]
    assert advisory["triggered"] is True
    assert advisory["registered_rows"] == 0


def test_advisory_swallow_is_narrow():
    source = pathlib.Path(skill_runtime.__file__).read_text(encoding="utf-8")
    match = re.search(
        r"def _created_data_advisory.*?return advisory", source, re.DOTALL)
    assert match, "_created_data_advisory 未找到"
    assert "except (OSError, UnsafePathError)" in match.group(0)
    assert "except Exception" not in match.group(0)
