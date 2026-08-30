"""v9.8 W2：身份需求前置申报回归测试。

设计文档：design/迭代方案/v9.8_难度感知执行与身份供给管线.md §W2 + §6 R7。
- 推导器精确匹配 planner risk_tag 词表（禁止子串猜测）：
  object-ownership|idor → peer_pair(2)；privilege|enum-tamper|auth-flow|
  auth-flow-abuse → role_pair；amount-tamper|accounting|business-logic →
  stateful_owner；redirect-chain|callback → single；其余 → single；
  纯匿名格无需身份。
- init 在首个网络动作前落盘 identity-requirements.json；未满足需求的格
  在 coverage-ledger 标 identity_blocked=true 且与 blocks_cells 交叉一致。
- checkpoint 复算：补身份后缺口清零；identity_blocked 格归因
  identity_missing（补 W1 的 Direct 归因缝隙）。
"""
from __future__ import annotations

import json
import pathlib

from engine.identity_requirements import (
    count_present_identities,
    derive_identity_requirements,
    requirements_from_identity_readiness,
)
from engine.skill_runtime import (
    checkpoint_direct_run,
    initialize_direct_run,
)

TARGET = "https://t.example/"


def _write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _surface(surface_id: str, tags: list[str],
             roles: list[str] | None = None) -> dict:
    return {
        "surface_id": surface_id,
        "endpoint": f"/api/{surface_id}",
        "method": "GET",
        "risk_tags": tags,
        "roles": roles or ["user"],
        "status": "not_tested",
    }


def _requirement_for(result: dict, surface_id: str) -> dict:
    for requirement in result["requirements"]:
        if surface_id in requirement["blocks_cells"]:
            return requirement
    raise AssertionError(f"no unmet requirement blocks {surface_id}")


def test_mapping_table_rules() -> None:
    cases = [
        (["object-ownership"], "peer_pair", 2, "peer_role_pair_missing"),
        (["idor"], "peer_pair", 2, "peer_role_pair_missing"),
        (["privilege"], "role_pair", 2, "required_role_pair_missing"),
        (["enum-tamper"], "role_pair", 2, "required_role_pair_missing"),
        (["auth-flow"], "role_pair", 2, "required_role_pair_missing"),
        (["auth-flow-abuse"], "role_pair", 2, "required_role_pair_missing"),
        (["amount-tamper"], "stateful_owner", 1, "test_owned_object_missing"),
        (["accounting"], "stateful_owner", 1, "test_owned_object_missing"),
        (["business-logic"], "stateful_owner", 1, "test_owned_object_missing"),
        (["redirect-chain"], "single", 1, "distinct_identity_missing"),
        (["callback"], "single", 1, "distinct_identity_missing"),
        (["ssrf"], "single", 1, "distinct_identity_missing"),
        (["xss"], "single", 1, "distinct_identity_missing"),
    ]
    for index, (tags, mode, needed, reason) in enumerate(cases):
        result = derive_identity_requirements(
            [_surface(f"s{index}", tags)], identities_present=0)
        requirement = _requirement_for(result, f"s{index}")
        assert requirement["mode"] == mode, tags
        assert requirement["count_needed"] == needed, tags
        assert requirement["count_present"] == 0
        assert requirement["reason_code"] == reason, tags


def test_mapping_precedence_is_deterministic() -> None:
    result = derive_identity_requirements([
        _surface("both-idor-auth", ["idor", "auth-flow"]),
        _surface("auth-amount", ["auth-flow", "amount-tamper"]),
        _surface("amount-redirect", ["amount-tamper", "redirect-chain"]),
    ], identities_present=0)
    assert _requirement_for(result, "both-idor-auth")["mode"] == "peer_pair"
    assert _requirement_for(result, "auth-amount")["mode"] == "role_pair"
    assert _requirement_for(result, "amount-redirect")["mode"] == (
        "stateful_owner")


def test_pure_anonymous_cell_needs_no_identity() -> None:
    result = derive_identity_requirements(
        [_surface("anon", ["xss"], roles=["anonymous"])], identities_present=0)
    assert result["requirements"] == []
    assert result["summary"]["blocked_cells"] == 0


def test_satisfied_requirements_block_nothing() -> None:
    result = derive_identity_requirements(
        [_surface("pair", ["idor"]), _surface("own", ["accounting"])],
        identities_present=2)
    assert result["summary"]["total_requirements"] == 2
    assert result["summary"]["unmet_requirements"] == 0
    assert result["summary"]["blocked_cells"] == 0
    assert all(not requirement["reason_code"]
               for requirement in result["requirements"])
    assert all(not requirement["blocks_cells"]
               for requirement in result["requirements"])


def test_terminal_cells_do_not_generate_requirements() -> None:
    closed = {**_surface("closed", ["idor"]), "status": "confirmed"}
    result = derive_identity_requirements([closed], identities_present=0)
    assert result["requirements"] == []


def test_count_present_identities_uses_fingerprints(tmp_path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    assert count_present_identities(run) == 0
    _write_json(run / "identities.json", {"schema_version": 1, "identities": [
        {"label": "a", "headers": {"Cookie": "sid=one"}},
        {"label": "b", "headers": {"Cookie": "sid=one"}},  # 同凭据 → 同一身份
    ]})
    assert count_present_identities(run) == 1
    _write_json(run / "identities.json", {"schema_version": 1, "identities": [
        {"label": "a", "headers": {"Cookie": "sid=one"}},
        {"label": "b", "headers": {"Cookie": "sid=two"}},
    ]})
    assert count_present_identities(run) == 2


def _init_idor_run(tmp_path: pathlib.Path, name: str = "run") -> pathlib.Path:
    inventory = tmp_path / f"{name}-inventory.json"
    _write_json(inventory, {"surfaces": [
        {"endpoint": "/api/orders", "method": "GET", "params": ["id"],
         "roles": ["user"]},
        {"endpoint": "/api/login", "method": "POST",
         "params": ["username"], "roles": ["anonymous"]},
    ]})
    run = tmp_path / name
    initialize_direct_run(run_dir=run, target=TARGET, inventory_path=inventory)
    return run


def test_init_materializes_requirements_and_flags(tmp_path) -> None:
    run = _init_idor_run(tmp_path)

    artifact = json.loads(
        (run / "identity-requirements.json").read_text(encoding="utf-8"))
    assert artifact["schema_version"] == "1"
    assert artifact["requirements"], "requirements 非空"
    assert artifact["summary"]["unmet_requirements"] > 0

    ledger = json.loads(
        (run / "coverage-ledger.json").read_text(encoding="utf-8"))
    flagged = {
        surface["surface_id"] for surface in ledger["surfaces"]
        if surface.get("identity_blocked") is True
    }
    blocked = {
        cell for requirement in artifact["requirements"]
        for cell in requirement["blocks_cells"]
    }
    # blocks_cells ↔ ledger 交叉一致（双向）
    assert flagged == blocked
    assert blocked, "identity_blocked 非空"


def test_checkpoint_attributes_identity_blocked_as_identity_missing(
        tmp_path) -> None:
    run = _init_idor_run(tmp_path)
    checkpoint = checkpoint_direct_run(run)

    assert checkpoint["attribution_error"] == ""
    summary = checkpoint["attribution_summary"]
    assert summary["cause_counts"].get("identity_missing", 0) >= 1
    validation = json.loads(
        (run / "finding_validation.json").read_text(encoding="utf-8"))
    assert validation["miss_attribution"]["cause_counts"].get(
        "identity_missing", 0) >= 1


def test_supplying_identities_clears_the_gap(tmp_path) -> None:
    run = _init_idor_run(tmp_path)
    before = json.loads(
        (run / "identity-requirements.json").read_text(encoding="utf-8"))
    assert before["summary"]["unmet_requirements"] > 0

    # 补两个独立身份后无需 re-init：checkpoint 复算并清零缺口。
    _write_json(run / "identities.json", {"schema_version": 1, "identities": [
        {"label": "owner", "headers": {"Cookie": "sid=owner"}},
        {"label": "peer", "headers": {"Cookie": "sid=peer"}},
    ]})
    checkpoint_direct_run(run)

    after = json.loads(
        (run / "identity-requirements.json").read_text(encoding="utf-8"))
    assert after["summary"]["unmet_requirements"] == 0
    assert after["summary"]["blocked_cells"] == 0
    assert all(not requirement["blocks_cells"]
               for requirement in after["requirements"])
    ledger = json.loads(
        (run / "coverage-ledger.json").read_text(encoding="utf-8"))
    assert all(surface.get("identity_blocked") is not True
               for surface in ledger["surfaces"])
    validation = json.loads(
        (run / "finding_validation.json").read_text(encoding="utf-8"))
    assert validation["miss_attribution"]["cause_counts"].get(
        "identity_missing", 0) == 0


def test_engine_readiness_conversion() -> None:
    readiness = {
        "schema_version": 1,
        "distinct_credentials": 1,
        "threats": [
            {"feature_id": "f1", "threat_id": "t1", "mode": "peer_pair",
             "ready": False, "reason_code": "peer_role_pair_missing"},
            {"feature_id": "f1", "threat_id": "t2", "mode": "role_pair",
             "ready": False, "reason_code": "required_role_pair_missing"},
            {"feature_id": "f2", "threat_id": "t3", "mode": "single",
             "ready": True, "reason_code": ""},
        ],
    }
    result = requirements_from_identity_readiness(readiness)
    assert result["schema_version"] == "1"
    assert result["summary"]["total_requirements"] == 2  # ready 格不产生需求
    assert result["summary"]["identities_present"] == 1
    by_reason = {
        requirement["reason_code"]: requirement
        for requirement in result["requirements"]
    }
    assert by_reason["peer_role_pair_missing"]["count_needed"] == 2
    assert by_reason["peer_role_pair_missing"]["blocks_cells"] == ["f1/t1"]
    assert by_reason["required_role_pair_missing"]["blocks_cells"] == ["f1/t2"]
    assert all(requirement["human_action"]
               for requirement in result["requirements"])
