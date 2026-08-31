"""v9.8.1 M0：存量重放验收落地（合成病态 inventory + 可选外部归档回放）。

设计文档：design/迭代方案/v9.8.1_可达性调度消费端与提交出口收口.md §1.4。
- 合成病态 inventory：107 端点 × 2 参数（id/user_id）× 2 角色
  （user/admin）× 声明 2 vuln_class（idor/auth-bypass），端点全部命中
  /api/order*（is_high_value 恒真），复刻"高价值同质大分母"。注意：
  格的真实总数由 planner 的 vuln_class 展开决定（_classes_for_endpoint
  基于 DEFAULT_VULN_CLASSES，不受 inventory 行级 vuln_classes 约束），
  实际总数 > 856；按设计文档 §1.4-1 的 ≥ 口径断言。
- fixture 预置 2 个独立身份的 identities.json（MAJOR-3）：冻结 20 格
  全部可达，"闭合数学上可达"脚手架对每格构造合规 negative_evidence
  信封（spike 已验证合同可行）。
- 外部归档回放走 ATOOLKIT_REPLAY_RUN_DIR 环境变量 opt-in：未设时该用例
  根本不注册（不产生新 skip）；设置后在 tmp 副本上读取其
  inventory.json 并重放 init（R8：不原地重放）。
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil

from engine.knowledge import _requirements, load_cards, negative_sufficient
from engine.ledger import CoverageLedger
from engine.reporting.validate import validate_run_artifacts
from engine.skill_runtime import (
    checkpoint_direct_run,
    initialize_direct_run,
    record_observation,
)

TARGET = "https://t.example/"
_ENDPOINTS = 107
_PARAMS = ["id", "user_id"]
_ROLES = ["user", "admin"]
_VULN_CLASSES = ["idor", "auth-bypass"]


def _write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _pathological_inventory(path: pathlib.Path) -> pathlib.Path:
    """107 端点高价值同质 inventory（设计 §1.4-1 的合成病态结构）。"""
    _write_json(path, {"surfaces": [
        {"endpoint": f"/api/order{index:03d}", "method": "GET",
         "params": list(_PARAMS), "roles": list(_ROLES),
         "vuln_classes": list(_VULN_CLASSES)}
        for index in range(1, _ENDPOINTS + 1)
    ]})
    return path


def _preset_identities(run: pathlib.Path) -> None:
    run.mkdir(parents=True, exist_ok=True)
    _write_json(run / "identities.json", {
        "schema_version": 1,
        "identities": [
            {"label": "owner", "headers": {"Cookie": "sid=owner"}},
            {"label": "peer", "headers": {"Cookie": "sid=peer"}},
        ],
    })


def _replay_init(tmp_path: pathlib.Path, name: str) -> pathlib.Path:
    run = tmp_path / name
    _preset_identities(run)
    initialize_direct_run(
        run_dir=run, target=TARGET,
        inventory_path=_pathological_inventory(tmp_path / f"{name}-inv.json"))
    return run


def _load(run: pathlib.Path, name: str) -> dict:
    return json.loads((run / name).read_text(encoding="utf-8"))


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


_CELL_FIELDS = ("asset_id", "endpoint", "method", "param", "actor_role",
                "vuln_class", "namespace", "param_location", "subject_role",
                "object_kind")


def _write_negative_envelope(
        run: pathlib.Path, surface: dict, index: int) -> str:
    """一格一个合规 negative_evidence 信封（3 独立向量 + 哈希绑定 + 断言）。"""
    exact_cell = {key: surface.get(key, "") for key in _CELL_FIELDS}
    role = str(
        surface.get("actor_role") or (surface.get("roles") or ["user"])[0])
    packets = []
    for vector in ("boolean", "error", "time"):
        marker = f"probe-{index:02d}-{vector}"
        request = (
            f"GET {surface['endpoint']}?{surface['param']}={marker} HTTP/1.1\n"
            f"Host: t.example\nCookie: sid={role}-token\n\n"
        )
        response = (
            "HTTP/1.1 200 OK\n\n"
            f'{{"result":"empty","probe":"{marker}"}}'
        )
        packets.append({
            "vector": vector,
            "request": request,
            "response": response,
            "request_sha256": _sha(request),
            "response_sha256": _sha(response),
            "assertions": [{
                "target": "response", "relation": "contains",
                "value": '"result":"empty"',
            }],
            "identity_assertions": {
                "actor_role": {
                    "target": "request", "relation": "contains",
                    "value": f"sid={role}-token",
                },
            },
        })
    envelope = {
        "schema_version": "1.0",
        "kind": "negative_evidence",
        "exact_cell": exact_cell,
        "evidence_types": ["baseline"],
        "identities": ["owner", "peer"],
        "roles": [role],
        "packets": packets,
    }
    relative = f"state/evidence/negative-{index:02d}.json"
    _write_json(run / relative, envelope)
    return relative


def _close_frozen_cells(run: pathlib.Path) -> None:
    """对全部冻结格写一条满足证明合同的 negative observation。"""
    cards = load_cards()
    ledger = CoverageLedger.load(run / "coverage-ledger.json")
    contracts = {
        c["surface_id"]: c
        for c in _load(run, "execution-contracts.json")["contracts"]
    }
    for index, surface in enumerate(ledger.surfaces):
        surface_id = surface["surface_id"]
        ref = _write_negative_envelope(run, surface, index)
        min_vectors, min_responses, types, min_ids, roles, _ = _requirements(
            surface, cards)
        negative = {
            "vectors": [
                f"vector-{i}" for i in range(max(min_vectors, 3))],
            "response_count": max(min_responses, 1),
            "evidence_types": sorted(types) or ["baseline"],
            "identities": ["owner", "peer", "third"][:max(min_ids, 2)],
            "roles": sorted(roles) or list(surface.get("roles") or ["user"]),
        }
        ok, missing = negative_sufficient(surface, negative, cards)
        assert ok, (surface_id, missing)
        record_observation(run_dir=run, agent_id="tester", observation={
            "schema_version": 1,
            "observation_id": f"obs-close-{index:02d}",
            "surface_id": surface_id,
            "outcome": "negative",
            "completed_obligations": [
                o["obligation_id"]
                for o in contracts[surface_id]["required_obligations"]
            ],
            "evidence_refs": [ref],
            "negative": negative,
        })


def test_feishu_like_inventory_freezes_at_cap(tmp_path):
    inventory = _pathological_inventory(tmp_path / "inventory.json")
    runs = []
    for twin in ("a", "b"):
        run = tmp_path / twin / "run"
        _preset_identities(run)
        initialize_direct_run(
            run_dir=run, target=TARGET, inventory_path=inventory)
        runs.append(run)
    run = runs[0]

    ledger = _load(run, "coverage-ledger.json")
    pool = _load(run, "deferred-pool.json")
    # 构造数断言：856 格起步的病态分母被预算截到 20 + deferred
    total = len(ledger["surfaces"]) + len(pool["surfaces"])
    assert total >= 856
    assert len(ledger["surfaces"]) <= 20
    assert pool["deferred_cells"] >= 836
    assert pool["deferred_cells"] == len(pool["surfaces"])
    # fixture 预置 2 身份 → 冻结集无 identity_blocked，deferred 全 budget_cap
    assert not any(s.get("identity_blocked") is True
                   for s in ledger["surfaces"])
    assert pool["deferred_reasons"]["identity_cap"] == 0
    assert pool["deferred_reasons"]["budget_cap"] == pool["deferred_cells"]
    # pool 字节级确定：两次 init 的 deferred-pool.json 完全一致
    assert (runs[0] / "deferred-pool.json").read_bytes() == (
        runs[1] / "deferred-pool.json").read_bytes()


def test_closure_mathematically_reachable_at_scale(tmp_path):
    # 856+ 格分母下，冻结 20 格走完整 negative 合同闭合后：W0 闸不触发、
    # 覆盖闭格门不拒绝 —— "闭合数学上可达"的机器断言（脚手架见 spike）。
    run = _replay_init(tmp_path, "run")
    _close_frozen_cells(run)
    checkpoint = checkpoint_direct_run(run)
    assert checkpoint["attribution_error"] == ""

    validation = validate_run_artifacts(run, allow_empty=True)
    reasons = validation["closure_gate"]["reasons"]
    assert "budget_cap_execution_below_floor" not in reasons
    assert "coverage_in_scope_incomplete" not in reasons
    assert "coverage_not_closed" not in reasons
    assert "negative_evidence_invalid" not in reasons
    budget = validation["closure_gate"]["budget_cap"]
    assert budget["frozen_execution_rate"] == 1.0
    ledger = _load(run, "coverage-ledger.json")
    assert {s["status"] for s in ledger["surfaces"]} == {"not_vulnerable"}


def test_deferred_pool_attributed_as_execution_not_started(tmp_path):
    # §1.1.1-4 归因剥离裁决的规模化验证：全部 deferred 格逐一出现在
    # miss-attribution 且 cause_code 恒为 execution_not_started。
    run = _replay_init(tmp_path, "run")
    checkpoint = checkpoint_direct_run(run)
    assert checkpoint["attribution_error"] == ""

    pool = _load(run, "deferred-pool.json")
    deferred_ids = {e["surface_id"] for e in pool["surfaces"]}
    assert len(deferred_ids) >= 836
    attribution = _load(run, "miss-attribution.json")
    rows = {
        r["surface_id"]: r for r in attribution["rows"] if r["kind"] == "cell"
    }
    assert deferred_ids <= set(rows)
    assert {rows[i]["cause_code"] for i in deferred_ids} == {
        "execution_not_started"}


_REPLAY_RUN_DIR = os.environ.get("ATOOLKIT_REPLAY_RUN_DIR")

if _REPLAY_RUN_DIR:
    def test_external_archive_replay(tmp_path):
        """opt-in 外部归档回放：在 tmp 副本上读 inventory 并重放 init（R8）。

        本地验收动作而非 CI 合同：ATOOLKIT_REPLAY_RUN_DIR 指向存量 run
        目录时注册；未设时本用例不进入收集（不产生新 skip）。
        """
        source = pathlib.Path(_REPLAY_RUN_DIR).resolve()
        inventory = source / "inventory.json"
        assert inventory.is_file(), f"归档缺 inventory.json: {source}"
        copied = tmp_path / "archive-copy"
        shutil.copytree(source, copied)
        document = json.loads(
            (copied / "inventory.json").read_text(encoding="utf-8"))
        target = str(document.get("target") or "").strip() or TARGET

        run = tmp_path / "replay-run"
        _preset_identities(run)
        initialize_direct_run(
            run_dir=run, target=target,
            inventory_path=copied / "inventory.json")

        ledger = _load(run, "coverage-ledger.json")
        pool_path = run / "deferred-pool.json"
        assert 0 < len(ledger["surfaces"]) <= 20
        if pool_path.is_file():
            pool = _load(run, "deferred-pool.json")
            assert pool["deferred_cells"] == len(pool["surfaces"])
            assert set(pool["deferred_reasons"]) == {
                "budget_cap", "identity_cap"}
