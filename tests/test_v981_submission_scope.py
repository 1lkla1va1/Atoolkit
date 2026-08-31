"""v9.8.1 W6：提交出口 scope 校验回归测试。

设计文档：design/迭代方案/v9.8.1_可达性调度消费端与提交出口收口.md §1.3。
- scope 源优先级：run_manifest.json.authorized_scopes → run_scope.json
  target_domains；皆缺 → submission_scope_source_missing（fail closed）。
- 目标源：finding_validation.json.normalized_findings[*].target（receipt
  绑定产物）；相对 target 按 manifest primary_target urljoin 解析取 host
  （MINOR-2），解析失败 → finding_target_unresolvable:<raw>。
- 不在册 → finding_target_out_of_scope:<host> 且 eligible=false；derived
  集合不允许作为 root target；零 finding run targets_checked=0 不产生拒绝
  （MINOR-5）。run.py 路由与 exit code 不变。
"""
from __future__ import annotations

import json
import pathlib

from engine.finalize import finalize_run
from engine.submission import inspect_submission
from tests.test_v89_delivery_contract import _complete_finding_run

TARGET = "https://t.example/"


def _write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _synthetic_run(
    tmp_path: pathlib.Path,
    *,
    manifest: dict | None,
    targets: list[str],
) -> pathlib.Path:
    """最小 run 目录：manifest（可选）+ finding_validation.json。

    其余 submission 前置（delivery/receipt/报告哈希）刻意缺失——这些测试
    只断言 scope 段自身的 reason 与 scope_check，不关心整体 eligible。
    """
    run = tmp_path / "run"
    run.mkdir(parents=True)
    if manifest is not None:
        _write_json(run / "run_manifest.json", manifest)
    _write_json(run / "finding_validation.json", {
        "schema_version": 2,
        "normalized_findings": [{"target": target} for target in targets],
    })
    return run


def _manifest(**overrides) -> dict:
    base = {
        "submission_contract_version": 1,
        "primary_target": TARGET,
        "authorized_scopes": [TARGET],
    }
    base.update(overrides)
    return base


def _eligible_run(tmp_path: pathlib.Path) -> pathlib.Path:
    """完整可提交 run（finalize 之后），作为既有 reasons 的回归基线。"""
    project = tmp_path / "project"
    run = project / "sessions" / "run-submit"
    _complete_finding_run(run, canonical_report_required=True)
    delivery = finalize_run(
        run_dir=run, project_dir=project, authority_dir=project / ".atoolkit",
        authority_trusted=True, authorization_assurance="dry_run_no_network",
        project_name="delivery-fixture", primary_target=TARGET,
    )
    assert delivery["delivery_complete"] is True
    return run


def test_counterfeit_domain_target_rejected_with_reason(tmp_path):
    # 可提交 run 的 receipt 绑定 finding_validation.json 指向仿冒域 → 拒绝
    run = _eligible_run(tmp_path)
    validation_path = run / "finding_validation.json"
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    counterfeit = "https://fake-t.example/api/orders/1001"
    validation["normalized_findings"][0]["target"] = counterfeit
    validation_path.write_text(
        json.dumps(validation, ensure_ascii=False), encoding="utf-8")

    inspected = inspect_submission(run)

    assert inspected["eligible"] is False
    assert "finding_target_out_of_scope:fake-t.example" in inspected["reasons"]
    assert inspected["scope_check"]["source"] == "manifest"
    assert inspected["scope_check"]["targets_checked"] == 1
    assert inspected["scope_check"]["targets_rejected"] == [counterfeit]


def test_multi_asset_scope_targets_pass(tmp_path):
    # 多资产 run（4 个在册资产，v9.3 gzfsf_172 场景）→ 全部通过 scope 段
    scopes = [f"https://{name}.example/" for name in ("a", "b", "c", "d")]
    run = _synthetic_run(
        tmp_path,
        manifest=_manifest(
            primary_target=scopes[0], authorized_scopes=scopes),
        targets=[
            "https://a.example/api/orders/1001",
            "https://b.example/pay/callback",
            "https://c.example/u/1",
            "https://d.example/",
        ],
    )

    inspected = inspect_submission(run)

    assert inspected["scope_check"] == {
        "source": "manifest", "targets_checked": 4, "targets_rejected": []}
    assert not any(reason.startswith("finding_target_")
                   for reason in inspected["reasons"])


def test_derived_only_target_rejected(tmp_path):
    # 派生资产只能出现在证据包：root target 落在 derived 集合 → 拒绝
    run = _synthetic_run(
        tmp_path,
        manifest=_manifest(
            derived_assets=["https://t-example-cdn.example/"]),
        targets=["https://t-example-cdn.example/poc.png"],
    )

    inspected = inspect_submission(run)

    assert inspected["eligible"] is False
    assert ("finding_target_out_of_scope:t-example-cdn.example"
            in inspected["reasons"])
    assert inspected["scope_check"]["targets_rejected"] == [
        "https://t-example-cdn.example/poc.png"]


def test_missing_scope_source_fails_closed(tmp_path):
    # 无 manifest 且无 run_scope.json → fail closed
    run = _synthetic_run(
        tmp_path, manifest=None, targets=["https://t.example/api/orders/1001"])

    inspected = inspect_submission(run)

    assert inspected["eligible"] is False
    assert "submission_scope_source_missing" in inspected["reasons"]
    assert inspected["scope_check"] == {
        "source": "", "targets_checked": 0, "targets_rejected": []}

    # 兜底源：补 run_scope.json 后 scope 段恢复判定，在册目标通过
    _write_json(run / "run_scope.json", {
        "target_domains": [TARGET], "excluded_domains": [], "reason": "t",
    })
    rescued = inspect_submission(run)
    assert "submission_scope_source_missing" not in rescued["reasons"]
    assert rescued["scope_check"] == {
        "source": "run_scope", "targets_checked": 1, "targets_rejected": []}


def test_relative_target_resolved_against_primary_target(tmp_path):
    # MINOR-2：相对 target 按 manifest primary_target urljoin 解析取 host
    run = _synthetic_run(
        tmp_path, manifest=_manifest(),
        targets=["/api/orders/1001", "GET /api/orders/1001"],
    )

    inspected = inspect_submission(run)

    assert inspected["scope_check"] == {
        "source": "manifest", "targets_checked": 2, "targets_rejected": []}
    assert not any(reason.startswith("finding_target_")
                   for reason in inspected["reasons"])

    # 无 primary_target 时相对 target 无法解析 → fail closed
    run_no_primary = _synthetic_run(
        tmp_path / "b",
        manifest=_manifest(primary_target=""),
        targets=["/api/orders/1001"],
    )
    closed = inspect_submission(run_no_primary)
    assert closed["eligible"] is False
    assert ("finding_target_unresolvable:/api/orders/1001"
            in closed["reasons"])
    assert closed["scope_check"]["targets_rejected"] == ["/api/orders/1001"]


def test_existing_reasons_unchanged(tmp_path):
    # 回归快照：可提交 run 在 scope 校验引入后 eligible/reasons 不变
    run = _eligible_run(tmp_path)

    inspected = inspect_submission(run)

    assert inspected["eligible"] is True
    assert inspected["reasons"] == []
    assert inspected["scope_check"] == {
        "source": "manifest", "targets_checked": 1, "targets_rejected": []}

    # 篡改报告后既有哈希 reasons 逐一保持（scope 段不新增、不干扰）
    report = run / "final_report.md"
    report.write_text(
        report.read_text(encoding="utf-8") + "\ntampered\n", encoding="utf-8")
    tampered = inspect_submission(run)
    assert tampered["eligible"] is False
    assert tampered["reasons"] == [
        "canonical_report_hash_mismatch", "receipt_report_hash_mismatch"]
    assert tampered["scope_check"]["targets_rejected"] == []
