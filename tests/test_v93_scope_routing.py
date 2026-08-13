"""v9.3：多资产授权收口与运行环境路由的回归测试。

实证背景（gzfsf_20260813_blackbox）：Direct 模式 checkpoint 只用单一
`metadata.target` 当授权列表，导致其他在册资产上的 finding 全部
"target out of authorized hosts" 被拒；中途扩资产无通道；非 Codex IDE
误跑 run.py 拉起外部 codex/gpt 后端。
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import run
from engine.reporting.schema import load_finding
from engine.reporting.validate import ValidationContext, validate_finding
from engine.host_policy import normalize_authorized_scopes
from engine.skill_runtime import (
    checkpoint_direct_run,
    initialize_direct_run,
    parse_scope_file,
    scope_direct_run,
)
from tests.test_reporting_proof_contract import _idor_fixture


def _write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _retarget_fixture(fdir: pathlib.Path, host_url: str, host: str) -> None:
    """把 idor fixture 的 target/Host 改写到指定在册资产。"""
    finding_path = fdir / "finding.json"
    finding = json.loads(finding_path.read_text(encoding="utf-8"))
    finding["target"] = f"{host_url}/api/orders/1001"
    finding_path.write_text(json.dumps(finding, ensure_ascii=False, indent=2),
                            encoding="utf-8")
    for name in ("request_owner.http", "request_attacker.http", "request_denied.http"):
        path = fdir / name
        path.write_text(path.read_text(encoding="utf-8").replace(
            "Host: t.example", f"Host: {host}"), encoding="utf-8")
    poc = fdir / "poc.sh"
    poc.write_text(poc.read_text(encoding="utf-8").replace(
        "https://t.example", host_url), encoding="utf-8")


def _init_run(tmp_path: pathlib.Path, **kwargs) -> pathlib.Path:
    run_dir = tmp_path / "run-1"
    inventory = tmp_path / "inventory.json"
    _write_json(inventory, {"surfaces": [{
        "endpoint": "/api/orders/1001", "method": "GET", "params": ["id"],
    }]})
    initialize_direct_run(
        run_dir=run_dir, target="https://a.example/",
        inventory_path=inventory, **kwargs)
    return run_dir


def test_checkpoint_accepts_finding_on_second_authorized_asset(tmp_path):
    """gzfsf 实证回归：第二在册资产上的 finding 不得再被 scope 误杀。"""
    run_dir = _init_run(tmp_path, extra_scopes=["https://b.example/"])
    fdir = _idor_fixture(run_dir)
    _retarget_fixture(fdir, "https://b.example", "b.example")

    checkpoint = checkpoint_direct_run(run_dir)

    validation = checkpoint["finding_validation"]
    assert validation["accepted"] == 1, validation["rejected_items"]


def test_checkpoint_still_rejects_out_of_scope_asset(tmp_path):
    run_dir = _init_run(tmp_path)
    fdir = _idor_fixture(run_dir)
    _retarget_fixture(fdir, "https://b.example", "b.example")

    checkpoint = checkpoint_direct_run(run_dir)

    rejected = checkpoint["finding_validation"]["rejected_items"]
    assert rejected
    assert any("out of authorized hosts" in reason
               for reason in rejected[0]["reasons"])


def test_scope_command_appends_mid_run_asset_with_audit(tmp_path):
    """中途扩资产：scope --add 后新资产上的 finding 可 accepted，且留审计。"""
    run_dir = _init_run(tmp_path)
    fdir = _idor_fixture(run_dir)
    _retarget_fixture(fdir, "https://b.example", "b.example")

    result = scope_direct_run(
        run_dir, add=["https://b.example/"], reason="客户中途补充端口资产")
    assert result["added_scopes"] == normalize_authorized_scopes(
        ["https://b.example/"])
    audit = (run_dir / "state" / "scope-audit.jsonl").read_text(encoding="utf-8")
    assert "客户中途补充端口资产" in audit

    checkpoint = checkpoint_direct_run(run_dir)
    assert checkpoint["finding_validation"]["accepted"] == 1

    # 重复添加去重，不再产生新条目
    again = scope_direct_run(run_dir, add=["https://b.example/"])
    assert again["added_scopes"] == []
    assert again["authorized_scopes"] == result["authorized_scopes"]


def test_scope_file_markdown_and_json_parsing(tmp_path):
    authz = tmp_path / "AUTHZ.md"
    authz.write_text(
        "# 授权声明\n\n"
        "## 授权 Scope（在册资产，超出即停）\n"
        "- https://a.example/\n"
        "1. https://b.example:8443/\n\n"
        "## 派生资产（仅作证据目标）\n"
        "- https://bucket.oss-cn-beijing.aliyuncs.com/\n",
        encoding="utf-8")
    scopes, derived = parse_scope_file(authz)
    assert scopes == ["https://a.example/", "https://b.example:8443/"]
    assert derived == ["https://bucket.oss-cn-beijing.aliyuncs.com/"]

    scope_json = tmp_path / "run_scope.json"
    _write_json(scope_json, {
        "target_domains": ["https://c.example/"],
        "derived_assets": ["https://cdn.example/"],
    })
    scopes, derived = parse_scope_file(scope_json)
    assert scopes == ["https://c.example/"]
    assert derived == ["https://cdn.example/"]


def test_init_scope_file_populates_ledger_metadata(tmp_path):
    authz = tmp_path / "AUTHZ.md"
    authz.write_text(
        "## 授权 Scope\n- https://a.example/\n- https://b.example/\n\n"
        "## 派生资产\n- https://bucket.oss.example/\n",
        encoding="utf-8")
    run_dir = _init_run(tmp_path, scope_files=[authz])

    ledger = json.loads(
        (run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
    metadata = ledger["metadata"]
    assert metadata["authorized_scopes"] == normalize_authorized_scopes(
        ["https://a.example/", "https://b.example/"])
    assert metadata["derived_assets"] == normalize_authorized_scopes(
        ["https://bucket.oss.example/"])

    fdir = _idor_fixture(run_dir)
    _retarget_fixture(fdir, "https://b.example", "b.example")
    checkpoint = checkpoint_direct_run(run_dir)
    assert checkpoint["finding_validation"]["accepted"] == 1


def _derived_packet_context() -> ValidationContext:
    return ValidationContext.from_manifest({
        "primary_target": "https://a.example/",
        "authorized_scopes": ["https://a.example/"],
        "derived_scopes": ["https://bucket.oss.example/"],
    })


def _derived_packet_fixture(tmp_path: pathlib.Path) -> pathlib.Path:
    """idor fixture，owner 证据包指向派生 OSS 资产（绝对 URL 形式）。"""
    fdir = _idor_fixture(tmp_path)
    _retarget_fixture(fdir, "https://a.example", "a.example")
    (fdir / "request_owner.http").write_text(
        "GET https://bucket.oss.example/comprehensivepay/poc.html HTTP/1.1\n"
        "Host: bucket.oss.example\nCookie: sid=owner-a\n\n", encoding="utf-8")
    return fdir


def test_derived_asset_packet_allowed_with_in_scope_issued_by(tmp_path):
    fdir = _derived_packet_fixture(tmp_path)
    finding = load_finding(fdir / "finding.json")
    finding["verification"]["issued_by"] = "https://a.example/comprehensive/oss-sign"
    result = validate_finding(
        finding, fdir / "finding.json", tmp_path, context=_derived_packet_context())
    assert result.ok, result.reasons


def test_derived_asset_packet_rejected_without_issued_by(tmp_path):
    fdir = _derived_packet_fixture(tmp_path)
    finding = load_finding(fdir / "finding.json")
    result = validate_finding(
        finding, fdir / "finding.json", tmp_path, context=_derived_packet_context())
    assert not result.ok
    assert any("out of authorized scopes" in reason for reason in result.reasons)


def test_derived_asset_packet_rejected_when_issued_by_out_of_scope(tmp_path):
    fdir = _derived_packet_fixture(tmp_path)
    finding = load_finding(fdir / "finding.json")
    finding["verification"]["issued_by"] = "https://evil.example/oss-sign"
    result = validate_finding(
        finding, fdir / "finding.json", tmp_path, context=_derived_packet_context())
    assert not result.ok
    assert any("out of authorized scopes" in reason for reason in result.reasons)


def test_run_py_live_run_requires_explicit_via_attestation(tmp_path):
    """非 Codex 环境误跑 run.py：无 --via 时必须在拉起适配器之前 fail closed。"""
    result = subprocess.run(
        [
            sys.executable,
            str(run.ROOT / "run.py"),
            "--target", "https://t.example/login/",
            "--authz", "authorized fixture",
            "--ad-hoc",
        ],
        cwd=run.ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert "--via codex" in result.stderr
    assert "engine.skill_runtime" in result.stderr
