"""v9.8.2 W1：scope 输入边界归一回归测试。

设计文档：design/迭代方案/v9.8.2_哲学归位与框架指纹路由.md §W1（B1/N1/N2 修订）。
- 带非空非 "/" 的 path/query/fragment 的 URL 在三个输入边界归一到 origin：
  Direct init（_resolve_scope_inputs）、scope --add（scope_direct_run）、
  Engine CLI（run.py --target/--allow）；每次归一 stdout warning +
  state/scope-audit.jsonl 记 {"action":"scope_path_normalized",...}。
- path="/" 或空、纯域名/IP/通配 → 原样；userinfo → 维持 fail closed。
- 严禁改验证期行为：normalize_authorized_scopes / is_authorized_url 对存量
  带路径 scope 的判定逐字节不变（路径钉定是有测试背书的安全特性）。
"""
from __future__ import annotations

import json
import pathlib

import run
from engine.host_policy import (
    is_authorized_url,
    normalize_authorized_scopes,
    parse_authorized_scope,
    strip_scope_path_with_warning,
)
from engine.skill_runtime import (
    initialize_direct_run,
    preflight_direct_run,
    scope_direct_run,
)

TARGET = "https://t.example/"


def _write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _inventory(tmp_path: pathlib.Path) -> pathlib.Path:
    path = tmp_path / "inventory.json"
    _write_json(path, {"surfaces": [
        {"endpoint": "/api/orders/1001", "method": "GET", "params": ["id"]},
    ]})
    return path


def _audit_lines(run_dir: pathlib.Path) -> list[dict]:
    path = run_dir / "state" / "scope-audit.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


# ── 归一规则单元测试 ──────────────────────────────────────────────────────

def test_strip_rules_path_query_fragment_to_origin():
    normalized, warning = strip_scope_path_with_warning(
        "https://host.example:20002/login")
    assert normalized == "https://host.example:20002"
    assert warning and "/login" in warning

    normalized, warning = strip_scope_path_with_warning(
        "https://host.example?x=1")
    assert normalized == "https://host.example"
    assert warning

    normalized, warning = strip_scope_path_with_warning(
        "http://host.example:8080/app#frag")
    assert normalized == "http://host.example:8080"
    assert warning


def test_strip_rules_passthrough_forms():
    for value in (
        "https://host.example",          # 空 path
        "https://host.example/",          # path == "/"
        "host.example",                   # 纯域名
        "host.example:8080",              # 域名+端口
        "192.0.2.10",                     # 纯 IP
        "192.0.2.10:8180",                # IP+端口
        "*.example.com",                  # 通配
    ):
        normalized, warning = strip_scope_path_with_warning(value)
        assert normalized == value, value
        assert warning is None, value


def test_strip_userinfo_keeps_fail_closed():
    value = "https://user:pass@host.example/login"
    normalized, warning = strip_scope_path_with_warning(value)
    # userinfo 不归一、不扩权：原样返回，交给下游 parse 维持 fail closed
    assert normalized == value
    assert warning is None
    assert parse_authorized_scope(normalized) is None


# ── 验证期行为不变（存量 Run 不 retroactive 改判）────────────────────────

def test_stored_path_pinned_scope_semantics_unchanged():
    # 存量带路径 scope 的路径钉定收窄保持原样（B1：这是安全特性，不许动）
    scopes = normalize_authorized_scopes(["https://h.example:20002/login"])
    assert scopes == ["https://h.example:20002/login"]
    assert not is_authorized_url("https://h.example:20002/prod-api/x", scopes)
    assert is_authorized_url("https://h.example:20002/login", scopes)
    assert is_authorized_url("https://h.example:20002/login/sub", scopes)
    # 归一后的 origin scope 则覆盖整站——这正是输入边界归一的目的
    origin = normalize_authorized_scopes(["https://h.example:20002"])
    assert is_authorized_url("https://h.example:20002/prod-api/x", origin)


# ── 边界 1：Direct init（_resolve_scope_inputs）───────────────────────────

def test_direct_init_allow_with_path_normalized_warned_audited(tmp_path, capsys):
    run_dir = tmp_path / "run"
    initialize_direct_run(
        run_dir=run_dir, target=TARGET,
        inventory_path=_inventory(tmp_path),
        extra_scopes=["https://b.example/login"])

    ledger = json.loads(
        (run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
    scopes = ledger["metadata"]["authorized_scopes"]
    assert "https://b.example:443/" in scopes
    assert not any("/login" in scope for scope in scopes)

    out = capsys.readouterr().out
    assert out.count("[scope-normalize]") == 1  # preflight 打一次，init 不重复
    assert "https://b.example/login" in out

    audit = _audit_lines(run_dir)
    records = [row for row in audit
               if row.get("action") == "scope_path_normalized"]
    assert len(records) == 1
    assert records[0]["from"] == "https://b.example/login"
    assert records[0]["to"] == "https://b.example"


def test_direct_init_target_with_path_normalized(tmp_path, capsys):
    run_dir = tmp_path / "run"
    initialize_direct_run(
        run_dir=run_dir, target="https://t.example/login",
        inventory_path=_inventory(tmp_path))

    ledger = json.loads(
        (run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
    assert ledger["metadata"]["authorized_scopes"] == [
        "https://t.example:443/"]
    assert "[scope-normalize]" in capsys.readouterr().out
    records = [row for row in _audit_lines(run_dir)
               if row.get("action") == "scope_path_normalized"]
    assert records and records[0]["to"] == "https://t.example"


def test_direct_init_scope_file_with_path_normalized(tmp_path, capsys):
    authz = tmp_path / "AUTHZ.md"
    authz.write_text(
        "## 授权 Scope\n- https://a.example/\n- https://b.example/admin\n",
        encoding="utf-8")
    run_dir = tmp_path / "run"
    initialize_direct_run(
        run_dir=run_dir, target=TARGET,
        inventory_path=_inventory(tmp_path),
        scope_files=[authz])

    ledger = json.loads(
        (run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
    scopes = ledger["metadata"]["authorized_scopes"]
    assert "https://b.example:443/" in scopes
    assert "https://a.example:443/" in scopes
    assert "[scope-normalize]" in capsys.readouterr().out
    records = [row for row in _audit_lines(run_dir)
               if row.get("action") == "scope_path_normalized"]
    assert len(records) == 1
    assert records[0]["from"] == "https://b.example/admin"


def test_direct_init_clean_scopes_silent(tmp_path, capsys):
    run_dir = tmp_path / "run"
    preflight_direct_run(
        run_dir=run_dir, target=TARGET,
        extra_scopes=["https://b.example/", "c.example:8080", "*.d.example"])

    assert "[scope-normalize]" not in capsys.readouterr().out
    assert _audit_lines(run_dir) == []


# ── 边界 2：Direct 中途扩范围（scope --add）───────────────────────────────

def test_scope_add_with_path_normalized_warned_audited(tmp_path, capsys):
    run_dir = tmp_path / "run"
    initialize_direct_run(
        run_dir=run_dir, target=TARGET, inventory_path=_inventory(tmp_path))
    capsys.readouterr()  # 清掉 init 输出

    result = scope_direct_run(
        run_dir, add=["https://b.example/login"], reason="补录资产")

    assert result["added_scopes"] == ["https://b.example:443/"]
    out = capsys.readouterr().out
    assert "[scope-normalize]" in out and "https://b.example" in out
    records = [row for row in _audit_lines(run_dir)
               if row.get("action") == "scope_path_normalized"]
    assert len(records) == 1
    assert records[0]["from"] == "https://b.example/login"
    assert records[0]["to"] == "https://b.example"
    # 主审计条目仍然存在（扩范围留痕不被归一记录替代）
    assert any("补录资产" in json.dumps(row, ensure_ascii=False)
               for row in _audit_lines(run_dir))


def test_scope_add_clean_url_no_normalization(tmp_path, capsys):
    run_dir = tmp_path / "run"
    initialize_direct_run(
        run_dir=run_dir, target=TARGET, inventory_path=_inventory(tmp_path))
    capsys.readouterr()

    result = scope_direct_run(run_dir, add=["https://b.example/"])

    assert result["added_scopes"] == ["https://b.example:443/"]
    assert "[scope-normalize]" not in capsys.readouterr().out
    assert not any(row.get("action") == "scope_path_normalized"
                   for row in _audit_lines(run_dir))


# ── 边界 3：Engine CLI（run.py --target/--allow）──────────────────────────

def test_engine_cli_scope_inputs_strip_target_and_allow():
    target, allow, normalizations = run._strip_cli_scope_inputs(
        "https://t.example/login",
        ["t2.example", "https://t3.example/admin?x=1", "*.t4.example"])

    assert target == "https://t.example"
    assert allow == ["t2.example", "https://t3.example", "*.t4.example"]
    assert normalizations == [
        ("https://t.example/login", "https://t.example"),
        ("https://t3.example/admin?x=1", "https://t3.example"),
    ]


def test_engine_cli_scope_inputs_clean_passthrough():
    target, allow, normalizations = run._strip_cli_scope_inputs(
        "https://t.example/", ["t2.example", "https://t3.example/"])
    assert target == "https://t.example/"
    assert allow == ["t2.example", "https://t3.example/"]
    assert normalizations == []
