"""v9.8.2 W2：框架指纹路由回归测试。

设计文档：design/迭代方案/v9.8.2_哲学归位与框架指纹路由.md §W2（M1/M2/N3/N4 修订）。
- ruoyi.json 框架卡 schema：card_id/framework/last_verified/
  verified_against_version/fingerprints/prefix_variants/known_surfaces（无部署
  前缀）/default_credentials。
- init 读 <recon_dir>/framework_fingerprint.md 首行 `framework: <name>` →
  加载 knowledge/cards/frameworks/<name>.json → 冻结前打 framework_hit=true
  （prefix_variants × path_prefix 笛卡尔展开、大小写不敏感路径前缀匹配、
  先剥 query/fragment）；已知面未覆盖端点输出 advisory（不自动入 inventory）。
- 冻结排序键 (identity_blocked, high_value, framework_hit, feature,
  surface_id)：framework_hit 只做 high_value 之后的 tie-breaker（M1 回归：
  高价值业务格不被低价值卡片格挤位）；无卡环境该维恒 1，两次 init 逐字节一致。
"""
from __future__ import annotations

import json
import pathlib

from engine import skill_runtime
from engine.ledger import CoverageLedger
from engine.skill_runtime import (
    _freeze_budget_capped,
    initialize_direct_run,
)

TARGET = "https://t.example/"


def _write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _inventory(tmp_path: pathlib.Path, rows: list[dict]) -> pathlib.Path:
    path = tmp_path / "inventory.json"
    _write_json(path, {"surfaces": rows})
    return path


def _recon_with_fingerprint(tmp_path: pathlib.Path) -> pathlib.Path:
    recon = tmp_path / "recon"
    recon.mkdir()
    (recon / "framework_fingerprint.md").write_text(
        "framework: ruoyi\n\n命中指纹：captchaImage 端点 + com.ruoyi 类名\n",
        encoding="utf-8")
    return recon


def _load_card() -> dict:
    card_path = skill_runtime._framework_cards_dir() / "ruoyi.json"
    return json.loads(card_path.read_text(encoding="utf-8"))


def _surface(surface_id: str, endpoint: str, **extra) -> dict:
    surface = {
        "surface_id": surface_id,
        "endpoint": endpoint,
        "method": "GET",
        "param": "",
        "roles": ["anonymous"],
        "status": "not_tested",
        "in_run_scope": True,
        "feature": "",
    }
    surface.update(extra)
    return surface


def _freeze(tmp_path: pathlib.Path, surfaces: list[dict], cap: int):
    run = tmp_path / "run"
    run.mkdir(parents=True)
    ledger = CoverageLedger(surfaces, metadata={"sid": "run", "target": TARGET})
    pool = _freeze_budget_capped(run, ledger, cap)
    return ledger, pool


# ── 卡片 schema ───────────────────────────────────────────────────────────

def test_ruoyi_card_schema_and_coverage():
    card = _load_card()
    for key in ("card_id", "framework", "last_verified",
                "verified_against_version", "fingerprints", "prefix_variants",
                "known_surfaces", "default_credentials"):
        assert key in card, key
    assert card["card_id"] == "framework.ruoyi"
    assert card["framework"] == "ruoyi"
    assert card["last_verified"] and card["verified_against_version"]
    assert card["fingerprints"]
    assert "/prod-api" in card["prefix_variants"] and "" in card["prefix_variants"]

    surfaces = card["known_surfaces"]
    prefixes = {item["path_prefix"] for item in surfaces}
    # §0 病因清单全部端点 + initPassword 配置面
    assert {"/druid", "/monitor/job", "/tool/swagger", "/v2/api-docs",
            "/actuator", "/common/download", "/system/role/export"} <= prefixes
    assert any("initPassword" in item["hypothesis"] for item in surfaces)
    for item in surfaces:
        assert item["path_prefix"].startswith("/")
        assert item["hypothesis"] and item["role"]
        # N4：known_surfaces 不硬编码部署前缀（前缀由 prefix_variants 承载）
        assert not item["path_prefix"].startswith("/prod-api")
    for cred in card["default_credentials"]:
        assert cred["user"] and cred["pass"]


# ── 匹配语义：prefix_variants × path_prefix 展开 ──────────────────────────

def test_prefix_variants_cartesian_expansion_matching():
    card = _load_card()
    prefixes = skill_runtime._framework_expanded_prefixes(card)
    assert "/prod-api/druid" in prefixes and "/druid" in prefixes

    hit = skill_runtime._framework_hit
    assert hit("/druid", prefixes)
    assert hit("/druid/index", prefixes)
    assert hit("/prod-api/druid", prefixes)
    assert hit("/prod-api/druid/index?x=1", prefixes)       # query 先剥
    assert hit("/PROD-API/DRUID", prefixes)                  # 大小写不敏感
    assert hit("https://t.example/prod-api/druid", prefixes)  # 绝对 URL 剥 authority
    assert not hit("/api/druidic", prefixes)
    assert not hit("/api/orders", prefixes)
    assert not hit("", prefixes)


# ── init 链路：指纹命中 → 打标 → advisory ─────────────────────────────────

def test_init_fingerprint_hit_marks_surfaces_and_advises(tmp_path, capsys):
    recon = _recon_with_fingerprint(tmp_path)
    inventory = _inventory(tmp_path, [
        {"endpoint": "/prod-api/druid", "method": "GET", "params": ["id"]},
        {"endpoint": "/api/orders/{id}", "method": "GET", "params": ["id"],
         "roles": ["user"]},
    ])
    run_dir = tmp_path / "run"
    initialize_direct_run(
        run_dir=run_dir, target=TARGET,
        inventory_path=inventory, recon_dir=recon)

    ledger = json.loads(
        (run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
    hit = [s for s in ledger["surfaces"]
           if str(s["endpoint"]).startswith("/prod-api/druid")]
    miss = [s for s in ledger["surfaces"]
            if str(s["endpoint"]).startswith("/api/orders")]
    assert hit and all(s.get("framework_hit") is True for s in hit)
    assert miss and all("framework_hit" not in s for s in miss)

    out = capsys.readouterr().out
    assert "命中框架卡 framework.ruoyi" in out
    # 已知面中未入 inventory 的端点输出 advisory（不自动扩面）+ 回路提示
    assert "未覆盖端点" in out and "/actuator" in out
    assert "重跑 init" in out and "checkpoint" in out


def test_init_missing_fingerprint_prints_advisory(tmp_path, capsys):
    recon = tmp_path / "recon"
    recon.mkdir()
    (recon / "app.js").write_text("fetch('/api/orders');\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    initialize_direct_run(
        run_dir=run_dir, target=TARGET,
        inventory_path=_inventory(tmp_path, [
            {"endpoint": "/api/orders", "method": "GET", "params": ["id"]},
        ]),
        recon_dir=recon)

    out = capsys.readouterr().out
    assert "[framework] advisory" in out and "framework_fingerprint.md" in out


def test_init_unknown_framework_degrades_to_advisory(tmp_path, capsys):
    recon = tmp_path / "recon"
    recon.mkdir()
    (recon / "framework_fingerprint.md").write_text(
        "framework: nosuchframework\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    initialize_direct_run(
        run_dir=run_dir, target=TARGET,
        inventory_path=_inventory(tmp_path, [
            {"endpoint": "/api/orders", "method": "GET", "params": ["id"]},
        ]),
        recon_dir=recon)

    out = capsys.readouterr().out
    assert "[framework] advisory" in out and "nosuchframework" in out
    ledger = json.loads(
        (run_dir / "coverage-ledger.json").read_text(encoding="utf-8"))
    assert all("framework_hit" not in s for s in ledger["surfaces"])


# ── 冻结排序 tie-breaker（M1 回归）────────────────────────────────────────

def test_framework_hit_never_outranks_high_value_business_cell(tmp_path):
    # M1 回归断言：低价值卡片命中格不得挤掉高价值业务格（Ruoyi 冻结错配换皮）。
    # 注意用 /actuator 而不是 /druid 做低价值卡片格——normalize_surface 会把
    # "/druid" 里的 "id" 子串推成 idor 高价值标签，用它当低价值格是错误前提。
    ledger, pool = _freeze(tmp_path, [
        _surface("s-card", "/actuator", framework_hit=True),     # 低价值 + 命中
        _surface("s-biz", "/api/order/refund", param="id"),       # 高价值（order/refund）
    ], cap=1)

    assert [s["surface_id"] for s in ledger.surfaces] == ["s-biz"]
    assert [s["surface_id"] for s in pool] == ["s-card"]


def test_framework_hit_tiebreaks_within_same_value_tier(tmp_path):
    # 同价值级内命中格排前（两个都是 general-review 低价值格）
    ledger, pool = _freeze(tmp_path, [
        _surface("s-plain", "/static/info"),                      # 低价值、未命中
        _surface("s-hit", "/actuator", framework_hit=True),       # 低价值、命中
    ], cap=1)

    assert [s["surface_id"] for s in ledger.surfaces] == ["s-hit"]
    assert [s["surface_id"] for s in pool] == ["s-plain"]


def test_identity_blocked_still_outranks_framework_hit(tmp_path):
    ledger, pool = _freeze(tmp_path, [
        _surface("s-blocked-hit", "/actuator", framework_hit=True,
                 identity_blocked=True),
        _surface("s-reachable", "/static/info"),
    ], cap=1)

    assert [s["surface_id"] for s in ledger.surfaces] == ["s-reachable"]
    assert pool[0]["surface_id"] == "s-blocked-hit"
    assert pool[0]["deferred_reason"] == "identity_cap"


# ── 无卡环境确定性 ─────────────────────────────────────────────────────────

def test_no_card_environment_is_byte_identical(tmp_path, capsys):
    inventory = _inventory(tmp_path, [
        {"endpoint": f"/api/order{index}", "method": "GET", "params": ["id"],
         "roles": ["user"]}
        for index in range(1, 26)  # > 默认 20 格预算，触发冻结路径
    ])
    run_a = tmp_path / "a" / "run"
    run_b = tmp_path / "b" / "run"
    initialize_direct_run(
        run_dir=run_a, target=TARGET, inventory_path=inventory,
        max_frozen_cells=20)
    initialize_direct_run(
        run_dir=run_b, target=TARGET, inventory_path=inventory,
        max_frozen_cells=20)
    capsys.readouterr()

    assert (run_a / "coverage-ledger.json").read_bytes() == (
        run_b / "coverage-ledger.json").read_bytes()
    assert (run_a / "deferred-pool.json").read_bytes() == (
        run_b / "deferred-pool.json").read_bytes()
    ledger = json.loads(
        (run_a / "coverage-ledger.json").read_text(encoding="utf-8"))
    assert all("framework_hit" not in s for s in ledger["surfaces"])
