"""Tests for the read-only module_map derived view (engine/module_map.py)."""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine import module_map  # noqa: E402


def _endpoint(path, method="GET", params=None, source=""):
    row = {"endpoint": path, "method": method, "params": params or []}
    if source:
        row["provenance"] = [{"source_file": f"/recon/{source}"}]
    return row


def _write_run(tmp_path, endpoints, surfaces=None):
    (tmp_path / "inventory.json").write_text(
        json.dumps({"endpoints": endpoints}), encoding="utf-8")
    if surfaces is not None:
        (tmp_path / "coverage-ledger.json").write_text(
            json.dumps({"schema_version": 1, "surfaces": surfaces}),
            encoding="utf-8")
    return module_map.build_module_map(tmp_path)


def _module(result, module_id):
    for module in result["modules"]:
        if module["module_id"] == module_id:
            return module
    return None


def test_prefix_grouping_and_labels(tmp_path):
    endpoints = [
        _endpoint("/api/admin/login.php", "POST", ["username"], "admin.js"),
        _endpoint("/api/admin/user-list.php", "GET", [], "admin.js"),
        _endpoint("/api/admin/lock.php", "POST", ["user_id"], "admin.js"),
        _endpoint("/api/user/login.php", "POST", ["username"], "user.js"),
        _endpoint("/api/user/profile.php", "GET", [], "user1_index.html"),
        _endpoint("/api/user/orders.php", "GET", [], "user.js"),
    ]
    result = _write_run(tmp_path, endpoints)
    ids = {m["module_id"] for m in result["modules"]}
    assert ids == {"api/admin", "api/user"}
    assert _module(result, "api/admin")["label"] == "管理后台"
    assert _module(result, "api/user")["label"] == "用户"
    assert result["scale"]["endpoint_count"] == 6


def test_small_groups_merge_into_misc(tmp_path):
    endpoints = [
        _endpoint("/a/one.php"), _endpoint("/a/two.php"),
        _endpoint("/b/one.php"), _endpoint("/b/two.php"),
        _endpoint("/c/one.php"), _endpoint("/c/two.php"),
        _endpoint("/c/three.php"),
    ]
    result = _write_run(tmp_path, endpoints)
    ids = {m["module_id"] for m in result["modules"]}
    assert "c" in ids
    assert "_misc" in ids
    assert _module(result, "_misc")["endpoint_count"] == 4


def test_probe_and_pages_segregated(tmp_path):
    endpoints = [
        _endpoint("/.git/config"),
        _endpoint("/favicon.ico"),
        _endpoint("/index.php"),
        _endpoint("/api/a/1.php"), _endpoint("/api/a/2.php"),
        _endpoint("/api/a/3.php"),
    ]
    result = _write_run(tmp_path, endpoints)
    assert _module(result, "_probe")["endpoint_count"] == 2
    assert _module(result, "_pages")["endpoint_count"] == 1
    assert _module(result, "api")["endpoint_count"] == 3


def test_deployment_base_prefix_stripped_and_deduped(tmp_path):
    endpoints = [
        _endpoint("/api/admin/login.php", "POST"),
        _endpoint("/range/pentest/shop/api/admin/login.php", "POST"),
        _endpoint("/range/pentest/shop/api/admin/users.php", "GET"),
        _endpoint("/api/admin/users.php", "GET"),
        _endpoint("/api/admin/audit.php", "POST"),
        _endpoint("/range/pentest/shop/api/admin/audit.php", "POST"),
    ]
    result = _write_run(tmp_path, endpoints)
    module = _module(result, "api")
    assert module is not None
    assert module["endpoint_count"] == 3
    assert result["scale"]["endpoint_count"] == 3


def test_functional_prefix_not_stripped(tmp_path):
    # Everything lives under /api/: 100% coverage must not be stripped.
    endpoints = [
        _endpoint("/api/merchant/login.php", "POST"),
        _endpoint("/api/merchant/product-add.php", "POST"),
        _endpoint("/api/merchant/product-list.php", "GET"),
        _endpoint("/api/user/login.php", "POST"),
        _endpoint("/api/user/orders.php", "GET"),
        _endpoint("/api/user/profile.php", "GET"),
    ]
    result = _write_run(tmp_path, endpoints)
    ids = {m["module_id"] for m in result["modules"]}
    assert ids == {"api/merchant", "api/user"}


def test_flat_singletons_not_split(tmp_path):
    # Duplicate methods on one endpoint must not count as sub-modules.
    endpoints = [
        _endpoint(f"/api/ep-{index}", "GET") for index in range(8)
    ] + [
        _endpoint("/api/my-bugs/{id}", "GET"),
        _endpoint("/api/my-bugs/{id}", "POST"),
    ]
    result = _write_run(tmp_path, endpoints)
    assert _module(result, "api")["endpoint_count"] == 10
    assert _module(result, "_misc") is None


def test_coverage_and_roles_from_ledger(tmp_path):
    endpoints = [
        _endpoint("/api/pay/refund.php", "POST"),
        _endpoint("/api/pay/order.php", "POST"),
        _endpoint("/api/pay/recharge.php", "POST"),
    ]
    surfaces = [
        {"endpoint": "/api/pay/refund.php", "method": "POST", "param": "order_no",
         "roles": ["user", "attacker"], "status": "confirmed",
         "risk_tags": ["amount-tamper"]},
        {"endpoint": "/api/pay/order.php", "method": "POST", "param": "",
         "role": "merchant", "status": "not_tested",
         "risk_tags": ["idor"]},
    ]
    result = _write_run(tmp_path, endpoints, surfaces)
    module = _module(result, "api")
    assert module["coverage"] == {"confirmed": 1, "not_tested": 1}
    assert module["roles"] == ["attacker", "merchant", "user"]
    assert module["high_value_open"] == 1
    assert result["scale"]["cell_count"] == 2
    assert result["scale"]["high_value_open"] == 1


def test_ledger_only_fallback(tmp_path):
    surfaces = [
        {"endpoint": "/api/bugs", "method": "GET", "param": "-",
         "role": "anon", "status": "confirmed"},
        {"endpoint": "/api/bugs", "method": "POST", "param": "id",
         "role": "user", "status": "not_tested"},
    ]
    (tmp_path / "coverage-ledger.json").write_text(
        json.dumps({"schema_version": 1, "surfaces": surfaces}),
        encoding="utf-8")
    result = module_map.build_module_map(tmp_path)
    assert result["scale"]["endpoint_count"] == 2
    assert result["scale"]["cell_count"] == 2


def test_scale_assessment_boundaries():
    small = module_map.scale_assessment(
        endpoint_count=79, module_count=3, role_count=2,
        cell_count=100, high_value_open=0)
    assert small["level"] == "small"
    medium = module_map.scale_assessment(
        endpoint_count=80, module_count=3, role_count=2,
        cell_count=100, high_value_open=0)
    assert medium["level"] == "medium"
    large_by_cells = module_map.scale_assessment(
        endpoint_count=50, module_count=3, role_count=2,
        cell_count=501, high_value_open=0)
    assert large_by_cells["level"] == "large"
    large_by_modules = module_map.scale_assessment(
        endpoint_count=100, module_count=9, role_count=2,
        cell_count=100, high_value_open=0)
    assert large_by_modules["level"] == "large"


def test_render_and_write(tmp_path):
    _write_run(tmp_path, [
        _endpoint("/api/a/1.php"), _endpoint("/api/a/2.php"),
        _endpoint("/api/a/3.php"),
    ])
    result = module_map.write_module_map(tmp_path)
    assert (tmp_path / "module_map.json").is_file()
    md = (tmp_path / "module_map.md").read_text(encoding="utf-8")
    assert "Module Map" in md
    assert "api/a" in md
    assert result["scale"]["endpoint_count"] == 3
    # Existing artifacts must remain untouched (read-only view).
    assert (tmp_path / "inventory.json").is_file()
