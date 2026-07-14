"""v8.9 recon/planner regressions derived from the 2026-07-13 shop run."""
from __future__ import annotations

import json
from pathlib import Path

from engine.planner import infer_roles, plan_surfaces
from engine.surface import bootstrap


def _by_endpoint(rows: list[dict], endpoint: str) -> list[dict]:
    return [row for row in rows if row.get("endpoint") == endpoint]


def test_detached_js_and_json_paths_are_unresolved_and_observation_suppresses_hint(tmp_path):
    (tmp_path / "app.js").write_text(
        """
        const hint = '/api/hint-only.php';
        const observed = '/api/observed.php';
        fetch(observed);
        const dynamicOptions = buildOptionsAtRuntime();
        fetch('/api/dynamic-options.php', dynamicOptions);
        fetch('/api/dynamic-method.php', {method: `${runtimeMethod}`});
        """,
        encoding="utf-8",
    )
    (tmp_path / "snapshot.json").write_text(
        json.dumps({"next": "/api/json-only.php", "other": "/api/observed.php"}),
        encoding="utf-8",
    )

    rows = bootstrap(tmp_path)
    assert {row["method"] for row in _by_endpoint(rows, "/api/hint-only.php")} == {""}
    assert {row["method"] for row in _by_endpoint(rows, "/api/json-only.php")} == {""}
    assert {row["method"] for row in _by_endpoint(rows, "/api/dynamic-options.php")} == {""}
    assert {row["method"] for row in _by_endpoint(rows, "/api/dynamic-method.php")} == {""}

    observed_rows = _by_endpoint(rows, "/api/observed.php")
    assert {row["method"] for row in observed_rows} == {"GET"}
    assert observed_rows[0]["method_confidence"] == "observed"
    assert observed_rows[0]["suppressed_unresolved_provenance"]


def test_local_ternary_urls_and_fetch_body_are_extracted_without_option_keys(tmp_path):
    (tmp_path / "app.js").write_text(
        """
        function save(editing) {
          const data = {name: name, price: price};
          data.product_no = productNo;
          const url = editing ? '/api/item-edit.php' : '/api/item-add.php';
          jsonPost(url, data);
        }
        fetch('/api/refund.php?order_no=' + encodeURIComponent(orderNo), {
          method: 'PATCH',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({amount: amount, reason: reason})
        });
        """,
        encoding="utf-8",
    )

    rows = bootstrap(tmp_path)
    for endpoint in ("/api/item-edit.php", "/api/item-add.php"):
        row = _by_endpoint(rows, endpoint)
        assert len(row) == 1
        assert row[0]["method"] == "POST"
        assert set(row[0]["params"]) == {"name", "price", "product_no"}

    refund = _by_endpoint(rows, "/api/refund.php")
    assert len(refund) == 1
    assert refund[0]["method"] == "PATCH"
    assert set(refund[0]["params"]) == {"order_no", "amount", "reason"}
    assert refund[0]["query_params"] == ["order_no"]
    assert set(refund[0]["body_params"]) == {"amount", "reason"}
    assert not {"method", "headers", "body"}.intersection(refund[0]["params"])

    param_locations = {
        surface["param"]: surface["param_location"]
        for surface in plan_surfaces(refund)
    }
    assert param_locations == {"order_no": "query", "amount": "body", "reason": "body"}


def test_formdata_append_keys_stay_with_nearest_instance(tmp_path):
    (tmp_path / "forms.js").write_text(
        """
        function upload() {
          var formData = new FormData();
          formData.append('product_no', productNo);
          formData.append('category', 'products');
          formData.append('file', file);
          return fetch('/api/upload.php', {method: 'POST', body: formData});
        }
        function audit() {
          var formData = new FormData();
          formData.append('description', description);
          formData.append('license', license);
          return fetch('/api/submit-audit.php', {method: 'POST', body: formData});
        }
        """,
        encoding="utf-8",
    )

    rows = bootstrap(tmp_path)
    upload = _by_endpoint(rows, "/api/upload.php")[0]
    audit = _by_endpoint(rows, "/api/submit-audit.php")[0]
    assert set(upload["params"]) == {"product_no", "category", "file"}
    assert set(audit["params"]) == {"description", "license"}
    assert set(upload["body_params"]) == {"product_no", "category", "file"}
    assert set(audit["body_params"]) == {"description", "license"}
    assert not set(upload["params"]).intersection({"description", "license"})
    assert not set(audit["params"]).intersection({"product_no", "category", "file"})


def test_cross_function_parameters_shadow_sibling_url_and_formdata_bindings(tmp_path):
    (tmp_path / "scopes.js").write_text(
        """
        function first() {
          const url = '/api/first.php';
          const fd = new FormData();
          fd.append('secret', value);
        }
        function second(url, fd) {
          fetch(url, {method: 'POST', body: fd});
        }
        function local() {
          const url = '/api/local.php';
          const fd = new FormData();
          fd.append('name', value);
          fetch(url, {method: 'POST', body: fd});
        }
        """,
        encoding="utf-8",
    )

    rows = bootstrap(tmp_path)
    first = _by_endpoint(rows, "/api/first.php")
    assert len(first) == 1
    assert first[0]["method"] == ""
    assert first[0]["params"] == []
    assert not first[0].get("suppressed_unresolved_provenance")

    local = _by_endpoint(rows, "/api/local.php")
    assert len(local) == 1
    assert local[0]["method"] == "POST"
    assert local[0]["body_params"] == ["name"]


def test_expression_arrow_parameter_shadows_outer_url_binding(tmp_path):
    (tmp_path / "arrow.js").write_text(
        """
        const url = '/api/global.php';
        const call = url => fetch(url, {method: 'POST'});
        const pair = (url, body) => fetch(url, {method: 'POST', body});
        """,
        encoding="utf-8",
    )

    rows = _by_endpoint(bootstrap(tmp_path), "/api/global.php")
    assert len(rows) == 1
    assert rows[0]["method"] == ""
    assert not rows[0].get("suppressed_unresolved_provenance")


def test_planner_prioritizes_auth_flow_roles_and_does_not_schedule_unresolved():
    assert infer_roles("/api/merchant/login.php") == ["anonymous", "merchant"]
    assert infer_roles("/api/admin/login.php") == ["anonymous", "admin"]
    assert infer_roles("/api/login.php", {"observed_roles": ["admin"]}) == ["anonymous", "admin"]
    assert infer_roles(
        "/api/refund.php", {"roles": ["user"], "observed_roles": ["merchant"]}
    ) == ["user", "merchant"]

    planned = plan_surfaces([{
        "endpoint": "/api/merchant/login.php",
        "method": "POST",
        "roles": ["auditor"],
        "observed_roles": ["merchant"],
    }])
    assert planned
    assert set(planned[0]["roles"]) == {"anonymous", "merchant", "auditor"}
    assert planned[0]["explicit_roles"] == ["auditor"]
    assert planned[0]["observed_roles"] == ["merchant"]

    assert plan_surfaces([{
        "endpoint": "/api/method-unknown.php", "method": "", "source": "json"
    }]) == []
    assert plan_surfaces(["/api/bare-cli-endpoint.php"]) == []


def _shop_recon_or_fixture(tmp_path: Path) -> Path:
    # The real run stays outside the repository.  CI uses a minimal equivalent
    # fixture rather than copying cookies, responses, or other run artifacts.
    workspace_root = Path(__file__).resolve().parents[2]
    real_recon = workspace_root / "runs" / "shop_2026-07-13" / "recon"
    if real_recon.is_dir():
        return real_recon

    recon = tmp_path / "shop-recon"
    recon.mkdir()
    (recon / "js_merchant.js").write_text(
        """
        function saveProduct(productNo) {
          var data = {name: name, price: price, stock: stock, description: description};
          var url = productNo ? '../api/merchant/product-edit.php'
                              : '../api/merchant/product-add.php';
          if (productNo) data.product_no = productNo;
          jsonPost(url, data);
        }
        function upload(productNo, file) {
          var formData = new FormData();
          formData.append('product_no', productNo);
          formData.append('category', 'products');
          formData.append('file', file);
          fetch('../api/upload.php', {method: 'POST', body: formData});
        }
        function audit(description, license) {
          var formData = new FormData();
          formData.append('description', description);
          formData.append('license', license);
          fetch('../api/merchant/submit-audit.php', {method: 'POST', body: formData});
        }
        """,
        encoding="utf-8",
    )
    return recon


def test_shop_recon_has_real_post_methods_formdata_params_and_no_phantom_get(tmp_path):
    rows = bootstrap(_shop_recon_or_fixture(tmp_path))

    expected = {
        "/api/merchant/product-edit.php": {"name", "price"},
        "/api/merchant/product-add.php": {"name", "price"},
        "/api/upload.php": {"product_no", "category", "file"},
        "/api/merchant/submit-audit.php": {"description", "license"},
    }
    for endpoint, required_params in expected.items():
        endpoint_rows = _by_endpoint(rows, endpoint)
        assert endpoint_rows, endpoint
        assert {row["method"] for row in endpoint_rows} == {"POST"}
        assert required_params.issubset(set().union(*(set(row["params"]) for row in endpoint_rows)))

    upload_params = set(_by_endpoint(rows, "/api/upload.php")[0]["params"])
    audit_params = set(_by_endpoint(rows, "/api/merchant/submit-audit.php")[0]["params"])
    assert upload_params == {"product_no", "category", "file"}
    assert audit_params == {"description", "license"}
    assert not {"method", "headers", "body"}.intersection(upload_params | audit_params)
