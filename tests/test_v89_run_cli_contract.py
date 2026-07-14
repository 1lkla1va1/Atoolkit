from __future__ import annotations

import subprocess
import sys

import pytest

import run


def test_base_path_is_only_explicit() -> None:
    assert run.normalize_explicit_base_path("") == "/"
    assert run.normalize_explicit_base_path("/range/pentest/shop") == "/range/pentest/shop/"
    with pytest.raises(ValueError):
        run.normalize_explicit_base_path("/app/../admin")


def test_entry_page_does_not_change_default_project_identity() -> None:
    login = run.default_project_slug("https://t.example/login/")
    dashboard = run.default_project_slug("https://t.example/dashboard")
    assert login == dashboard == "t.example_443"


def test_explicit_app_namespaces_do_not_collide() -> None:
    shop = run.default_project_slug(
        "http://192.0.2.10:8180/login", base_path="/range/pentest/shop/")
    blog = run.default_project_slug(
        "http://192.0.2.10:8180/login", base_path="/range/pentest/blog/")
    assert shop != blog


def test_bare_endpoint_argument_remains_unresolved_until_method_is_observed() -> None:
    endpoints, records = run._inventory_records_from_endpoint_arg("/api/mystery")

    assert endpoints == []
    assert records == [{
        "endpoint": "/api/mystery",
        "method": "",
        "source": "endpoints",
        "source_file": "",
        "source_line": 1,
        "source_kind": "cli_endpoints",
        "last_seen": "",
        "discovered_during_testing": False,
    }]


def test_explicit_endpoint_method_is_admitted_as_resolved() -> None:
    endpoints, records = run._inventory_records_from_endpoint_arg(
        "POST /api/mystery")

    assert endpoints == ["POST /api/mystery"]
    assert records[0]["method"] == "POST"


def test_live_run_is_fail_closed_without_explicit_egress_acceptance() -> None:
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
    assert "live run 默认拒绝" in result.stderr
