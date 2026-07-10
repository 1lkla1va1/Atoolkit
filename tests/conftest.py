import sys, pathlib, pytest, json, tempfile, shutil

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture
def sample_endpoints():
    return [
        "POST /api/refund",
        "GET /api/refund",   # rc3: pairs with POST /api/refund → 2-step flow
        "POST /api/login",
        "POST /api/register",
        "GET /api/users",
        "GET /api/orders",
        "POST /api/upload",
        "GET /admin/dashboard",
        "POST /api/pay",
        "GET /api/products",
        "DELETE /api/user/profile",
    ]


@pytest.fixture
def sample_inventory(sample_endpoints):
    inv = []
    for ep in sample_endpoints:
        parts = ep.split(" ", 1)
        method = parts[0] if len(parts) == 2 else "GET"
        path = parts[1] if len(parts) == 2 else parts[0]
        inv.append({"method": method, "path": path, "endpoint": f"{method} {path}"})
    return inv


@pytest.fixture
def sample_confirmed_fact():
    return {
        "id": "F001",
        "status": "CONFIRMED",
        "vuln_class": "idor",
        "endpoint": "POST /api/refund",
        "evidence": "order_id controllable",
        "severity": "P1",
        "detail": "Refund endpoint allows arbitrary order_id",
    }


@pytest.fixture
def tmp_project_dir():
    d = tempfile.mkdtemp(prefix="atoolkit_test_")
    p = pathlib.Path(d)
    (p / "blackboard.json").write_text(json.dumps({
        "schema_version": "2.0",
        "facts": [], "intents": [],
        "negatives": [], "dead_ends": [],
        "domains_covered": {}, "surface_index": {},
    }))
    (p / "business_graph.json").write_text(json.dumps({
        "roles": [], "objects": [], "flows": [], "endpoint_map": {},
    }))
    yield p
    shutil.rmtree(d, ignore_errors=True)
