"""D1 + D2: BusinessGraph schema contract tests."""
import pytest
from engine.business_graph import BusinessGraph


class TestD2_ValueField:
    """D2: endpoint_map entries must have a 'value' field (high/medium/low)."""

    def test_endpoint_has_value_field(self, sample_inventory):
        bg = BusinessGraph()
        bg.build_from_inventory(sample_inventory)
        assert len(bg.endpoint_map) > 0, "endpoint_map should not be empty after build"
        for ep, meta in bg.endpoint_map.items():
            assert "value" in meta, (
                f"D2 FAIL: endpoint {ep!r} has no 'value' field. "
                f"Keys: {list(meta.keys())}"
            )

    def test_value_is_valid_tier(self, sample_inventory):
        bg = BusinessGraph()
        bg.build_from_inventory(sample_inventory)
        valid = {"high", "medium", "low"}
        for ep, meta in bg.endpoint_map.items():
            v = meta.get("value")
            assert v in valid, (
                f"D2 FAIL: endpoint {ep!r} value={v!r} not in {valid}"
            )

    def test_high_value_endpoints_exist(self, sample_inventory):
        """At least some endpoints should be inferred as high value."""
        bg = BusinessGraph()
        bg.build_from_inventory(sample_inventory)
        high_eps = [ep for ep, m in bg.endpoint_map.items() if m.get("value") == "high"]
        assert len(high_eps) > 0, (
            "D2 FAIL: no endpoint was inferred as high value. "
            "Expected /api/refund, /api/pay, /admin/* to be high."
        )


class TestD1_FlowsSchema:
    """D1: BusinessGraph.flows must have 'steps' key compatible with scheduler."""

    def test_flows_have_steps_key(self, sample_inventory, sample_confirmed_fact):
        bg = BusinessGraph()
        bg.build_from_inventory(sample_inventory)
        bg.update_from_fact(sample_confirmed_fact)
        if not bg.flows:
            pytest.skip("No flows generated")
        for flow in bg.flows:
            assert "steps" in flow, (
                f"D1 FAIL: flow {flow!r} has no 'steps' key. "
                f"Keys: {list(flow.keys())}. "
                f"Scheduler expects flow.get('steps') with step objects."
            )

    def test_flow_steps_contain_endpoint(self, sample_inventory, sample_confirmed_fact):
        bg = BusinessGraph()
        bg.build_from_inventory(sample_inventory)
        bg.update_from_fact(sample_confirmed_fact)
        if not bg.flows:
            pytest.skip("No flows generated")
        for flow in bg.flows:
            steps = flow.get("steps", [])
            assert len(steps) > 0, f"D1 FAIL: flow steps is empty for flow {flow!r}"
            for step in steps:
                assert "endpoint" in step, (
                    f"D1 FAIL: step {step!r} missing 'endpoint' key"
                )


def test_placeholder_ids_do_not_merge_unrelated_resources():
    bg = BusinessGraph()
    bg.build_from_inventory(["GET /api/orders/{id}", "GET /api/users/{id}"])
    assert bg.endpoint_map["GET /api/orders/{id}"]["objects"] == ["order"]
    assert bg.endpoint_map["GET /api/users/{id}"]["objects"] == ["user"]
    assert all(len(flow["steps"]) == 1 for flow in bg.flows)


def test_fact_added_endpoint_updates_top_level_roles_and_objects():
    bg = BusinessGraph()
    bg.update_from_fact({
        "method": "GET", "endpoint": "/api/user/orders/{id}",
        "vuln_class": "idor", "summary": "order IDOR",
    })
    assert "user" in bg.roles
    assert "order" in bg.objects
