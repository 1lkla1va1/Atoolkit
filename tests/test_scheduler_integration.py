"""D1 + D2: Scheduler integration tests."""
import pytest
from engine.business_graph import BusinessGraph
from engine import scheduler


def _build_graph(inventory, fact):
    bg = BusinessGraph()
    bg.build_from_inventory(inventory)
    bg.update_from_fact(fact)
    return bg


class TestD2_SchedulerHighValue:
    """D2: within same target domain, high-value endpoints must sort above medium."""

    def test_refund_before_orders_within_txn(self, sample_inventory, sample_confirmed_fact):
        """Both /api/refund and /api/orders are txn-domain.
        Without value field, both get medium priority and sort alphabetically
        (orders < refund). With proper value inference, refund should be high
        and sort before orders."""
        bg = _build_graph(sample_inventory, sample_confirmed_fact)
        emap = bg.endpoint_map
        refund_meta = emap.get("POST /api/refund", {})
        orders_meta = emap.get("GET /api/orders", {})
        # Both should be in txn domain
        assert "txn" in refund_meta.get("domains", []), "refund not in txn domain"
        assert "txn" in orders_meta.get("domains", []), "orders not in txn domain"
        # refund should be high, orders should be medium
        refund_val = refund_meta.get("value", "medium")
        orders_val = orders_meta.get("value", "medium")
        assert refund_val == "high", (
            f"D2 FAIL: /api/refund value={refund_val!r}, expected 'high'. "
            f"BusinessGraph does not infer value field for sensitive endpoints."
        )
        # Verify sorting: high-value refund should appear before medium-value orders
        sorted_eps = scheduler._high_value_endpoints(
            bg.export_dict(), target_domains=["txn"]
        )
        if "POST /api/refund" in sorted_eps and "GET /api/orders" in sorted_eps:
            refund_idx = sorted_eps.index("POST /api/refund")
            orders_idx = sorted_eps.index("GET /api/orders")
            assert refund_idx < orders_idx, (
                f"D2 FAIL: refund at idx {refund_idx} should be before "
                f"orders at idx {orders_idx}. Value field not differentiating."
            )


class TestD1_FlowCompletion:
    """D1: scheduler._flow_completion_endpoints must work with BusinessGraph.flows."""

    def test_flow_completion_returns_endpoints(self, sample_inventory, sample_confirmed_fact):
        bg = _build_graph(sample_inventory, sample_confirmed_fact)
        bb = {"facts": [sample_confirmed_fact], "intents": [], "negatives": [],
              "dead_ends": [], "discovered_endpoints": []}
        flow_eps = scheduler._flow_completion_endpoints(bg.export_dict(), bb)
        assert len(flow_eps) > 0, (
            f"D1 FAIL: _flow_completion_endpoints returned empty list. "
            f"BusinessGraph.flows schema: "
            f"{list(bg.flows[0].keys()) if bg.flows else 'no flows'}. "
            f"Scheduler expects 'steps' key with endpoint objects."
        )

    def test_flow_completion_excludes_tested(self, sample_inventory, sample_confirmed_fact):
        bg = _build_graph(sample_inventory, sample_confirmed_fact)
        bb_empty = {"facts": [], "intents": [], "negatives": [],
                    "dead_ends": [], "discovered_endpoints": []}
        all_eps = scheduler._flow_completion_endpoints(bg.export_dict(), bb_empty)
        if not all_eps:
            pytest.skip("D1: no flow endpoints returned")
        tested_ep = all_eps[0]
        bb_tested = {"facts": [{"endpoint": tested_ep, "source_type": "confirmed"}], "intents": [],
                     "negatives": [], "dead_ends": [], "discovered_endpoints": []}
        filtered = scheduler._flow_completion_endpoints(bg.export_dict(), bb_tested)
        assert tested_ep not in filtered, (
            f"D1: tested endpoint {tested_ep!r} still in flow completion list"
        )

    def test_discovered_endpoint_is_not_treated_as_tested(self):
        bg = {"flows": [{"steps": [
            {"endpoint": "GET /api/order"},
            {"endpoint": "POST /api/refund"},
        ]}]}
        bb = {
            "facts": [{"endpoint": "/api/order", "method": "GET",
                       "source_type": "confirmed"}],
            "negatives": [], "dead_ends": [],
            "discovered_endpoints": ["POST /api/refund"],
        }
        assert scheduler._flow_completion_endpoints(bg, bb) == ["POST /api/refund"]
