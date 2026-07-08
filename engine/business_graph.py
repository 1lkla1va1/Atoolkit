"""Business Graph runtime for Atoolkit v8.6.

Maps endpoints to domain, object, role, and state effect for planner and
LOW_ROTI advisory coverage reasoning.
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any


# ---------------------------------------------------------------------------
# Keyword / pattern tables
# ---------------------------------------------------------------------------

DOMAIN_KEYWORDS: dict[str, list[str]] = {
    "txn":  ["amount", "refund", "recharge", "payment", "points", "balance",
             "coupon", "order", "lottery", "price", "fee", "withdraw",
             "\u91d1\u989d", "\u9000\u6b3e", "\u5145\u503c", "\u79ef\u5206", "\u652f\u4ed8"],
    "auth": ["login", "token", "password", "session", "register", "captcha",
             "oauth", "verify", "sms_code", "mfa"],
    "idor": ["id", "user_id", "account", "profile", "ownership", "uid",
             "member", "org_id"],
    "file": ["upload", "download", "file", "path", "import", "export",
             "attachment", "image"],
}

ROLE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("admin",    re.compile(r"/admin(?:/|$)")),
    ("merchant", re.compile(r"/(?:merchant|shop)(?:/|$)")),
    ("user",     re.compile(r"/(?:user|api/user)(?:/|$)")),
]

_ACTION_VERBS = re.compile(r"(approve|reject|refund|cancel|confirm|freeze|unfreeze)")

_METHOD_STATE: dict[str, str] = {
    "POST":   "resource_created",
    "PUT":    "resource_updated",
    "PATCH":  "resource_updated",
    "DELETE": "resource_deleted",
}

_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})


# ---------------------------------------------------------------------------
# Inference helpers
# ---------------------------------------------------------------------------

def _infer_domains(endpoint: str, params: list[str] | None = None) -> list[str]:
    """Return all matching domains for an endpoint + its params."""
    blob = (endpoint + " " + " ".join(params or [])).lower()
    matched = [d for d, kws in DOMAIN_KEYWORDS.items() if any(k in blob for k in kws)]
    return matched or ["general"]

def _infer_roles(endpoint: str) -> list[str]:
    roles = [r for r, pat in ROLE_PATTERNS if pat.search(endpoint)]
    return roles or ["anonymous"]

def _infer_object(endpoint: str) -> str:
    """Extract the last meaningful path segment as the object name."""
    parts = [p for p in endpoint.strip("/").split("/") if p and not p.startswith("api")]
    return parts[-1] if parts else "unknown"

def _infer_state_effect(method: str, endpoint: str) -> str:
    m = _ACTION_VERBS.search(endpoint.lower())
    if m and method == "GET":
        return "state_transition"
    return _METHOD_STATE.get(method.upper(), "read")

# ---------------------------------------------------------------------------
# BusinessGraph
# ---------------------------------------------------------------------------

class BusinessGraph:
    """Business-context graph: maps endpoints to domains, objects, roles,
    and state effects for planner and advisory use."""

    def __init__(self) -> None:
        self.roles: list[str] = []
        self.objects: list[str] = []
        self.flows: list[dict[str, Any]] = []
        self.endpoint_map: dict[str, dict[str, Any]] = {}

    # -- seeding (session start) ---------------------------------------------

    def build_from_inventory(
        self,
        endpoints: list[str | dict[str, str]],
        target_domains: list[str] | None = None,
    ) -> None:
        """Seed the graph from inventory. Accepts strings ("POST /api/x") or dicts."""
        for ep in endpoints:
            if isinstance(ep, dict):
                method = ep.get("method", "GET").upper()
                path = ep.get("path", "")
            else:
                # Parse "METHOD /path" or just "/path"
                parts = str(ep).strip().split(None, 1)
                if len(parts) == 2 and parts[0].upper() in _HTTP_METHODS:
                    method, path = parts[0].upper(), parts[1]
                else:
                    method, path = "GET", str(ep).strip()
            key = f"{method} {path}"
            domains = _infer_domains(path)
            if target_domains:
                domains = [d for d in domains if d in target_domains] or domains
            roles = _infer_roles(path)
            obj = _infer_object(path)
            state = _infer_state_effect(method, path)

            self.endpoint_map[key] = {
                "domains": domains,
                "objects": [obj],
                "roles": roles,
                "state_effect": state,
            }
            for r in roles:
                if r not in self.roles:
                    self.roles.append(r)
            if obj not in self.objects:
                self.objects.append(obj)

        self._rebuild_flows()

    # -- fact-driven updates -------------------------------------------------

    def update_from_fact(self, fact_data: dict[str, Any]) -> None:
        """Update the graph when a confirmed Fact is recorded."""
        method = fact_data.get("method", "GET").upper()
        endpoint = fact_data.get("endpoint", "")
        key = f"{method} {endpoint}"

        entry = self.endpoint_map.get(key)
        if entry is None:
            entry = {
                "domains": _infer_domains(endpoint, fact_data.get("params")),
                "objects": [_infer_object(endpoint)],
                "roles": _infer_roles(endpoint),
                "state_effect": _infer_state_effect(method, endpoint),
            }
            self.endpoint_map[key] = entry

        extra_domains = _infer_domains(endpoint, fact_data.get("params"))
        for d in extra_domains:
            if d not in entry["domains"]:
                entry["domains"].append(d)

        vc = fact_data.get("vuln_class", "")
        if vc and vc not in entry["domains"]:
            entry["domains"].append(vc)

        if fact_data.get("summary"):
            entry["last_fact_summary"] = fact_data["summary"]

        self._rebuild_flows()

    # -- coverage queries ----------------------------------------------------

    def get_untested_high_value(self, coverage_matrix: dict[str, Any]) -> list[str]:
        """Return endpoint keys in {txn, auth, idor} domains not yet tested."""
        high_value_domains = {"txn", "auth", "idor"}
        untested: list[str] = []
        for key, meta in self.endpoint_map.items():
            if not high_value_domains & set(meta.get("domains", [])):
                continue
            cov = coverage_matrix.get(key, {})
            if not cov.get("tested"):
                untested.append(key)
        return untested

    def low_roi_advisory(self, coverage_matrix: dict[str, Any]) -> bool:
        """Return True when high-value nodes remain untested (advisory only)."""
        return bool(self.get_untested_high_value(coverage_matrix))

    # -- persistence ---------------------------------------------------------

    def export_dict(self) -> dict[str, Any]:
        """Return the graph as a JSON-serializable dict."""
        return self._to_dict()

    def export_to_file(self, path: str | pathlib.Path) -> None:
        p = pathlib.Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps(self._to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    @classmethod
    def load_from_file(cls, path: str | pathlib.Path) -> "BusinessGraph":
        """Load a BusinessGraph from a JSON file."""
        data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        g = cls()
        g.roles = data.get("roles", [])
        g.objects = data.get("objects", [])
        g.flows = data.get("flows", [])
        g.endpoint_map = data.get("endpoint_map", {})
        return g

    # -- internals -----------------------------------------------------------
    def _to_dict(self) -> dict[str, Any]:
        return {
            "roles": self.roles,
            "objects": self.objects,
            "flows": self.flows,
            "endpoint_map": self.endpoint_map,
        }

    def _rebuild_flows(self) -> None:
        """Group endpoint keys by shared object for planner quick-view."""
        obj_groups: dict[str, list[str]] = {}
        for key, meta in self.endpoint_map.items():
            for obj in meta.get("objects", []):
                obj_groups.setdefault(obj, []).append(key)
        self.flows = [
            {"object": obj, "endpoints": keys}
            for obj, keys in sorted(obj_groups.items())
            if len(keys) > 1 or obj not in ("unknown",)
        ]

    def stats(self) -> dict[str, int]:
        return {
            "total_endpoints": len(self.endpoint_map),
            "total_roles": len(self.roles),
            "total_objects": len(self.objects),
            "total_flows": len(self.flows),
        }


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sample = [
        {"method": "POST", "path": "/api/refund"},
        {"method": "GET",  "path": "/api/user/profile"},
        {"method": "POST", "path": "/admin/order/approve"},
        {"method": "GET",  "path": "/merchant/shop/download"},
        {"method": "POST", "path": "/api/user/recharge"},
        {"method": "GET",  "path": "/api/items"},
    ]
    bg = BusinessGraph()
    bg.build_from_inventory(sample)
    print("=== Business Graph (seeded) ===")
    for key, meta in bg.endpoint_map.items():
        print(f"  {key:40s} {meta['domains']}  {meta['roles']}  {meta['state_effect']}")
    print(f"\nStats: {bg.stats()}")
    bg.update_from_fact({
        "method": "POST", "endpoint": "/api/refund",
        "params": ["refund_amount"], "vuln_class": "amount-tamper",
        "summary": "\u9000\u6b3e\u91d1\u989d\u65e0\u4e0a\u9650\u6821\u9a8c",
    })
    print(f"\nAfter fact update: {bg.endpoint_map['POST /api/refund']['domains']}")
    coverage: dict[str, Any] = {}
    untested = bg.get_untested_high_value(coverage)
    print(f"\nUntested high-value ({len(untested)}): {untested}")
    print(f"LOW_ROTI advisory: {bg.low_roi_advisory(coverage)}")
    coverage["POST /api/refund"] = {"tested": True}
    coverage["POST /api/user/recharge"] = {"tested": True}
    remaining = bg.get_untested_high_value(coverage)
    print(f"\nAfter partial coverage: {remaining}")
    print(f"LOW_ROTI advisory: {bg.low_roi_advisory(coverage)}")
