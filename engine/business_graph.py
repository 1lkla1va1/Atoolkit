"""Business Graph runtime for Atoolkit v8.6.

Maps endpoints to domain, object, role, and state effect for planner and
LOW_ROTI advisory coverage reasoning.
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any


try:
    from .surface_key import canonical_surface_key
    from .safe_io import atomic_write_text
except ImportError:
    from surface_key import canonical_surface_key
    from safe_io import atomic_write_text


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
    """Extract a resource noun, never a generic ``{id}`` placeholder."""
    raw_parts = [p for p in endpoint.strip("/").split("/") if p]
    parts: list[str] = []
    for raw in raw_parts:
        part = re.sub(r"\.(?:php|asp|aspx|jsp|json)$", "", raw.lower())
        if (part in {"api", "v1", "v2", "v3"} or part.isdigit()
                or (part.startswith("{") and part.endswith("}"))):
            continue
        parts.append(part)
    if not parts:
        return "unknown"
    action_segments = {
        "detail", "list", "create", "add", "update", "edit", "delete",
        "remove", "toggle", "approve", "reject", "cancel", "confirm",
    }
    noun = parts[-2] if parts[-1] in action_segments and len(parts) > 1 else parts[-1]
    if len(noun) > 3 and noun.endswith("ies"):
        noun = noun[:-3] + "y"
    elif len(noun) > 3 and noun.endswith("s") and not noun.endswith("ss"):
        noun = noun[:-1]
    return noun

def _infer_state_effect(method: str, endpoint: str) -> str:
    m = _ACTION_VERBS.search(endpoint.lower())
    if m and method == "GET":
        return "state_transition"
    return _METHOD_STATE.get(method.upper(), "read")

# Financial / auth keywords for value inference
_FINANCIAL_KW = re.compile(
    r"(refund|pay|transfer|withdraw|balance|recharge|approve|reject"
    r"|cancel|confirm|freeze|unfreeze)"
)
_AUTH_KW = re.compile(r"(login|register|password|token|oauth|mfa)")

def _infer_value(method: str, path: str) -> str:
    """Infer endpoint value tier: high / medium / low.

    - high: admin paths, or write ops on financial/auth endpoints
    - medium: read ops on sensitive keywords, or generic write ops
    - low: plain read-only endpoints with no sensitive keywords
    """
    path_lower = path.lower()
    if "/admin" in path_lower:
        return "high"
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        if _FINANCIAL_KW.search(path_lower) or _AUTH_KW.search(path_lower):
            return "high"
        if "order" in path_lower:
            return "high"
        return "medium"
    # GET / HEAD / OPTIONS
    if _FINANCIAL_KW.search(path_lower) or _AUTH_KW.search(path_lower):
        return "medium"
    return "low"

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
        endpoints: list[str | dict[str, Any]],
        target_domains: list[str] | None = None,
    ) -> None:
        """Seed the graph from inventory. Accepts strings ("POST /api/x") or dicts.

        All endpoint_map keys are canonicalized via canonical_surface_key so
        downstream consumers (scheduler, planner) see a consistent
        ``"METHOD /path"`` form — never a bare path or ``"GET "`` (trailing space).
        """
        for ep in endpoints:
            key = canonical_surface_key(ep)
            if not key:
                continue
            # Extract path (without method prefix) for inference helpers.
            _method, _, path = key.partition(" ")
            method = _method
            # target_domains is a scheduling hint, never a graph filter.  A
            # cross-domain endpoint must keep every inferred domain so later
            # runs can follow Fact-Intent chains outside the current focus.
            explicit = ep if isinstance(ep, dict) else {}
            params = [str(x) for x in (explicit.get("params") or []) if str(x)]
            domains = _infer_domains(path, params)
            roles = [str(x) for x in (explicit.get("roles") or []) if str(x)] or _infer_roles(path)
            observed_roles = [
                str(x) for x in (explicit.get("observed_roles") or []) if str(x)
            ]
            obj = _infer_object(path)
            state = _infer_state_effect(method, path)

            entry = self.endpoint_map.setdefault(key, {
                "domains": [], "objects": [], "roles": [],
                "observed_roles": [], "params": [], "sources": [],
                "state_effect": state, "value": _infer_value(method, path),
                "confirmed_vuln_classes": [],
            })

            def merge_list(field: str, values: list[str]) -> None:
                current = entry.setdefault(field, [])
                for value in values:
                    if value and value not in current:
                        current.append(value)

            merge_list("domains", domains)
            if len(entry["domains"]) > 1 and "general" in entry["domains"]:
                entry["domains"].remove("general")
            merge_list("objects", [obj])
            merge_list("roles", roles)
            merge_list("observed_roles", observed_roles)
            merge_list("params", params)
            source = str(explicit.get("source") or "")
            merge_list("sources", [source] if source else [])
            # Never let a later low-information heuristic rebuild downgrade an
            # observed high-value endpoint.
            rank = {"low": 0, "medium": 1, "high": 2}
            inferred_value = _infer_value(method, path)
            if rank.get(inferred_value, 0) > rank.get(entry.get("value", "low"), 0):
                entry["value"] = inferred_value
            if entry.get("state_effect") in (None, "", "read") and state != "read":
                entry["state_effect"] = state
            for r in roles + observed_roles:
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
        key = canonical_surface_key({"method": method, "endpoint": endpoint})

        entry = self.endpoint_map.get(key)
        if entry is None:
            entry = {
                "domains": _infer_domains(endpoint, fact_data.get("params")),
                "objects": [_infer_object(endpoint)],
                "roles": _infer_roles(endpoint),
                "observed_roles": [],
                "params": [],
                "sources": [],
                "state_effect": _infer_state_effect(method, endpoint),
                "value": _infer_value(method, endpoint),
                "confirmed_vuln_classes": [],
            }
            self.endpoint_map[key] = entry

        for param in fact_data.get("params") or []:
            text = str(param or "")
            if text and text not in entry.setdefault("params", []):
                entry["params"].append(text)
        affected_role = str(fact_data.get("affected_role") or "")
        if affected_role and affected_role not in entry.setdefault("observed_roles", []):
            entry["observed_roles"].append(affected_role)

        for role in entry.get("roles", []):
            if role not in self.roles:
                self.roles.append(role)
        for obj in entry.get("objects", []):
            if obj not in self.objects:
                self.objects.append(obj)

        # Business domains come from the inventory/route model.  Fact params
        # and vuln classes are observations stored below, not a second domain
        # classifier (otherwise a vuln named ``idor`` silently pollutes the
        # graph's business taxonomy).
        extra_domains = _infer_domains(endpoint)
        for d in extra_domains:
            if d not in entry["domains"]:
                entry["domains"].append(d)

        vc = fact_data.get("vuln_class", "")
        if vc and vc not in entry.setdefault("confirmed_vuln_classes", []):
            entry["confirmed_vuln_classes"].append(vc)

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
        atomic_write_text(
            p,
            json.dumps(self._to_dict(), ensure_ascii=False, indent=2),
            root=p.parent,
            reject_leaf_symlink=True,
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
        """Group endpoint keys by shared object for planner quick-view.

        D1: Emit ``steps`` (list of ``{endpoint, order}``) instead of a flat
        ``endpoints`` list so that scheduler._flow_completion_endpoints can
        track partial flow progress.
        """
        obj_groups: dict[str, list[str]] = {}
        for key, meta in self.endpoint_map.items():
            for obj in meta.get("objects", []):
                obj_groups.setdefault(obj, []).append(key)
        flows: list[dict[str, Any]] = []
        for obj, keys in sorted(obj_groups.items()):
            if len(keys) <= 1 and obj in ("unknown",):
                continue
            # Derive primary domain from the first endpoint that has domains
            primary_domain = ""
            for k in keys:
                meta = self.endpoint_map.get(k, {})
                doms = meta.get("domains", [])
                if doms:
                    primary_domain = doms[0]
                    break
            steps = [{"endpoint": k, "order": i} for i, k in enumerate(keys)]
            flows.append({
                "object": obj,
                "domain": primary_domain,
                "steps": steps,
            })
        self.flows = flows

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
