"""
Deterministic surface planners for the coverage ledger.

The planner turns coarse endpoint inventories into endpoint/method/param/role
surfaces and task hints. It is intentionally conservative and payload-free:
it names coverage dimensions, not exploit strings.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlsplit


DEFAULT_ROLES = ["anonymous", "user"]
ADMIN_DIFF_ROLES = ["anonymous", "user", "merchant", "admin"]
MERCHANT_PAIR = ["merchant_a", "merchant_b"]
USER_PAIR = ["owner:user", "attacker:user"]

PARAM_RISK_RULES: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("amount", "refund_amount", "use_points", "price", "fee", "balance", "stock"),
     ("amount-tamper", "accounting")),
    (("order_time", "timestamp", "create_time"), ("time-tamper",)),
    (("order_no", "product_no", "user_id", "user_hash", "id"), ("object-ownership", "idor")),
    (("redirect", "return_url", "callback_url"), ("redirect-chain", "callback")),
    (("image_url", "url", "fetch"), ("ssrf",)),
    (("filename", "category", "file", "upload"), ("file-upload", "path-traversal")),
    (("keyword", "search", "sort", "orderby", "filter"), ("input-validation", "injection")),
    (("status", "discount", "role", "state"), ("enum-tamper", "privilege")),
)

AUTH_FLOW_KEYWORDS = (
    "register", "login", "forgot", "password", "reset", "captcha", "sms",
    "verify-code", "verify_code", "audit", "lock", "unlock", "enum", "token",
    "session", "role", "sub-login", "change-audit",
)

OBJECT_PARAM_NAMES = {
    "id", "uid", "user_id", "order_id", "product_id", "merchant_id",
    "address_id", "hash",
}

HIGH_VALUE_TAGS = {
    "auth-flow", "auth-flow-abuse", "amount-tamper", "accounting", "payment",
    "object-ownership", "idor", "privilege", "callback", "ssrf", "file-upload",
}


def _as_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return sorted(value)
    return [value]


def _norm_token(value: Any) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", str(value or "").strip().lower()).strip("_")


def _dedupe(values: Iterable[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        key = text.lower()
        if key not in seen:
            seen.add(key)
            out.append(text)
    return out


def _split_method(method: Any) -> list[str]:
    raw = str(method or "GET").upper().strip()
    parts = re.split(r"[/,| ]+", raw)
    return [p for p in parts if p] or ["GET"]


def _endpoint_from_item(item: str | dict[str, Any]) -> tuple[str, dict[str, Any]]:
    if isinstance(item, dict):
        endpoint = item.get("endpoint") or item.get("path") or item.get("url") or ""
        return str(endpoint).strip(), dict(item)
    return str(item or "").strip(), {}


def extract_params(endpoint: str, meta: dict[str, Any] | None = None) -> list[str]:
    """Extract param names from inventory metadata, query strings, and path placeholders."""
    meta = meta or {}
    params: list[str] = []
    for key in ("param", "params", "parameters", "query_params", "body_params", "form_params"):
        for value in _as_list(meta.get(key)):
            if isinstance(value, dict):
                value = value.get("name") or value.get("key") or value.get("param")
            params.append(str(value or "").strip())

    parsed = urlsplit(endpoint)
    for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
        params.append(key)
    for name in re.findall(r"{([^{}]+)}|:([A-Za-z_][A-Za-z0-9_]*)", parsed.path or endpoint):
        params.extend(x for x in name if x)
    return _dedupe(params)


def infer_risk_tags(param: str = "", endpoint: str = "", feature: str = "") -> list[str]:
    """Return deterministic risk tags for a param/endpoint/feature tuple."""
    hay = " ".join(_norm_token(x) for x in (param, endpoint, feature))
    tags: list[str] = []
    for names, risks in PARAM_RISK_RULES:
        if any(name in hay for name in names):
            tags.extend(risks)
    if is_auth_flow_endpoint(endpoint, feature):
        tags.extend(["auth-flow", "auth-flow-abuse"])
    if any(word in hay for word in ("pay", "payment", "recharge", "refund", "coupon", "lottery")):
        tags.extend(["payment", "accounting"])
    return _dedupe(tags)


def is_object_param(param: str) -> bool:
    name = _norm_token(param)
    return name in OBJECT_PARAM_NAMES or name.endswith("_no")


def is_auth_flow_endpoint(endpoint: str, feature: str = "") -> bool:
    hay = f"{endpoint} {feature}".lower()
    return any(keyword in hay for keyword in AUTH_FLOW_KEYWORDS)


def infer_feature(endpoint: str, meta: dict[str, Any] | None = None) -> str:
    if meta and meta.get("feature"):
        return str(meta["feature"]).strip()
    path = urlsplit(endpoint).path or endpoint
    parts = [p for p in re.split(r"[/?#]+", path) if p]
    if "api" in [p.lower() for p in parts]:
        api_idx = max(i for i, p in enumerate(parts) if p.lower() == "api")
        parts = parts[api_idx + 1:] or parts
    skip = {"api", "v1", "v2", "v3", "rest", "service", "services"}
    for part in parts:
        low = re.sub(r"\.(php|asp|aspx|jsp|json)$", "", part.lower())
        if low not in skip and not low.isdigit():
            return low
    return "default"


def infer_roles(endpoint: str, meta: dict[str, Any] | None = None) -> list[str]:
    meta = meta or {}
    explicit = _as_list(meta.get("roles") or meta.get("role") or meta.get("needed_roles"))
    if explicit:
        return _dedupe(str(x) for x in explicit)
    low = endpoint.lower()
    if "admin" in low:
        return ADMIN_DIFF_ROLES
    if "merchant" in low:
        return ["merchant"]
    if is_auth_flow_endpoint(endpoint):
        return ["anonymous", "user"]
    return list(DEFAULT_ROLES)


def default_source(meta: dict[str, Any] | None = None) -> str:
    source = (meta or {}).get("source") or "manual"
    if isinstance(source, list):
        return ",".join(str(x) for x in source)
    return str(source)


@dataclass
class PlannedTask:
    task_id: str
    kind: str
    endpoint: str
    method: str
    param: str = ""
    roles: list[str] = field(default_factory=list)
    risk_tags: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)


@dataclass
class PlannedSurface:
    surface_id: str
    endpoint: str
    method: str
    param: str = ""
    roles: list[str] = field(default_factory=list)
    risk_tags: list[str] = field(default_factory=list)
    feature: str = "default"
    status: str = "not_tested"
    evidence_ref: str | None = None
    blocker: dict[str, Any] | None = None
    next_actions: list[str] = field(default_factory=list)
    source: str = "manual"
    tasks: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def make_surface_id(endpoint: str, method: str, param: str = "", roles: Iterable[str] | None = None,
                    risk_tags: Iterable[str] | None = None) -> str:
    role_s = ",".join(_dedupe(roles or [])) or "any"
    risk_s = ",".join(_dedupe(risk_tags or []))
    parts = [method.upper(), endpoint]
    if param:
        parts.append(param)
    parts.append(f"[{role_s}]")
    if risk_s:
        parts.append(f"{{{risk_s}}}")
    return " ".join(parts)


def plan_object_pair_tasks(endpoint: str, method: str, param: str, roles: list[str],
                           risk_tags: list[str]) -> list[PlannedTask]:
    if not is_object_param(param):
        return []
    low = endpoint.lower()
    if "merchant" in low or "product" in low:
        pair = MERCHANT_PAIR
    else:
        pair = USER_PAIR
    operation = "read"
    if method.upper() in {"POST", "PUT", "PATCH", "DELETE"} or any(x in low for x in ("edit", "delete", "update", "toggle", "ship")):
        operation = "write"
    steps = [
        "owner creates or enumerates an in-scope object",
        "attacker attempts the same object operation with an authorized peer identity",
        "owner or victim checks whether business state changed",
    ]
    task_id = f"object-pair:{method.upper()}:{endpoint}:{param}:{operation}"
    return [PlannedTask(task_id, "object-pair", endpoint, method.upper(), param, list(pair), risk_tags, steps)]


def plan_role_diff_tasks(endpoint: str, method: str, roles: list[str], risk_tags: list[str]) -> list[PlannedTask]:
    low = endpoint.lower()
    if "admin" not in low and "role" not in " ".join(risk_tags):
        return []
    task_id = f"role-diff:{method.upper()}:{endpoint}"
    return [PlannedTask(
        task_id=task_id,
        kind="role-diff",
        endpoint=endpoint,
        method=method.upper(),
        roles=ADMIN_DIFF_ROLES if "admin" in low else roles,
        risk_tags=_dedupe(list(risk_tags) + ["privilege"]),
        steps=[
            "compare anonymous, low-privilege, merchant, and admin reachability",
            "record backend status and response shape for each role",
            "close only with evidence for denied and allowed boundaries",
        ],
    )]


def plan_auth_flow_tasks(endpoint: str, method: str, roles: list[str],
                         risk_tags: list[str]) -> list[PlannedTask]:
    if "auth-flow" not in risk_tags:
        return []
    return [PlannedTask(
        task_id=f"auth-flow:{method.upper()}:{endpoint}",
        kind="auth-flow",
        endpoint=endpoint,
        method=method.upper(),
        roles=roles or ["anonymous", "user"],
        risk_tags=_dedupe(list(risk_tags) + ["auth-flow-abuse"]),
        steps=[
            "cover anonymous and authenticated baselines",
            "cover registration, login, reset, captcha or token state binding when present",
            "record user enumeration and role/session consistency evidence",
        ],
    )]


def plan_surfaces(endpoints: list[str | dict[str, Any]], *, default_roles: list[str] | None = None) -> list[dict[str, Any]]:
    """Expand endpoint inventory into ledger-ready surface dictionaries."""
    surfaces: list[PlannedSurface] = []
    seen: set[str] = set()
    for item in endpoints:
        endpoint, meta = _endpoint_from_item(item)
        if not endpoint:
            continue
        feature = infer_feature(endpoint, meta)
        roles = infer_roles(endpoint, meta) or list(default_roles or DEFAULT_ROLES)
        params = extract_params(endpoint, meta) or [""]
        methods = _split_method(meta.get("method") or meta.get("methods") or "GET")
        source = default_source(meta)
        clean_endpoint = urlsplit(endpoint).path or endpoint.split("?", 1)[0]

        for method in methods:
            for param in params:
                risk_tags = infer_risk_tags(param, clean_endpoint, feature)
                if not risk_tags:
                    risk_tags = ["general-review"]
                tasks: list[PlannedTask] = []
                tasks.extend(plan_object_pair_tasks(clean_endpoint, method, param, roles, risk_tags))
                tasks.extend(plan_role_diff_tasks(clean_endpoint, method, roles, risk_tags))
                tasks.extend(plan_auth_flow_tasks(clean_endpoint, method, roles, risk_tags))
                surface_id = make_surface_id(clean_endpoint, method, param, roles, risk_tags)
                if surface_id in seen:
                    continue
                seen.add(surface_id)
                surfaces.append(PlannedSurface(
                    surface_id=surface_id,
                    endpoint=clean_endpoint,
                    method=method.upper(),
                    param=param,
                    roles=roles,
                    risk_tags=risk_tags,
                    feature=feature,
                    status="not_tested",
                    evidence_ref=None,
                    blocker=None,
                    next_actions=[],
                    source=source,
                    tasks=[asdict(task) for task in tasks],
                ))
    return [surface.to_dict() for surface in surfaces]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Expand endpoints into coverage surfaces.")
    parser.add_argument("inventory", nargs="?", help="JSON file with endpoints/discovered_apis, or omitted for stdin")
    args = parser.parse_args(argv)
    text = open(args.inventory, encoding="utf-8").read() if args.inventory else input()
    data = json.loads(text)
    endpoints = data.get("discovered_apis") if isinstance(data, dict) else data
    print(json.dumps({"surfaces": plan_surfaces(endpoints or [])}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
