"""
Blocker classification and recovery planning for coverage surfaces.

The resolver is payload-free: it decides whether a blocked surface can be
recovered, needs human input, or is out of scope, then emits status and
next_actions suitable for the coverage ledger.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any


RECOVERABLE = "recoverable"
NEEDS_INPUT = "needs_input"
OUT_OF_SCOPE = "out_of_scope"

BLOCKED_STATUS = "blocked"
NOT_APPLICABLE_STATUS = "not_applicable"


@dataclass
class BlockerResolution:
    blocker_type: str
    category: str
    status: str
    next_actions: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


BLOCKER_RULES: dict[str, dict[str, Any]] = {
    "quota_exhausted": {
        "category": RECOVERABLE,
        "status": BLOCKED_STATUS,
        "next_actions": ["reset test data", "switch to another authorized account", "create a fresh object"],
        "patterns": ("quota", "remaining=0", "lottery_remaining=0", "limit exceeded", "exhausted", "used up"),
    },
    "object_absent": {
        "category": RECOVERABLE,
        "status": BLOCKED_STATUS,
        "next_actions": ["create the object with the owner account", "enumerate owned objects", "retry with fresh object evidence"],
        "patterns": ("object absent", "not found", "missing object", "no such", "empty list", "no order", "no product"),
    },
    "missing_role": {
        "category": NEEDS_INPUT,
        "status": BLOCKED_STATUS,
        "next_actions": ["register an in-scope account for the missing role", "request an authorized role account from the program owner"],
        "patterns": ("missing role", "need role", "no admin", "no merchant", "role account", "permission account"),
    },
    "captcha_required": {
        "category": NEEDS_INPUT,
        "status": BLOCKED_STATUS,
        "next_actions": ["request human-provided captcha or verification code", "do not bypass human verification boundaries"],
        "patterns": ("captcha", "verify code", "verification code", "sms", "mfa", "2fa"),
    },
    "out_of_scope": {
        "category": OUT_OF_SCOPE,
        "status": NOT_APPLICABLE_STATUS,
        "next_actions": ["stop testing this surface", "record the authorization boundary"],
        "patterns": ("out of scope", "not authorized", "outside scope", "third-party", "forbidden by scope"),
    },
}


def _text(obj: Any) -> str:
    if isinstance(obj, dict):
        parts: list[str] = []
        for key in ("type", "blocker_type", "kind", "reason", "message", "detail", "status"):
            if obj.get(key):
                parts.append(str(obj[key]))
        return " ".join(parts)
    return str(obj or "")


def classify_blocker(blocker: str | dict[str, Any] | None, context: dict[str, Any] | None = None) -> str:
    """Classify a blocker into a known type."""
    raw = " ".join(x for x in (_text(blocker), _text(context or {})) if x).lower()
    explicit = ""
    if isinstance(blocker, dict):
        explicit = str(blocker.get("type") or blocker.get("blocker_type") or blocker.get("kind") or "").strip()
    if explicit in BLOCKER_RULES:
        return explicit
    for blocker_type, rule in BLOCKER_RULES.items():
        if any(pattern in raw for pattern in rule["patterns"]):
            return blocker_type
    if re.search(r"\b401\b|\b403\b|permission|unauthorized|forbidden", raw):
        return "missing_role"
    return "object_absent" if "not found" in raw else "unknown"


def resolve_blocker(blocker: str | dict[str, Any] | None, context: dict[str, Any] | None = None) -> BlockerResolution:
    """Return category/status/next_actions for a blocker."""
    blocker_type = classify_blocker(blocker, context)
    rule = BLOCKER_RULES.get(blocker_type)
    reason = _text(blocker) or _text(context or {})
    if not rule:
        return BlockerResolution(
            blocker_type="unknown",
            category=NEEDS_INPUT,
            status=BLOCKED_STATUS,
            next_actions=["clarify the blocker and convert it into a concrete retest task"],
            reason=reason,
        )
    return BlockerResolution(
        blocker_type=blocker_type,
        category=rule["category"],
        status=rule["status"],
        next_actions=list(rule["next_actions"]),
        reason=reason,
    )


def apply_blocker(surface: dict[str, Any], blocker: str | dict[str, Any]) -> dict[str, Any]:
    """Return a copy of surface updated with blocker, status, and next actions."""
    out = dict(surface or {})
    resolution = resolve_blocker(blocker, out)
    out["blocker"] = resolution.to_dict()
    out["status"] = resolution.status
    actions = list(out.get("next_actions") or [])
    for action in resolution.next_actions:
        if action not in actions:
            actions.append(action)
    out["next_actions"] = actions
    return out


def is_recoverable(blocker: str | dict[str, Any] | None) -> bool:
    return resolve_blocker(blocker).category == RECOVERABLE


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Classify a coverage blocker.")
    parser.add_argument("blocker", nargs="?", default="", help="Blocker text or JSON object")
    args = parser.parse_args(argv)
    try:
        obj: Any = json.loads(args.blocker)
    except Exception:
        obj = args.blocker
    print(json.dumps(resolve_blocker(obj).to_dict(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
