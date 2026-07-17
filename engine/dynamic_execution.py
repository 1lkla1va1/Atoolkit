"""Threat-driven dynamic execution contracts and projections.

The frozen threat plan remains the coverage denominator.  This module adds an
append-only experiment layer inside each exact cell: evidence obligations are
compiled, model observations are bound to physical files, and a deterministic
reducer emits the next bounded work queue.  Execution events can schedule or
reopen work; they never prove a vulnerability or a negative by themselves.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
from typing import Any, Iterable

try:
    from .ledger import (
        STATUS_BLOCKED,
        STATUS_CONFIRMED,
        STATUS_EXPLORING,
        STATUS_NOT_APPLICABLE,
        STATUS_NOT_TESTED,
        STATUS_NOT_VULNERABLE,
        STATUS_SHALLOW_NEGATIVE,
        CoverageLedger,
        is_high_value,
        normalize_status,
    )
    from .run_authority import canonical_digest
    from .safe_io import (
        atomic_write_json,
        create_json_exclusive,
        ensure_directory,
        safe_read_bytes,
        safe_read_text,
    )
except ImportError:  # pragma: no cover - direct script fallback
    from ledger import (STATUS_BLOCKED, STATUS_CONFIRMED, STATUS_EXPLORING,
                        STATUS_NOT_APPLICABLE, STATUS_NOT_TESTED,
                        STATUS_NOT_VULNERABLE, STATUS_SHALLOW_NEGATIVE,
                        CoverageLedger, is_high_value, normalize_status)
    from run_authority import canonical_digest
    from safe_io import (atomic_write_json, create_json_exclusive,
                         ensure_directory, safe_read_bytes, safe_read_text)


EXECUTION_CONTRACT_VERSION = 1
EXECUTION_QUEUE_LIMIT = 8
EXECUTION_EVENT_RE = re.compile(
    r"^\s*EXECUTION_EVENT\s*[:：]\s*(\{.*\})\s*$", re.MULTILINE)
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_OUTCOMES = {"observed", "blocked", "discovery", "proof_repair"}
KNOWN_BARRIERS = {
    "waf_blocked", "waf_bypass_exhausted", "session_expired",
    "auth_required", "object_absent", "empty_dataset",
    "ownership_unproven", "missing_role", "challenge_unsolved",
    "format_unresolved",
}
_CONTROL_ARTIFACTS = {
    "run_manifest.json", "run_plan.json", "inventory.json",
    "coverage-ledger.json", "candidate-ledger.json", "state.json",
    "execution-contracts.json", "execution-progress.json",
    "execution-queue.json", "execution-backlog.json",
    "runtime-preflight.json", "runtime-status.json",
}


class DynamicExecutionError(ValueError):
    pass


def _as_list(value: Any) -> list[Any]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _dedupe(values: Iterable[Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            out.append(text)
    return out


def _obligation(identifier: str, source: str, description: str) -> dict[str, str]:
    return {
        "obligation_id": identifier,
        "source": source,
        "description": description,
    }


def _threat_obligation(index: int, description: str) -> dict[str, str]:
    digest = hashlib.sha256(description.encode("utf-8")).hexdigest()[:10]
    return _obligation(
        f"threat-evidence-{index:02d}-{digest}",
        "threat_model",
        description,
    )


def _family_text(surface: dict[str, Any]) -> str:
    values = [
        surface.get("vuln_class"), surface.get("legacy_vuln"),
        surface.get("security_invariant"), surface.get("observable_violation"),
        surface.get("feature"), surface.get("endpoint"), surface.get("param"),
        *(_as_list(surface.get("risk_tags"))),
    ]
    return " ".join(str(value or "").lower() for value in values)


def compile_execution_contract(surface: dict[str, Any]) -> dict[str, Any]:
    """Compile one exact cell into model-authored and deterministic obligations."""
    surface_id = str(surface.get("surface_id") or "").strip()
    if not surface_id:
        raise DynamicExecutionError("execution contract requires surface_id")
    obligations: list[dict[str, str]] = [
        _obligation(
            "valid-baseline", "depth_floor",
            "Capture a valid control request and response with satisfied preconditions.",
        )
    ]
    for index, description in enumerate(
            _dedupe(surface.get("evidence_required") or []), start=1):
        obligations.append(_threat_obligation(index, description))

    family = _family_text(surface)
    requirement = surface.get("identity_requirement")
    requirement = requirement if isinstance(requirement, dict) else {}
    identity_mode = str(requirement.get("mode") or "single").lower()
    if identity_mode in {"peer_pair", "role_pair"}:
        obligations.extend([
            _obligation("owner-control", "depth_floor",
                        "Capture the owner or permitted-role control."),
            _obligation("alternate-identity-attempt", "depth_floor",
                        "Repeat the exact action with the required distinct identity."),
            _obligation("ownership-or-role-marker", "depth_floor",
                        "Bind the object or action to an observable owner/role marker."),
        ])
    elif identity_mode == "anonymous_plus_authenticated":
        obligations.extend([
            _obligation("authenticated-control", "depth_floor",
                        "Capture the authenticated control."),
            _obligation("anonymous-attempt", "depth_floor",
                        "Repeat the exact action without the authenticated context."),
        ])
    elif identity_mode == "stateful_owner":
        obligations.extend([
            _obligation("test-data-prepared", "depth_floor",
                        "Create or identify a real owned test object."),
            _obligation("state-before", "depth_floor",
                        "Capture the relevant business state before the action."),
            _obligation("state-after", "depth_floor",
                        "Read back the relevant business state after the action."),
        ])

    # Object authorization is never allowed to inherit a model-authored
    # single-identity floor.  A weak threat plan must not make an IDOR negative
    # closable without the owner/alternate-identity comparison.
    if any(token in family for token in (
            "idor", "bola", "object-level authorization", "object level authorization",
            "对象级授权", "水平越权", "垂直越权")):
        obligations.extend([
            _obligation("owner-control", "depth_floor",
                        "Capture the owner or permitted-role control."),
            _obligation("alternate-identity-attempt", "depth_floor",
                        "Repeat the exact action with a distinct unauthorized identity."),
            _obligation("ownership-or-role-marker", "depth_floor",
                        "Bind the object or action to an observable owner/role marker."),
        ])

    if any(token in family for token in ("enumerat", "枚举")):
        obligations.extend([
            _obligation("auth-message-channel", "depth_floor",
                        "Compare valid and invalid identities through the message channel."),
            _obligation("auth-timing-channel", "depth_floor",
                        "Compare repeated median timing for valid and invalid identities."),
            _obligation("auth-behavior-channel", "depth_floor",
                        "Compare lockout, throttling, or other behavioral outcomes."),
        ])
    if any(token in family for token in (
            "auth bypass", "auth-bypass", "认证绕过", "captcha", "token bypass",
            "reset", "forgot-password", "verify-code", "sms")):
        obligations.extend([
            _obligation("auth-field-omission", "depth_floor",
                        "Exercise omission of the security decision field."),
            _obligation("auth-empty-null", "depth_floor",
                        "Exercise empty and null boundary representations."),
            _obligation("auth-type-shape", "depth_floor",
                        "Exercise independent type or request-shape variants."),
            _obligation("auth-step-order", "depth_floor",
                        "Exercise step ordering or direct access to a later state."),
            _obligation("auth-reuse-binding", "depth_floor",
                        "Exercise reuse and identity/session binding."),
        ])

    transaction_tokens = (
        "payment", "accounting", "refund", "recharge", "amount", "price",
        "balance", "points", "积分", "金额", "退款", "支付", "交易",
    )
    if any(token in family for token in transaction_tokens):
        obligations.extend([
            _obligation("transaction-valid-control", "depth_floor",
                        "Capture a valid transaction control."),
            _obligation("transaction-zero-negative", "depth_floor",
                        "Exercise zero and negative boundaries where meaningful."),
            _obligation("transaction-large-precision", "depth_floor",
                        "Exercise oversized and precision/unit boundaries."),
            _obligation("transaction-type-shape", "depth_floor",
                        "Exercise independent type or structural variants."),
            _obligation("transaction-state-delta", "depth_floor",
                        "Recalculate the before/action/after business-state delta."),
        ])

    if any(token in family for token in ("xss", "cross-site scripting", "跨站")):
        obligations.extend([
            _obligation("xss-input-attempt", "depth_floor",
                        "Submit an independent controlled input and capture the outcome."),
            _obligation("xss-render-outcome", "depth_floor",
                        "Capture the resulting rendering/sink context or its rejection."),
            _obligation("xss-browser-outcome", "depth_floor",
                        "Check browser execution with a marker and capture the observed outcome."),
        ])
        if any(token in family for token in ("stored", "persistent", "存储")):
            obligations.extend([
                _obligation("stored-input-readback", "depth_floor",
                            "Check the product read path and capture the read-back outcome."),
                _obligation("stored-input-peer-view", "depth_floor",
                            "Check the required second-identity view and capture the outcome."),
            ])
    if any(token in family for token in ("sqli", "sql injection", "sql 注入")):
        obligations.extend([
            _obligation("injection-multi-family", "depth_floor",
                        "Exercise independent payload families for the inferred sink context."),
            _obligation("injection-encoding-transport", "depth_floor",
                        "Exercise an independent encoding or transport representation."),
            _obligation("injection-response-differential", "depth_floor",
                        "Capture a repeatable content, length, status, error, or timing differential."),
        ])
    if any(token in family for token in ("ssrf", "server-side fetch", "服务端请求")):
        obligations.extend([
            _obligation("fetch-destination-control", "depth_floor",
                        "Exercise a destination-specific marker and capture the response."),
            _obligation("server-side-fetch-outcome", "depth_floor",
                        "Capture callback, response, or rejection evidence for the fetch attempt."),
        ])
    if any(token in family for token in ("redirect", "跳转", "return_url")):
        obligations.append(
            _obligation("navigation-final-destination", "depth_floor",
                        "Capture the browser-visible final navigation destination."))
    if any(token in family for token in ("upload", "file write", "文件上传", "文件落地")):
        obligations.extend([
            _obligation("file-valid-control", "depth_floor",
                        "Capture a permitted upload/write control or its documented baseline."),
            _obligation("file-bypass-families", "depth_floor",
                        "Exercise independent type, name, content, or parser bypass families."),
            _obligation("file-retrieval-outcome", "depth_floor",
                        "Check retrieval/location and capture the success or rejection outcome."),
            _obligation("file-nonfile-params", "depth_floor",
                        "Exercise relevant non-file metadata parameters independently."),
        ])

    unique: dict[str, dict[str, str]] = {}
    for item in obligations:
        unique.setdefault(item["obligation_id"], item)
    return {
        "schema_version": EXECUTION_CONTRACT_VERSION,
        "surface_id": surface_id,
        "feature_id": str(surface.get("feature_id") or ""),
        "threat_id": str(surface.get("threat_id") or ""),
        "endpoint": str(surface.get("endpoint") or ""),
        "method": str(surface.get("method") or "").upper(),
        "param": str(surface.get("param") or ""),
        "roles": _dedupe(surface.get("roles") or []),
        "vuln_class": str(surface.get("vuln_class") or ""),
        "security_invariant": str(surface.get("security_invariant") or ""),
        "observable_violation": str(surface.get("observable_violation") or ""),
        "required_obligations": list(unique.values()),
    }


_RECOVERY_OBLIGATIONS = {
    "object": [
        _obligation("recovery-data-prepared", "barrier_recovery",
                    "Create or locate a real owned object with observable data."),
        _obligation("retest-after-data-recovery", "barrier_recovery",
                    "Repeat the exact cell after data preparation."),
    ],
    "session": [
        _obligation("recovery-session-baseline", "barrier_recovery",
                    "Refresh the authorized session and recapture a valid baseline."),
        _obligation("retest-after-session-recovery", "barrier_recovery",
                    "Repeat the exact cell with the refreshed session."),
    ],
    "format": [
        _obligation("recovery-request-shape", "barrier_recovery",
                    "Resolve method, content type, parameter location, and request shape."),
        _obligation("retest-after-format-recovery", "barrier_recovery",
                    "Repeat the exact cell with the resolved request shape."),
    ],
    "identity": [
        _obligation("recovery-identity-ready", "barrier_recovery",
                    "Provide the authorized role or human challenge input."),
        _obligation("retest-after-identity-recovery", "barrier_recovery",
                    "Repeat the exact cell after identity readiness is restored."),
    ],
    "waf": [
        _obligation("waf-transport-family", "barrier_recovery",
                    "Exercise an independent transport-layer family."),
        _obligation("waf-parser-family", "barrier_recovery",
                    "Exercise an independent parser/normalization family."),
        _obligation("waf-logic-family", "barrier_recovery",
                    "Exercise an equivalent logic-level family."),
        _obligation("waf-blind-family", "barrier_recovery",
                    "Exercise a blind differential family where applicable."),
    ],
}


def _recovery_for_barriers(barriers: Iterable[str]) -> list[dict[str, str]]:
    values = set(barriers)
    groups: list[str] = []
    if values & {"object_absent", "empty_dataset", "ownership_unproven"}:
        groups.append("object")
    if values & {"session_expired", "auth_required"}:
        groups.append("session")
    if "format_unresolved" in values:
        groups.append("format")
    if values & {"missing_role", "challenge_unsolved"}:
        groups.append("identity")
    if values & {"waf_blocked", "waf_bypass_exhausted"}:
        groups.append("waf")
    return [item for group in groups for item in _RECOVERY_OBLIGATIONS[group]]


def _validate_ref(run: pathlib.Path, ref: Any) -> str:
    text = str(ref or "").strip()
    path = pathlib.Path(text)
    if not text or path.is_absolute() or ".." in path.parts:
        raise DynamicExecutionError(
            f"execution evidence ref must stay inside run dir: {text!r}")
    if path.name in _CONTROL_ARTIFACTS or "execution-events" in path.parts:
        raise DynamicExecutionError(
            f"execution evidence ref cannot be a control artifact: {text!r}")
    try:
        payload = safe_read_bytes(run / path, root=run)
    except (OSError, ValueError) as exc:
        raise DynamicExecutionError(
            f"execution evidence ref is unreadable: {text!r}: {exc}") from exc
    if not payload:
        raise DynamicExecutionError(
            f"execution evidence ref is empty: {text!r}")
    return path.as_posix()


def normalize_execution_event(
    run_dir: str | pathlib.Path,
    ledger: CoverageLedger,
    event: dict[str, Any],
) -> dict[str, Any]:
    run = pathlib.Path(run_dir).resolve()
    if not isinstance(event, dict) or event.get("schema_version") != 1:
        raise DynamicExecutionError("execution event schema_version must be 1")
    event_id = str(event.get("event_id") or "")
    if not _ID_RE.fullmatch(event_id):
        raise DynamicExecutionError("execution event_id is invalid")
    outcome = str(event.get("outcome") or "observed").strip().lower()
    if outcome not in _OUTCOMES:
        raise DynamicExecutionError(f"invalid execution outcome: {outcome}")
    surface_id = str(event.get("surface_id") or "")
    surface = ledger.get(surface_id)
    if not surface or surface.get("in_run_scope") is False:
        raise DynamicExecutionError(
            f"execution event references unknown/out-of-run surface: {surface_id}")
    contract = compile_execution_contract(surface)
    allowed_obligations = {
        item["obligation_id"] for item in contract["required_obligations"]
    } | {
        item["obligation_id"]
        for rows in _RECOVERY_OBLIGATIONS.values() for item in rows
    }
    completed = _dedupe(event.get("completed_obligations") or [])
    unknown = sorted(set(completed) - allowed_obligations)
    if unknown:
        raise DynamicExecutionError(
            f"execution event references unknown obligations: {unknown}")
    barriers = _dedupe(event.get("barrier_signals") or [])
    unknown_barriers = sorted(set(barriers) - KNOWN_BARRIERS)
    if unknown_barriers:
        raise DynamicExecutionError(
            f"execution event has unknown barriers: {unknown_barriers}")
    refs = [_validate_ref(run, ref) for ref in _as_list(event.get("evidence_refs"))]
    evidence_sha256 = {
        ref: hashlib.sha256(safe_read_bytes(run / ref, root=run)).hexdigest()
        for ref in refs
    }
    discoveries = _as_list(event.get("discovered_surfaces"))
    if len(completed) > 64 or len(refs) > 32 or len(discoveries) > 16:
        raise DynamicExecutionError("execution event exceeds bounded field limits")
    if (completed or discoveries or outcome != "blocked") and not refs:
        raise DynamicExecutionError(
            "execution completion/discovery requires physical evidence_refs")
    normalized_discoveries: list[dict[str, Any]] = []
    for position, raw in enumerate(discoveries):
        if not isinstance(raw, dict):
            raise DynamicExecutionError(
                f"discovered_surfaces[{position}] must be an object")
        endpoint = str(raw.get("endpoint") or raw.get("path") or "").strip()
        method = str(raw.get("method") or "").strip().upper()
        if not endpoint or not method:
            raise DynamicExecutionError(
                f"discovered_surfaces[{position}] requires method and endpoint")
        normalized_discoveries.append({
            "endpoint": endpoint,
            "method": method,
            "params": _dedupe(raw.get("params") or raw.get("param") or []),
            "source_surface_id": surface_id,
            "source_evidence_refs": refs,
            "disposition": "next_run_required",
        })
    return {
        "schema_version": 1,
        "event_id": event_id,
        "surface_id": surface_id,
        "feature_id": str(surface.get("feature_id") or ""),
        "threat_id": str(surface.get("threat_id") or ""),
        "outcome": outcome,
        "completed_obligations": completed,
        "evidence_refs": refs,
        "evidence_sha256": evidence_sha256,
        "barrier_signals": barriers,
        "discovered_surfaces": normalized_discoveries,
        **({"note": str(event.get("note") or "")[:500]}
           if str(event.get("note") or "").strip() else {}),
    }


def record_execution_event(
    *, run_dir: str | pathlib.Path, ledger: CoverageLedger,
    event: dict[str, Any],
) -> dict[str, Any]:
    """Store a create-only normalized event; authority promotion is external."""
    run = pathlib.Path(run_dir).resolve()
    normalized = normalize_execution_event(run, ledger, event)
    destination = (
        run / "state" / "execution-events" /
        f"{normalized['event_id']}.json"
    )
    ensure_directory(destination.parent, root=run)
    created = create_json_exclusive(destination, normalized, root=run)
    if not created:
        try:
            existing = json.loads(safe_read_text(destination, root=run))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise DynamicExecutionError(
                f"existing execution event is invalid: {exc}") from exc
        if existing != normalized:
            raise DynamicExecutionError(
                f"execution event_id already exists with different content: "
                f"{normalized['event_id']}")
    return {
        "path": destination.relative_to(run).as_posix(),
        "idempotent": not created,
        "event": normalized,
    }


def parse_execution_event_lines(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    for raw in EXECUTION_EVENT_RE.findall(text or ""):
        try:
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("event must be an object")
            events.append(value)
        except (ValueError, json.JSONDecodeError) as exc:
            errors.append(f"invalid EXECUTION_EVENT JSON: {exc}")
    return events, errors


def load_run_execution_events(run_dir: str | pathlib.Path) -> list[dict[str, Any]]:
    run = pathlib.Path(run_dir).resolve()
    root = run / "state" / "execution-events"
    if not root.is_dir():
        return []
    events: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json")):
        try:
            value = json.loads(safe_read_text(path, root=run))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise DynamicExecutionError(
                f"invalid execution event {path.name}: {exc}") from exc
        if not isinstance(value, dict):
            raise DynamicExecutionError(
                f"invalid execution event {path.name}: expected object")
        events.append(value)
    return events


def rejected_finding_surface_ids(
    run_dir: str | pathlib.Path,
    ledger: CoverageLedger,
    rejected_findings: Iterable[dict[str, Any]],
) -> list[str]:
    """Bind rejected canonical Finding files back to their frozen threat cells."""
    run = pathlib.Path(run_dir).resolve()
    matched: set[str] = set()
    for item in rejected_findings:
        if not isinstance(item, dict):
            continue
        raw_path = pathlib.Path(str(item.get("path") or ""))
        path = raw_path if raw_path.is_absolute() else run / raw_path
        try:
            resolved = path.resolve(strict=False)
            resolved.relative_to(run)
            finding = json.loads(safe_read_text(resolved, root=run))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(finding, dict):
            continue
        feature = finding.get("feature_point")
        feature = feature if isinstance(feature, dict) else {}
        claim = finding.get("claim")
        claim = claim if isinstance(claim, dict) else {}
        feature_id = str(feature.get("feature_id") or "")
        threat_id = str(claim.get("threat_id") or "")
        if not feature_id or not threat_id:
            continue
        apis = [api for api in _as_list(finding.get("apis"))
                if isinstance(api, dict)]
        for surface in ledger.surfaces:
            if (str(surface.get("feature_id") or "") != feature_id
                    or str(surface.get("threat_id") or "") != threat_id):
                continue
            if apis:
                endpoint = str(surface.get("endpoint") or "").split("?", 1)[0]
                method = str(surface.get("method") or "").upper()
                param = str(surface.get("param") or "")
                api_match = False
                for api in apis:
                    api_endpoint = str(
                        api.get("path") or api.get("endpoint") or ""
                    ).split("?", 1)[0]
                    api_method = str(api.get("method") or "").upper()
                    params = _dedupe(api.get("risk_params") or [])
                    if (api_endpoint == endpoint and api_method == method
                            and (not params or not param or param in params)):
                        api_match = True
                        break
                if not api_match:
                    continue
            matched.add(str(surface.get("surface_id") or ""))
    return sorted(value for value in matched if value)


def load_authority_execution_events(
    authority_dir: str | pathlib.Path, session_id: str,
) -> list[dict[str, Any]]:
    """Read and verify the host-owned execution event hash chain."""
    authority = pathlib.Path(authority_dir).resolve()
    path = authority / "events" / str(session_id) / "execution.jsonl"
    if not path.exists():
        return []
    if path.is_symlink():
        raise DynamicExecutionError("authority execution event chain is a symlink")
    previous = ""
    expected_sequence = 1
    events: list[dict[str, Any]] = []
    try:
        lines = safe_read_text(path, root=authority).splitlines()
    except (OSError, ValueError) as exc:
        raise DynamicExecutionError(
            f"authority execution event chain is unreadable: {exc}") from exc
    for line in lines:
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise DynamicExecutionError(
                f"authority execution event chain JSON is invalid: {exc}") from exc
        supplied = str(record.get("event_sha256") or "")
        canonical = dict(record)
        canonical.pop("event_sha256", None)
        if (record.get("stream") != "execution"
                or int(record.get("sequence", 0) or 0) != expected_sequence
                or str(record.get("previous_event_sha256") or "") != previous
                or supplied != canonical_digest(canonical)):
            raise DynamicExecutionError(
                "authority execution event hash chain is invalid")
        event = record.get("event")
        if not isinstance(event, dict):
            raise DynamicExecutionError(
                "authority execution event payload must be an object")
        events.append(event)
        previous = supplied
        expected_sequence += 1
    return events


def _event_obligation_evidence(
    events: Iterable[dict[str, Any]],
) -> tuple[set[str], dict[str, list[str]], set[str], list[dict[str, Any]]]:
    completed: set[str] = set()
    mapping: dict[str, list[str]] = {}
    barriers: set[str] = set()
    discoveries: list[dict[str, Any]] = []
    for event in events:
        refs = _dedupe(event.get("evidence_refs") or [])
        for obligation_id in _dedupe(event.get("completed_obligations") or []):
            completed.add(obligation_id)
            mapping[obligation_id] = _dedupe([
                *mapping.get(obligation_id, []), *refs,
            ])
        barriers.update(_dedupe(event.get("barrier_signals") or []))
        discoveries.extend(
            item for item in _as_list(event.get("discovered_surfaces"))
            if isinstance(item, dict))
    # Barrier observations are append-only, but a barrier is no longer active
    # once every deterministic recovery obligation for that barrier has
    # evidence.  This gives the reducer a monotonic recovery transition without
    # allowing model text to erase a blocker.
    for barrier in list(barriers):
        recovery_ids = {
            item["obligation_id"] for item in _recovery_for_barriers([barrier])
        }
        if recovery_ids and recovery_ids.issubset(completed):
            barriers.discard(barrier)
    return completed, mapping, barriers, discoveries


def build_execution_projection(
    ledger: CoverageLedger,
    events: Iterable[dict[str, Any]],
    *, rejected_surface_ids: Iterable[str] = (),
) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    event_ids: set[str] = set()
    for event in events:
        if not isinstance(event, dict):
            continue
        event_id = str(event.get("event_id") or "")
        if event_id and event_id in event_ids:
            continue
        if event_id:
            event_ids.add(event_id)
        grouped.setdefault(str(event.get("surface_id") or ""), []).append(event)
    rejected = set(str(value) for value in rejected_surface_ids)
    contracts: list[dict[str, Any]] = []
    progress_rows: list[dict[str, Any]] = []
    backlog: list[dict[str, Any]] = []
    queue: list[dict[str, Any]] = []
    for surface in ledger.surfaces:
        if surface.get("in_run_scope") is False:
            continue
        contract = compile_execution_contract(surface)
        current_events = grouped.get(contract["surface_id"], [])
        completed, evidence_map, barriers, discoveries = (
            _event_obligation_evidence(current_events))
        recovery = _recovery_for_barriers(barriers)
        required = [*contract["required_obligations"], *recovery]
        unique_required: dict[str, dict[str, str]] = {
            item["obligation_id"]: item for item in required
        }
        missing = [
            item for key, item in unique_required.items() if key not in completed
        ]
        status = normalize_status(surface.get("status"))
        closure_allowed = False
        if status in {STATUS_CONFIRMED, STATUS_NOT_APPLICABLE}:
            execution_status = "closed"
            closure_allowed = True
        elif contract["surface_id"] in rejected:
            execution_status = "proof_repair"
        elif status == STATUS_NOT_VULNERABLE and not missing and not barriers:
            execution_status = "closed"
            closure_allowed = True
        elif status == STATUS_BLOCKED or barriers & {
                "object_absent", "empty_dataset", "ownership_unproven",
                "session_expired", "auth_required", "format_unresolved",
                "missing_role", "challenge_unsolved"}:
            execution_status = "blocked_recoverable"
        elif status in {STATUS_SHALLOW_NEGATIVE, STATUS_EXPLORING,
                        STATUS_NOT_VULNERABLE}:
            execution_status = "needs_followup"
        elif current_events:
            execution_status = "executing"
        else:
            execution_status = "ready"
        row = {
            "surface_id": contract["surface_id"],
            "feature_id": contract["feature_id"],
            "threat_id": contract["threat_id"],
            "ledger_status": status,
            "execution_status": execution_status,
            "closure_allowed": closure_allowed,
            "event_ids": [str(item.get("event_id") or "") for item in current_events],
            "completed_obligations": sorted(completed),
            "missing_obligations": missing,
            "obligation_evidence": {
                key: value for key, value in sorted(evidence_map.items())
            },
            "barrier_signals": sorted(barriers),
        }
        contracts.append({
            **contract,
            "required_obligations": list(unique_required.values()),
        })
        progress_rows.append(row)
        for discovery in discoveries:
            backlog.append({
                **discovery,
                "source_surface_id": contract["surface_id"],
                "disposition": "next_run_required",
            })
        if execution_status != "closed":
            queue.append({
                "surface_id": contract["surface_id"],
                "feature_id": contract["feature_id"],
                "threat_id": contract["threat_id"],
                "endpoint": contract["endpoint"],
                "method": contract["method"],
                "param": contract["param"],
                "roles": contract["roles"],
                "vuln_class": contract["vuln_class"],
                "execution_status": execution_status,
                "barrier_signals": sorted(barriers),
                "next_obligations": missing[:6],
                "high_value": bool(is_high_value(surface)),
            })
    priority = {
        "proof_repair": 0,
        "blocked_recoverable": 1,
        "needs_followup": 2,
        "executing": 3,
        "ready": 4,
    }
    queue.sort(key=lambda item: (
        priority.get(item["execution_status"], 9),
        0 if item["high_value"] else 1,
        item["feature_id"], item["surface_id"],
    ))
    deduped_backlog: dict[str, dict[str, Any]] = {}
    for item in backlog:
        key = json.dumps({
            "method": item.get("method"), "endpoint": item.get("endpoint"),
            "params": item.get("params") or [],
            "source_surface_id": item.get("source_surface_id"),
        }, ensure_ascii=False, sort_keys=True)
        deduped_backlog.setdefault(key, item)
    projection = {
        "schema_version": EXECUTION_CONTRACT_VERSION,
        "execution_contract_version": EXECUTION_CONTRACT_VERSION,
        "contracts": contracts,
        "progress": progress_rows,
        "queue": queue[:EXECUTION_QUEUE_LIMIT],
        "backlog": list(deduped_backlog.values()),
        "stats": {
            "contracts": len(contracts),
            "closed": sum(1 for item in progress_rows
                          if item["execution_status"] == "closed"),
            "open": sum(1 for item in progress_rows
                        if item["execution_status"] != "closed"),
            "events": len(event_ids),
            "backlog": len(deduped_backlog),
        },
    }
    projection["projection_sha256"] = canonical_digest(projection)
    return projection


def write_execution_projection(
    run_dir: str | pathlib.Path,
    ledger: CoverageLedger,
    events: Iterable[dict[str, Any]],
    *, rejected_surface_ids: Iterable[str] = (),
) -> dict[str, Any]:
    run = pathlib.Path(run_dir).resolve()
    projection = build_execution_projection(
        ledger, events, rejected_surface_ids=rejected_surface_ids)
    atomic_write_json(run / "execution-contracts.json", {
        "schema_version": EXECUTION_CONTRACT_VERSION,
        "execution_contract_version": EXECUTION_CONTRACT_VERSION,
        "contracts": projection["contracts"],
    }, root=run, reject_leaf_symlink=True)
    atomic_write_json(run / "execution-progress.json", {
        key: value for key, value in projection.items()
        if key not in {"contracts", "queue", "backlog"}
    } | {"progress": projection["progress"]}, root=run,
        reject_leaf_symlink=True)
    atomic_write_json(run / "execution-queue.json", {
        "schema_version": EXECUTION_CONTRACT_VERSION,
        "queue": projection["queue"],
        "stats": projection["stats"],
    }, root=run, reject_leaf_symlink=True)
    atomic_write_json(run / "execution-backlog.json", {
        "schema_version": EXECUTION_CONTRACT_VERSION,
        "disposition": "next_run_required",
        "surfaces": projection["backlog"],
    }, root=run, reject_leaf_symlink=True)
    return projection


def render_execution_queue(projection: dict[str, Any]) -> str:
    queue = projection.get("queue") or []
    stats = projection.get("stats") or {}
    lines = [
        "## 动态执行队列（Host 维护）",
        f"- Experiment contracts: closed {stats.get('closed', 0)}/"
        f"{stats.get('contracts', 0)}；events={stats.get('events', 0)}；"
        f"next-run backlog={stats.get('backlog', 0)}",
        "- 每组真实实验后必须输出一行紧凑 JSON："
        "`EXECUTION_EVENT: {\"schema_version\":1,\"event_id\":\"...\","
        "\"surface_id\":\"...\",\"outcome\":\"observed\","
        "\"completed_obligations\":[\"...\"],"
        "\"evidence_refs\":[\"evidence/...\"],\"barrier_signals\":[]}`",
        "- Event 只推进实验队列；阳性仍需 canonical Finding，阴性仍需 canonical negative。",
    ]
    if not queue:
        lines.append("- 当前无 open execution contract。")
        return "\n".join(lines)
    for index, item in enumerate(queue, start=1):
        missing = item.get("next_obligations") or []
        obligation_text = "；".join(
            f"{row.get('obligation_id')}: {row.get('description')}"
            for row in missing)
        lines.append(
            f"{index}. `{item.get('surface_id')}` · {item.get('method')} "
            f"{item.get('endpoint')} · param={item.get('param') or '(none)'} · "
            f"{item.get('vuln_class')} · state={item.get('execution_status')}\n"
            f"   缺少：{obligation_text or '按 proof-repair/barrier 指令返工'}"
        )
    return "\n".join(lines)


def projection_matches_files(
    run_dir: str | pathlib.Path, projection: dict[str, Any],
) -> list[str]:
    """Compare a recomputed projection with all four model-writable views."""
    run = pathlib.Path(run_dir).resolve()
    expected = {
        "execution-contracts.json": {
            "schema_version": EXECUTION_CONTRACT_VERSION,
            "execution_contract_version": EXECUTION_CONTRACT_VERSION,
            "contracts": projection["contracts"],
        },
        "execution-progress.json": {
            key: value for key, value in projection.items()
            if key not in {"contracts", "queue", "backlog"}
        } | {"progress": projection["progress"]},
        "execution-queue.json": {
            "schema_version": EXECUTION_CONTRACT_VERSION,
            "queue": projection["queue"],
            "stats": projection["stats"],
        },
        "execution-backlog.json": {
            "schema_version": EXECUTION_CONTRACT_VERSION,
            "disposition": "next_run_required",
            "surfaces": projection["backlog"],
        },
    }
    reasons: list[str] = []
    for name, value in expected.items():
        try:
            actual = json.loads(safe_read_text(run / name, root=run))
        except (OSError, ValueError, json.JSONDecodeError):
            reasons.append(f"execution_projection_missing_or_invalid:{name}")
            continue
        if actual != value:
            reasons.append(f"execution_projection_mismatch:{name}")
    return reasons


__all__ = [
    "DynamicExecutionError",
    "EXECUTION_CONTRACT_VERSION",
    "EXECUTION_EVENT_RE",
    "EXECUTION_QUEUE_LIMIT",
    "KNOWN_BARRIERS",
    "build_execution_projection",
    "compile_execution_contract",
    "load_authority_execution_events",
    "load_run_execution_events",
    "normalize_execution_event",
    "parse_execution_event_lines",
    "projection_matches_files",
    "rejected_finding_surface_ids",
    "record_execution_event",
    "render_execution_queue",
    "write_execution_projection",
]
