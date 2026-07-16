"""Deterministic Direct-Skill execution feedback runtime.

This module improves execution quality in QoderWork/Direct Skill environments
without pretending to establish an independent authority.  It initializes an
exact runtime ledger, stores append-only per-agent observations, reduces them
through the same proof/negative gates used by Engine Mode, and emits a bounded
work queue.  Every artifact produced here remains diagnostic:
``authority_trusted=false`` and ``delivery_eligible=false`` are invariants.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from typing import Any, Iterable

try:
    from .blocker import RECOVERABLE, resolve_blocker
    from .knowledge import (
        load_cards,
        match_cards,
        negative_barrier_signals,
        negative_sufficient,
        render_skill_hint,
    )
    from .ledger import (
        STATUS_BLOCKED,
        STATUS_CONFIRMED,
        STATUS_EXPLORING,
        STATUS_NOT_APPLICABLE,
        STATUS_NOT_TESTED,
        STATUS_NOT_VULNERABLE,
        STATUS_SHALLOW_NEGATIVE,
        CoverageLedger,
    )
    from .orchestrator import CognitiveState
    from .planner import plan_surfaces
    from .project_state import canonical_asset
    from .reporting.collect import collect_structured_findings
    from .safe_io import (
        atomic_write_json,
        create_json_exclusive,
        ensure_directory,
        safe_read_bytes,
        safe_read_text,
    )
    from .surface import bootstrap as bootstrap_recon
    from .threat_model import (
        ThreatModelError,
        compile_threat_model,
        derive_threat_coverage,
        validate_threat_plan,
    )
    from .vuln_classes import norm_vc
except ImportError:  # pragma: no cover - script execution fallback
    from blocker import RECOVERABLE, resolve_blocker
    from knowledge import (load_cards, match_cards, negative_barrier_signals,
                           negative_sufficient, render_skill_hint)
    from ledger import (STATUS_BLOCKED, STATUS_CONFIRMED, STATUS_EXPLORING,
                        STATUS_NOT_APPLICABLE, STATUS_NOT_TESTED,
                        STATUS_NOT_VULNERABLE, STATUS_SHALLOW_NEGATIVE,
                        CoverageLedger)
    from orchestrator import CognitiveState
    from planner import plan_surfaces
    from project_state import canonical_asset
    from reporting.collect import collect_structured_findings
    from safe_io import (atomic_write_json, create_json_exclusive,
                         ensure_directory, safe_read_bytes, safe_read_text)
    from surface import bootstrap as bootstrap_recon
    from threat_model import (ThreatModelError, compile_threat_model,
                              derive_threat_coverage, validate_threat_plan)
    from vuln_classes import norm_vc


class SkillRuntimeError(RuntimeError):
    pass


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_OUTCOMES = {"confirmed", "negative", "blocked", "exploring"}
_CLOSED = {STATUS_CONFIRMED, STATUS_NOT_VULNERABLE, STATUS_NOT_APPLICABLE}
_WAF_SIGNALS = {"waf_blocked", "waf_bypass_exhausted"}
_OBJECT_SIGNALS = {"object_absent", "empty_dataset", "ownership_unproven"}
_SESSION_SIGNALS = {"session_expired", "auth_required"}
_FORMAT_SIGNALS = {"format_unresolved"}
_HUMAN_SIGNALS = {"missing_role", "challenge_unsolved"}
DIRECT_QUEUE_LIMIT = 16
DIRECT_HINT_CARD_LIMIT = 4


def _load_json(path: pathlib.Path, *, root: pathlib.Path | None = None) -> Any:
    absolute = path.resolve()
    safe_root = root.resolve() if root is not None else absolute.parent
    try:
        return json.loads(safe_read_text(absolute, root=safe_root))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SkillRuntimeError(f"invalid JSON {path}: {exc}") from exc


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


def _inventory_rows(path: pathlib.Path | None) -> list[dict[str, Any] | str]:
    if path is None:
        return []
    value = _load_json(path)
    if isinstance(value, dict):
        rows = (value.get("surfaces") or value.get("endpoints")
                or value.get("discovered_apis") or [])
    else:
        rows = value
    if not isinstance(rows, list):
        raise SkillRuntimeError("inventory must contain a surfaces/endpoints list")
    return [row for row in rows if isinstance(row, (dict, str))]


def _row_key(row: dict[str, Any] | str) -> tuple[str, str]:
    if isinstance(row, str):
        parts = row.strip().split(None, 1)
        if len(parts) == 2 and parts[0].isalpha():
            return parts[1].split("?", 1)[0], parts[0].upper()
        return row.split("?", 1)[0], ""
    endpoint = str(row.get("endpoint") or row.get("path") or row.get("url") or "")
    return endpoint.split("?", 1)[0], str(row.get("method") or "").upper()


def _merge_rows(rows: list[dict[str, Any] | str]) -> list[dict[str, Any] | str]:
    merged: dict[tuple[str, str], dict[str, Any] | str] = {}
    for row in rows:
        key = _row_key(row)
        if not key[0]:
            continue
        existing = merged.get(key)
        if existing is None or isinstance(existing, str) or isinstance(row, str):
            if existing is None or isinstance(row, dict):
                merged[key] = dict(row) if isinstance(row, dict) else row
            continue
        current = dict(existing)
        for field, value in row.items():
            if field in {"params", "roles", "risk_tags", "vuln_classes", "source"}:
                current[field] = _dedupe(_as_list(current.get(field)) + _as_list(value))
            elif value not in (None, "", [], {}) and field not in current:
                current[field] = value
        merged[key] = current
    return [merged[key] for key in sorted(merged)]


def _cards_for_surface(surface: dict[str, Any], cards: list[dict]) -> list[dict]:
    return match_cards(surface, cards)


def _decorate_surface(surface: dict[str, Any], cards: list[dict]) -> None:
    matched = _cards_for_surface(surface, cards)
    surface["knowledge_card_ids"] = [str(card.get("id")) for card in matched if card.get("id")]


def _queue_from_ledger(ledger: CoverageLedger, cards: list[dict]) -> list[dict[str, Any]]:
    queue: list[dict[str, Any]] = []
    for surface in ledger.next_surfaces(DIRECT_QUEUE_LIMIT):
        matched = _cards_for_surface(surface, cards)
        hint_cards = matched[:DIRECT_HINT_CARD_LIMIT]
        queue.append({
            "surface_id": surface.get("surface_id", ""),
            "asset_id": surface.get("asset_id", ""),
            "endpoint": surface.get("endpoint", ""),
            "method": surface.get("method", ""),
            "param": surface.get("param", ""),
            "roles": list(surface.get("roles") or []),
            "vuln_class": surface.get("vuln_class", ""),
            "feature_id": surface.get("feature_id", ""),
            "threat_id": surface.get("threat_id", ""),
            "security_invariant": surface.get("security_invariant", ""),
            "observable_violation": surface.get("observable_violation", ""),
            "evidence_required": list(surface.get("evidence_required") or []),
            "status": surface.get("status", STATUS_NOT_TESTED),
            "next_actions": list(surface.get("next_actions") or []),
            "knowledge_card_ids": [card.get("id") for card in matched if card.get("id")],
            "knowledge_hint": render_skill_hint(hint_cards),
        })
    return queue


def _runtime_status(
    run: pathlib.Path,
    ledger: CoverageLedger,
    *,
    accepted_findings: int = 0,
    rejected_findings: int = 0,
    projection_stale: bool = False,
    observation_errors: int = 0,
    threat_coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    stats = ledger.stats()
    planning_mode = str(ledger.metadata.get("planning_mode") or "legacy_risk")
    planning_degraded = bool(
        ledger.metadata.get("planning_degraded", planning_mode != "threat_model"))
    threat_stats = (threat_coverage or {}).get("stats") or {}
    threat_closed = (
        planning_mode == "threat_model"
        and int(threat_stats.get("open_threats", 1) or 0) == 0
        and int(threat_stats.get("open_features", 1) or 0) == 0
    )
    return {
        "schema_version": 1,
        "mode": "direct_diagnostic",
        "run_dir": str(run),
        "authority_trusted": False,
        "delivery_eligible": False,
        "planning_mode": planning_mode,
        "planning_degraded": planning_degraded,
        "coverage": stats,
        "accepted_findings": accepted_findings,
        "rejected_findings": rejected_findings,
        "projection_stale": projection_stale,
        "observation_errors": observation_errors,
        "report_ready": bool(
            not planning_degraded and threat_closed
            and stats.get("total") and not stats.get("open")
            and not projection_stale and not rejected_findings
            and not observation_errors),
    }


def initialize_direct_run(
    *,
    run_dir: pathlib.Path,
    target: str,
    inventory_path: pathlib.Path | None = None,
    recon_dir: pathlib.Path | None = None,
    feature_graph_path: pathlib.Path | None = None,
    threat_model_path: pathlib.Path | None = None,
) -> dict[str, Any]:
    """Initialize a diagnostic Direct-Skill ledger and bounded work queue."""
    run = run_dir.resolve()
    ensure_directory(run, root=run.parent)
    rows = _inventory_rows(inventory_path)
    if recon_dir is not None:
        rows.extend(bootstrap_recon(recon_dir))
    rows = _merge_rows(rows)
    if not rows:
        raise SkillRuntimeError("Direct runtime needs inventory or recon observations")

    if (feature_graph_path is None) != (threat_model_path is None):
        raise SkillRuntimeError(
            "feature_graph_path and threat_model_path must be provided together")
    planning_mode = "legacy_risk"
    planning_degraded = True
    normalized_threat_model: dict[str, Any] | None = None
    planning_artifact_hashes: dict[str, str] = {}
    if feature_graph_path is not None and threat_model_path is not None:
        feature_graph = _load_json(feature_graph_path)
        threat_model = _load_json(threat_model_path)
        try:
            plan = validate_threat_plan(
                feature_graph, threat_model, rows, run_dir=run)
        except ThreatModelError as exc:
            raise SkillRuntimeError(str(exc)) from exc
        planned = compile_threat_model(plan, rows, target=target)
        if not planned:
            raise SkillRuntimeError("threat plan compiled no executable threat cells")
        planning_mode = "threat_model"
        planning_degraded = False
        normalized_threat_model = plan["threat_model"]
        atomic_write_json(
            run / "feature-graph.json", plan["feature_graph"], root=run,
            reject_leaf_symlink=True)
        atomic_write_json(
            run / "threat-model.json", normalized_threat_model, root=run,
            reject_leaf_symlink=True)
        planning_artifact_hashes = {
            name: hashlib.sha256(safe_read_bytes(run / name, root=run)).hexdigest()
            for name in ("feature-graph.json", "threat-model.json")
        }
        ledger = CoverageLedger(planned, metadata={
            "sid": run.name,
            "target": target,
            "source": "direct-skill-runtime",
            "authority_trusted": False,
            "planning_mode": planning_mode,
            "planning_degraded": planning_degraded,
        })
    else:
        planned = plan_surfaces(rows)
        if not planned:
            raise SkillRuntimeError("inventory has no method-resolved surface")
        state = CognitiveState(run.name, target)
        state.seed_matrix(planned)
        ledger = CoverageLedger.from_state({
            "sid": run.name,
            "target": target,
            "matrix": state.matrix,
        })
    if not planned:
        raise SkillRuntimeError("inventory has no method-resolved surface")
    cards = load_cards()
    for surface in ledger.surfaces:
        surface["in_run_scope"] = True
        surface["source"] = "direct-skill-runtime"
        _decorate_surface(surface, cards)

    unresolved = [row for row in rows if not _row_key(row)[1]]
    resolved = [row for row in rows if _row_key(row)[1]]
    atomic_write_json(run / "inventory.json", {
        "schema_version": "2.0",
        "target": target,
        "endpoints": resolved,
        "unresolved": unresolved,
    }, root=run, reject_leaf_symlink=True)
    ledger.metadata.update({
        "sid": run.name,
        "target": target,
        "source": "direct-skill-runtime",
        "authority_trusted": False,
        "planning_mode": planning_mode,
        "planning_degraded": planning_degraded,
        "planning_artifact_hashes": planning_artifact_hashes,
    })
    ledger.save(run / "coverage-ledger.json")
    atomic_write_json(run / "candidate-ledger.json", {
        "schema_version": "1.1", "candidates": [],
    }, root=run, reject_leaf_symlink=True)
    queue = _queue_from_ledger(ledger, cards)
    atomic_write_json(run / "execution-queue.json", {
        "schema_version": 1, "queue": queue,
    }, root=run, reject_leaf_symlink=True)
    threat_coverage = None
    if normalized_threat_model is not None:
        threat_coverage = derive_threat_coverage(
            ledger.surfaces, normalized_threat_model)
        atomic_write_json(
            run / "threat-coverage.json", threat_coverage, root=run,
            reject_leaf_symlink=True)
    status = _runtime_status(run, ledger, threat_coverage=threat_coverage)
    atomic_write_json(run / "runtime-status.json", status, root=run, reject_leaf_symlink=True)
    return {**status, "execution_queue": queue}


def _validate_ref(run: pathlib.Path, ref: str) -> str:
    text = str(ref or "").strip()
    path = pathlib.Path(text)
    if not text or path.is_absolute() or ".." in path.parts:
        raise SkillRuntimeError(f"evidence ref must stay inside run dir: {text}")
    candidate = run / path
    try:
        safe_read_bytes(candidate, root=run)
    except (OSError, ValueError) as exc:
        raise SkillRuntimeError(f"invalid evidence ref {text}: {exc}") from exc
    return path.as_posix()


def record_observation(
    *,
    run_dir: pathlib.Path,
    agent_id: str,
    observation: dict[str, Any],
) -> dict[str, Any]:
    """Create one immutable observation or accept an identical retry."""
    run = run_dir.resolve()
    if not _ID_RE.fullmatch(agent_id or ""):
        raise SkillRuntimeError("invalid agent_id")
    if not isinstance(observation, dict) or observation.get("schema_version") != 1:
        raise SkillRuntimeError("observation schema_version must be 1")
    observation_id = str(observation.get("observation_id") or "")
    if not _ID_RE.fullmatch(observation_id):
        raise SkillRuntimeError("invalid observation_id")
    outcome = str(observation.get("outcome") or "").strip().lower()
    if outcome not in _OUTCOMES:
        raise SkillRuntimeError(f"invalid observation outcome: {outcome}")
    ledger = CoverageLedger.load(run / "coverage-ledger.json")
    surface_id = str(observation.get("surface_id") or "")
    surface = ledger.get(surface_id)
    if not surface:
        raise SkillRuntimeError(f"observation references unknown surface: {surface_id}")
    for key in ("feature_id", "threat_id"):
        expected = str(surface.get(key) or "")
        supplied = str(observation.get(key) or "")
        if supplied and supplied != expected:
            raise SkillRuntimeError(
                f"observation {key} mismatch: expected {expected!r}, got {supplied!r}")

    refs = [_validate_ref(run, str(ref)) for ref in _as_list(observation.get("evidence_refs"))]
    normalized = {
        **observation,
        "schema_version": 1,
        "agent_id": agent_id,
        "observation_id": observation_id,
        "surface_id": surface_id,
        "outcome": outcome,
        "evidence_refs": refs,
        **({"feature_id": surface["feature_id"]} if surface.get("feature_id") else {}),
        **({"threat_id": surface["threat_id"]} if surface.get("threat_id") else {}),
    }
    destination = run / "state" / "observations" / f"{agent_id}--{observation_id}.json"
    ensure_directory(destination.parent, root=run)
    created = create_json_exclusive(destination, normalized, root=run)
    if created:
        return {"path": destination.relative_to(run).as_posix(), "idempotent": False}
    existing = _load_json(destination, root=run)
    if existing != normalized:
        raise SkillRuntimeError(
            f"observation id already exists with different content: {agent_id}/{observation_id}")
    return {"path": destination.relative_to(run).as_posix(), "idempotent": True}


def _read_observations(run: pathlib.Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    root = run / "state" / "observations"
    if not root.exists():
        return [], []
    observations: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for path in sorted(root.glob("*.json")):
        try:
            value = _load_json(path, root=run)
            if not isinstance(value, dict):
                raise SkillRuntimeError("observation must be an object")
            observations.append(value)
        except SkillRuntimeError as exc:
            errors.append({"path": path.relative_to(run).as_posix(), "error": str(exc)})
    return observations, errors


def _finding_matches_surface(normalized: dict[str, Any], surface: dict[str, Any]) -> bool:
    expected_method = str(surface.get("method") or "").upper()
    expected_endpoint = str(surface.get("endpoint") or "").split("?", 1)[0]
    expected_param = str(surface.get("param") or "")
    expected_class = norm_vc(str(surface.get("vuln_class") or ""))
    expected_asset = canonical_asset(str(surface.get("asset_id") or ""))
    expected_roles = {str(role).lower() for role in surface.get("roles") or ["unknown"]}
    exact_dimensions = {
        "namespace": str(surface.get("namespace") or ""),
        "param_location": str(surface.get("param_location") or "").lower(),
        "subject_role": str(surface.get("subject_role") or "").lower(),
        "object_kind": str(surface.get("object_kind") or "").lower(),
    }

    def path_matches(left: str, right: str) -> bool:
        if left == right:
            return True
        for template, concrete in ((left, right), (right, left)):
            if "{" not in template:
                continue
            pattern = re.sub(r"\\\{[^{}]+\\\}", r"[^/]+", re.escape(template))
            if re.fullmatch(pattern, concrete):
                return True
        return False

    rows = normalized.get("exact_cells") or []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("method") or "").upper() != expected_method:
            continue
        row_endpoint = str(
            row.get("endpoint") or row.get("path") or "").split("?", 1)[0]
        if not path_matches(row_endpoint, expected_endpoint):
            continue
        if str(row.get("param") or "") != expected_param:
            continue
        role = str(row.get("actor_role") or row.get("role_scope") or "unknown").lower()
        if expected_roles and role not in expected_roles:
            continue
        row_asset = canonical_asset(str(row.get("asset_id") or row.get("asset") or ""))
        if expected_asset and row_asset != expected_asset:
            continue
        if any(
            expected and str(row.get(field) or "").strip().lower() != expected
            for field, expected in exact_dimensions.items()
        ):
            continue
        row_class = norm_vc(str(row.get("vuln_class") or normalized.get("vuln_class") or ""))
        if expected_class and row_class and row_class != expected_class:
            continue
        return True
    return False


def _proof_ref_for_observation(
    run: pathlib.Path,
    surface: dict[str, Any],
    observation: dict[str, Any],
    accepted_by_path: dict[str, dict[str, Any]],
) -> str:
    for ref in observation.get("evidence_refs") or []:
        absolute = str((run / ref).resolve())
        normalized = accepted_by_path.get(absolute)
        if normalized and _finding_matches_surface(normalized, surface):
            return str(ref)
    return ""


def _blocker_for_signals(signals: set[str], surface: dict[str, Any]) -> tuple[dict, list[str]]:
    if signals & _OBJECT_SIGNALS:
        token = "object absent"
    elif signals & _SESSION_SIGNALS:
        token = "session expired"
    elif signals & _FORMAT_SIGNALS:
        token = "format unresolved"
    elif "missing_role" in signals:
        token = "missing role"
    elif "challenge_unsolved" in signals:
        token = "captcha"
    else:
        token = "unknown"
    resolution = resolve_blocker(token, surface)
    blocker = {
        **resolution.to_dict(),
        "kind": resolution.blocker_type,
        "recoverable": resolution.category == RECOVERABLE,
    }
    return blocker, list(resolution.next_actions)


def _projection_stale(run: pathlib.Path, accepted_count: int) -> bool:
    summary = run / "state" / "findings_summary.md"
    if not summary.is_file() or summary.is_symlink():
        return False
    try:
        lines = safe_read_text(summary, root=run).splitlines()
    except (OSError, ValueError):
        return True
    table_rows = [
        line for line in lines
        if line.lstrip().startswith("|")
        and "---" not in line
        and "漏洞名" not in line
        and "title" not in line.lower()
    ]
    return len(table_rows) != accepted_count


def checkpoint_direct_run(run_dir: pathlib.Path) -> dict[str, Any]:
    """Reduce all immutable observations into ledger/status/queue projections."""
    run = run_dir.resolve()
    ledger = CoverageLedger.load(run / "coverage-ledger.json")
    for name, expected in sorted(
            (ledger.metadata.get("planning_artifact_hashes") or {}).items()):
        try:
            actual = hashlib.sha256(
                safe_read_bytes(run / str(name), root=run)).hexdigest()
        except (OSError, ValueError) as exc:
            raise SkillRuntimeError(
                f"planning artifact is missing or unsafe: {name}: {exc}") from exc
        if actual != str(expected or ""):
            raise SkillRuntimeError(
                f"planning artifact digest mismatch: {name}")
    cards = load_cards()
    observations, observation_errors = _read_observations(run)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for observation in observations:
        grouped.setdefault(str(observation.get("surface_id") or ""), []).append(observation)

    target = str(ledger.metadata.get("target") or "").strip()
    collected = collect_structured_findings(
        run, authorized_hosts=[target] if target else None)
    accepted_by_path: dict[str, dict[str, Any]] = {}
    for accepted, normalized in zip(collected.get("accepted") or [], collected.get("normalized") or []):
        accepted_by_path[str(pathlib.Path(accepted["path"]).resolve())] = normalized

    conflicts: list[dict[str, Any]] = []
    for surface in ledger.surfaces:
        current = grouped.get(str(surface.get("surface_id") or ""), [])
        if not current:
            _decorate_surface(surface, cards)
            continue
        proof_refs: list[str] = []
        declared_positive = False
        negative_results: list[dict[str, Any]] = []
        explicit_blockers: list[dict[str, Any]] = []
        for observation in current:
            outcome = str(observation.get("outcome") or "")
            if outcome == "confirmed":
                declared_positive = True
                proof_ref = _proof_ref_for_observation(
                    run, surface, observation, accepted_by_path)
                if proof_ref:
                    proof_refs.append(proof_ref)
            elif outcome == "negative":
                negative = observation.get("negative")
                negative = dict(negative) if isinstance(negative, dict) else {}
                signals = set(negative_barrier_signals(negative))
                if signals & _WAF_SIGNALS:
                    status = STATUS_SHALLOW_NEGATIVE
                    blocker = None
                    actions = [
                        "review the WAF knowledge card and try independent bypass families",
                        "keep waf_bypass_exhausted as shallow_negative; do not close the backend cell",
                    ]
                elif signals & (_OBJECT_SIGNALS | _SESSION_SIGNALS | _FORMAT_SIGNALS | _HUMAN_SIGNALS):
                    status = STATUS_BLOCKED
                    blocker, actions = _blocker_for_signals(signals, surface)
                else:
                    sufficient, missing = negative_sufficient(surface, negative, cards)
                    status = STATUS_NOT_VULNERABLE if sufficient else STATUS_SHALLOW_NEGATIVE
                    blocker = None
                    actions = [] if sufficient else missing
                negative_results.append({
                    "status": status,
                    "negative": negative,
                    "signals": sorted(signals),
                    "blocker": blocker,
                    "next_actions": actions,
                    "evidence_refs": list(observation.get("evidence_refs") or []),
                })
            elif outcome == "blocked":
                signals = set(negative_barrier_signals({
                    "barrier_signals": observation.get("barrier_signals") or [],
                }))
                if signals:
                    blocker, actions = _blocker_for_signals(signals, surface)
                else:
                    resolution = resolve_blocker(observation.get("blocker"), surface)
                    blocker = {
                        **resolution.to_dict(),
                        "kind": resolution.blocker_type,
                        "recoverable": resolution.category == RECOVERABLE,
                    }
                    actions = list(resolution.next_actions)
                explicit_blockers.append({"blocker": blocker, "next_actions": actions})

        if proof_refs:
            surface["status"] = STATUS_CONFIRMED
            surface["evidence_ref"] = proof_refs[0]
            surface["blocker"] = None
            surface["next_actions"] = []
            surface["negative_depth_checked"] = False
            surface.pop("negative", None)
            surface.pop("negative_depth", None)
            if negative_results:
                conflicts.append({
                    "surface_id": surface["surface_id"],
                    "resolution": "proof_confirmed_overrode_negative",
                    "observation_count": len(current),
                })
        elif declared_positive and (negative_results or explicit_blockers):
            surface["status"] = STATUS_EXPLORING
            surface["evidence_ref"] = None
            surface["blocker"] = None
            surface["next_actions"] = [
                "retest the exact cell and package a proof-valid canonical Finding",
            ]
            conflicts.append({
                "surface_id": surface["surface_id"],
                "resolution": "manual_retest_required",
                "observation_count": len(current),
            })
        elif declared_positive:
            surface["status"] = STATUS_EXPLORING
            surface["evidence_ref"] = None
            surface["next_actions"] = [
                "complete the canonical Finding proof contract before confirming",
            ]
        elif explicit_blockers and negative_results:
            surface["status"] = STATUS_EXPLORING
            surface["evidence_ref"] = None
            surface["blocker"] = None
            surface["next_actions"] = [
                "resolve blocked versus negative observations with one valid exact-cell retest",
            ]
            conflicts.append({
                "surface_id": surface["surface_id"],
                "resolution": "manual_retest_required",
                "observation_count": len(current),
            })
        elif explicit_blockers:
            blocker_kinds = {
                str(item["blocker"].get("kind") or "") for item in explicit_blockers
            }
            if len(blocker_kinds) > 1:
                surface["status"] = STATUS_EXPLORING
                surface["evidence_ref"] = None
                surface["blocker"] = None
                surface["next_actions"] = [
                    "resolve conflicting blocker classifications before retesting",
                ]
                conflicts.append({
                    "surface_id": surface["surface_id"],
                    "resolution": "manual_retest_required",
                    "observation_count": len(current),
                })
                _decorate_surface(surface, cards)
                continue
            chosen = explicit_blockers[0]
            surface["status"] = STATUS_BLOCKED
            surface["blocker"] = chosen["blocker"]
            surface["next_actions"] = chosen["next_actions"]
            surface["evidence_ref"] = None
        elif negative_results:
            statuses = {item["status"] for item in negative_results}
            if len(statuses) > 1:
                surface["status"] = STATUS_EXPLORING
                surface["next_actions"] = [
                    "resolve conflicting experiment preconditions before closing",
                ]
                conflicts.append({
                    "surface_id": surface["surface_id"],
                    "resolution": "manual_retest_required",
                    "observation_count": len(current),
                })
            else:
                chosen = negative_results[-1]
                surface["status"] = chosen["status"]
                surface["blocker"] = chosen["blocker"]
                surface["next_actions"] = chosen["next_actions"]
                surface["negative"] = chosen["negative"]
                surface["negative_depth_checked"] = (
                    chosen["status"] == STATUS_NOT_VULNERABLE)
                surface["evidence_ref"] = (
                    chosen["evidence_refs"][0]
                    if chosen["status"] == STATUS_NOT_VULNERABLE
                    and chosen["evidence_refs"] else None)
                if chosen["status"] == STATUS_SHALLOW_NEGATIVE:
                    surface["negative_depth"] = "shallow"
                else:
                    surface.pop("negative_depth", None)
        matched = match_cards({**surface, "barrier_signals": [
            signal for item in negative_results for signal in item["signals"]
        ]}, cards)
        surface["knowledge_card_ids"] = [
            card.get("id") for card in matched if card.get("id")]

    ledger.save(run / "coverage-ledger.json")
    queue = _queue_from_ledger(ledger, cards)
    atomic_write_json(run / "execution-queue.json", {
        "schema_version": 1, "queue": queue,
    }, root=run, reject_leaf_symlink=True)
    stale = _projection_stale(run, len(collected.get("accepted") or []))
    threat_coverage = None
    if str(ledger.metadata.get("planning_mode") or "") == "threat_model":
        threat_model = _load_json(run / "threat-model.json", root=run)
        threat_coverage = derive_threat_coverage(ledger.surfaces, threat_model)
        atomic_write_json(
            run / "threat-coverage.json", threat_coverage, root=run,
            reject_leaf_symlink=True)
    status = _runtime_status(
        run,
        ledger,
        accepted_findings=len(collected.get("accepted") or []),
        rejected_findings=(
            len(collected.get("rejected") or [])
            + len(collected.get("ingestion_errors") or [])),
        projection_stale=stale,
        observation_errors=len(observation_errors),
        threat_coverage=threat_coverage,
    )
    checkpoint = {
        "schema_version": 1,
        **status,
        "observations": len(observations),
        "observation_errors": observation_errors,
        "conflicts": conflicts,
        "execution_queue": queue,
        "finding_validation": {
            "accepted": len(collected.get("accepted") or []),
            "rejected": len(collected.get("rejected") or []),
            "ingestion_errors": collected.get("ingestion_errors") or [],
        },
        **({"threat_coverage": threat_coverage} if threat_coverage is not None else {}),
    }
    atomic_write_json(run / "state" / "checkpoint.json", checkpoint, root=run,
                      reject_leaf_symlink=True)
    atomic_write_json(run / "runtime-status.json", status, root=run,
                      reject_leaf_symlink=True)
    return checkpoint


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Atoolkit Direct-Skill diagnostic init/observe/checkpoint runtime")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--run-dir", required=True, type=pathlib.Path)
    init.add_argument("--target", required=True)
    init.add_argument("--inventory", type=pathlib.Path)
    init.add_argument("--recon-dir", type=pathlib.Path)
    init.add_argument("--feature-graph", type=pathlib.Path)
    init.add_argument("--threat-model", type=pathlib.Path)
    observe = sub.add_parser("observe")
    observe.add_argument("--run-dir", required=True, type=pathlib.Path)
    observe.add_argument("--agent-id", required=True)
    observe.add_argument("--input", required=True, help="observation JSON file or - for stdin")
    checkpoint = sub.add_parser("checkpoint")
    checkpoint.add_argument("--run-dir", required=True, type=pathlib.Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "init":
            result = initialize_direct_run(
                run_dir=args.run_dir, target=args.target,
                inventory_path=args.inventory, recon_dir=args.recon_dir,
                feature_graph_path=args.feature_graph,
                threat_model_path=args.threat_model)
        elif args.command == "observe":
            if args.input == "-":
                observation = json.load(sys.stdin)
            else:
                observation = json.loads(pathlib.Path(args.input).read_text(encoding="utf-8"))
            result = record_observation(
                run_dir=args.run_dir, agent_id=args.agent_id,
                observation=observation)
        else:
            result = checkpoint_direct_run(args.run_dir)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"status": "error", "error": f"{type(exc).__name__}: {exc}"},
                         ensure_ascii=False))
        return 2
    printable = dict(result)
    queue = printable.pop("execution_queue", None)
    if isinstance(queue, list):
        printable["execution_queue_count"] = len(queue)
        printable["execution_queue_path"] = str(
            (args.run_dir.resolve() / "execution-queue.json"))
    print(json.dumps(printable, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "SkillRuntimeError",
    "initialize_direct_run",
    "record_observation",
    "checkpoint_direct_run",
    "DIRECT_QUEUE_LIMIT",
]
