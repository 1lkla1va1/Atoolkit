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
import os
import pathlib
import re
import sys
import time
from typing import Any, Iterable

try:
    from .blocker import RECOVERABLE, resolve_blocker
    from .continuation import ContinuationError, load_prior_continuation
    from .enforce import ACCEPTED, DEMOTED, guardian_check_finding
    from .dynamic_execution import (
        EXECUTION_CONTRACT_VERSION,
        DynamicExecutionError,
        build_execution_projection,
        compile_execution_contract,
        normalize_execution_event,
        record_execution_event,
        rejected_finding_surface_ids,
        write_execution_projection,
    )
    from .identity_requirements import (
        count_present_identities,
        derive_identity_requirements,
    )
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
        is_high_value,
        normalize_status,
    )
    from .orchestrator import CognitiveState
    from .planner import plan_surfaces
    from .project_state import canonical_asset
    from .host_policy import normalize_authorized_scopes
    from .reporting.collect import collect_structured_findings
    from .reporting.decision import decide_canonical_report, gate_outcomes
    from .reporting.observations import (
        build_observation_records,
        write_observations_json,
    )
    from .reporting.render_md import (
        render_final_report,
        render_observation_report,
    )
    from .reporting.schema import load_finding
    from .reporting.validate import validate_run_artifacts
    from .runtime_manifest import inspect_workspace_instructions
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
    from .vuln_classes import exact_vc, norm_vc
    from .module_map import write_module_map
except ImportError:  # pragma: no cover - script execution fallback
    from blocker import RECOVERABLE, resolve_blocker
    from continuation import ContinuationError, load_prior_continuation
    from enforce import ACCEPTED, DEMOTED, guardian_check_finding
    from dynamic_execution import (EXECUTION_CONTRACT_VERSION,
                                   DynamicExecutionError,
                                   build_execution_projection,
                                   compile_execution_contract,
                                   normalize_execution_event,
                                   record_execution_event,
                                   rejected_finding_surface_ids,
                                   write_execution_projection)
    from identity_requirements import (count_present_identities,
                                       derive_identity_requirements)
    from knowledge import (load_cards, match_cards, negative_barrier_signals,
                           negative_sufficient, render_skill_hint)
    from ledger import (STATUS_BLOCKED, STATUS_CONFIRMED, STATUS_EXPLORING,
                        STATUS_NOT_APPLICABLE, STATUS_NOT_TESTED,
                        STATUS_NOT_VULNERABLE, STATUS_SHALLOW_NEGATIVE,
                        CoverageLedger, is_high_value, normalize_status)
    from orchestrator import CognitiveState
    from planner import plan_surfaces
    from project_state import canonical_asset
    from host_policy import normalize_authorized_scopes
    from reporting.collect import collect_structured_findings
    from reporting.decision import decide_canonical_report, gate_outcomes
    from reporting.observations import (build_observation_records,
                                        write_observations_json)
    from reporting.render_md import (render_final_report,
                                     render_observation_report)
    from reporting.schema import load_finding
    from reporting.validate import validate_run_artifacts
    from runtime_manifest import inspect_workspace_instructions
    from safe_io import (atomic_write_json, create_json_exclusive,
                         ensure_directory, safe_read_bytes, safe_read_text)
    from surface import bootstrap as bootstrap_recon
    from threat_model import (ThreatModelError, compile_threat_model,
                              derive_threat_coverage, validate_threat_plan)
    from vuln_classes import exact_vc, norm_vc
    from module_map import write_module_map


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
DIRECT_RESERVED_ARTIFACTS = (
    "final_report.md",
    "draft_report.md",
    "observation_report.md",
    "summary.json",
    "delivery_status.json",
    "submission_status.json",
)


def _rendered_artifact_hashes(run: pathlib.Path) -> dict[str, str]:
    """Read code-rendered artifact hashes recorded in runtime-status.json."""
    status_path = run / "runtime-status.json"
    if not status_path.is_file() or status_path.is_symlink():
        return {}
    try:
        status = _load_json(status_path, root=run)
    except SkillRuntimeError:
        return {}
    rendered = status.get("rendered_artifacts") if isinstance(status, dict) else None
    if not isinstance(rendered, dict):
        return {}
    return {str(name): str(digest) for name, digest in rendered.items()}


def _quarantine_reserved_artifacts(
    run: pathlib.Path, rendered_hashes: dict[str, str],
) -> list[str]:
    """Move hand-written reserved artifacts into state/quarantine/.

    A reserved file whose sha256 matches the hash recorded by a previous
    code render is a legitimate projection and is left in place.  Everything
    else is renamed (never deleted) so it stays auditable and recoverable.
    """
    quarantined: list[str] = []
    for name in DIRECT_RESERVED_ARTIFACTS:
        candidate = run / name
        if candidate.is_symlink():
            suspicious = True
        elif not candidate.exists():
            continue
        elif candidate.is_file():
            digest = hashlib.sha256(
                safe_read_bytes(candidate, root=run)).hexdigest()
            suspicious = rendered_hashes.get(name) != digest
        else:
            suspicious = True
        if not suspicious:
            continue
        quarantine_dir = run / "state" / "quarantine"
        ensure_directory(quarantine_dir, root=run)
        stamp = int(time.time())
        destination = quarantine_dir / f"{name}.agent.{stamp}.md"
        counter = 0
        while destination.exists():
            counter += 1
            destination = quarantine_dir / f"{name}.agent.{stamp}.{counter}.md"
        os.replace(candidate, destination)
        quarantined.append(name)
    return quarantined


def preflight_direct_run(
    *,
    run_dir: pathlib.Path,
    target: str,
    workspace_root: pathlib.Path | None = None,
    require_instruction_match: bool = False,
    extra_scopes: Iterable[str] | None = None,
    scope_files: Iterable[pathlib.Path] | None = None,
    derived_assets: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Create the diagnostic trust boundary before fresh black-box recon.

    A fresh target cannot have an inventory before its first authorized recon
    request.  v8.13 separates that bootstrap from ``init`` so Direct users no
    longer have to violate the pre-network runtime rule merely to discover the
    first endpoint.
    """
    run = run_dir.resolve()
    normalized_target = str(target).strip()
    if not normalized_target:
        raise SkillRuntimeError("Direct preflight requires target")
    authorized_scopes, derived_scopes = _resolve_scope_inputs(
        normalized_target, extra_scopes, scope_files, derived_assets)
    instruction_binding: dict[str, Any] | None = None
    if require_instruction_match:
        workspace = workspace_root.resolve() if workspace_root else None
        if workspace is None:
            for candidate in (run.parent, *run.parents):
                if (candidate / "AGENTS.md").is_file():
                    workspace = candidate
                    break
        if workspace is None:
            raise SkillRuntimeError(
                "cannot locate active workspace AGENTS.md; pass --workspace-root")
        project_root = pathlib.Path(__file__).resolve().parent.parent
        instruction_binding = inspect_workspace_instructions(
            project_root, workspace)
        if instruction_binding.get("status") != "ok":
            raise SkillRuntimeError(
                "active workspace AGENTS.md is missing, unsafe, or stale; "
                "install the project AGENTS.md before Direct preflight")
    ensure_directory(run, root=run.parent)
    record = {
        "schema_version": 2 if instruction_binding is not None else 1,
        "mode": "direct_diagnostic",
        "phase": "recon",
        "target": normalized_target,
        "authorized_scopes": authorized_scopes,
        "derived_assets": derived_scopes,
        "authority_trusted": False,
        "delivery_eligible": False,
        "execution_contract_version": EXECUTION_CONTRACT_VERSION,
        "runtime_incomplete": True,
        "next_action": "complete recon, then run skill_runtime init",
        **({"instruction_binding": instruction_binding}
           if instruction_binding is not None else {}),
    }
    path = run / "runtime-preflight.json"
    created = create_json_exclusive(path, record, root=run)
    if not created:
        existing = _load_json(path, root=run)
        if existing != record:
            raise SkillRuntimeError(
                "Direct preflight already exists with different target/state")
    atomic_write_json(
        run / "runtime-status.json", record, root=run,
        reject_leaf_symlink=True)
    return {**record, "idempotent": not created}


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


_URL_TOKEN = re.compile(r"https?://[^\s)\]>\"'，。；、]+")
_SCOPE_HEADING = re.compile(r"^#{1,6}\s*(?P<title>.+?)\s*$")
_SCOPE_JSON_KEYS = ("target_domains", "authorized_scopes", "scopes")
_DERIVED_JSON_KEYS = ("derived_assets", "derived_scopes")


def _markdown_section_urls(text: str, keywords: tuple[str, ...]) -> list[str]:
    """Collect absolute URLs listed under the first matching Markdown heading."""
    collect = False
    found: list[str] = []
    for line in text.splitlines():
        heading = _SCOPE_HEADING.match(line.strip())
        if heading:
            if collect:
                break
            title = heading.group("title").lower()
            collect = any(keyword in title for keyword in keywords)
            continue
        if collect:
            found.extend(_URL_TOKEN.findall(line))
    return found


def parse_scope_file(path: pathlib.Path) -> tuple[list[str], list[str]]:
    """Return ``(authorized_scopes, derived_assets)`` from a JSON or Markdown file.

    JSON files (run_scope.json and friends) contribute ``target_domains`` /
    ``authorized_scopes`` / ``scopes`` and ``derived_assets`` / ``derived_scopes``.
    Markdown files (AUTHZ.md / authz.md) contribute URLs listed under a heading
    containing ``scope``/``范围`` and, for derived assets, ``派生资产``/``derived``.
    """
    absolute = path.resolve()
    if not absolute.is_file() or absolute.is_symlink():
        raise SkillRuntimeError(f"scope file is missing or unsafe: {path}")
    text = absolute.read_text(encoding="utf-8", errors="ignore")
    stripped = text.lstrip()
    scopes: list[str] = []
    derived: list[str] = []
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SkillRuntimeError(f"invalid scope file JSON {path}: {exc}") from exc
        if isinstance(value, list):
            scopes = [str(item) for item in value]
        elif isinstance(value, dict):
            for key in _SCOPE_JSON_KEYS:
                raw = value.get(key)
                if isinstance(raw, list):
                    scopes.extend(str(item) for item in raw)
            for key in _DERIVED_JSON_KEYS:
                raw = value.get(key)
                if isinstance(raw, list):
                    derived.extend(str(item) for item in raw)
        else:
            raise SkillRuntimeError(f"scope file JSON must be object or list: {path}")
    else:
        scopes = _markdown_section_urls(text, ("scope", "范围"))
        derived = _markdown_section_urls(text, ("派生资产", "derived"))
    return scopes, derived


def _resolve_scope_inputs(
    target: str,
    extra_scopes: Iterable[str] | None,
    scope_files: Iterable[pathlib.Path] | None,
    derived_assets: Iterable[str] | None,
) -> tuple[list[str], list[str]]:
    """Normalize primary target + extra scopes + scope files into scope lists."""
    scopes: list[str] = [str(target or "").strip()]
    derived: list[str] = [str(item).strip() for item in (derived_assets or [])]
    scopes.extend(str(item).strip() for item in (extra_scopes or []))
    for scope_file in scope_files or []:
        file_scopes, file_derived = parse_scope_file(pathlib.Path(scope_file))
        scopes.extend(file_scopes)
        derived.extend(file_derived)
    normalized = normalize_authorized_scopes([item for item in scopes if item])
    if not normalized:
        raise SkillRuntimeError("no valid authorized scope could be derived")
    return normalized, normalize_authorized_scopes([item for item in derived if item])


def _metadata_authorized_scopes(metadata: dict[str, Any]) -> list[str]:
    """Full authorized scope list from ledger metadata (legacy runs fall back)."""
    scopes = metadata.get("authorized_scopes")
    if isinstance(scopes, list) and scopes:
        return [str(item) for item in scopes]
    target = str(metadata.get("target") or "").strip()
    return [target] if target else []


def _metadata_derived_assets(metadata: dict[str, Any]) -> list[str]:
    derived = metadata.get("derived_assets")
    if isinstance(derived, list):
        return [str(item) for item in derived]
    return []


def _attribution_allowed_hosts(run: pathlib.Path) -> list[str] | None:
    """Scope source for the checkpoint attribution pass (v9.8 W1.1).

    A run with an authority manifest validates against its attested scopes
    (anything broader would trip ``allow_scope_not_in_manifest``); runs
    without a manifest fall back to ``run_scope.json`` target_domains.
    """
    manifest_path = run / "run_manifest.json"
    if manifest_path.is_file() and not manifest_path.is_symlink():
        try:
            manifest = _load_json(manifest_path, root=run)
        except SkillRuntimeError:
            manifest = {}
        scopes = manifest.get("authorized_scopes") if isinstance(manifest, dict) else None
        if isinstance(scopes, list) and scopes:
            return [str(item) for item in scopes]
    scope_path = run / "run_scope.json"
    if scope_path.is_file() and not scope_path.is_symlink():
        try:
            scopes, _derived = parse_scope_file(scope_path)
        except SkillRuntimeError:
            scopes = []
        if scopes:
            return scopes
    return None


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


def _queue_from_ledger(
    ledger: CoverageLedger,
    cards: list[dict],
    execution_projection: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    progress_by_id = {
        str(item.get("surface_id") or ""): item
        for item in (execution_projection or {}).get("progress", [])
        if isinstance(item, dict)
    }
    queue: list[dict[str, Any]] = []
    for surface in ledger.next_surfaces(DIRECT_QUEUE_LIMIT):
        matched = _cards_for_surface(surface, cards)
        hint_cards = matched[:DIRECT_HINT_CARD_LIMIT]
        progress = progress_by_id.get(str(surface.get("surface_id") or ""), {})
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
            "execution_status": progress.get("execution_status", "ready"),
            "completed_obligations": list(
                progress.get("completed_obligations") or []),
            "next_obligations": list(
                progress.get("missing_obligations") or [])[:6],
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
    execution_projection: dict[str, Any] | None = None,
    reserved_artifact_violations: int = 0,
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
    execution_stats = (execution_projection or {}).get("stats") or {}
    execution_closed = (
        int(execution_stats.get("contracts", 0) or 0) > 0
        and int(execution_stats.get("open", 1) or 0) == 0
    )
    return {
        "schema_version": 1,
        "mode": "direct_diagnostic",
        "run_dir": str(run),
        "authority_trusted": False,
        "delivery_eligible": False,
        "planning_mode": planning_mode,
        "planning_degraded": planning_degraded,
        "execution_contract_version": EXECUTION_CONTRACT_VERSION,
        "execution": execution_stats,
        "coverage": stats,
        "accepted_findings": accepted_findings,
        "rejected_findings": rejected_findings,
        "projection_stale": projection_stale,
        "observation_errors": observation_errors,
        "reserved_artifact_violations": reserved_artifact_violations,
        "report_ready": bool(
            not planning_degraded and threat_closed and execution_closed
            and stats.get("total") and not stats.get("open")
            and not projection_stale and not rejected_findings
            and not observation_errors and not reserved_artifact_violations),
    }


def _rejected_finding_details(
    run: pathlib.Path, rejected: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    details: list[dict[str, Any]] = []
    for item in rejected[:32]:
        raw_path = str(item.get("path") or "")
        rendered_path = raw_path
        if raw_path:
            try:
                rendered_path = pathlib.Path(raw_path).resolve().relative_to(run).as_posix()
            except ValueError:
                rendered_path = raw_path
        details.append({
            "id": str(item.get("id") or ""),
            "path": rendered_path,
            "layout": str(item.get("layout") or ""),
            "method": str(item.get("method") or "").strip().upper(),
            "endpoint": str(item.get("endpoint") or "").strip(),
            "params": [str(value) for value in _as_list(item.get("params"))[:16]],
            "roles": [str(value) for value in _as_list(item.get("roles"))[:8]],
            "vuln_class": str(item.get("vuln_class") or "").strip(),
            "feature_id": str(item.get("feature_id") or "").strip(),
            "threat_id": str(item.get("threat_id") or "").strip(),
            "reasons": [str(reason) for reason in (item.get("reasons") or [])[:12]],
        })
    return details


def _continuation_inventory_rows(
    items: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Map validated continuation agenda items onto inventory rows.

    The agenda's critical→high→medium→low order is preserved in the returned
    row stream; final scheduling order stays Host-owned via the ledger.
    """
    rows: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        endpoint = str(item.get("target_endpoint") or "").strip()
        method = str(item.get("target_method") or "").strip().upper()
        if not endpoint or not method:
            continue
        row: dict[str, Any] = {
            "endpoint": endpoint,
            "method": method,
            "params": [str(param) for param in _as_list(item.get("target_params"))],
            "roles": [str(role) for role in _as_list(item.get("target_roles"))],
            "source": "v9_host_continuation",
            "continuation_intent_id": str(item.get("intent_id") or ""),
            "continuation_priority": str(item.get("priority") or ""),
        }
        vuln_class = str(item.get("vuln_class") or "").strip()
        if vuln_class:
            row["vuln_classes"] = [vuln_class]
        rows.append(row)
    return rows


def _apply_identity_requirements(
    run: pathlib.Path,
    ledger: CoverageLedger,
) -> dict[str, Any]:
    """Recompute identity requirements and mirror unmet ones into the ledger.

    v9.8 W2: identity needs are declared before the first network action and
    recomputed at every checkpoint, so supplying identities mid-run clears
    the gap without re-init.  Unmet cells stay in the queue and are flagged
    ``identity_blocked=true``; attribution reads the flag as
    ``identity_missing``.
    """
    requirements = derive_identity_requirements(
        ledger.surfaces, identities_present=count_present_identities(run))
    blocked = {
        cell
        for requirement in requirements.get("requirements") or []
        for cell in (requirement.get("blocks_cells") or [])
    }
    for surface in ledger.surfaces:
        surface_id = str(surface.get("surface_id") or "")
        if surface_id in blocked:
            surface["identity_blocked"] = True
        else:
            surface.pop("identity_blocked", None)
    atomic_write_json(run / "identity-requirements.json", requirements,
                      root=run, reject_leaf_symlink=True)
    return requirements


def _freeze_budget_capped(
    run: pathlib.Path,
    ledger: CoverageLedger,
    max_frozen_cells: int,
) -> list[dict[str, Any]]:
    """Freeze only the top-N priority cells into this run's denominator.

    v9.8 W0: when the inventory compiles to more cells than a session budget
    can close, the overflow is deferred to ``deferred-pool.json`` instead of
    entering the coverage ledger.  Deferred cells keep their full surface
    identity and priority, are attributed as ``execution_not_started`` at
    checkpoint, and flow into the next-run agenda.  The ordering key mirrors
    the ledger's existing priority (high-value first, then feature, then
    surface_id) so repeated inits are byte-identical.
    """
    if len(ledger.surfaces) <= max_frozen_cells:
        return []
    ordered = sorted(
        ledger.surfaces,
        key=lambda surface: (
            0 if is_high_value(surface) else 1,
            str(surface.get("feature") or ""),
            str(surface.get("surface_id") or ""),
        ),
    )
    frozen_ids = {
        str(surface.get("surface_id") or "")
        for surface in ordered[:max_frozen_cells]
    }
    deferred = ordered[max_frozen_cells:]
    ledger.surfaces = [
        surface for surface in ledger.surfaces
        if str(surface.get("surface_id") or "") in frozen_ids
    ]
    pool = [
        {**surface,
         "priority_rank": rank,
         "deferred_reason": "budget_cap"}
        for rank, surface in enumerate(deferred, start=len(frozen_ids) + 1)
    ]
    ledger.metadata["budget_cap"] = {
        "max_frozen_cells": max_frozen_cells,
        "frozen_cells": len(ledger.surfaces),
        "deferred_cells": len(pool),
    }
    atomic_write_json(run / "deferred-pool.json", {
        "schema_version": 1,
        "deferred_reason": "budget_cap",
        "max_frozen_cells": max_frozen_cells,
        "frozen_cells": len(ledger.surfaces),
        "deferred_cells": len(pool),
        "surfaces": pool,
    }, root=run, reject_leaf_symlink=True)
    return pool


def initialize_direct_run(
    *,
    run_dir: pathlib.Path,
    target: str,
    inventory_path: pathlib.Path | None = None,
    recon_dir: pathlib.Path | None = None,
    feature_graph_path: pathlib.Path | None = None,
    threat_model_path: pathlib.Path | None = None,
    workspace_root: pathlib.Path | None = None,
    require_instruction_match: bool = False,
    extra_scopes: Iterable[str] | None = None,
    scope_files: Iterable[pathlib.Path] | None = None,
    derived_assets: Iterable[str] | None = None,
    continue_from_run: pathlib.Path | None = None,
    max_frozen_cells: int = 20,
) -> dict[str, Any]:
    """Initialize a diagnostic Direct-Skill ledger and bounded work queue."""
    if int(max_frozen_cells) < 1:
        raise SkillRuntimeError("--max-frozen-cells must be >= 1")
    run = run_dir.resolve()
    preflight_direct_run(
        run_dir=run,
        target=target,
        workspace_root=workspace_root,
        require_instruction_match=require_instruction_match,
        extra_scopes=extra_scopes,
        scope_files=scope_files,
        derived_assets=derived_assets,
    )
    authorized_scopes, derived_scopes = _resolve_scope_inputs(
        target, extra_scopes, scope_files, derived_assets)
    continuation: dict[str, Any] | None = None
    if continue_from_run is not None:
        # v9.8 W1.2: consume the prior run's Host-validated agenda.  This only
        # restores scheduling — ProjectState and submission eligibility are
        # untouched (Direct stays diagnostic).
        try:
            continuation = load_prior_continuation(
                continue_from_run,
                primary_target=target,
                authorized_scopes=authorized_scopes)
        except ContinuationError as exc:
            # Stale-hash trap escape hatch (v9.8 R6): when the prior run was
            # updated after its last checkpoint, one fresh checkpoint rebuilds
            # the validation triplet and unblocks continuation.
            raise ContinuationError(
                f"{exc}；自愈：对 prior run 重跑 `python3 -m "
                f"engine.skill_runtime checkpoint --run-dir {continue_from_run}` "
                f"刷新三件套后重试") from exc
        atomic_write_json(run / "continuation-input.json", {
            **continuation,
            "run_dir": str(run),
            "diagnostic_only": True,
        }, root=run, reject_leaf_symlink=True)
    rows = _inventory_rows(inventory_path)
    if recon_dir is not None:
        rows.extend(bootstrap_recon(recon_dir))
    if continuation is not None:
        rows.extend(_continuation_inventory_rows(
            continuation.get("items") or []))
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

    # v9.8 W0: budget-matched denominator freeze (legacy plan_surfaces path
    # only — threat-mode cells stay bound to their compiled feature/threat
    # denominator per v8.12).
    deferred_surfaces: list[dict[str, Any]] = []
    if planning_mode == "legacy_risk":
        deferred_surfaces = _freeze_budget_capped(
            run, ledger, int(max_frozen_cells))

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
        "authorized_scopes": authorized_scopes,
        "derived_assets": derived_scopes,
        "source": "direct-skill-runtime",
        "authority_trusted": False,
        "planning_mode": planning_mode,
        "planning_degraded": planning_degraded,
        "planning_artifact_hashes": planning_artifact_hashes,
        "execution_contract_version": EXECUTION_CONTRACT_VERSION,
    })
    # v9.8 W2: identity requirements are materialized before the first
    # network action; unmet cells keep their queue slot with
    # identity_blocked=true (Direct 降级不阻塞, design W2.2).
    identity_requirements = _apply_identity_requirements(run, ledger)
    ledger.save(run / "coverage-ledger.json")
    atomic_write_json(run / "candidate-ledger.json", {
        "schema_version": "1.1", "candidates": [],
    }, root=run, reject_leaf_symlink=True)
    execution_projection = write_execution_projection(run, ledger, [])
    # execution-queue.json keeps the Host-owned projection shape written by
    # write_execution_projection; the richer model-facing queue only lives in
    # the returned status dict.  Overwriting the file here used to desync it
    # from the closure gate's recomputed projection
    # (execution_projection_mismatch after any checkpoint/init).
    queue = _queue_from_ledger(ledger, cards, execution_projection)
    threat_coverage = None
    if normalized_threat_model is not None:
        threat_coverage = derive_threat_coverage(
            ledger.surfaces, normalized_threat_model)
        atomic_write_json(
            run / "threat-coverage.json", threat_coverage, root=run,
            reject_leaf_symlink=True)
    status = _runtime_status(
        run, ledger, threat_coverage=threat_coverage,
        execution_projection=execution_projection)
    if continuation is not None:
        status["continuation"] = {
            "source_run": continuation.get("source_run"),
            "items": len(continuation.get("items") or []),
            "trust_level": continuation.get("trust_level"),
        }
    if deferred_surfaces:
        status["deferred_pool"] = {
            "deferred_reason": "budget_cap",
            "deferred_cells": len(deferred_surfaces),
            "max_frozen_cells": int(max_frozen_cells),
        }
    status["identity_requirements"] = dict(
        identity_requirements.get("summary") or {})
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
    # v8.13: explicit execution claims are validated at observation time.  Old
    # observations remain readable and are conservatively inferred at checkpoint.
    observation_barriers = _dedupe([
        *_as_list(normalized.get("barrier_signals")),
        *negative_barrier_signals(
            normalized.get("negative")
            if isinstance(normalized.get("negative"), dict) else {}),
    ])
    if normalized.get("completed_obligations") or observation_barriers:
        probe_event = {
            "schema_version": 1,
            "event_id": "obs-" + hashlib.sha256(
                f"{agent_id}\x1f{observation_id}".encode("utf-8")
            ).hexdigest()[:24],
            "surface_id": surface_id,
            "outcome": (
                "blocked" if normalized.get("outcome") == "blocked"
                or (observation_barriers and not refs) else "observed"),
            "completed_obligations": normalized.get("completed_obligations") or [],
            "evidence_refs": refs,
            "barrier_signals": observation_barriers,
        }
        try:
            normalize_execution_event(run, ledger, probe_event)
            record_execution_event(
                run_dir=run, ledger=ledger, event=probe_event)
        except DynamicExecutionError as exc:
            raise SkillRuntimeError(str(exc)) from exc
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
    expected_class = exact_vc(str(surface.get("vuln_class") or ""))
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
        row_class = exact_vc(str(
            row.get("vuln_class") or normalized.get("vuln_class") or ""))
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


def _execution_events_from_observations(
    run: pathlib.Path,
    ledger: CoverageLedger,
    observations: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Normalize Direct observations into the shared v8.13 event contract."""
    events: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for observation in observations:
        negative = observation.get("negative")
        negative = negative if isinstance(negative, dict) else {}
        barriers = _dedupe([
            *_as_list(observation.get("barrier_signals")),
            *negative_barrier_signals(negative),
        ])
        completed = _dedupe(observation.get("completed_obligations") or [])
        refs = _dedupe(observation.get("evidence_refs") or [])
        if (str(observation.get("outcome") or "") in {"negative", "confirmed"}
                and refs
                and int(negative.get("response_count", 1) or 0) > 0
                and "valid-baseline" not in completed):
            completed.append("valid-baseline")
        if not completed and not barriers:
            continue
        raw = {
            "schema_version": 1,
            "event_id": "obs-" + hashlib.sha256(
                (str(observation.get("agent_id") or "") + "\x1f"
                 + str(observation.get("observation_id") or "")).encode("utf-8")
            ).hexdigest()[:24],
            "surface_id": str(observation.get("surface_id") or ""),
            "outcome": (
                "blocked" if str(observation.get("outcome") or "") == "blocked"
                or (barriers and not refs) else "observed"),
            "completed_obligations": completed,
            "evidence_refs": refs,
            "barrier_signals": barriers,
        }
        try:
            events.append(normalize_execution_event(run, ledger, raw))
        except DynamicExecutionError as exc:
            errors.append({
                "observation_id": str(observation.get("observation_id") or ""),
                "error": str(exc),
            })
    return events, errors


def _apply_direct_execution_gate(
    ledger: CoverageLedger,
    projection: dict[str, Any],
) -> bool:
    """Reopen a negative whose v8.13 experiment obligations are still open."""
    changed = False
    for progress in projection.get("progress") or []:
        surface = ledger.get(str(progress.get("surface_id") or ""))
        if not surface or normalize_status(surface.get("status")) != STATUS_NOT_VULNERABLE:
            continue
        if progress.get("closure_allowed"):
            continue
        missing = [
            str(item.get("description") or item.get("obligation_id") or "")
            for item in progress.get("missing_obligations") or []
            if isinstance(item, dict)
        ]
        surface["status"] = STATUS_SHALLOW_NEGATIVE
        surface["negative_depth"] = "shallow"
        surface["negative_depth_checked"] = False
        surface["next_actions"] = _dedupe(
            missing or ["complete the v8.13 execution obligations"])
        changed = True
    return changed


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
    # v9.8 W2: re-derive identity requirements at every checkpoint so a newly
    # supplied identity clears the gap without re-init; identity_blocked
    # flags feed miss-attribution as identity_missing (W2.4).
    identity_requirements = _apply_identity_requirements(run, ledger)
    observations, observation_errors = _read_observations(run)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for observation in observations:
        grouped.setdefault(str(observation.get("surface_id") or ""), []).append(observation)

    # v9.3: the full authorized scope list (multi-asset runs) is authoritative;
    # legacy runs without `authorized_scopes` fall back to the single target.
    scope_hosts = _metadata_authorized_scopes(ledger.metadata)
    collected = collect_structured_findings(
        run,
        authorized_hosts=scope_hosts or None,
        derived_hosts=_metadata_derived_assets(ledger.metadata) or None)
    # v9.2: wire the Guardian gate into the Skill checkpoint path, mirroring
    # validate_run_artifacts.  Demotions (incl. L1 garbage-title hits) become
    # observations — they never inflate proof_repair_required and never block
    # report_ready; hard rejections keep their repair semantics.
    guardian_hosts = scope_hosts or None
    guardian_accepted: list[dict[str, Any]] = []
    observation_items: list[dict[str, Any]] = [
        dict(item) for item in (collected.get("observations") or [])]
    rejected_findings: list[dict[str, Any]] = list(collected.get("rejected") or [])
    accepted_by_path: dict[str, dict[str, Any]] = {}
    for item, normalized in zip(
            collected.get("accepted") or [], collected.get("normalized") or []):
        path = pathlib.Path(str(item.get("path") or ""))
        verdict = guardian_check_finding(
            item.get("finding") or {}, path.parent,
            authorized_hosts=guardian_hosts, context=None)
        if verdict.result == ACCEPTED:
            guardian_accepted.append(item)
            accepted_by_path[str(path.resolve())] = normalized
        elif verdict.result == DEMOTED or verdict.level == 1:
            observation_items.append({
                "id": item.get("id"),
                "path": str(path),
                "finding": item.get("finding") or {},
                "outcome": "observation",
                "reasons": [
                    f"guardian:{verdict.result}:L{verdict.level}:{verdict.reason}"],
            })
        else:
            rejected_findings.append({
                "id": item.get("id"),
                "path": str(path),
                "reasons": [
                    f"guardian:{verdict.result}:L{verdict.level}:{verdict.reason}"],
            })

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

    execution_events, execution_errors = _execution_events_from_observations(
        run, ledger, observations)
    rejected_execution_surfaces = rejected_finding_surface_ids(
        run, ledger, rejected_findings)
    execution_projection = build_execution_projection(
        ledger, execution_events,
        rejected_surface_ids=rejected_execution_surfaces)
    if _apply_direct_execution_gate(ledger, execution_projection):
        execution_projection = build_execution_projection(
            ledger, execution_events,
            rejected_surface_ids=rejected_execution_surfaces)
    ledger.metadata["execution_contract_version"] = EXECUTION_CONTRACT_VERSION
    ledger.save(run / "coverage-ledger.json")
    execution_projection = write_execution_projection(
        run, ledger, execution_events,
        rejected_surface_ids=rejected_execution_surfaces)
    # execution-queue.json keeps the Host-owned projection shape written by
    # write_execution_projection; the richer model-facing queue only lives in
    # the checkpoint dict.  Overwriting the file here used to desync it from
    # the closure gate's recomputed projection
    # (execution_projection_mismatch after any checkpoint).
    queue = _queue_from_ledger(ledger, cards, execution_projection)
    stale = _projection_stale(run, len(guardian_accepted))
    # v9.2: hand-written reserved artifacts are quarantined (never deleted);
    # code-rendered projections whose hash matches runtime-status.json stay.
    rendered_hashes = _rendered_artifact_hashes(run)
    reserved_violations = _quarantine_reserved_artifacts(run, rendered_hashes)
    rejected_details = _rejected_finding_details(run, rejected_findings)
    proof_repair_required = (
        len(rejected_findings)
        + len(collected.get("ingestion_errors") or []))
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
        accepted_findings=len(guardian_accepted),
        rejected_findings=(
            len(rejected_findings)
            + len(collected.get("ingestion_errors") or [])),
        projection_stale=stale,
        observation_errors=len(observation_errors) + len(execution_errors),
        threat_coverage=threat_coverage,
        execution_projection=execution_projection,
        reserved_artifact_violations=len(reserved_violations),
    )
    if rendered_hashes:
        # Preserve the report-command verification hook across status rewrites.
        status["rendered_artifacts"] = rendered_hashes
    # v9.8 W1.1: every Direct checkpoint also emits the attribution triplet
    # (finding_validation.json + miss-attribution.json + next-run-agenda.json)
    # via the shared validator, so the next run can consume them through
    # init --continue-from-run.  A non-zero validation exit code
    # (precondition_missing / empty_input / incomplete) is a legal diagnostic
    # state for Direct runs and never fails the checkpoint itself.
    attribution_summary: dict[str, Any] = {}
    attribution_error = ""
    try:
        validation = validate_run_artifacts(
            run,
            allowed_hosts=_attribution_allowed_hosts(run),
            derived_hosts=_metadata_derived_assets(ledger.metadata) or None,
            allow_empty=True,
            write_output=True,
        )
        cause_counts = dict(
            (validation.get("miss_attribution") or {}).get("cause_counts") or {})
        agenda = validation.get("next_run_agenda") or {}
        attribution_summary = {
            "status": validation.get("status"),
            "exit_code": validation.get("exit_code"),
            "cause_counts": cause_counts,
            "agenda_items": int(agenda.get("count", 0) or 0),
            "identity_missing": int(cause_counts.get("identity_missing", 0) or 0),
        }
    except Exception as exc:  # noqa: BLE001
        attribution_error = f"{type(exc).__name__}: {exc}"
    write_observations_json(run, observation_items, root=run)
    checkpoint = {
        "schema_version": 1,
        **status,
        "observations": len(observations),
        "observation_errors": [*observation_errors, *execution_errors],
        "conflicts": conflicts,
        "execution_queue": queue,
        "execution": execution_projection,
        "finding_validation": {
            "accepted": len(guardian_accepted),
            "rejected": len(rejected_findings),
            "rejected_items": rejected_details,
            "ingestion_errors": collected.get("ingestion_errors") or [],
            "proof_repair_required": proof_repair_required,
            "observations": len(observation_items),
        },
        "reserved_artifact_violations": reserved_violations,
        "attribution_summary": attribution_summary,
        "attribution_error": attribution_error,
        "identity_requirements": dict(
            identity_requirements.get("summary") or {}),
        **({"threat_coverage": threat_coverage} if threat_coverage is not None else {}),
    }
    atomic_write_json(run / "state" / "checkpoint.json", checkpoint, root=run,
                      reject_leaf_symlink=True)
    atomic_write_json(run / "runtime-status.json", status, root=run,
                      reject_leaf_symlink=True)
    return checkpoint


def scope_direct_run(
    run_dir: pathlib.Path,
    *,
    add: Iterable[str] | None = None,
    derived: Iterable[str] | None = None,
    reason: str = "",
) -> dict[str, Any]:
    """Append authorized scopes / derived assets to an initialized Direct run.

    v9.3: mid-run asset expansion (new port, newly approved host) used to be
    impossible without restarting the run — findings on the new asset were
    rejected at checkpoint.  Scopes are append-only and every change leaves an
    audit line in ``state/scope-audit.jsonl``.
    """
    run = run_dir.resolve()
    ledger_path = run / "coverage-ledger.json"
    if not ledger_path.is_file() or ledger_path.is_symlink():
        raise SkillRuntimeError(
            "scope requires an initialized run (coverage-ledger.json missing); "
            "run skill_runtime init first")
    ledger = CoverageLedger.load(ledger_path)
    added_scopes = normalize_authorized_scopes(
        [str(item).strip() for item in (add or []) if str(item).strip()])
    added_derived = normalize_authorized_scopes(
        [str(item).strip() for item in (derived or []) if str(item).strip()])
    if not added_scopes and not added_derived:
        raise SkillRuntimeError("scope requires at least one valid --add/--derived URL")
    current_scopes = _metadata_authorized_scopes(ledger.metadata)
    current_derived = _metadata_derived_assets(ledger.metadata)
    new_scopes = [item for item in added_scopes if item not in current_scopes]
    new_derived = [item for item in added_derived if item not in current_derived]
    ledger.metadata["authorized_scopes"] = current_scopes + new_scopes
    ledger.metadata["derived_assets"] = current_derived + new_derived
    ledger.save(ledger_path)
    audit_entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "added_scopes": new_scopes,
        "added_derived": new_derived,
        "reason": str(reason or "").strip(),
        "actor": "skill_runtime scope",
    }
    ensure_directory(run / "state", root=run)
    audit_path = run / "state" / "scope-audit.jsonl"
    if audit_path.is_symlink():
        raise SkillRuntimeError("scope audit log is a symlink; refusing to append")
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(audit_entry, ensure_ascii=False) + "\n")
    return {
        "schema_version": 1,
        "mode": "direct_diagnostic",
        "authorized_scopes": ledger.metadata["authorized_scopes"],
        "derived_assets": ledger.metadata["derived_assets"],
        "added_scopes": new_scopes,
        "added_derived": new_derived,
        "audit_log": str(audit_path),
    }


def _report_target_name(run: pathlib.Path) -> str:
    ledger_path = run / "coverage-ledger.json"
    if ledger_path.is_file() and not ledger_path.is_symlink():
        try:
            metadata = _load_json(ledger_path, root=run).get("metadata") or {}
            target = str(metadata.get("target") or "").strip()
            if target:
                return target
        except (SkillRuntimeError, AttributeError):
            pass
    manifest_path = run / "run_manifest.json"
    if manifest_path.is_file() and not manifest_path.is_symlink():
        try:
            manifest = _load_json(manifest_path, root=run)
            target = str(manifest.get("primary_target") or "").strip()
            if target:
                return target
        except (SkillRuntimeError, AttributeError):
            pass
    return "目标"


def _live_report_items(
    run: pathlib.Path, validation: dict[str, Any],
) -> list[dict[str, Any]]:
    """Reload proof-confirmed Finding packages from the live run dir.

    Diagnostic mode has no authority snapshot; ``validate_run_artifacts``
    already filtered ``proof_confirmed``/``normalized_findings`` down to the
    same guardian-accepted set, so the pairing is implicit in the validation
    dict itself.
    """
    items: list[dict[str, Any]] = []
    for record in validation.get("proof_confirmed") or []:
        if not isinstance(record, dict):
            continue
        path = pathlib.Path(str(record.get("path") or "")).resolve(strict=False)
        try:
            path.relative_to(run)
        except ValueError as exc:
            raise SkillRuntimeError(
                f"proof-confirmed report path escapes run dir: {path}") from exc
        try:
            finding = load_finding(path)
        except ValueError as exc:
            raise SkillRuntimeError(
                f"proof-confirmed finding is invalid: {path}: {exc}") from exc
        items.append({"id": record.get("id"), "path": str(path), "finding": finding})
    return items


def _write_rendered_status(run: pathlib.Path, rendered: dict[str, str]) -> None:
    status_path = run / "runtime-status.json"
    status: dict[str, Any] = {}
    if status_path.is_file() and not status_path.is_symlink():
        try:
            value = _load_json(status_path, root=run)
            if isinstance(value, dict):
                status = value
        except SkillRuntimeError:
            status = {}
    if not status:
        status = {
            "schema_version": 1,
            "mode": "direct_diagnostic",
            "run_dir": str(run),
            "authority_trusted": False,
            "delivery_eligible": False,
        }
    status["rendered_artifacts"] = rendered
    atomic_write_json(status_path, status, root=run, reject_leaf_symlink=True)


def report_direct_run(run_dir: pathlib.Path) -> dict[str, Any]:
    """Render the canonical vuln report and observation report for a Direct run.

    The final/draft/none decision shares ``decide_canonical_report`` with the
    authority finalizer byte-for-byte; every artifact here stays diagnostic.
    Exit semantics are always-success: proof/closure failures only change the
    decision, never the exit code.
    """
    run = run_dir.resolve()
    rendered_before = _rendered_artifact_hashes(run)
    quarantined = _quarantine_reserved_artifacts(run, rendered_before)

    # v9.3: report-time validation honors the full multi-asset scope recorded
    # at init (legacy runs fall back to the single registered target).
    report_scopes: list[str] = []
    report_derived: list[str] = []
    ledger_path = run / "coverage-ledger.json"
    if ledger_path.is_file() and not ledger_path.is_symlink():
        try:
            ledger_metadata = _load_json(ledger_path, root=run).get("metadata") or {}
            report_scopes = _metadata_authorized_scopes(ledger_metadata)
            report_derived = _metadata_derived_assets(ledger_metadata)
        except (SkillRuntimeError, AttributeError):
            report_scopes, report_derived = [], []
    validation = validate_run_artifacts(
        run, write_output=False,
        allowed_hosts=report_scopes or None,
        derived_hosts=report_derived or None)
    proof_pass, closure_pass = gate_outcomes(validation)
    report_items = _live_report_items(run, validation)
    decision, report_name = decide_canonical_report(
        proof_pass=proof_pass,
        closure_pass=closure_pass,
        exit_code=int(validation.get("exit_code", 3)),
        report_items=report_items,
    )
    target_name = _report_target_name(run)

    rendered: dict[str, str] = {}
    if report_name is not None:
        report_status = (
            "complete" if decision == "complete" else "draft_incomplete")
        kwargs: dict[str, Any] = {}
        if report_status == "draft_incomplete":
            kwargs["session_gate"] = validation.get("closure_gate") or {}
        path = render_final_report(
            report_items, run / report_name, target_name=target_name,
            status=report_status, **kwargs)
        rendered[report_name] = hashlib.sha256(
            safe_read_bytes(path, root=run)).hexdigest()

    observation_items = list(validation.get("observations") or [])
    write_observations_json(run, observation_items, root=run)
    if observation_items:
        path = render_observation_report(
            build_observation_records(run, observation_items),
            run / "observation_report.md", target_name=target_name,
            status="diagnostic")
        rendered["observation_report.md"] = hashlib.sha256(
            safe_read_bytes(path, root=run)).hexdigest()

    # Stale code-rendered projections from an earlier decision are removed.
    # Quarantine above already relocated every non-matching file, so anything
    # left behind under a reserved report name is provably code-rendered.
    for name in ("final_report.md", "draft_report.md", "observation_report.md"):
        stale = run / name
        if name not in rendered and stale.is_file() and not stale.is_symlink():
            stale.unlink()

    _write_rendered_status(run, rendered)
    summary_line = (
        f"report: decision={decision} findings={len(report_items)} "
        f"observations={len(observation_items)} "
        f"quarantined={quarantined or []}")
    print(summary_line)
    return {
        "schema_version": 1,
        "mode": "direct_diagnostic",
        "authority_trusted": False,
        "delivery_eligible": False,
        "validation_status": validation.get("status"),
        "decision": decision,
        "report": report_name or "",
        "findings": len(report_items),
        "observations": len(observation_items),
        "quarantined": quarantined,
        "rendered_artifacts": rendered,
        "summary": summary_line,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Atoolkit Direct-Skill diagnostic "
            "preflight/init/observe/checkpoint runtime"))
    sub = parser.add_subparsers(dest="command", required=True)
    preflight = sub.add_parser("preflight")
    preflight.add_argument("--run-dir", required=True, type=pathlib.Path)
    preflight.add_argument("--target", required=True)
    preflight.add_argument("--allow", action="append", default=[],
                           help="额外授权资产 URL/host（可多次，v9.3）")
    preflight.add_argument("--scope-file", action="append", default=[],
                           type=pathlib.Path,
                           help="授权 scope 文件（AUTHZ.md/authz.md 或 JSON，可多次，v9.3）")
    preflight.add_argument("--allow-derived", action="append", default=[],
                           help="派生资产 URL/host（OSS/CDN 等，仅作证据目标，可多次，v9.3）")
    preflight.add_argument("--workspace-root", type=pathlib.Path)
    init = sub.add_parser("init")
    init.add_argument("--run-dir", required=True, type=pathlib.Path)
    init.add_argument("--target", required=True)
    init.add_argument("--allow", action="append", default=[],
                      help="额外授权资产 URL/host（可多次，v9.3）")
    init.add_argument("--scope-file", action="append", default=[],
                      type=pathlib.Path,
                      help="授权 scope 文件（AUTHZ.md/authz.md 或 JSON，可多次，v9.3）")
    init.add_argument("--allow-derived", action="append", default=[],
                      help="派生资产 URL/host（OSS/CDN 等，仅作证据目标，可多次，v9.3）")
    init.add_argument("--inventory", type=pathlib.Path)
    init.add_argument("--recon-dir", type=pathlib.Path)
    init.add_argument("--feature-graph", type=pathlib.Path)
    init.add_argument("--threat-model", type=pathlib.Path)
    init.add_argument("--continue-from-run", type=pathlib.Path,
                      help="消费上一 Run 的归因 agenda（diagnostic-only，v9.8）")
    init.add_argument("--max-frozen-cells", type=int, default=20,
                      help="本轮冻结进闭合分母的最大覆盖格数，其余进 deferred-pool（v9.8 W0，默认 20）")
    init.add_argument("--workspace-root", type=pathlib.Path)
    observe = sub.add_parser("observe")
    observe.add_argument("--run-dir", required=True, type=pathlib.Path)
    observe.add_argument("--agent-id", required=True)
    observe.add_argument("--input", required=True, help="observation JSON file or - for stdin")
    checkpoint = sub.add_parser("checkpoint")
    checkpoint.add_argument("--run-dir", required=True, type=pathlib.Path)
    scope = sub.add_parser("scope")
    scope.add_argument("--run-dir", required=True, type=pathlib.Path)
    scope.add_argument("--add", action="append", default=[],
                       help="追加授权资产 URL/host（可多次，append-only）")
    scope.add_argument("--derived", action="append", default=[],
                       help="追加派生资产 URL/host（可多次，append-only）")
    scope.add_argument("--reason", default="", help="追加原因（写入审计日志）")
    report = sub.add_parser("report")
    report.add_argument("--run-dir", required=True, type=pathlib.Path)
    map_cmd = sub.add_parser(
        "map",
        help="生成 module_map 派生视图（模块聚类 + 规模判断，只读输入）")
    map_cmd.add_argument("--run-dir", required=True, type=pathlib.Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "preflight":
            result = preflight_direct_run(
                run_dir=args.run_dir, target=args.target,
                workspace_root=args.workspace_root,
                require_instruction_match=True,
                extra_scopes=args.allow, scope_files=args.scope_file,
                derived_assets=args.allow_derived)
        elif args.command == "init":
            result = initialize_direct_run(
                run_dir=args.run_dir, target=args.target,
                inventory_path=args.inventory, recon_dir=args.recon_dir,
                feature_graph_path=args.feature_graph,
                threat_model_path=args.threat_model,
                workspace_root=args.workspace_root,
                require_instruction_match=True,
                extra_scopes=args.allow, scope_files=args.scope_file,
                derived_assets=args.allow_derived,
                continue_from_run=args.continue_from_run,
                max_frozen_cells=args.max_frozen_cells)
        elif args.command == "observe":
            if args.input == "-":
                observation = json.load(sys.stdin)
            else:
                observation = json.loads(pathlib.Path(args.input).read_text(encoding="utf-8"))
            result = record_observation(
                run_dir=args.run_dir, agent_id=args.agent_id,
                observation=observation)
        elif args.command == "scope":
            result = scope_direct_run(
                args.run_dir, add=args.add, derived=args.derived,
                reason=args.reason)
        elif args.command == "report":
            result = report_direct_run(args.run_dir)
        elif args.command == "map":
            result = write_module_map(args.run_dir)
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
    "preflight_direct_run",
    "initialize_direct_run",
    "record_observation",
    "checkpoint_direct_run",
    "report_direct_run",
    "scope_direct_run",
    "write_module_map",
    "parse_scope_file",
    "DIRECT_QUEUE_LIMIT",
]
