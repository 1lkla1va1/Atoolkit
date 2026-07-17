"""Host-owned Engine planning phase for v8.12.

The Host explicitly supplies a bounded, redacted recon snapshot and disables
target network.  Current workspace backends do not attest global read
isolation, so fresh attack credentials are materialized only after this phase
and every planning output is scanned before promotion.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Any, Iterable

try:
    from .data_hygiene import (
        canonical_credential_sha256,
        redact_json_value,
        redact_text,
        sensitive_kinds,
    )
    from .run_authority import create_run_plan, run_plan_path
    from .runtime_manifest import (
        create_run_manifest,
        sha256_file,
        validate_manifest_binding,
    )
    from .safe_io import (atomic_write_json, atomic_write_text,
                          ensure_directory, safe_read_bytes)
    from .threat_model import validate_threat_plan
except ImportError:  # pragma: no cover
    from data_hygiene import (canonical_credential_sha256, redact_json_value,
                              redact_text, sensitive_kinds)
    from run_authority import create_run_plan, run_plan_path
    from runtime_manifest import (create_run_manifest, sha256_file,
                                  validate_manifest_binding)
    from safe_io import (atomic_write_json, atomic_write_text,
                         ensure_directory, safe_read_bytes)
    from threat_model import validate_threat_plan


class EnginePlanningError(RuntimeError):
    """Raised when a planning phase cannot safely transition to attack."""


_TEXT_SUFFIXES = {
    ".html", ".htm", ".js", ".mjs", ".cjs", ".json", ".har", ".txt",
    ".md", ".xml", ".yaml", ".yml", ".map", ".css",
}
MAX_RECON_FILES = 128
MAX_RECON_FILE_BYTES = 1024 * 1024
MAX_RECON_TOTAL_BYTES = 8 * 1024 * 1024
MAX_PLAN_OUTPUT_BYTES = 2 * 1024 * 1024


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def snapshot_recon_evidence(
    recon_dir: str | pathlib.Path,
    planning_dir: str | pathlib.Path,
) -> dict[str, Any]:
    """Copy a bounded, redacted, no-follow text snapshot for model planning."""
    source_input = pathlib.Path(recon_dir)
    destination_input = pathlib.Path(planning_dir)
    if source_input.is_symlink() or destination_input.is_symlink():
        raise EnginePlanningError("planning/recon root cannot be a symlink")
    source = source_input.resolve()
    destination = destination_input.resolve()
    if not source.is_dir():
        raise EnginePlanningError(f"recon directory is missing: {source}")
    copied: list[dict[str, Any]] = []
    omitted: list[dict[str, str]] = []
    total = 0
    candidates = sorted(path for path in source.rglob("*") if path.is_file())
    for path in candidates:
        try:
            relative = path.relative_to(source)
        except ValueError:
            continue
        if len(copied) >= MAX_RECON_FILES:
            omitted.append({"path": relative.as_posix(), "reason": "file_limit"})
            continue
        if path.is_symlink() or path.suffix.lower() not in _TEXT_SUFFIXES:
            omitted.append({"path": relative.as_posix(), "reason": "unsupported_or_symlink"})
            continue
        try:
            payload = safe_read_bytes(path, root=source, max_bytes=MAX_RECON_FILE_BYTES)
        except (OSError, ValueError) as exc:
            omitted.append({"path": relative.as_posix(), "reason": type(exc).__name__})
            continue
        if total + len(payload) > MAX_RECON_TOTAL_BYTES:
            omitted.append({"path": relative.as_posix(), "reason": "total_byte_limit"})
            continue
        text = payload.decode("utf-8", errors="replace")
        redacted, counts = redact_text(text)
        target = destination / "recon" / relative
        atomic_write_text(
            target, redacted, root=destination, reject_leaf_symlink=True)
        total += len(payload)
        copied.append({
            "source_path": relative.as_posix(),
            "snapshot_path": (pathlib.Path("recon") / relative).as_posix(),
            "source_sha256": _digest(payload),
            "snapshot_sha256": sha256_file(target),
            "source_bytes": len(payload),
            "redactions": counts,
        })
    result = {
        "schema_version": 1,
        "copied": copied,
        "omitted": omitted,
        "stats": {
            "copied_files": len(copied),
            "omitted_files": len(omitted),
            "source_bytes": total,
            "redactions": sum(
                sum(item.get("redactions", {}).values()) for item in copied),
        },
    }
    atomic_write_json(
        destination / "discovery-evidence.json", result,
        root=destination, reject_leaf_symlink=True)
    return result


def build_identity_readiness(
    identities: dict[str, dict[str, str]],
    threat_model: dict[str, Any],
    *,
    roles: dict[str, str] | None = None,
    markers: dict[str, str] | None = None,
    owned_ids: Iterable[str] = (),
) -> dict[str, Any]:
    """Evaluate threat identity prerequisites without storing credentials/PII."""
    roles = {str(k): str(v).strip().lower() for k, v in (roles or {}).items()}
    markers = {str(k): str(v) for k, v in (markers or {}).items()}
    records: list[dict[str, Any]] = []
    for label, headers in sorted(identities.items()):
        fingerprint = canonical_credential_sha256(headers)
        marker = markers.get(label, "")
        records.append({
            "label": label,
            "role": roles.get(label, label.lower()),
            "credential_sha256": fingerprint,
            "marker_sha256": (
                hashlib.sha256(marker.encode("utf-8")).hexdigest() if marker else ""),
        })
    unique = {item["credential_sha256"] for item in records
              if item["credential_sha256"]}
    owned = [str(value).strip() for value in owned_ids if str(value).strip()]
    threat_records: list[dict[str, Any]] = []
    for feature in threat_model.get("features") or []:
        if not isinstance(feature, dict):
            continue
        feature_id = str(feature.get("feature_id") or "")
        for threat in feature.get("threats") or []:
            if not isinstance(threat, dict):
                continue
            requirement = threat.get("identity_requirement") or {"mode": "single"}
            mode = str(requirement.get("mode") or "single").strip().lower()
            required_roles = [str(value).strip().lower()
                              for value in requirement.get("roles") or []
                              if str(value).strip()]
            minimum = int(requirement.get("minimum_distinct_credentials", 0) or 0)
            ready = len(unique) >= minimum
            reason_code = "" if ready else "distinct_identity_missing"
            if ready and mode == "peer_pair" and required_roles:
                role = required_roles[0]
                role_fingerprints = {
                    item["credential_sha256"] for item in records
                    if item["role"] == role and item["credential_sha256"]
                }
                ready = len(role_fingerprints) >= max(2, minimum)
                reason_code = "" if ready else "peer_role_pair_missing"
            if ready and mode == "role_pair" and required_roles:
                present = {item["role"] for item in records
                           if item["credential_sha256"]}
                ready = set(required_roles).issubset(present) and len(unique) >= max(2, minimum)
                reason_code = "" if ready else "required_role_pair_missing"
            if ready and mode == "stateful_owner" and not owned:
                ready = False
                reason_code = "test_owned_object_missing"
            threat_records.append({
                "feature_id": feature_id,
                "threat_id": str(threat.get("threat_id") or ""),
                "mode": mode,
                "ready": ready,
                "reason_code": reason_code,
            })
    return {
        "schema_version": 1,
        "identities": records,
        "distinct_credentials": len(unique),
        "threats": threat_records,
    }


def create_planning_session(
    *,
    planning_dir: str | pathlib.Path,
    project: str,
    project_id: str,
    authority_dir: str | pathlib.Path,
    primary_target: str,
    authorized_scopes: list[str],
    authz: str,
    inventory_rows: list[dict[str, Any]],
    recon_dir: str | pathlib.Path,
    instruction_sources: list[dict[str, Any]],
    source_root: str | pathlib.Path,
    base_path: str = "/",
    base_path_explicit: bool = False,
    allow_paths: list[str] | None = None,
    deny_paths: list[str] | None = None,
    execution_provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Freeze planning inputs and authority before the planning model runs."""
    run_input = pathlib.Path(planning_dir)
    if run_input.is_symlink():
        raise EnginePlanningError("planning directory cannot be a symlink")
    run = run_input.resolve()
    ensure_directory(run)
    redacted_inventory, inventory_redactions = redact_json_value({
        "schema_version": 1,
        "endpoints": inventory_rows,
    })
    atomic_write_json(
        run / "inventory.json", redacted_inventory,
        root=run, reject_leaf_symlink=True)
    evidence = snapshot_recon_evidence(recon_dir, run)
    if not evidence["copied"]:
        raise EnginePlanningError("planning recon snapshot contains no supported evidence")
    create_run_plan(
        authority_dir, project_id=project_id, session_id=run.name,
        admitted_cells=[],
        budget={"phase": "planning", "network": "disabled"},
    )
    artifacts: dict[str, pathlib.Path] = {
        "inventory.json": run / "inventory.json",
        "discovery-evidence.json": run / "discovery-evidence.json",
    }
    for position, item in enumerate(evidence["copied"], start=1):
        relative = str(item["snapshot_path"])
        artifacts[f"recon-{position:04d}"] = run / relative
    manifest = create_run_manifest(
        run,
        mode="engine",
        project=project,
        project_id=project_id,
        session_id=run.name,
        primary_target=primary_target,
        authorized_scopes=authorized_scopes,
        authz=authz,
        instruction_sources=instruction_sources,
        source_root=source_root,
        authority_dir=authority_dir,
        base_path=base_path,
        base_path_explicit=base_path_explicit,
        allow_paths=allow_paths,
        deny_paths=deny_paths,
        authorization_assurance="planning_no_network",
        run_plan_path=run_plan_path(authority_dir, run.name),
        execution_provenance=execution_provenance,
        planning_mode="threat_discovery",
        planning_degraded=False,
        planning_artifacts=artifacts,
        canonical_report_required=False,
        run_phase="planning",
    )
    return {
        "manifest": manifest,
        "inventory_redactions": inventory_redactions,
        "evidence": evidence,
    }


def run_planning_model(
    adapter: Any,
    *,
    planning_dir: str | pathlib.Path,
    prompt: str,
    inventory_rows: list[dict[str, Any]],
    base_path: str = "/",
    base_path_explicit: bool = False,
    allow_paths: list[str] | None = None,
    deny_paths: list[str] | None = None,
    max_attempts: int = 2,
) -> dict[str, Any]:
    """Run bounded model attempts, then validate and normalize its plan."""
    run = pathlib.Path(planning_dir).resolve()
    manifest = json.loads(safe_read_bytes(
        run / "run_manifest.json", root=run,
        max_bytes=MAX_PLAN_OUTPUT_BYTES,
    ).decode("utf-8"))
    last_error = ""
    for attempt in range(1, max(1, max_attempts) + 1):
        suffix = (
            "\n\n上一次输出未通过 Host 校验：" + last_error
            if last_error else "")
        for _chunk in adapter.run(prompt + suffix, session_id=run.name):
            pass
        binding = validate_manifest_binding(manifest, run_dir=run)
        if not binding["ok"]:
            raise EnginePlanningError(
                f"planning input was modified: {binding['errors']}")
        try:
            graph_text = safe_read_bytes(
                run / "feature-graph.json", root=run,
                max_bytes=MAX_PLAN_OUTPUT_BYTES,
            ).decode("utf-8")
            model_text = safe_read_bytes(
                run / "threat-model.json", root=run,
                max_bytes=MAX_PLAN_OUTPUT_BYTES,
            ).decode("utf-8")
            if sensitive_kinds(graph_text) or sensitive_kinds(model_text):
                raise EnginePlanningError("planning output contains sensitive values")
            graph = json.loads(graph_text)
            model = json.loads(model_text)
            plan = validate_threat_plan(
                graph, model, inventory_rows, run_dir=run,
                base_path=base_path,
                base_path_explicit=base_path_explicit,
                allow_paths=allow_paths,
                deny_paths=deny_paths,
                require_discovery_adequacy=True,
            )
        except Exception as exc:  # noqa: BLE001 - bounded repair feedback
            last_error = f"{type(exc).__name__}: {exc}"[:2000]
            if attempt >= max_attempts:
                raise EnginePlanningError(last_error) from exc
            continue
        atomic_write_json(
            run / "feature-graph.json", plan["feature_graph"],
            root=run, reject_leaf_symlink=True)
        atomic_write_json(
            run / "threat-model.json", plan["threat_model"],
            root=run, reject_leaf_symlink=True)
        result = {
            "schema_version": 1,
            "status": "validated",
            "attempts": attempt,
            "feature_graph_sha256": sha256_file(run / "feature-graph.json"),
            "threat_model_sha256": sha256_file(run / "threat-model.json"),
        }
        atomic_write_json(
            run / "planning-result.json", result,
            root=run, reject_leaf_symlink=True)
        return {**result, **plan}
    raise EnginePlanningError(last_error or "planning model did not produce a plan")


def accept_prebuilt_plan(
    *,
    planning_dir: str | pathlib.Path,
    feature_graph_path: str | pathlib.Path,
    threat_model_path: str | pathlib.Path,
    inventory_rows: list[dict[str, Any]],
    base_path: str = "/",
    base_path_explicit: bool = False,
    allow_paths: list[str] | None = None,
    deny_paths: list[str] | None = None,
) -> dict[str, Any]:
    """Validate externally prepared model output through the same Host gate."""
    run = pathlib.Path(planning_dir).resolve()
    feature_input = pathlib.Path(feature_graph_path)
    threat_input = pathlib.Path(threat_model_path)
    if feature_input.is_symlink() or threat_input.is_symlink():
        raise EnginePlanningError("prebuilt planning artifacts cannot be symlinks")
    feature_source = feature_input.resolve()
    threat_source = threat_input.resolve()
    graph_text = safe_read_bytes(
        feature_source, root=feature_source.parent,
        max_bytes=MAX_PLAN_OUTPUT_BYTES,
    ).decode("utf-8")
    model_text = safe_read_bytes(
        threat_source, root=threat_source.parent,
        max_bytes=MAX_PLAN_OUTPUT_BYTES,
    ).decode("utf-8")
    if sensitive_kinds(graph_text) or sensitive_kinds(model_text):
        raise EnginePlanningError("prebuilt planning output contains sensitive values")
    try:
        plan = validate_threat_plan(
            json.loads(graph_text), json.loads(model_text), inventory_rows,
            run_dir=run,
            base_path=base_path,
            base_path_explicit=base_path_explicit,
            allow_paths=allow_paths,
            deny_paths=deny_paths,
            require_discovery_adequacy=True,
        )
    except (ValueError, json.JSONDecodeError) as exc:
        raise EnginePlanningError(str(exc)) from exc
    atomic_write_json(
        run / "feature-graph.json", plan["feature_graph"],
        root=run, reject_leaf_symlink=True)
    atomic_write_json(
        run / "threat-model.json", plan["threat_model"],
        root=run, reject_leaf_symlink=True)
    result = {
        "schema_version": 1,
        "status": "validated_prebuilt",
        "attempts": 0,
        "feature_graph_sha256": sha256_file(run / "feature-graph.json"),
        "threat_model_sha256": sha256_file(run / "threat-model.json"),
    }
    atomic_write_json(
        run / "planning-result.json", result,
        root=run, reject_leaf_symlink=True)
    return {**result, **plan}


def promote_planning_artifacts(
    planning_dir: str | pathlib.Path,
    attack_dir: str | pathlib.Path,
) -> dict[str, Any]:
    """Copy validated, redacted planning truth into the attack session."""
    source_input = pathlib.Path(planning_dir)
    destination_input = pathlib.Path(attack_dir)
    if source_input.is_symlink() or destination_input.is_symlink():
        raise EnginePlanningError("planning/attack root cannot be a symlink")
    source = source_input.resolve()
    destination = destination_input.resolve()
    ensure_directory(destination)
    promoted: dict[str, bytes] = {}
    for name in ("feature-graph.json", "threat-model.json", "discovery-evidence.json"):
        payload = safe_read_bytes(source / name, root=source)
        promoted[name] = payload
        target = destination / name
        atomic_write_text(
            target, payload.decode("utf-8"), root=destination,
            reject_leaf_symlink=True)
    index = json.loads(promoted["discovery-evidence.json"].decode("utf-8"))
    for item in index.get("copied") or []:
        relative = pathlib.Path(str(item.get("snapshot_path") or ""))
        payload = safe_read_bytes(source / relative, root=source)
        atomic_write_text(
            destination / relative, payload.decode("utf-8"),
            root=destination, reject_leaf_symlink=True)
    parent_manifest = source / "run_manifest.json"
    parent = json.loads(safe_read_bytes(
        parent_manifest, root=source,
        max_bytes=MAX_PLAN_OUTPUT_BYTES,
    ).decode("utf-8"))
    return {
        "session_id": source.name,
        "manifest_path": str(pathlib.Path(parent["authority_path"])),
        "manifest_sha256": sha256_file(parent_manifest),
    }


__all__ = [
    "EnginePlanningError",
    "build_identity_readiness",
    "accept_prebuilt_plan",
    "create_planning_session",
    "promote_planning_artifacts",
    "run_planning_model",
    "snapshot_recon_evidence",
]
