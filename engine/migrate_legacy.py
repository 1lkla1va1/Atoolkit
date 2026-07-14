"""Conservative migration of pre-v8.9 runs into revalidation work.

Legacy prose is never upgraded to a proof-confirmed finding.  The migrator can
recover attack-surface candidates, evidence digests and pending intents while
preserving contradictions in an audit artifact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

try:
    from .project_state import ProjectStateStore, canonical_asset
    from .safe_io import atomic_write_json
    from .surface import bootstrap
except ImportError:  # pragma: no cover - direct script execution
    from project_state import ProjectStateStore, canonical_asset
    from safe_io import atomic_write_json
    from surface import bootstrap


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _method_path(value: str) -> tuple[str, str]:
    text = str(value or "").split("->", 1)[0].strip()
    if not text:
        return "", ""
    parts = text.split(None, 1)
    method = parts[0].upper() if len(parts) == 2 else ""
    endpoint = parts[1] if method in {
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
    } else text
    # Legacy targets often append prose such as ``(category)`` or a chain
    # annotation after the request path.  Raw HTTP targets cannot contain an
    # unescaped space, so retain only the first path token.
    endpoint = endpoint.split(None, 1)[0]
    parsed = urlsplit(endpoint)
    path = parsed.path if parsed.scheme and parsed.netloc else endpoint.split("?", 1)[0]
    if not path:
        return method, ""
    return method, path if path.startswith("/") else "/" + path


def _explicit_legacy_target(finding: dict[str, Any]) -> str:
    for key in ("target", "endpoint", "url", "path"):
        value = str(finding.get(key) or "").strip()
        if value:
            return value
    return ""


def _legacy_target(finding: dict[str, Any]) -> str:
    """Recover only an explicit or unambiguous legacy endpoint hint."""
    explicit = _explicit_legacy_target(finding)
    if explicit:
        return explicit
    candidates = list(dict.fromkeys(re.findall(
        r"/(?:api|admin)/[A-Za-z0-9_./{}:-]+", str(finding.get("title") or ""))))
    return candidates[0] if len(candidates) == 1 else ""


def _stable_intent_id(run_id: str, finding: dict[str, Any]) -> str:
    material = json.dumps({
        "run": run_id,
        "id": finding.get("id", ""),
        "target": _legacy_target(finding),
        "type": finding.get("vuln_type") or finding.get("type") or "",
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "legacy_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


def _legacy_evidence_refs(finding: dict[str, Any]) -> list[str]:
    refs: list[Any] = []

    def add_many(value: Any) -> None:
        if value in (None, "", [], {}):
            return
        refs.extend(value if isinstance(value, (list, tuple, set)) else [value])

    add_many(finding.get("evidence_files"))
    add_many(finding.get("evidence"))
    for packet in finding.get("proof_packets") or []:
        if isinstance(packet, dict):
            refs.extend([packet.get("request_file"), packet.get("response_file")])
    for section_name, keys in (
        ("poc", ("file",)),
        ("source_proof", ("file", "constructed_packet_file")),
    ):
        section = finding.get(section_name)
        if isinstance(section, dict):
            refs.extend(section.get(key) for key in keys)
    verification = finding.get("verification")
    if isinstance(verification, dict):
        add_many(verification.get("evidence_files"))
        add_many(verification.get("impact_proof_refs"))
        access = verification.get("access_expectation")
        if isinstance(access, dict):
            add_many(access.get("proof_refs"))
    out: list[str] = []
    for value in refs:
        text = str(value or "").strip()
        if text and text not in out:
            out.append(text)
    return out


def _evidence_records(
    run: pathlib.Path,
    finding: dict[str, Any],
    *,
    base_dir: pathlib.Path | None = None,
    finding_file: pathlib.Path | None = None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    root = run.resolve()
    base = (base_dir or run).resolve(strict=False)
    raw_refs = _legacy_evidence_refs(finding)
    for ref in raw_refs:
        relative = pathlib.Path(ref)
        if ".." in relative.parts:
            records.append({"ref": ref, "status": "path_escape", "sha256": ""})
            continue
        path = (relative if relative.is_absolute() else base / relative).resolve(strict=False)
        try:
            run_relative = path.relative_to(root)
        except ValueError:
            records.append({"ref": ref, "status": "path_escape", "sha256": ""})
            continue
        normalized_ref = run_relative.as_posix()
        if path.is_file() and not path.is_symlink():
            records.append({
                "ref": normalized_ref, "status": "present",
                "sha256": _sha256(path), "size": path.stat().st_size,
            })
        else:
            records.append({"ref": normalized_ref, "status": "missing", "sha256": ""})
    if finding_file is not None:
        path = finding_file.resolve(strict=False)
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            records.append({
                "ref": str(finding_file), "status": "path_escape",
                "sha256": "", "kind": "legacy_finding",
            })
        else:
            if path.is_file() and not path.is_symlink():
                records.append({
                    "ref": relative, "status": "present",
                    "sha256": _sha256(path), "size": path.stat().st_size,
                    "kind": "legacy_finding",
                })
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for record in records:
        key = (str(record.get("ref") or ""), str(record.get("status") or ""))
        if key not in seen:
            seen.add(key)
            deduped.append(record)
    return deduped


def _legacy_finding_artifacts(run: pathlib.Path) -> list[dict[str, Any]]:
    """Load only bounded, non-symlink legacy finding packets as hints."""
    root = run.resolve()
    artifacts: list[dict[str, Any]] = []
    for base_name in ("evidence", "findings"):
        base = run / base_name
        if not base.is_dir() or base.is_symlink():
            continue
        try:
            children = sorted(base.iterdir())
        except OSError:
            continue
        for child in children:
            if (not child.name.startswith("finding_") or not child.is_dir()
                    or child.is_symlink()):
                continue
            path = child / "finding.json"
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(root)
            except (OSError, ValueError):
                continue
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
                continue
            value = _load_json(path)
            if not isinstance(value, dict):
                continue
            artifacts.append({
                "id": str(value.get("id") or child.name),
                "path": path,
                "finding": value,
            })
    return artifacts


def _match_legacy_artifact(
    claim: dict[str, Any], artifacts: list[dict[str, Any]],
) -> dict[str, Any] | None:
    claim_id = str(claim.get("id") or "").strip().casefold()
    if not claim_id:
        return None
    candidates = []
    for artifact in artifacts:
        artifact_id = str(artifact.get("id") or "").strip().casefold()
        directory_id = pathlib.Path(artifact["path"]).parent.name.casefold()
        if (artifact_id == claim_id or artifact_id.startswith(claim_id + "_")
                or directory_id == claim_id or directory_id.startswith(claim_id + "_")):
            candidates.append(artifact)
    return candidates[0] if len(candidates) == 1 else None


def _legacy_claims(summary: Any) -> list[dict[str, Any]]:
    if not isinstance(summary, dict):
        return []
    rows = summary.get("findings") or summary.get("vulnerabilities") or []
    return [dict(row) for row in rows if isinstance(row, dict)]


def _audit_contradictions(run: pathlib.Path, summary: Any, claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    conflicts: list[dict[str, Any]] = []
    declared = (
        (summary.get("summary") or {}).get("total_findings")
        or summary.get("total_findings")
        if isinstance(summary, dict) else None)
    if declared is not None and int(declared) != len(claims):
        conflicts.append({
            "code": "finding_count_mismatch", "declared": int(declared),
            "observed": len(claims),
        })
    score_path = run / "score_report.md"
    if score_path.is_file():
        score = score_path.read_text(encoding="utf-8", errors="replace")
        counts = sorted({int(value) for value in re.findall(
            r"(?:命中的?|发现(?:了)?)\s*[*：:]?\s*(\d+)\s*个(?:漏洞点|漏洞)",
            score,
        )})
        if len(counts) > 1:
            conflicts.append({"code": "score_report_count_conflict", "counts": counts})
    corpus = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in run.rglob("*.md")
        if path.is_file() and path.stat().st_size <= 2 * 1024 * 1024
    ).lower()
    for finding in claims:
        method, endpoint = _method_path(_legacy_target(finding))
        title = str(finding.get("title") or "")
        if endpoint and endpoint.lower() in corpus:
            # Preserve only explicit contradictory language. It remains an
            # audit flag and never decides exploit truth automatically.
            patterns = (
                rf"{re.escape(endpoint.lower())}.{{0,100}}(?:正确校验|不存在|未发现|negative)",
                rf"(?:正确校验|不存在|未发现|negative).{{0,100}}{re.escape(endpoint.lower())}",
            )
            if any(re.search(pattern, corpus, re.S) for pattern in patterns):
                conflicts.append({
                    "code": "positive_negative_text_conflict",
                    "finding_id": finding.get("id", ""),
                    "method": method, "endpoint": endpoint, "title": title,
                })
    return conflicts


def migrate_legacy_run(
    run_dir: str | pathlib.Path,
    project_dir: str | pathlib.Path,
    *,
    primary_asset: str = "",
    commit: bool = True,
) -> dict[str, Any]:
    run = pathlib.Path(run_dir).resolve()
    project = pathlib.Path(project_dir).resolve()
    if not run.is_dir():
        raise ValueError(f"legacy run does not exist: {run}")
    summary = _load_json(run / "summary.json") or {}
    run_id = str(summary.get("run_id") or run.name) if isinstance(summary, dict) else run.name
    target = str(summary.get("target") or "") if isinstance(summary, dict) else ""
    asset = canonical_asset(primary_asset or target)
    claims = _legacy_claims(summary)
    legacy_artifacts = _legacy_finding_artifacts(run)

    recon_dir = run / "recon"
    surfaces = bootstrap(recon_dir) if recon_dir.is_dir() else []
    inventory: list[dict[str, Any]] = []
    for surface in surfaces:
        inventory.append({
            **surface,
            "asset": asset,
            "source": f"legacy_migration:{surface.get('source', 'recon')}",
            "trust": "legacy_unvalidated",
        })

    intents: list[dict[str, Any]] = []
    evidence_index: dict[str, list[dict[str, Any]]] = {}
    for finding in claims:
        artifact = _match_legacy_artifact(finding, legacy_artifacts)
        artifact_finding = (
            dict(artifact.get("finding") or {}) if artifact else {})
        # Summary fields remain authoritative legacy metadata when explicit.
        # A uniquely matched packet may only fill missing hints; it never
        # changes trust or promotes the claim to a confirmed finding.
        target_hint = (
            _explicit_legacy_target(finding)
            or _explicit_legacy_target(artifact_finding)
            or _legacy_target(finding)
        )
        effective = dict(finding)
        if target_hint:
            effective["target"] = target_hint
        if not (effective.get("vuln_type") or effective.get("type")):
            effective["vuln_type"] = (
                artifact_finding.get("vuln_type")
                or artifact_finding.get("type") or "")
        method, endpoint = _method_path(target_hint)
        evidence = _evidence_records(run, finding)
        legacy_source = ""
        if artifact:
            artifact_path = pathlib.Path(artifact["path"])
            artifact_records = _evidence_records(
                run, artifact_finding, base_dir=artifact_path.parent,
                finding_file=artifact_path)
            existing = {
                (str(item.get("ref") or ""), str(item.get("status") or ""))
                for item in evidence
            }
            evidence.extend(
                item for item in artifact_records
                if (str(item.get("ref") or ""), str(item.get("status") or ""))
                not in existing)
            legacy_source = artifact_path.relative_to(run).as_posix()
        evidence_index[str(finding.get("id") or len(intents) + 1)] = evidence
        intents.append({
            "intent_id": _stable_intent_id(run_id, effective),
            "status": "pending",
            "source": "legacy_run_revalidation",
            "trust": "legacy_unvalidated",
            "priority": "high",
            "description": f"Revalidate legacy claim {finding.get('id', '')}: {finding.get('title', '')}",
            "target_endpoint": endpoint,
            "method": method,
            "vuln_class": str(
                effective.get("vuln_type") or effective.get("type") or ""),
            "legacy_finding_id": str(finding.get("id") or ""),
            "legacy_source_finding": legacy_source,
            "legacy_evidence": evidence,
        })

    conflicts = _audit_contradictions(run, summary, claims)
    result: dict[str, Any] = {
        "schema_version": 1,
        "migration_id": "migration_" + hashlib.sha256(
            f"{run}:{run_id}".encode("utf-8")).hexdigest()[:20],
        "source_run": str(run),
        "source_run_id": run_id,
        "source_tool_version": str(summary.get("tool_version") or "unknown")
        if isinstance(summary, dict) else "unknown",
        "asset": asset,
        "inventory_candidates": len(inventory),
        "legacy_claims": len(claims),
        "proof_confirmed_imported": 0,
        "pending_revalidation_intents": len(intents),
        "pending_revalidation": intents,
        "conflicts": conflicts,
        "evidence_index": evidence_index,
        "committed": False,
        "created_at": _now(),
    }
    audit_path = project / "migrations" / f"{run_id}.json"
    if audit_path.is_file():
        old = _load_json(audit_path)
        if isinstance(old, dict) and old.get("migration_id") == result["migration_id"]:
            if not commit or old.get("committed"):
                return old
            # A prior --dry-run from an older release may have left a
            # diagnostic audit.  Continue into the one real commit rather
            # than treating that record as an already-applied migration.
        else:
            raise ValueError(f"conflicting migration already exists: {audit_path}")

    if not commit:
        # A dry run is genuinely read-only: callers can inspect/redirect the
        # returned JSON without creating a misleading project migration.
        return result

    project.mkdir(parents=True, exist_ok=True, mode=0o700)
    if commit:
        store = ProjectStateStore(project, project_scope=[asset] if asset else [])
        store.commit_run(
            f"legacy:{run_id}",
            inventory=inventory,
            findings=[],
            negatives=[],
            dead_ends=[],
            intents=intents,
            run_summary={
                "status": "legacy_migrated_pending_revalidation",
                "source_run": str(run),
                "proof_confirmed_imported": 0,
                "conflict_count": len(conflicts),
            },
        )
        result["committed"] = True
    atomic_write_json(audit_path, result, root=project)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Migrate a legacy Atoolkit run as unvalidated work")
    parser.add_argument("--run-dir", required=True, type=pathlib.Path)
    parser.add_argument("--project-dir", required=True, type=pathlib.Path)
    parser.add_argument("--primary-asset", default="")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = migrate_legacy_run(
            args.run_dir, args.project_dir,
            primary_asset=args.primary_asset,
            commit=not args.dry_run,
        )
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"status": "error", "error": f"{type(exc).__name__}: {exc}"},
                         ensure_ascii=False))
        return 3
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["migrate_legacy_run"]
