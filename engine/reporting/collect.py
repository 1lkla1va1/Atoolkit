from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Any

from .schema import load_finding, normalize_finding
from .validate import validate_finding


MAX_FINDING_BYTES = 2 * 1024 * 1024


def _inside(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _safe_file(path: pathlib.Path, root: pathlib.Path) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    resolved = path.resolve(strict=False)
    return _inside(resolved, root) and not any(parent.is_symlink() for parent in path.parents if parent != root.parent)


def _artifact(path: pathlib.Path, root: pathlib.Path, layout: str) -> dict[str, Any]:
    return {
        "path": str(path.resolve(strict=False)),
        "relative_path": path.resolve(strict=False).relative_to(root).as_posix(),
        "layout": layout,
        "size": path.stat().st_size,
    }


def discover_finding_artifacts(run_dir: str | pathlib.Path) -> dict[str, Any]:
    """Discover canonical and known legacy finding layouts without recursion.

    Suspicious discovery is intentionally bounded to at most two directories
    below ``findings/`` or ``evidence/``.  Symlinks are never followed.
    """
    root = pathlib.Path(run_dir).resolve()
    artifacts: list[dict[str, Any]] = []
    seen: set[pathlib.Path] = set()

    def add(path: pathlib.Path, layout: str) -> None:
        resolved = path.resolve(strict=False)
        if resolved in seen or not _safe_file(path, root):
            return
        seen.add(resolved)
        artifacts.append(_artifact(path, root, layout))

    findings = root / "findings"
    if findings.is_dir() and not findings.is_symlink():
        for child in sorted(findings.iterdir()):
            if child.is_dir() and not child.is_symlink() and child.name.startswith("finding_"):
                add(child / "finding.json", "canonical")
            elif child.is_file() and child.name.startswith("finding_") and child.suffix == ".json":
                add(child, "legacy_flat")

    evidence = root / "evidence"
    if evidence.is_dir() and not evidence.is_symlink():
        for child in sorted(evidence.iterdir()):
            if child.is_dir() and not child.is_symlink() and child.name.startswith("finding_"):
                add(child / "finding.json", "legacy_evidence")

    # Bounded suspicious scan: base/name, base/a/name, base/a/b/name.
    for base in (findings, evidence):
        if not base.is_dir() or base.is_symlink():
            continue
        stack: list[tuple[pathlib.Path, int]] = [(base, 0)]
        while stack:
            directory, depth = stack.pop()
            try:
                entries = sorted(directory.iterdir())
            except OSError:
                continue
            for entry in entries:
                if entry.is_symlink():
                    continue
                if entry.is_dir() and depth < 2:
                    stack.append((entry, depth + 1))
                elif (entry.is_file() and entry.suffix == ".json"
                      and entry.name.startswith("finding")):
                    add(entry, "unsupported")

    order = {"canonical": 0, "legacy_flat": 1, "legacy_evidence": 2, "unsupported": 3}
    artifacts.sort(key=lambda x: (order.get(x["layout"], 9), x["relative_path"]))
    counts = {name: sum(1 for x in artifacts if x["layout"] == name) for name in order}
    return {
        "artifacts": artifacts,
        "counts": {
            "discovered": len(artifacts),
            "canonical": counts["canonical"],
            "legacy": counts["legacy_flat"] + counts["legacy_evidence"],
            "suspicious": counts["unsupported"],
        },
    }


def iter_finding_files(run_dir: str | pathlib.Path) -> list[pathlib.Path]:
    """Backward-compatible canonical-only iterator."""
    discovery = discover_finding_artifacts(run_dir)
    return [pathlib.Path(x["path"]) for x in discovery["artifacts"] if x["layout"] == "canonical"]


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_structured_findings(
    run_dir: str | pathlib.Path,
    authorized_hosts: list[str] | None = None,
    *,
    context: Any = None,
) -> dict[str, Any]:
    base = pathlib.Path(run_dir).resolve()
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    normalized: list[dict[str, Any]] = []
    finding_objs: list[dict[str, Any]] = []
    ingestion_errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    discovery = discover_finding_artifacts(base)

    parsed: list[tuple[dict[str, Any], pathlib.Path, dict[str, Any], str]] = []
    for artifact in discovery["artifacts"]:
        path = pathlib.Path(artifact["path"])
        if artifact["size"] > MAX_FINDING_BYTES:
            ingestion_errors.append({
                "code": "finding_too_large", "path": str(path),
                "limit": MAX_FINDING_BYTES,
            })
            continue
        try:
            finding = load_finding(path)
        except ValueError as exc:
            ingestion_errors.append({
                "code": "malformed_finding", "path": str(path), "reason": str(exc),
            })
            continue
        fid = str(finding.get("id") or path.parent.name or path.stem)
        parsed.append((artifact, path, finding, fid))

    by_id: dict[str, list[tuple[dict[str, Any], pathlib.Path, dict[str, Any], str]]] = {}
    for item in parsed:
        by_id.setdefault(item[3], []).append(item)
    conflicted: set[str] = set()
    representatives: dict[str, pathlib.Path] = {}
    for fid, items in by_id.items():
        hashes = {_sha256(item[1]) for item in items}
        if len(hashes) > 1:
            conflicted.add(fid)
            ingestion_errors.append({
                "code": "duplicate_id_conflict", "id": fid,
                "paths": [str(item[1]) for item in items],
            })
        elif len(items) > 1:
            warnings.append({
                "code": "duplicate_id_shadow", "id": fid,
                "paths": [str(item[1]) for item in items],
            })
            # Identical bytes under the same ID are one logical finding.  Pick
            # one canonical representative deterministically; processing both
            # would duplicate normalized/project truth even though there is no
            # content conflict.
            canonical = [item for item in items if item[0]["layout"] == "canonical"]
            chosen = min(canonical or items, key=lambda item: str(item[1]))
            representatives[fid] = chosen[1]
        else:
            representatives[fid] = items[0][1]

    for artifact, path, finding, fid in parsed:
        if fid in conflicted:
            continue
        if representatives.get(fid) != path:
            continue
        layout = artifact["layout"]
        if layout != "canonical":
            rejected.append({
                "id": fid, "path": str(path),
                "reasons": [f"legacy or unsupported finding layout: {layout}; migrate to findings/finding_<id>/finding.json"],
                "layout": layout,
            })
            continue
        result = validate_finding(
            finding, path, base, authorized_hosts=authorized_hosts, context=context)
        if result.ok:
            item = {"id": result.id, "path": str(path.resolve()), "finding": finding}
            accepted.append(item)
            finding_objs.append(item)
            normalized.append(result.normalized or normalize_finding(finding, path, base))
        else:
            rejected.append(result.to_dict())

    counts = {
        **discovery["counts"],
        "accepted": len(accepted),
        "rejected": len(rejected),
        "ingestion_errors": len(ingestion_errors),
    }
    return {
        "accepted": accepted,
        "proof_confirmed": accepted,
        "schema_valid": accepted,
        "proof_pending": [],
        "rejected": rejected,
        "normalized": normalized,
        "finding_objs": finding_objs,
        "discovery": discovery,
        "counts": counts,
        "ingestion_errors": ingestion_errors,
        "warnings": warnings,
    }
