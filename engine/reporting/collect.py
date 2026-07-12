from __future__ import annotations

import pathlib
from typing import Any

from .schema import load_finding, normalize_finding
from .validate import validate_finding


def iter_finding_files(run_dir: str | pathlib.Path) -> list[pathlib.Path]:
    base = pathlib.Path(run_dir)
    findings_dir = base / "findings"
    if not findings_dir.exists():
        return []
    return sorted(findings_dir.glob("finding_*/finding.json"))


def collect_structured_findings(
    run_dir: str | pathlib.Path,
    authorized_hosts: list[str] | None = None,
) -> dict[str, Any]:
    base = pathlib.Path(run_dir).resolve()
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    normalized: list[dict[str, Any]] = []
    finding_objs: list[dict[str, Any]] = []

    for path in iter_finding_files(base):
        try:
            finding = load_finding(path)
        except ValueError as exc:
            rejected.append({"id": path.parent.name, "path": str(path.resolve()), "reasons": [str(exc)]})
            continue
        result = validate_finding(finding, path, base, authorized_hosts=authorized_hosts)
        if result.ok:
            item = {"id": result.id, "path": str(path.resolve()), "finding": finding}
            accepted.append(item)
            finding_objs.append(item)
            normalized.append(result.normalized or normalize_finding(finding, path, base))
        else:
            rejected.append(result.to_dict())

    return {
        "accepted": accepted,
        "proof_confirmed": accepted,
        "schema_valid": accepted,
        "proof_pending": [],
        "rejected": rejected,
        "normalized": normalized,
        "finding_objs": finding_objs,
    }
