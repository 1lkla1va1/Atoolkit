"""Read-only audit for legacy, Direct and canonical Atoolkit run directories."""
from __future__ import annotations

import argparse
import json
import pathlib
import re
from typing import Any

from .data_hygiene import sensitive_kinds
from .reporting.collect import discover_finding_artifacts
from .reporting.validate import validate_run_artifacts
from .safe_io import safe_read_bytes
from .submission import inspect_submission


_ENDPOINT = re.compile(
    r"(?:(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+)?"
    r"`?(/[^`|\s]+)`?", re.I)
_METHOD_ENDPOINT = re.compile(
    r"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+`?(/[^`|\s]+)`?", re.I)
_PATH_TOKEN = re.compile(
    r"\b([A-Za-z0-9_.{}-]+/[A-Za-z0-9_./{}?=-]+)", re.I)
_NEGATIVE = re.compile(r"\b(?:not_vulnerable|shallow_negative|blocked|not_applicable)\b", re.I)
_POSITIVE = re.compile(r"\bP[123]\b")
_CREDENTIAL_NAME = re.compile(r"(?:token|cookie|credential|secret|account)", re.I)
_RUN_MARKER = re.compile(r"\bRun\s*([0-9]+)\b", re.I)


def _relative(path: pathlib.Path, root: pathlib.Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _text(path: pathlib.Path, root: pathlib.Path) -> str:
    try:
        return safe_read_bytes(path, root=root).decode("utf-8", errors="ignore")
    except (OSError, ValueError):
        return ""


def _report_files(run: pathlib.Path) -> list[pathlib.Path]:
    result: list[pathlib.Path] = []
    for path in run.rglob("*.md"):
        relative = _relative(path, run).lower()
        if (path.name.startswith(("final_report", "draft_report", "report"))
                or path.name == "legacy_draft_report.md"
                or path.name == "submission_summary.md"
                or "/findings/" in f"/{relative}" and path.name == "report.md"):
            result.append(path)
    return sorted(set(result))


def _risk_family(text: str) -> str:
    low = str(text or "").lower()
    routes = (
        ("error", ("type confusion", "类型混淆", "500 internal")),
        ("idor", ("idor", "越权", "对象归属")),
        ("sqli", ("sqli", "sql注入", "sql 注入")),
        ("xss", ("xss", "跨站脚本")),
        ("ssrf", ("ssrf", "服务端请求伪造")),
        ("auth", ("认证绕过", "auth bypass", "未授权访问")),
        ("amount", ("金额篡改", "amount", "refund", "wallet")),
        ("redirect", ("开放重定向", "open redirect")),
        ("token", ("token泄露", "token leak", "令牌泄露")),
    )
    return next((family for family, terms in routes
                 if any(term in low for term in terms)), "")


def _risk_param(text: str) -> str:
    low = str(text or "").lower()
    for canonical, terms in (
        ("id", ("taskid", "messageid", "cardid", "?id=", "{id}")),
        ("username", ("username", "user_name")),
        ("password", ("password", "passwd")),
        ("email", ("email", "邮箱")),
        ("amount", ("amount", "金额")),
        ("token", ("token", "令牌")),
    ):
        if any(term in low for term in terms):
            return canonical
    return ""


def _summary_surface(line: str) -> tuple[str, str, str]:
    cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
    match = _METHOD_ENDPOINT.search(line)
    if match:
        endpoint = match.group(1)
    else:
        token = next((
            match for cell in cells[:2]
            if (match := _PATH_TOKEN.search(cell)) is not None
        ), None)
        if token:
            endpoint = "/" + token.group(1).lstrip("/")
        else:
            fallback = _ENDPOINT.search(line)
            endpoint = fallback.group(1) if fallback else ""
    endpoint = endpoint.split("?", 1)[0].rstrip("/").lower()
    endpoint = re.sub(r"\{[^/{}]+\}", "{}", endpoint)
    endpoint = re.sub(r"(?<=/)\d{3,}(?=/|$)", "{}", endpoint)
    return endpoint, _risk_family(line), _risk_param(line)


def _same_surface(
    left: tuple[str, str, str], right: tuple[str, str, str],
) -> bool:
    left_endpoint, left_family, left_param = left
    right_endpoint, right_family, right_param = right
    if not left_endpoint or not right_endpoint or not left_family:
        return False
    if left_family != right_family:
        return False
    if left_param and right_param and left_param != right_param:
        return False
    return bool(
        left_endpoint == right_endpoint
        or left_endpoint.endswith(right_endpoint)
        or right_endpoint.endswith(left_endpoint)
    )


def _summary_conflicts(run: pathlib.Path) -> list[dict[str, str]]:
    positives: list[tuple[tuple[str, str, str], str]] = []
    negatives: list[tuple[tuple[str, str, str], str]] = []
    state = run / "state"
    if not state.is_dir():
        return []
    for path in sorted(state.glob("*.md")):
        for line in _text(path, run).splitlines():
            surface = _summary_surface(line)
            if not surface[0]:
                continue
            if _NEGATIVE.search(line):
                negatives.append((surface, _relative(path, run)))
            elif _POSITIVE.search(line):
                positives.append((surface, _relative(path, run)))
    result: list[dict[str, str]] = []
    for positive, positive_source in positives:
        for negative, negative_source in negatives:
            if not _same_surface(positive, negative):
                continue
            item = {
                "endpoint": positive[0],
                "vuln_family": positive[1],
                "param": positive[2] or negative[2],
                "positive_source": positive_source,
                "negative_source": negative_source,
            }
            if item not in result:
                result.append(item)
    return result


def audit_run(run_dir: str | pathlib.Path) -> dict[str, Any]:
    run = pathlib.Path(run_dir).resolve()
    if not run.is_dir():
        raise ValueError(f"run directory does not exist: {run}")
    validation = validate_run_artifacts(
        run, allow_empty=True, write_output=False)
    reports = _report_files(run)
    report_findings: list[dict[str, Any]] = []
    for path in reports:
        kinds = sensitive_kinds(_text(path, run))
        report_findings.append({
            "path": _relative(path, run),
            "sensitive_kinds": kinds,
        })
    credential_files: list[dict[str, Any]] = []
    state = run / "state"
    if state.is_dir():
        for path in sorted(item for item in state.rglob("*") if item.is_file()):
            kinds = sensitive_kinds(_text(path, run))
            if kinds or _CREDENTIAL_NAME.search(path.name):
                credential_files.append({
                    "path": _relative(path, run),
                    "sensitive_kinds": kinds or ["credential_file"],
                })
    try:
        submission = inspect_submission(run)
    except (OSError, ValueError):
        submission = {"eligible": False, "status": "unverified",
                      "reasons": ["submission_inspection_error"]}
    conflicts = _summary_conflicts(run)
    mixed_run_ids: set[str] = set()
    if state.is_dir():
        for path in state.glob("*.md"):
            mixed_run_ids.update(_RUN_MARKER.findall(_text(path, run)))
    discovery = discover_finding_artifacts(run)
    manifest = run / "run_manifest.json"
    required = {
        name: (run / name).is_file()
        for name in (
            "run_manifest.json", "inventory.json", "coverage-ledger.json",
            "candidate-ledger.json", "feature-graph.json", "threat-model.json",
            "execution-contracts.json", "miss-attribution.json",
            "next-run-agenda.json", "delivery_status.json", "run_receipt.json",
        )
    }
    manual_complete_claim = False
    summary = run / "summary.json"
    if summary.is_file():
        text = _text(summary, run)
        manual_complete_claim = bool(
            re.search(r'"(?:termination_status|status)"\s*:\s*"[^"\n]*(?:complete|VULN_FOUND)', text, re.I)
            and not submission.get("eligible"))
    if not manual_complete_claim:
        for path in (run / "state" / "findings_summary.md",):
            if path.is_file() and "VULN_FOUND (complete)" in _text(path, run):
                manual_complete_claim = not submission.get("eligible")

    attribution = validation.get("miss_attribution") or {}
    standards = {
        "no_silent_omission": bool(
            required["coverage-ledger.json"] and attribution.get("complete")),
        "no_evidenceless_finding": bool(
            int((validation.get("counts") or {}).get("canonical", 0) or 0)
            == int((validation.get("counts") or {}).get("proof_confirmed", 0) or 0)
            and not (reports and not discovery["counts"]["canonical"])),
        "no_manual_report_bypass": bool(not reports or submission.get("eligible")),
        "no_false_coverage": bool(
            validation.get("closure_gate", {}).get("result") == "pass"),
        "no_garbage_submission": bool(
            not reports or submission.get("eligible")),
        "exact_miss_attribution": bool(attribution.get("complete")),
        "automatic_next_run": bool(required["next-run-agenda.json"]),
        "model_independent_contract": bool(
            required["run_manifest.json"] and required["run_receipt.json"]),
    }
    issues: list[dict[str, Any]] = []
    for name, present in required.items():
        if not present:
            issues.append({"code": "artifact_missing", "artifact": name})
    if reports and not submission.get("eligible"):
        issues.append({
            "code": "orphan_or_unverified_report",
            "paths": [item["path"] for item in report_findings],
        })
    if any(item["sensitive_kinds"] for item in report_findings):
        issues.append({
            "code": "report_sensitive_data",
            "files": [item for item in report_findings if item["sensitive_kinds"]],
        })
    if credential_files:
        issues.append({
            "code": "credential_material_outside_restricted_identity_store",
            "files": credential_files,
        })
    if conflicts:
        issues.append({"code": "positive_negative_truth_conflict", "items": conflicts})
    if len(mixed_run_ids) > 1:
        issues.append({
            "code": "multiple_runs_mixed_in_one_session",
            "run_markers": sorted(mixed_run_ids, key=int),
        })
    if manual_complete_claim:
        issues.append({"code": "manual_complete_claim_without_verified_delivery"})
    if validation.get("proof_gate", {}).get("result") != "pass":
        issues.append({
            "code": "proof_gate_failed",
            "rejected": int((validation.get("counts") or {}).get("rejected", 0) or 0),
        })
    return {
        "schema_version": 1,
        "run_dir": str(run),
        "status": "clean" if not issues and all(standards.values()) else "issues_found",
        "required_artifacts": required,
        "finding_counts": validation.get("counts") or {},
        "validation_status": validation.get("status"),
        "submission": {
            "status": submission.get("status"),
            "eligible": bool(submission.get("eligible")),
            "reasons": list(submission.get("reasons") or []),
        },
        "report_files": report_findings,
        "summary_conflicts": conflicts,
        "mixed_run_markers": sorted(mixed_run_ids, key=int),
        "manual_complete_claim": manual_complete_claim,
        "standards": standards,
        "issues": issues,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only Atoolkit v9 contract audit for any run directory")
    parser.add_argument("run_dir", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        result = audit_run(args.run_dir)
    except Exception as exc:  # noqa: BLE001 - CLI maps operational failure
        print(json.dumps({
            "schema_version": 1, "status": "error", "exit_code": 3,
            "reason": f"{type(exc).__name__}: {exc}",
        }, ensure_ascii=False, indent=2))
        return 3
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "clean" else 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["audit_run"]
