"""Verify that a report is a receipt-bound v9 SRC submission projection."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
from typing import Any
from urllib.parse import urljoin, urlparse

from .data_hygiene import sensitive_kinds
from .host_policy import (
    hostname_from_url,
    is_authorized_url,
    normalize_authorized_scopes,
)
from .runtime_manifest import verify_run_receipt
from .safe_io import safe_read_bytes
from .skill_runtime import parse_scope_file


_TARGET_METHODS = {
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
}


def _resolve_finding_target(raw: str, primary_target: str) -> str:
    """Resolve a finding target to an absolute URL (``""`` when impossible).

    Mirrors the ``ValidationContext.target_url`` semantics
    (reporting/validate.py): an optional leading HTTP method token is
    stripped, absolute http(s) targets pass through, and relative targets
    are joined onto the manifest ``primary_target``.  Fail closed: anything
    that still has no http(s) scheme after resolution returns ``""``.
    """
    text = str(raw or "").strip()
    parts = text.split(None, 1)
    if len(parts) == 2 and parts[0].upper() in _TARGET_METHODS:
        text = parts[1]
    if urlparse(text).scheme in {"http", "https"}:
        return text
    if not primary_target:
        return ""
    resolved = urljoin(primary_target.rstrip("/") + "/", text.lstrip("/"))
    if urlparse(resolved).scheme in {"http", "https"}:
        return resolved
    return ""


def _submission_scopes(
    run: pathlib.Path, manifest: dict[str, Any],
) -> tuple[str, list[str]]:
    """Scope source for the submission exit check (fail closed when absent).

    Priority: (1) ``run_manifest.json.authorized_scopes``; (2) for runs
    without a manifest, ``run_scope.json`` target_domains.  Derived assets
    are deliberately excluded: they may appear in proof packets but never
    as a root finding target.
    """
    scopes = manifest.get("authorized_scopes")
    if isinstance(scopes, list):
        normalized = normalize_authorized_scopes([str(item) for item in scopes])
        if normalized:
            return "manifest", normalized
    scope_path = run / "run_scope.json"
    if scope_path.is_file() and not scope_path.is_symlink():
        try:
            parsed, _derived = parse_scope_file(scope_path)
        except Exception:  # noqa: BLE001 - unreadable scope file fails closed
            parsed = []
        normalized = normalize_authorized_scopes(parsed)
        if normalized:
            return "run_scope", normalized
    return "", []


def _json(path: pathlib.Path, root: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(safe_read_bytes(path, root=root).decode("utf-8"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def inspect_submission(run_dir: str | pathlib.Path) -> dict[str, Any]:
    run = pathlib.Path(run_dir).resolve()
    reasons: list[str] = []
    manifest = _json(run / "run_manifest.json", run)
    delivery = _json(run / "delivery_status.json", run)
    receipt = _json(run / "run_receipt.json", run)
    summary = _json(run / "summary.json", run)
    attribution = _json(run / "miss-attribution.json", run)
    report = run / "final_report.md"
    if int(manifest.get("submission_contract_version", 0) or 0) != 1:
        reasons.append("submission_contract_missing")
    if not delivery.get("delivery_complete"):
        reasons.append("delivery_incomplete")
    if not delivery.get("canonical_report_verified"):
        reasons.append("canonical_report_unverified")
    if not attribution.get("complete"):
        reasons.append("miss_attribution_incomplete")
    if not report.is_file():
        reasons.append("canonical_report_missing")

    verification: dict[str, Any] = {}
    authority_text = str(manifest.get("authority_path") or "")
    authority_dir = (
        pathlib.Path(authority_text).resolve().parent.parent
        if authority_text and pathlib.Path(authority_text).is_absolute() else None
    )
    if receipt and authority_dir is not None:
        try:
            verification = verify_run_receipt(
                run / "run_receipt.json", run_dir=run,
                authority_dir=authority_dir)
        except (OSError, ValueError) as exc:
            reasons.append(f"receipt_verification_error:{type(exc).__name__}")
        else:
            if not verification.get("integrity_valid"):
                reasons.append("receipt_integrity_invalid")
            if not verification.get("delivery_complete"):
                reasons.append("receipt_delivery_incomplete")
    else:
        reasons.append("receipt_or_authority_missing")

    actual_report_sha256 = ""
    report_sensitive: list[str] = []
    if report.is_file():
        try:
            payload = safe_read_bytes(report, root=run)
        except (OSError, ValueError):
            reasons.append("canonical_report_unreadable")
        else:
            actual_report_sha256 = hashlib.sha256(payload).hexdigest()
            report_sensitive = sensitive_kinds(
                payload.decode("utf-8", errors="ignore"))
            if report_sensitive:
                reasons.append("canonical_report_contains_sensitive_data")
            expected = str(summary.get("canonical_report_sha256") or "")
            if not expected or actual_report_sha256 != expected:
                reasons.append("canonical_report_hash_mismatch")
            receipt_report = ((receipt.get("artifacts") or {}).get("final_report") or {})
            if str(receipt_report.get("sha256") or "") != actual_report_sha256:
                reasons.append("receipt_report_hash_mismatch")

    # v9.8.1 W6: deterministic scope membership check at the submission exit.
    # Every confirmed finding target (receipt-bound finding_validation.json)
    # must resolve into this run's authorized scopes; relative targets are
    # resolved against the manifest primary_target.  Pure set membership —
    # no ownership heuristics, no counterfeit judgement (v9.6).
    scope_source, scope_values = _submission_scopes(run, manifest)
    scope_check: dict[str, Any] = {
        "source": scope_source,
        "targets_checked": 0,
        "targets_rejected": [],
    }
    if not scope_source:
        reasons.append("submission_scope_source_missing")
    else:
        primary_target = str(manifest.get("primary_target") or "").strip()
        validation_doc = _json(run / "finding_validation.json", run)
        for item in validation_doc.get("normalized_findings") or []:
            if not isinstance(item, dict):
                continue
            raw_target = str(item.get("target") or "").strip()
            scope_check["targets_checked"] += 1
            resolved = _resolve_finding_target(raw_target, primary_target)
            if not resolved:
                reasons.append(f"finding_target_unresolvable:{raw_target}")
                scope_check["targets_rejected"].append(raw_target)
                continue
            if not is_authorized_url(resolved, scope_values):
                reasons.append(
                    "finding_target_out_of_scope:"
                    + (hostname_from_url(resolved) or resolved))
                scope_check["targets_rejected"].append(raw_target)

    reasons = list(dict.fromkeys(reasons))
    return {
        "schema_version": 1,
        "run_dir": str(run),
        "status": "verified" if not reasons else "unverified",
        "eligible": not reasons,
        "reasons": reasons,
        "scope_check": scope_check,
        "report_path": str(report) if report.is_file() else "",
        "report_sha256": actual_report_sha256,
        "sensitive_kinds": report_sensitive,
        "receipt_verification": verification,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a receipt-bound canonical Atoolkit submission "
        "(finding targets are machine-checked against the manifest/run_scope "
        "authorized scopes — no manual ownership judgement)")
    parser.add_argument("run_dir", type=pathlib.Path)
    args = parser.parse_args(argv)
    result = inspect_submission(args.run_dir)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["eligible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["inspect_submission"]
