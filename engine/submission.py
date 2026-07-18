"""Verify that a report is a receipt-bound v9 SRC submission projection."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
from typing import Any

from .data_hygiene import sensitive_kinds
from .runtime_manifest import verify_run_receipt
from .safe_io import safe_read_bytes


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

    reasons = list(dict.fromkeys(reasons))
    return {
        "schema_version": 1,
        "run_dir": str(run),
        "status": "verified" if not reasons else "unverified",
        "eligible": not reasons,
        "reasons": reasons,
        "report_path": str(report) if report.is_file() else "",
        "report_sha256": actual_report_sha256,
        "sensitive_kinds": report_sensitive,
        "receipt_verification": verification,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a receipt-bound canonical Atoolkit submission")
    parser.add_argument("run_dir", type=pathlib.Path)
    args = parser.parse_args(argv)
    result = inspect_submission(args.run_dir)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["eligible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["inspect_submission"]
