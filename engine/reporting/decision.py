"""Shared canonical-report three-state decision (v9.2).

``finalize.py`` (authority path) and ``engine.skill_runtime report`` (Direct
diagnostic path) must produce a byte-identical final/draft/none decision for
the same validation dict, so the decision lives here exactly once.
"""
from __future__ import annotations

from typing import Any


def _gate_pass(validation: dict[str, Any], key: str, fallback: bool) -> bool:
    gate = validation.get(key)
    if isinstance(gate, dict):
        return gate.get("result") == "pass"
    return fallback


def gate_outcomes(validation: dict[str, Any]) -> tuple[bool, bool]:
    """proof_pass / closure_pass with the exact finalizer semantics."""
    proof_pass = _gate_pass(
        validation, "proof_gate",
        not validation.get("ingestion_errors")
        and not validation.get("proof_pending_or_rejected"),
    )
    closure_pass = _gate_pass(
        validation, "closure_gate",
        int(validation.get("exit_code", 3)) == 0,
    )
    return proof_pass, closure_pass


def decide_canonical_report(
    *,
    proof_pass: bool,
    closure_pass: bool,
    exit_code: int,
    report_items: list[Any],
) -> tuple[str, str | None]:
    """Return (status, report_name): complete/draft_incomplete/not_generated."""
    if proof_pass and closure_pass and int(exit_code) == 0:
        return "complete", "final_report.md"
    if proof_pass and report_items:
        return "draft_incomplete", "draft_report.md"
    return "not_generated", None


__all__ = ["decide_canonical_report", "gate_outcomes"]
