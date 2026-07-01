"""
Session completeness gate.

Guardian decides whether individual findings are reportable. This gate decides
whether the whole session may claim completion.
"""
from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any

try:
    from .blocker import NEEDS_INPUT, RECOVERABLE, resolve_blocker
    from .ledger import (
        STATUS_BLOCKED,
        STATUS_CONFIRMED,
        STATUS_NOT_APPLICABLE,
        STATUS_NOT_TESTED,
        CoverageLedger,
        is_high_value,
        normalize_status,
    )
except ImportError:  # pragma: no cover - script execution fallback
    from blocker import NEEDS_INPUT, RECOVERABLE, resolve_blocker
    from ledger import (
        STATUS_BLOCKED,
        STATUS_CONFIRMED,
        STATUS_NOT_APPLICABLE,
        STATUS_NOT_TESTED,
        CoverageLedger,
        is_high_value,
        normalize_status,
    )


PASS = "pass"
INCOMPLETE = "incomplete"
NEEDS_INPUT_RESULT = "needs_input"
ERROR = "error"


def _as_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return sorted(value)
    return [value]


def _load_ledger(ledger: str | pathlib.Path | dict[str, Any] | CoverageLedger) -> CoverageLedger:
    if isinstance(ledger, CoverageLedger):
        return ledger
    if isinstance(ledger, (str, pathlib.Path)):
        return CoverageLedger.load(ledger)
    return CoverageLedger.from_dict(ledger)


def _reason(predicate: str, surface: dict[str, Any] | None = None, action: str = "", detail: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {"predicate": predicate}
    if surface:
        out["surface_id"] = surface.get("surface_id", "")
        out["endpoint"] = surface.get("endpoint", "")
        out["method"] = surface.get("method", "")
        out["param"] = surface.get("param", "")
    if action:
        out["action"] = action
    if detail:
        out["detail"] = detail
    return out


def _resolve_evidence_path(evidence_ref: str, evidence_dir: str | pathlib.Path | None,
                           ledger_path: str | pathlib.Path | None) -> pathlib.Path:
    ref = pathlib.Path(evidence_ref)
    if ref.is_absolute():
        return ref
    bases = []
    if evidence_dir:
        bases.append(pathlib.Path(evidence_dir))
    if ledger_path:
        bases.append(pathlib.Path(ledger_path).parent)
    bases.append(pathlib.Path.cwd())
    for base in bases:
        cand = base / ref
        if cand.exists():
            return cand
    return bases[0] / ref


def _evidence_claims_not_confirmed(path: pathlib.Path) -> str:
    if not path.exists():
        return "evidence file is missing"
    try:
        if path.suffix.lower() == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            for key in ("confirmed", "accepted", "valid", "reproducible"):
                if key in data and data[key] is False:
                    return f"evidence has {key}=false"
            status = str(data.get("status", "")).lower() if isinstance(data, dict) else ""
            if status in {"rejected", "false_positive", "not_vulnerable", "failed"}:
                return f"evidence status is {status}"
    except Exception as exc:
        return f"evidence parse error: {exc}"
    return ""


def _matches_oracle(surface: dict[str, Any], hint: dict[str, Any]) -> bool:
    endpoint = hint.get("endpoint") or hint.get("path") or hint.get("url")
    if endpoint and str(endpoint).split("?", 1)[0] != surface.get("endpoint"):
        return False
    method = hint.get("method")
    if method and str(method).upper() != str(surface.get("method", "")).upper():
        return False
    params = _as_list(hint.get("params") or hint.get("param"))
    if params and surface.get("param") not in [str(x) for x in params]:
        return False
    klass = str(hint.get("class") or hint.get("risk_tag") or hint.get("risk") or "").lower()
    if klass:
        tags = {str(x).lower() for x in _as_list(surface.get("risk_tags"))}
        legacy = str(surface.get("legacy_vuln") or "").lower()
        return klass in tags or klass in legacy
    return True


def oracle_hint_uncovered(surface_list: list[dict[str, Any]], oracle_hints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    missed: list[dict[str, Any]] = []
    closed = {STATUS_CONFIRMED, "not_vulnerable", STATUS_NOT_APPLICABLE}
    for hint in oracle_hints:
        matches = [s for s in surface_list if _matches_oracle(s, hint)]
        if not matches:
            missed.append({"hint": hint, "detail": "no matching surface"})
            continue
        if not any(normalize_status(s.get("status")) in closed for s in matches):
            missed.append({"hint": hint, "detail": "matching surfaces have no closed test record"})
    return missed


def evaluate_session_gate(
    ledger: str | pathlib.Path | dict[str, Any] | CoverageLedger,
    *,
    evidence_dir: str | pathlib.Path | None = None,
    oracle_hints: list[dict[str, Any]] | None = None,
    ledger_path: str | pathlib.Path | None = None,
) -> dict[str, Any]:
    obj = _load_ledger(ledger)
    reasons: list[dict[str, Any]] = []
    result = PASS

    for surface in obj.surfaces:
        status = normalize_status(surface.get("status"))
        if is_high_value(surface) and status == STATUS_NOT_TESTED:
            reasons.append(_reason("high_value_not_tested", surface, "test_or_mark_not_applicable_with_reason"))
            result = INCOMPLETE

        if status == STATUS_BLOCKED:
            resolution = resolve_blocker(surface.get("blocker"), surface)
            if resolution.category == RECOVERABLE:
                action = (resolution.next_actions or surface.get("next_actions") or ["recover and retest"])[0]
                reasons.append(_reason("recoverable_blocked", surface, action))
                result = INCOMPLETE
            elif resolution.category == NEEDS_INPUT:
                action = (resolution.next_actions or surface.get("next_actions") or ["request input"])[0]
                reasons.append(_reason("needs_input_blocked", surface, action))
                if result != ERROR:
                    result = NEEDS_INPUT_RESULT

        next_actions = [str(x) for x in _as_list(surface.get("next_actions")) if str(x).strip()]
        has_needs = any("NEED" in action.upper() for action in next_actions) or bool(surface.get("needs"))
        if next_actions and status in {STATUS_NOT_TESTED, STATUS_BLOCKED}:
            reasons.append(_reason("open_next_actions", surface, next_actions[0]))
            if result == PASS:
                result = INCOMPLETE
        if has_needs and status not in {STATUS_CONFIRMED, STATUS_NOT_APPLICABLE}:
            reasons.append(_reason("open_needs", surface, "convert NEEDS into a concrete retest task or request input"))
            if result not in {ERROR, NEEDS_INPUT_RESULT}:
                result = NEEDS_INPUT_RESULT

        if status == STATUS_CONFIRMED:
            evidence_ref = surface.get("evidence_ref")
            if not evidence_ref:
                reasons.append(_reason("confirmed_evidence_mismatch", surface, detail="confirmed surface has no evidence_ref"))
                result = ERROR
            else:
                path = _resolve_evidence_path(str(evidence_ref), evidence_dir, ledger_path)
                mismatch = _evidence_claims_not_confirmed(path)
                if mismatch:
                    reasons.append(_reason("confirmed_evidence_mismatch", surface, detail=f"{path}: {mismatch}"))
                    result = ERROR

    if oracle_hints:
        for miss in oracle_hint_uncovered(obj.surfaces, oracle_hints):
            reasons.append({
                "predicate": "oracle_hint_uncovered",
                "action": "create matching surface and test record",
                "detail": miss["detail"],
                "hint": miss["hint"],
            })
            if result == PASS:
                result = INCOMPLETE

    return {"result": result, "reasons": reasons, "stats": obj.stats()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate coverage-ledger session completeness.")
    parser.add_argument("ledger", help="Path to coverage-ledger.json")
    parser.add_argument("--evidence-dir", default=None)
    parser.add_argument("--oracle", default=None, help="Optional JSON oracle hints")
    args = parser.parse_args(argv)
    oracle = None
    if args.oracle:
        data = json.loads(pathlib.Path(args.oracle).read_text(encoding="utf-8"))
        oracle = data.get("items") if isinstance(data, dict) else data
    out = evaluate_session_gate(args.ledger, evidence_dir=args.evidence_dir, oracle_hints=oracle, ledger_path=args.ledger)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out["result"] == PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
