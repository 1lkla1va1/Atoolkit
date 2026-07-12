"""
Session completeness gate.

Guardian decides whether individual findings are reportable. This gate decides
whether the whole session may claim completion.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
from typing import Any

try:
    from .blocker import NEEDS_INPUT, RECOVERABLE, resolve_blocker
    from .knowledge import negative_sufficient
    from .ledger import (
        STATUS_BLOCKED,
        STATUS_CONFIRMED,
        STATUS_NOT_APPLICABLE,
        STATUS_NOT_TESTED,
        STATUS_NOT_VULNERABLE,
        CoverageLedger,
        is_high_value,
        normalize_status,
    )
except ImportError:  # pragma: no cover - script execution fallback
    from blocker import NEEDS_INPUT, RECOVERABLE, resolve_blocker
    from knowledge import negative_sufficient
    from ledger import (
        STATUS_BLOCKED,
        STATUS_CONFIRMED,
        STATUS_NOT_APPLICABLE,
        STATUS_NOT_TESTED,
        STATUS_NOT_VULNERABLE,
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


def _norm_ep(ep: str) -> str:
    """Normalize an endpoint for inventory comparison: strip scheme://host,
    fragment, and query, then lowercase. Keeps path placeholders like {id}
    intact (inventory records and ledger surfaces both carry them)."""
    ep = str(ep or "").strip()
    ep = re.sub(r'^https?://[^/]+', '', ep)
    ep = ep.split("#", 1)[0]
    ep = ep.split("?", 1)[0]
    return ep.lower()


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


def _negative_obj_from_surface(surface: dict[str, Any]) -> dict[str, Any] | None:
    """Build a knowledge.negative_sufficient negative-evidence object from a
    ledger surface, if it carries one.

    Returns None when the surface has no negative-evidence metadata, so the
    gate does not re-litigate a plain not_vulnerable/close surface that was
    closed without recording vectors/responses.
    """
    neg = surface.get("negative")
    if isinstance(neg, dict):
        return neg
    obj = {
        "vectors": _as_list(surface.get("vectors")),
        "response_count": int(surface.get("response_count", 0) or 0),
        "evidence_types": _as_list(surface.get("evidence_types")),
        "identities": _as_list(surface.get("identities")),
    }
    if any(obj[k] for k in ("vectors", "response_count", "evidence_types", "identities")):
        return obj
    return None


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
    inventory_path: str | pathlib.Path | None = None,
    candidates: list[dict[str, Any]] | None = None,
    finding_candidate_ids: set[str] | None = None,
) -> dict[str, Any]:
    obj = _load_ledger(ledger)
    reasons: list[dict[str, Any]] = []
    result = PASS
    finding_ids = finding_candidate_ids or set()

    # P1-3: load the run's inventory.json (if present) for the
    # inventory_evidence_inconsistent predicate. Missing/unparseable inventory →
    # the predicate is skipped (does not block), since an ad-hoc or
    # --endpoints-only run has no bootstrap inventory to compare against.
    inventory_eps: set[str] | None = None
    if inventory_path:
        inv_p = pathlib.Path(inventory_path)
        if inv_p.exists():
            try:
                inv_data = json.loads(inv_p.read_text(encoding="utf-8"))
                inv_records = inv_data.get("endpoints") if isinstance(inv_data, dict) else inv_data
                if isinstance(inv_records, list):
                    inventory_eps = {
                        _norm_ep(r.get("endpoint")) for r in inv_records
                        if isinstance(r, dict) and r.get("endpoint")
                    }
            except Exception:
                inventory_eps = None

    for surface in obj.surfaces:
        # Out-of-run backlog is reported separately by ledger.stats.  It keeps
        # the project incomplete but must not explode one bounded run into
        # hundreds of duplicate session-gate reasons.
        if surface.get("in_run_scope") is False:
            continue
        status = normalize_status(surface.get("status"))
        if is_high_value(surface) and status == STATUS_NOT_TESTED:
            reasons.append(_reason("high_value_not_tested", surface, "test_or_mark_not_applicable_with_reason"))
            result = INCOMPLETE

        # shallow_negative_open (v4.1 P0-2): a shallow negative must not slip
        # through just because it is neither high-value nor carrying
        # next_actions. normalize_status collapses "shallow_negative" onto
        # STATUS_NOT_TESTED, so the ledger carries a `negative_depth="shallow"`
        # marker (see engine/ledger.py) to keep the distinction. We also re-run
        # knowledge.negative_sufficient when the surface exposes negative
        # evidence, so a not_vulnerable surface whose vectors/responses are
        # below threshold is re-opened. Placed after high_value_not_tested and
        # before recoverable_blocked so high-value wins and shallow is not
        # swallowed by the blocked/needs predicates below.
        if status not in {STATUS_CONFIRMED, STATUS_NOT_APPLICABLE, STATUS_BLOCKED}:
            raw_status = str(surface.get("status") or "").strip().lower()
            shallow = surface.get("negative_depth") == "shallow" or raw_status == "shallow_negative"
            neg_obj = _negative_obj_from_surface(surface)
            insufficient = False
            if neg_obj is not None:
                sufficient, _missing = negative_sufficient(surface, neg_obj, None)
                insufficient = not sufficient
            if shallow or insufficient:
                reasons.append(_reason(
                    "shallow_negative_open",
                    surface,
                    "retest_with_more_vectors_or_mark_not_vulnerable",
                    detail="shallow_negative" if shallow else "negative evidence below negative_sufficient threshold",
                ))
                if result == PASS:
                    result = INCOMPLETE

        # v6.1 §6.2: negative_depth_not_checked — a not_vulnerable surface whose
        # negative depth floor has not been closed-loop verified must not pass.
        if status == STATUS_NOT_VULNERABLE and not surface.get("negative_depth_checked"):
            reasons.append(_reason(
                "negative_depth_not_checked",
                surface,
                "recheck negative depth floor against knowledge cards",
                detail="not_vulnerable surface has negative_depth_checked=false",
            ))
            if result == PASS:
                result = INCOMPLETE

        # v6.1 §4.2/§6: surface_candidates_all_shallow_refuted — surface has
        # candidates but they were all refuted at shallow depth (depth_score <
        # depth_floor), meaning the surface was "tested" but not deeply enough.
        cand_count = int(surface.get("candidate_count", 0) or 0)
        deepest = str(surface.get("deepest_status", "") or "")
        if cand_count > 0 and deepest == "refuted" and status in {STATUS_NOT_VULNERABLE, STATUS_NOT_TESTED}:
            surf_cands = [c for c in (candidates or [])
                         if c.get("surface_id") == surface.get("surface_id")]
            all_shallow = bool(surf_cands) and all(
                c.get("status") == "refuted"
                and int(c.get("depth_score", 0) or 0) < int(c.get("depth_floor", 1) or 1)
                for c in surf_cands)
            if all_shallow:
                reasons.append(_reason(
                    "surface_candidates_all_shallow_refuted",
                    surface,
                    "retest candidates to depth_floor before closing",
                    detail=f"{cand_count} candidates all refuted below depth_floor",
                ))
                if result == PASS:
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
            # inventory_evidence_inconsistent (v4.1 P1-3): a confirmed surface whose
            # endpoint is not registered in the run's inventory.json (neither at
            # bootstrap nor as discovered_during_testing) means the report cites an
            # endpoint the run never inventoried — a coverage/evidence inconsistency.
            # The run cannot claim completion while referencing unregistered endpoints.
            # Skipped when inventory is absent/unparseable/empty (non-bootstrap or
            # empty-recon runs have no registered endpoints to compare against).
            if inventory_eps and _norm_ep(surface.get("endpoint")) not in inventory_eps:
                reasons.append(_reason(
                    "inventory_evidence_inconsistent",
                    surface,
                    "register endpoint in inventory before claiming completion",
                    detail="报告引用未登记 endpoint（不在 inventory.json，且无 discovered_during_testing 记录）",
                ))
                if result == PASS:
                    result = INCOMPLETE

    # v6.1 §8.2: candidate-based predicates (proof_ready_without_finding,
    # recoverable_blocked_open). These fire when candidates exist in states
    # that indicate "found but not in report" or "blocked but recoverable".
    for cand in candidates or []:
        cid = str(cand.get("candidate_id") or "")
        c_status = str(cand.get("status") or "")
        # proof_ready_without_finding (§8.2 ④): a proof_ready candidate that
        # never produced a finding → "漏进报告" headroom.
        if c_status == "proof_ready" and cid not in finding_ids:
            reasons.append({
                "predicate": "proof_ready_without_finding",
                "candidate_id": cid,
                "surface_id": cand.get("surface_id", ""),
                "endpoint": cand.get("endpoint", ""),
                "action": "produce finding package or mark NEED_INPUT",
                "detail": f"proof_ready candidate without finding: {cand.get('hypothesis', '')[:60]}",
            })
            if result == PASS:
                result = INCOMPLETE
        # recoverable_blocked_open (§8.2 ③): a blocked candidate whose blocker
        # is recoverable but whose next_actions have not been cleared.
        if c_status == "blocked":
            blocker = cand.get("blocker") or {}
            if isinstance(blocker, dict) and blocker.get("recoverable") and _as_list(cand.get("next_actions")):
                reasons.append({
                    "predicate": "recoverable_blocked_open",
                    "candidate_id": cid,
                    "surface_id": cand.get("surface_id", ""),
                    "endpoint": cand.get("endpoint", ""),
                    "action": (cand.get("next_actions") or ["recover and retest"])[0],
                    "detail": f"recoverable blocker with uncleared next_actions: {blocker.get('kind', '')}",
                })
                if result == PASS:
                    result = INCOMPLETE

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
    parser.add_argument("--inventory", default=None,
                        help="Optional inventory.json path for inventory_evidence_inconsistent")
    args = parser.parse_args(argv)
    oracle = None
    if args.oracle:
        data = json.loads(pathlib.Path(args.oracle).read_text(encoding="utf-8"))
        oracle = data.get("items") if isinstance(data, dict) else data
    out = evaluate_session_gate(args.ledger, evidence_dir=args.evidence_dir,
                                oracle_hints=oracle, ledger_path=args.ledger,
                                inventory_path=args.inventory)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out["result"] == PASS else 1


def _selftest() -> None:
    """Self-test for the shallow_negative_open predicate (v4.1 P0-2)."""
    print("=== session_gate self-test: shallow_negative_open (v4.1 P0-2) ===")

    # Case 1: a non-high-value, no-next_actions shallow_negative cell must be
    # caught by shallow_negative_open (previously slipped through as a plain
    # not_tested with no next_actions).
    ledger1 = CoverageLedger(surfaces=[{
        "endpoint": "/api/search",
        "method": "GET",
        "param": "q",
        "feature": "search",
        "status": "shallow_negative",
        # no next_actions, not high-value
    }])
    out1 = evaluate_session_gate(ledger1)
    preds1 = [r["predicate"] for r in out1["reasons"]]
    assert out1["result"] == INCOMPLETE, f"case1: expected incomplete, got {out1['result']}"
    assert "shallow_negative_open" in preds1, f"case1: expected shallow_negative_open in {preds1}"
    assert ledger1.surfaces[0].get("negative_depth") == "shallow", "case1: negative_depth marker should be retained"
    assert ledger1.surfaces[0].get("status") == STATUS_NOT_TESTED, "case1: status should normalize to not_tested"
    print(f"  case1 ✅ shallow_negative_open fired; result={out1['result']} predicates={preds1}")

    # Case 2: all not_vulnerable with sufficient negative evidence (>=3 vectors,
    # >=1 response) -> pass. Proves the predicate does not false-positive on
    # genuinely closed negatives. v6.1: must also set negative_depth_checked=True
    # (§6.2 closed-loop verification) to pass the new negative_depth_not_checked.
    ledger2 = CoverageLedger(surfaces=[{
        "endpoint": "/api/search2",
        "method": "GET",
        "param": "q",
        "feature": "search",
        "status": "not_vulnerable",
        "negative_depth_checked": True,
        "negative": {"vectors": ["baseline", "boundary", "type"], "response_count": 1,
                     "evidence_types": ["baseline"]},
    }])
    out2 = evaluate_session_gate(ledger2)
    assert out2["result"] == PASS, f"case2: expected pass, got {out2['result']} reasons={out2['reasons']}"
    print(f"  case2 ✅ sufficient not_vulnerable passes; result={out2['result']}")

    # Case 3: a high-value not_tested cell must still report high_value_not_tested
    # first (predicate ordering), and must NOT trigger shallow_negative_open.
    ledger3 = CoverageLedger(surfaces=[{
        "endpoint": "/api/admin/users",
        "method": "GET",
        "param": "",
        "feature": "admin",
        "status": "not_tested",
    }])
    out3 = evaluate_session_gate(ledger3)
    preds3 = [r["predicate"] for r in out3["reasons"]]
    assert out3["result"] == INCOMPLETE, f"case3: expected incomplete, got {out3['result']}"
    assert preds3 and preds3[0] == "high_value_not_tested", f"case3: high_value_not_tested must be first, got {preds3}"
    assert "shallow_negative_open" not in preds3, "case3: plain not_tested should not trigger shallow_negative_open"
    print(f"  case3 ✅ high_value_not_tested reported first; predicates={preds3}")

    # Case 4 (bonus): a not_vulnerable surface whose negative evidence is below
    # the negative_sufficient threshold is re-opened as shallow_negative_open.
    ledger4 = CoverageLedger(surfaces=[{
        "endpoint": "/api/lookup",
        "method": "GET",
        "param": "q",
        "feature": "search",
        "status": "not_vulnerable",
        "negative": {"vectors": ["baseline"], "response_count": 0},
    }])
    out4 = evaluate_session_gate(ledger4)
    preds4 = [r["predicate"] for r in out4["reasons"]]
    assert out4["result"] == INCOMPLETE, f"case4: expected incomplete, got {out4['result']}"
    assert "shallow_negative_open" in preds4, f"case4: expected shallow_negative_open in {preds4}"
    print(f"  case4 ✅ insufficient not_vulnerable re-opened; predicates={preds4}")

    print("=== session_gate self-test: inventory_evidence_inconsistent (v4.1 P1-3) ===")

    # Case 5: a confirmed surface whose endpoint is NOT in the inventory →
    # inventory_evidence_inconsistent fires and the result is INCOMPLETE.
    import tempfile
    inv_dir = pathlib.Path(tempfile.mkdtemp())
    inv_path = inv_dir / "inventory.json"
    inv_path.write_text(json.dumps({"endpoints": [
        {"endpoint": "/api/registered", "method": "GET", "source": "js",
         "last_seen": "", "discovered_during_testing": False},
    ]}, ensure_ascii=False), encoding="utf-8")
    ledger5 = CoverageLedger(surfaces=[{
        "endpoint": "/api/secret-admin",      # not in inventory
        "method": "GET", "param": "", "feature": "admin",
        "status": "confirmed", "evidence_ref": "report.md",
    }])
    ev5 = (inv_dir / "report.md")
    ev5.write_text("---\nseverity: P1\ntitle: t\ntarget: https://t.example\n---\nbody\n",
                   encoding="utf-8")
    out5 = evaluate_session_gate(ledger5, evidence_dir=str(inv_dir),
                                 ledger_path=inv_path, inventory_path=inv_path)
    preds5 = [r["predicate"] for r in out5["reasons"]]
    assert "inventory_evidence_inconsistent" in preds5, f"case5: expected predicate, got {preds5}"
    assert out5["result"] == INCOMPLETE, f"case5: expected incomplete, got {out5['result']}"
    print(f"  case5 ✅ confirmed endpoint not in inventory → {out5['result']} preds={preds5}")

    # Case 6: a confirmed surface whose endpoint IS in the inventory (as a
    # discovered_during_testing record) → predicate must NOT fire.
    inv_path2 = inv_dir / "inventory2.json"
    inv_path2.write_text(json.dumps({"endpoints": [
        {"endpoint": "/api/orders/{id}", "method": "GET", "source": "discovered_in_testing",
         "last_seen": "", "discovered_during_testing": True},
    ]}, ensure_ascii=False), encoding="utf-8")
    ledger6 = CoverageLedger(surfaces=[{
        "endpoint": "/api/orders/{id}",       # registered as discovered
        "method": "GET", "param": "id", "feature": "order",
        "status": "confirmed", "evidence_ref": "report.md",
    }])
    out6 = evaluate_session_gate(ledger6, evidence_dir=str(inv_dir),
                                 ledger_path=inv_path2, inventory_path=inv_path2)
    preds6 = [r["predicate"] for r in out6["reasons"]]
    assert "inventory_evidence_inconsistent" not in preds6, \
        f"case6: registered (discovered) endpoint must not fire, got {preds6}"
    assert out6["result"] == PASS, f"case6: expected pass, got {out6['result']}"
    print(f"  case6 ✅ confirmed endpoint registered as discovered → {out6['result']} (no fire)")

    # Case 7: inventory missing → predicate skipped (does not block). Confirmed
    # surface with valid evidence → PASS, no inventory_evidence_inconsistent.
    ledger7 = CoverageLedger(surfaces=[{
        "endpoint": "/api/anything",
        "method": "GET", "param": "", "feature": "x",
        "status": "confirmed", "evidence_ref": "report.md",
    }])
    out7 = evaluate_session_gate(ledger7, evidence_dir=str(inv_dir),
                                 ledger_path=inv_path,
                                 inventory_path=inv_dir / "does-not-exist.json")
    preds7 = [r["predicate"] for r in out7["reasons"]]
    assert "inventory_evidence_inconsistent" not in preds7, \
        f"case7: missing inventory must skip predicate, got {preds7}"
    assert out7["result"] == PASS, f"case7: expected pass, got {out7['result']}"
    print(f"  case7 ✅ missing inventory → predicate skipped, result={out7['result']}")

    # Case 8: no inventory_path passed at all (ad-hoc/--endpoints-only runs) → skip.
    out8 = evaluate_session_gate(ledger7, evidence_dir=str(inv_dir), ledger_path=inv_path)
    assert "inventory_evidence_inconsistent" not in [r["predicate"] for r in out8["reasons"]]
    assert out8["result"] == PASS
    print(f"  case8 ✅ no inventory_path → predicate skipped, result={out8['result']}")

    # Case 9: empty inventory (endpoints:[]) → predicate skipped (no registered
    # endpoints to compare against; a degenerate empty-recon run must not block).
    inv_empty = inv_dir / "inventory_empty.json"
    inv_empty.write_text(json.dumps({"endpoints": []}), encoding="utf-8")
    out9 = evaluate_session_gate(ledger7, evidence_dir=str(inv_dir),
                                 ledger_path=inv_empty, inventory_path=inv_empty)
    assert "inventory_evidence_inconsistent" not in [r["predicate"] for r in out9["reasons"]]
    assert out9["result"] == PASS
    print(f"  case9 ✅ empty inventory (endpoints=[]) → predicate skipped, result={out9['result']}")

    print("✅ all session_gate self-test cases passed")


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        _selftest()
    else:
        raise SystemExit(main())
