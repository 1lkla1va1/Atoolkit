#!/usr/bin/env python3
"""run.py —— 一条命令起一次授权 SRC 会话。

把 engine 三件套(orchestrator+enforce+verify) + Codex 适配器接成入口。
本文件只做接线，不含新逻辑（逻辑在 engine/ 与 codex/）。

用法：
  # 真实跑（用 Codex）
  python3 run.py --target https://t.example --authz "仅限 https://t.example，已授权" \
      --cookie 'session=...' [--model gpt-5.5-codex] [--allow t2.example] \
      [--identity owner:session=A --identity attacker:session=B --victim-marker '收货地址']

  # 不接模型/网络，自检接线是否通（用 MockAdapter）
  python3 run.py --dry-run --target https://t.example --authz "demo"

换模型：改 --model 即可；换运行时：把 CodexAdapter 换成别的 ModelAdapter（本文件 1 处）。
"""
from __future__ import annotations
import argparse, inspect, sys, time, re, pathlib, json, shutil, os, secrets, hashlib
from fnmatch import fnmatch
from urllib.parse import urlsplit

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from engine.orchestrator import run_session, MockAdapter          # noqa: E402
from engine.verify import (verify_idor, extract_poc, urllib_transport,  # noqa: E402
                           VerifyResult, INCONCLUSIVE, NOT_APPLICABLE,
                           extract_poc_from_finding)
from engine.host_policy import (authorization_scope_from_url, hostname_from_url,
                                normalize_authorized_scopes,
                                parse_authorized_scope)  # noqa: E402
from engine.runtime_manifest import doctor  # noqa: E402
from engine.run_authority import validate_session_id as _validate_session_id  # noqa: E402
from engine.safe_io import atomic_write_text, ensure_directory  # noqa: E402
from engine.version import __version__  # noqa: E402


def host_of(url: str) -> str:
    return hostname_from_url(url) or url


def safe_project_slug(value: str) -> str:
    """Return a path-safe project slug; never allow project path traversal."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "")).strip("._-")
    return slug or "target"


def normalize_explicit_base_path(value: str) -> str:
    """Normalize an explicitly supplied application namespace.

    Target URL paths are deliberately not consulted: ``/login/`` is an entry
    page, not proof that it is the stable application root.
    """
    raw = str(value or "").strip()
    if not raw:
        return "/"
    if "?" in raw or "#" in raw or "\\" in raw or "\x00" in raw:
        raise ValueError("--base-path 只能是无 query/fragment 的 URL path")
    if not raw.startswith("/"):
        raw = "/" + raw
    segments: list[str] = []
    for segment in raw.split("/"):
        if segment in {"", "."}:
            continue
        if segment == "..":
            raise ValueError("--base-path 不能包含 ..")
        segments.append(segment)
    return "/" + "/".join(segments) + ("/" if segments else "")


def default_project_slug(target: str, *, base_path: str = "/") -> str:
    """Stable project slug from origin plus an *explicit* app namespace."""
    parsed = urlsplit(str(target or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return "target"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    origin_label = safe_project_slug(f"{parsed.hostname}_{port}")
    namespace = normalize_explicit_base_path(base_path)
    if namespace == "/":
        return origin_label
    readable = safe_project_slug(namespace.strip("/").replace("/", "_"))[:36]
    digest = hashlib.sha256(namespace.encode("utf-8")).hexdigest()[:10]
    return safe_project_slug(f"{origin_label}_{readable}_{digest}")


def safe_session_id(value: str) -> str:
    """Validate, rather than sanitize, a session ID used as a path component."""
    return _validate_session_id(value)


def safe_session_dir(base: pathlib.Path, sid: str) -> pathlib.Path:
    """Resolve a session child path and reject traversal or existing symlinks."""
    clean_sid = safe_session_id(sid)
    ensure_directory(base)
    try:
        base.chmod(0o700)
    except OSError:
        pass
    candidate = base / clean_sid
    if candidate.is_symlink():
        raise ValueError(f"session 目录不能是符号链接: {candidate}")
    resolved_base = base.resolve()
    resolved_candidate = candidate.resolve(strict=False)
    try:
        resolved_candidate.relative_to(resolved_base)
    except ValueError as exc:
        raise ValueError(f"session 目录逃逸: {candidate}") from exc
    return candidate


def _secure_mkdir(path: pathlib.Path) -> None:
    ensure_directory(path)
    try:
        path.chmod(0o700)
    except OSError:
        pass


def _secure_write_text(path: pathlib.Path, value: str) -> None:
    """Atomically write without mutating symlink or hardlink targets."""
    _secure_mkdir(path.parent)
    atomic_write_text(
        path,
        value,
        root=path.parent,
        mode=0o600,
        # Atomic replacement removes an alias entry without following it and
        # leaves any other hardlink inode untouched.
        reject_leaf_symlink=False,
    )


def _atomic_write_json(path: pathlib.Path, value: dict) -> None:
    """Atomically replace a private JSON delivery artifact."""
    _secure_write_text(
        path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def _write_runtime_inventory(
    path: pathlib.Path,
    value: dict,
    *,
    root: pathlib.Path,
) -> None:
    """Persist parent-owned inventory without changing its legacy JSON format."""
    atomic_write_text(
        path,
        json.dumps(value, ensure_ascii=False, indent=2),
        root=root,
        reject_leaf_symlink=True,
    )


def build_verify_fn(identities: dict, victim_marker: str, hosts: list[str],
                    owner_label: str = "owner"):
    """对 Guardian accepted 的报告做确定性重放复验。无身份/无标记则不复验。"""
    if not identities or not victim_marker:
        return None
    def verify_fn(report_md: str) -> VerifyResult:
        if not re.search(r"(?:idor|越权)", report_md, re.I):
            return VerifyResult(NOT_APPLICABLE, "非 IDOR finding，不适用 IDOR 重放器")
        req = extract_poc(report_md)
        if req is None:
            return VerifyResult(INCONCLUSIVE, "报告无可解析 PoC")
        return verify_idor(req, identities, victim_marker, urllib_transport, hosts,
                           owner_label=owner_label)

    def verify_finding(finding: dict, finding_dir: pathlib.Path) -> VerifyResult:
        vuln_type = str(finding.get("vuln_type") or "")
        if not re.search(r"(?:idor|越权)", vuln_type, re.I):
            return VerifyResult(NOT_APPLICABLE, "非 IDOR finding，不适用 IDOR 重放器")
        req = extract_poc_from_finding(finding, finding_dir)
        if req is None:
            return VerifyResult(INCONCLUSIVE, "finding 无可解析 PoC")
        return verify_idor(req, identities, victim_marker, urllib_transport, hosts,
                           owner_label=owner_label)

    verify_fn.verify_finding = verify_finding
    return verify_fn


def _oracle_hit_str(oracle_path: str, res: dict) -> str:
    """Post-run oracle hint from accepted, proof-confirmed root findings only."""
    ledger_path = res.get("coverage_ledger_path")
    if not ledger_path:
        return "N/A"
    try:
        from engine import benchmark_eval as be
        from engine.ledger import CoverageLedger
        oracle = be.load_oracle(pathlib.Path(oracle_path))
        findings = []
        for row in res.get("normalized_findings") or []:
            if (row.get("acceptance_status") != "accepted"
                    or row.get("proof_status") != "confirmed"
                    or row.get("claim_kind") != "root_finding"):
                continue
            findings.append(be.Finding(
                id=str(row.get("id") or ""),
                title=str(row.get("title") or ""),
                endpoints=be._dedupe(row.get("endpoints") or [row.get("endpoint", "")]),
                methods=be._dedupe(row.get("methods") or [row.get("method", "")]),
                params=be._dedupe(row.get("params") or []),
                vuln_class=str(row.get("vuln_class") or row.get("class") or ""),
                roles=be._dedupe(row.get("roles") or []),
                evidence_file=str(row.get("evidence_file") or ""),
                raw=row,
            ))
        coverage = be.load_coverage(pathlib.Path(ledger_path))
        ev = be.evaluate(oracle, findings, coverage)
        return f"{len(ev['hits'])}/{len(oracle)}"
    except Exception as e:                       # oracle 缺失/格式错 → 不阻断收尾打印
        return f"err:{type(e).__name__}"


def _render_scorecard_md(result: dict, *, sid: str, oracle_path: pathlib.Path,
                         summary_path: pathlib.Path, coverage_path: pathlib.Path) -> str:
    meta = result.get("meta") or {}
    hits = result.get("hits") or []
    misses = result.get("misses") or []
    lines = [
        f"# Atoolkit Scorecard: {sid}",
        "",
        f"- oracle_used_post_run_only: `{meta.get('oracle_used_post_run_only', True)}`",
        f"- oracle: `{oracle_path}`",
        f"- summary: `{summary_path}`",
        f"- coverage: `{coverage_path}`",
        f"- hits: `{len(hits)}/{meta.get('oracle_cases', len(hits) + len(misses))}`",
        f"- score: `{result.get('total_score', 0)}/{result.get('max_score', 0)}`",
        f"- score_rate: `{result.get('score_rate', 0)}`",
        "",
        "## Hits",
    ]
    if hits:
        for item in hits[:50]:
            oc = item.get("oracle") or {}
            finding = item.get("finding") or {}
            lines.append(
                f"- `{oc.get('id','')}` {oc.get('endpoint','')} "
                f"{oc.get('params', [])} -> `{finding.get('id','')}`")
    else:
        lines.append("- none")
    lines.extend(["", "## Misses"])
    if misses:
        for item in misses[:100]:
            oc = item.get("oracle") or {}
            attr = item.get("attribution") or {}
            lines.append(
                f"- `{oc.get('id','')}` {oc.get('endpoint','')} "
                f"{oc.get('params', [])} class={oc.get('class','')} "
                f"coverage={attr.get('status','unknown')}")
    else:
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)


def _score_run(argv: list[str]) -> int:
    """Offline post-run score command.

    This deliberately reads only run artifacts plus the oracle. It never feeds
    oracle contents into the attack prompt or live session state.
    """
    ap = argparse.ArgumentParser(description="赛后离线评分，只读 summary/coverage/findings，不进入攻击 prompt")
    ap.add_argument("--sid", default="", help="runs/<sid> 会话 ID")
    ap.add_argument("--run-dir", default="", help="显式 run 目录；优先于 --sid")
    ap.add_argument("--oracle", required=True, type=pathlib.Path, help="Oracle file: JSON/YAML/CSV/PHP array")
    ap.add_argument("--summary", default=None, type=pathlib.Path, help="默认 <run-dir>/summary.json")
    ap.add_argument("--coverage", default=None, type=pathlib.Path, help="默认 <run-dir>/coverage-ledger.json")
    ap.add_argument("--compact", action="store_true", help="stdout 输出 compact JSON")
    ap.add_argument("--trust-legacy", action="store_true",
                    help="显式兼容没有 finding_validation.json 的旧 summary（默认拒绝计分）")
    args = ap.parse_args(argv)

    if args.run_dir:
        run_dir = pathlib.Path(args.run_dir)
        sid = run_dir.name
    elif args.sid:
        sid = args.sid
        run_dir = ROOT / "runs" / sid
    else:
        ap.error("--sid 或 --run-dir 必填")
    summary_path = args.summary or (run_dir / "summary.json")
    coverage_path = args.coverage or (run_dir / "coverage-ledger.json")
    if not summary_path.exists():
        ap.error(f"summary 不存在: {summary_path}")
    if not coverage_path.exists():
        ap.error(f"coverage-ledger 不存在: {coverage_path}")
    if not args.oracle.exists():
        ap.error(f"oracle 不存在: {args.oracle}")

    from engine import benchmark_eval as be
    oracle = be.load_oracle(args.oracle)
    findings = be.load_findings(summary_path, trust_legacy=args.trust_legacy)
    coverage = be.load_coverage(coverage_path)
    result = be.evaluate(oracle, findings, coverage)
    result["meta"] = {
        "oracle_cases": len(oracle),
        "findings": len(findings),
        "coverage_surfaces": len(coverage),
        "sid": sid,
        "run_dir": str(run_dir.resolve()),
        "summary": str(summary_path.resolve()),
        "coverage": str(coverage_path.resolve()),
        "oracle": str(args.oracle.resolve()),
        "oracle_used_post_run_only": True,
        "trust_legacy": bool(args.trust_legacy),
    }
    run_dir.mkdir(parents=True, exist_ok=True)
    scorecard_json = run_dir / "scorecard.json"
    scorecard_md = run_dir / "scorecard.md"
    atomic_write_text(
        scorecard_json,
        json.dumps(result, ensure_ascii=False, indent=2),
        root=run_dir,
        reject_leaf_symlink=True,
    )
    atomic_write_text(
        scorecard_md,
        _render_scorecard_md(result, sid=sid, oracle_path=args.oracle,
                             summary_path=summary_path, coverage_path=coverage_path),
        root=run_dir,
        reject_leaf_symlink=True,
    )
    json.dump(result, sys.stdout, ensure_ascii=False, indent=None if args.compact else 2)
    sys.stdout.write("\n")
    print(f"scorecard_json={scorecard_json}")
    print(f"scorecard_md={scorecard_md}")
    return 0


def _print_open_high_value(res: dict):
    """打印未闭合高价值面清单（每条 endpoint+role+risk_tag），取自 ledger high_value not_tested/blocked。"""
    ledger_path = res.get("coverage_ledger_path")
    if not ledger_path:
        return
    try:
        from engine.ledger import (CoverageLedger, is_high_value,
                                   normalize_status, STATUS_NOT_TESTED, STATUS_BLOCKED)
        ledger = CoverageLedger.load(pathlib.Path(ledger_path))
        hv_open = [s for s in ledger.surfaces
                   if is_high_value(s)
                   and normalize_status(s.get("status")) in (STATUS_NOT_TESTED, STATUS_BLOCKED)]
    except Exception:
        return
    if not hv_open:
        print("未闭合高价值面清单: (无)")
        return
    print(f"未闭合高价值面清单 ({len(hv_open)}):")
    for s in hv_open:
        roles = ",".join(s.get("roles", [])) or "-"
        tags = ",".join(s.get("risk_tags", [])) or "-"
        print(f"  - {s.get('endpoint', '')} | method={s.get('method', 'GET')} "
              f"| role={roles} | risk_tag={tags}")


def _map_finding_for_summary(f: dict, idx: int) -> dict:
    """aggregate_findings 的 finding（root_cause/affected_role 命名）→ summary.json 行，
    补 engine.benchmark_eval.load_findings 期望的键（class/vuln_class/roles/id/endpoint）。
    不改 aggregate_findings 本身的输出，只在这份产物里做字段映射：class=root_cause、
    roles=[affected_role]、id=finding_key。method/params 留空（benchmark_eval 对空 method/params
    取宽容匹配），endpoint 保留 aggregate_findings 的可读原值。"""
    role = f.get("affected_role")
    facets = f.get("facets") or []
    endpoint = f.get("endpoint", "")
    return {
        "id": f.get("finding_key") or f"finding-{idx:03d}",
        "endpoint": endpoint,
        "endpoints": [endpoint] if endpoint else [],
        "method": "",
        "methods": [],
        "params": [],
        "evidence_file": "",
        "class": f.get("root_cause", ""),
        "vuln_class": f.get("root_cause", ""),
        "roles": ([role] if role and role != "default" else []),
        "severity": f.get("severity", ""),
        "title": facets[0] if facets else "",
        # 保留原始聚合信息（不影响 benchmark_eval 读取，仅供溯源）
        "root_cause": f.get("root_cause", ""),
        "affected_role": role,
        "facets": facets,
        "primary_impact": f.get("primary_impact", ""),
        "report_count": f.get("report_count", 0),
        "finding_key": f.get("finding_key", ""),
        "acceptance_status": "untrusted_legacy",
        "proof_status": "pending",
        "claim_kind": "legacy_report",
    }


_SUMMARY_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SUMMARY_HEXID_RE = re.compile(r"^[0-9a-fA-F]{12,}$")


def _norm_summary_endpoint(endpoint: str) -> str:
    endpoint = re.sub(r"^https?://[^/]+", "", str(endpoint or "").strip())
    endpoint = endpoint.split("#", 1)[0].split("?", 1)[0]
    segs = []
    for seg in endpoint.split("/"):
        if not seg:
            segs.append(seg)
        elif (seg.isdigit() or _SUMMARY_UUID_RE.match(seg) or _SUMMARY_HEXID_RE.match(seg)
              or (seg.startswith("{") and seg.endswith("}"))):
            segs.append("{}")
        else:
            segs.append(seg)
    return "/".join(segs)


def _dedupe_keep(values: list) -> list[str]:
    seen, out = set(), []
    for value in values:
        text = str(value or "").strip()
        if text and text.lower() not in seen:
            seen.add(text.lower())
            out.append(text)
    return out


def _summary_findings(res: dict) -> list[dict]:
    """Project the validator's normalized roots without Coverage enrichment.

    Coverage may detect a mismatch, but it must never invent a method, param,
    role or evidence reference that was absent from the validated Finding.
    """
    return [
        dict(f) for f in (res.get("normalized_findings") or [])
        if f.get("acceptance_status") == "accepted"
        and f.get("proof_status") == "confirmed"
        and f.get("claim_kind") == "root_finding"
    ]


def _summary_status(res: dict) -> str:
    status = str(res.get("status") or "")
    gate = res.get("session_gate") or {}
    if gate.get("result") and gate.get("result") != "pass":
        if status == "vuln_found" or res.get("accepted"):
            return "incomplete_with_findings"
        return "incomplete"
    return status


def _inventory_records_from_endpoint_arg(arg: str) -> tuple[list, list[dict]]:
    p = pathlib.Path(arg)
    endpoints: list = []
    records: list[dict] = []

    def normalized(endpoint: str, method: str = "") -> tuple[str, str, str]:
        # A bare path is a discovery hint, not an observed GET.  Passing an
        # empty default preserves the unresolved method until traffic/source
        # code proves one.
        key = canonical_surface_key(
            {"endpoint": endpoint, "method": method}, default_method="")
        normalized_method, _, path = key.partition(" ")
        return (key if normalized_method else ""), normalized_method, path

    from engine.surface_key import canonical_surface_key
    if p.exists():
        if p.suffix.lower() == ".json":
            data = json.loads(p.read_text(encoding="utf-8"))
            raw_items = data.get("endpoints") if isinstance(data, dict) else data
            for index, item in enumerate(raw_items or [], start=1):
                if isinstance(item, dict):
                    endpoint = str(item.get("endpoint") or item.get("path") or item.get("url") or "").strip()
                    if not endpoint:
                        continue
                    endpoint_key, endpoint_method, endpoint_path = normalized(
                        endpoint, str(item.get("method") or ""))
                    rec = {
                        **item,
                        "endpoint": endpoint_path,
                        "method": endpoint_method,
                        "params": item.get("params") or item.get("parameters") or [],
                        "source": item.get("source") or "endpoints",
                        "source_file": str(p.resolve()),
                        "source_line": item.get("source_line") or index,
                        "source_kind": item.get("source_kind") or "endpoints_json",
                        "last_seen": item.get("last_seen") or "",
                        "discovered_during_testing": bool(item.get("discovered_during_testing", False)),
                    }
                    if endpoint_method:
                        endpoints.append({**rec})
                    records.append(rec)
                    continue
                endpoint = str(item or "").strip()
                if endpoint:
                    endpoint_key, endpoint_method, endpoint_path = normalized(endpoint)
                    if endpoint_method:
                        endpoints.append(endpoint_key)
                    records.append({
                        "endpoint": endpoint_path,
                        "method": endpoint_method,
                        "source": "endpoints",
                        "source_file": str(p.resolve()),
                        "source_line": index,
                        "source_kind": "endpoints_json",
                        "last_seen": "",
                        "discovered_during_testing": False,
                    })
            return endpoints, records
        raw_lines = p.read_text(encoding="utf-8").splitlines()
        for line_no, line in enumerate(raw_lines, start=1):
            endpoint = line.strip()
            if not endpoint or endpoint.lstrip().startswith("#"):
                continue
            endpoint_key, endpoint_method, endpoint_path = normalized(endpoint)
            if endpoint_method:
                endpoints.append(endpoint_key)
            records.append({
                "endpoint": endpoint_path,
                "method": endpoint_method,
                "source": "endpoints",
                "source_file": str(p.resolve()),
                "source_line": line_no,
                "source_kind": "endpoints_file",
                "last_seen": "",
                "discovered_during_testing": False,
            })
    else:
        for index, endpoint in enumerate([x.strip() for x in arg.replace(",", "\n").splitlines()], start=1):
            if not endpoint or endpoint.lstrip().startswith("#"):
                continue
            endpoint_key, endpoint_method, endpoint_path = normalized(endpoint)
            if endpoint_method:
                endpoints.append(endpoint_key)
            records.append({
                "endpoint": endpoint_path,
                "method": endpoint_method,
                "source": "endpoints",
                "source_file": "",
                "source_line": index,
                "source_kind": "cli_endpoints",
                "last_seen": "",
                "discovered_during_testing": False,
            })
    return endpoints, records


def _merge_inventory_records(records: list[dict]) -> list[dict]:
    merged: dict[tuple, dict] = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        key = (
            str(rec.get("endpoint") or ""),
            str(rec.get("method") or "").upper(),
            bool(rec.get("discovered_during_testing")),
        )
        if not key[0]:
            continue
        if key not in merged:
            cur = dict(rec)
            cur["method"] = key[1]
            merged[key] = cur
            continue
        cur = merged[key]
        if rec.get("last_seen") and str(rec.get("last_seen")) > str(cur.get("last_seen") or ""):
            cur["last_seen"] = rec["last_seen"]
        for field in ("source_file", "source_kind", "source", "source_line"):
            if not cur.get(field) and rec.get(field):
                cur[field] = rec[field]
    return list(merged.values())


def _endpoint_excluded(endpoint: str, patterns: list[str]) -> bool:
    """Return True when an endpoint matches a user-supplied exclude pattern.

    Patterns are intentionally simple: shell-style globs, with a substring
    fallback for common path snippets such as ``vuln.php``.
    """
    ep = str(endpoint or "").strip()
    low = ep.lower()
    for raw in patterns or []:
        pat = str(raw or "").strip()
        if not pat:
            continue
        p_low = pat.lower()
        if fnmatch(low, p_low) or p_low in low:
            return True
    return False


def _filter_endpoint_records(records: list[dict], patterns: list[str]) -> list[dict]:
    if not patterns:
        return records
    return [r for r in records
            if not _endpoint_excluded(str(r.get("endpoint") or ""), patterns)]


def _filter_inventory(items: list, patterns: list[str]) -> list:
    if not patterns:
        return items
    out = []
    for item in items:
        endpoint = item.get("endpoint") if isinstance(item, dict) else item
        if not _endpoint_excluded(str(endpoint or ""), patterns):
            out.append(item)
    return out


def _run_self_check() -> int:
    """--self-check 自检门：临时生成 fixture 跑断言，不接真实模型/网络。

    三十条断言覆盖 bootstrap、Coverage/预算、Blackboard/Intent、结构化
    proof contract、Guardian、复验、评分和多参数 Cell。全过 exit 0，任一失败
    exit 1 并打印具体合同。
    """
    from engine.surface import bootstrap
    from engine import benchmark_eval as be
    from engine.ledger import CoverageLedger
    from engine.session_gate import evaluate_session_gate, INCOMPLETE
    from engine.enforce import guardian_check, ACCEPTED
    import tempfile, shutil

    def _write_text(path: pathlib.Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _make_self_check_fixtures(base: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        """生成自检所需的最小样例，避免把 fixtures/ 测试数据放进仓库。"""
        recon = base / "recon_sample"
        reporting = base / "reporting" / "basic_idor"
        _write_text(recon / "app.js", (
            "fetch('/api/order/detail?order_no=1');\n"
            "axios.post('/api/user/login', { password: 'redacted' });\n"
        ))
        _write_text(recon / "page.html", """<!doctype html>
<html lang="zh">
<body>
  <form action="/api/user/login" method="POST">
    <input name="password" type="password">
  </form>
  <a href="/api/order/list">order list</a>
</body>
</html>
""")
        _write_text(recon / "traffic.har", json.dumps({
            "log": {
                "version": "1.2",
                "creator": {"name": "atoolkit-self-check", "version": "1.0"},
                "entries": [{
                    "request": {
                        "method": "GET",
                        "url": "https://t.example/api/user/info",
                        "headers": [],
                    },
                    "response": {"status": 200, "statusText": "OK"},
                }],
            }
        }, ensure_ascii=False, indent=2))
        oracle = base / "oracle_sample.json"
        _write_text(oracle, json.dumps([
            {"id": "case-001", "endpoint": "/api/order/detail", "method": "GET",
             "params": ["order_no"], "class": "越权/IDOR", "score": 3.0, "roles": []},
            {"id": "case-002", "endpoint": "/api/user/login", "method": "POST",
             "params": ["password"], "class": "认证", "score": 2.0, "roles": []},
            {"id": "case-003", "endpoint": "/api/order/list", "method": "GET",
             "params": [], "class": "越权/IDOR", "score": 2.0, "roles": []},
            {"id": "case-004", "endpoint": "/api/user/info", "method": "GET",
             "params": [], "class": "信息泄露", "score": 2.0, "roles": []},
            {"id": "case-005", "endpoint": "/api/orders/{id}", "method": "GET",
             "params": [], "class": "越权/IDOR", "score": 3.0, "roles": [],
             "discovered_during_testing": True},
        ], ensure_ascii=False, indent=2))
        _write_text(reporting / "finding.json", json.dumps({
            "schema_version": 1,
            "id": "finding_001",
            "title": "订单详情接口存在水平越权漏洞",
            "severity": "P1",
            "vuln_type": "越权/IDOR",
            "target": "https://t.example",
            "risk": {
                "summary": "攻击者可读取其他用户订单详情。",
                "proven_impact": "实测 B 账号读取到 A 账号订单收货地址与金额。",
            },
            "recommendation": {
                "summary": "服务端按当前登录身份校验订单归属。",
                "details": ["查询订单详情时绑定 current_user_id 与 order_id。"],
            },
            "feature_point": {
                "module": "订单模块",
                "function": "订单详情查询",
                "trigger": "进入订单详情页时触发",
                "trigger_api": "GET /api/order/detail",
                "vulnerable_param": "order_id",
                "statement": "订单模块 -> 订单详情查询，触发 GET /api/order/detail 接口，order_id 参数存在水平越权漏洞。",
            },
            "apis": [{
                "method": "GET",
                "path": "/api/order/detail",
                "purpose": "根据订单 ID 查询订单详情",
                "risk_params": ["order_id"],
                "params": [{"name": "order_id", "location": "query", "risk": "服务端未校验订单归属"}],
            }],
            "proof_packets": [{
                "name": "owner_control",
                "phase": "owner_control",
                "request_file": "request_0.http",
                "response_file": "response_0.http",
                "evidence_summary": "A 账号读取自身订单，建立对象归属与正常响应基线。",
            }, {
                "name": "attacker_read_victim_order",
                "phase": "unauthorized_actor",
                "request_file": "request_1.http",
                "response_file": "response_1.http",
                "evidence_summary": "响应中返回受害者订单地址与金额。",
            }, {
                "name": "denied_control",
                "phase": "access_denied_control",
                "request_file": "request_denied.http",
                "response_file": "response_denied.http",
                "evidence_summary": "同一接口对另一非属主订单返回 403，证明资源存在属主边界。",
            }],
            "verification": {
                "status": "confirmed",
                "evidence_type": "authorization_differential",
                "observed_effect": "B 账号读取到明确归属于 A 账号的同一订单。",
                "identities": ["owner_a", "attacker_b"],
                "objects": ["order_1001 owned_by_owner_a"],
                "object_marker": "\"order_id\":\"1001\"",
                "access_expectation": {
                    "expected_access": "owner_only",
                    "basis": "same_endpoint_denial",
                    "proof_packet_ids": ["denied_control"],
                    "proof_refs": [],
                    "marker": "order owner required",
                },
                "evidence_files": ["request_0.http", "response_0.http",
                                   "request_1.http", "response_1.http",
                                   "request_denied.http", "response_denied.http"],
                "impact_proof_refs": [],
                "assertions": [
                    {"file": "response_0.http", "relation": "contains",
                     "value": "\"owner\":\"owner_a\""},
                    {"file": "response_1.http", "relation": "contains",
                     "value": "\"owner\":\"victim_a\""},
                ],
            },
            "claim": {
                "kind": "root_finding",
                "profile": "idor_read",
                "invariant": "订单详情只能由订单所有者或获授权角色读取",
                "proof_packet_ids": ["owner_control", "attacker_read_victim_order",
                                     "denied_control"],
            },
            "impact_claims": [{
                "id": "impact_001",
                "status": "proven",
                "statement": "实测 B 账号读取到 A 账号订单收货地址与金额。",
                "proof_refs": ["response_1.http"],
                "marker": "\"owner\":\"victim_a\"",
            }],
            "chain_assessment": {
                "status": "not_tested",
                "chain_feasible": False,
                "chain_path": "",
                "final_impact": "",
                "blockers": [],
                "proof_refs": [],
            },
            "manual_burp_replay": [
                "登录攻击者账号并进入订单详情页面。",
                "使用 Burp Suite 捕获 GET /api/order/detail 请求。",
                "将 order_id 修改为受害者订单 ID。",
                "重放请求后响应中返回受害者订单详情。",
            ],
            "poc": {
                "type": "curl",
                "file": "poc.sh",
                "description": "替换 Cookie 与 order_id 后可复现越权读取。",
            },
            "source_proof": None,
            "crypto_chain": None,
        }, ensure_ascii=False, indent=2))
        _write_text(reporting / "poc.sh", (
            "curl 'https://t.example/api/order/detail?order_id=1001' \\\n"
            "  -H 'Cookie: session=attacker_b' \\\n"
            "  -H 'Accept: application/json'\n"
        ))
        _write_text(reporting / "request_0.http", (
            "GET /api/order/detail?order_id=1001 HTTP/1.1\n"
            "Host: t.example\nCookie: session=owner_a\nAccept: application/json\n\n"
        ))
        _write_text(reporting / "response_0.http", (
            "HTTP/1.1 200 OK\nContent-Type: application/json\n\n"
            "{\"order_id\":\"1001\",\"owner\":\"owner_a\",\"address\":\"北京市海淀区示例路 1 号\",\"amount\":\"1299.00\"}\n"
        ))
        _write_text(reporting / "request_1.http", (
            "GET /api/order/detail?order_id=1001 HTTP/1.1\n"
            "Host: t.example\nCookie: session=attacker_b\nAccept: application/json\n\n"
        ))
        _write_text(reporting / "response_1.http", (
            "HTTP/1.1 200 OK\nContent-Type: application/json\n\n"
            "{\"order_id\":\"1001\",\"owner\":\"victim_a\",\"address\":\"北京市海淀区示例路 1 号\",\"amount\":\"1299.00\"}\n"
        ))
        _write_text(reporting / "request_denied.http", (
            "GET /api/order/detail?order_id=2002 HTTP/1.1\n"
            "Host: t.example\nCookie: session=attacker_b\nAccept: application/json\n\n"
        ))
        _write_text(reporting / "response_denied.http", (
            "HTTP/1.1 403 Forbidden\nContent-Type: application/json\n\n"
            "{\"error\":\"order owner required\"}\n"
        ))
        return recon, oracle, reporting

    # macOS exposes tempfile paths through the system `/var -> /private/var`
    # alias.  Canonicalize this trusted self-check boundary before exercising
    # the no-symlink authority writer.
    fixture_root = pathlib.Path(
        tempfile.mkdtemp(prefix="atoolkit-selfcheck-")).resolve()
    recon_dir, oracle_path, reporting_fixture = _make_self_check_fixtures(fixture_root)
    print("▶ self-check（临时 fixture，不接模型/网络）")

    failures: list[str] = []

    # 断言1：bootstrap(fixture) 覆盖 oracle 全部端点。
    # discovered_during_testing==true 的 case 是测试中发现的面，不期望在 bootstrap 种子里
    # （如 case-005 /api/orders/{id} 是 IDOR 报告中发现的具体端点，非 recon 产物），
    # 跳过这些 case，仅要求 bootstrap 覆盖剩余（种子）端点。
    def _assert1():
        surfaces = bootstrap(recon_dir)
        boot_eps = {s.get("endpoint", "") for s in surfaces}
        assert boot_eps, "bootstrap 未解析出任何端点（fixture 缺失/为空？）"
        oracle = be.load_oracle(oracle_path)
        exempt = [c for c in oracle if c.raw.get("discovered_during_testing")]
        exempt_ids = [c.id for c in exempt]
        checkable = [c for c in oracle if not c.raw.get("discovered_during_testing")]
        missing = [c.endpoint for c in checkable
                   if c.endpoint and c.endpoint not in boot_eps]
        assert not missing, (
            f"bootstrap 未覆盖 oracle 端点 {missing}；bootstrap 端点={sorted(boot_eps)}")
        note = (f"（豁免 {len(exempt)} 个 discovered_during_testing case：{exempt_ids}）"
                if exempt else "")
        print(f"  断言1 ✅ bootstrap 覆盖 oracle {len(checkable)}/{len(oracle)} 端点{note}：{sorted(boot_eps)}")

    # 断言2：浅阴性 ledger（非高价值、无 next_actions）→ session_gate incomplete。
    def _assert2():
        ledger = CoverageLedger(surfaces=[{
            "endpoint": "/api/search",
            "method": "GET", "param": "q", "feature": "search",
            "status": "shallow_negative",   # 非高价值、无 next_actions 的浅阴性格
        }])
        out = evaluate_session_gate(ledger)
        preds = [r.get("predicate") for r in out.get("reasons", [])]
        assert out["result"] == INCOMPLETE, (
            f"浅阴性格应判 incomplete，实得 {out['result']}")
        assert "shallow_negative_open" in preds, (
            f"应命中 shallow_negative_open 谓词，实得 {preds}")
        print(f"  断言2 ✅ 浅阴性格 → {out['result']}（命中 shallow_negative_open，演示 P0-2）")

    # 断言3：合格报告（target/curl/响应证据）→ Guardian accepted。
    def _assert3():
        report = (
            "---\nseverity: P1\ntitle: 订单详情越权读取\ntarget: https://t.example\n"
            "type: 越权/IDOR\n---\n"
            "换用 B 账号 Cookie 越权读取了 A 用户订单详情，提取了收货地址与金额。\n"
            "```\ncurl 'https://t.example/api/order/detail?order_no=1001' -H 'Cookie: B'\n"
            "HTTP/1.1 200 ... 返回了 A 的订单数据\n```\n" + "证据充分。" * 30)
        v = guardian_check(report, authorized_hosts=["t.example"])
        assert v.result == ACCEPTED, (
            f"合格报告应被 Guardian accepted，实得 {v.result}（L{v.level}: {v.reason}）")
        print(f"  断言3 ✅ 合格报告 → Guardian accepted（L{v.level}）")

    # 断言4：surface 内容嗅探 + wrapper + 变量一跳 + 相对路径 + body shorthand 参数。
    def _assert4():
        tmp = pathlib.Path(tempfile.mkdtemp()).resolve()
        (tmp / "bundle.asset").write_text(
            "const detailUrl = '../api/order/detail.php?order_no=1';\n"
            "fetch(detailUrl, { method: 'POST', body: JSON.stringify({ user_id, status }) });\n"
            "jsonPost('../../api/pay.php', { order_no, amount, status });\n"
            "api.post('../api/refund.php', { refund_amount, order_no });\n",
            encoding="utf-8",
        )
        surfaces = bootstrap(tmp)
        by_ep = {s["endpoint"]: s for s in surfaces}
        by_ep_method = {(s["endpoint"], s["method"]): s for s in surfaces}
        assert "/api/order/detail.php" in by_ep, f"变量 fetch 相对路径未抽出: {surfaces}"
        assert ("/api/pay.php", "POST") in by_ep_method, f"jsonPost 相对路径未抽出: {surfaces}"
        assert ("/api/refund.php", "POST") in by_ep_method, f"api.post 相对路径未抽出: {surfaces}"
        params = set(by_ep_method[("/api/pay.php", "POST")].get("params") or [])
        assert {"order_no", "amount", "status"} <= params, f"body shorthand 参数缺失: {params}"
        src = by_ep_method[("/api/pay.php", "POST")]
        assert src.get("source_file") and src.get("source_line") and src.get("source_kind"), \
            f"source_file/source_line/source_kind 缺失: {src}"
        print("  断言4 ✅ recon 解析 wrapper/变量/相对路径/body 参数/source 元数据")

    # 断言5：有 gate 未通过时 summary 不能写完成态。
    def _assert5():
        status = _summary_status({
            "status": "vuln_found",
            "accepted": ["P1"],
            "session_gate": {"result": "incomplete"},
        })
        assert status == "incomplete_with_findings", f"gate 未过的 summary.status 不应完成: {status}"
        print("  断言5 ✅ session_gate 未 pass 时 summary.status=incomplete_with_findings")

    # 断言6：benchmark_eval 能从 evidence request 提取 method/params。
    def _assert6():
        tmp = pathlib.Path(tempfile.mkdtemp()).resolve()
        (tmp / "evidence.json").write_text(json.dumps({
            "request": {
                "method": "POST",
                "url": "https://t.example/api/order/detail?order_no=1",
                "body": {"amount": 100, "status": "paid"},
            }
        }, ensure_ascii=False), encoding="utf-8")
        (tmp / "summary.json").write_text(json.dumps({
            "findings": [{
                "id": "f-1",
                "class": "交易篡改",
                "evidence_file": "evidence.json",
                "acceptance_status": "accepted",
                "proof_status": "confirmed",
                "claim_kind": "root_finding",
            }]
        }, ensure_ascii=False), encoding="utf-8")
        findings = be.load_findings(tmp / "summary.json", trust_legacy=True)
        assert findings and findings[0].methods == ["POST"], f"method 提取失败: {findings}"
        assert {"order_no", "amount", "status"} <= set(findings[0].params), \
            f"params 提取失败: {findings[0].params}"
        print("  断言6 ✅ benchmark 从 evidence request 提取 method/params")

    # 断言7：reporting basic IDOR fixture validate accepted，缺 response 时 rejected。
    def _assert7():
        from engine.reporting.schema import load_finding
        from engine.reporting.validate import validate_finding
        fixture = reporting_fixture
        finding = load_finding(fixture / "finding.json")
        ok = validate_finding(finding, fixture / "finding.json", fixture,
                              authorized_hosts=["t.example"])
        assert ok.ok, f"basic_idor 应 accepted: {ok.reasons}"
        tmp = pathlib.Path(tempfile.mkdtemp()).resolve()
        dst = tmp / "findings" / "finding_001"
        shutil.copytree(fixture, dst)
        (dst / "response_1.http").unlink()
        bad = load_finding(dst / "finding.json")
        rejected = validate_finding(bad, dst / "finding.json", tmp,
                                    authorized_hosts=["t.example"])
        assert not rejected.ok and any("response_file" in r for r in rejected.reasons), \
            f"缺 response 应 rejected: {rejected.reasons}"
        shutil.rmtree(tmp)
        tmp = pathlib.Path(tempfile.mkdtemp()).resolve()
        dst = tmp / "findings" / "finding_001"
        shutil.copytree(fixture, dst)
        escaped = load_finding(dst / "finding.json")
        escaped["poc"]["file"] = "../../../outside.sh"
        escape_res = validate_finding(escaped, dst / "finding.json", tmp,
                                      authorized_hosts=["t.example"])
        assert not escape_res.ok and any("escapes run directory" in r for r in escape_res.reasons), \
            f"路径逃逸应 rejected: {escape_res.reasons}"
        print("  断言7 ✅ reporting validate accepted/rejected/path-escape")

    # 断言8：collect/render/normalized mapping + Verify finding PoC helper。
    def _assert8():
        from engine.reporting.collect import collect_structured_findings
        from engine.reporting.render_md import render_final_report
        fixture = reporting_fixture
        tmp = pathlib.Path(tempfile.mkdtemp()).resolve()
        dst = tmp / "findings" / "finding_001"
        shutil.copytree(fixture, dst)
        collected = collect_structured_findings(tmp, authorized_hosts=["t.example"])
        assert len(collected["accepted"]) == 1, collected
        nf = collected["normalized"][0]
        assert nf["methods"] == ["GET"], nf
        assert "order_id" in nf["params"], nf
        assert nf["evidence_file"] == "findings/finding_001/finding.json", nf
        report_path = render_final_report(collected["accepted"], tmp / "final_report.md", "t.example")
        report = report_path.read_text(encoding="utf-8")
        assert report.startswith("# t.example 授权安全测试报告\n\n## 1. 漏洞名称"), report[:120]
        assert "### 安全风险" in report and "### 漏洞证明" in report, report
        req = extract_poc_from_finding(collected["accepted"][0]["finding"], dst)
        assert req and req.method == "GET" and "order_id=1001" in req.url, req
        print("  断言8 ✅ collect/render/normalized/verify helper")

    # 断言9：_conclude 等价闭环写 final_report_path，gate 未过时 draft_incomplete。
    def _assert9():
        from engine.orchestrator import CognitiveState, harvest_evidence, _conclude
        fixture = reporting_fixture
        tmp = pathlib.Path(tempfile.mkdtemp()).resolve()
        dst = tmp / "findings" / "finding_001"
        shutil.copytree(fixture, dst)
        state = CognitiveState(sid="selfcheck", target="https://t.example")
        state.seed_matrix(["/api/order/detail"])
        evidence = harvest_evidence(tmp, authorized_hosts=["t.example"])
        state.update("", evidence, maintain_matrix=True)
        out = _conclude("VULN_FOUND", evidence, tmp, state, ["t.example"], 1)
        assert out["structured_findings"]["accepted"] == 1, out
        assert out["final_report_status"] == "draft_incomplete", out
        assert out["final_report_path"] and pathlib.Path(out["final_report_path"]).exists(), out
        summary = {
            "findings": _summary_findings(out),
            "final_report_path": out.get("final_report_path"),
            "final_report_status": out.get("final_report_status"),
            "structured_findings": out.get("structured_findings"),
        }
        (tmp / "summary.json").write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")
        loaded = json.loads((tmp / "summary.json").read_text(encoding="utf-8"))
        assert loaded["final_report_path"] and loaded["final_report_status"] == "draft_incomplete", loaded
        print("  断言9 ✅ _conclude structured finding → draft final_report + summary fields")

    # ── v6.1 §10.4: 6 条新断言（候选台账 / depth floor / 再探测 / proof 保底 / 缺口附录）──
    def _assert10():
        """MockAdapter DIM/CANDIDATE → candidate-ledger.json + surface.candidate_count 回填。"""
        from engine.candidate import CandidateLedger
        from engine.ledger import CoverageLedger
        from engine.knowledge import load_cards
        import tempfile
        cards = load_cards()
        tmp = pathlib.Path(tempfile.mkdtemp()).resolve()
        cl = CandidateLedger()
        dim_text = (
            "DIM: object-ownership | CANDIDATE: 换 attacker 读取他人订单 | need:owner建单+attacker改单号 | P1 | probe:三步越权\n"
            "DIM: auth-flow-abuse | NONE: 非认证端点\n")
        surface = {"endpoint": "/api/orders/{id}", "method": "GET", "param": "id",
                   "risk_tags": ["object-ownership", "idor"], "feature": "order"}
        ledger = CoverageLedger(surfaces=[surface])
        sid = ledger.surfaces[0]["surface_id"]
        sctx = {"surface_id": sid, "endpoint": "/api/orders/{id}", "method": "GET",
                "param": "id", "depth_floor": 3}
        def _link(sid_, status, depth_score):
            ledger.link_candidate(sid_, status=status, depth_score=depth_score)
        cl.apply(dim_text, turn=0, cards=cards, surface_ctx=sctx, link_callback=_link)
        cl.save(tmp / "candidate-ledger.json")
        # candidate-ledger.json exists with candidates
        assert (tmp / "candidate-ledger.json").exists(), "candidate-ledger.json should exist"
        loaded = CandidateLedger.load(tmp / "candidate-ledger.json")
        active = [c for c in loaded.candidates if c.get("status") != "duplicate"]
        assert len(active) >= 1, f"should have ≥1 active candidate, got {active}"
        # surface.candidate_count backfilled
        surf = ledger.get(sid)
        assert surf and surf.get("candidate_count", 0) >= 1, \
            f"surface candidate_count should be ≥1, got {surf.get('candidate_count') if surf else 'None'}"
        print(f"  断言10 ✅ DIM→candidate-ledger.json({len(active)}候选) + surface.candidate_count={surf['candidate_count']}")

    def _assert11():
        """depth_score < depth_floor → TRIAGE proof_ready 被外壳拒（退回 triaging）。"""
        from engine.candidate import CandidateLedger, PROPOSED, TRIAGING
        from engine.knowledge import load_cards
        cards = load_cards()
        cl = CandidateLedger()
        dim_text = "DIM: object-ownership | CANDIDATE: 越权读他人订单 | P1 | probe:换id\n"
        sctx = {"surface_id": "GET /api/orders/{id} id [user] {object-ownership,idor}",
                "endpoint": "/api/orders/{id}", "method": "GET", "param": "id", "depth_floor": 3}
        cl.apply(dim_text, turn=0, cards=cards, surface_ctx=sctx)
        cid = [c for c in cl.candidates if c.get("status") == PROPOSED][0]["candidate_id"]
        # TRIAGE proof_ready with depth_score=0 → should be rejected
        cl.apply(f"TRIAGE: {cid} | proof_ready | 测试 | evidence.md | ", turn=1, cards=cards)
        cand = cl.get(cid)
        assert cand["status"] == TRIAGING, \
            f"depth_score=0 proof_ready should be rejected→triaging, got {cand['status']}"
        # Now give depth and retry → should pass
        cand["vectors"] = ["v1", "v2", "v3"]
        cand["roles_tested"] = ["owner", "attacker"]
        cand["evidence_refs"] = ["evidence.md"]
        cl.apply(f"TRIAGE: {cid} | proof_ready | 充分 | evidence.md | ", turn=2, cards=cards)
        cand = cl.get(cid)
        assert cand["status"] == "proof_ready", \
            f"depth met proof_ready should pass, got {cand['status']} (score={cand['depth_score']})"
        print(f"  断言11 ✅ depth_floor gate: depth=0→rejected(triaging), depth={cand['depth_score']}→proof_ready")

    def _assert12():
        """阴性 surface 闭环校验不达 floor → 降级 not_tested + negative_depth_not_checked。"""
        from engine.ledger import CoverageLedger
        from engine.session_gate import evaluate_session_gate
        from engine.knowledge import load_cards
        cards = load_cards()
        # not_vulnerable surface with insufficient negative evidence, not checked
        ledger = CoverageLedger(surfaces=[{
            "endpoint": "/api/search", "method": "GET", "param": "q",
            "feature": "search", "status": "not_vulnerable",
            "negative_depth_checked": False,
            "negative": {"vectors": ["baseline"], "response_count": 0},
        }])
        out = evaluate_session_gate(ledger, candidates=[], finding_candidate_ids=set())
        preds = [r.get("predicate") for r in out.get("reasons", [])]
        assert "negative_depth_not_checked" in preds, \
            f"expect negative_depth_not_checked, got {preds}"
        assert out["result"] == "incomplete", f"expect incomplete, got {out['result']}"
        print(f"  断言12 ✅ not_vulnerable + unchecked → negative_depth_not_checked + incomplete")

    def _assert13():
        """reprobe_triggers 命中（新角色到账）→ refuted 候选重开。"""
        from engine.candidate import CandidateLedger, REFUTED, PROPOSED
        cl = CandidateLedger()
        # Create a refuted candidate with new_role trigger
        cl.candidates.append({
            "candidate_id": "cand_001", "surface_id": "x", "endpoint": "/api/admin",
            "status": REFUTED, "depth_score": 0, "depth_floor": 2,
            "reprobe_triggers": [{"type": "new_role", "reason": "需 admin 角色"}],
            "hypothesis": "admin 越权", "vectors": [], "roles_tested": [],
            "objects_tested": [], "evidence_refs": [],
        })
        # Scan with new_roles=["admin"] → should reopen
        hits = cl.reprobe_scan(new_roles=["admin"])
        assert hits, f"reprobe_scan should find a hit, got {hits}"
        cand = cl.get("cand_001")
        assert cand["status"] == PROPOSED, \
            f"refuted candidate should reopen to proposed, got {cand['status']}"
        print(f"  断言13 ✅ reprobe: new_role=admin → refuted→proposed (reopened)")

    def _assert14():
        """proof_ready 候选在工作队列中永远最前（§5 保底）。"""
        from engine.candidate import top_work_queue, PROOF_READY, PROPOSED, TRIAGING
        cands = [
            {"candidate_id": "c1", "status": PROPOSED, "endpoint": "/api/a",
             "depth_score": 0, "depth_floor": 1, "hypothesis": "low value"},
            {"candidate_id": "c2", "status": PROOF_READY, "endpoint": "/api/b",
             "depth_score": 3, "depth_floor": 3, "hypothesis": "ready to prove"},
            {"candidate_id": "c3", "status": TRIAGING, "endpoint": "/api/c",
             "depth_score": 1, "depth_floor": 3, "hypothesis": "still probing"},
        ]
        top = top_work_queue(cands, n=3)
        assert top[0]["candidate_id"] == "c2", \
            f"proof_ready should be first, got {top[0]['candidate_id']}"
        print(f"  断言14 ✅ work_queue: proof_ready(c2) first → {[c['candidate_id'] for c in top]}")

    def _assert15():
        """proof_ready 无 finding → 终态 incomplete + 四类缺口附录④非空。"""
        from engine.candidate import CandidateLedger, compute_coverage_gaps, coverage_gaps_nonempty
        from engine.orchestrator import CognitiveState, _conclude, harvest_evidence
        import tempfile
        tmp = pathlib.Path(tempfile.mkdtemp()).resolve()
        cl = CandidateLedger(candidates=[{
            "candidate_id": "cand_001", "surface_id": "GET /api/x id [user] {object-ownership,idor}",
            "endpoint": "/api/x", "method": "GET", "status": "proof_ready",
            "depth_score": 3, "depth_floor": 3, "hypothesis": "IDOR",
            "vectors": ["v1","v2","v3"], "roles_tested": ["owner","attacker"],
            "evidence_refs": ["ev.md"], "root_cause": None,
        }])
        state = CognitiveState(sid="selfcheck15", target="https://t.example")
        state.seed_matrix(["/api/x"])
        evidence = harvest_evidence(tmp, authorized_hosts=["t.example"])
        out = _conclude("LOW_ROI", evidence, tmp, state, ["t.example"], 1,
                        candidate_ledger=cl, cards=__import__('engine.knowledge', fromlist=['load_cards']).load_cards())
        # proof_ready without finding → incomplete
        assert out["status"] == "incomplete", \
            f"proof_ready without finding → incomplete, got {out['status']}"
        # coverage_gaps ④ non-empty
        gaps = out.get("coverage_gaps", {})
        assert gaps.get("proof_ready_without_finding"), \
            f"gaps④ should be non-empty, got {gaps.get('proof_ready_without_finding')}"
        assert out.get("coverage_gaps_nonempty"), "coverage_gaps_nonempty should be True"
        print(f"  断言15 ✅ proof_ready无finding → incomplete + gaps④={len(gaps.get('proof_ready_without_finding',[]))}条")

    def _assert16():
        """v6.2 loop phase 注入与 events.jsonl 记录生效。"""
        import tempfile
        from engine.orchestrator import run_session

        class PhaseAdapter:
            name = "phase"
            def run(self, prompt, *, session_id):
                assert "## Loop 编排器" in prompt, "正式覆盖跑 prompt 应注入 Loop 编排器"
                assert "phase: recall" in prompt, "无候选首轮应进入 recall phase"
                yield "DIM: input-validation | NONE: 本轮无候选\nLOW_ROI\n"

        tmp = pathlib.Path(tempfile.mkdtemp()).resolve() / "runs" / "sess-phase"
        tmp.mkdir(parents=True)
        out = run_session(
            PhaseAdapter(),
            target="https://t.example",
            authz="仅限 https://t.example，已授权。",
            core_skill="self-check",
            workdir=str(tmp),
            authorized_hosts=["t.example"],
            max_turns=1,
            endpoints=[{"endpoint": "/api/search", "params": ["keyword"]}],
            vuln_classes=["SQLi"],
            verbose=False,
        )
        events = [json.loads(line) for line in (tmp / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        start = next(e for e in events if e.get("ev") == "start")
        turn = next(e for e in events if e.get("ev") == "turn")
        assert start.get("loop", {}).get("mode") == "recall-first", start
        assert turn.get("loop_phase") == "recall", turn
        assert out.get("coverage_ledger_path") and pathlib.Path(out["coverage_ledger_path"]).exists(), out
        print("  断言16 ✅ v6.2 loop phase: prompt 注入 + events.jsonl loop_phase=recall")

    def _assert17():
        """run.py score 只读赛后产物并写 scorecard.json/md。"""
        import tempfile
        tmp = pathlib.Path(tempfile.mkdtemp()).resolve() / "runs" / "sess-score"
        tmp.mkdir(parents=True)
        oracle = tmp / "oracle.json"
        oracle.write_text(json.dumps([{
            "id": "case-001", "endpoint": "/api/order/detail", "method": "GET",
            "params": ["order_no"], "class": "越权/IDOR", "score": 160, "roles": [],
        }], ensure_ascii=False), encoding="utf-8")
        (tmp / "evidence.json").write_text(json.dumps({
            "request": {
                "method": "GET",
                "url": "https://t.example/api/order/detail?order_no=1001",
            }
        }, ensure_ascii=False), encoding="utf-8")
        (tmp / "summary.json").write_text(json.dumps({
            "findings": [{
                "id": "finding_001",
                "endpoint": "/api/order/detail",
                "class": "越权/IDOR",
                "evidence_file": "evidence.json",
                "acceptance_status": "accepted",
                "proof_status": "confirmed",
                "claim_kind": "root_finding",
            }]
        }, ensure_ascii=False), encoding="utf-8")
        (tmp / "coverage-ledger.json").write_text(json.dumps({
            "schema_version": 1,
            "surfaces": [{
                "surface_id": "GET /api/order/detail order_no [user] {object-ownership,idor}",
                "endpoint": "/api/order/detail",
                "method": "GET",
                "param": "order_no",
                "roles": ["user"],
                "risk_tags": ["object-ownership", "idor"],
                "status": "confirmed",
            }]
        }, ensure_ascii=False), encoding="utf-8")
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            rc = _score_run(["--run-dir", str(tmp), "--oracle", str(oracle),
                             "--compact", "--trust-legacy"])
        assert rc == 0
        scorecard = json.loads((tmp / "scorecard.json").read_text(encoding="utf-8"))
        assert scorecard["meta"]["oracle_used_post_run_only"] is True
        assert len(scorecard["hits"]) == 1 and scorecard["total_score"] == 160
        assert (tmp / "scorecard.md").exists()
        print("  断言17 ✅ score: 离线评分写 scorecard.json/md 且 oracle_used_post_run_only=true")

    # 断言18：Fact-Intent 管道完整性（v8.5.1 P0 修复验证）。
    def _assert18():
        from engine.graph import FactIntentGraph
        from engine.vuln_classes import norm_vc, vc_matches, is_chainable
        g = FactIntentGraph()
        # 18a: Intent status 必须被设置
        fact, intents = g.add_fact({
            "source_type": "confirmed", "endpoint": "/api/test",
            "vuln_class": "ssrf", "summary": "SSRF test", "params": ["url"],
        })
        assert all("status" in i for i in g.intents), "intent 缺少 status 键"
        assert all(i["status"] == "pending" for i in g.intents), "status 不是 pending"
        pending = g.get_pending_intents(limit=10)
        assert len(pending) == len(intents), (
            f"get_pending_intents 返回 {len(pending)}，应有 {len(intents)}")
        # 18b: stored-xss 必须触发兜底规则（不再 zero-trigger）
        g2 = FactIntentGraph()
        _, i2 = g2.add_fact({
            "source_type": "confirmed", "endpoint": "/api/field",
            "vuln_class": "stored-xss", "params": ["name"], "summary": "XSS",
        })
        assert len(i2) >= 1, "stored-xss 零触发（兜底规则失效）"
        # 18c: norm_vc 归一化正确
        assert norm_vc("越权") == "idor", f"norm_vc(越权)={norm_vc('越权')}"
        assert norm_vc("stored-xss") == "xss"
        assert vc_matches("privilege-escalation", "idor")
        assert is_chainable("auth-bypass")
        assert not is_chainable("xss")
        # 18d: stats 不掩盖假阳性
        stats = g.stats()
        assert stats["high_priority_pending"] == sum(
            1 for i in g.intents
            if i.get("priority") == "high" and i.get("status") == "pending"
        ), "stats high_priority_pending 与实际不一致"
        print("  断言18 ✅ Fact-Intent 管道完整性（status/兜底/norm_vc/stats）")

    def _assert19():
        """v8.5.2: resolve_intent 生命周期 + fact_from_candidate 归一化"""
        from engine.graph import FactIntentGraph
        from engine.vuln_classes import norm_vc
        # 19a: fact_from_candidate normalizes vuln_class
        g = FactIntentGraph()
        cand = {"candidate_id": "c1", "endpoint": "/api/test",
                "vuln_class": "越权访问", "hypothesis": "test", "param": "id"}
        fact_data = g.fact_from_candidate(cand, fact_type="confirmed")
        assert fact_data["vuln_class"] == norm_vc("越权访问"), (
            f"fact_from_candidate 未归一化: {fact_data['vuln_class']} != {norm_vc('越权访问')}")
        assert fact_data["vuln_class"] == "idor", f"norm_vc(越权访问)={fact_data['vuln_class']}"
        # 19b: resolve_intent transitions work
        fact, intents = g.add_fact({
            "source_type": "confirmed", "endpoint": "/api/refund",
            "vuln_class": "amount-tamper", "summary": "退款无上限", "params": ["amount"],
            "chain_feasible": True,
        })
        assert len(intents) >= 1, "应生成至少1个intent"
        first_id = intents[0]["intent_id"]
        assert intents[0]["status"] == "pending", "新intent应为pending"
        # resolve as completed
        resolved = g.resolve_intent(first_id, "completed",
                                     summary="产出1个新发现", spawned_facts=["fact_002"])
        assert resolved is not None, "resolve_intent 应返回已更新的intent"
        assert resolved["status"] == "completed", f"status应为completed: {resolved['status']}"
        assert resolved["spawned_facts"] == ["fact_002"], "spawned_facts 未正确存储"
        assert resolved["resolved_at"], "resolved_at 应被设置"
        # get_pending_intents should exclude resolved
        pending = g.get_pending_intents(limit=10)
        assert all(i["intent_id"] != first_id for i in pending), (
            "已completed的intent不应出现在pending列表中")
        # 19c: deferred status also works
        if len(intents) >= 2:
            second_id = intents[1]["intent_id"]
            g.resolve_intent(second_id, "deferred", summary="3次无结果")
            deferred_intent = next(i for i in g.intents if i["intent_id"] == second_id)
            assert deferred_intent["status"] == "deferred", "deferred状态未正确设置"
        # 19d: stats reflect resolved intents
        stats = g.stats()
        assert "completed" in stats["intents_by_status"], "stats应包含completed状态"
        print("  断言19 ✅ Intent生命周期（resolve/归一化/pending过滤）")

    def _assert20():
        """v8.6: build_from_inventory 正确处理 dict inventory（无 'GET ' 空路径 bug）"""
        from engine.business_graph import BusinessGraph
        bg = BusinessGraph()
        # Simulate real recon inventory: dicts with 'endpoint' but no 'path'
        inv = [
            {"endpoint": "/api/user/login", "method": "POST"},
            {"endpoint": "/api/orders", "method": "GET"},
            {"endpoint": "/api/refund", "method": "POST"},
        ]
        bg.build_from_inventory(inv)
        for key in bg.endpoint_map:
            assert not key.endswith(" "), (
                f"build_from_inventory 产生空路径 key={key!r}，dict inventory 的 'endpoint' 未被正确解析")
            assert "/" in key, f"endpoint_map key={key!r} 不含路径，inventory 解析失败"
        assert "POST /api/refund" in bg.endpoint_map, "POST /api/refund 应在 endpoint_map 中"
        print("  断言20 ✅ build_from_inventory dict inventory 解析正确（无空路径）")

    def _assert21():
        """v8.6: _parse_negative 输出 vectors_tried 和 depth_sufficient"""
        from engine.orchestrator import _parse_negative
        # 深度阴性：3+ vectors + response evidence
        deep_txt = ("endpoint: /api/search\nvuln: SQLi\n"
                    "reason: 多向量测试无注入\n"
                    "vectors: time-based, boolean, error-based\n"
                    "evidence_types: response_diff\n\n"
                    "curl ... HTTP/1.1 200\n响应无差异")
        deep = _parse_negative(deep_txt, "negative_deep.md")
        assert "vectors_tried" in deep, "depth阴性缺少 vectors_tried 字段"
        assert "depth_sufficient" in deep, "depth阴性缺少 depth_sufficient 字段"
        assert deep["vectors_tried"] >= 3, f"vectors_tried={deep['vectors_tried']} 应>=3"
        assert deep["depth_sufficient"] is True, "3向量+response 应为 depth_sufficient=True"
        # 浅阴性：1 vector, 0 response
        thin_txt = "endpoint: /api/user\nvuln: XSS\nreason: 仅测了反射\nvectors: reflect\n\n简单测试"
        thin = _parse_negative(thin_txt, "negative_thin.md")
        assert thin["vectors_tried"] <= 2, f"浅阴性 vectors_tried={thin['vectors_tried']} 应<=2"
        assert thin["depth_sufficient"] is False, "1向量0响应 应为 depth_sufficient=False"
        print("  断言21 ✅ _parse_negative vectors_tried/depth_sufficient 输出正确")

    def _assert22():
        """rc3: canonical_surface_key helper 统一归一所有输入形态"""
        from engine.surface_key import canonical_surface_key, is_canonical, canonical_cell_key
        expected = "GET /api/refund"
        forms = [
            "/api/refund",
            "GET /api/refund",
            {"endpoint": "/api/refund", "method": "GET"},
            {"endpoint": "GET /api/refund"},
            {"path": "/api/refund", "method": "POST"},   # POST variant
            {"url": "https://t.example/api/refund", "method": "GET"},
            {"method": "POST", "path": "/api/refund", "endpoint": "POST /api/refund"},
        ]
        for f in forms:
            ck = canonical_surface_key(f)
            assert ck, f"canonical_surface_key({f!r}) 返回空"
        # The first 5 forms (excluding POST variants) should produce GET /api/refund
        assert canonical_surface_key(forms[0]) == expected, f"裸路径未归一: {canonical_surface_key(forms[0])}"
        assert canonical_surface_key(forms[1]) == expected, f"METHOD /path 未保持: {canonical_surface_key(forms[1])}"
        assert canonical_surface_key(forms[2]) == expected, f"dict+method 未归一: {canonical_surface_key(forms[2])}"
        assert canonical_surface_key(forms[3]) == expected, f"dict endpoint含method 未剥前缀: {canonical_surface_key(forms[3])}"
        assert canonical_surface_key(forms[4]) == "POST /api/refund", f"dict path+method=POST 未归一: {canonical_surface_key(forms[4])}"
        assert canonical_surface_key(forms[5]) == expected, f"url+method 未剥host: {canonical_surface_key(forms[5])}"
        assert canonical_surface_key(forms[6]) == "POST /api/refund", (
            f"dict 同时含 method+endpoint(含method) 双重method: {canonical_surface_key(forms[6])}")
        # is_canonical
        assert is_canonical("GET /api/refund"), "is_canonical 应接受 GET /api/refund"
        assert not is_canonical("/api/refund"), "is_canonical 应拒绝裸路径"
        assert not is_canonical(""), "is_canonical 应拒绝空串"
        # canonical_cell_key
        ck = canonical_cell_key("GET /api/refund", "业务逻辑")
        assert ck == "GET /api/refund × 业务逻辑", f"canonical_cell_key 错误: {ck}"
        print("  断言22 ✅ canonical_surface_key 统一归一（6种输入形态 + is_canonical + cell_key）")

    # ── rc3 端到端 dry-run fixture（断言23-29 共用） ──────────────────────
    def _run_budget_dryrun(fixture_dir: pathlib.Path) -> dict:
        """跑一个最小 dry-run session，surface_budget=1, intent_budget=2。
        返回 run_session 结果 dict + 落盘路径，供断言23-29 校验真实产物。"""
        from engine.orchestrator import run_session, MockAdapter
        import tempfile
        _proj = fixture_dir / "budget_proj"
        _proj.mkdir(parents=True, exist_ok=True)
        _wd = _proj / "sessions" / "run1"
        _wd.mkdir(parents=True, exist_ok=True)
        res = run_session(
            MockAdapter(_wd),
            target="https://t.example",
            authz="仅限 https://t.example，已授权。",
            core_skill="（测试占位技能文件）",
            workdir=str(_wd),
            authorized_hosts=["t.example"],
            max_turns=20,
            endpoints=["/api/user/login", "/api/refund"],
            target_domains=["auth", "txn"],
            surface_budget=1,
            intent_budget=2,
            verbose=False,
        )
        return res

    def _assert23():
        """v8.6.1 端到端: surface_budget 限制 METHOD/path Surface。"""
        import tempfile
        _fdir = pathlib.Path(tempfile.mkdtemp(prefix="selfcheck_rc3_")).resolve()
        try:
            res = _run_budget_dryrun(_fdir)
            sched = res.get("scheduler_stats", {})
            assert sched.get("budget_unit") == "surface", (
                f"budget_unit 应为 surface，实得 {sched.get('budget_unit')}")
            assert sched.get("must_test_count") == 1, sched
            _accepted = sched.get("accepted_updates", 0)
            _ignored = sched.get("ignored_by_budget", 0)
            _closed_cells = [c for c in (res.get("state", {}).get("matrix", {}) or {}).values()
                             if c.get("state") != "untested"]
            _closed_surfaces = {
                f"{c.get('method', 'GET')} {c.get('endpoint', '')}" for c in _closed_cells
            }
            assert len(_closed_surfaces) <= 1, _closed_surfaces
            print(f"  断言23 ✅ surface_budget=1 真实限制 "
                  f"(accepted={_accepted}, ignored={_ignored}, surfaces={_closed_surfaces})")
        finally:
            import shutil
            shutil.rmtree(_fdir, ignore_errors=True)

    def _assert24():
        """rc3 端到端: intent_budget 限制 claim/prompt intent 数"""
        import tempfile, json
        from engine.scheduler import compute_run_scope
        # 构造含多个 pending high-priority intent 的 blackboard
        bb = {"facts": [], "negatives": [], "discovered_endpoints": [],
              "intents": [
                  {"intent_id": "i1", "status": "pending", "priority": "high"},
                  {"intent_id": "i2", "status": "pending", "priority": "high"},
                  {"intent_id": "i3", "status": "pending", "priority": "high"},
                  {"intent_id": "i4", "status": "pending", "priority": "high"},
              ]}
        bg = {"endpoint_map": {"GET /api/refund": {"domains": ["txn"], "value": "high"}}}
        scope = compute_run_scope(bb, bg, ["GET /api/refund"], ["txn"],
                                  surface_budget=10, intent_budget=2)
        carryover = scope.get("carryover_intents", [])
        assert len(carryover) <= 2, (
            f"carryover_intents={len(carryover)} 超过 intent_budget=2")
        print(f"  断言24 ✅ intent_budget=2 限制 carryover_intents={len(carryover)} ≤ 2")

    def _assert25():
        """v8.8 端到端: 精确角色深阴性 run2 继承 not_vulnerable"""
        import tempfile, json
        from engine.orchestrator import NEGATIVE_WITH_EVIDENCE, run_session, MockAdapter
        from engine.project_state import ProjectStateStore
        _fdir = pathlib.Path(tempfile.mkdtemp(prefix="selfcheck_deep_")).resolve()
        try:
            _proj = _fdir / "deep_proj"
            _proj.mkdir(parents=True, exist_ok=True)
            _neg_dir = _proj / "sessions" / "run1"
            _neg_dir.mkdir(parents=True, exist_ok=True)
            (_neg_dir / "neg.md").write_text("depth evidence", encoding="utf-8")
            ProjectStateStore(
                _proj, project_scope=["https://t.example"]
            ).commit_run(
                "run1",
                inventory=[{
                    "asset": "https://t.example", "endpoint": "/api/search",
                    "method": "GET", "roles": ["user"],
                }],
                negatives=[{
                    "asset": "https://t.example", "endpoint": "/api/search",
                    "method": "GET", "role_scope": "user",
                    "vuln_class": "SQLi", "vectors_tried": 5,
                    "depth_sufficient": True, "evidence_refs": ["neg.md"],
                }],
            )
            _wd = _proj / "sessions" / "run2"
            _wd.mkdir(parents=True, exist_ok=True)
            res = run_session(
                MockAdapter(_wd),
                target="https://t.example",
                authz="授权",
                core_skill="占位",
                workdir=str(_wd),
                authorized_hosts=["t.example"],
                max_turns=3,
                endpoints=[{"endpoint": "/api/search", "method": "GET",
                            "roles": ["user"]}],
                vuln_classes=["SQLi"],
                surface_budget=0,  # 不限预算，测继承
                verbose=False,
            )
            # 精确角色深阴性应在 run2 继承为 negative_with_evidence。
            mtx = res.get("state", {}).get("matrix", {})
            _found_skip = any(
                c.get("state") == NEGATIVE_WITH_EVIDENCE for c in mtx.values()
                if "search" in c.get("endpoint", ""))
            assert _found_skip, (
                "精确角色深阴性 negative 在 run2 未继承为 not_vulnerable")
            print("  断言25 ✅ 精确角色深阴性 run2 继承 not_vulnerable")
        finally:
            import shutil
            shutil.rmtree(_fdir, ignore_errors=True)

    def _assert26():
        """rc3 端到端: 浅阴性 run2 保持 open（不被深阴性误继承为 skip）"""
        import tempfile, json
        from engine.orchestrator import SKIPPED, run_session, MockAdapter
        _fdir = pathlib.Path(tempfile.mkdtemp(prefix="selfcheck_shallow_")).resolve()
        try:
            _proj = _fdir / "shallow_proj"
            _proj.mkdir(parents=True, exist_ok=True)
            bb_data = {
                "schema_version": "2.0",
                "facts": [], "intents": [], "dead_ends": [],
                "negatives": [{
                    "endpoint": "/api/user", "method": "GET",
                    "vuln_class": "XSS", "surface_key": "/api/user::XSS",
                    "vectors_tried": 1, "depth_sufficient": False,
                    "file": "neg_thin.md",
                }],
                "discovered_endpoints": [],
            }
            (_proj / "blackboard.json").write_text(
                json.dumps(bb_data, ensure_ascii=False), encoding="utf-8")
            _wd = _proj / "sessions" / "run2"
            _wd.mkdir(parents=True, exist_ok=True)
            res = run_session(
                MockAdapter(_wd),
                target="https://t.example",
                authz="授权",
                core_skill="占位",
                workdir=str(_wd),
                authorized_hosts=["t.example"],
                max_turns=1,   # 避免 MockAdapter 批量 SKIP 干扰继承验证
                endpoints=["/api/user"],
                surface_budget=0,
                verbose=False,
            )
            # 浅阴性 (depth_sufficient=False) 不应被继承为 SKIPPED — 它应保持
            # open (untested 或 shallow_negative)，带 next_actions 等待深测。
            mtx = res.get("state", {}).get("matrix", {})
            _user_cells = [c for c in mtx.values()
                           if "user" in c.get("endpoint", "")]
            assert _user_cells, "run2 未 seed /api/user 矩阵格"
            _skipped = [c for c in _user_cells if c.get("state") == SKIPPED]
            assert not _skipped, (
                f"浅阴性被误继承为 SKIPPED: {[c['endpoint'] for c in _skipped]}")
            # 至少有一个格应保持 open (untested/shallow_negative)
            _open = [c for c in _user_cells
                     if c.get("state") in ("untested", "shallow_negative")]
            assert _open, (
                f"浅阴性格未保持 open: states={[c.get('state') for c in _user_cells]}")
            print("  断言26 ✅ 浅阴性 run2 保持 open（不被误继承为 skip）")
        finally:
            import shutil
            shutil.rmtree(_fdir, ignore_errors=True)

    def _assert27():
        """rc3: completed/abandoned/superseded intent 不 reappear in pending"""
        from engine.graph import FactIntentGraph
        g = FactIntentGraph()
        # 添加一个 fact 触发 intent 生成
        fact, intents = g.add_fact({
            "source_type": "confirmed", "endpoint": "/api/test",
            "vuln_class": "idor", "summary": "test vuln",
        })
        assert len(intents) >= 1, "应生成至少1个intent"
        first_id = intents[0]["intent_id"]
        # resolve as completed
        g.resolve_intent(first_id, "completed", summary="done")
        # pending 列表不应含已 completed 的 intent
        pending = g.get_pending_intents(limit=10)
        assert all(i["intent_id"] != first_id for i in pending), (
            "已 completed 的 intent 不应出现在 pending 列表中")
        # 测试 abandoned 和 superseded
        if len(intents) >= 2:
            second_id = intents[1]["intent_id"]
            g.resolve_intent(second_id, "abandoned", summary="no value")
            pending2 = g.get_pending_intents(limit=10)
            assert all(i["intent_id"] != second_id for i in pending2), (
                "已 abandoned 的 intent 不应出现在 pending 列表中")
        if len(intents) >= 3:
            third_id = intents[2]["intent_id"]
            g.resolve_intent(third_id, "superseded", summary="replaced")
            pending3 = g.get_pending_intents(limit=10)
            assert all(i["intent_id"] != third_id for i in pending3), (
                "已 superseded 的 intent 不应出现在 pending 列表中")
        print("  断言27 ✅ completed/abandoned/superseded intent 不 reappear")

    def _assert28():
        """rc3 端到端: summary 有 domains_covered、无 domains_coveraged、
        含 business_graph_open_high_value、scheduler_stats 非空"""
        import tempfile, json
        _fdir = pathlib.Path(tempfile.mkdtemp(prefix="selfcheck_summary_")).resolve()
        try:
            res = _run_budget_dryrun(_fdir)
            _bad = "domains_cover" + "aged"  # avoid self-match
            # domains_covered
            assert res.get("domains_covered") is not None, "summary 缺 domains_covered"
            # no misspelled variant in output keys
            assert _bad not in res, f"summary 含拼写错误 {_bad}"
            # business_graph_open_high_value
            bg_open = res.get("business_graph_open_high_value")
            assert bg_open is not None, "summary 缺 business_graph_open_high_value"
            # scheduler_stats non-empty
            sched = res.get("scheduler_stats", {})
            assert sched, "scheduler_stats 为空"
            assert sched.get("budget_unit") == "surface", (
                f"scheduler_stats.budget_unit 错误: {sched.get('budget_unit')}")
            print(f"  断言28 ✅ summary 有 domains_covered + business_graph_open_high_value "
                  f"({len(bg_open)} 项) + scheduler_stats 非空 + 无拼写错误")
        finally:
            import shutil
            shutil.rmtree(_fdir, ignore_errors=True)

    def _assert29():
        """Finalizer projections exist without promoting incomplete graph truth."""
        import tempfile, json, pathlib as _p
        from engine.orchestrator import run_session, MockAdapter
        _fdir = _p.Path(tempfile.mkdtemp(prefix="selfcheck_auth_")).resolve()
        try:
            _proj = _fdir / "auth_proj"
            _proj.mkdir(parents=True, exist_ok=True)
            _wd = _proj / "sessions" / "run1"
            _wd.mkdir(parents=True, exist_ok=True)
            res = run_session(
                MockAdapter(_wd),
                target="https://t.example", authz="授权",
                core_skill="占位", workdir=str(_wd),
                authorized_hosts=["t.example"], max_turns=3,
                endpoints=["/api/refund"], target_domains=["txn"],
                surface_budget=5, verbose=False,
            )
            # run_summary.md 应在项目目录生成
            _rs = _proj / "run_summary.md"
            assert _rs.exists(), f"run_summary.md 未生成: {_rs}"
            # run_scope.json 应存在
            assert (_proj / "run_scope.json").exists(), "run_scope.json 未生成"
            # business_graph is cumulative project truth and is published only
            # after full closure.  This fixture remains incomplete under the
            # v8.9 exact-role denominator, so it must not leak a partial graph.
            _run_complete = bool(
                (res.get("delivery_status") or {}).get("run_complete"))
            if _run_complete:
                assert (_proj / "business_graph.json").exists(), (
                    "完整 run 未生成 business_graph.json")
            else:
                assert not (_proj / "business_graph.json").exists(), (
                    "未闭合 run 不得发布 business_graph.json 项目真值")
            # blackboard.json 应存在（_conclude 写回）
            assert (_proj / "blackboard.json").exists(), "blackboard.json 未生成"
            # 验证 run_scope.json 全 canonical
            scope = json.loads((_proj / "run_scope.json").read_text(encoding="utf-8"))
            from engine.surface_key import is_canonical
            for k in scope.get("must_test", []):
                assert is_canonical(k), f"run_scope must_test 含非 canonical key: {k!r}"
            print("  断言29 ✅ run_summary/run_scope/blackboard 投影生成，"
                  "business_graph 按 closure gate 发布，must_test 全 canonical")
        finally:
            import shutil
            shutil.rmtree(_fdir, ignore_errors=True)

    def _assert30():
        """Root/impact/chain proof contract + parameter-cell independence."""
        from engine.orchestrator import CognitiveState, POSITIVE, UNTESTED
        from engine.reporting.schema import load_finding
        from engine.reporting.validate import validate_finding
        finding = load_finding(reporting_fixture / "finding.json")
        finding["risk"]["proven_impact"] = "管理员账户接管"
        finding["verification"]["impact_proof_refs"] = ["response_1.http"]
        result = validate_finding(
            finding, reporting_fixture / "finding.json", reporting_fixture,
            authorized_hosts=["t.example"])
        assert not result.ok, "链式影响推断不得替代 root finding 的已证明影响"
        assert any("proven_impact must exactly match" in reason for reason in result.reasons), result.reasons

        state = CognitiveState("param-check", "https://t.example", vuln_classes=["业务逻辑"])
        state.seed_matrix([{
            "endpoint": "/api/create-order", "method": "POST",
            "params": ["quantity", "use_points", "order_time"],
        }])
        assert len(state.matrix) == 3, f"多参数被错误合并: {list(state.matrix)}"
        ok, reason = state.set_cell(
            "POST /api/create-order", "业务逻辑", POSITIVE,
            evidence="finding.json", param="use_points")
        assert ok, reason
        assert state._find_cell(
            "POST /api/create-order", "业务逻辑", param="quantity")["state"] == UNTESTED
        print("  断言30 ✅ chain 假设不冒充 proven impact + 多参数独立闭格")

    for name, fn in (("断言1", _assert1), ("断言2", _assert2), ("断言3", _assert3),
                     ("断言4", _assert4), ("断言5", _assert5), ("断言6", _assert6),
                     ("断言7", _assert7), ("断言8", _assert8), ("断言9", _assert9),
                     ("断言10", _assert10), ("断言11", _assert11), ("断言12", _assert12),
                     ("断言13", _assert13), ("断言14", _assert14), ("断言15", _assert15),
                     ("断言16", _assert16), ("断言17", _assert17),
                     ("断言18", _assert18), ("断言19", _assert19),
                     ("断言20", _assert20), ("断言21", _assert21),
                     ("断言22", _assert22), ("断言23", _assert23),
                     ("断言24", _assert24), ("断言25", _assert25),
                     ("断言26", _assert26), ("断言27", _assert27),
                     ("断言28", _assert28), ("断言29", _assert29),
                     ("断言30", _assert30)):
        try:
            fn()
        except AssertionError as exc:
            failures.append(f"{name} 失败: {exc}")
            print(f"  {name} ✗ {exc}", file=sys.stderr)
        except Exception as exc:                       # noqa: BLE001
            failures.append(f"{name} 异常: {type(exc).__name__}: {exc}")
            print(f"  {name} ✗ {type(exc).__name__}: {exc}", file=sys.stderr)

    if failures:
        print(f"\n✗ self-check 失败（{len(failures)} 条）:", file=sys.stderr)
        for fail in failures:
            print(f"  - {fail}", file=sys.stderr)
        shutil.rmtree(fixture_root, ignore_errors=True)
        return 1
    print("✅ self-check 全部通过")
    shutil.rmtree(fixture_root, ignore_errors=True)
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "score":
        return _score_run(sys.argv[2:])
    ap = argparse.ArgumentParser(description="起一次授权 SRC 会话（engine 三件套接线）")
    ap.add_argument("--version", action="version", version=f"Atoolkit {__version__}")
    ap.add_argument("--target", default="", help="授权目标 URL")
    ap.add_argument("--authz", default="", help="授权说明文本，或授权文件路径")
    ap.add_argument("--cookie", default="", help="人已拿到的新鲜 Cookie/Session")
    ap.add_argument("--bearer", default="", help="人已拿到的新鲜 Bearer JWT（与 --cookie 二选一）")
    ap.add_argument("--auth-scheme", choices=["cookie", "bearer"], default="cookie",
                    help="--identity 凭据的注入方式：cookie→Cookie 头；bearer→Authorization: Bearer")
    ap.add_argument("--model", default="gpt-5.5", help="模型名（换模型只改这里）")
    ap.add_argument("--allow", action="append", default=[], help="额外授权 host（可多次）")
    ap.add_argument("--base-path", default="",
                    help="显式应用根路径（如 /range/pentest/shop/）；不从 target 的 /login/ 等入口猜测")
    ap.add_argument("--allow-path", action="append", default=[],
                    help="授权路径前缀（可多次，写入 manifest；当前 Codex backend 不提供 hard pre-exec）")
    ap.add_argument("--deny-path", action="append", default=[],
                    help="禁止路径前缀（可多次，供产物验证；当前 Codex backend 不提供 hard pre-exec）")
    ap.add_argument("--allow-unrestricted-egress", action="store_true",
                    help="危险降级：允许当前 Codex backend 的非受控网络；不会标记为 preexec_enforced")
    ap.add_argument("--target-fingerprint", default="",
                    help="显式部署 fingerprint；v8.10 只保存/比较，不自动把历史 cell 标 stale")
    ap.add_argument("--target-fingerprint-file", default="",
                    help="从文件读取显式部署 fingerprint（与 --target-fingerprint 二选一）")
    ap.add_argument("--identity", action="append", default=[],
                    help="复验身份 label:cred（cookie 模式如 owner:session=A；bearer 模式如 owner:eyJ...；可多次）")
    ap.add_argument("--victim-marker", default="", help="证明越权的受害者数据特征串")
    ap.add_argument("--owner-label", default="owner",
                    help="确定性 IDOR 复验中的属主 identity 标签（默认 owner）")
    ap.add_argument("--owned-id", action="append", default=[],
                    help="本会话自有对象 id（可多次）；改删类命中其中即自动放行，否则熔断交人工")
    ap.add_argument("--confirm-policy", choices=["halt", "allow"], default="halt",
                    help="改删他人/未知 id 时：halt=熔断停手交人工(默认)；allow=放行(信任场景)")
    ap.add_argument("--hint", default="", help="攻击面提示(按意图触发)，注入 prompt 的 skill_hint 槽；或提示文件路径")
    ap.add_argument("--endpoints", default="",
                    help="覆盖矩阵的攻击面来源：文件路径(每行一个 endpoint，# 起注释) 或逗号分隔")
    ap.add_argument("--recon-dir", default="",
                    help="recon 产物目录(JS/HTML/JSON/HAR)；由 engine.surface.bootstrap 解析为攻击面，"
                         "喂 planner.plan_surfaces 展开后与 --endpoints 合并")
    ap.add_argument("--exclude-endpoint", action="append", default=[],
                    help="从 inventory/coverage 输入排除 endpoint（glob 或路径片段，可多次；例如 vuln.php）")
    ap.add_argument("--ad-hoc", action="store_true",
                    help="显式声明退化单点验证(无 --endpoints/--recon-dir 时放行空启动，退化为首洞即结)")
    ap.add_argument("--vuln-class", action="append", default=[],
                    help="覆盖矩阵的漏洞类(列)，可多次；缺省用引擎内置 OWASP/SRC 主流类")
    ap.add_argument("--enable-auth-flow-column", action="store_true",
                    help="显式启用 auth endpoint 的认证绕过/枚举列；自定义 --vuln-class 时也生效")
    ap.add_argument("--max-turns", type=int, default=50)
    ap.add_argument("--sid", default="", help="会话 ID（默认按时间生成）")
    ap.add_argument("--resume", action="store_true",
                    help="断点续测：复用 --sid 的 runs/<sid>/state.json 承接覆盖进度（无则照常新开）")
    ap.add_argument("--dry-run", action="store_true", help="用 MockAdapter，不接模型/网络")
    ap.add_argument("--self-check", action="store_true",
                    help="自检门：临时生成 fixture 跑断言（不接模型/网络），全过 exit 0、失败 exit 1；"
                         "独立于 --target/--authz，可不带这两参数")
    ap.add_argument("--doctor", action="store_true",
                    help="只读检查版本、AGENTS/Skill Mode 指令解析与 /src 别名，不启动测试")
    # v6.1 §10.3 flags
    ap.add_argument("--loop-mode", default="recall-first",
                    choices=["recall-first", "coverage-first"],
                    help="v6.1：循环模式。recall-first（默认）优先榨干候选；coverage-first 优先覆盖矩阵")
    ap.add_argument("--candidate-top-n", type=int, default=8,
                    help="v6.1：每轮注入候选工作队列上限（§5）")
    ap.add_argument("--adversarial-pass", action="store_true",
                    help="v6.1 §3.3：对抗式补漏 pass（默认关，预算紧时不开）")
    ap.add_argument("--lens", default="",
                    help="v6.1 §3.4：多视角 recall（逗号分隔，如 attacker-A,business-abuser；默认关）")
    ap.add_argument("--proof-budget-floor", type=float, default=0.3,
                    help="v6.1 §5：proof 保底预算下限比例（0-1）")
    ap.add_argument("--no-flow-surfaces", action="store_true",
                    help="v6.1 §9：关闭 flow surface 识别（退化兼容）")
    ap.add_argument("--oracle", default="",
                    help="可选 oracle 文件(JSON/YAML/CSV/PHP array)；存在则用 engine.benchmark_eval "
                         "算 hit/total（仅 accepted + proof-confirmed root finding）并打印")
    # v8.6: project-level state layout
    ap.add_argument("--project", default="",
                    help="v8.6：项目名（目录 slug）。指定后状态落盘到 runs/targets/<slug>/sessions/<sid>/；"
                         "省略则从 target host 派生，或退回旧 runs/<sid>/ 布局")
    ap.add_argument("--target-domains", default="",
                    help="v8.6：逗号分隔的目标域（auth,txn,idor,file,business）。"
                         "域内 surface 优先测试，域外不丢弃仅降优先级")
    ap.add_argument("--surface-budget", type=int, default=0,
                    help="v8.6：本次 run 最多测试 surface 数（0=不限）")
    ap.add_argument("--intent-budget", type=int, default=0,
                    help="v8.6：本次 run 最多追踪 intent 数（0=不限）")
    args = ap.parse_args()

    # --self-check：临时生成 fixture 跑断言，不接模型/网络，独立于 --target/--authz。
    if args.self_check:
        return _run_self_check()
    if args.doctor:
        result = doctor(ROOT)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["ok"] else 1
    # 非 self-check：--target/--authz 仍为必填（argparse 层已放宽为非 required 以放行 --self-check）。
    if not args.target or not args.authz:
        ap.error("--target 与 --authz 为必填（自检门用 --self-check，可不带这两参数）")
    if args.target_fingerprint and args.target_fingerprint_file:
        ap.error("--target-fingerprint 与 --target-fingerprint-file 不能同时使用")
    if not args.dry_run and not args.allow_unrestricted_egress:
        ap.error(
            "当前 Codex backend 无法证明命令执行前的 host/path 出站约束；"
            "live run 默认拒绝。若明确接受风险，传 --allow-unrestricted-egress"
        )
    try:
        explicit_base_path = normalize_explicit_base_path(args.base_path)
    except ValueError as exc:
        ap.error(str(exc))
    if args.target_fingerprint_file:
        fingerprint_path = pathlib.Path(args.target_fingerprint_file)
        try:
            target_fingerprint = fingerprint_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            ap.error(f"无法读取 --target-fingerprint-file: {exc}")
    else:
        target_fingerprint = args.target_fingerprint.strip()
    if (args.target_fingerprint or args.target_fingerprint_file) and not target_fingerprint:
        ap.error("target fingerprint 不能为空")

    # 会话目录与落盘（runs/ 已被 .gitignore）
    os.umask(0o077)
    try:
        sid = safe_session_id(
            args.sid or f"{time.strftime('sess-%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}"
        )
    except ValueError as exc:
        ap.error(str(exc))
    # v8.6: project-level state layout
    _project_slug = safe_project_slug(
        args.project or default_project_slug(args.target, base_path=explicit_base_path)
    )
    if _project_slug:
        project_dir = ROOT / "runs" / "targets" / _project_slug
        _secure_mkdir(project_dir)
        try:
            wd = safe_session_dir(project_dir / "sessions", sid)
        except ValueError as exc:
            ap.error(str(exc))
    else:
        project_dir = None
        try:
            wd = safe_session_dir(ROOT / "runs", sid)
        except ValueError as exc:
            ap.error(str(exc))
    _secure_mkdir(wd)
    # Backward compatibility: migrate an existing runs/<sid> session into the
    # project layout on first resume.  The legacy source remains untouched.
    if args.resume and not args.project:
        legacy_wd = ROOT / "runs" / sid
        if legacy_wd != wd and (legacy_wd / "state.json").exists():
            for name in (
                "state.json", "candidate-ledger.json", "fact_intent_graph.json",
                "inventory.json", "coverage-ledger.json", "events.jsonl",
            ):
                source = legacy_wd / name
                destination = wd / name
                if source.exists() and not destination.exists():
                    shutil.copy2(source, destination)
                    try:
                        destination.chmod(0o600)
                    except OSError:
                        pass
    # v8.6: parse target-domains
    _target_domains = [d.strip() for d in args.target_domains.split(",") if d.strip()] if args.target_domains else None
    authz = (pathlib.Path(args.authz).read_text(encoding="utf-8")
             if pathlib.Path(args.authz).exists() else args.authz)
    _secure_write_text(wd / "authz.md", authz)
    # 会话凭据：cookie 或 bearer（落盘到 cookies.txt 供模型读取，runs/ 已 gitignore）
    cred = args.bearer or args.cookie
    cred_line = (f"Authorization: Bearer {args.bearer}" if args.bearer
                 else (f"Cookie: {args.cookie}" if args.cookie else ""))
    if cred:
        _secure_write_text(wd / "cookies.txt", cred_line)

    skill = (ROOT / "skill" / "核心技能文件.v3.md").read_text(encoding="utf-8")
    target_scope = authorization_scope_from_url(args.target)
    if not target_scope:
        ap.error("--target 必须是合法的 http(s) 绝对 URL")
    raw_scopes = [target_scope] + args.allow
    if any(parse_authorized_scope(scope) is None for scope in raw_scopes):
        ap.error("--allow 必须是合法的 host、host:port、*.domain 或 http(s) URL")
    hosts = normalize_authorized_scopes(raw_scopes)
    try:
        allow_paths = [normalize_explicit_base_path(value) for value in args.allow_path]
        deny_paths = [normalize_explicit_base_path(value) for value in args.deny_path]
    except ValueError as exc:
        ap.error(str(exc))
    authorization_assurance = (
        "dry_run_no_network" if args.dry_run else "unrestricted_user_accepted"
    )

    # 覆盖矩阵的攻击面来源（支柱 2）：
    #   ① --endpoints：文件(每行一个，# 注释) 或逗号分隔
    #   ② --recon-dir：recon 产物目录 → engine.surface.bootstrap 解析为端点清单，
    #      再喂 planner.plan_surfaces 展开成 ledger-ready surfaces，与 ① 合并
    endpoints: list[str] = []
    endpoint_inv_records: list[dict] = []
    if args.endpoints:
        endpoints, endpoint_inv_records = _inventory_records_from_endpoint_arg(args.endpoints)
        endpoints = _filter_inventory(endpoints, args.exclude_endpoint)
        endpoint_inv_records = _filter_endpoint_records(endpoint_inv_records, args.exclude_endpoint)
    from engine.planner import plan_surfaces
    inventory: list = (
        plan_surfaces(endpoint_inv_records) if endpoint_inv_records else list(endpoints)
    )  # parameter-aware dict surfaces for --endpoints + recon expansion below
    inventory_records: list[dict] = list(endpoint_inv_records)
    from engine.surface import is_saturated
    if args.recon_dir:
        from engine.surface import bootstrap
        recon_surfaces = bootstrap(pathlib.Path(args.recon_dir))
        recon_surfaces = _filter_endpoint_records(recon_surfaces, args.exclude_endpoint)
        if not recon_surfaces:
            print(f"  ⚠ --recon-dir {args.recon_dir} 未解析出任何攻击面", file=sys.stderr)
        # P1-3：落 endpoint 台账 inventory.json（与 coverage-ledger.json 同目录）。
        # bootstrap 时 discovered_during_testing=false；断点续测时保留测试中发现的 endpoint。
        inv_path = wd / "inventory.json"
        existing_discovered = []
        if inv_path.exists():                          # --resume 续测：保留 discovered_during_testing 记录
            try:
                old = json.loads(inv_path.read_text(encoding="utf-8"))
                old_recs = old.get("endpoints") if isinstance(old, dict) else old
                existing_discovered = [r for r in old_recs
                                       if isinstance(r, dict) and r.get("discovered_during_testing")]
            except Exception:
                existing_discovered = []
        inv_records = [
            {
                "endpoint": s.get("endpoint", ""),
                "method": s.get("method") or "",
                "source": s.get("source", "manual"),
                "source_file": s.get("source_file", ""),
                "source_line": s.get("source_line", 0),
                "source_kind": s.get("source_kind", s.get("source", "manual")),
                "last_seen": s.get("last_seen", ""),
                "discovered_during_testing": False,
            }
            for s in recon_surfaces
        ] + existing_discovered
        inventory_records.extend(inv_records)
        inventory.extend(_filter_inventory(plan_surfaces(recon_surfaces), args.exclude_endpoint))

    # 正式覆盖跑统一落 endpoint 台账：--endpoints-only 也必须有 inventory.json，
    # 这样 session_gate 能解释 endpoint 来源，报告引用未登记面也能被拦住。
    unresolved_inventory: list[dict] = []
    if args.endpoints or args.recon_dir:
        inv_path = wd / "inventory.json"
        existing_discovered = []
        existing_unresolved = []
        if inv_path.exists():
            try:
                old = json.loads(inv_path.read_text(encoding="utf-8"))
                old_recs = old.get("endpoints") if isinstance(old, dict) else old
                existing_discovered = [r for r in old_recs
                                       if isinstance(r, dict) and r.get("discovered_during_testing")]
                if isinstance(old, dict):
                    existing_unresolved = [
                        r for r in (old.get("unresolved") or [])
                        if isinstance(r, dict)
                    ]
            except Exception:
                existing_discovered = []
                existing_unresolved = []
        inv_records = _merge_inventory_records(_filter_endpoint_records(
            inventory_records + existing_discovered + existing_unresolved,
            args.exclude_endpoint))
        resolved_inventory = [row for row in inv_records if row.get("method")]
        unresolved_inventory = [row for row in inv_records if not row.get("method")]
        _write_runtime_inventory(
            inv_path,
            {"endpoints": resolved_inventory,
             "unresolved": unresolved_inventory,
             "saturation_reached": is_saturated(resolved_inventory)},
            root=wd,
        )

    # v8.8: subsequent runs may start from authoritative project inventory.
    project_inventory_count = 0
    if project_dir and (project_dir / "project_state.json").is_file():
        try:
            project_value = json.loads(
                (project_dir / "project_state.json").read_text(encoding="utf-8"))
            project_inventory_count = len(
                project_value.get("inventory", {}).get("surfaces", {}) or {})
            project_inventory_count += len(
                project_value.get("inventory", {}).get("unresolved", {}) or {})
        except (OSError, json.JSONDecodeError):
            project_inventory_count = 0
    # 硬门：首次正式覆盖跑需输入；后续允许从 project_state 恢复。
    if (not endpoints and not args.recon_dir and not args.ad_hoc
            and project_inventory_count == 0):
        print("✗ 拒绝空启动：首次正式覆盖跑需 --endpoints/--recon-dir；"
              "后续 Run 可复用 project_state.json；单点验证用 --ad-hoc",
              file=sys.stderr)
        sys.exit(2)

    identities = {}
    for spec in args.identity:
        label, _, val = spec.partition(":")
        val = val.strip()
        auth = ({"Authorization": f"Bearer {val}"} if args.auth_scheme == "bearer"
                else {"Cookie": val})
        identities[label.strip()] = auth

    if identities and args.victim_marker and args.owner_label not in identities:
        ap.error(f"--owner-label {args.owner_label!r} 不在 --identity 标签中")

    # 适配器：唯一与模型耦合处（换运行时改这里）
    if args.dry_run:
        adapter, verify_fn = MockAdapter(wd), None      # dry-run 不联网复验
    else:
        from codex.codex_adapter import CodexAdapter
        adapter = CodexAdapter(
            model=args.model,
            workdir=str(wd),
            allow_hosts=hosts,
            allow_unrestricted_egress=args.allow_unrestricted_egress,
        )
        verify_fn = build_verify_fn(
            identities, args.victim_marker, hosts, owner_label=args.owner_label)

    target = args.target + (f"\n（本会话凭据见 {wd/'cookies.txt'}，按其中的 header 行原样带上）" if cred else "")

    print(f"▶ 会话 {sid} ｜ 模型 {'mock' if args.dry_run else args.model} ｜ 授权 host {hosts}")
    print(f"  网络保证: {authorization_assurance} ｜ preexec_enforced=false")
    print(f"  复验: {'开（'+','.join(identities)+'）' if verify_fn else '关'} ｜ 工作目录 {wd}")
    auth_flow_note = " + auth-flow gated" if (args.enable_auth_flow_column or not args.vuln_class) else ""
    if args.recon_dir:
        src_note = "recon" + ("+endpoints" if endpoints else "")
    elif endpoints:
        src_note = "endpoints"
    elif args.ad_hoc:
        src_note = "ad-hoc 退化(首洞即结)"
    elif project_inventory_count:
        src_note = f"project-state({project_inventory_count})"
    else:
        src_note = ""
    print(f"  覆盖矩阵: {len(inventory)} surface × "
          f"{len(args.vuln_class) or '内置'} 类{auth_flow_note} ({src_note})")
    print("─" * 60)
    hint = (pathlib.Path(args.hint).read_text(encoding="utf-8")
            if args.hint and pathlib.Path(args.hint).exists() else args.hint)
    if args.resume and not (wd / "state.json").exists():
        print(f"  ⚠ --resume 但 {wd/'state.json'} 不存在 → 按新会话起（无进度可承接）")
    run_kwargs = {
        "target": target,
        "authz": authz,
        "core_skill": skill,
        "workdir": str(wd),
        "authorized_hosts": hosts,
        "max_turns": args.max_turns,
        "verify_fn": verify_fn,
        "owned_ids": set(args.owned_id),
        "confirm_policy": args.confirm_policy,
        "skill_hint": hint,
        "endpoints": inventory,
        "unresolved_endpoints": unresolved_inventory,
        "vuln_classes": (args.vuln_class or None),
        "resume": args.resume,
    }
    if "enable_auth_flow_column" in inspect.signature(run_session).parameters:
        run_kwargs["enable_auth_flow_column"] = (
            True if args.enable_auth_flow_column else None
        )
    # v6.1 §10.3 flags
    run_kwargs["candidate_top_n"] = args.candidate_top_n
    run_kwargs["loop_mode"] = args.loop_mode
    run_kwargs["adversarial_pass"] = args.adversarial_pass
    run_kwargs["proof_budget_floor"] = args.proof_budget_floor
    run_kwargs["no_flow_surfaces"] = args.no_flow_surfaces
    if args.lens:
        run_kwargs["lens"] = [x.strip() for x in args.lens.split(",") if x.strip()]
    if "exclude_endpoints" in inspect.signature(run_session).parameters:
        run_kwargs["exclude_endpoints"] = args.exclude_endpoint
    optional_runtime_args = {
        "base_path": explicit_base_path,
        "base_path_explicit": bool(args.base_path),
        "allow_paths": allow_paths,
        "deny_paths": deny_paths,
        "authorization_assurance": authorization_assurance,
        "target_fingerprint": target_fingerprint,
        "execution_provenance": {
            "provider": "internal" if args.dry_run else "openai",
            "model": "mock" if args.dry_run else args.model,
            "adapter": str(getattr(adapter, "name", "unknown") or "unknown"),
        },
    }
    run_parameters = inspect.signature(run_session).parameters
    for key, value in optional_runtime_args.items():
        if key in run_parameters:
            run_kwargs[key] = value
    # v8.6: project-level state — domain scope + budgets
    if _target_domains:
        run_kwargs["target_domains"] = _target_domains
    if args.surface_budget:
        run_kwargs["surface_budget"] = args.surface_budget
    if args.intent_budget:
        run_kwargs["intent_budget"] = args.intent_budget
    res = run_session(adapter, **run_kwargs)
    led_stats = (res.get("coverage_ledger") or {}).get("stats") or {}
    delivery = res.get("delivery_status") or {}
    if delivery:
        print(
            f"交付: {delivery.get('status')} | integrity="
            f"{delivery.get('integrity_valid')} | complete="
            f"{delivery.get('delivery_complete')} | assurance="
            f"{delivery.get('authorization_assurance')}"
        )
    else:
        res.setdefault("persistence_errors", []).append("shared_finalizer:missing_delivery")
        res["status"] = "incomplete"
    print("─" * 60)
    print(f"终态: {res['status']} ｜ 标记: {res.get('marker')} ｜ 轮次: {res['turn']}")
    if "accepted" in res:          # error/needs_confirm 终态返回里没有 Guardian 账本
        print(f"Guardian: accepted={res['accepted']} demoted={res['demoted']} rejected={res['rejected']} "
              f"负向留证={res.get('negatives', 0)}")
        cov = res.get("coverage")
        if cov:
            print(f"覆盖矩阵: 闭合 {cov.get('closed', 0)}/{cov.get('total', 0)} "
                  f"(PASS={cov.get('positive', 0)} "
                  f"NEG={cov.get('negative_with_evidence', 0)} "
                  f"SHALLOW={cov.get('shallow_negative', 0)} "
                  f"SKIP={cov.get('skipped', 0)} "
                  f"未测={cov.get('untested', 0)} "
                  f"OPEN={cov.get('open_risk', 0)} "
                  f"NEEDS={cov.get('needs_account', 0)})")
        led = (res.get("coverage_ledger") or {}).get("stats")
        if led:
            print(f"coverage-ledger: 闭合 {led.get('closed', 0)}/{led.get('total', 0)} "
                  f"(confirmed={led.get('confirmed', 0)} "
                  f"not_vulnerable={led.get('not_vulnerable', 0)} "
                  f"not_applicable={led.get('not_applicable', 0)} "
                  f"not_tested={led.get('not_tested', 0)} "
                  f"blocked={led.get('blocked', 0)} "
                  f"high_value_open={led.get('high_value_open', 0)})")
            print(f"本轮准入范围: 闭合 {led.get('in_scope_closed', 0)}/"
                  f"{led.get('in_scope_total', 0)} "
                  f"(open={led.get('in_scope_open', 0)}; "
                  f"project_backlog_out_of_run={led.get('out_of_run', 0)})")
            if res.get("coverage_ledger_path"):
                print(f"coverage-ledger 文件: {res['coverage_ledger_path']}")
        gate = res.get("session_gate")
        if gate:
            reasons = gate.get("reasons") or []
            first = reasons[0] if reasons else {}
            why = first.get("predicate") or "ok"
            action = first.get("action") or first.get("detail") or ""
            suffix = f" ｜ {why}{(': ' + action) if action else ''}" if reasons else ""
            print(f"session-gate: {gate.get('result')}{suffix} ｜ reasons={len(reasons)}")
        if res.get("final_report_path"):
            print(f"综合报告: {res['final_report_path']} ({res.get('final_report_status')})")
        sat = res.get("saturation_reached")
        if sat is not None:
            print(f"discovery 饱和: {'是（连续来源不再新增 endpoint）' if sat else '否'}")
        # P1-2：报告质量 vs 覆盖完成度 分开打印（accepted/hit=报告质量；其余=覆盖完成度）
        hit_str = _oracle_hit_str(args.oracle, res) if args.oracle else "N/A"
        print(f"摘要: accepted={len(res.get('accepted', []))} hit={hit_str} "
              f"high_value_open={led.get('high_value_open', 0)} "
              f"shallow={(cov or {}).get('shallow_negative', 0)} "
              f"next_actions={res.get('open_next_actions_count', 0)}")
        _print_open_high_value(res)
    elif res.get("reason"):
        print(f"原因: {res['reason']}")
        if res.get("cmd"):
            print(f"暂停命令: {res['cmd']}")
    if res.get("verified"):
        print(f"确定性复验: {res['verified']}")
    if res.get("interrupted"):
        print(f"⚠ 流式中断已抢救（{res.get('error')}）；已落盘证据在 {wd}")
        print(f"  断点续测: python3 run.py --sid {sid} --resume --target {args.target} --authz <...> [--cookie/--bearer ...]")
    print(f"证据/报告/状态/日志: {wd}（事件流见 events.jsonl）")
    if isinstance(delivery, dict) and "exit_code" in delivery:
        return int(delivery.get("exit_code", 3))
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
