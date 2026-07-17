from __future__ import annotations

import pathlib
from typing import Any

try:
    from ..safe_io import atomic_write_text
    from ..data_hygiene import redact_text
except ImportError:  # pragma: no cover
    from safe_io import atomic_write_text
    from data_hygiene import redact_text

from .schema import resolve_finding_file


def _title(target_name: str) -> str:
    return f"# {target_name or '目标'} 授权安全测试报告"


def _clip_file(path: pathlib.Path, limit: int = 1200) -> str:
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n...（已截断，完整内容见证据文件）"


def _rel(path: pathlib.Path, root: pathlib.Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _finding_and_path(item: dict[str, Any]) -> tuple[dict[str, Any], pathlib.Path]:
    finding = item.get("finding") if "finding" in item else item
    path = pathlib.Path(item.get("path") or finding.get("_finding_path") or "")
    return finding, path


# ── v6.1 §8.2: 四类缺口附录渲染 ──────────────────────────────────────────────
def _render_gaps_appendix(gaps: dict[str, list] | None) -> list[str]:
    """渲染四类缺口附录（§8.2），供 final_report.md 末尾追加。空则返回空清单。"""
    if not gaps:
        return []
    lines: list[str] = ["", "## 附录：覆盖缺口清单（v6.1 §8.2）", ""]
    any_nonempty = False
    cat1 = gaps.get("untested_candidates", [])
    if cat1:
        any_nonempty = True
        lines.append("### ① 发现了但没测（未深测候选清单）")
        for c in cat1[:20]:
            lines.append(f"- [{c.get('status','')}] {c.get('endpoint','')} "
                         f"{c.get('hypothesis','')[:60]} ｜ next_probe: {c.get('next_probe','')[:60]}")
        lines.append("")
    cat2 = gaps.get("shallow_confirmed_or_negative", [])
    if cat2:
        any_nonempty = True
        lines.append("### ② 测了但没深入（浅确认/浅阴性清单）")
        for c in cat2[:20]:
            kind = c.get("kind", "")
            lines.append(f"- {kind}: {c.get('endpoint','')} "
                         f"{c.get('root_cause','') or c.get('surface_id','')}")
        lines.append("")
    cat3 = gaps.get("recoverable_blocked", [])
    if cat3:
        any_nonempty = True
        lines.append("### ③ 阻塞未恢复（可恢复阻塞清单）")
        for c in cat3[:20]:
            lines.append(f"- {c.get('endpoint','')} ｜ blocker: {c.get('blocker',{}).get('kind','')} "
                         f"｜ next: {c.get('next_actions',[])}")
        lines.append("")
    cat4 = gaps.get("proof_ready_without_finding", [])
    if cat4:
        any_nonempty = True
        lines.append("### ④ 漏进报告（待复验/未证清单）")
        for c in cat4[:20]:
            if c.get("kind") == "demoted_or_uncertain":
                lines.append(f"- demoted={c.get('demoted_count',0)} "
                             f"verify_uncertain={c.get('verify_uncertain_count',0)}")
            else:
                lines.append(f"- {c.get('endpoint','')} {c.get('hypothesis','')[:60]} "
                             f"｜ 证据: {c.get('evidence_refs',[])}")
        lines.append("")
    if any_nonempty:
        lines.append("> 铁律：四类缺口任一非空，本次测试不得视为完整（终态 incomplete_with_findings 或 incomplete）。")
        lines.append("")
    return lines if any_nonempty else []


def render_coverage_gaps(
    gaps: dict[str, list] | None,
    output_path: str | pathlib.Path,
) -> pathlib.Path:
    """渲染独立的 coverage_gaps.md（§8.2），列出四类缺口。"""
    out = pathlib.Path(output_path)
    lines = ["# 覆盖缺口清单（coverage_gaps.md · v6.1 §8.2）", ""]
    lines.extend(_render_gaps_appendix(gaps))
    if len(lines) <= 2:
        lines.append("（无缺口：四类清单均为空。）")
    rendered, _redactions = redact_text("\n".join(lines).rstrip() + "\n")
    atomic_write_text(
        out,
        rendered,
        root=out.parent,
        reject_leaf_symlink=True,
    )
    return out.resolve()


def render_final_report(
    findings: list[dict[str, Any]],
    output_path: str | pathlib.Path,
    target_name: str = "",
    *,
    status: str = "complete",
    session_gate: dict[str, Any] | None = None,
    open_risk_cells: list[dict[str, Any]] | None = None,
    coverage_stats: dict[str, Any] | None = None,
    coverage_gaps: dict[str, list] | None = None,
) -> pathlib.Path:
    out = pathlib.Path(output_path)
    run_dir = out.parent.resolve()
    lines: list[str] = [_title(target_name), ""]
    if status == "draft_incomplete":
        lines.extend([
            "> 状态：测试未完成。本报告仅汇总已确认漏洞；仍存在未闭合高价值攻击面，不能视为完整安全测试结论。",
            "",
            "## 测试完整性说明",
            "",
        ])
        gate = session_gate or {}
        reasons = gate.get("reasons") or []
        if reasons:
            lines.append("- session-gate: " + str(gate.get("result", "")))
            for reason in reasons[:8]:
                pred = reason.get("predicate") or reason.get("kind") or "reason"
                detail = reason.get("action") or reason.get("detail") or ""
                lines.append(f"- {pred}: {detail}".rstrip(": "))
        if coverage_stats:
            lines.append(f"- high_value_open: {coverage_stats.get('high_value_open', 0)}")
        for cell in (open_risk_cells or [])[:8]:
            lines.append(f"- 未闭合：{cell.get('endpoint', '')} × {cell.get('vuln', '')} ({cell.get('state', '')})")
        lines.append("")

    if not findings:
        lines.extend([
            "## 结论",
            "",
            "本轮 Canonical 验证未发现满足证明合同、可进入正式报告的漏洞。",
            "",
            "> 此结论仅在覆盖闭合且验证门通过时表示本轮无可报告发现；不等同于目标绝对安全。",
            "",
        ])

    for index, item in enumerate(findings, start=1):
        finding, finding_path = _finding_and_path(item)
        finding_dir = finding_path.parent
        lines.extend([
            f"## {index}. 漏洞名称：{finding.get('title', '')}",
            "",
            f"- 严重等级：{finding.get('severity', '')}",
            f"- 漏洞类型：{finding.get('vuln_type', '')}",
            f"- 目标：{finding.get('target', '')}",
            "",
            "### 安全风险",
            "",
            str((finding.get("risk") or {}).get("summary", "")).strip(),
            "",
            f"已证明影响：{(finding.get('risk') or {}).get('proven_impact', '')}",
            "",
            "### 安全建议",
            "",
            str((finding.get("recommendation") or {}).get("summary", "")).strip(),
        ])
        claim = finding.get("claim") if isinstance(finding.get("claim"), dict) else {}
        if claim:
            lines.extend([
                "### 根漏洞声明",
                "",
                f"- kind：{claim.get('kind', '')}",
                f"- profile：{claim.get('profile', '')}",
                f"- 被破坏的安全不变量：{claim.get('invariant', '')}",
                "",
            ])
        verification = (finding.get("verification")
                        if isinstance(finding.get("verification"), dict) else {})
        access = (verification.get("access_expectation")
                  if isinstance(verification.get("access_expectation"), dict) else {})
        if access:
            lines.extend([
                "### 权限预期证明",
                "",
                f"- 预期访问边界：{access.get('expected_access', '')}",
                f"- 判定依据：{access.get('basis', '')}",
                f"- 证据标记：{access.get('marker', '')}",
                "",
            ])
        impacts = finding.get("impact_claims") or []
        if impacts:
            lines.extend(["### 影响声明", ""])
            for impact in impacts:
                if not isinstance(impact, dict):
                    continue
                label = "已证明" if impact.get("status") == "proven" else "待验证假设（不计严重度）"
                lines.append(f"- [{label}] {impact.get('statement', '')}")
            lines.append("")
        chain = (finding.get("chain_assessment")
                 if isinstance(finding.get("chain_assessment"), dict) else {})
        if chain:
            chain_status = str(chain.get("status") or "not_tested")
            chain_label = ("已由独立证据证明" if chain_status == "proven"
                           else "内部待验证假设，不属于本 finding 的已证明影响")
            lines.extend([
                "### 利用链评估",
                "",
                f"- 状态：{chain_status}（{chain_label}）",
                f"- 路径：{chain.get('chain_path', '')}",
                f"- 假设最终影响：{chain.get('final_impact', '')}",
                "",
            ])
        details = (finding.get("recommendation") or {}).get("details") or []
        for detail in details:
            lines.append(f"- {detail}")
        lines.extend(["", "### 漏洞证明", ""])

        feature = finding.get("feature_point")
        if isinstance(feature, dict) and feature:
            lines.append(feature.get("statement") or f"{feature.get('module', '')} -> {feature.get('function', '')}")
            lines.append("")

        apis = finding.get("apis") or []
        if apis:
            lines.extend(["| Method | Path | Purpose | Risk Params |", "|---|---|---|---|"])
            for api in apis:
                lines.append(
                    f"| {api.get('method', '')} | {api.get('path', '')} | "
                    f"{api.get('purpose', '')} | {', '.join(api.get('risk_params') or [])} |"
                )
            lines.append("")

        source = finding.get("source_proof")
        if isinstance(source, dict) and source:
            lines.extend([
                "### 源码或前端证据",
                "",
                f"- 文件：{source.get('file', '')}",
                f"- 位置：line={source.get('line', '')} function={source.get('function', '')}",
                f"- 证据：{source.get('evidence', '')}",
                f"- 构造数据包：{source.get('constructed_packet_file', '')}",
                "",
            ])

        crypto = finding.get("crypto_chain")
        if isinstance(crypto, dict) and crypto:
            lines.extend([
                "### 加密链路说明",
                "",
                f"- 范围：{crypto.get('scope', '')}",
                f"- 算法：{crypto.get('algorithm', '')}",
                f"- key 来源：{crypto.get('key_source', '')}",
                f"- iv 来源：{crypto.get('iv_source', '')}",
                f"- 解密方式：{crypto.get('decrypt_method', '')}",
                f"- 重加密方式：{crypto.get('reencrypt_method', '')}",
                f"- 辅助文件：{', '.join(crypto.get('helper_files') or [])}",
                f"- 安全结论：{crypto.get('security_statement', '')}",
                "",
            ])

        for packet in finding.get("proof_packets") or []:
            lines.append(f"证据包：{packet.get('name', '')}。{packet.get('evidence_summary', '')}")
            for label in ("request_file", "response_file"):
                ref = packet.get(label)
                if not ref:
                    continue
                path = resolve_finding_file(finding_dir, ref, run_dir)
                lines.extend([f"- {label}: `{_rel(path, run_dir)}`", "", "```http", _clip_file(path), "```", ""])

        poc = finding.get("poc") or {}
        if isinstance(poc, dict) and poc.get("file"):
            path = resolve_finding_file(finding_dir, poc.get("file"), run_dir)
            lines.extend([
                "PoC 执行方式：" + str(poc.get("description") or "按文件内命令替换授权凭据后执行。"),
                "",
                f"- PoC 文件：`{_rel(path, run_dir)}`",
                "",
                "```bash",
                _clip_file(path),
                "```",
                "",
            ])

        steps = finding.get("manual_burp_replay") or []
        if steps:
            lines.extend(["Burp 手工复测步骤：", ""])
            for step_no, step in enumerate(steps, start=1):
                lines.append(f"{step_no}. {step}")
            lines.append("")

    # v6.1 §8.2: 四类缺口附录（发现但没测/测了没深入/阻塞未恢复/漏进报告）
    lines.extend(_render_gaps_appendix(coverage_gaps))

    rendered, _redactions = redact_text("\n".join(lines).rstrip() + "\n")
    atomic_write_text(
        out,
        rendered,
        root=out.parent,
        reject_leaf_symlink=True,
    )
    return out.resolve()
