"""回归测试：finding 中按 list 渲染的字段被 agent 写成 str 时，
报告不得逐字符拆成单字母 bullet（gzfsf_172 draft_report 实际 bug）。"""
from __future__ import annotations

from engine.reporting.render_md import _as_list, render_final_report


def _finding_with_str_fields() -> dict:
    return {
        "title": "测试漏洞",
        "severity": "P2",
        "vuln_type": "idor",
        "target": "https://example.com",
        "summary": "摘要",
        "recommendation": {"details": "验证码一次性、短时效、与account绑定。"},
        "apis": [
            {"method": "GET", "path": "/api/x", "purpose": "p", "risk_params": "orgId"}
        ],
        "crypto_chain": {"scope": "s", "helper_files": "helper.py"},
    }


def test_as_list_coerces_str():
    assert _as_list("abc") == ["abc"]
    assert _as_list("  ") == []
    assert _as_list(None) == []
    assert _as_list(["a", "b"]) == ["a", "b"]


def test_str_details_render_as_single_bullet(tmp_path):
    out = tmp_path / "final_report.md"
    render_final_report([_finding_with_str_fields()], out, target_name="t")
    text = out.read_text(encoding="utf-8")
    assert "- 验证码一次性、短时效、与account绑定。" in text
    # 逐字符拆行的特征：单独成行的 "- 验"
    assert "\n- 验\n" not in text
    # risk_params 字符串不得被 join 成 "o, r, g, I, d"
    assert "| orgId |" in text
    assert "o, r, g" not in text
    assert "- 辅助文件：helper.py" in text
