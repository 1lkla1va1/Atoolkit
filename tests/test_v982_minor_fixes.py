"""v9.8.2 实现审查 MINOR 修复的回归测试。

覆盖实现对抗审查的 5 条 MINOR 修复：
- MINOR-1：run.py `--allow-derived` 与 --target/--allow 同口径归一；
- MINOR-3：framework_fingerprint.md 解析容忍 BOM 与大写 key；
- MINOR-4：v3 §7 的 reference 指针逐一对得上 reference 实际标题；
- MINOR-5：Direct 侧归一 warning 文案不指向不存在的机制；
- MINOR-7：_budget_guardrail 写盘只吞 OSError/UnsafePathError，编程错误照常抛出。
"""

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

from engine import skill_runtime  # noqa: E402
from run import _strip_derived_inputs  # noqa: E402


def test_derived_inputs_strip_paths_with_warning():
    stripped, normalizations = _strip_derived_inputs(
        ["https://oss.example.com/bucket/x", "cdn.example.com", ""])
    assert stripped == ["https://oss.example.com", "cdn.example.com"]
    assert normalizations == [
        ("https://oss.example.com/bucket/x", "https://oss.example.com")]


def test_derived_inputs_without_paths_pass_through():
    stripped, normalizations = _strip_derived_inputs(
        ["*.example.com", "10.0.0.1:8080"])
    assert stripped == ["*.example.com", "10.0.0.1:8080"]
    assert normalizations == []


def _parse_framework(tmp_path, text: str):
    recon = tmp_path / "recon"
    recon.mkdir(exist_ok=True)
    (recon / "framework_fingerprint.md").write_text(text, encoding="utf-8")
    return skill_runtime._load_framework_card(recon)


def test_fingerprint_tolerates_bom_and_uppercase_key(tmp_path):
    for payload in ("﻿Framework: ruoyi\n证据…", "Framework: ruoyi\n",
                    "  framework:  ruoyi  \n"):
        card, _advisory = _parse_framework(tmp_path, payload)
        assert card is not None, f"指纹解析失败: {payload!r}"
        assert card["framework"] == "ruoyi"


def test_fingerprint_rejects_traversal_name(tmp_path):
    card, advisory = _parse_framework(tmp_path, "framework: ../../etc\n")
    assert card is None
    assert "advisory" in advisory


def test_v3_reference_pointers_resolve_to_real_headings():
    v3 = (ROOT / "skill" / "核心技能文件.v3.md").read_text(encoding="utf-8")
    reference = (ROOT / "skill" / "skillmode-reference.md").read_text(
        encoding="utf-8")
    section = v3.split("## 7. 决策树", 1)[1].split("## 8.", 1)[0]
    pointers = re.findall(r"→ §([^\s），；)]+)", section)
    assert pointers, "§7 应保留 reference 触发式指针"
    missing = [p for p in pointers if p not in reference]
    assert not missing, f"悬空指针（reference 无对应内容）: {missing}"


def test_direct_warning_text_does_not_reference_missing_mechanism():
    source = (ROOT / "engine" / "skill_runtime.py").read_text(encoding="utf-8")
    assert "Direct 模式无路径级收窄通道" in source
    assert "（路径级收窄请用显式路径授权机制）" not in source


def test_guardrail_swallow_is_narrow():
    source = (ROOT / "engine" / "skill_runtime.py").read_text(encoding="utf-8")
    match = re.search(
        r"def _budget_guardrail.*?return guardrail", source, re.DOTALL)
    assert match, "_budget_guardrail 未找到"
    assert "except (OSError, UnsafePathError)" in match.group(0)
    assert "except Exception" not in match.group(0)
