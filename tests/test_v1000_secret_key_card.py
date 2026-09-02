"""v10.0 · 新增知识卡 secret-key-validation（认钥闸）回归测试。

- schema：过 ``_validate_card`` 必填键；
- payload-free：套用 input-validation 同款禁用词表；
- match：按密钥材质 keywords / risk_tags 触发，且不误触发
  仅含泛词（token/credential/登录）的无关 surface——误触发会经
  ``_requirements`` 抬高无关面阴性闭合门槛（max/union 语义）。
"""
from __future__ import annotations

from engine.knowledge import (
    _INPUT_VALIDATION_FORBIDDEN,
    _string_values,
    load_cards,
    match_cards,
)


def _card():
    cards = {card["id"]: card for card in load_cards()}
    assert "secret-key-validation" in cards, "知识卡缺失: secret-key-validation"
    return cards["secret-key-validation"]


def test_secret_key_card_schema_valid():
    card = _card()
    for key in ("dimensions", "false_negative_rules",
                "evidence_required", "negative_sufficiency"):
        assert key in card, f"缺 schema 键 {key}"
    assert card["dimensions"], "dimensions 为空"
    match = card.get("match") or {}
    assert any(match.get(key) for key in ("params", "keywords", "risk_tags")), (
        "match 无触发元数据")


def test_secret_key_card_is_payload_free():
    card = _card()
    joined = "\n".join(_string_values(card)).lower()
    for forbidden in _INPUT_VALIDATION_FORBIDDEN:
        assert forbidden not in joined, f"含禁用内容 {forbidden!r}"


def test_secret_key_card_matches_key_material_surfaces():
    cards = load_cards()

    def ids(cell):
        return {card["id"] for card in match_cards(cell, cards)}

    # keywords 路径：match 对 _haystack 切出的 token 精确相等，
    # 密钥材质词必须出现在 endpoint/params 等真实字段里
    assert "secret-key-validation" in ids(
        {"endpoint": "/static/js/app.js?access_key=AKID"})
    assert "secret-key-validation" in ids({"params": ["secret_key"]})
    # risk_tags / vuln_classes 路径
    assert "secret-key-validation" in ids({"risk_tags": ["secret-exposure"]})
    assert "secret-key-validation" in ids({"vuln_class": "密钥泄露"})


def test_secret_key_card_no_misfire_on_generic_surfaces():
    cards = load_cards()

    def ids(cell):
        return {card["id"] for card in match_cards(cell, cards)}

    # 泛词面：session/token/登录态，无密钥材质词——不得触发
    assert "secret-key-validation" not in ids(
        {"endpoint": "/api/auth/refresh", "params": ["token"],
         "vuln_class": "认证绕过"})
    assert "secret-key-validation" not in ids(
        {"params": ["redirect_uri"], "vuln_class": "开放重定向"})
    assert "secret-key-validation" not in ids(
        {"risk_tags": ["idor"], "vuln_class": "越权"})
