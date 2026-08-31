"""v9.8.3 · 新增知识卡（redirect-chain / time-tamper / privilege-escalation /
ssrf / payment-concurrency）回归测试。

- schema：五卡过 ``_validate_card`` 必填键；
- payload-free：对五卡套用 input-validation 同款禁用词表（只含测试维度、
  证据要求、阴性闭合门槛，不含攻击字符串）；
- match：按 params / keywords / risk_tags 触发，且不误触发无关 surface。
"""
from __future__ import annotations

from engine.knowledge import (
    _INPUT_VALIDATION_FORBIDDEN,
    _string_values,
    load_cards,
    match_cards,
)

NEW_CARD_IDS = (
    "redirect-chain",
    "time-tamper",
    "privilege-escalation",
    "ssrf",
    "payment-concurrency",
)


def _new_cards() -> dict:
    cards = {card["id"]: card for card in load_cards()}
    for card_id in NEW_CARD_IDS:
        assert card_id in cards, f"知识卡缺失: {card_id}"
    return {card_id: cards[card_id] for card_id in NEW_CARD_IDS}


def test_new_cards_present_and_schema_valid():
    cards = _new_cards()
    for card_id, card in cards.items():
        for key in ("dimensions", "false_negative_rules",
                    "evidence_required", "negative_sufficiency"):
            assert key in card, f"{card_id} 缺 schema 键 {key}"
        assert card["dimensions"], f"{card_id} dimensions 为空"
        match = card.get("match") or {}
        assert any(match.get(key) for key in ("params", "keywords", "risk_tags")), (
            f"{card_id} match 无触发元数据")


def test_new_cards_are_payload_free():
    for card_id, card in _new_cards().items():
        joined = "\n".join(_string_values(card)).lower()
        for forbidden in _INPUT_VALIDATION_FORBIDDEN:
            assert forbidden not in joined, (
                f"{card_id} 含禁用内容 {forbidden!r}")


def test_new_cards_match_expected_surfaces():
    cards = load_cards()

    def ids(cell):
        return {card["id"] for card in match_cards(cell, cards)}

    assert "redirect-chain" in ids({"params": ["redirect_uri"]})
    assert "redirect-chain" in ids({"risk_tags": ["redirect-chain"]})
    assert "time-tamper" in ids({"params": ["create_time"]})
    assert "time-tamper" in ids({"risk_tags": ["time-tamper"]})
    assert "privilege-escalation" in ids({"params": ["role"]})
    assert "privilege-escalation" in ids({"risk_tags": ["privilege"]})
    assert "ssrf" in ids({"params": ["image_url"]})
    assert "ssrf" in ids({"risk_tags": ["ssrf"]})
    assert "payment-concurrency" in ids({"params": ["stock"]})
    assert "payment-concurrency" in ids({"endpoint": "/api/seckill/秒杀"})


def test_new_cards_do_not_overmatch_unrelated_surface():
    cards = load_cards()
    ids = {card["id"] for card in match_cards(
        {"endpoint": "/api/items/get", "params": ["product_no"],
         "risk_tags": ["idor"]}, cards)}
    assert not set(NEW_CARD_IDS) & ids
