"""Tests for the shared Card model (Solver spec 6.1)."""

from __future__ import annotations

import pytest

from poker_core.card import DECK_SIZE, RANKS, SUITS, Card, cards_mask, parse_cards


def test_from_str_round_trips():
    card = Card.from_str("As")
    assert card.rank == "A"
    assert card.suit == "s"
    assert str(card) == "As"


def test_value_ace_high():
    assert Card("A", "s").value == 14
    assert Card("K", "h").value == 13
    assert Card("T", "d").value == 10
    assert Card("2", "c").value == 2


def test_index_is_unique_over_full_deck():
    indices = {Card(rank, suit).index for rank in RANKS for suit in SUITS}
    assert len(indices) == DECK_SIZE
    assert min(indices) == 0
    assert max(indices) == DECK_SIZE - 1


def test_mask_is_single_bit_at_index():
    card = Card("Q", "d")
    assert card.mask == 1 << card.index


@pytest.mark.parametrize("bad", ["Xs", "1h", "A", "Ass", "10s"])
def test_invalid_card_string_rejected(bad):
    with pytest.raises(ValueError):
        Card.from_str(bad)


@pytest.mark.parametrize("bad_suit", ["S", "x", "H"])
def test_invalid_suit_rejected(bad_suit):
    with pytest.raises(ValueError):
        Card("A", bad_suit)


def test_parse_cards_from_string_and_list():
    from_str = parse_cards("As Kh Td")
    from_list = parse_cards(["As", "Kh", "Td"])
    assert from_str == from_list
    assert len(from_str) == 3


def test_parse_cards_rejects_duplicates():
    with pytest.raises(ValueError, match="duplicate"):
        parse_cards("As As")


def test_cards_mask_is_union():
    cards = parse_cards("As Kh")
    assert cards_mask(cards) == cards[0].mask | cards[1].mask


def test_sort_key_orders_by_value_then_suit():
    cards = [Card("2", "s"), Card("A", "c"), Card("A", "s")]
    ordered = sorted(cards, key=lambda c: c.sort_key)
    assert [str(c) for c in ordered] == ["As", "Ac", "2s"]
