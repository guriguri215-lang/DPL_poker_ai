"""Tests for the two-card Combo model (Solver spec 6.2)."""

from __future__ import annotations

import pytest

from poker_core.card import Card
from poker_core.combo import Combo


def test_canonicalisation_is_order_independent():
    assert Combo.from_str("AsKh").canonical() == "AsKh"
    assert Combo.from_str("KhAs").canonical() == "AsKh"
    assert Combo.from_str("KhAs") == Combo.from_str("AsKh")


def test_canonical_orders_by_value_then_suit():
    # Same rank, different suits: suit order s > h > d > c.
    assert Combo.from_str("AhAs").canonical() == "AsAh"


def test_distinct_cards_required():
    with pytest.raises(ValueError, match="distinct"):
        Combo.from_str("AsAs")


def test_mask_is_two_bits():
    combo = Combo.from_str("AsKh")
    assert bin(combo.mask).count("1") == 2
    assert combo.mask == Card("A", "s").mask | Card("K", "h").mask


def test_collides_with_shared_card():
    assert Combo.from_str("AsKh").collides_with(Combo.from_str("AsQd"))
    assert not Combo.from_str("AsKh").collides_with(Combo.from_str("QdJc"))


def test_blocked_by_dead_mask():
    board = Card("A", "s").mask
    assert Combo.from_str("AsKh").blocked_by(board)
    assert not Combo.from_str("QdJc").blocked_by(board)


def test_from_str_requires_four_chars():
    with pytest.raises(ValueError, match="4 characters"):
        Combo.from_str("AsK")
