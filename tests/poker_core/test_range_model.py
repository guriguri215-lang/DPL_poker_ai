"""Tests for weighted combo ranges (Solver spec 6.3, test 19.2)."""

from __future__ import annotations

import math

import pytest

from poker_core.card import parse_cards
from poker_core.range_model import Range


def test_construction_canonicalises_keys():
    rng = Range({"KhAs": 1.0})
    assert set(rng.weights) == {"AsKh"}


def test_negative_weight_rejected():
    with pytest.raises(ValueError, match=">= 0"):
        Range({"AsKh": -0.1})


def test_nan_weight_rejected():
    with pytest.raises(ValueError, match="finite"):
        Range({"AsKh": math.nan})


def test_inf_weight_rejected():
    with pytest.raises(ValueError, match="finite"):
        Range({"AsKh": math.inf})


def test_duplicate_combo_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        Range({"AsKh": 1.0, "KhAs": 0.5})


def test_drop_zero_weight():
    rng = Range({"AsKh": 1.0, "QsQd": 0.0}).drop_zero_weight()
    assert set(rng.weights) == {"AsKh"}


def test_without_blockers_excludes_board_combos():
    # 19.2.1: combos sharing a card with the board are removed.
    board = parse_cards("As Kd 7h 2c 2s")
    rng = Range({"AsKh": 1.0, "QsQd": 1.0}).without_blockers(board)
    assert set(rng.weights) == {"QsQd"}


def test_without_conflicts_excludes_opponent_cards():
    # 19.2.2: combos colliding with specific dead (opponent) cards are removed.
    dead = parse_cards("Qs")
    rng = Range({"QsQd": 1.0, "AsKh": 1.0}).without_conflicts(dead)
    assert set(rng.weights) == {"AsKh"}


def test_normalized_sums_to_one():
    # 19.2.3: range weights normalise to sum to 1.
    rng = Range({"AsKh": 3.0, "QsQd": 1.0}).normalized()
    assert rng.total_weight() == pytest.approx(1.0)
    assert rng.weights["AsKh"] == pytest.approx(0.75)


def test_normalized_drops_zero_weight_combos():
    # 19.2.4: weight-0 combos are excluded on normalisation.
    rng = Range({"AsKh": 1.0, "QsQd": 0.0}).normalized()
    assert set(rng.weights) == {"AsKh"}


def test_normalize_empty_range_raises():
    with pytest.raises(ValueError, match="empty or zero-weight"):
        Range({"AsKh": 0.0}).normalized()


def test_iter_yields_combo_and_weight():
    rng = Range({"AsKh": 0.25})
    combos = list(rng)
    assert len(combos) == 1
    combo, weight = combos[0]
    assert combo.canonical() == "AsKh"
    assert weight == 0.25
