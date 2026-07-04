"""Tests for range-vs-range showdown EV (Solver spec test 19.3, Phase S0).

Covers the spec's showdown-EV cases plus the acceptance criteria from the task
handoff: EV sign, Hero/Opponent antisymmetry, blocker exclusion, exact
determinism, seeded Monte Carlo reproducibility, and the performance target.
"""

from __future__ import annotations

import math
import time
from itertools import combinations

import pytest

from poker_core.card import RANKS, SUITS, Card, parse_cards
from poker_core.range_model import Range
from poker_core.showdown_ev import (
    EV_DEFINITION,
    estimate_showdown_equity,
    showdown_equity,
    showdown_ev,
)

ROYAL_BOARD = parse_cards("As Ks Qs Js Ts")  # board is itself a royal flush
TRIPS_BOARD = parse_cards("Qs Jd 9h 4c 2s")  # Qh/Qd hole -> trip queens


def all_combos(board: tuple[Card, ...]) -> Range:
    """A uniform range of every 2-card combo not blocked by the board."""
    board_indices = {card.index for card in board}
    deck = [
        Card(rank, suit)
        for rank in RANKS
        for suit in SUITS
        if Card(rank, suit).index not in board_indices
    ]
    return Range({f"{a}{b}": 1.0 for a, b in combinations(deck, 2)})


def test_hero_always_wins_positive_ev():
    # 19.3.1
    hero = Range({"QhQd": 1.0})  # trip queens
    opponent = Range({"3h3c": 1.0, "5d5s": 1.0, "6h6c": 1.0})  # lower pairs, all lose
    result = showdown_ev(hero, opponent, TRIPS_BOARD, pot=10.0)
    assert result.equity.win == pytest.approx(1.0)
    assert result.hero_ev == pytest.approx(5.0)  # +pot / 2
    assert result.ev_definition == EV_DEFINITION


def test_hero_always_loses_negative_ev():
    # 19.3.2
    hero = Range({"3h3c": 1.0})
    opponent = Range({"QhQd": 1.0})  # trip queens
    result = showdown_ev(hero, opponent, TRIPS_BOARD, pot=10.0)
    assert result.equity.lose == pytest.approx(1.0)
    assert result.hero_ev == pytest.approx(-5.0)


def test_complete_tie_zero_ev():
    # 19.3.3: both hole hands play the board's royal flush -> chop.
    hero = Range({"2h3h": 1.0})
    opponent = Range({"4d5d": 1.0})
    result = showdown_ev(hero, opponent, ROYAL_BOARD, pot=10.0)
    assert result.equity.tie == pytest.approx(1.0)
    assert result.hero_ev == pytest.approx(0.0)


def test_hero_and_opponent_ev_are_antisymmetric():
    hero = all_combos(TRIPS_BOARD)
    opponent = Range({"AhAd": 1.0, "KhKd": 1.0, "7h7d": 1.0})
    result = showdown_ev(hero, opponent, TRIPS_BOARD, pot=8.0)
    # opponent_ev property and the swapped-range EV must both be -hero_ev.
    assert result.opponent_ev == pytest.approx(-result.hero_ev)
    swapped = showdown_ev(opponent, hero, TRIPS_BOARD, pot=8.0)
    assert swapped.hero_ev == pytest.approx(-result.hero_ev)


def test_equity_probabilities_sum_to_one():
    hero = all_combos(TRIPS_BOARD)
    opponent = all_combos(TRIPS_BOARD)
    eq = showdown_equity(hero, opponent, TRIPS_BOARD)
    assert eq.win + eq.tie + eq.lose == pytest.approx(1.0)
    # A range against an identical range is symmetric: win prob == lose prob.
    assert eq.win == pytest.approx(eq.lose)


def test_blocker_exclusion_skips_colliding_pairs():
    # The opponent combo AhKh shares the Ah with the hero combo AhAd and must be
    # excluded, so only the 3h5c pairing is weighed.
    hero = Range({"AhAd": 1.0})
    opponent = Range({"AhKh": 1.0, "3h5c": 1.0})  # 3h5c makes only 5-high on this board
    eq = showdown_equity(hero, opponent, TRIPS_BOARD)
    assert eq.considered_weight == pytest.approx(1.0)  # not 2.0
    assert eq.win == pytest.approx(1.0)  # pair of aces beats a 5-high hand


def test_board_blocked_combos_are_dropped():
    # A hero range whose only extra combo collides with the board must give the
    # same result as the board-legal combo alone.
    with_blocked = Range({"QhQd": 1.0, "QsJc": 1.0})  # QsJc shares Qs with board
    legal_only = Range({"QhQd": 1.0})
    opponent = Range({"3h3c": 1.0})
    assert showdown_ev(with_blocked, opponent, TRIPS_BOARD, pot=10.0).hero_ev == pytest.approx(
        showdown_ev(legal_only, opponent, TRIPS_BOARD, pot=10.0).hero_ev
    )


def test_exact_evaluation_is_deterministic():
    hero = all_combos(TRIPS_BOARD)
    opponent = all_combos(TRIPS_BOARD)
    first = showdown_ev(hero, opponent, TRIPS_BOARD, pot=10.0).hero_ev
    second = showdown_ev(hero, opponent, TRIPS_BOARD, pot=10.0).hero_ev
    assert first == second


def test_monte_carlo_is_reproducible_and_close_to_exact():
    hero = all_combos(TRIPS_BOARD)
    opponent = Range({"AhAd": 1.0, "KhKd": 1.0, "5c5d": 1.0})
    exact = showdown_equity(hero, opponent, TRIPS_BOARD)
    first = estimate_showdown_equity(hero, opponent, TRIPS_BOARD, samples=20_000, seed=7)
    second = estimate_showdown_equity(hero, opponent, TRIPS_BOARD, samples=20_000, seed=7)
    # Same seed -> identical estimate.
    assert (first.win, first.tie, first.lose) == (second.win, second.tie, second.lose)
    # And the estimate is close to the exact equity.
    assert first.equity == pytest.approx(exact.equity, abs=0.02)


def test_empty_range_raises():
    with pytest.raises(ValueError):
        showdown_equity(Range({"QhQd": 0.0}), Range({"3h3c": 1.0}), TRIPS_BOARD)


def test_negative_pot_raises():
    with pytest.raises(ValueError, match="pot"):
        showdown_ev(Range({"QhQd": 1.0}), Range({"3h3c": 1.0}), TRIPS_BOARD, pot=-1.0)


def test_non_river_board_rejected():
    # A flop/turn board (not exactly 5 cards) must fail fast, not return a number.
    hero, opponent = Range({"QhQd": 1.0}), Range({"3h3c": 1.0})
    four_card_board = parse_cards("Qs Jd 9h 4c")
    with pytest.raises(ValueError, match="exactly 5"):
        showdown_equity(hero, opponent, four_card_board)
    with pytest.raises(ValueError, match="exactly 5"):
        showdown_ev(hero, opponent, four_card_board, pot=10.0)
    with pytest.raises(ValueError, match="exactly 5"):
        estimate_showdown_equity(hero, opponent, four_card_board, samples=10)


def test_duplicate_board_card_rejected():
    # Board with a repeated card (built directly) is an impossible river.
    dup_board = (
        Card("Q", "s"),
        Card("Q", "s"),
        Card("9", "h"),
        Card("4", "c"),
        Card("2", "s"),
    )
    with pytest.raises(ValueError, match="duplicate"):
        showdown_equity(Range({"AhAd": 1.0}), Range({"3h3c": 1.0}), dup_board)


@pytest.mark.parametrize("bad_pot", [math.nan, math.inf, -math.inf])
def test_non_finite_pot_rejected(bad_pot):
    with pytest.raises(ValueError, match="finite"):
        showdown_ev(Range({"QhQd": 1.0}), Range({"3h3c": 1.0}), TRIPS_BOARD, pot=bad_pot)


def test_monte_carlo_raises_when_it_cannot_reach_samples():
    # Identical single-combo ranges: every draw collides, so no valid matchup can
    # be sampled. The estimator must raise rather than return a short sample.
    same = Range({"AhKh": 1.0})
    with pytest.raises(ValueError, match="non-colliding"):
        estimate_showdown_equity(same, same, TRIPS_BOARD, samples=10, seed=1)


@pytest.mark.parametrize("_run", range(1))
def test_full_range_vs_range_performance(_run):
    # Full 1081-combo range vs full range (~1.17M pairings). Target is < 1s on
    # reference hardware (Phase 1 acceptance); the assertion is lenient for CI.
    hero = all_combos(TRIPS_BOARD)
    opponent = all_combos(TRIPS_BOARD)
    assert len(hero) == 1081  # C(47, 2)
    start = time.perf_counter()
    showdown_equity(hero, opponent, TRIPS_BOARD)
    elapsed = time.perf_counter() - start
    assert elapsed < 3.0, f"showdown enumeration too slow: {elapsed:.2f}s"
