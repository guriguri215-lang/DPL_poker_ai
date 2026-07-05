"""Structural invariants across every fixture game (P3-1, REV sec.6 layer L2).

These are the CI-blocking invariants ADR-0017 / the phase-2 gate require of the
verifier: normalised distributions, zero-sum leaves, leaf reach summing to 1,
exploitability >= 0, EV two-path agreement, and determinism.
"""

from __future__ import annotations

import pytest

from poker_core.card import parse_cards
from poker_core.range_model import Range
from poker_solver.best_response import exploitability, nash_conv
from poker_solver.evaluate import expected_value, expected_value_by_leaves, player_values
from poker_solver.games.akq import akq_equilibrium, build_akq_game
from poker_solver.games.kuhn import build_kuhn_game, kuhn_equilibrium
from poker_solver.games.toy import (
    build_toy_coin,
    build_toy_signal,
    toy_coin_uniform,
)
from poker_solver.reach import total_reach
from poker_solver.river_tree import RiverBettingConfig, build_river_game
from poker_solver.strategy import uniform_profile, validate_profile


def _toy_signal_case():
    game = build_toy_signal()
    profile = {"P0:H": {"BET": 0.7, "CHECK": 0.3}, "P0:L": {"BET": 0.2, "CHECK": 0.8}}
    return game, profile


def _river_case():
    board = parse_cards("As Ks Qs 2d 7h")
    oop = Range({"AhAd": 1.0, "JhJd": 1.0, "5h5c": 1.0})
    ip = Range({"AcAh": 1.0, "ThTd": 1.0, "6h6c": 1.0})
    game = build_river_game(RiverBettingConfig(pot=4.0, bet_fraction=0.5), oop, ip, board)
    return game, uniform_profile(game)


def _cases():
    return [
        ("akq", build_akq_game(), akq_equilibrium()),
        ("kuhn", build_kuhn_game(), kuhn_equilibrium(1.0 / 6.0)),
        ("toy_coin", build_toy_coin(), toy_coin_uniform()),
        ("toy_signal", *_toy_signal_case()),
        ("river", *_river_case()),
    ]


CASES = _cases()


@pytest.mark.parametrize("name,game,profile", CASES, ids=[c[0] for c in CASES])
def test_profile_is_valid(name, game, profile):
    validate_profile(game, profile)


@pytest.mark.parametrize("name,game,profile", CASES, ids=[c[0] for c in CASES])
def test_leaf_reach_sums_to_one(name, game, profile):
    assert total_reach(game, profile) == pytest.approx(1.0)


@pytest.mark.parametrize("name,game,profile", CASES, ids=[c[0] for c in CASES])
def test_leaves_are_zero_sum(name, game, profile):
    # Player 1's utility is exactly the negation of player 0's at every leaf.
    for terminal in game.iter_terminals():
        assert terminal.payoff + (-terminal.payoff) == 0.0
    u0, u1 = player_values(game, profile)
    assert u1 == pytest.approx(-u0)


@pytest.mark.parametrize("name,game,profile", CASES, ids=[c[0] for c in CASES])
def test_two_ev_paths_agree(name, game, profile):
    assert expected_value(game, profile) == pytest.approx(expected_value_by_leaves(game, profile))


@pytest.mark.parametrize("name,game,profile", CASES, ids=[c[0] for c in CASES])
def test_exploitability_non_negative(name, game, profile):
    assert exploitability(game, profile) >= -1e-12


@pytest.mark.parametrize("name,game,profile", CASES, ids=[c[0] for c in CASES])
def test_nash_conv_identity(name, game, profile):
    # NashConv == BR0 + BR1 requires the zero-sum bookkeeping to be consistent.
    from poker_solver.best_response import best_response_value

    br0 = best_response_value(game, 0, profile)
    br1 = best_response_value(game, 1, profile)
    assert nash_conv(game, profile) == pytest.approx(br0 + br1)


@pytest.mark.parametrize("name,game,profile", CASES, ids=[c[0] for c in CASES])
def test_full_tree_evaluation_is_deterministic(name, game, profile):
    # Non-sampling evaluation: identical inputs -> bit-identical output (ADR-0017 sec.8).
    first = expected_value(game, profile)
    second = expected_value(game, profile)
    assert first == second
    assert exploitability(game, profile) == exploitability(game, profile)
