"""Best response and exploitability, hand-computed on the toy tree (P3-1)."""

from __future__ import annotations

import pytest

from poker_solver.best_response import (
    best_response_strategy,
    best_response_value,
    exploitability,
    nash_conv,
)
from poker_solver.games.toy import build_toy_coin, toy_coin_uniform


def test_uniform_toy_coin_is_equilibrium():
    game = build_toy_coin()
    profile = toy_coin_uniform()
    # Both best responses are worth the game value/its negation -> zero gain.
    assert best_response_value(game, 0, profile) == pytest.approx(0.5)
    assert best_response_value(game, 1, profile) == pytest.approx(-0.5)
    assert exploitability(game, profile) == pytest.approx(0.0, abs=1e-12)


def test_best_response_to_pure_leak_is_hand_computed():
    game = build_toy_coin()
    # Player 1 always plays X; player 0 uniform. BR for P0 is A worth +2.
    profile = {"P0": {"A": 0.5, "B": 0.5}, "P1": {"X": 1.0, "Y": 0.0}}
    assert best_response_value(game, 0, profile) == pytest.approx(2.0)
    assert best_response_strategy(game, 0, profile)["P0"] == "A"
    # NashConv = (2 - 0.5) + (-0.5 - (-0.5)) = 1.5  ->  exploitability 0.75.
    assert nash_conv(game, profile) == pytest.approx(1.5)
    assert exploitability(game, profile) == pytest.approx(0.75)


def test_best_response_is_infoset_level_not_node_level():
    # Player 1's single infoset spans both nodes; if player 0 plays A for sure,
    # the node under B is unreached (counterfactual reach 0), so BR is decided by
    # the reachable node only: minimise player-0's payoff at the A-node -> Y.
    game = build_toy_coin()
    profile = {"P0": {"A": 1.0, "B": 0.0}, "P1": {"X": 0.5, "Y": 0.5}}
    assert best_response_strategy(game, 1, profile)["P1"] == "Y"
    # BR value to player 1 = -(payoff of A,Y) = -(-1) = +1.
    assert best_response_value(game, 1, profile) == pytest.approx(1.0)


def test_nash_conv_equals_sum_of_best_responses():
    # Identity for 2p zero-sum: NashConv = BR0 + BR1 (own-utility terms).
    game = build_toy_coin()
    profile = {"P0": {"A": 0.2, "B": 0.8}, "P1": {"X": 0.6, "Y": 0.4}}
    br0 = best_response_value(game, 0, profile)
    br1 = best_response_value(game, 1, profile)
    assert nash_conv(game, profile) == pytest.approx(br0 + br1)
    assert exploitability(game, profile) >= -1e-12
