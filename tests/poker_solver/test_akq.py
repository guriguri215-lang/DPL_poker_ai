"""AKQ half-street game: closed-form equilibrium checks (P3-1, ADR-0017 sec.5).

The AKQ equilibrium is unique, so we assert the game value, the mixing
frequencies, exploitability ~ 0, the provably-unique pure best-response
components, and a hand-computed best-response value against an over-fold leak.
"""

from __future__ import annotations

import copy

import pytest

from poker_solver.best_response import (
    best_response_strategy,
    best_response_value,
    exploitability,
)
from poker_solver.evaluate import expected_value
from poker_solver.games.akq import akq_equilibrium, akq_solution, build_akq_game
from poker_solver.tolerances import (
    EXPLOITABILITY_ZERO_TOL,
    GAME_VALUE_ABS_TOL,
    STRATEGY_LINF_TOL,
)


def test_akq_default_solution_constants():
    # pot=3, bet=1: f = b/(P+b) = 1/4, c = (P-b)/(P+b) = 1/2, value = -1/12.
    sol = akq_solution()
    assert sol.bluff_freq == pytest.approx(0.25)
    assert sol.call_freq == pytest.approx(0.5)
    assert sol.game_value == pytest.approx(-1.0 / 12.0)


def test_akq_equilibrium_value_matches_closed_form():
    game = build_akq_game()
    profile = akq_equilibrium()
    value = expected_value(game, profile)
    assert value == pytest.approx(akq_solution().game_value, abs=GAME_VALUE_ABS_TOL)


def test_akq_equilibrium_is_unexploitable():
    game = build_akq_game()
    profile = akq_equilibrium()
    assert exploitability(game, profile) == pytest.approx(0.0, abs=EXPLOITABILITY_ZERO_TOL)


@pytest.mark.parametrize("pot,bet", [(3.0, 1.0), (4.0, 2.0), (5.0, 1.0), (2.0, 1.0)])
def test_akq_equilibrium_unexploitable_across_sizes(pot, bet):
    game = build_akq_game(pot, bet)
    profile = akq_equilibrium(pot, bet)
    assert expected_value(game, profile) == pytest.approx(
        akq_solution(pot, bet).game_value, abs=GAME_VALUE_ABS_TOL
    )
    assert exploitability(game, profile) == pytest.approx(0.0, abs=EXPLOITABILITY_ZERO_TOL)


def test_akq_best_response_recovers_unique_pure_components():
    # A best response to the equilibrium must play the strictly-dominant pure
    # actions; OOP's K is indifferent, so it is not asserted (ADR-0017 sec.5).
    game = build_akq_game()
    profile = akq_equilibrium()
    ip_br = best_response_strategy(game, 1, profile)
    oop_br = best_response_strategy(game, 0, profile)
    assert ip_br["IP:A"] == "BET"
    assert ip_br["IP:K"] == "CHECK"
    assert oop_br["OOP:A:facing_bet"] == "CALL"
    assert oop_br["OOP:Q:facing_bet"] == "FOLD"


def test_akq_overfold_leak_best_response_is_hand_computed():
    # Leak: OOP folds K to a bet always (c=0), never bluff-catching. IP's best
    # response (bet A, check K, bluff Q always) is worth exactly +1/3 bb to IP:
    #   deals with IP action -> IP utility (pot=3 so half=1.5, half+bet=2.5):
    #   (K,A)BET +1.5 (Q,A)BET +1.5 (A,K)CHECK -1.5 (Q,K)CHECK +1.5
    #   (A,Q)BET -2.5 (K,Q)BET +1.5  ; sum = 2.0 ; /6 = 1/3.
    game = build_akq_game()
    leak = copy.deepcopy(akq_equilibrium())
    leak["OOP:K:facing_bet"] = {"CALL": 0.0, "FOLD": 1.0}
    assert best_response_value(game, 1, leak) == pytest.approx(1.0 / 3.0, abs=GAME_VALUE_ABS_TOL)
    br = best_response_strategy(game, 1, leak)
    assert br["IP:Q"] == "BET"
    assert br["IP:K"] == "CHECK"
    # The leak strictly increases what IP can win vs the equilibrium value.
    assert best_response_value(game, 1, leak) > -akq_solution().game_value + STRATEGY_LINF_TOL
