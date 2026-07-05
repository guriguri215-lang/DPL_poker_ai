"""Vanilla CFR core checks (P3-2).

Convergence assertions measure exploitability through the independent
best-response module from P3-1, not through CFR regrets or utility caches.
"""

from __future__ import annotations

import pytest

from poker_solver.best_response import exploitability
from poker_solver.cfr import VanillaCFR, regret_matching, solve_vanilla_cfr
from poker_solver.evaluate import expected_value
from poker_solver.games.akq import akq_solution, build_akq_game
from poker_solver.games.kuhn import GAME_VALUE_P1, build_kuhn_game
from poker_solver.games.toy import build_toy_signal
from poker_solver.strategy import validate_profile


def test_regret_matching_uses_positive_regret_only():
    dist = regret_matching({"A": -2.0, "B": 1.0, "C": 3.0}, ("A", "B", "C"))
    assert dist == {"A": 0.0, "B": 0.25, "C": 0.75}


def test_regret_matching_uniform_fallback_for_non_positive_regrets():
    dist = regret_matching({"A": -2.0, "B": 0.0}, ("A", "B"))
    assert dist == {"A": 0.5, "B": 0.5}


def test_average_strategy_uniform_fallback_before_any_iteration():
    game = build_toy_signal()
    avg = VanillaCFR(game).average_strategy()
    validate_profile(game, avg)
    assert avg["P0:H"] == {"BET": 0.5, "CHECK": 0.5}
    assert avg["P0:L"] == {"BET": 0.5, "CHECK": 0.5}


def test_average_strategy_rejects_stale_infoset_key():
    solver = VanillaCFR(build_toy_signal())
    solver.strategy_sum["STALE"] = {"BET": 1.0, "CHECK": 0.0}
    with pytest.raises(ValueError, match="unknown infosets"):
        solver.average_strategy()


def test_vanilla_cfr_is_deterministic_for_same_iteration_count():
    game = build_kuhn_game()
    left = solve_vanilla_cfr(game, 250)
    right = solve_vanilla_cfr(game, 250)
    assert left == right


def test_toy_signal_converges_to_hand_computed_best_policy():
    game = build_toy_signal()
    solver = VanillaCFR(game)

    solver.run(1)
    first = solver.average_strategy()
    first_exploitability = exploitability(game, first)
    assert first == {
        "P0:H": {"BET": 0.5, "CHECK": 0.5},
        "P0:L": {"BET": 0.5, "CHECK": 0.5},
    }
    assert expected_value(game, first) == pytest.approx(0.25)
    assert first_exploitability == pytest.approx(0.25)

    solver.run(99)
    final = solver.average_strategy()
    validate_profile(game, final)
    assert final["P0:H"]["BET"] == pytest.approx(0.995)
    assert final["P0:L"]["CHECK"] == pytest.approx(0.995)
    assert expected_value(game, final) == pytest.approx(0.745)
    assert exploitability(game, final) == pytest.approx(0.0025)
    assert exploitability(game, final) < first_exploitability


def test_akq_vanilla_cfr_converges_by_independent_exploitability():
    game = build_akq_game()
    solution = akq_solution()
    solver = VanillaCFR(game)

    solver.run(100)
    early = solver.average_strategy()
    early_exploitability = exploitability(game, early)

    solver.run(49_900)
    final = solver.average_strategy()
    validate_profile(game, final)
    final_exploitability = exploitability(game, final)

    assert final_exploitability < early_exploitability
    assert final_exploitability < 1e-3
    assert expected_value(game, final) == pytest.approx(solution.game_value, abs=5e-5)
    assert final["IP:Q"]["BET"] == pytest.approx(solution.bluff_freq, abs=5e-3)
    assert final["OOP:K:facing_bet"]["CALL"] == pytest.approx(solution.call_freq, abs=5e-3)
    assert final["IP:A"]["BET"] > 0.999
    assert final["IP:K"]["CHECK"] > 0.999
    assert final["OOP:A:facing_bet"]["CALL"] > 0.999
    assert final["OOP:Q:facing_bet"]["FOLD"] > 0.999


def test_kuhn_vanilla_cfr_converges_by_independent_exploitability():
    game = build_kuhn_game()
    solver = VanillaCFR(game)

    solver.run(100)
    early = solver.average_strategy()
    early_exploitability = exploitability(game, early)

    solver.run(59_900)
    final = solver.average_strategy()
    validate_profile(game, final)
    final_exploitability = exploitability(game, final)

    assert final_exploitability < early_exploitability
    assert final_exploitability < 1e-3
    assert expected_value(game, final) == pytest.approx(GAME_VALUE_P1, abs=5e-5)
