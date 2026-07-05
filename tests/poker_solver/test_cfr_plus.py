"""CFR+ and convergence-metric checks (P3-3)."""

from __future__ import annotations

import pytest

from poker_solver.best_response import exploitability
from poker_solver.cfr import VanillaCFR
from poker_solver.cfr_metrics import solve_cfr_plus_with_metrics
from poker_solver.cfr_plus import CFRPlus, regret_matching_plus, solve_cfr_plus
from poker_solver.evaluate import expected_value
from poker_solver.games.akq import akq_solution, build_akq_game
from poker_solver.games.kuhn import GAME_VALUE_P1, build_kuhn_game
from poker_solver.games.toy import build_toy_signal
from poker_solver.strategy import validate_profile


def test_regret_matching_plus_uses_uniform_fallback():
    dist = regret_matching_plus({"A": 0.0, "B": 0.0}, ("A", "B"))
    assert dist == {"A": 0.5, "B": 0.5}


def test_cfr_plus_floors_negative_regret_updates():
    solver = CFRPlus(build_toy_signal())
    solver.run_iteration()

    assert solver.cumulative_regrets["P0:H"]["BET"] == pytest.approx(0.125)
    assert solver.cumulative_regrets["P0:H"]["CHECK"] == pytest.approx(0.0)
    assert solver.cumulative_regrets["P0:L"]["BET"] == pytest.approx(0.0)
    assert solver.cumulative_regrets["P0:L"]["CHECK"] == pytest.approx(0.375)
    assert all(
        regret >= 0.0 for table in solver.cumulative_regrets.values() for regret in table.values()
    )


def test_cfr_plus_linear_weighted_average_records_iteration_weights():
    solver = CFRPlus(build_toy_signal()).run(3)

    assert solver.average_weight_sum == pytest.approx(6.0)
    assert sum(solver.strategy_sum["P0:H"].values()) == pytest.approx(6.0)
    assert sum(solver.strategy_sum["P0:L"].values()) == pytest.approx(6.0)


def test_cfr_plus_alternating_updates_differ_from_vanilla_cfr():
    game = build_akq_game()
    vanilla = VanillaCFR(game).run(1).current_profile()
    plus = CFRPlus(game).run(1).current_profile()

    assert plus != vanilla


def test_cfr_plus_is_deterministic_for_same_iteration_count():
    game = build_kuhn_game()
    left = solve_cfr_plus(game, 250)
    right = solve_cfr_plus(game, 250)
    assert left == right


def test_convergence_metrics_are_measured_by_independent_br():
    game = build_toy_signal()
    result = solve_cfr_plus_with_metrics(game, 100, checkpoints=(0, 10, 100))

    validate_profile(game, result.profile)
    assert result.metrics.iterations == 100
    assert [point.iterations for point in result.metrics.checkpoints] == [0, 10, 100]
    assert result.metrics.game_value == pytest.approx(expected_value(game, result.profile))
    assert result.metrics.final_exploitability == pytest.approx(
        exploitability(game, result.profile)
    )
    assert result.metrics.final_exploitability < result.metrics.checkpoints[0].exploitability


def test_akq_cfr_plus_converges_by_independent_exploitability():
    game = build_akq_game()
    solution = akq_solution()

    result = solve_cfr_plus_with_metrics(game, 10_000, checkpoints=(100,))
    validate_profile(game, result.profile)

    assert result.metrics.final_exploitability < result.metrics.checkpoints[0].exploitability
    assert result.metrics.final_exploitability < 1e-3
    assert expected_value(game, result.profile) == pytest.approx(solution.game_value, abs=5e-5)
    assert result.profile["IP:Q"]["BET"] == pytest.approx(solution.bluff_freq, abs=5e-3)
    assert result.profile["OOP:K:facing_bet"]["CALL"] == pytest.approx(solution.call_freq, abs=5e-3)


def test_kuhn_cfr_plus_converges_by_independent_exploitability():
    game = build_kuhn_game()

    result = solve_cfr_plus_with_metrics(game, 15_000, checkpoints=(100,))
    validate_profile(game, result.profile)

    assert result.metrics.final_exploitability < result.metrics.checkpoints[0].exploitability
    assert result.metrics.final_exploitability < 1e-3
    assert expected_value(game, result.profile) == pytest.approx(GAME_VALUE_P1, abs=5e-5)
