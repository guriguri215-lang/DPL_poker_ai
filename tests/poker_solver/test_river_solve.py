"""Frozen river scenario solve checks (P3-3)."""

from __future__ import annotations

import pytest

from poker_ai.hand_bucket import bucket_def_version, classify_combo
from poker_ai.scenario import Scenario
from poker_core.combo import Combo
from poker_core.state_cluster import classify_board, cluster_def_version
from poker_solver.river_solve import solve_frozen_river_scenario


def _scenario(position: str = "OOP") -> Scenario:
    return Scenario(
        scenario_id=f"S-{position}",
        board=("As", "Ks", "Qh", "2d", "7c"),
        position=position,
        pot=4.0,
        effective_stack=10.0,
        hero_combo="AhAd",
        hero_range={"AhAd": 1.0, "JhJd": 1.0, "5h5c": 1.0},
        opponent_range={"TcTd": 1.0, "9h9c": 1.0, "6h6c": 1.0},
    )


def test_frozen_river_scenario_solve_returns_combo_policies_and_metrics():
    scenario = _scenario("OOP")

    result = solve_frozen_river_scenario(
        scenario,
        bet_fraction=0.5,
        iterations=40,
        checkpoints=(1, 20, 40),
    )

    board = scenario.board_cards()
    hero_combo = Combo.from_str(scenario.hero_combo)
    assert result.scenario_id == scenario.scenario_id
    assert result.position == "OOP"
    assert result.state_cluster == classify_board(board)
    assert result.cluster_def_version == cluster_def_version()
    assert result.hand_bucket == classify_combo(hero_combo, scenario.hero_range_obj(), board)
    assert result.bucket_def_version == bucket_def_version()
    assert result.hero_combo == "AhAd"
    assert result.metrics.iterations == 40
    assert [point.iterations for point in result.metrics.checkpoints] == [1, 20, 40]

    hero_start = [policy for policy in result.combo_policies if policy.infoset == "OOP:AhAd:start"]
    assert len(hero_start) == 1
    assert hero_start[0].phase == "start"
    assert set(hero_start[0].policy) == {"CHECK", "BET"}
    assert hero_start[0].reach_prob > 0.0


def test_frozen_river_scenario_solve_maps_ip_hero_range_to_ip_infosets():
    scenario = _scenario("IP")

    result = solve_frozen_river_scenario(
        scenario,
        bet_fraction=0.5,
        iterations=20,
    )

    hero_infosets = {policy.infoset for policy in result.combo_policies if policy.combo == "AhAd"}
    assert "IP:AhAd:vs_check" in hero_infosets
    assert "IP:AhAd:vs_bet" in hero_infosets


def test_frozen_river_scenario_solve_rejects_bet_above_effective_stack():
    scenario = _scenario("OOP")

    with pytest.raises(ValueError, match="exceeds effective stack"):
        solve_frozen_river_scenario(scenario, bet_fraction=3.0, iterations=1)
