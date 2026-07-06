"""Frozen river scenario solve checks (P3-3)."""

from __future__ import annotations

import pytest

from poker_ai.hand_bucket import bucket_def_version, classify_combo
from poker_ai.leak import action_baseline_table_from_strategy_table
from poker_ai.scenario import Scenario
from poker_core.combo import Combo
from poker_core.state_cluster import classify_board, cluster_def_version
from poker_core.strategy_table import StrategyTable
from poker_solver.river_solve import (
    build_baseline_strategy_table,
    build_baseline_strategy_tables,
    solve_frozen_river_scenario,
    write_baseline_strategy_tables,
)


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


def test_solve_result_builds_strategy_table_per_phase(tmp_path):
    scenario = _scenario("OOP")
    result = solve_frozen_river_scenario(scenario, bet_fraction=0.5, iterations=20)

    table = build_baseline_strategy_table(result, phase="start")

    assert isinstance(table, StrategyTable)
    assert table.table_version.startswith("river-solve-S-OOP-oop-start-i20")
    assert table.situation_key == f"{result.state_cluster}:OOP:river_start"
    assert table.cluster_def_version == result.cluster_def_version
    assert table.source == "poker_solver.solve_frozen_river_scenario"
    assert {entry.combo for entry in table.entries} == {
        policy.combo for policy in result.combo_policies if policy.phase == "start"
    }
    for entry in table.entries:
        source_policy = next(
            policy
            for policy in result.combo_policies
            if policy.phase == "start" and policy.combo == entry.combo
        )
        assert entry.policy == source_policy.policy
        assert entry.reach_prob == pytest.approx(source_policy.reach_prob)

    written = write_baseline_strategy_tables((table,), tmp_path)
    assert len(written) == 1
    reloaded = StrategyTable.model_validate_json(written[0].read_text(encoding="utf-8"))
    assert reloaded == table


def test_strategy_table_version_and_path_include_solve_config(tmp_path):
    scenario = _scenario("OOP")
    half_pot = solve_frozen_river_scenario(scenario, bet_fraction=0.5, iterations=20)
    three_quarter_pot = solve_frozen_river_scenario(
        scenario,
        bet_fraction=0.75,
        iterations=20,
    )

    half_pot_table = build_baseline_strategy_table(half_pot, phase="start")
    three_quarter_pot_table = build_baseline_strategy_table(
        three_quarter_pot,
        phase="start",
    )
    written = write_baseline_strategy_tables(
        (half_pot_table, three_quarter_pot_table),
        tmp_path,
    )

    assert half_pot.solve_config_digest != three_quarter_pot.solve_config_digest
    assert half_pot_table.table_version != three_quarter_pot_table.table_version
    assert len(set(written)) == 2
    assert all(path.exists() for path in written)


def test_solve_result_builds_all_strategy_table_phases():
    result = solve_frozen_river_scenario(_scenario("IP"), bet_fraction=0.5, iterations=10)

    tables = build_baseline_strategy_tables(result)

    assert {table.situation_key for table in tables} == {
        f"{result.state_cluster}:IP:river_vs_bet",
        f"{result.state_cluster}:IP:river_vs_check",
    }
    assert all(isinstance(table, StrategyTable) for table in tables)


def test_call_fold_solve_phase_cannot_build_checked_to_action_baseline():
    result = solve_frozen_river_scenario(_scenario("IP"), bet_fraction=0.5, iterations=10)
    tables = build_baseline_strategy_tables(result)
    vs_bet = next(table for table in tables if table.situation_key.endswith(":river_vs_bet"))
    vs_check = next(table for table in tables if table.situation_key.endswith(":river_vs_check"))

    with pytest.raises(ValueError, match="CHECK/BET actions"):
        action_baseline_table_from_strategy_table(vs_bet)

    baseline = action_baseline_table_from_strategy_table(vs_check)
    assert baseline.table_version.endswith("-action-baseline")


def test_build_strategy_table_rejects_unknown_phase():
    result = solve_frozen_river_scenario(_scenario("OOP"), bet_fraction=0.5, iterations=10)

    with pytest.raises(ValueError, match="no hero policy"):
        build_baseline_strategy_table(result, phase="missing")
