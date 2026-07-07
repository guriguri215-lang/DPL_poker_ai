"""Node-lock checks (Phase 4)."""

from __future__ import annotations

import math

import pytest

from poker_ai.scenario import Scenario
from poker_solver.best_response import best_response_value
from poker_solver.evaluate import expected_value
from poker_solver.nodelock import (
    NodeLockConfig,
    NodeLockRule,
    analyze_nodelock_sensitivity,
    apply_node_locks,
    river_infoset_reach_weights,
    solve_nodelocked_river_scenario,
)
from poker_solver.river_solve import solve_frozen_river_scenario
from poker_solver.river_tree import RiverBettingConfig, build_river_game
from poker_solver.strategy import uniform_profile, validate_profile


def _scenario(position: str = "OOP") -> Scenario:
    return Scenario(
        scenario_id=f"NL-{position}",
        board=("As", "Ks", "Qh", "2d", "7c"),
        position=position,
        pot=4.0,
        effective_stack=10.0,
        hero_combo="AhAd",
        hero_range={"AhAd": 1.0, "JhJd": 1.0, "5h5c": 1.0},
        opponent_range={"TcTd": 1.0, "9h9c": 1.0, "6h6c": 1.0},
    )


def _river_game():
    scenario = _scenario("OOP")
    return _river_game_for_scenario(scenario)


def _river_game_for_scenario(scenario: Scenario):
    config = RiverBettingConfig(pot=scenario.pot, bet_fraction=0.5)
    if scenario.position == "OOP":
        return build_river_game(
            config,
            scenario.hero_range_obj(),
            scenario.opponent_range_obj(),
            scenario.board_cards(),
        )
    return build_river_game(
        config,
        scenario.opponent_range_obj(),
        scenario.hero_range_obj(),
        scenario.board_cards(),
    )


def _blocked_river_game():
    scenario = Scenario(
        scenario_id="NL-BLOCKERS",
        board=("As", "Ks", "Qh", "2d", "7c"),
        position="OOP",
        pot=4.0,
        effective_stack=10.0,
        hero_combo="AhAd",
        hero_range={"AhAd": 1.0, "JhJd": 1.0, "5h5c": 1.0},
        opponent_range={"AhTc": 1.0, "JhTc": 1.0, "5hTc": 1.0},
    )
    config = RiverBettingConfig(pot=scenario.pot, bet_fraction=0.5)
    return build_river_game(
        config,
        scenario.hero_range_obj(),
        scenario.opponent_range_obj(),
        scenario.board_cards(),
    )


def _baseline_profile(game):
    profile = uniform_profile(game)
    profile["OOP:AhAd:start"] = {"CHECK": 0.8, "BET": 0.2}
    profile["OOP:JhJd:start"] = {"CHECK": 0.5, "BET": 0.5}
    profile["OOP:5h5c:start"] = {"CHECK": 0.2, "BET": 0.8}
    validate_profile(game, profile)
    return profile


def _weighted_frequency(profile, infosets, action, weights):
    total = math.fsum(weights[infoset] for infoset in infosets)
    weighted_action = math.fsum(weights[infoset] * profile[infoset][action] for infoset in infosets)
    return weighted_action / total


def test_empty_nodelock_config_matches_frozen_river_solve():
    scenario = _scenario("OOP")
    base = solve_frozen_river_scenario(scenario, bet_fraction=0.5, iterations=20)

    locked = solve_nodelocked_river_scenario(
        scenario,
        bet_fraction=0.5,
        iterations=20,
        nodelock_config=NodeLockConfig(),
    )

    assert locked.strategy == base.strategy
    assert locked.combo_policies == base.combo_policies
    assert locked.applied_locks == ()
    assert locked.lock_mode == "HARD"
    assert locked.unlocked_policy_mode == "fix_to_baseline"
    assert locked.metrics.base_game_value == pytest.approx(base.metrics.game_value)
    assert locked.metrics.game_value == pytest.approx(base.metrics.game_value)
    assert locked.metrics.ev_delta == pytest.approx(0.0)
    assert locked.metrics.exploitability == pytest.approx(base.metrics.final_exploitability)
    assert locked.metrics.worst_case is None


def test_disable_mode_ignores_rules_and_matches_baseline_profile():
    game = _river_game()
    baseline = _baseline_profile(game)
    config = NodeLockConfig(
        lock_mode="DISABLE",
        rules=(NodeLockRule(actor="OOP", phase="start", action="BET", target_frequency=1.0),),
    )

    application = apply_node_locks(
        game,
        baseline,
        config,
        reach_weights=river_infoset_reach_weights(game, baseline),
    )

    assert application.profile == baseline
    assert application.applied_locks == ()


def test_baseline_scaled_allocation_hits_target_without_uniformizing_combos():
    game = _river_game()
    baseline = _baseline_profile(game)
    config = NodeLockConfig(
        rules=(NodeLockRule(actor="OOP", phase="start", action="BET", target_frequency=0.6),)
    )

    application = apply_node_locks(
        game,
        baseline,
        config,
        reach_weights=river_infoset_reach_weights(game, baseline),
    )

    lock = application.applied_locks[0]
    assert lock.combo_allocation == "baseline_scaled"
    assert lock.achieved_frequency == pytest.approx(0.6)
    assert application.profile["OOP:AhAd:start"]["BET"] == pytest.approx(0.36)
    assert application.profile["OOP:JhJd:start"]["BET"] == pytest.approx(0.6)
    assert application.profile["OOP:5h5c:start"]["BET"] == pytest.approx(0.84)
    assert {
        application.profile["OOP:AhAd:start"]["BET"],
        application.profile["OOP:JhJd:start"]["BET"],
        application.profile["OOP:5h5c:start"]["BET"],
    } != {0.6}
    validate_profile(game, application.profile)


def test_non_start_baseline_scaled_uses_profile_reach_weights():
    game = _blocked_river_game()
    baseline = _baseline_profile(game)
    baseline["IP:AhTc:vs_bet"] = {"CALL": 0.1, "FOLD": 0.9}
    baseline["IP:JhTc:vs_bet"] = {"CALL": 0.5, "FOLD": 0.5}
    baseline["IP:Tc5h:vs_bet"] = {"CALL": 0.9, "FOLD": 0.1}
    validate_profile(game, baseline)
    reach_weights = river_infoset_reach_weights(game, baseline)
    config = NodeLockConfig(
        rules=(NodeLockRule(actor="IP", phase="vs_bet", action="CALL", target_frequency=0.7),)
    )

    application = apply_node_locks(game, baseline, config, reach_weights=reach_weights)

    target_infosets = tuple(
        infoset
        for infoset in game.infosets
        if infoset.startswith("IP:") and infoset.endswith(":vs_bet")
    )
    chance_combo_weights = dict.fromkeys(target_infosets, 1.0 / 3.0)
    assert reach_weights["OOP:AhAd:start"] == pytest.approx(1.0 / 3.0)
    assert reach_weights["IP:AhTc:vs_bet"] == pytest.approx((0.5 + 0.8) / 6.0)
    assert reach_weights["IP:JhTc:vs_bet"] == pytest.approx((0.2 + 0.8) / 6.0)
    assert reach_weights["IP:Tc5h:vs_bet"] == pytest.approx((0.2 + 0.5) / 6.0)
    assert application.applied_locks[0].achieved_frequency == pytest.approx(0.7)
    assert _weighted_frequency(
        application.profile, target_infosets, "CALL", reach_weights
    ) == pytest.approx(0.7)
    assert (
        abs(
            _weighted_frequency(application.profile, target_infosets, "CALL", chance_combo_weights)
            - 0.7
        )
        > 0.02
    )
    validate_profile(game, application.profile)


def test_uniform_allocation_sets_each_target_combo_to_target_frequency():
    game = _river_game()
    baseline = _baseline_profile(game)
    config = NodeLockConfig(
        rules=(
            NodeLockRule(
                actor="OOP",
                phase="start",
                action="BET",
                target_frequency=0.25,
                combo_allocation="uniform",
            ),
        )
    )

    application = apply_node_locks(
        game,
        baseline,
        config,
        reach_weights=river_infoset_reach_weights(game, baseline),
    )

    assert application.applied_locks[0].achieved_frequency == pytest.approx(0.25)
    assert application.profile["OOP:AhAd:start"]["BET"] == pytest.approx(0.25)
    assert application.profile["OOP:JhJd:start"]["BET"] == pytest.approx(0.25)
    assert application.profile["OOP:5h5c:start"]["BET"] == pytest.approx(0.25)
    validate_profile(game, application.profile)


def test_resolve_mode_keeps_hard_locked_infosets_fixed():
    game = _river_game()
    baseline = _baseline_profile(game)
    config = NodeLockConfig(
        unlocked_policy_mode="resolve",
        rules=(NodeLockRule(actor="OOP", phase="start", action="BET", target_frequency=1.0),),
    )

    application = apply_node_locks(
        game,
        baseline,
        config,
        reach_weights=river_infoset_reach_weights(game, baseline),
        resolve_iterations=5,
    )

    assert application.unlocked_policy_mode == "resolve"
    assert application.applied_locks[0].achieved_frequency == pytest.approx(1.0)
    for infoset in application.applied_locks[0].target_infosets:
        assert application.profile[infoset] == {"CHECK": 0.0, "BET": 1.0}
    validate_profile(game, application.profile)


def test_soft_resolve_is_not_part_of_p4_1_application():
    game = _river_game()
    baseline = _baseline_profile(game)
    config = NodeLockConfig(
        unlocked_policy_mode="soft_resolve",
        rules=(NodeLockRule(actor="OOP", phase="start", action="BET", target_frequency=0.5),),
    )

    with pytest.raises(NotImplementedError, match="soft_resolve"):
        apply_node_locks(
            game,
            baseline,
            config,
            reach_weights=river_infoset_reach_weights(game, baseline),
            resolve_iterations=5,
        )


def test_soft_lock_mode_with_rules_is_not_part_of_p4_1_application():
    game = _river_game()
    baseline = _baseline_profile(game)
    reach_weights = river_infoset_reach_weights(game, baseline)

    empty_application = apply_node_locks(
        game,
        baseline,
        NodeLockConfig(lock_mode="SOFT"),
        reach_weights=reach_weights,
    )
    assert empty_application.profile == baseline
    assert empty_application.applied_locks == ()
    assert empty_application.lock_mode == "SOFT"

    with pytest.raises(NotImplementedError, match="SOFT"):
        apply_node_locks(
            game,
            baseline,
            NodeLockConfig(
                lock_mode="SOFT",
                rules=(
                    NodeLockRule(
                        actor="OOP",
                        phase="start",
                        action="BET",
                        target_frequency=0.5,
                    ),
                ),
            ),
            reach_weights=reach_weights,
        )


def test_nodelock_config_rejects_invalid_modes_and_target_frequency():
    with pytest.raises(ValueError, match="unknown lock_mode"):
        NodeLockConfig(lock_mode="BAD")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unknown unlocked_policy_mode"):
        NodeLockConfig(unlocked_policy_mode="BAD")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="target_frequency"):
        NodeLockRule(actor="OOP", phase="start", action="BET", target_frequency=1.1)
    with pytest.raises(ValueError, match="unknown combo_allocation"):
        NodeLockRule(  # type: ignore[arg-type]
            actor="OOP",
            phase="start",
            action="BET",
            target_frequency=0.5,
            combo_allocation="bad",
        )


def test_nodelock_application_rejects_unknown_infoset_and_wrong_action():
    game = _river_game()
    baseline = _baseline_profile(game)

    with pytest.raises(ValueError, match="unknown infoset"):
        apply_node_locks(
            game,
            baseline,
            NodeLockConfig(
                rules=(
                    NodeLockRule(
                        infoset="OOP:missing:start",
                        action="BET",
                        target_frequency=0.5,
                    ),
                )
            ),
        )

    with pytest.raises(ValueError, match="not available"):
        apply_node_locks(
            game,
            baseline,
            NodeLockConfig(
                rules=(
                    NodeLockRule(
                        actor="IP",
                        phase="vs_bet",
                        action="BET",
                        target_frequency=0.5,
                    ),
                )
            ),
        )


def test_nodelock_application_rejects_unnormalized_baseline_profile():
    game = _river_game()
    baseline = _baseline_profile(game)
    baseline["OOP:AhAd:start"] = {"CHECK": 0.8, "BET": 0.8}

    with pytest.raises(ValueError, match="sum to"):
        apply_node_locks(
            game,
            baseline,
            NodeLockConfig(
                rules=(
                    NodeLockRule(actor="OOP", phase="start", action="BET", target_frequency=0.5),
                )
            ),
        )


def test_nodelocked_river_result_records_modes_and_allocation():
    result = solve_nodelocked_river_scenario(
        _scenario("OOP"),
        bet_fraction=0.5,
        iterations=10,
        nodelock_config=NodeLockConfig(
            rules=(NodeLockRule(actor="OOP", phase="start", action="BET", target_frequency=0.75),)
        ),
    )

    assert result.lock_mode == "HARD"
    assert result.unlocked_policy_mode == "fix_to_baseline"
    assert result.applied_locks[0].combo_allocation == "baseline_scaled"
    assert result.applied_locks[0].achieved_frequency == pytest.approx(0.75)
    assert result.metrics.base_game_value == pytest.approx(result.base_result.metrics.game_value)
    assert result.metrics.ev_delta == pytest.approx(
        result.metrics.game_value - result.base_result.metrics.game_value
    )
    assert math.isfinite(result.metrics.game_value)
    assert math.isfinite(result.metrics.ev_delta)
    assert math.isfinite(result.metrics.exploitability)
    assert result.metrics.worst_case is None


def test_fix_to_baseline_result_records_locked_ev_delta():
    scenario = _scenario("OOP")
    result = solve_nodelocked_river_scenario(
        scenario,
        bet_fraction=0.5,
        iterations=20,
        nodelock_config=NodeLockConfig(
            rules=(NodeLockRule(actor="IP", phase="vs_bet", action="CALL", target_frequency=1.0),)
        ),
    )

    locked_game_value = expected_value(_river_game(), result.strategy)

    assert result.unlocked_policy_mode == "fix_to_baseline"
    assert result.applied_locks[0].achieved_frequency == pytest.approx(1.0)
    assert result.metrics.base_game_value == pytest.approx(result.base_result.metrics.game_value)
    assert result.metrics.game_value == pytest.approx(locked_game_value)
    assert result.metrics.ev_delta == pytest.approx(
        locked_game_value - result.base_result.metrics.game_value
    )
    assert result.metrics.ev_delta > 0.0
    assert result.metrics.worst_case is None


def test_resolve_result_records_mode2_opponent_best_response_worst_case():
    scenario = _scenario("OOP")
    result = solve_nodelocked_river_scenario(
        scenario,
        bet_fraction=0.5,
        iterations=20,
        nodelock_config=NodeLockConfig(
            unlocked_policy_mode="resolve",
            rules=(NodeLockRule(actor="IP", phase="vs_bet", action="FOLD", target_frequency=1.0),),
        ),
    )
    game = _river_game_for_scenario(scenario)
    worst_case = result.metrics.worst_case

    assert result.unlocked_policy_mode == "resolve"
    assert worst_case is not None
    opponent_best_response = best_response_value(game, 1, result.strategy)
    assert worst_case.hero_player == 0
    assert worst_case.opponent_player == 1
    assert worst_case.opponent_best_response_value == pytest.approx(opponent_best_response)
    assert worst_case.player0_worst_case_value == pytest.approx(-opponent_best_response)
    assert worst_case.hero_value == pytest.approx(result.metrics.game_value)
    assert worst_case.hero_worst_case_value == pytest.approx(-opponent_best_response)
    assert worst_case.worst_case_penalty == pytest.approx(
        result.metrics.game_value - worst_case.hero_worst_case_value
    )
    assert worst_case.worst_case_penalty >= -1e-12


def test_resolve_mode2_worst_case_uses_hero_sign_for_ip_scenarios():
    scenario = _scenario("IP")
    result = solve_nodelocked_river_scenario(
        scenario,
        bet_fraction=0.5,
        iterations=20,
        nodelock_config=NodeLockConfig(
            unlocked_policy_mode="resolve",
            rules=(NodeLockRule(actor="OOP", phase="start", action="BET", target_frequency=1.0),),
        ),
    )
    game = _river_game_for_scenario(scenario)
    worst_case = result.metrics.worst_case

    assert result.unlocked_policy_mode == "resolve"
    assert worst_case is not None
    opponent_best_response = best_response_value(game, 0, result.strategy)
    assert worst_case.hero_player == 1
    assert worst_case.opponent_player == 0
    assert worst_case.opponent_best_response_value == pytest.approx(opponent_best_response)
    assert worst_case.player0_worst_case_value == pytest.approx(opponent_best_response)
    assert worst_case.hero_value == pytest.approx(-result.metrics.game_value)
    assert worst_case.hero_worst_case_value == pytest.approx(-opponent_best_response)
    assert worst_case.worst_case_penalty == pytest.approx(
        -result.metrics.game_value - worst_case.hero_worst_case_value
    )
    assert worst_case.worst_case_penalty >= -1e-12


def test_nodelock_sensitivity_records_target_sweep_and_allocation_gap():
    scenario = _scenario("OOP")
    rule = NodeLockRule(actor="OOP", phase="start", action="BET", target_frequency=0.0)

    report = analyze_nodelock_sensitivity(
        scenario,
        bet_fraction=0.5,
        iterations=20,
        rule=rule,
        target_frequencies=(0.25, 0.5, 0.75),
    )

    assert report.scenario_id == scenario.scenario_id
    assert report.action == "BET"
    assert report.actor == "OOP"
    assert report.phase == "start"
    assert report.infoset is None
    assert report.lock_mode == "HARD"
    assert report.unlocked_policy_mode == "fix_to_baseline"
    assert len(report.points) == 6
    assert len(report.allocation_comparisons) == 3
    for point in report.points:
        assert point.base_game_value == pytest.approx(report.base_game_value)
        assert point.achieved_frequency == pytest.approx(point.target_frequency)
        assert point.worst_case_penalty is None

    baseline_points = [
        point for point in report.points if point.combo_allocation == "baseline_scaled"
    ]
    uniform_points = [point for point in report.points if point.combo_allocation == "uniform"]
    assert [point.target_frequency for point in baseline_points] == [0.25, 0.5, 0.75]
    assert [point.ev_delta for point in baseline_points] == sorted(
        point.ev_delta for point in baseline_points
    )
    assert [point.ev_delta for point in uniform_points] == sorted(
        point.ev_delta for point in uniform_points
    )

    direct_uniform = solve_nodelocked_river_scenario(
        scenario,
        bet_fraction=0.5,
        iterations=20,
        nodelock_config=NodeLockConfig(
            rules=(
                NodeLockRule(
                    actor="OOP",
                    phase="start",
                    action="BET",
                    target_frequency=0.5,
                    combo_allocation="uniform",
                ),
            )
        ),
    )
    uniform_midpoint = next(
        point
        for point in report.points
        if point.target_frequency == 0.5 and point.combo_allocation == "uniform"
    )
    comparison_midpoint = next(
        comparison
        for comparison in report.allocation_comparisons
        if comparison.target_frequency == 0.5
    )

    assert uniform_midpoint.game_value == pytest.approx(direct_uniform.metrics.game_value)
    assert uniform_midpoint.ev_delta == pytest.approx(direct_uniform.metrics.ev_delta)
    assert comparison_midpoint.uniform_ev_delta == pytest.approx(uniform_midpoint.ev_delta)
    assert comparison_midpoint.uniform_minus_baseline_scaled_ev_delta == pytest.approx(
        comparison_midpoint.uniform_ev_delta - comparison_midpoint.baseline_scaled_ev_delta
    )
    assert comparison_midpoint.uniform_minus_baseline_scaled_game_value == pytest.approx(
        comparison_midpoint.uniform_game_value - comparison_midpoint.baseline_scaled_game_value
    )
    assert all(
        comparison.uniform_minus_baseline_scaled_ev_delta < 0.0
        for comparison in report.allocation_comparisons
    )


def test_nodelock_sensitivity_rejects_invalid_sweeps():
    scenario = _scenario("OOP")
    rule = NodeLockRule(actor="OOP", phase="start", action="BET", target_frequency=0.0)

    with pytest.raises(ValueError, match="target_frequencies"):
        analyze_nodelock_sensitivity(
            scenario,
            bet_fraction=0.5,
            iterations=1,
            rule=rule,
            target_frequencies=(),
        )
    with pytest.raises(ValueError, match="unique"):
        analyze_nodelock_sensitivity(
            scenario,
            bet_fraction=0.5,
            iterations=1,
            rule=rule,
            target_frequencies=(0.5, 0.5),
        )
    with pytest.raises(ValueError, match="combo_allocations"):
        analyze_nodelock_sensitivity(
            scenario,
            bet_fraction=0.5,
            iterations=1,
            rule=rule,
            target_frequencies=(0.5,),
            combo_allocations=(),
        )
    with pytest.raises(ValueError, match="unknown combo_allocation"):
        analyze_nodelock_sensitivity(
            scenario,
            bet_fraction=0.5,
            iterations=1,
            rule=rule,
            target_frequencies=(0.5,),
            combo_allocations=("bad",),  # type: ignore[arg-type]
        )
    with pytest.raises(NotImplementedError, match="HARD"):
        analyze_nodelock_sensitivity(
            scenario,
            bet_fraction=0.5,
            iterations=1,
            rule=rule,
            target_frequencies=(0.5,),
            lock_mode="DISABLE",
        )
