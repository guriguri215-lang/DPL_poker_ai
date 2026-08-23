"""CFR river base-policy adapter checks."""

from __future__ import annotations

import math

import pytest

import poker_ai.cfr_policy as cfr_policy_module
from poker_ai.cfr_policy import (
    CFR_RIVER_POLICY_SOURCE,
    DEFAULT_CFR_RIVER_POLICY_CONFIG,
    CfrRiverNoFacingPolicyConfig,
    CfrRiverNoFacingPolicyProvider,
    CfrRiverPolicyConfig,
    CfrRiverPolicyProvider,
    CfrRiverR001NoFacingPolicyProvider,
    exact_oop_start_action_evs,
)
from poker_ai.decision import Observation
from poker_ai.opponent import load_r001_fixture_synthesis, load_r002_fixture_synthesis
from poker_ai.scenario import Scenario, generate_scenarios
from poker_core.state_cluster import classify_board


def _scenario(position: str) -> Scenario:
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


def _observation(position: str, *, facing_bet: float = 10.0) -> Observation:
    scenario = _scenario(position)
    return Observation(
        hand_id=f"H-{position}",
        session_id="S0",
        board=scenario.board_cards(),
        position=scenario.position,
        pot=scenario.pot,
        facing_bet=facing_bet,
        effective_stack=scenario.effective_stack,
        hero_combo=scenario.hero_combo_obj(),
        hero_range=scenario.hero_range_obj(),
        opponent_assumed_range=scenario.opponent_range_obj(),
    )


def _generated_oop_observation(seed: int) -> tuple[Scenario, Observation]:
    generated = next(iter(generate_scenarios(seed, 1)))
    payload = generated.model_dump(mode="python")
    payload["position"] = "OOP"
    payload["effective_stack"] = max(generated.effective_stack, generated.pot * 0.75)
    scenario = Scenario.model_validate(payload)
    return scenario, Observation(
        hand_id=f"RIVER-LARGE-BET-{seed}",
        session_id=f"S{seed}",
        board=scenario.board_cards(),
        position="OOP",
        pot=scenario.pot,
        facing_bet=0.0,
        effective_stack=scenario.effective_stack,
        hero_combo=scenario.hero_combo_obj(),
        hero_range=scenario.hero_range_obj(),
        opponent_assumed_range=scenario.opponent_range_obj(),
    )


@pytest.mark.parametrize("position", ["IP", "OOP"])
def test_provider_selects_hero_combo_vs_bet_policy_for_position(position):
    obs = _observation(position)
    provider = CfrRiverPolicyProvider(
        CfrRiverPolicyConfig(iterations=20, average_delay=0, checkpoints=())
    )

    selected = provider.policy_for(obs, state_cluster=classify_board(obs.board))
    table = selected.strategy_table
    hero_entry = next(entry for entry in table.entries if entry.combo == "AhAd")

    assert table.situation_key == f"{classify_board(obs.board)}:{position}:river_vs_bet"
    assert table.table_version == provider.strategy_version
    assert table.source == provider.source == CFR_RIVER_POLICY_SOURCE
    assert selected.config_sha256 == provider.config_ref().sha256
    assert set(hero_entry.policy) == {"FOLD", "CALL"}
    assert math.fsum(hero_entry.policy.values()) == pytest.approx(1.0)
    assert hero_entry.reach_prob > 0.0


def test_provider_matches_solver_bet_size_to_observed_facing_bet(monkeypatch):
    obs = _observation("IP", facing_bet=10.0)
    provider = CfrRiverPolicyProvider(
        CfrRiverPolicyConfig(iterations=1, average_delay=0, checkpoints=())
    )
    observed: dict[str, float] = {}
    original = cfr_policy_module._solve_frozen_river_scenario

    def capture(scenario, **kwargs):
        observed["bet_fraction"] = kwargs["bet_fraction"]
        return original(scenario, **kwargs)

    monkeypatch.setattr(cfr_policy_module, "_solve_frozen_river_scenario", capture)

    provider.policy_for(obs, state_cluster=classify_board(obs.board))

    assert observed["bet_fraction"] * obs.pot == pytest.approx(obs.facing_bet)


def test_provider_is_deterministic_for_identical_observation():
    obs = _observation("OOP")
    provider = CfrRiverPolicyProvider(
        CfrRiverPolicyConfig(iterations=10, average_delay=0, checkpoints=())
    )

    first = provider.policy_for(obs, state_cluster=classify_board(obs.board))
    second = provider.policy_for(obs, state_cluster=classify_board(obs.board))

    assert first == second


def test_provider_rejects_non_all_in_facing_bet():
    obs = _observation("IP", facing_bet=9.0)
    provider = CfrRiverPolicyProvider(
        CfrRiverPolicyConfig(iterations=1, average_delay=0, checkpoints=())
    )

    with pytest.raises(ValueError, match="only supports facing an all-in"):
        provider.policy_for(obs, state_cluster=classify_board(obs.board))


def test_r007_no_facing_provider_returns_start_policy_and_exact_action_evs():
    obs = _observation("OOP", facing_bet=0.0)
    provider = CfrRiverNoFacingPolicyProvider(
        CfrRiverNoFacingPolicyConfig(iterations=5, average_delay=0, checkpoints=())
    )

    selected = provider.policy_for(obs, state_cluster=classify_board(obs.board))
    table = selected.strategy_table
    hero_entry = next(entry for entry in table.entries if entry.combo == "AhAd")

    assert table.situation_key == f"{classify_board(obs.board)}:OOP:river_start"
    assert set(hero_entry.policy) == {"CHECK", "BET_33"}
    assert selected.decision_action_ev is not None
    assert set(selected.decision_action_ev) == {"CHECK", "BET_33"}
    assert all(math.isfinite(value) for value in selected.decision_action_ev.values())
    assert "phase=start" in provider.config_ref().path
    assert "public_bet=BET_33" in provider.config_ref().path


def test_r001_no_facing_provider_reuses_frozen_bet_fraction_and_exact_action_evs():
    obs = _observation("OOP", facing_bet=0.0)
    fixture = load_r001_fixture_synthesis()
    provider = CfrRiverR001NoFacingPolicyProvider(
        CfrRiverPolicyConfig(iterations=5, average_delay=0, checkpoints=()),
        bet_fraction=fixture.bet_fraction,
        equilibrium_version=fixture.equilibrium_version,
        equilibrium_artifact_sha256=fixture.equilibrium_artifact_sha256,
    )

    selected = provider.policy_for(obs, state_cluster=classify_board(obs.board))
    hero_entry = next(entry for entry in selected.strategy_table.entries if entry.combo == "AhAd")
    solver_ref = provider.config_ref()

    assert fixture.bet_fraction == pytest.approx(0.75)
    assert set(hero_entry.policy) == {"CHECK", "BET_75"}
    assert selected.decision_action_ev is not None
    assert set(selected.decision_action_ev) == {"CHECK", "BET_75"}
    assert all(math.isfinite(value) for value in selected.decision_action_ev.values())
    assert "public_bet=BET_75" in solver_ref.path
    assert "bet_fraction=0.75" in solver_ref.path
    assert f"equilibrium={fixture.equilibrium_version}" in solver_ref.path
    assert f"artifact={fixture.equilibrium_artifact_sha256}" in solver_ref.path


@pytest.mark.parametrize("iterations", [5, 40], ids=["iterations-5", "iterations-40"])
def test_r001_r002_same_scenario_combo_exact_ev_regression(iterations):
    r001 = load_r001_fixture_synthesis()
    r002 = load_r002_fixture_synthesis()
    config = CfrRiverPolicyConfig(iterations=iterations, average_delay=0, checkpoints=())
    r001_provider = CfrRiverR001NoFacingPolicyProvider(
        config,
        bet_fraction=r001.bet_fraction,
        equilibrium_version=r001.equilibrium_version,
        equilibrium_artifact_sha256=r001.equilibrium_artifact_sha256,
    )
    r002_provider = CfrRiverR001NoFacingPolicyProvider(
        config,
        bet_fraction=r002.bet_fraction,
        equilibrium_version=r002.equilibrium_version,
        equilibrium_artifact_sha256=r002.equilibrium_artifact_sha256,
    )

    assert r001.bet_fraction == r002.bet_fraction == 0.75
    assert r001.equilibrium_version == r002.equilibrium_version
    assert r001.equilibrium_artifact_sha256 == r002.equilibrium_artifact_sha256
    for seed in range(20260000, 20260016):
        scenario, observation = _generated_oop_observation(seed)
        state_cluster = classify_board(observation.board)
        r001_selection = r001_provider.policy_for(observation, state_cluster=state_cluster)
        r002_selection = r002_provider.policy_for(observation, state_cluster=state_cluster)
        r001_policy = next(
            entry.policy
            for entry in r001_selection.strategy_table.entries
            if entry.combo == scenario.hero_combo
        )
        r002_policy = next(
            entry.policy
            for entry in r002_selection.strategy_table.entries
            if entry.combo == scenario.hero_combo
        )

        assert set(r001_policy) == set(r002_policy) == {"CHECK", "BET_75"}
        assert all(
            abs(r001_policy[action] - r002_policy[action]) <= 1e-12 for action in r001_policy
        )
        assert r001_selection.decision_action_ev is not None
        assert r002_selection.decision_action_ev is not None
        assert (
            set(r001_selection.decision_action_ev)
            == set(r002_selection.decision_action_ev)
            == {
                "CHECK",
                "BET_75",
            }
        )
        assert all(
            abs(
                r001_selection.decision_action_ev[action]
                - r002_selection.decision_action_ev[action]
            )
            <= 1e-12
            for action in r001_selection.decision_action_ev
        )


def test_r007_no_facing_provider_rejects_ip_hero():
    obs = _observation("IP", facing_bet=0.0)
    provider = CfrRiverNoFacingPolicyProvider(
        CfrRiverNoFacingPolicyConfig(iterations=1, average_delay=0, checkpoints=())
    )

    with pytest.raises(ValueError, match="requires Hero to be OOP"):
        provider.policy_for(obs, state_cluster=classify_board(obs.board))


def test_r007_current_node_action_evs_use_incremental_dpl_normalization():
    scenario = Scenario(
        scenario_id="R007-known-ev",
        board=("As", "Ks", "Qh", "2d", "7c"),
        position="OOP",
        pot=4.0,
        effective_stack=10.0,
        hero_combo="AhAd",
        hero_range={"AhAd": 1.0},
        opponent_range={"TcTd": 1.0},
    )
    profile = {
        "OOP:AhAd:start": {"CHECK": 0.5, "BET": 0.5},
        "IP:TdTc:vs_check": {"CHECK": 1.0, "BET": 0.0},
        "OOP:AhAd:vs_bet": {"CALL": 1.0, "FOLD": 0.0},
        "IP:TdTc:vs_bet": {"CALL": 1.0, "FOLD": 0.0},
    }

    call_action_evs = exact_oop_start_action_evs(scenario, profile)
    fold_profile = {
        **profile,
        "IP:TdTc:vs_bet": {"CALL": 0.0, "FOLD": 1.0},
    }
    fold_action_evs = exact_oop_start_action_evs(scenario, fold_profile)

    assert call_action_evs == pytest.approx({"CHECK": 4.0, "BET_33": 5.32})
    assert fold_action_evs == pytest.approx({"CHECK": 4.0, "BET_33": 4.0})


def test_default_solver_config_is_explicit_and_manifest_addressable():
    config = DEFAULT_CFR_RIVER_POLICY_CONFIG
    provider = CfrRiverPolicyProvider(config)

    assert config.iterations == 40
    assert config.average_delay == 0
    assert config.checkpoints == ()
    assert "iterations=40" in provider.config_ref().path
    assert "average_delay=0" in provider.config_ref().path
    assert "checkpoints=none" in provider.config_ref().path
    assert len(provider.config_ref().sha256) == 64


@pytest.mark.parametrize(
    "kwargs",
    [
        {"iterations": 0, "average_delay": 0},
        {"iterations": 5, "average_delay": 5},
        {"iterations": 5, "average_delay": 0, "checkpoints": (3, 2)},
    ],
)
def test_solver_config_rejects_non_reproducible_or_invalid_values(kwargs):
    with pytest.raises(ValueError):
        CfrRiverPolicyConfig(**kwargs)
