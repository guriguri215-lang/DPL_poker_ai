"""CFR river base-policy adapter checks."""

from __future__ import annotations

import math

import pytest

import poker_ai.cfr_policy as cfr_policy_module
from poker_ai.cfr_policy import (
    CFR_RIVER_POLICY_SOURCE,
    DEFAULT_CFR_RIVER_POLICY_CONFIG,
    CfrRiverPolicyConfig,
    CfrRiverPolicyProvider,
)
from poker_ai.decision import Observation
from poker_ai.scenario import Scenario
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
