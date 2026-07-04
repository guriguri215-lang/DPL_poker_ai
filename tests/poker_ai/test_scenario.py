"""Tests for the river scenario schema and deterministic generator (Q3, M-5)."""

from __future__ import annotations

import random

import pytest

from poker_ai.scenario import (
    SCENARIO_SCHEMA_VERSION,
    Scenario,
    generate_scenario,
    generate_scenarios,
)


def _dump(scenarios):
    return [s.model_dump() for s in scenarios]


def test_schema_version_is_draft():
    assert SCENARIO_SCHEMA_VERSION.endswith("-draft")


def test_generation_is_deterministic_for_a_seed():
    first = _dump(generate_scenarios(20260704, 30))
    second = _dump(generate_scenarios(20260704, 30))
    assert first == second


def test_different_seeds_differ():
    a = _dump(generate_scenarios(1, 30))
    b = _dump(generate_scenarios(2, 30))
    assert a != b


def test_generated_scenarios_are_valid_and_playable():
    for scenario in generate_scenarios(7, 50):
        board = scenario.board_cards()
        assert len(board) == 5
        # Hero's dealt combo is board-legal and part of Hero's range.
        assert scenario.hero_combo in scenario.hero_range
        legal_hero = scenario.hero_range_obj().drop_zero_weight().without_blockers(board)
        legal_opp = scenario.opponent_range_obj().drop_zero_weight().without_blockers(board)
        assert len(legal_hero) > 0
        assert len(legal_opp) > 0
        assert scenario.effective_stack > 0
        assert scenario.pot >= 0


def test_num_hands_must_be_positive():
    with pytest.raises(ValueError, match="num_hands"):
        list(generate_scenarios(1, 0))


def test_single_scenario_generation_is_reproducible():
    a = generate_scenario(random.Random(99), "SC0")
    b = generate_scenario(random.Random(99), "SC0")
    assert a == b


def _valid_kwargs():
    scenario = generate_scenario(random.Random(3), "SC0")
    return scenario.model_dump()


def test_scenario_rejects_hero_combo_absent_from_range():
    kwargs = _valid_kwargs()
    hero_combo = kwargs["hero_combo"]
    kwargs["hero_range"] = {k: v for k, v in kwargs["hero_range"].items() if k != hero_combo}
    with pytest.raises(ValueError, match="member of hero_range"):
        Scenario(**kwargs)


def test_scenario_rejects_short_board():
    kwargs = _valid_kwargs()
    kwargs["board"] = kwargs["board"][:4]
    with pytest.raises(ValueError, match="exactly 5"):
        Scenario(**kwargs)


def test_scenario_rejects_negative_stack():
    kwargs = _valid_kwargs()
    kwargs["effective_stack"] = -1.0
    with pytest.raises(ValueError):
        Scenario(**kwargs)


def test_scenario_rejects_opponent_range_fully_colliding_with_hero():
    # Board-legal but every opponent combo shares a card with Hero's exact combo:
    # schema validation used to pass, yet DPL generation would fail because no
    # showdown matchup survives hero-card removal. The scenario must be rejected.
    kwargs = _valid_kwargs()
    kwargs["opponent_range"] = {kwargs["hero_combo"]: 1.0}
    with pytest.raises(ValueError, match="hero_combo"):
        Scenario(**kwargs)
