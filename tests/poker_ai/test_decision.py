"""Tests for Hero's decision: exact call/fold EV, alpha=0 mixing, no peeking."""

from __future__ import annotations

import math

import pytest

from poker_ai.baseline_strategy import get_baseline_strategy
from poker_ai.decision import (
    EV_DEFINITION,
    HeroAgent,
    Observation,
    call_fold_action_evs,
    policy_ev,
)
from poker_ai.hand_bucket import get_bucket_definition
from poker_ai.mixer import is_pure_base
from poker_ai.opponent import HiddenStrategyAccessError, StubOpponent
from poker_ai.scenario import generate_scenario
from poker_core.card import parse_cards
from poker_core.range_model import Range
from poker_core.showdown_ev import showdown_equity

BOARD = parse_cards("Qs Jd 9h 4c 2s")


def _equity(hero: str, opponent: dict[str, float]):
    return showdown_equity(Range({hero: 1.0}), Range(opponent), BOARD)


def test_call_ev_positive_when_hero_always_wins():
    equity = _equity("QhQd", {"3h3c": 1.0, "5d5s": 1.0})  # trips vs low pairs
    evs = call_fold_action_evs(equity, pot=10.0, facing_bet=20.0)
    assert evs["FOLD"] == 0.0
    assert evs["CALL"] == pytest.approx(10.0 + 20.0)  # win*(pot+bet)


def test_call_ev_negative_when_hero_always_loses():
    equity = _equity("3h3c", {"QhQd": 1.0})
    evs = call_fold_action_evs(equity, pot=10.0, facing_bet=20.0)
    assert evs["CALL"] == pytest.approx(-20.0)  # -lose*bet


def test_call_ev_on_tie_returns_half_dead_money():
    # Both hole hands play the board -> chop; calling wins back half the dead pot.
    royal = parse_cards("As Ks Qs Js Ts")
    equity = showdown_equity(Range({"2h3h": 1.0}), Range({"4d5d": 1.0}), royal)
    evs = call_fold_action_evs(equity, pot=8.0, facing_bet=20.0)
    assert equity.tie == pytest.approx(1.0)
    assert evs["CALL"] == pytest.approx(4.0)  # pot / 2


def test_policy_ev_is_probability_weighted():
    action_ev = {"FOLD": 0.0, "CALL": 30.0}
    assert policy_ev({"FOLD": 0.5, "CALL": 0.5}, action_ev) == pytest.approx(15.0)
    assert policy_ev({"CALL": 1.0}, action_ev) == pytest.approx(30.0)


def _observation_from_scenario(scenario, hand_id="H0"):
    opponent = StubOpponent(
        opponent_id="stub_jam_all",
        opponent_version="0.1.0",
        assumed_range=scenario.opponent_range_obj(),
    )
    action = opponent.act(effective_stack=scenario.effective_stack)
    return Observation(
        hand_id=hand_id,
        session_id="S0",
        board=scenario.board_cards(),
        position=scenario.position,
        pot=scenario.pot,
        facing_bet=action.bet_size,
        effective_stack=scenario.effective_stack,
        hero_combo=scenario.hero_combo_obj(),
        hero_range=scenario.hero_range_obj(),
        opponent_assumed_range=scenario.opponent_range_obj(),
    )


def _agent() -> HeroAgent:
    return HeroAgent(get_baseline_strategy(), get_bucket_definition())


def test_decide_produces_valid_alpha_zero_decision():
    import random

    obs = _observation_from_scenario(generate_scenario(random.Random(5), "SC0"))
    result = _agent().decide(obs)
    # final == base at alpha = 0.
    assert is_pure_base(result.base_policy, result.final_policy)
    assert result.exploit_policy == result.base_policy
    # A proper distribution over the legal facing-all-in actions.
    assert set(result.final_policy) <= {"FOLD", "CALL"}
    assert math.fsum(result.final_policy.values()) == pytest.approx(1.0)
    # Selected action carries positive mass.
    assert result.final_policy[result.selected_action] > 0.0
    # EVs agree across the identical policies, and the definition is the exact one.
    assert result.base_ev == pytest.approx(result.final_ev)
    assert result.ev_definition == EV_DEFINITION


def test_decide_is_reproducible():
    import random

    obs = _observation_from_scenario(generate_scenario(random.Random(5), "SC0"))
    assert _agent().decide(obs) == _agent().decide(obs)


def test_agent_rejects_nonzero_alpha():
    with pytest.raises(ValueError, match="safety_alpha=0"):
        HeroAgent(get_baseline_strategy(), get_bucket_definition(), safety_alpha=0.5)


def test_hero_only_sees_public_info_and_cannot_peek():
    # Hero decides from the public Observation alone; the opponent object is never
    # handed to it. A code path that tried to read the hidden strategy would raise.
    import random

    scenario = generate_scenario(random.Random(8), "SC0")
    obs = _observation_from_scenario(scenario)
    # The Observation exposes only the *assumed* range, never a hidden strategy.
    assert not hasattr(obs, "hidden_strategy")
    result = _agent().decide(obs)  # succeeds without any opponent object
    assert result.selected_action in {"FOLD", "CALL"}

    opponent = StubOpponent(
        opponent_id="stub_jam_all",
        opponent_version="0.1.0",
        assumed_range=scenario.opponent_range_obj(),
    )
    with pytest.raises(HiddenStrategyAccessError):
        _ = opponent.hidden_strategy
