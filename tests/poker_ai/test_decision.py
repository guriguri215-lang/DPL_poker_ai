"""Tests for Hero's decision: exact call/fold EV, safety mixing, no peeking."""

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
from poker_ai.exploit import RuleExploitResult
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


def test_exploration_epsilon_zero_matches_default_decision():
    import random

    obs = _observation_from_scenario(generate_scenario(random.Random(5), "SC0"))
    default = _agent().decide(obs)
    explicit_zero = HeroAgent(
        get_baseline_strategy(),
        get_bucket_definition(),
        exploration_epsilon=0.0,
    ).decide(obs)

    assert explicit_zero == default


def test_epsilon_one_records_exploration_without_changing_final_policy():
    import random

    obs = _observation_from_scenario(generate_scenario(random.Random(5), "SC0"))
    result = HeroAgent(
        get_baseline_strategy(),
        get_bucket_definition(),
        exploration_epsilon=1.0,
    ).decide(obs)

    assert is_pure_base(result.base_policy, result.final_policy)
    assert result.mix_reasons == ["MIX_EPSILON"]
    assert result.execution_sampling is not None
    assert result.execution_sampling.epsilon == pytest.approx(1.0)
    assert result.selected_action in result.execution_sampling.epsilon_distribution
    assert result.execution_sampling.epsilon_distribution[result.selected_action] > 0.0


def test_epsilon_only_does_not_record_policy_reasons_from_exploit_provider():
    import random

    obs = _observation_from_scenario(generate_scenario(random.Random(5), "SC0"))
    result = HeroAgent(
        get_baseline_strategy(),
        get_bucket_definition(),
        safety_alpha=0.0,
        exploration_epsilon=1.0,
        exploit_provider=_StaticExploitProvider(),
    ).decide(obs)

    assert is_pure_base(result.base_policy, result.final_policy)
    assert result.mix_reasons == ["MIX_EPSILON"]
    assert result.applied_leak_reason_ids == []
    assert result.trigger_reasons == []


def test_epsilon_with_policy_mix_records_policy_and_sampling_reasons():
    import random

    obs = _observation_from_scenario(generate_scenario(random.Random(5), "SC0"))
    result = HeroAgent(
        get_baseline_strategy(),
        get_bucket_definition(),
        safety_alpha=0.25,
        exploration_epsilon=1.0,
        exploit_provider=_StaticExploitProvider(),
    ).decide(obs)

    assert result.mix_reasons == ["MIX_R001", "MIX_EPSILON"]
    assert result.applied_leak_reason_ids == ["LEAK_R008"]
    assert result.trigger_reasons == ["TRG_R001", "TRG_R002"]
    assert result.execution_sampling is not None


def test_agent_rejects_alpha_outside_unit_interval():
    with pytest.raises(ValueError, match="safety_alpha"):
        HeroAgent(get_baseline_strategy(), get_bucket_definition(), safety_alpha=1.5)


def test_agent_rejects_epsilon_outside_unit_interval():
    with pytest.raises(ValueError, match="exploration_epsilon"):
        HeroAgent(get_baseline_strategy(), get_bucket_definition(), exploration_epsilon=1.5)


def test_positive_alpha_mixes_base_with_rule_exploit():
    import random

    obs = _observation_from_scenario(generate_scenario(random.Random(5), "SC0"))
    agent = HeroAgent(
        get_baseline_strategy(),
        get_bucket_definition(),
        safety_alpha=0.25,
        exploit_provider=_StaticExploitProvider(),
    )

    result = agent.decide(obs)

    assert result.exploit_policy == {"FOLD": 0.2, "CALL": 0.8}
    for action in set(result.base_policy) | set(result.exploit_policy):
        expected = 0.75 * result.base_policy.get(action, 0.0) + 0.25 * result.exploit_policy.get(
            action, 0.0
        )
        assert result.final_policy.get(action, 0.0) == pytest.approx(expected)
    assert result.trigger_reasons == ["TRG_R001", "TRG_R002"]
    assert result.mix_reasons == ["MIX_R001"]


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


class _StaticExploitProvider:
    def build(self, **_kwargs) -> RuleExploitResult:
        return RuleExploitResult(
            policy={"FOLD": 0.2, "CALL": 0.8},
            applied_leak_reason_ids=("LEAK_R008",),
            trigger_reasons=("TRG_R001", "TRG_R002"),
        )
