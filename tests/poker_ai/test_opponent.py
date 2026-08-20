"""Tests for the stub opponent and its hidden-strategy tripwire (AI Spec 6.3)."""

from __future__ import annotations

import pytest

from poker_ai.opponent import (
    CHECK_BACK_OPPONENT_ID,
    HiddenStrategyAccessError,
    StubOpponent,
    reveal_stub_opponent_answer_key,
)
from poker_core.range_model import Range


def _opponent() -> StubOpponent:
    return StubOpponent(
        opponent_id="stub_jam_all",
        opponent_version="0.1.0",
        assumed_range=Range({"AhAd": 1.0, "KhKd": 1.0}),
    )


def test_reading_hidden_strategy_raises():
    opponent = _opponent()
    with pytest.raises(HiddenStrategyAccessError, match="AI Spec 6.3"):
        _ = opponent.hidden_strategy


def test_assumed_range_is_public():
    # The opponent's hand range is public scenario information (used for EV), unlike
    # the action strategy. Reading it must not raise.
    opponent = _opponent()
    assert opponent.assumed_range.total_weight() == pytest.approx(2.0)


def test_act_jams_all_in():
    action = _opponent().act(effective_stack=12.5)
    assert action.action == "BET_ALL_IN"
    assert action.bet_size == pytest.approx(12.5)


def test_act_rejects_nonpositive_stack():
    with pytest.raises(ValueError, match="effective_stack"):
        _opponent().act(effective_stack=0.0)


def test_r007_stub_checks_back_only_after_environment_check():
    opponent = StubOpponent(
        opponent_id=CHECK_BACK_OPPONENT_ID,
        opponent_version="0.1.0",
        assumed_range=Range({"AhAd": 1.0, "KhKd": 1.0}),
        _policy="check_back_all",
    )

    action = opponent.respond_to_check(effective_stack=12.5)
    answer_key = reveal_stub_opponent_answer_key(opponent_model_id=CHECK_BACK_OPPONENT_ID)

    assert action.action == "CHECK"
    assert action.bet_size == 0.0
    assert answer_key.action_probabilities == (("CHECK", 1.0),)
