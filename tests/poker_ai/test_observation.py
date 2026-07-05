"""Tests for public observation tracking."""

from __future__ import annotations

import pytest

from poker_ai.observation import ObservationTracker
from poker_ai.opponent import HiddenStrategyAccessError, StubOpponent
from poker_core.range_model import Range


def test_tracker_counts_public_actions_by_situation():
    tracker = ObservationTracker()
    tracker.record_opponent_action(situation_key="dry:IP:facing_all_in", action="BET_ALL_IN")
    tracker.record_opponent_action(situation_key="dry:IP:facing_all_in", action="CHECK")
    tracker.record_opponent_action(situation_key="paired:OOP:facing_all_in", action="BET_ALL_IN")

    dry = tracker.stats_for("dry:IP:facing_all_in")
    assert dry is not None
    assert dry.opportunities == 2
    assert dry.count("BET_ALL_IN") == 1
    assert dry.count_any(("BET_ALL_IN", "BET_75")) == 1
    assert dry.rate_any(("CHECK",)) == pytest.approx(0.5)

    keys = [item.situation_key for item in tracker.snapshot()]
    assert keys == ["dry:IP:facing_all_in", "paired:OOP:facing_all_in"]


def test_tracker_rejects_empty_public_fields():
    tracker = ObservationTracker()
    with pytest.raises(ValueError, match="situation_key"):
        tracker.record_opponent_action(situation_key="", action="BET_ALL_IN")
    with pytest.raises(ValueError, match="action"):
        tracker.record_opponent_action(situation_key="dry:IP:facing_all_in", action="")


def test_observation_path_does_not_read_hidden_strategy():
    opponent = StubOpponent(
        opponent_id="stub_jam_all",
        opponent_version="0.1.0",
        assumed_range=Range({"AhAd": 1.0}),
    )
    action = opponent.act(effective_stack=10.0)

    tracker = ObservationTracker()
    tracker.record_opponent_action(
        situation_key="dry:IP:facing_all_in",
        action=action.action,
    )
    assert tracker.stats_for("dry:IP:facing_all_in") is not None

    with pytest.raises(HiddenStrategyAccessError):
        _ = opponent.hidden_strategy
