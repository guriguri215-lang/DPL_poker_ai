"""Tests for the action-only leak detector."""

from __future__ import annotations

import pytest

from poker_ai.leak import (
    BET_ACTIONS,
    ActionBaselineTable,
    ActionLeakRule,
    LeakDetector,
    LeakDetectorConfig,
    action_baseline_table_from_strategy_table,
    action_baseline_table_sha256,
    leaky_fixture_action_baseline_table,
)
from poker_ai.observation import ObservationTracker
from poker_ai.opponent import HiddenStrategyAccessError, StubOpponent
from poker_core.range_model import Range
from poker_core.strategy_table import StrategyEntry, StrategyTable

KEY = "dry:IP:facing_all_in"


def _tracker_with_actions(actions: list[str]) -> ObservationTracker:
    tracker = ObservationTracker()
    for action in actions:
        tracker.record_opponent_action(situation_key=KEY, action=action)
    return tracker


def _bet_rule(*, baseline_rate: float) -> ActionLeakRule:
    return ActionLeakRule(
        reason_id="LEAK_R008",
        leak_type="bet_too_often_when_checked_to",
        action_group=BET_ACTIONS,
        baseline_rate=baseline_rate,
        direction="decrease_bet_frequency_when_checked_to",
    )


def _detector(
    *,
    baseline_rate: float,
    min_effective_sample_size: int = 4,
    min_deviation: float = 0.25,
    min_confidence: float = 0.5,
) -> LeakDetector:
    return LeakDetector(
        ActionBaselineTable("fixture-action-baseline", (_bet_rule(baseline_rate=baseline_rate),)),
        LeakDetectorConfig(
            min_effective_sample_size=min_effective_sample_size,
            min_deviation=min_deviation,
            min_confidence=min_confidence,
        ),
    )


def test_positive_action_leak_matches_dpl_detected_leak_contract():
    tracker = _tracker_with_actions(["BET_ALL_IN", "BET_ALL_IN", "BET_ALL_IN", "CHECK"])
    leaks = _detector(baseline_rate=0.25).detect(tracker.snapshot())

    assert len(leaks) == 1
    leak = leaks[0]
    assert leak.reason_id == "LEAK_R008"
    assert leak.leak_type == "bet_too_often_when_checked_to"
    assert leak.situation_key == KEY
    assert leak.observed_rate == pytest.approx(0.75)
    assert leak.baseline_rate == pytest.approx(0.25)
    assert leak.effective_sample_size == 4
    assert leak.confidence == pytest.approx(1.0)


def test_negative_case_below_sample_floor():
    tracker = _tracker_with_actions(["BET_ALL_IN", "BET_ALL_IN", "BET_ALL_IN"])
    leaks = _detector(baseline_rate=0.0, min_effective_sample_size=4).detect(tracker.snapshot())
    assert leaks == []


def test_negative_case_below_deviation_threshold():
    tracker = _tracker_with_actions(["BET_ALL_IN", "BET_ALL_IN", "CHECK", "CHECK"])
    leaks = _detector(baseline_rate=0.30, min_deviation=0.25).detect(tracker.snapshot())
    assert leaks == []


def test_threshold_boundary_is_inclusive():
    tracker = _tracker_with_actions(["BET_ALL_IN", "BET_ALL_IN", "BET_ALL_IN", "CHECK"])
    leaks = _detector(baseline_rate=0.50, min_deviation=0.25, min_confidence=0.5).detect(
        tracker.snapshot()
    )
    assert len(leaks) == 1
    assert leaks[0].observed_rate - leaks[0].baseline_rate == pytest.approx(0.25)
    assert leaks[0].confidence == pytest.approx(0.5)


def test_ontology_label_mismatch_is_rejected():
    with pytest.raises(ValueError, match="does not match ontology label"):
        ActionLeakRule(
            reason_id="LEAK_R008",
            leak_type="wrong_label",
            action_group=BET_ACTIONS,
            baseline_rate=0.25,
            direction="decrease_bet_frequency_when_checked_to",
        )


def test_detector_rejects_non_leak_reason_id():
    with pytest.raises(ValueError, match="non-LEAK"):
        ActionLeakRule(
            reason_id="TRG_R002",
            leak_type="leak_confidence_over_threshold",
            action_group=BET_ACTIONS,
            baseline_rate=0.25,
            direction="x",
        )


def test_leak_detector_does_not_read_hidden_strategy():
    opponent = StubOpponent(
        opponent_id="stub_jam_all",
        opponent_version="0.1.0",
        assumed_range=Range({"AhAd": 1.0}),
    )
    public_action = opponent.act(effective_stack=10.0).action
    tracker = _tracker_with_actions([public_action] * 4)

    leaks = _detector(baseline_rate=0.0).detect(tracker.snapshot())
    assert len(leaks) == 1
    with pytest.raises(HiddenStrategyAccessError):
        _ = opponent.hidden_strategy


def test_action_baseline_can_be_derived_from_strategy_table():
    table = StrategyTable(
        table_version="solver-table-v1",
        situation_key=KEY,
        cluster_def_version="cluster-v1",
        source="test",
        entries=(
            StrategyEntry(combo="AhAd", policy={"CHECK": 0.5, "BET": 0.5}, reach_prob=0.5),
            StrategyEntry(combo="KhKd", policy={"CHECK": 1.0}, reach_prob=0.5),
        ),
    )

    baseline = action_baseline_table_from_strategy_table(table)
    detector = LeakDetector(
        baseline,
        LeakDetectorConfig(
            min_effective_sample_size=1,
            min_deviation=0.25,
            min_confidence=0.5,
        ),
    )
    leaks = detector.detect(_tracker_with_actions(["BET_ALL_IN"]).snapshot())

    assert baseline.table_version == "solver-table-v1-action-baseline"
    assert action_baseline_table_sha256(baseline) == action_baseline_table_sha256(baseline)
    assert len(leaks) == 1
    assert leaks[0].reason_id == "LEAK_R008"
    assert leaks[0].baseline_rate == pytest.approx(0.25)


def test_action_baseline_rejects_call_fold_strategy_table():
    table = StrategyTable(
        table_version="solver-table-vs-bet",
        situation_key="dry:IP:river_vs_bet",
        cluster_def_version="cluster-v1",
        source="test",
        entries=(StrategyEntry(combo="AhAd", policy={"CALL": 0.5, "FOLD": 0.5}, reach_prob=1.0),),
    )

    with pytest.raises(ValueError, match="CHECK/BET actions"):
        action_baseline_table_from_strategy_table(table)


def test_leaky_fixture_baseline_is_public_and_deterministic():
    first = leaky_fixture_action_baseline_table()
    second = leaky_fixture_action_baseline_table()
    detector = LeakDetector(
        first,
        LeakDetectorConfig(
            min_effective_sample_size=1,
            min_deviation=0.25,
            min_confidence=0.5,
        ),
    )

    leaks = detector.detect(_tracker_with_actions(["BET_ALL_IN"]).snapshot())

    assert first.table_version == "fixture-action-baseline"
    assert action_baseline_table_sha256(first) == action_baseline_table_sha256(second)
    assert [leak.reason_id for leak in leaks] == ["LEAK_R008"]
