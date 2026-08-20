"""Tests for the action-only leak detector."""

from __future__ import annotations

import math
from decimal import Decimal, localcontext
from math import comb

import pytest

from poker_ai.leak import (
    BET_ACTIONS,
    ActionBaselineTable,
    ActionLeakRule,
    LeakDetector,
    LeakDetectorConfig,
    action_baseline_table_from_strategy_table,
    action_baseline_table_sha256,
    beta_binomial_upper_tail,
    classify_ground_truth_boundary,
    leaky_fixture_action_baseline_table,
    leaky_r007_fixture_action_baseline_table,
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
    assert leak.confidence == pytest.approx(0.8125)


def test_r007_fixture_baseline_detects_public_check_backs_only():
    detector = LeakDetector(
        leaky_r007_fixture_action_baseline_table(),
        LeakDetectorConfig(
            min_effective_sample_size=1,
            min_deviation=0.25,
            min_confidence=0.5,
        ),
    )
    tracker = _tracker_with_actions(["CHECK", "CHECK"])

    leaks = detector.detect(tracker.snapshot())

    assert [leak.reason_id for leak in leaks] == ["LEAK_R007"]
    assert leaks[0].observed_rate == 1.0


def test_negative_case_below_sample_floor():
    tracker = _tracker_with_actions(["BET_ALL_IN", "BET_ALL_IN", "BET_ALL_IN"])
    leaks = _detector(baseline_rate=0.0, min_effective_sample_size=4).detect(tracker.snapshot())
    assert leaks == []


def test_negative_case_below_deviation_threshold():
    tracker = _tracker_with_actions(["BET_ALL_IN", "BET_ALL_IN", "CHECK", "CHECK"])
    leaks = _detector(baseline_rate=0.30, min_deviation=0.25).detect(tracker.snapshot())
    assert leaks == []


def test_negative_case_below_posterior_confidence_threshold():
    tracker = _tracker_with_actions(["BET_ALL_IN", "BET_ALL_IN", "BET_ALL_IN", "CHECK"])
    leaks = _detector(
        baseline_rate=0.25,
        min_effective_sample_size=4,
        min_deviation=0.25,
        min_confidence=0.9,
    ).detect(tracker.snapshot())
    assert leaks == []


def test_structurally_ineligible_q_is_not_emitted():
    tracker = _tracker_with_actions(["BET_ALL_IN"] * 20)
    assert _detector(baseline_rate=0.75, min_confidence=0.0).detect(tracker.snapshot()) == []


def test_threshold_boundary_is_inclusive():
    tracker = _tracker_with_actions(["BET_ALL_IN", "BET_ALL_IN", "BET_ALL_IN", "CHECK"])
    leaks = _detector(baseline_rate=0.50, min_deviation=0.25, min_confidence=0.3).detect(
        tracker.snapshot()
    )
    assert len(leaks) == 1
    assert leaks[0].observed_rate - leaks[0].baseline_rate == pytest.approx(0.25)
    assert leaks[0].confidence == pytest.approx(0.3671875)


def _decimal_binomial_cdf(*, k: int, n: int, q: str) -> Decimal:
    with localcontext() as context:
        context.prec = 80
        probability = Decimal(q)
        one_minus = Decimal(1) - probability
        return sum(
            Decimal(comb(n + 1, j)) * probability**j * one_minus ** (n + 1 - j)
            for j in range(k + 1)
        )


@pytest.mark.parametrize(
    ("k", "n", "baseline", "tau", "expected"),
    [
        (0, 0, 0.25, 0.25, 0.5),
        (3, 4, 0.25, 0.25, 0.8125),
        (10, 10, 0.0, 0.25, 0.9999997615814209),
        (0, 10, 0.0, 0.25, 0.04223513603210449),
    ],
)
def test_beta_binomial_upper_tail_known_values(k, n, baseline, tau, expected):
    assert beta_binomial_upper_tail(
        k=k,
        n=n,
        baseline_rate=baseline,
        tau=tau,
    ) == pytest.approx(expected, abs=1e-14)


def test_beta_binomial_upper_tail_matches_independent_decimal_reference():
    expected = _decimal_binomial_cdf(k=731, n=1000, q="0.712345678901")
    actual = beta_binomial_upper_tail(
        k=731,
        n=1000,
        baseline_rate=0.462345678901,
        tau=0.25,
    )
    assert actual == pytest.approx(float(expected), abs=1e-12)
    assert math.isfinite(actual)
    assert 0.0 <= actual <= 1.0


def test_beta_binomial_upper_tail_is_monotone_in_success_count():
    scores = [beta_binomial_upper_tail(k=k, n=100, baseline_rate=0.4, tau=0.25) for k in range(101)]
    assert scores == sorted(scores)


def test_beta_binomial_upper_tail_q_boundary_and_invalid_inputs():
    assert beta_binomial_upper_tail(k=10, n=10, baseline_rate=0.75, tau=0.25) == 0.0
    with pytest.raises(ValueError, match="0 <= k <= n"):
        beta_binomial_upper_tail(k=2, n=1, baseline_rate=0.0, tau=0.25)
    with pytest.raises(ValueError, match="tau"):
        beta_binomial_upper_tail(k=0, n=1, baseline_rate=0.0, tau=0.0)


def test_action_group_duplicates_are_rejected_before_counting():
    with pytest.raises(ValueError, match="duplicate actions"):
        ActionLeakRule(
            reason_id="LEAK_R008",
            leak_type="bet_too_often_when_checked_to",
            action_group=("BET", "BET"),
            baseline_rate=0.25,
            direction="decrease_bet_frequency_when_checked_to",
        )


def test_ground_truth_decimal_boundary_policy_is_deterministic():
    assert classify_ground_truth_boundary(p_true="0.75", q="0.75") == "indifference"
    assert classify_ground_truth_boundary(p_true="0.750000000001", q="0.75") == "indifference"
    assert classify_ground_truth_boundary(p_true="0.750000000002", q="0.75") == "positive"
    assert classify_ground_truth_boundary(p_true="0.749999999998", q="0.75") == "negative"
    with pytest.raises(TypeError, match="not floats"):
        classify_ground_truth_boundary(p_true=0.75, q="0.75")


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
