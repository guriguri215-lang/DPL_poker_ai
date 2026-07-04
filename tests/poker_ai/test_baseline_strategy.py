"""Tests for the stub base strategy and the per-combo StrategyTable builder."""

from __future__ import annotations

import math

import pytest

from poker_ai.actions import FACING_ALL_IN_ACTIONS
from poker_ai.baseline_strategy import (
    FACING_ALL_IN,
    BaselineStrategy,
    baseline_table_version,
    build_situation_key,
    build_strategy_table,
    get_baseline_strategy,
)
from poker_ai.hand_bucket import (
    BUCKET_NAMES_WEAK_TO_STRONG,
    classify_combo,
    get_bucket_definition,
)
from poker_core.card import parse_cards
from poker_core.combo import Combo
from poker_core.range_model import Range
from poker_core.state_cluster import cluster_def_version

BOARD = parse_cards("Qs Jd 9h 4c 2s")


def test_version_is_stub():
    assert baseline_table_version().endswith("-stub")


def test_all_buckets_covered_with_legal_distributions():
    baseline = get_baseline_strategy()
    for bucket in BUCKET_NAMES_WEAK_TO_STRONG:
        policy = baseline.policy_for(FACING_ALL_IN, bucket)
        assert set(policy) <= set(FACING_ALL_IN_ACTIONS)
        assert math.fsum(policy.values()) == pytest.approx(1.0)


def test_stronger_buckets_call_more():
    baseline = get_baseline_strategy()
    call_freqs = [
        baseline.policy_for(FACING_ALL_IN, bucket).get("CALL", 0.0)
        for bucket in BUCKET_NAMES_WEAK_TO_STRONG
    ]
    assert call_freqs == sorted(call_freqs)  # weak->strong is non-decreasing in CALL


def test_missing_profile_rejected():
    with pytest.raises(ValueError, match="missing hand_bucket"):
        BaselineStrategy(
            baseline_table_version="x",
            description="y",
            profiles={FACING_ALL_IN: {"nuts": {"CALL": 1.0}}},
        )


def test_illegal_action_in_profile_rejected():
    full = {b: {"CALL": 1.0} for b in BUCKET_NAMES_WEAK_TO_STRONG}
    full["air"] = {"BET_75": 1.0}
    with pytest.raises(ValueError, match="non-facing-all-in"):
        BaselineStrategy(
            baseline_table_version="x",
            description="y",
            profiles={FACING_ALL_IN: full},
        )


def test_build_strategy_table_validates_and_matches_policy_for():
    hero_range = Range({"QhQd": 1.0, "TdTs": 1.0, "7h7c": 1.0, "3h5c": 1.0})
    situation_key = build_situation_key("river_paired_board", "IP", FACING_ALL_IN)
    table = build_strategy_table(
        situation_key=situation_key,
        cluster_def_version=cluster_def_version(),
        facing_state=FACING_ALL_IN,
        hero_range=hero_range,
        board=BOARD,
        bucket_def=get_bucket_definition(),
    )
    # The frozen StrategyTable contract accepted the table (no duplicate combos etc.)
    assert len(table.entries) == 4
    assert table.situation_key == situation_key
    # Each per-combo entry equals the base policy of that combo's bucket.
    baseline = get_baseline_strategy()
    for entry in table.entries:
        combo = Combo.from_str(entry.combo)
        bucket = classify_combo(combo, hero_range, BOARD)
        assert entry.policy == baseline.policy_for(FACING_ALL_IN, bucket)
    # Reach probabilities are a normalised distribution.
    assert math.fsum(e.reach_prob for e in table.entries) == pytest.approx(1.0)


def test_build_strategy_table_aggregate_is_a_distribution():
    hero_range = Range({"QhQd": 1.0, "TdTs": 1.0, "7h7c": 1.0, "3h5c": 1.0})
    table = build_strategy_table(
        situation_key=build_situation_key("river_paired_board", "OOP", FACING_ALL_IN),
        cluster_def_version=cluster_def_version(),
        facing_state=FACING_ALL_IN,
        hero_range=hero_range,
        board=BOARD,
        bucket_def=get_bucket_definition(),
    )
    aggregate = table.aggregate_policy()
    assert math.fsum(aggregate.values()) == pytest.approx(1.0)


def test_build_strategy_table_rejects_all_blocked_range():
    # A range whose only combo is blocked by the board yields no legal entry.
    hero_range = Range({"QsJs": 1.0})  # Qs and Js both interact with the board (Qs on board)
    with pytest.raises(ValueError, match="no board-legal"):
        build_strategy_table(
            situation_key=build_situation_key("river_paired_board", "IP", FACING_ALL_IN),
            cluster_def_version=cluster_def_version(),
            facing_state=FACING_ALL_IN,
            hero_range=hero_range,
            board=BOARD,
            bucket_def=get_bucket_definition(),
        )
