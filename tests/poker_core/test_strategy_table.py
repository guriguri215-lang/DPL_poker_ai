"""Tests for the StrategyTable contract v1 (ADR-0006 freeze; ADR-0005, REV M-3)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from poker_core.strategy_table import STRATEGY_TABLE_SCHEMA_VERSION, StrategyTable


def test_valid_strategy_table_round_trips(valid_strategy_table):
    table = StrategyTable.model_validate(valid_strategy_table)
    assert table.schema_version == STRATEGY_TABLE_SCHEMA_VERSION
    assert len(table.entries) == 2
    again = StrategyTable.model_validate_json(table.model_dump_json())
    assert again == table


def test_aggregate_policy_is_reach_weighted(valid_strategy_table):
    table = StrategyTable.model_validate(valid_strategy_table)
    agg = table.aggregate_policy()
    # 0.6*{0.2,0.8} + 0.4*{0.7,0.3} = {0.40, 0.60}
    assert agg["CHECK"] == pytest.approx(0.40)
    assert agg["BET_75"] == pytest.approx(0.60)
    assert sum(agg.values()) == pytest.approx(1.0)


def test_empty_entries_rejected(valid_strategy_table):
    valid_strategy_table["entries"] = []
    with pytest.raises(ValidationError, match="at least one entry"):
        StrategyTable.model_validate(valid_strategy_table)


def test_duplicate_combos_rejected(valid_strategy_table):
    valid_strategy_table["entries"][1]["combo"] = "AhKh"  # same as entry 0
    with pytest.raises(ValidationError, match="duplicate combos"):
        StrategyTable.model_validate(valid_strategy_table)


def test_entry_policy_must_sum_to_one(valid_strategy_table):
    valid_strategy_table["entries"][0]["policy"] = {"CHECK": 0.2, "BET_75": 0.2}
    with pytest.raises(ValidationError, match="sum to 1.0"):
        StrategyTable.model_validate(valid_strategy_table)


def test_reach_prob_out_of_range_rejected(valid_strategy_table):
    valid_strategy_table["entries"][0]["reach_prob"] = 1.5
    with pytest.raises(ValidationError):
        StrategyTable.model_validate(valid_strategy_table)


def test_unsupported_schema_version_rejected(valid_strategy_table):
    valid_strategy_table["schema_version"] = "0.1.0"
    with pytest.raises(ValidationError, match="unsupported StrategyTable schema_version"):
        StrategyTable.model_validate(valid_strategy_table)


def test_zero_total_reach_cannot_aggregate(valid_strategy_table):
    for entry in valid_strategy_table["entries"]:
        entry["reach_prob"] = 0.0
    table = StrategyTable.model_validate(valid_strategy_table)
    with pytest.raises(ValueError, match="total reach probability is zero"):
        table.aggregate_policy()
