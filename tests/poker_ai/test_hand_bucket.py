"""Tests for the hand-bucket percentile classifier (Q5 proposal, ADR-0005)."""

from __future__ import annotations

import pytest

from poker_ai.hand_bucket import (
    BUCKET_NAMES_WEAK_TO_STRONG,
    BucketDefinition,
    bucket_def_version,
    classify_combo,
    get_bucket_definition,
    load_bucket_definition,
    strength_percentile,
)
from poker_core.card import parse_cards
from poker_core.combo import Combo
from poker_core.dpl_schema import HandBucket
from poker_core.range_model import Range

BOARD = parse_cards("Qs Jd 9h 4c 2s")


def test_names_match_frozen_dpl_enum():
    # The band names must equal the frozen DPL hand_bucket literal, in weak->strong
    # order, so the classifier can never emit an out-of-contract class.
    assert set(BUCKET_NAMES_WEAK_TO_STRONG) == set(HandBucket.__args__)
    assert get_bucket_definition().buckets[0].name == "air"
    assert get_bucket_definition().buckets[-1].name == "nuts"


def test_version_is_frozen():
    # Q5 frozen at 0.1.0 (ADR-0015): no longer a -draft proposal.
    assert bucket_def_version() == "0.1.0"


@pytest.mark.parametrize(
    ("percentile", "expected"),
    [
        (0.0, "air"),
        (0.19, "air"),
        (0.20, "weak_showdown"),
        (0.44, "weak_showdown"),
        (0.45, "marginal"),
        (0.69, "marginal"),
        (0.70, "strong_value"),
        (0.89, "strong_value"),
        (0.90, "nuts"),
        (0.999, "nuts"),
    ],
)
def test_classify_boundaries(percentile, expected):
    assert get_bucket_definition().classify(percentile) == expected


def test_classify_rejects_out_of_range_percentile():
    with pytest.raises(ValueError, match="percentile"):
        get_bucket_definition().classify(1.0)


def test_strength_percentile_orders_by_strength():
    # Trip queens is the strongest; a 5-high (3h5c) is the weakest.
    hero_range = Range({"QhQd": 1.0, "TdTs": 1.0, "7h7c": 1.0, "3h5c": 1.0})
    nuts = strength_percentile(Combo.from_str("QhQd"), hero_range, BOARD)
    worst = strength_percentile(Combo.from_str("3h5c"), hero_range, BOARD)
    assert nuts == pytest.approx(0.75)  # 3 of 4 combos are weaker
    assert worst == pytest.approx(0.0)  # nothing is weaker


def test_classify_combo_maps_to_band():
    hero_range = Range({"QhQd": 1.0, "TdTs": 1.0, "7h7c": 1.0, "3h5c": 1.0})
    assert classify_combo(Combo.from_str("QhQd"), hero_range, BOARD) == "strong_value"
    assert classify_combo(Combo.from_str("3h5c"), hero_range, BOARD) == "air"


def test_percentile_rejects_board_blocked_combo():
    hero_range = Range({"QhQd": 1.0})
    with pytest.raises(ValueError, match="blocked"):
        strength_percentile(Combo.from_str("QsJs"), hero_range, BOARD)


def test_percentile_rejects_combo_absent_from_range():
    hero_range = Range({"QhQd": 1.0})
    with pytest.raises(ValueError, match="member of hero_range"):
        strength_percentile(Combo.from_str("TdTs"), hero_range, BOARD)


def _write(tmp_path, text: str):
    path = tmp_path / "bucket.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_load_rejects_wrong_names(tmp_path):
    bad = _write(
        tmp_path,
        "bucket_def_version: x\ndescription: y\nbuckets:\n"
        "  - {name: air, max_percentile: 0.5}\n"
        "  - {name: nuts, max_percentile: null}\n",
    )
    with pytest.raises(ValueError, match="frozen DPL hand_bucket enum"):
        load_bucket_definition(bad)


def test_load_rejects_non_monotone_bounds(tmp_path):
    bad = _write(
        tmp_path,
        "bucket_def_version: x\ndescription: y\nbuckets:\n"
        "  - {name: air, max_percentile: 0.5}\n"
        "  - {name: weak_showdown, max_percentile: 0.4}\n"
        "  - {name: marginal, max_percentile: 0.6}\n"
        "  - {name: strong_value, max_percentile: 0.8}\n"
        "  - {name: nuts, max_percentile: null}\n",
    )
    with pytest.raises(ValueError, match="strictly increase"):
        load_bucket_definition(bad)


def test_load_rejects_open_non_top_band(tmp_path):
    bad = _write(
        tmp_path,
        "bucket_def_version: x\ndescription: y\nbuckets:\n"
        "  - {name: air, max_percentile: null}\n"
        "  - {name: weak_showdown, max_percentile: 0.4}\n"
        "  - {name: marginal, max_percentile: 0.6}\n"
        "  - {name: strong_value, max_percentile: 0.8}\n"
        "  - {name: nuts, max_percentile: null}\n",
    )
    with pytest.raises(ValueError, match="only the strongest band"):
        load_bucket_definition(bad)


def test_bucket_band_rejects_out_of_unit_bound():
    with pytest.raises(ValueError, match="max_percentile"):
        BucketDefinition(
            bucket_def_version="x",
            description="y",
            buckets=(
                {"name": "air", "max_percentile": 1.5},
                {"name": "weak_showdown", "max_percentile": 0.4},
                {"name": "marginal", "max_percentile": 0.6},
                {"name": "strong_value", "max_percentile": 0.8},
                {"name": "nuts", "max_percentile": None},
            ),
        )
