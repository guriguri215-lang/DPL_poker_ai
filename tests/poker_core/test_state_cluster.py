"""Tests for the frozen MVP state-cluster classifier (REV-20260702 H-9, Q4).

The taxonomy is frozen for the MVP at v0.1.0. Every board maps to exactly one
cluster (total coverage via the trailing fallback, exclusivity via first-match),
and each of the six clusters is reachable.
"""

from __future__ import annotations

import random

import pytest
from pydantic import ValidationError

from poker_core.card import RANKS, SUITS, Card, parse_cards
from poker_core.state_cluster import (
    ClusterDefinition,
    board_features,
    classify_board,
    cluster_def_version,
    get_cluster_definition,
)

_DECK = [Card(rank, suit) for rank in RANKS for suit in SUITS]

_EXAMPLES = [
    ("As Ks 9s 4s 2h", "river_flush_complete"),  # four to a flush
    ("As Ks 9s 4h 2d", "river_flush_complete"),  # three to a flush
    ("Ts 9d 8h 7c 2s", "river_straight_complete"),  # four to a straight
    ("Ks Kd 8h 4c 2s", "river_paired_board"),  # paired, not straighty/flushy
    ("Ah Kd Qc 7h 2s", "river_high_connected"),  # high, three to a straight
    ("9d 7h 4c 3s 2h", "river_low_disconnected"),  # low board
    ("Kd Th 7c 4s 2h", "river_dry_high_card"),  # high but uncoordinated
]


def test_version_is_frozen():
    # Q4 frozen at 0.1.0 (ADR-0016): no longer a -draft proposal.
    assert cluster_def_version() == "0.1.0"


@pytest.mark.parametrize("board,expected", _EXAMPLES)
def test_representative_boards(board, expected):
    assert classify_board(parse_cards(board)) == expected


def test_flush_takes_precedence_over_straight():
    assert classify_board(parse_cards("Ts 9s 8s 7s 2h")) == "river_flush_complete"


def test_straight_takes_precedence_over_paired():
    # 9-8-7-6 straight board that is also paired: straight wins by precedence.
    assert classify_board(parse_cards("9h 9d 8c 7s 6h")) == "river_straight_complete"


def test_every_board_maps_to_exactly_one_cluster():
    names = set(get_cluster_definition().names)
    rng = random.Random(20260703)
    seen: set[str] = set()
    for _ in range(30_000):
        board = tuple(rng.sample(_DECK, 5))
        cluster = classify_board(board)
        assert cluster in names  # total coverage: always a known cluster
        assert classify_board(board) == cluster  # deterministic
        seen.add(cluster)
    # Reachability: the sample exercises all six clusters.
    assert seen == names


def test_definition_ends_with_single_fallback():
    clusters = get_cluster_definition().clusters
    assert clusters[-1].when == {}
    assert all(rule.when for rule in clusters[:-1])


def test_board_features_basic():
    features = board_features(parse_cards("As Ks Qs Js Ts"))
    assert features.max_suit_count == 5
    assert features.max_window_ranks == 5
    assert features.is_paired is False
    assert features.top_rank == 14


def test_board_features_requires_three_cards():
    with pytest.raises(ValueError, match="at least 3"):
        board_features(parse_cards("As Ks"))


# -- invalid definitions are rejected --------------------------------------


def _definition(clusters: list[dict]) -> dict:
    return {"cluster_def_version": "0.0.0-test", "description": "t", "clusters": clusters}


def test_unknown_constraint_key_rejected():
    bad = _definition([{"name": "x", "when": {"min_flushiness": 3}}, {"name": "fb", "when": {}}])
    with pytest.raises(ValidationError, match="unknown constraint"):
        ClusterDefinition.model_validate(bad)


def test_missing_fallback_rejected():
    bad = _definition([{"name": "x", "when": {"is_paired": True}}])
    with pytest.raises(ValidationError, match="fallback"):
        ClusterDefinition.model_validate(bad)


def test_fallback_must_be_last():
    bad = _definition([{"name": "fb", "when": {}}, {"name": "x", "when": {"is_paired": True}}])
    with pytest.raises(ValidationError, match="fallback"):
        ClusterDefinition.model_validate(bad)


def test_duplicate_cluster_name_rejected():
    bad = _definition(
        [
            {"name": "x", "when": {"is_paired": True}},
            {"name": "x", "when": {}},
        ]
    )
    with pytest.raises(ValidationError, match="duplicate cluster name"):
        ClusterDefinition.model_validate(bad)
