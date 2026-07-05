"""Strategy-profile helpers and validation (P3-1, ADR-0017 sec.7)."""

from __future__ import annotations

import pytest

from poker_solver.games.toy import build_toy_coin
from poker_solver.strategy import (
    normalized_action_dist,
    uniform_profile,
    validate_profile,
)


def test_uniform_profile_is_valid_and_even():
    game = build_toy_coin()
    profile = uniform_profile(game)
    validate_profile(game, profile)
    assert profile["P0"] == {"A": 0.5, "B": 0.5}
    assert profile["P1"] == {"X": 0.5, "Y": 0.5}


def test_normalized_action_dist_scales_to_one():
    dist = normalized_action_dist({"A": 3.0, "B": 1.0}, ("A", "B"))
    assert dist == {"A": 0.75, "B": 0.25}


def test_normalized_action_dist_uniform_fallback_on_zero_mass():
    # ADR-0017 sec.7: an unreached infoset's zero-mass average falls back to uniform.
    dist = normalized_action_dist({"A": 0.0, "B": 0.0}, ("A", "B"))
    assert dist == {"A": 0.5, "B": 0.5}


def test_normalized_action_dist_fills_missing_actions():
    dist = normalized_action_dist({"A": 1.0}, ("A", "B"))
    assert dist == {"A": 1.0, "B": 0.0}


def test_validate_profile_missing_infoset():
    game = build_toy_coin()
    profile = uniform_profile(game)
    del profile["P1"]
    with pytest.raises(ValueError, match="missing infoset"):
        validate_profile(game, profile)


def test_validate_profile_rejects_unnormalized():
    game = build_toy_coin()
    profile = uniform_profile(game)
    profile["P0"] = {"A": 0.6, "B": 0.6}
    with pytest.raises(ValueError, match="sum to"):
        validate_profile(game, profile)


def test_validate_profile_rejects_negative_probability():
    game = build_toy_coin()
    profile = uniform_profile(game)
    profile["P0"] = {"A": 1.5, "B": -0.5}
    with pytest.raises(ValueError, match="< 0"):
        validate_profile(game, profile)


def test_validate_profile_rejects_wrong_action_keys():
    game = build_toy_coin()
    profile = uniform_profile(game)
    profile["P0"] = {"A": 0.5, "Z": 0.5}
    with pytest.raises(ValueError, match="!= actions"):
        validate_profile(game, profile)
