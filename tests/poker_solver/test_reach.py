"""Reach-probability decomposition (P3-1, ADR-0017 sec.4)."""

from __future__ import annotations

import pytest

from poker_solver.games.toy import build_toy_coin, build_toy_signal
from poker_solver.reach import leaf_reaches, total_reach


def test_toy_signal_reach_factorises_by_chance_and_player0():
    # Profile: bet in H, check in L. Only two leaves are reachable, each 0.5.
    game = build_toy_signal()
    profile = {"P0:H": {"BET": 1.0, "CHECK": 0.0}, "P0:L": {"BET": 0.0, "CHECK": 1.0}}
    reaches = leaf_reaches(game, profile)
    positive = [lr for lr in reaches if lr.combined > 0]
    assert len(positive) == 2
    for lr in positive:
        assert lr.chance == pytest.approx(0.5)
        assert lr.player1 == pytest.approx(1.0)  # no player-1 decisions
        assert lr.combined == pytest.approx(0.5)
    assert total_reach(game, profile) == pytest.approx(1.0)


def test_toy_coin_counterfactual_uses_opponent_reach_only():
    # Under both-uniform, each of player 1's two infoset nodes is reached with
    # opponent (player 0) probability 0.5 and chance 1.0.
    game = build_toy_coin()
    profile = {"P0": {"A": 0.5, "B": 0.5}, "P1": {"X": 0.5, "Y": 0.5}}
    reaches = leaf_reaches(game, profile)
    assert len(reaches) == 4
    for lr in reaches:
        assert lr.chance == pytest.approx(1.0)
        assert lr.player0 == pytest.approx(0.5)
        assert lr.player1 == pytest.approx(0.5)
        assert lr.combined == pytest.approx(0.25)
    assert total_reach(game, profile) == pytest.approx(1.0)


def test_total_reach_is_one_for_skewed_profile():
    game = build_toy_coin()
    profile = {"P0": {"A": 0.9, "B": 0.1}, "P1": {"X": 0.3, "Y": 0.7}}
    assert total_reach(game, profile) == pytest.approx(1.0)
