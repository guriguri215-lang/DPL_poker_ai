"""Exact EV evaluation, two independent paths (P3-1, ADR-0017 sec.1)."""

from __future__ import annotations

import pytest

from poker_solver.evaluate import (
    expected_value,
    expected_value_by_leaves,
    player_values,
)
from poker_solver.games.toy import build_toy_coin, build_toy_signal, toy_coin_uniform


def test_toy_signal_ev_matches_hand_calc():
    # bet in H, check in L: u0 = 0.5*(1) + 0.5*(0.5) = 0.75 (see toy module derivation).
    game = build_toy_signal()
    profile = {"P0:H": {"BET": 1.0, "CHECK": 0.0}, "P0:L": {"BET": 0.0, "CHECK": 1.0}}
    assert expected_value(game, profile) == pytest.approx(0.75)


def test_toy_signal_ev_mixed_matches_hand_calc():
    game = build_toy_signal()
    # q_H = 0.5, q_L = 0.5: u0 = 0.5*(0.5*1+0.5*0.5) + 0.5*(0.5*-1+0.5*0.5)
    #                          = 0.5*0.75 + 0.5*(-0.25) = 0.25.
    profile = {"P0:H": {"BET": 0.5, "CHECK": 0.5}, "P0:L": {"BET": 0.5, "CHECK": 0.5}}
    assert expected_value(game, profile) == pytest.approx(0.25)


def test_toy_coin_value_is_half_at_equilibrium():
    game = build_toy_coin()
    assert expected_value(game, toy_coin_uniform()) == pytest.approx(0.5)


def test_two_evaluation_paths_agree():
    # Tree walk vs reach-weighted leaves must match (REV sec.6 layer L4).
    game = build_toy_coin()
    profile = {"P0": {"A": 0.3, "B": 0.7}, "P1": {"X": 0.8, "Y": 0.2}}
    assert expected_value(game, profile) == pytest.approx(expected_value_by_leaves(game, profile))


def test_player_values_are_antisymmetric():
    game = build_toy_coin()
    profile = {"P0": {"A": 0.3, "B": 0.7}, "P1": {"X": 0.8, "Y": 0.2}}
    u0, u1 = player_values(game, profile)
    assert u1 == pytest.approx(-u0)
