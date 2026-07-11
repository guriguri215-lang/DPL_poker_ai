"""Strict Phase 6 exact-EV compiler and evaluator fixtures."""

from __future__ import annotations

import math

import pytest

import phase6.exact_ev as exact_ev_module
from phase6.exact_ev import (
    EFFICIENCY_STATUS_DEFINED,
    EFFICIENCY_STATUS_ZERO_OPPORTUNITY,
    EV_CONSISTENCY_ABS_TOLERANCE_WIRE,
    EV_DENOMINATOR_ABS_TOLERANCE_WIRE,
    PolicySlice,
    calculate_efficiency,
    compile_strategy_profiles,
    evaluate_exact_ev,
)
from poker_solver.games.kuhn import build_kuhn_game, kuhn_equilibrium
from poker_solver.games.toy import build_toy_coin


def _slice(policy: dict, *, game_id: str = "toy_coin", opponent_id: str = "opp-1"):
    return PolicySlice(game_id=game_id, opponent_id=opponent_id, policy=policy)


def _toy_inputs(
    *,
    hero_player: int = 0,
    opponent: dict | None = None,
    base: dict | None = None,
    final: dict | None = None,
):
    if hero_player == 0:
        return {
            "opponent_policy": _slice(
                {"P1": {"X": 1.0, "Y": 0.0}} if opponent is None else opponent
            ),
            "base_hero_policy": _slice({"P0": {"A": 0.5, "B": 0.5}} if base is None else base),
            "final_hero_policy": _slice({"P0": {"A": 1.0, "B": 0.0}} if final is None else final),
        }
    return {
        "opponent_policy": _slice({"P0": {"A": 1.0, "B": 0.0}} if opponent is None else opponent),
        "base_hero_policy": _slice({"P1": {"X": 0.5, "Y": 0.5}} if base is None else base),
        "final_hero_policy": _slice({"P1": {"X": 0.0, "Y": 1.0}} if final is None else final),
    }


def test_approved_tolerances_have_canonical_fixed_point_wire_values():
    assert EV_CONSISTENCY_ABS_TOLERANCE_WIRE == "0.000000000001"
    assert EV_DENOMINATOR_ABS_TOLERANCE_WIRE == "0.000000000001"


@pytest.mark.parametrize("hero_player", [0, 1], ids=["oop", "ip"])
def test_exact_ev_is_hero_relative_for_both_positions(hero_player):
    result = evaluate_exact_ev(
        build_toy_coin(), hero_player=hero_player, **_toy_inputs(hero_player=hero_player)
    )

    assert result.base_ev.production == pytest.approx(-0.5 if hero_player == 1 else 0.5)
    assert result.final_ev.production == pytest.approx(1.0 if hero_player == 1 else 2.0)
    assert result.oracle_br_ev.production == pytest.approx(result.final_ev.production)
    assert result.efficiency == pytest.approx(1.0)
    assert result.efficiency_status == EFFICIENCY_STATUS_DEFINED
    assert result.base_ev.production == pytest.approx(result.base_ev.independent_leaves)
    assert result.final_ev.production == pytest.approx(result.final_ev.independent_leaves)
    assert result.oracle_br_ev.production == pytest.approx(result.oracle_br_ev.independent_leaves)


def test_final_overlay_copies_every_unmodified_hero_infoset_and_fixes_opponent():
    game = build_kuhn_game()
    equilibrium = kuhn_equilibrium(1.0 / 6.0)
    hero_infosets = game.infosets_of(0)
    opponent_infosets = game.infosets_of(1)
    base = {infoset: equilibrium[infoset] for infoset in hero_infosets}
    opponent = {infoset: equilibrium[infoset] for infoset in opponent_infosets}
    changed_infoset = "P1:J"
    final_overlay = {changed_infoset: {"CHECK": 1.0, "BET": 0.0}}

    profiles = compile_strategy_profiles(
        game,
        hero_player=0,
        opponent_policy=PolicySlice("kuhn", "kuhn-opp", opponent),
        base_hero_policy=PolicySlice("kuhn", "kuhn-opp", base),
        final_hero_policy=PolicySlice("kuhn", "kuhn-opp", final_overlay),
    )

    assert set(profiles.base) == set(game.infosets)
    assert set(profiles.final) == set(game.infosets)
    assert set(profiles.oracle_br) == set(game.infosets)
    assert profiles.final[changed_infoset] == final_overlay[changed_infoset]
    for infoset in hero_infosets:
        if infoset == changed_infoset:
            continue
        assert profiles.final[infoset] == profiles.base[infoset]
        assert profiles.final[infoset] is not profiles.base[infoset]
    for infoset in opponent_infosets:
        assert profiles.base[infoset] == opponent[infoset]
        assert profiles.final[infoset] == opponent[infoset]
        assert profiles.oracle_br[infoset] == opponent[infoset]
    for infoset in hero_infosets:
        assert set(profiles.oracle_br[infoset].values()) <= {0.0, 1.0}
        assert math.fsum(profiles.oracle_br[infoset].values()) == 1.0


def test_base_equals_final_has_zero_gain_without_hiding_positive_opportunity():
    inputs = _toy_inputs(final={})
    result = evaluate_exact_ev(build_toy_coin(), hero_player=0, **inputs)

    assert result.gain == pytest.approx(0.0)
    assert result.opportunity == pytest.approx(1.5)
    assert result.efficiency == pytest.approx(0.0)
    assert result.efficiency_status == EFFICIENCY_STATUS_DEFINED


def test_negative_gain_and_efficiency_are_not_clipped():
    inputs = _toy_inputs(
        opponent={"P1": {"X": 0.75, "Y": 0.25}},
        final={"P0": {"A": 0.0, "B": 1.0}},
    )
    result = evaluate_exact_ev(build_toy_coin(), hero_player=0, **inputs)

    assert result.gain == pytest.approx(-0.75)
    assert result.opportunity == pytest.approx(0.75)
    assert result.efficiency == pytest.approx(-1.0)


@pytest.mark.parametrize(
    ("opponent", "expected_max_opportunity"),
    [
        ({"P1": {"X": 0.5, "Y": 0.5}}, 0.0),
        ({"P1": {"X": 0.5000000000001, "Y": 0.4999999999999}}, 1e-12),
    ],
    ids=["zero", "near-zero"],
)
def test_zero_or_near_zero_opportunity_is_null(opponent, expected_max_opportunity):
    result = evaluate_exact_ev(
        build_toy_coin(),
        hero_player=0,
        **_toy_inputs(opponent=opponent, final={}),
    )

    assert abs(result.opportunity) <= expected_max_opportunity
    assert result.efficiency is None
    assert result.efficiency_status == EFFICIENCY_STATUS_ZERO_OPPORTUNITY


def test_calculate_efficiency_rejects_negative_oracle_opportunity():
    with pytest.raises(ValueError, match="opportunity is negative"):
        calculate_efficiency(base_ev=1.0, final_ev=1.0, oracle_br_ev=0.0)


def test_evaluator_rejects_final_policy_above_a_broken_oracle(monkeypatch):
    monkeypatch.setattr(
        exact_ev_module,
        "best_response_strategy",
        lambda _game, _hero, _profile: {"P0": "B"},
    )
    inputs = _toy_inputs(
        base={"P0": {"A": 0.0, "B": 1.0}},
        final={"P0": {"A": 1.0, "B": 0.0}},
    )

    with pytest.raises(ValueError, match="final policy exceeds the oracle BR"):
        evaluate_exact_ev(build_toy_coin(), hero_player=0, **inputs)


@pytest.mark.parametrize(
    ("field", "bad_policy", "match"),
    [
        ("base_hero_policy", {}, "missing infosets"),
        ("opponent_policy", {}, "missing infosets"),
        ("final_hero_policy", {"P1": {"X": 1.0, "Y": 0.0}}, "wrong-player"),
        ("final_hero_policy", {"P0": {"A": 1.0, "C": 0.0}}, "legal actions"),
        ("final_hero_policy", {"P0": {"A": 0.4, "B": 0.4}}, "not normalized"),
        ("final_hero_policy", {"P0": {"A": math.inf, "B": 0.0}}, "must be finite"),
        ("final_hero_policy", {"P0": {"A": math.nan, "B": 0.0}}, "must be finite"),
    ],
    ids=[
        "incomplete-base",
        "incomplete-opponent",
        "extra-infoset",
        "illegal-action",
        "non-normalized",
        "infinite",
        "nan",
    ],
)
def test_policy_inputs_fail_closed(field, bad_policy, match):
    inputs = _toy_inputs()
    inputs[field] = _slice(bad_policy)

    with pytest.raises(ValueError, match=match):
        compile_strategy_profiles(build_toy_coin(), hero_player=0, **inputs)


@pytest.mark.parametrize(
    ("field", "replacement", "match"),
    [
        (
            "base_hero_policy",
            PolicySlice("another-game", "opp-1", {"P0": {"A": 0.5, "B": 0.5}}),
            "do not join game",
        ),
        (
            "final_hero_policy",
            PolicySlice("toy_coin", "opp-2", {"P0": {"A": 1.0, "B": 0.0}}),
            "opponent_id values do not join",
        ),
    ],
    ids=["game", "opponent"],
)
def test_policy_inputs_require_same_game_and_opponent(field, replacement, match):
    inputs = _toy_inputs()
    inputs[field] = replacement

    with pytest.raises(ValueError, match=match):
        compile_strategy_profiles(build_toy_coin(), hero_player=0, **inputs)


@pytest.mark.parametrize(
    ("divergent_call", "match"),
    [(1, "base"), (2, "final"), (3, "oracle BR")],
)
def test_each_profile_rejects_independent_leaf_path_disagreement(
    monkeypatch, divergent_call, match
):
    real_leaf_evaluator = exact_ev_module.expected_value_by_leaves
    calls = 0

    def divergent_leaf_evaluator(game, profile):
        nonlocal calls
        calls += 1
        value = real_leaf_evaluator(game, profile)
        return value + 1e-6 if calls == divergent_call else value

    monkeypatch.setattr(exact_ev_module, "expected_value_by_leaves", divergent_leaf_evaluator)

    with pytest.raises(ValueError, match=match):
        evaluate_exact_ev(build_toy_coin(), hero_player=0, **_toy_inputs())
