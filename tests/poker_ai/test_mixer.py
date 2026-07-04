"""Tests for the SafetyMixer and the seeded ActionSelector (AI Spec 6.8/6.9)."""

from __future__ import annotations

import math

import pytest

from poker_ai.mixer import ActionSelector, is_pure_base, safety_mix
from poker_core.dpl_schema import MIXING_ABS_TOL

BASE = {"FOLD": 0.7, "CALL": 0.3}
EXPLOIT = {"FOLD": 0.2, "CALL": 0.8}


def test_alpha_zero_final_equals_base():
    final = safety_mix(BASE, EXPLOIT, 0.0)
    assert is_pure_base(BASE, final)
    assert final == pytest.approx(BASE)


def test_alpha_one_final_equals_exploit():
    # Pure mixer math; the task-3 session never runs at alpha > 0.
    final = safety_mix(BASE, EXPLOIT, 1.0)
    assert final == pytest.approx(EXPLOIT)


def test_mid_alpha_is_convex_combination():
    final = safety_mix(BASE, EXPLOIT, 0.25)
    assert final["FOLD"] == pytest.approx(0.75 * 0.7 + 0.25 * 0.2)
    assert final["CALL"] == pytest.approx(0.75 * 0.3 + 0.25 * 0.8)
    assert math.fsum(final.values()) == pytest.approx(1.0)


def test_mix_over_disjoint_actions_unions_them():
    final = safety_mix({"FOLD": 1.0}, {"CALL": 1.0}, 0.3)
    assert final == pytest.approx({"FOLD": 0.7, "CALL": 0.3})


def test_safety_mix_rejects_bad_alpha():
    with pytest.raises(ValueError, match="alpha"):
        safety_mix(BASE, EXPLOIT, 1.5)


def test_safety_mix_rejects_unnormalised_policy():
    with pytest.raises(ValueError, match="sum to 1.0"):
        safety_mix({"FOLD": 0.5, "CALL": 0.2}, EXPLOIT, 0.0)


def test_action_selector_is_reproducible():
    a = ActionSelector(12345).select(BASE)
    b = ActionSelector(12345).select(BASE)
    assert a == b


def test_action_selector_only_returns_positive_mass_actions():
    # FOLD has zero mass; the selector must always return CALL.
    assert ActionSelector(1).select({"FOLD": 0.0, "CALL": 1.0}) == "CALL"


def test_action_selector_distribution_is_roughly_proportional():
    selector = ActionSelector(2024)
    counts = {"FOLD": 0, "CALL": 0}
    for _ in range(4000):
        counts[selector.select(BASE)] += 1
    assert counts["FOLD"] / 4000 == pytest.approx(0.7, abs=0.05)


def test_action_selector_raises_on_empty_mass():
    with pytest.raises(ValueError, match="positive probability"):
        ActionSelector(1).select({"FOLD": 0.0, "CALL": 0.0})


def test_is_pure_base_detects_deviation():
    assert not is_pure_base(BASE, {"FOLD": 0.7 + 10 * MIXING_ABS_TOL, "CALL": 0.3})
