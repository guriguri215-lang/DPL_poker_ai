"""Tests for the river action vocabulary and legal-set gating (task 3)."""

from __future__ import annotations

import pytest

from poker_ai.actions import (
    ALL_ACTIONS,
    FACING_ACTIONS,
    FACING_ALL_IN_ACTIONS,
    NO_FACING_ACTIONS,
    legal_actions,
)


def test_vocabulary_is_disjoint_and_complete():
    assert set(NO_FACING_ACTIONS).isdisjoint(FACING_ACTIONS)
    assert set(ALL_ACTIONS) == set(NO_FACING_ACTIONS) | set(FACING_ACTIONS)


def test_facing_all_in_is_fold_call():
    assert legal_actions(facing_bet=True, bet_is_all_in=True) == FACING_ALL_IN_ACTIONS
    assert FACING_ALL_IN_ACTIONS == ("FOLD", "CALL")


def test_no_facing_is_not_scored_yet():
    with pytest.raises(NotImplementedError, match="no-facing"):
        legal_actions(facing_bet=False, bet_is_all_in=False)


def test_facing_non_all_in_is_not_scored_yet():
    with pytest.raises(NotImplementedError, match="non all-in"):
        legal_actions(facing_bet=True, bet_is_all_in=False)
