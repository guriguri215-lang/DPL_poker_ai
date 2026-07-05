"""Kuhn poker: value + exploitability only, no strategy assertion (P3-1).

Kuhn's equilibrium is a one-parameter family (alpha in [0, 1/3]); asserting a
particular strategy would be wrong (REV-20260705-phase2-gate2-fable5 sec.6 L1). We
check the game value (-1/18 to player 1) and exploitability ~ 0 across the family.
"""

from __future__ import annotations

import pytest

from poker_solver.best_response import exploitability
from poker_solver.evaluate import expected_value
from poker_solver.games.kuhn import GAME_VALUE_P1, build_kuhn_game, kuhn_equilibrium
from poker_solver.tolerances import GAME_VALUE_ABS_TOL, NON_UNIQUE_ABS_TOL


@pytest.mark.parametrize("alpha", [0.0, 1.0 / 12.0, 1.0 / 6.0, 0.25, 1.0 / 3.0])
def test_kuhn_family_has_value_minus_one_eighteenth(alpha):
    game = build_kuhn_game()
    profile = kuhn_equilibrium(alpha)
    assert expected_value(game, profile) == pytest.approx(GAME_VALUE_P1, abs=GAME_VALUE_ABS_TOL)
    assert pytest.approx(-1.0 / 18.0) == GAME_VALUE_P1


@pytest.mark.parametrize("alpha", [0.0, 1.0 / 12.0, 1.0 / 6.0, 0.25, 1.0 / 3.0])
def test_kuhn_family_is_unexploitable(alpha):
    game = build_kuhn_game()
    profile = kuhn_equilibrium(alpha)
    assert exploitability(game, profile) == pytest.approx(0.0, abs=NON_UNIQUE_ABS_TOL)


def test_kuhn_rejects_alpha_out_of_range():
    with pytest.raises(ValueError, match=r"alpha must be in"):
        kuhn_equilibrium(0.5)


def test_kuhn_non_equilibrium_is_exploitable():
    # Never bluffing and always calling is not an equilibrium: it is exploitable.
    game = build_kuhn_game()
    profile = kuhn_equilibrium(1.0 / 6.0)
    profile["P1:J:facing_bet"] = {"CALL": 1.0, "FOLD": 0.0}  # calling J is a leak
    assert exploitability(game, profile) > NON_UNIQUE_ABS_TOL
