r"""Tiny hand-computed toy trees (ADR-0017 / REV sec.6 layer L2 unit tests).

These depth-2..3 trees have every number worked out by hand in the comments, so
the EV evaluator, the reach decomposition and the best-response module can be
unit-tested against fully explicit values -- the last line of defence against a
turn-sign or counterfactual-reach mistake that larger fixtures might mask.

toy_coin
--------
A matching-pennies-shaped tree that exercises **infoset-level** best response.
Player 0 picks ``A`` or ``B`` at infoset ``"P0"``; player 1, at the single
infoset ``"P1"`` (it cannot see player 0's move -- both nodes share the key),
picks ``X`` or ``Y``. Player-0 payoffs::

        X     Y
    A   +2   -1
    B   -1   +2

This is symmetric zero-sum with value ``+0.5`` to player 0 at the mixed
equilibrium ``P(A) = P(X) = 1/2`` (payoff ``(2 - 1 - 1 + 2)/4``). Because player
1 has one infoset over two nodes, a *node-level* max would let it cheat on player
0's hidden move; the correct infoset-level best response may not.

  * Under both-uniform, ``u0 = 0.5`` and exploitability ``= 0`` (equilibrium).
  * Against ``P1 = {X:1}`` with ``P0`` uniform: BR for P0 is ``A`` worth ``2``;
    ``u0 = 0.5``; BR for P1 vs uniform P0 is worth ``-0.5`` (player-1 utility);
    NashConv ``= (2 - 0.5) + (-0.5 - (-0.5)) = 1.5`` -> exploitability ``0.75``.

toy_signal
----------
A chance + single-player tree for the reach decomposition and EV. Nature deals
``H`` or ``L`` (prob 1/2 each); player 0 then bets or checks knowing its signal::

    H: BET -> +1.0 , CHECK -> +0.5
    L: BET -> -1.0 , CHECK -> +0.5

There is no opponent. Combined leaf reach always sums to 1, and for the profile
``BET`` w.p. ``q_H`` in H and ``q_L`` in L::

    u0 = 0.5*(q_H*1 + (1-q_H)*0.5) + 0.5*(q_L*(-1) + (1-q_L)*0.5)
"""

from __future__ import annotations

from ..game import Chance, Decision, Game, Terminal
from ..strategy import StrategyProfile


def build_toy_coin() -> Game:
    """The matching-pennies-shaped toy (see module docstring)."""
    node_a = Decision(
        player=1,
        infoset="P1",
        actions=("X", "Y"),
        children=(Terminal(2.0), Terminal(-1.0)),
    )
    node_b = Decision(
        player=1,
        infoset="P1",
        actions=("X", "Y"),
        children=(Terminal(-1.0), Terminal(2.0)),
    )
    root = Decision(
        player=0,
        infoset="P0",
        actions=("A", "B"),
        children=(node_a, node_b),
    )
    return Game(root, name="toy_coin")


def toy_coin_uniform() -> StrategyProfile:
    """Both players uniform -- the equilibrium of ``toy_coin`` (value 0.5)."""
    return {"P0": {"A": 0.5, "B": 0.5}, "P1": {"X": 0.5, "Y": 0.5}}


def build_toy_signal() -> Game:
    """The chance + single-player toy for reach / EV tests (see module docstring)."""
    decision_h = Decision(
        player=0,
        infoset="P0:H",
        actions=("BET", "CHECK"),
        children=(Terminal(1.0), Terminal(0.5)),
    )
    decision_l = Decision(
        player=0,
        infoset="P0:L",
        actions=("BET", "CHECK"),
        children=(Terminal(-1.0), Terminal(0.5)),
    )
    root = Chance(((0.5, decision_h, "H"), (0.5, decision_l, "L")))
    return Game(root, name="toy_signal")
