"""Exact expected-value evaluation of a strategy profile (ADR-0017 sec.1/sec.2).

The value of a profile is player 0's expected utility with the tree solved
exactly (full enumeration, no sampling), so it is deterministic and seedless.
Two independent evaluation paths are provided and are asserted to agree in the
tests (REV-20260705-phase2-gate2-fable5 sec.6 L4):

* :func:`expected_value` -- a top-down recursive tree walk.
* :func:`expected_value_by_leaves` -- the reach-weighted sum over terminals,
  using the factorised reach probabilities from :mod:`poker_solver.reach`.

Player 1's utility is ``-expected_value`` by the zero-sum convention; helpers
expose per-player values for symmetry checks.
"""

from __future__ import annotations

import math

from .game import Chance, Game, Node, Terminal
from .reach import leaf_reaches
from .strategy import StrategyProfile, validate_profile


def expected_value(game: Game, profile: StrategyProfile, *, validate: bool = True) -> float:
    """Player 0's exact expected utility (bb) under ``profile`` via a tree walk."""
    if validate:
        validate_profile(game, profile)
    return _value(game.root, profile)


def expected_value_by_leaves(
    game: Game, profile: StrategyProfile, *, validate: bool = True
) -> float:
    """Player 0's expected utility computed as ``sum(combined_reach * payoff)``.

    An independent second path used to cross-check :func:`expected_value`.
    """
    if validate:
        validate_profile(game, profile)
    return math.fsum(leaf.combined * leaf.terminal.payoff for leaf in leaf_reaches(game, profile))


def player_values(game: Game, profile: StrategyProfile) -> tuple[float, float]:
    """Both players' expected utilities ``(u0, u1)`` with ``u1 == -u0`` (zero-sum)."""
    u0 = expected_value(game, profile)
    return u0, -u0


def _value(node: Node, profile: StrategyProfile) -> float:
    if isinstance(node, Terminal):
        return node.payoff
    if isinstance(node, Chance):
        return math.fsum(prob * _value(child, profile) for prob, child, _label in node.branches)
    dist = profile[node.infoset]
    return math.fsum(
        dist[action] * _value(child, profile)
        for action, child in zip(node.actions, node.children, strict=True)
    )
