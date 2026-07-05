"""Reach-probability decomposition for a game under a strategy profile.

Every terminal is reached along one root-to-leaf path. The probability of that
path factorises into three independent contributions (ADR-0017 sec.4):

* ``chance`` -- the product of the nature probabilities on the path,
* ``player0`` -- the product of player 0's action probabilities on the path,
* ``player1`` -- the product of player 1's action probabilities on the path.

Keeping the three separate is exactly what the best-response / counterfactual
construction needs: the counterfactual reach of an acting player's information
set excludes that player's own contribution and multiplies only the *others*
(chance and the opponent). Collapsing them early is the most common CFR bug, so
P3-1 exposes them explicitly and the invariant tests assert that the combined
leaf reach (product of all three) sums to 1.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .game import Chance, Game, Node, Terminal
from .strategy import StrategyProfile


@dataclass(frozen=True, slots=True)
class LeafReach:
    """A terminal leaf with its factorised reach probabilities."""

    terminal: Terminal
    chance: float
    player0: float
    player1: float

    @property
    def combined(self) -> float:
        """Total probability of reaching this leaf: ``chance * player0 * player1``."""
        return self.chance * self.player0 * self.player1


def leaf_reaches(game: Game, profile: StrategyProfile) -> list[LeafReach]:
    """Every leaf paired with its (chance, player0, player1) reach probabilities."""
    leaves: list[LeafReach] = []
    _walk(game.root, profile, 1.0, 1.0, 1.0, leaves)
    return leaves


def total_reach(game: Game, profile: StrategyProfile) -> float:
    """Sum of combined leaf reach; equals 1 for any valid profile (invariant)."""
    return math.fsum(leaf.combined for leaf in leaf_reaches(game, profile))


def _walk(
    node: Node,
    profile: StrategyProfile,
    chance: float,
    reach0: float,
    reach1: float,
    out: list[LeafReach],
) -> None:
    if isinstance(node, Terminal):
        out.append(LeafReach(node, chance, reach0, reach1))
        return
    if isinstance(node, Chance):
        for prob, child, _label in node.branches:
            _walk(child, profile, chance * prob, reach0, reach1, out)
        return
    dist = profile[node.infoset]
    for action, child in zip(node.actions, node.children, strict=True):
        prob = dist[action]
        if node.player == 0:
            _walk(child, profile, chance, reach0 * prob, reach1, out)
        else:
            _walk(child, profile, chance, reach0, reach1 * prob, out)
