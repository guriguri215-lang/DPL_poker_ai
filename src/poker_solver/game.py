"""Extensive-form game tree for the solver's verification layer (P3-1, ADR-0017).

This module is the shared substrate that the exact EV evaluator, the best
response module and the analytic fixtures (AKQ / Kuhn / hand-computed toy trees)
all build on. It is deliberately independent of any CFR machinery: P3-1 delivers
the *measuring instruments* before the CFR solver (P3-2) exists, so that reach
probability and turn-sign mistakes cannot hide inside "it looks converged"
(REV-20260705-phase2-gate2-fable5 sec.5/sec.6).

Model
-----
A game is a finite tree of three node kinds:

* :class:`Terminal` -- a leaf carrying ``payoff``, the utility to **player 0**
  (the hero). The game is two-player zero-sum, so player 1's utility is
  ``-payoff`` (ADR-0017: every leaf satisfies ``u0 + u1 = 0``). EV is in big
  blinds (ADR-0017 unit ``bb``).
* :class:`Chance` -- a node whose branches are drawn by nature with fixed
  probabilities (e.g. dealing the two players' private combos). Chance
  probabilities are kept separate from the players' reach probabilities so the
  counterfactual construction downstream can exclude the acting player's own
  reach (ADR-0017 sec.4, the most common CFR bug).
* :class:`Decision` -- a node where ``player`` (0 or 1) chooses among ``actions``.
  Every decision node declares the ``infoset`` it belongs to. An *information
  set* groups the decision nodes a player cannot tell apart -- same player, same
  private info, same public action history. Nodes sharing an ``infoset`` string
  MUST agree on ``player`` and ``actions``; :class:`Game` enforces this.

The tree is built bottom-up out of frozen dataclasses; :class:`Game` walks it
once to validate structure and index the information sets.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

#: Absolute tolerance for chance-branch probabilities summing to 1.
CHANCE_SUM_TOLERANCE = 1e-9

#: The two player identifiers in a heads-up game (player 0 = hero).
PLAYERS = (0, 1)


@dataclass(frozen=True, slots=True)
class Terminal:
    """A leaf node holding the payoff to player 0 (player 1 gets ``-payoff``)."""

    payoff: float

    def __post_init__(self) -> None:
        if not isinstance(self.payoff, int | float):
            raise TypeError(f"terminal payoff must be a number, got {self.payoff!r}")


@dataclass(frozen=True, slots=True)
class Chance:
    """A nature node: ``branches`` is ``((probability, child, label), ...)``.

    ``label`` names the outcome (e.g. the dealt cards) for readability and for
    the structural inspection tests; probabilities must be positive and sum to 1.
    """

    branches: tuple[tuple[float, Node, str], ...]

    def __post_init__(self) -> None:
        if not self.branches:
            raise ValueError("chance node needs at least one branch")
        total = 0.0
        for prob, _child, _label in self.branches:
            if not prob > 0:
                raise ValueError(f"chance branch probability must be > 0, got {prob}")
            total += prob
        if abs(total - 1.0) > CHANCE_SUM_TOLERANCE:
            raise ValueError(f"chance branch probabilities must sum to 1, got {total}")


@dataclass(frozen=True, slots=True)
class Decision:
    """A decision node: ``player`` chooses one of ``actions`` (parallel children).

    ``infoset`` is the information-set key. Two decision nodes with the same key
    are indistinguishable to the acting player and must be played identically.
    """

    player: int
    infoset: str
    actions: tuple[str, ...]
    children: tuple[Node, ...]

    def __post_init__(self) -> None:
        if self.player not in PLAYERS:
            raise ValueError(f"decision player must be 0 or 1, got {self.player}")
        if not self.actions:
            raise ValueError(f"decision {self.infoset!r} needs at least one action")
        if len(set(self.actions)) != len(self.actions):
            raise ValueError(f"decision {self.infoset!r} has duplicate actions {self.actions}")
        if len(self.actions) != len(self.children):
            raise ValueError(
                f"decision {self.infoset!r} has {len(self.actions)} actions but "
                f"{len(self.children)} children"
            )

    def child_of(self, action: str) -> Node:
        """The child reached by ``action`` (raises ``KeyError`` if unknown)."""
        for candidate, child in zip(self.actions, self.children, strict=True):
            if candidate == action:
                return child
        raise KeyError(f"action {action!r} not in infoset {self.infoset!r}")


#: A tree node is exactly one of the three kinds above.
Node = Terminal | Chance | Decision


class Game:
    """An indexed, validated extensive-form game rooted at ``root``.

    Construction walks the whole tree once, checking node invariants and building
    the information-set index (key -> owning player and action list). Repeated
    infoset keys are cross-checked for a consistent player and action set.
    """

    __slots__ = ("root", "name", "_infoset_player", "_infoset_actions")

    def __init__(self, root: Node, name: str = "game") -> None:
        self.root = root
        self.name = name
        self._infoset_player: dict[str, int] = {}
        self._infoset_actions: dict[str, tuple[str, ...]] = {}
        self._index(root)

    def _index(self, node: Node) -> None:
        if isinstance(node, Terminal):
            return
        if isinstance(node, Chance):
            for _prob, child, _label in node.branches:
                self._index(child)
            return
        # Decision node: record/verify infoset ownership and action set.
        known_player = self._infoset_player.get(node.infoset)
        if known_player is None:
            self._infoset_player[node.infoset] = node.player
            self._infoset_actions[node.infoset] = node.actions
        else:
            if known_player != node.player:
                raise ValueError(
                    f"infoset {node.infoset!r} used by both player {known_player} "
                    f"and player {node.player}"
                )
            if self._infoset_actions[node.infoset] != node.actions:
                raise ValueError(
                    f"infoset {node.infoset!r} has inconsistent actions "
                    f"{self._infoset_actions[node.infoset]} vs {node.actions}"
                )
        for child in node.children:
            self._index(child)

    # -- infoset queries -----------------------------------------------------

    @property
    def infosets(self) -> tuple[str, ...]:
        """All information-set keys, in first-seen (depth-first) order."""
        return tuple(self._infoset_player)

    def player_of(self, infoset: str) -> int:
        """The player that owns ``infoset``."""
        return self._infoset_player[infoset]

    def actions_of(self, infoset: str) -> tuple[str, ...]:
        """The action list at ``infoset``."""
        return self._infoset_actions[infoset]

    def infosets_of(self, player: int) -> tuple[str, ...]:
        """All infoset keys owned by ``player`` (depth-first order)."""
        return tuple(key for key, owner in self._infoset_player.items() if owner == player)

    # -- traversal helpers ---------------------------------------------------

    def iter_decisions(self) -> Iterator[Decision]:
        """Yield every decision node in the tree (depth-first)."""
        yield from _iter_decisions(self.root)

    def iter_terminals(self) -> Iterator[Terminal]:
        """Yield every terminal node in the tree (depth-first, with repeats)."""
        yield from _iter_terminals(self.root)


def _iter_decisions(node: Node) -> Iterator[Decision]:
    if isinstance(node, Decision):
        yield node
        for child in node.children:
            yield from _iter_decisions(child)
    elif isinstance(node, Chance):
        for _prob, child, _label in node.branches:
            yield from _iter_decisions(child)


def _iter_terminals(node: Node) -> Iterator[Terminal]:
    if isinstance(node, Terminal):
        yield node
    elif isinstance(node, Chance):
        for _prob, child, _label in node.branches:
            yield from _iter_terminals(child)
    elif isinstance(node, Decision):
        for child in node.children:
            yield from _iter_terminals(child)
