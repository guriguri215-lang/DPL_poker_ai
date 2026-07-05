"""Best response and exploitability -- the independent verifier (ADR-0017 sec.3/sec.4).

This module computes, for a fixed strategy profile, each player's best response
value and the profile's exploitability. It is written to be **independent of any
CFR implementation**: it never reads CFR regret tables or utility caches, only
the game tree and the profile. This is the ADR-0017 sec.4 rule (and the Phase 5
Verifier discipline) -- an exploitability derived from a solver's own internal
numbers is self-verifying and hides "it looks converged" bugs.

Best response with imperfect information
----------------------------------------
The responding player must play one action per *information set*, not per node,
because it cannot tell apart the nodes in an infoset. So the best action is the
one maximising the **counterfactual-reach-weighted** value across the whole
infoset (summing over the nodes in it), where the counterfactual reach uses only
chance and the opponent's probabilities -- never the responder's own reach
(ADR-0017 sec.4). With perfect recall this per-infoset argmax, evaluated with deeper
infosets already best-responded, gives the exact best response.

Exploitability
--------------
For a two-player zero-sum game::

    NashConv(sigma) = sum_i [ max_{sigma'_i} u_i(sigma'_i, sigma_{-i}) - u_i(sigma) ]
    exploitability  = NashConv / 2      (unit: bb/hand, ADR-0017 sec.3)

``u1(sigma) = -u0(sigma)`` by zero-sum, so both bracket terms are non-negative and
exploitability >= 0 always (an invariant test asserts this).
"""

from __future__ import annotations

import math

from .evaluate import expected_value
from .game import Chance, Decision, Game, Node, Terminal
from .strategy import StrategyProfile, validate_profile


def _util_to(payoff: float, player: int) -> float:
    """Player-0 ``payoff`` re-expressed as ``player``'s own utility (zero-sum)."""
    return payoff if player == 0 else -payoff


class _BestResponder:
    """Computes ``br_player``'s best response value against a fixed profile."""

    def __init__(self, game: Game, br_player: int, profile: StrategyProfile) -> None:
        self.game = game
        self.br_player = br_player
        self.opponent = 1 - br_player
        self.profile = profile
        # infoset -> list of (node, counterfactual_reach) for br_player's infosets.
        self._infoset_nodes: dict[str, list[tuple[Decision, float]]] = {}
        self._collect(game.root, 1.0)
        self._value_memo: dict[int, float] = {}
        self._best_action_memo: dict[str, str] = {}

    def _collect(self, node: Node, cf_reach: float) -> None:
        """Index br_player's infoset nodes with chance+opponent reach only."""
        if isinstance(node, Terminal):
            return
        if isinstance(node, Chance):
            for prob, child, _label in node.branches:
                self._collect(child, cf_reach * prob)
            return
        if node.player == self.br_player:
            self._infoset_nodes.setdefault(node.infoset, []).append((node, cf_reach))
            for child in node.children:
                self._collect(child, cf_reach)  # responder's own reach excluded
        else:
            dist = self.profile[node.infoset]
            for action, child in zip(node.actions, node.children, strict=True):
                self._collect(child, cf_reach * dist[action])

    def _value(self, node: Node) -> float:
        """br_player's utility of the subtree, playing best response within it."""
        if isinstance(node, Terminal):
            return _util_to(node.payoff, self.br_player)
        key = id(node)
        cached = self._value_memo.get(key)
        if cached is not None:
            return cached
        if isinstance(node, Chance):
            value = math.fsum(prob * self._value(child) for prob, child, _label in node.branches)
        elif node.player == self.opponent:
            dist = self.profile[node.infoset]
            value = math.fsum(
                dist[action] * self._value(child)
                for action, child in zip(node.actions, node.children, strict=True)
            )
        else:  # br_player's node: follow the infoset's best action
            value = self._value(node.child_of(self._best_action(node.infoset)))
        self._value_memo[key] = value
        return value

    def _best_action(self, infoset: str) -> str:
        """Argmax action over the whole infoset, counterfactual-reach weighted."""
        cached = self._best_action_memo.get(infoset)
        if cached is not None:
            return cached
        actions = self.game.actions_of(infoset)
        nodes = self._infoset_nodes.get(infoset, [])
        best_action = actions[0]
        best_value = -math.inf
        for action in actions:
            # Counterfactual value of committing to `action` at this infoset,
            # summed over its nodes; deeper infosets best-respond via _value().
            action_value = math.fsum(
                cf_reach * self._value(node.child_of(action)) for node, cf_reach in nodes
            )
            if action_value > best_value:
                best_value = action_value
                best_action = action
        self._best_action_memo[infoset] = best_action
        return best_action

    def value(self) -> float:
        return self._value(self.game.root)

    def strategy(self) -> dict[str, str]:
        """The pure best-response action per br_player infoset.

        Unreached infosets (zero counterfactual reach) have no preference; the
        first action is returned deterministically.
        """
        return {
            infoset: self._best_action(infoset) for infoset in self.game.infosets_of(self.br_player)
        }


def best_response_value(game: Game, br_player: int, profile: StrategyProfile) -> float:
    """``br_player``'s best-response value (its own utility, bb) vs ``profile``.

    Only the opponent's entries of ``profile`` are used; ``br_player``'s own
    entries are ignored (it is optimising over them).
    """
    validate_profile(game, profile)
    return _BestResponder(game, br_player, profile).value()


def best_response_strategy(game: Game, br_player: int, profile: StrategyProfile) -> dict[str, str]:
    """A pure best-response strategy (infoset -> action) for ``br_player``."""
    validate_profile(game, profile)
    return _BestResponder(game, br_player, profile).strategy()


def nash_conv(game: Game, profile: StrategyProfile) -> float:
    """NashConv: total both-players gain from unilaterally best responding (bb)."""
    validate_profile(game, profile)
    u0 = expected_value(game, profile, validate=False)
    gain0 = _BestResponder(game, 0, profile).value() - u0
    gain1 = _BestResponder(game, 1, profile).value() - (-u0)
    return gain0 + gain1


def exploitability(game: Game, profile: StrategyProfile) -> float:
    """Exploitability = NashConv / 2 (bb/hand, ADR-0017 sec.3)."""
    return nash_conv(game, profile) / 2.0
