"""Full-tree vanilla CFR for the small verification games (P3-2).

This module intentionally contains only the solver machinery: regret matching,
counterfactual regret updates, and average-strategy extraction. It does not
import the independent best-response verifier; exploitability checks live in
tests and downstream validation so the solver is not self-verifying.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field

from .game import PLAYERS, Chance, Game, Node, Terminal
from .strategy import ActionDist, StrategyProfile, normalized_action_dist, validate_profile


def regret_matching(regrets: Mapping[str, float], actions: tuple[str, ...]) -> ActionDist:
    """Return the regret-matching distribution over ``actions``.

    Only positive cumulative regret receives mass. If every regret is non-positive
    or missing, the distribution falls back to uniform.
    """
    positive = {action: max(regrets.get(action, 0.0), 0.0) for action in actions}
    return normalized_action_dist(positive, actions)


@dataclass(slots=True)
class VanillaCFR:
    """Deterministic full-tree vanilla CFR over a finite two-player zero-sum game."""

    game: Game
    cumulative_regrets: dict[str, ActionDist] = field(init=False)
    strategy_sum: dict[str, ActionDist] = field(init=False)
    iterations: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self.cumulative_regrets = _zero_table(self.game)
        self.strategy_sum = _zero_table(self.game)

    def current_profile(self) -> StrategyProfile:
        """The profile induced by current cumulative regrets."""
        self._validate_table_shape(self.cumulative_regrets, "cumulative_regrets")
        profile = {
            infoset: regret_matching(
                self.cumulative_regrets[infoset], self.game.actions_of(infoset)
            )
            for infoset in self.game.infosets
        }
        validate_profile(self.game, profile)
        return profile

    def average_strategy(self) -> StrategyProfile:
        """Return the accumulated average strategy, with uniform fallback off path."""
        self._validate_table_shape(self.strategy_sum, "strategy_sum")
        profile = {
            infoset: normalized_action_dist(
                self.strategy_sum[infoset], self.game.actions_of(infoset)
            )
            for infoset in self.game.infosets
        }
        validate_profile(self.game, profile)
        return profile

    def run_iteration(self) -> None:
        """Run one simultaneous full-tree CFR iteration."""
        profile = self.current_profile()
        self._accumulate_average(self.game.root, profile, reach0=1.0, reach1=1.0)
        for player in PLAYERS:
            self._counterfactual_value(
                self.game.root,
                update_player=player,
                profile=profile,
                chance_reach=1.0,
                reach0=1.0,
                reach1=1.0,
            )
        self.iterations += 1

    def run(self, iterations: int) -> VanillaCFR:
        """Run ``iterations`` more full-tree CFR iterations and return ``self``."""
        if iterations < 0:
            raise ValueError(f"iterations must be non-negative, got {iterations}")
        for _ in range(iterations):
            self.run_iteration()
        return self

    def _counterfactual_value(
        self,
        node: Node,
        *,
        update_player: int,
        profile: StrategyProfile,
        chance_reach: float,
        reach0: float,
        reach1: float,
    ) -> float:
        """Expected utility to ``update_player`` from ``node`` under ``profile``."""
        if isinstance(node, Terminal):
            return node.payoff if update_player == 0 else -node.payoff
        if isinstance(node, Chance):
            return math.fsum(
                prob
                * self._counterfactual_value(
                    child,
                    update_player=update_player,
                    profile=profile,
                    chance_reach=chance_reach * prob,
                    reach0=reach0,
                    reach1=reach1,
                )
                for prob, child, _label in node.branches
            )

        dist = profile[node.infoset]
        action_values: dict[str, float] = {}
        for action, child in zip(node.actions, node.children, strict=True):
            next_reach0 = reach0 * dist[action] if node.player == 0 else reach0
            next_reach1 = reach1 * dist[action] if node.player == 1 else reach1
            action_values[action] = self._counterfactual_value(
                child,
                update_player=update_player,
                profile=profile,
                chance_reach=chance_reach,
                reach0=next_reach0,
                reach1=next_reach1,
            )

        node_value = math.fsum(dist[action] * action_values[action] for action in node.actions)
        if node.player == update_player:
            opponent_reach = reach1 if update_player == 0 else reach0
            counterfactual_reach = chance_reach * opponent_reach
            regrets = self.cumulative_regrets[node.infoset]
            for action in node.actions:
                regrets[action] += counterfactual_reach * (action_values[action] - node_value)
        return node_value

    def _accumulate_average(
        self,
        node: Node,
        profile: StrategyProfile,
        *,
        reach0: float,
        reach1: float,
    ) -> None:
        if isinstance(node, Terminal):
            return
        if isinstance(node, Chance):
            for _prob, child, _label in node.branches:
                self._accumulate_average(child, profile, reach0=reach0, reach1=reach1)
            return

        dist = profile[node.infoset]
        own_reach = reach0 if node.player == 0 else reach1
        sums = self.strategy_sum[node.infoset]
        for action in node.actions:
            sums[action] += own_reach * dist[action]

        for action, child in zip(node.actions, node.children, strict=True):
            next_reach0 = reach0 * dist[action] if node.player == 0 else reach0
            next_reach1 = reach1 * dist[action] if node.player == 1 else reach1
            self._accumulate_average(child, profile, reach0=next_reach0, reach1=next_reach1)

    def _validate_table_shape(self, table: dict[str, ActionDist], name: str) -> None:
        game_infosets = set(self.game.infosets)
        extra = set(table) - game_infosets
        if extra:
            raise ValueError(f"{name} has unknown infosets {sorted(extra)}")
        missing = game_infosets - set(table)
        if missing:
            raise ValueError(f"{name} missing infosets {sorted(missing)}")
        for infoset in self.game.infosets:
            actions = self.game.actions_of(infoset)
            if set(table[infoset]) != set(actions):
                raise ValueError(
                    f"{name} keys for {infoset!r} {sorted(table[infoset])} "
                    f"!= actions {sorted(actions)}"
                )


def solve_vanilla_cfr(game: Game, iterations: int) -> StrategyProfile:
    """Run vanilla CFR from zero regrets and return the average strategy."""
    return VanillaCFR(game).run(iterations).average_strategy()


def _zero_table(game: Game) -> dict[str, ActionDist]:
    return {infoset: dict.fromkeys(game.actions_of(infoset), 0.0) for infoset in game.infosets}
