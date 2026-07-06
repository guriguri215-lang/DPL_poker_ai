"""Full-tree CFR+ for deterministic small-game solving (P3-3).

CFR+ differs from the vanilla CFR core in three intentional ways:

* cumulative regrets are floored at zero after every update;
* player updates are alternating, with the current profile recomputed between
  players inside an iteration;
* average strategies use linear iteration weights.

The independent best-response verifier remains outside this module. Metrics live
in :mod:`poker_solver.cfr_metrics` so the solver does not validate itself.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field

from .game import PLAYERS, Chance, Game, Node, Terminal
from .strategy import (
    ActionDist,
    StrategyProfile,
    normalized_action_dist,
    uniform_profile,
    validate_profile,
)


def regret_matching_plus(regrets: Mapping[str, float], actions: tuple[str, ...]) -> ActionDist:
    """Return a regret-matching distribution for a non-negative CFR+ table."""
    positive = {action: max(regrets.get(action, 0.0), 0.0) for action in actions}
    return normalized_action_dist(positive, actions)


@dataclass(slots=True)
class CFRPlus:
    """Deterministic full-tree CFR+ over a finite two-player zero-sum game."""

    game: Game
    average_delay: int = 0
    fixed_strategy: Mapping[str, Mapping[str, float]] | None = None
    cumulative_regrets: dict[str, ActionDist] = field(init=False)
    strategy_sum: dict[str, ActionDist] = field(init=False)
    iterations: int = field(default=0, init=False)
    average_weight_sum: float = field(default=0.0, init=False)

    def __post_init__(self) -> None:
        if self.average_delay < 0:
            raise ValueError(f"average_delay must be non-negative, got {self.average_delay}")
        self.fixed_strategy = _validated_fixed_strategy(self.game, self.fixed_strategy)
        self.cumulative_regrets = _zero_table(self.game)
        self.strategy_sum = _zero_table(self.game)

    def current_profile(self) -> StrategyProfile:
        """The profile induced by current non-negative cumulative regrets."""
        self._validate_table_shape(self.cumulative_regrets, "cumulative_regrets")
        profile = {}
        for infoset in self.game.infosets:
            fixed_dist = self.fixed_strategy.get(infoset)
            if fixed_dist is not None:
                profile[infoset] = dict(fixed_dist)
            else:
                profile[infoset] = regret_matching_plus(
                    self.cumulative_regrets[infoset], self.game.actions_of(infoset)
                )
        validate_profile(self.game, profile)
        return profile

    def average_strategy(self) -> StrategyProfile:
        """Return the linear-weighted average strategy, uniform off path."""
        self._validate_table_shape(self.strategy_sum, "strategy_sum")
        profile = {}
        for infoset in self.game.infosets:
            fixed_dist = self.fixed_strategy.get(infoset)
            if fixed_dist is not None:
                profile[infoset] = dict(fixed_dist)
            else:
                profile[infoset] = normalized_action_dist(
                    self.strategy_sum[infoset], self.game.actions_of(infoset)
                )
        validate_profile(self.game, profile)
        return profile

    def run_iteration(self) -> None:
        """Run one alternating CFR+ iteration."""
        next_iteration = self.iterations + 1
        for player in PLAYERS:
            profile = self.current_profile()
            self._counterfactual_value(
                self.game.root,
                update_player=player,
                profile=profile,
                chance_reach=1.0,
                reach0=1.0,
                reach1=1.0,
            )

        self.iterations = next_iteration
        weight = self._average_weight(next_iteration)
        if weight > 0.0:
            profile = self.current_profile()
            self._accumulate_average(self.game.root, profile, reach0=1.0, reach1=1.0, weight=weight)
            self.average_weight_sum += weight

    def run(self, iterations: int) -> CFRPlus:
        """Run ``iterations`` more full-tree CFR+ iterations and return ``self``."""
        if iterations < 0:
            raise ValueError(f"iterations must be non-negative, got {iterations}")
        for _ in range(iterations):
            self.run_iteration()
        return self

    def _average_weight(self, iteration: int) -> float:
        if iteration <= self.average_delay:
            return 0.0
        return float(iteration - self.average_delay)

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
        if node.player == update_player and node.infoset not in self.fixed_strategy:
            opponent_reach = reach1 if update_player == 0 else reach0
            counterfactual_reach = chance_reach * opponent_reach
            regrets = self.cumulative_regrets[node.infoset]
            for action in node.actions:
                delta = counterfactual_reach * (action_values[action] - node_value)
                regrets[action] = max(0.0, regrets[action] + delta)
        return node_value

    def _accumulate_average(
        self,
        node: Node,
        profile: StrategyProfile,
        *,
        reach0: float,
        reach1: float,
        weight: float,
    ) -> None:
        if isinstance(node, Terminal):
            return
        if isinstance(node, Chance):
            for _prob, child, _label in node.branches:
                self._accumulate_average(
                    child, profile, reach0=reach0, reach1=reach1, weight=weight
                )
            return

        dist = profile[node.infoset]
        own_reach = reach0 if node.player == 0 else reach1
        sums = self.strategy_sum[node.infoset]
        for action in node.actions:
            sums[action] += weight * own_reach * dist[action]

        for action, child in zip(node.actions, node.children, strict=True):
            next_reach0 = reach0 * dist[action] if node.player == 0 else reach0
            next_reach1 = reach1 * dist[action] if node.player == 1 else reach1
            self._accumulate_average(
                child, profile, reach0=next_reach0, reach1=next_reach1, weight=weight
            )

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


def solve_cfr_plus(game: Game, iterations: int, *, average_delay: int = 0) -> StrategyProfile:
    """Run CFR+ from zero regrets and return the linear-weighted average strategy."""
    return CFRPlus(game, average_delay=average_delay).run(iterations).average_strategy()


def _zero_table(game: Game) -> dict[str, ActionDist]:
    return {infoset: dict.fromkeys(game.actions_of(infoset), 0.0) for infoset in game.infosets}


def _validated_fixed_strategy(
    game: Game, fixed_strategy: Mapping[str, Mapping[str, float]] | None
) -> StrategyProfile:
    if fixed_strategy is None:
        return {}
    extra = set(fixed_strategy) - set(game.infosets)
    if extra:
        raise ValueError(f"fixed_strategy has unknown infosets {sorted(extra)}")

    profile = uniform_profile(game)
    for infoset, dist in fixed_strategy.items():
        profile[infoset] = dict(dist)
    validate_profile(game, profile)
    return {infoset: dict(fixed_strategy[infoset]) for infoset in fixed_strategy}
