"""Frozen river scenario solving entry point (P3-3).

The solver reads the frozen Q3 scenario schema plus the Q4/Q5 classifiers and
builds an in-memory combo-granular river game. It intentionally stops at a
strategy/metrics result; writing BaselineTable artifacts and CLI smoke plumbing
belong to P3-4.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from poker_ai.hand_bucket import bucket_def_version, classify_combo
from poker_ai.scenario import Scenario
from poker_core.state_cluster import classify_board, cluster_def_version

from .cfr_metrics import ConvergenceMetrics, solve_cfr_plus_with_metrics
from .game import Chance, Game
from .river_tree import RiverBettingConfig, build_river_game
from .strategy import ActionDist, StrategyProfile


@dataclass(frozen=True, slots=True)
class RiverComboPolicy:
    """One solved combo/phase policy for the scenario hero seat."""

    combo: str
    infoset: str
    phase: str
    policy: ActionDist
    reach_prob: float


@dataclass(frozen=True, slots=True)
class RiverScenarioSolveResult:
    """In-memory result for a frozen river scenario solve."""

    scenario_id: str
    position: str
    state_cluster: str
    cluster_def_version: str
    hand_bucket: str
    bucket_def_version: str
    hero_combo: str
    strategy: StrategyProfile
    metrics: ConvergenceMetrics
    combo_policies: tuple[RiverComboPolicy, ...]


def solve_frozen_river_scenario(
    scenario: Scenario,
    *,
    bet_fraction: float,
    iterations: int,
    checkpoints: Iterable[int] = (),
    average_delay: int = 0,
) -> RiverScenarioSolveResult:
    """Solve a frozen Q3 river scenario as a small combo-granular game."""
    config = RiverBettingConfig(pot=scenario.pot, bet_fraction=bet_fraction)
    if config.bet > scenario.effective_stack:
        raise ValueError(
            f"bet size {config.bet} exceeds effective stack {scenario.effective_stack}"
        )

    board = scenario.board_cards()
    hero_range = scenario.hero_range_obj()
    opponent_range = scenario.opponent_range_obj()
    hero_combo = scenario.hero_combo_obj()
    if scenario.position == "OOP":
        game = build_river_game(config, hero_range, opponent_range, board)
        hero_prefix = "OOP"
    else:
        game = build_river_game(config, opponent_range, hero_range, board)
        hero_prefix = "IP"

    solve = solve_cfr_plus_with_metrics(
        game,
        iterations,
        checkpoints=checkpoints,
        average_delay=average_delay,
    )
    combo_policies = _combo_policies(game, solve.profile, hero_prefix)
    return RiverScenarioSolveResult(
        scenario_id=scenario.scenario_id,
        position=scenario.position,
        state_cluster=classify_board(board),
        cluster_def_version=cluster_def_version(),
        hand_bucket=classify_combo(hero_combo, hero_range, board),
        bucket_def_version=bucket_def_version(),
        hero_combo=hero_combo.canonical(),
        strategy=solve.profile,
        metrics=solve.metrics,
        combo_policies=combo_policies,
    )


def _combo_policies(
    game: Game, profile: StrategyProfile, hero_prefix: str
) -> tuple[RiverComboPolicy, ...]:
    reaches = _hero_chance_reaches(game, hero_prefix)
    policies: list[RiverComboPolicy] = []
    prefix = f"{hero_prefix}:"
    for infoset in game.infosets:
        if not infoset.startswith(prefix):
            continue
        _actor, combo, phase = infoset.split(":", maxsplit=2)
        policies.append(
            RiverComboPolicy(
                combo=combo,
                infoset=infoset,
                phase=phase,
                policy=dict(profile[infoset]),
                reach_prob=reaches[combo],
            )
        )
    return tuple(sorted(policies, key=lambda policy: (policy.combo, policy.phase)))


def _hero_chance_reaches(game: Game, hero_prefix: str) -> dict[str, float]:
    if not isinstance(game.root, Chance):
        raise ValueError("river game root must be a chance node")
    hero_index = 0 if hero_prefix == "OOP" else 1
    reaches: dict[str, float] = {}
    for prob, _child, label in game.root.branches:
        parts = label.split("|")
        if len(parts) != 2:
            raise ValueError(f"river deal label must be 'OOP|IP', got {label!r}")
        combo = parts[hero_index]
        reaches[combo] = reaches.get(combo, 0.0) + prob
    return reaches
