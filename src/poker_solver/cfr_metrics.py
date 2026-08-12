"""Finite-iteration exploitability and value diagnostics for CFR solvers (P3-3).

This module may import the CFR-independent evaluator and best-response checker.
Solver implementations themselves stay free of those imports. The diagnostics
do not certify convergence, exact equilibrium, or GTO status.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .best_response import exploitability
from .cfr_plus import CFRPlus
from .evaluate import expected_value
from .game import Game
from .strategy import StrategyProfile


@dataclass(frozen=True, slots=True)
class ConvergenceCheckpoint:
    """A measured profile snapshot at a completed iteration count."""

    iterations: int
    exploitability: float
    game_value: float


@dataclass(frozen=True, slots=True)
class ConvergenceMetrics:
    """Final finite-iteration diagnostics plus optional checkpoints."""

    iterations: int
    final_exploitability: float
    game_value: float
    checkpoints: tuple[ConvergenceCheckpoint, ...]


@dataclass(frozen=True, slots=True)
class CFRPlusResult:
    """CFR+ average strategy with exploitability and value diagnostics."""

    profile: StrategyProfile
    metrics: ConvergenceMetrics


def solve_cfr_plus_with_metrics(
    game: Game,
    iterations: int,
    *,
    checkpoints: Iterable[int] = (),
    average_delay: int = 0,
) -> CFRPlusResult:
    """Run CFR+ and measure exploitability/value with CFR-independent code."""
    if iterations < 0:
        raise ValueError(f"iterations must be non-negative, got {iterations}")
    solver = CFRPlus(game, average_delay=average_delay)
    checkpoint_targets = _normalize_checkpoints(iterations, checkpoints)

    records: list[ConvergenceCheckpoint] = []
    completed = 0
    for target in checkpoint_targets:
        solver.run(target - completed)
        completed = target
        records.append(_measure(game, solver.average_strategy(), target))

    solver.run(iterations - completed)
    profile = solver.average_strategy()
    final_exploitability = exploitability(game, profile)
    game_value = expected_value(game, profile)
    return CFRPlusResult(
        profile=profile,
        metrics=ConvergenceMetrics(
            iterations=solver.iterations,
            final_exploitability=final_exploitability,
            game_value=game_value,
            checkpoints=tuple(records),
        ),
    )


def _measure(game: Game, profile: StrategyProfile, iterations: int) -> ConvergenceCheckpoint:
    return ConvergenceCheckpoint(
        iterations=iterations,
        exploitability=exploitability(game, profile),
        game_value=expected_value(game, profile),
    )


def _normalize_checkpoints(iterations: int, checkpoints: Iterable[int]) -> tuple[int, ...]:
    normalized = tuple(sorted(set(checkpoints)))
    for checkpoint in normalized:
        if checkpoint < 0:
            raise ValueError(f"checkpoint iterations must be non-negative, got {checkpoint}")
        if checkpoint > iterations:
            raise ValueError(f"checkpoint {checkpoint} exceeds final iteration count {iterations}")
    return normalized
