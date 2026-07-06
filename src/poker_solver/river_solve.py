"""Frozen river scenario solving entry point (P3-3).

The solver reads the frozen Q3 scenario schema plus the Q4/Q5 classifiers and
builds an in-memory combo-granular river game. It intentionally stops at a
strategy/metrics result; writing BaselineTable artifacts and CLI smoke plumbing
belong to P3-4.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from poker_ai.hand_bucket import bucket_def_version, classify_combo
from poker_ai.scenario import Scenario
from poker_core.state_cluster import classify_board, cluster_def_version
from poker_core.strategy_table import StrategyEntry, StrategyTable

from .cfr_metrics import ConvergenceMetrics, solve_cfr_plus_with_metrics
from .game import Chance, Game
from .river_tree import RiverBettingConfig, build_river_game
from .strategy import ActionDist, StrategyProfile

_SOLVE_CONFIG_VERSION = "river-solve-config-v1"


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
    solve_config_digest: str


def build_baseline_strategy_table(
    result: RiverScenarioSolveResult,
    *,
    phase: str,
    table_version: str | None = None,
    source: str = "poker_solver.solve_frozen_river_scenario",
) -> StrategyTable:
    """Convert one solved hero phase into the frozen per-combo StrategyTable."""
    policies = [policy for policy in result.combo_policies if policy.phase == phase]
    if not policies:
        raise ValueError(f"solve result has no hero policy for phase {phase!r}")

    version = table_version or _baseline_table_version(result, phase)
    return StrategyTable(
        table_version=version,
        situation_key=river_solve_situation_key(result, phase),
        cluster_def_version=result.cluster_def_version,
        source=source,
        entries=tuple(
            StrategyEntry(
                combo=policy.combo,
                policy=dict(policy.policy),
                reach_prob=policy.reach_prob,
            )
            for policy in policies
        ),
    )


def build_baseline_strategy_tables(
    result: RiverScenarioSolveResult,
    *,
    phases: Iterable[str] | None = None,
    source: str = "poker_solver.solve_frozen_river_scenario",
) -> tuple[StrategyTable, ...]:
    """Convert solved hero phases into StrategyTable baseline artifacts."""
    selected = tuple(phases) if phases is not None else _solved_phases(result)
    return tuple(
        build_baseline_strategy_table(result, phase=phase, source=source) for phase in selected
    )


def write_baseline_strategy_tables(
    tables: Iterable[StrategyTable],
    out_dir: Path | str,
) -> tuple[Path, ...]:
    """Write StrategyTable artifacts as deterministic JSON files."""
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)

    paths: list[Path] = []
    for table in tables:
        path = target / f"{_safe_slug(table.table_version)}.strategy_table.json"
        path.write_text(table.model_dump_json(indent=2) + "\n", encoding="utf-8")
        paths.append(path)
    return tuple(paths)


def river_solve_situation_key(result: RiverScenarioSolveResult, phase: str) -> str:
    """Build a StrategyTable situation key for one solved river phase."""
    return f"{result.state_cluster}:{result.position}:river_{phase}"


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
        solve_config_digest=_solve_config_digest(
            bet_fraction=bet_fraction,
            average_delay=average_delay,
        ),
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


def _solved_phases(result: RiverScenarioSolveResult) -> tuple[str, ...]:
    return tuple(sorted({policy.phase for policy in result.combo_policies}))


def _baseline_table_version(result: RiverScenarioSolveResult, phase: str) -> str:
    return (
        f"river-solve-{_safe_slug(result.scenario_id)}-{result.position.lower()}-"
        f"{_safe_slug(phase)}-i{result.metrics.iterations}-cfg{result.solve_config_digest}"
    )


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return slug.strip("._-") or "strategy_table"


def _solve_config_digest(*, bet_fraction: float, average_delay: int) -> str:
    payload = {
        "version": _SOLVE_CONFIG_VERSION,
        "solver": "cfr_plus",
        "bet_fraction": bet_fraction,
        "average_delay": average_delay,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:12]


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
