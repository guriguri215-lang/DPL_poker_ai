"""poker_solver: finite-iteration solvers and fixed-profile evaluators.

Phase 3 builds this package as: P3-1 the *verification layer* --
an extensive-form game tree, an exact strategy-profile EV evaluator, and a
best-response / exploitability module that is deliberately independent of any CFR
code (ADR-0017 sec.4). P3-2 adds full-tree vanilla CFR on top of those measuring
instruments. P3-3 adds CFR+, independently computed exploitability/value metrics,
and an in-memory bounded frozen-river-scenario experiment entry point. P3-4 adds
StrategyTable baseline artifact generation from finite-iteration river policies.
These measurements do not certify convergence, exact equilibrium, or GTO status.
Phase 4 adds node-lock configuration,
river application helpers, EV deltas, resolve-mode worst-case metrics, and
sensitivity analysis.

Public API::

    from poker_solver import (
        Game, Terminal, Chance, Decision,          # game tree
        uniform_profile, validate_profile,         # strategy profiles
        expected_value, expected_value_by_leaves,  # exact EV
        leaf_reaches, total_reach,                 # reach decomposition
        best_response_value, best_response_strategy, nash_conv, exploitability,
        VanillaCFR, regret_matching, solve_vanilla_cfr,
        CFRPlus, solve_cfr_plus, solve_cfr_plus_with_metrics,
        solve_frozen_river_scenario,
        build_baseline_strategy_table, build_baseline_strategy_tables,
        write_baseline_strategy_tables,
        NodeLockConfig, NodeLockRule, analyze_nodelock_sensitivity,
        solve_nodelocked_river_scenario,
    )
"""

from __future__ import annotations

from .best_response import (
    best_response_strategy,
    best_response_value,
    exploitability,
    nash_conv,
)
from .cfr import VanillaCFR, regret_matching, solve_vanilla_cfr
from .cfr_metrics import (
    CFRPlusResult,
    ConvergenceCheckpoint,
    ConvergenceMetrics,
    solve_cfr_plus_with_metrics,
)
from .cfr_plus import CFRPlus, regret_matching_plus, solve_cfr_plus
from .evaluate import expected_value, expected_value_by_leaves, player_values
from .game import Chance, Decision, Game, Node, Terminal
from .nodelock import (
    AppliedNodeLock,
    NodeLockAllocationComparison,
    NodeLockApplication,
    NodeLockComboPolicy,
    NodeLockConfig,
    NodeLockMetrics,
    NodeLockRule,
    NodeLockSensitivityPoint,
    NodeLockSensitivityReport,
    NodeLockWorstCaseMetrics,
    RiverNodeLockSolveResult,
    analyze_nodelock_sensitivity,
    apply_node_locks,
    river_infoset_reach_weights,
    solve_nodelocked_river_scenario,
)
from .reach import LeafReach, leaf_reaches, total_reach
from .river_solve import (
    RiverComboPolicy,
    RiverScenarioSolveResult,
    build_baseline_strategy_table,
    build_baseline_strategy_tables,
    river_solve_situation_key,
    solve_frozen_river_scenario,
    write_baseline_strategy_tables,
)
from .strategy import (
    StrategyProfile,
    normalized_action_dist,
    uniform_profile,
    validate_profile,
)

__all__ = [
    "Chance",
    "CFRPlus",
    "CFRPlusResult",
    "ConvergenceCheckpoint",
    "ConvergenceMetrics",
    "Decision",
    "Game",
    "LeafReach",
    "Node",
    "AppliedNodeLock",
    "NodeLockApplication",
    "NodeLockAllocationComparison",
    "NodeLockComboPolicy",
    "NodeLockConfig",
    "NodeLockMetrics",
    "NodeLockRule",
    "NodeLockSensitivityPoint",
    "NodeLockSensitivityReport",
    "NodeLockWorstCaseMetrics",
    "RiverNodeLockSolveResult",
    "StrategyProfile",
    "Terminal",
    "VanillaCFR",
    "best_response_strategy",
    "best_response_value",
    "build_baseline_strategy_table",
    "build_baseline_strategy_tables",
    "expected_value",
    "expected_value_by_leaves",
    "exploitability",
    "analyze_nodelock_sensitivity",
    "apply_node_locks",
    "leaf_reaches",
    "nash_conv",
    "normalized_action_dist",
    "player_values",
    "regret_matching",
    "regret_matching_plus",
    "RiverComboPolicy",
    "RiverScenarioSolveResult",
    "river_infoset_reach_weights",
    "river_solve_situation_key",
    "solve_cfr_plus",
    "solve_cfr_plus_with_metrics",
    "solve_frozen_river_scenario",
    "solve_nodelocked_river_scenario",
    "solve_vanilla_cfr",
    "total_reach",
    "uniform_profile",
    "validate_profile",
    "write_baseline_strategy_tables",
]
