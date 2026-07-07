"""poker_ai: observation, lookup strategy, leak detection, exploitation and sessions.

Phase 2 implements the river MVP (ADR-0007): a river scenario is generated
deterministically, the stub opponent acts, public action observations feed an
action-only LeakDetector, Hero looks up its base policy by situation and
``hand_bucket`` (ADR-0005), optional rule exploitation feeds the SafetyMixer,
an action is sampled, and the decision is assembled into a frozen Decision
Provenance Log with an exact ``solver_exact`` EV (ADR-0008). Phase 5 adds an
optional node-lock solver exploit provider behind the same SafetyMixer contract.
"""

from __future__ import annotations

from .actions import ALL_ACTIONS, FACING_ACTIONS, NO_FACING_ACTIONS, legal_actions
from .baseline_strategy import (
    FACING_ALL_IN,
    BaselineStrategy,
    baseline_table_version,
    build_situation_key,
    build_strategy_table,
    get_baseline_strategy,
    load_baseline_strategy,
)
from .decision import (
    DecisionResult,
    HeroAgent,
    Observation,
    call_fold_action_evs,
    policy_ev,
)
from .exploit import (
    ExploitProvider,
    NodelockExploitConfig,
    NodelockExploitProvider,
    RuleExploitConfig,
    RuleExploitProvider,
    RuleExploitResult,
    nodelock_config_from_leaks,
)
from .hand_bucket import (
    BUCKET_NAMES_WEAK_TO_STRONG,
    BucketDefinition,
    bucket_def_version,
    classify_combo,
    get_bucket_definition,
    load_bucket_definition,
    strength_percentile,
)
from .leak import (
    ActionBaselineTable,
    ActionLeakRule,
    LeakDetector,
    LeakDetectorConfig,
    default_action_baseline_table,
)
from .mixer import ActionSelector, is_pure_base, safety_mix
from .observation import ActionStats, ObservationTracker
from .opponent import HiddenStrategyAccessError, OpponentAction, StubOpponent
from .scenario import (
    SCENARIO_SCHEMA_VERSION,
    Scenario,
    generate_scenario,
    generate_scenarios,
)
from .session import (
    SessionResult,
    build_manifest,
    iter_session_logs,
    run_session,
    write_jsonl,
    write_manifest,
)

__all__ = [
    "ALL_ACTIONS",
    "BUCKET_NAMES_WEAK_TO_STRONG",
    "FACING_ACTIONS",
    "FACING_ALL_IN",
    "NO_FACING_ACTIONS",
    "SCENARIO_SCHEMA_VERSION",
    "ActionSelector",
    "ActionBaselineTable",
    "ActionLeakRule",
    "ActionStats",
    "BaselineStrategy",
    "BucketDefinition",
    "DecisionResult",
    "ExploitProvider",
    "HeroAgent",
    "HiddenStrategyAccessError",
    "LeakDetector",
    "LeakDetectorConfig",
    "NodelockExploitConfig",
    "NodelockExploitProvider",
    "Observation",
    "ObservationTracker",
    "OpponentAction",
    "RuleExploitConfig",
    "RuleExploitProvider",
    "RuleExploitResult",
    "Scenario",
    "SessionResult",
    "StubOpponent",
    "baseline_table_version",
    "bucket_def_version",
    "build_manifest",
    "build_situation_key",
    "build_strategy_table",
    "call_fold_action_evs",
    "classify_combo",
    "default_action_baseline_table",
    "generate_scenario",
    "generate_scenarios",
    "get_baseline_strategy",
    "get_bucket_definition",
    "is_pure_base",
    "iter_session_logs",
    "legal_actions",
    "load_baseline_strategy",
    "load_bucket_definition",
    "nodelock_config_from_leaks",
    "policy_ev",
    "run_session",
    "safety_mix",
    "strength_percentile",
    "write_jsonl",
    "write_manifest",
]
