"""poker_ai: observation, lookup strategy, mixer, selector and the session runner.

Phase 2 (task 3) implements the vertical slice (ADR-0007): a river scenario is
generated deterministically, the stub opponent acts, Hero looks up its base policy
by situation and ``hand_bucket`` (ADR-0005), the SafetyMixer runs at ``alpha = 0``
(no exploitation), an action is sampled, and the decision is assembled into a frozen
Decision Provenance Log with an exact ``solver_exact`` EV (ADR-0008). Leak detection,
exploitation (``alpha > 0``), CFR and the LLM layer are later phases.
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
from .hand_bucket import (
    BUCKET_NAMES_WEAK_TO_STRONG,
    BucketDefinition,
    bucket_def_version,
    classify_combo,
    get_bucket_definition,
    load_bucket_definition,
    strength_percentile,
)
from .mixer import ActionSelector, is_pure_base, safety_mix
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
    "BaselineStrategy",
    "BucketDefinition",
    "DecisionResult",
    "HeroAgent",
    "HiddenStrategyAccessError",
    "Observation",
    "OpponentAction",
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
    "generate_scenario",
    "generate_scenarios",
    "get_baseline_strategy",
    "get_bucket_definition",
    "is_pure_base",
    "iter_session_logs",
    "legal_actions",
    "load_baseline_strategy",
    "load_bucket_definition",
    "policy_ev",
    "run_session",
    "safety_mix",
    "strength_percentile",
    "write_jsonl",
    "write_manifest",
]
