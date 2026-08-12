"""poker_ai: observation, finite-iteration policy, exploitation and sessions.

The river MVP generates scenarios deterministically, observes the stub opponent's
all-in, obtains Hero's finite-iteration combo- and position-specific ``vs_bet``
policy from CFR+, and keeps optional rule or node-lock exploitation behind the
SafetyMixer. The mixer applies the configured convex combination; it is not a
strategy-safety proof. Public action observations feed the LeakDetector without
exposing hidden opponent strategy. The decision is recorded in a versioned
Decision Provenance Log with exact frozen-model terminal/action ``solver_exact``
EV (ADR-0008). The CFR+ policy has no convergence, exact-equilibrium, or GTO
certificate.
"""

from __future__ import annotations

from .actions import ALL_ACTIONS, FACING_ACTIONS, NO_FACING_ACTIONS, legal_actions
from .base_policy import BasePolicyProvider, BasePolicySelection, StubBasePolicyProvider
from .baseline_strategy import (
    FACING_ALL_IN,
    BaselineStrategy,
    baseline_table_version,
    build_situation_key,
    build_strategy_table,
    get_baseline_strategy,
    load_baseline_strategy,
)
from .cfr_policy import (
    CFR_RIVER_POLICY_CONFIG_VERSION,
    CFR_RIVER_POLICY_SOURCE,
    DEFAULT_CFR_RIVER_POLICY_CONFIG,
    CfrRiverPolicyConfig,
    CfrRiverPolicyProvider,
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
    validate_provider_confidence_config,
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
    ActionLeakCandidateScore,
    ActionLeakRule,
    LeakDetector,
    LeakDetectorConfig,
    beta_binomial_upper_tail,
    classify_ground_truth_boundary,
    default_action_baseline_table,
    score_action_leak_candidate,
)
from .mixer import ActionSelector, is_pure_base, safety_mix
from .observation import ActionStats, ObservationTracker
from .opponent import HiddenStrategyAccessError, OpponentAction, StubOpponent
from .posterior_bundle import (
    ValidatedPosteriorBundle,
    load_posterior_run_bundle,
    validate_posterior_bundle,
)
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
    write_session_bundle,
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
    "ActionLeakCandidateScore",
    "ActionLeakRule",
    "ActionStats",
    "BaselineStrategy",
    "BasePolicyProvider",
    "BasePolicySelection",
    "BucketDefinition",
    "CFR_RIVER_POLICY_CONFIG_VERSION",
    "CFR_RIVER_POLICY_SOURCE",
    "DEFAULT_CFR_RIVER_POLICY_CONFIG",
    "CfrRiverPolicyConfig",
    "CfrRiverPolicyProvider",
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
    "StubBasePolicyProvider",
    "baseline_table_version",
    "beta_binomial_upper_tail",
    "classify_ground_truth_boundary",
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
    "load_posterior_run_bundle",
    "nodelock_config_from_leaks",
    "policy_ev",
    "run_session",
    "score_action_leak_candidate",
    "safety_mix",
    "strength_percentile",
    "validate_provider_confidence_config",
    "write_jsonl",
    "write_manifest",
    "write_session_bundle",
    "validate_posterior_bundle",
    "ValidatedPosteriorBundle",
]
