"""poker_core: shared contracts and primitives for the poker-xai project.

Phase 0 freezes the project's contracts here (ADR-0006): the Decision
Provenance Log schema, the Reason Ontology, the StrategyTable, and the
RunManifest. Phase 1 (task 2) adds the shared card model, hand evaluation,
weighted ranges, the range-vs-range showdown EV evaluator, and the frozen MVP
state-cluster classifier (Q4, ADR-0016).
"""

from __future__ import annotations

from .card import DECK_SIZE, RANKS, SUITS, Card, cards_mask, parse_cards
from .combo import Combo
from .dpl_schema import (
    DPL_SCHEMA_VERSION,
    MIX_EPSILON_REASON_ID,
    DecisionProvenanceLog,
    DetectedLeak,
    EvEstimate,
    ExecutionSampling,
)
from .hand_evaluator import (
    HandCategory,
    category_of,
    evaluate_best,
    evaluate_five,
    hand_strength,
)
from .range_model import Range
from .reason_ontology import (
    VALID_NAMESPACES,
    ReasonEntry,
    ReasonOntology,
    get_ontology,
    load_ontology,
)
from .run_manifest import (
    MANIFEST_SCHEMA_VERSION,
    ArtifactRef,
    CodeProvenance,
    ComponentVersions,
    ConfigRef,
    OpponentRef,
    RunManifest,
)
from .showdown_ev import (
    EV_DEFINITION,
    ShowdownEquity,
    ShowdownEV,
    estimate_showdown_equity,
    showdown_equity,
    showdown_ev,
)
from .state_cluster import (
    BoardFeatures,
    ClusterDefinition,
    board_features,
    classify_board,
    cluster_def_version,
    get_cluster_definition,
    load_cluster_definition,
)
from .strategy_table import (
    STRATEGY_TABLE_SCHEMA_VERSION,
    StrategyEntry,
    StrategyTable,
)

__all__ = [
    "DECK_SIZE",
    "DPL_SCHEMA_VERSION",
    "EV_DEFINITION",
    "MANIFEST_SCHEMA_VERSION",
    "MIX_EPSILON_REASON_ID",
    "RANKS",
    "SUITS",
    "STRATEGY_TABLE_SCHEMA_VERSION",
    "VALID_NAMESPACES",
    "ArtifactRef",
    "BoardFeatures",
    "Card",
    "ClusterDefinition",
    "CodeProvenance",
    "Combo",
    "ComponentVersions",
    "ConfigRef",
    "DecisionProvenanceLog",
    "DetectedLeak",
    "EvEstimate",
    "ExecutionSampling",
    "HandCategory",
    "OpponentRef",
    "Range",
    "ReasonEntry",
    "ReasonOntology",
    "RunManifest",
    "ShowdownEV",
    "ShowdownEquity",
    "StrategyEntry",
    "StrategyTable",
    "board_features",
    "cards_mask",
    "category_of",
    "classify_board",
    "cluster_def_version",
    "estimate_showdown_equity",
    "evaluate_best",
    "evaluate_five",
    "get_cluster_definition",
    "get_ontology",
    "hand_strength",
    "load_cluster_definition",
    "load_ontology",
    "parse_cards",
    "showdown_equity",
    "showdown_ev",
]
