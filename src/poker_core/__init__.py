"""poker_core: shared contracts and primitives for the poker-xai project.

Phase 0 freezes the project's contracts here (ADR-0006): the Decision
Provenance Log schema, the Reason Ontology, and the RunManifest. Later phases
add cards, hand evaluation, ranges, the state-cluster definition and the
strategy table alongside them.
"""

from __future__ import annotations

from .dpl_schema import (
    DPL_SCHEMA_VERSION,
    DecisionProvenanceLog,
    DetectedLeak,
    EvEstimate,
)
from .reason_ontology import (
    VALID_NAMESPACES,
    ReasonEntry,
    ReasonOntology,
    get_ontology,
    load_ontology,
)
from .run_manifest import (
    MANIFEST_SCHEMA_VERSION,
    CodeProvenance,
    ComponentVersions,
    ConfigRef,
    OpponentRef,
    RunManifest,
)

__all__ = [
    "DPL_SCHEMA_VERSION",
    "MANIFEST_SCHEMA_VERSION",
    "VALID_NAMESPACES",
    "CodeProvenance",
    "ComponentVersions",
    "ConfigRef",
    "DecisionProvenanceLog",
    "DetectedLeak",
    "EvEstimate",
    "OpponentRef",
    "ReasonEntry",
    "ReasonOntology",
    "RunManifest",
    "get_ontology",
    "load_ontology",
]
