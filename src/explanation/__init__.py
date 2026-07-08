"""Explanation contracts and deterministic template generation.

Phase 5 starts with a structured explanation object and an LLM-free template
renderer. The DPL remains the source of truth; explanations cite DPL and optional
solver diagnostic fields explicitly so a later independent verifier can audit
the output.
"""

from .contract import (
    EXPLANATION_SCHEMA_VERSION,
    TEMPLATE_GENERATOR,
    TEMPLATE_GENERATOR_VERSION,
    CounterfactualExplanation,
    EVBreakdown,
    ExplanationDocument,
    ExplanationStage,
    NumericClaim,
    PolicyReasonSet,
    ReasonCitation,
    SamplingReasonSet,
    SolverDiagnostics,
)
from .template import generate_template_explanation

__all__ = [
    "EXPLANATION_SCHEMA_VERSION",
    "TEMPLATE_GENERATOR",
    "TEMPLATE_GENERATOR_VERSION",
    "CounterfactualExplanation",
    "EVBreakdown",
    "ExplanationDocument",
    "ExplanationStage",
    "NumericClaim",
    "PolicyReasonSet",
    "ReasonCitation",
    "SamplingReasonSet",
    "SolverDiagnostics",
    "generate_template_explanation",
]
