"""Explanation contracts, deterministic template generation and verification.

Phase 5 starts with a structured explanation object and an LLM-free template
renderer. The DPL remains the source of truth; explanations cite DPL and optional
solver diagnostic fields explicitly so the separate in-repository verifier can
check the output. Its checks do not constitute external validation or certify
solver convergence, strategy safety, optimality, or GTO status.
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
from .verifier import (
    ExplanationVerificationError,
    VerificationIssue,
    VerificationResult,
    verify_explanation,
    verify_explanation_or_raise,
)

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
    "ExplanationVerificationError",
    "VerificationIssue",
    "VerificationResult",
    "generate_template_explanation",
    "verify_explanation",
    "verify_explanation_or_raise",
]
