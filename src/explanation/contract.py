"""Structured explanation contract for template-generated decision explanations.

The contract is intentionally separate from the frozen DPL schema: a DPL remains
the source of truth, while this object records exactly which DPL or solver
diagnostic fields a generated explanation cites. Template generation fills this
model deterministically; a separate in-repository verifier checks the same facts
without sharing generator code. This is not independent third-party validation.
"""

from __future__ import annotations

import math
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from poker_core.reason_ontology import get_ontology

EXPLANATION_SCHEMA_VERSION = "1.0.0"
TEMPLATE_GENERATOR = "template"
TEMPLATE_GENERATOR_VERSION = "template-v1"

ExplanationStageName = Literal[
    "observation",
    "hypothesis",
    "validation",
    "adjustment",
    "residual_risk",
]
NumericSourceKind = Literal["dpl", "dpl_derived", "solver_diagnostic"]
ReasonNamespace = Literal["LEAK", "TRG", "MIX"]
GeneratorKind = Literal["template"]

STAGE_ORDER: tuple[ExplanationStageName, ...] = (
    "observation",
    "hypothesis",
    "validation",
    "adjustment",
    "residual_risk",
)


def _namespace(reason_id: str) -> str:
    prefix, sep, _tail = reason_id.partition("_")
    if not sep:
        raise ValueError(f"reason id {reason_id!r} has no namespace prefix")
    return prefix


def _validate_known_unique(reason_ids: list[str], field_name: str) -> list[str]:
    ontology = get_ontology()
    seen: set[str] = set()
    for reason_id in reason_ids:
        if reason_id in seen:
            raise ValueError(f"{field_name} contains duplicate reason id {reason_id!r}")
        seen.add(reason_id)
        if not ontology.has(reason_id):
            raise ValueError(f"{field_name} contains unknown reason id {reason_id!r}")
    return reason_ids


class NumericClaim(BaseModel):
    """One numeric value in an explanation plus its auditable source."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    value: float
    unit: str = Field(min_length=1)
    source_kind: NumericSourceKind
    source_path: str = Field(min_length=1)
    derivation: str | None = None

    @model_validator(mode="after")
    def _source_is_explicit(self) -> NumericClaim:
        if not math.isfinite(self.value):
            raise ValueError(f"numeric claim {self.name!r} must be finite")
        if self.source_kind in ("dpl", "dpl_derived") and not self.source_path.startswith("dpl."):
            raise ValueError(
                f"{self.source_kind} numeric claim {self.name!r} must cite a dpl.* source"
            )
        if self.source_kind == "solver_diagnostic" and not self.source_path.startswith(
            "solver_diagnostics."
        ):
            raise ValueError(
                f"solver diagnostic claim {self.name!r} must cite solver_diagnostics.*"
            )
        if self.source_kind == "dpl_derived" and not self.derivation:
            raise ValueError(f"derived numeric claim {self.name!r} must record derivation")
        return self


class ReasonCitation(BaseModel):
    """A reason id as cited by the explanation."""

    model_config = ConfigDict(extra="forbid")

    reason_id: str = Field(pattern=r"^(?:LEAK|TRG|MIX)_")
    namespace: ReasonNamespace
    label: str = Field(min_length=1)
    description: str = Field(min_length=1)
    source_path: str = Field(min_length=1)

    @model_validator(mode="after")
    def _matches_ontology(self) -> ReasonCitation:
        ontology = get_ontology()
        if not ontology.has(self.reason_id):
            raise ValueError(f"unknown reason id {self.reason_id!r}")
        entry = ontology.get(self.reason_id)
        actual_namespace = _namespace(self.reason_id)
        if self.namespace != actual_namespace or entry.namespace != self.namespace:
            raise ValueError(f"reason {self.reason_id!r} is not in namespace {self.namespace!r}")
        if self.label != entry.label:
            raise ValueError(f"reason {self.reason_id!r} label does not match ontology")
        if self.description != entry.description:
            raise ValueError(f"reason {self.reason_id!r} description does not match ontology")
        return self


class PolicyReasonSet(BaseModel):
    """Policy reasons: leak hypotheses and trigger checks, never sampling reasons."""

    model_config = ConfigDict(extra="forbid")

    leak_reasons: list[ReasonCitation] = Field(default_factory=list)
    trigger_reasons: list[ReasonCitation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _namespaces_are_policy_only(self) -> PolicyReasonSet:
        for citation in self.leak_reasons:
            if citation.namespace != "LEAK":
                raise ValueError("leak_reasons may only contain LEAK reasons")
        for citation in self.trigger_reasons:
            if citation.namespace != "TRG":
                raise ValueError("trigger_reasons may only contain TRG reasons")
        return self

    @property
    def reason_ids(self) -> list[str]:
        return [
            *(c.reason_id for c in self.leak_reasons),
            *(c.reason_id for c in self.trigger_reasons),
        ]


class SamplingReasonSet(BaseModel):
    """Execution reasons: why this concrete action was realised from final policy."""

    model_config = ConfigDict(extra="forbid")

    selected_action: str = Field(min_length=1)
    selected_action_probability: NumericClaim
    sampling_seed: NumericClaim | None = None
    mix_reasons: list[ReasonCitation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _namespaces_are_sampling_only(self) -> SamplingReasonSet:
        for citation in self.mix_reasons:
            if citation.namespace != "MIX":
                raise ValueError("mix_reasons may only contain MIX reasons")
        if self.selected_action_probability.name != "selected_action_probability":
            raise ValueError("selected_action_probability claim has the wrong name")
        if self.sampling_seed is not None and self.sampling_seed.name != "sampling_seed":
            raise ValueError("sampling_seed claim has the wrong name")
        return self

    @property
    def reason_ids(self) -> list[str]:
        return [citation.reason_id for citation in self.mix_reasons]


class ExplanationStage(BaseModel):
    """One of the five required explanation stages."""

    model_config = ConfigDict(extra="forbid")

    stage: ExplanationStageName
    title: str = Field(min_length=1)
    text: str = Field(min_length=1)
    cited_reason_ids: list[str] = Field(default_factory=list)
    numeric_claims: list[NumericClaim] = Field(default_factory=list)

    @field_validator("cited_reason_ids")
    @classmethod
    def _known_unique_reasons(cls, value: list[str]) -> list[str]:
        return _validate_known_unique(value, "cited_reason_ids")


class EVBreakdown(BaseModel):
    """Decision-level EV facts, with optional solver diagnostics kept separate."""

    model_config = ConfigDict(extra="forbid")

    base_ev: NumericClaim
    exploit_ev: NumericClaim
    final_ev: NumericClaim
    exploit_ev_delta: NumericClaim
    decision_ev_delta: NumericClaim
    worst_case_penalty: NumericClaim | None = None
    solver_ev_delta: NumericClaim | None = None

    @model_validator(mode="after")
    def _ev_delta_sources_are_not_mixed(self) -> EVBreakdown:
        if self.decision_ev_delta.name != "decision_ev_delta":
            raise ValueError("decision_ev_delta claim has the wrong name")
        if self.decision_ev_delta.source_kind != "dpl_derived":
            raise ValueError("decision_ev_delta must be derived from DPL decision EV fields")
        if self.solver_ev_delta is not None:
            if self.solver_ev_delta.name != "solver_ev_delta":
                raise ValueError("solver_ev_delta claim has the wrong name")
            if self.solver_ev_delta.source_kind != "solver_diagnostic":
                raise ValueError("solver_ev_delta must come from solver diagnostics")
        return self


class CounterfactualExplanation(BaseModel):
    """Counterfactual view of the selected action without the policy adjustment."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1)
    text: str = Field(min_length=1)
    baseline_selected_action_probability: NumericClaim
    final_selected_action_probability: NumericClaim
    decision_ev_delta: NumericClaim

    @model_validator(mode="after")
    def _counterfactual_claims_are_decision_level(self) -> CounterfactualExplanation:
        if self.baseline_selected_action_probability.name != "baseline_selected_action_probability":
            raise ValueError("baseline selected-action probability claim has the wrong name")
        if self.final_selected_action_probability.name != "final_selected_action_probability":
            raise ValueError("final selected-action probability claim has the wrong name")
        if self.decision_ev_delta.name != "decision_ev_delta":
            raise ValueError("counterfactual must cite the decision-level EV delta")
        if self.decision_ev_delta.source_kind != "dpl_derived":
            raise ValueError("counterfactual EV delta must be decision-level DPL-derived")
        return self


class SolverDiagnostics(BaseModel):
    """Optional solver-level diagnostics that are not part of the DPL decision EV."""

    model_config = ConfigDict(extra="forbid")

    solver_result_id: str = Field(min_length=1)
    solver_ev_delta: NumericClaim

    @model_validator(mode="after")
    def _solver_ev_delta_is_solver_level(self) -> SolverDiagnostics:
        if self.solver_ev_delta.name != "solver_ev_delta":
            raise ValueError("solver diagnostics must use a solver_ev_delta claim")
        if self.solver_ev_delta.source_kind != "solver_diagnostic":
            raise ValueError("solver diagnostics EV delta must be solver_diagnostic")
        return self


class ExplanationDocument(BaseModel):
    """Complete template explanation object for one DPL decision."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = EXPLANATION_SCHEMA_VERSION
    dpl_ref: str = Field(min_length=1)
    source_dpl_schema_version: str = Field(min_length=1)
    reason_ontology_version: str = Field(min_length=1)
    generator: GeneratorKind = TEMPLATE_GENERATOR
    generator_version: str = TEMPLATE_GENERATOR_VERSION
    allowed_reason_ids: list[str] = Field(default_factory=list)
    policy_reasons: PolicyReasonSet
    sampling_reasons: SamplingReasonSet
    stages: tuple[
        ExplanationStage,
        ExplanationStage,
        ExplanationStage,
        ExplanationStage,
        ExplanationStage,
    ]
    ev_breakdown: EVBreakdown
    counterfactual: CounterfactualExplanation
    rendered_text: str = Field(min_length=1)

    @field_validator("schema_version")
    @classmethod
    def _supported_schema_version(cls, value: str) -> str:
        if value != EXPLANATION_SCHEMA_VERSION:
            raise ValueError(f"unsupported explanation schema_version {value!r}")
        return value

    @field_validator("allowed_reason_ids")
    @classmethod
    def _allowed_reason_ids_known(cls, value: list[str]) -> list[str]:
        return _validate_known_unique(value, "allowed_reason_ids")

    @model_validator(mode="after")
    def _closed_world_and_stage_order(self) -> ExplanationDocument:
        stages = tuple(stage.stage for stage in self.stages)
        if stages != STAGE_ORDER:
            raise ValueError(f"explanation stages must be ordered as {STAGE_ORDER}")

        allowed = set(self.allowed_reason_ids)
        cited = set(self.policy_reasons.reason_ids) | set(self.sampling_reasons.reason_ids)
        for stage in self.stages:
            cited.update(stage.cited_reason_ids)
        unallowed = sorted(cited - allowed)
        if unallowed:
            raise ValueError(f"explanation cites reason ids not in allowed_reason_ids: {unallowed}")
        return self
