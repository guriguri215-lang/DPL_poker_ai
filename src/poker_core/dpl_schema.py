"""Decision Provenance Log (DPL) schema v1 -- the project's core contract.

The DPL is the structured, auditable record of *why* the AI adjusted its policy
on a single decision. Every downstream artefact (template explanations, the
future LLM surface layer, the Explanation Verifier and the paper's faithfulness
metrics) is defined against this schema, which is frozen in Phase 0 and may only
change with an ADR and a ``schema_version`` bump (ADR-0006).

Key contracts encoded here:

* Reason ids are namespace-separated (ADR-0001). ``detected_leaks[].reason_id``
  must be ``LEAK_*`` and ``trigger_reasons`` must be ``TRG_*``; every id is
  resolved against :mod:`poker_core.reason_ontology`.
* EV provenance is explicit (ADR-0008). ``ev_estimate.ev_source`` is required and
  **only** ``solver_exact`` EVs are cleared for use in explanations. Use
  :meth:`EvEstimate.explanation_values` / :meth:`DecisionProvenanceLog.ev_for_explanation`
  to obtain the EV payload an explanation is allowed to cite; a heuristic or
  estimate source yields ``None`` so no unverifiable number can reach the reader.
* Policies (base / exploit / final) are proper distributions that sum to 1.0.
"""

from __future__ import annotations

import math
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from .reason_ontology import get_ontology

#: Current DPL schema version. Bump (with an ADR) on any breaking change.
DPL_SCHEMA_VERSION = "1.0.0"

#: Absolute tolerance for the "policy probabilities sum to 1.0" check.
POLICY_SUM_TOL = 1e-6

HandBucket = Literal["nuts", "strong_value", "marginal", "weak_showdown", "air"]
ExploitSource = Literal["rule_based", "nodelock_solver"]
EvSource = Literal["solver_exact", "solver_estimate", "heuristic"]

#: The only ``ev_source`` whose EV values may appear in an explanation (ADR-0008).
EXPLANATION_SAFE_EV_SOURCE = "solver_exact"


def _check_policy(policy: dict[str, float]) -> dict[str, float]:
    """Validate that ``policy`` is a non-empty probability distribution."""
    if not policy:
        raise ValueError("policy must not be empty")
    for action, prob in policy.items():
        if not 0.0 <= prob <= 1.0:
            raise ValueError(f"policy probability for {action!r} is out of [0, 1]: {prob}")
    total = math.fsum(policy.values())
    if abs(total - 1.0) > POLICY_SUM_TOL:
        raise ValueError(f"policy probabilities must sum to 1.0 (got {total})")
    return policy


#: A validated action -> probability distribution.
Policy = Annotated[dict[str, float], AfterValidator(_check_policy)]


def _validate_reason_ids(
    reason_ids: list[str], namespace: str | None, field_name: str
) -> list[str]:
    """Reject unknown ids, wrong-namespace ids and duplicates."""
    ontology = get_ontology()
    seen: set[str] = set()
    for rid in reason_ids:
        if rid in seen:
            raise ValueError(f"{field_name} contains duplicate reason id {rid!r}")
        seen.add(rid)
        if not ontology.is_valid(rid, namespace=namespace):
            if not ontology.has(rid):
                raise ValueError(f"{field_name} contains unknown reason id {rid!r}")
            raise ValueError(f"{field_name} requires a {namespace}_ reason id but got {rid!r}")
    return reason_ids


class DetectedLeak(BaseModel):
    """One opponent-leak hypothesis produced by the Leak Detector (Spec 6.6)."""

    model_config = ConfigDict(extra="forbid")

    reason_id: str
    leak_type: str
    situation_key: str
    observed_rate: float = Field(ge=0.0, le=1.0)
    baseline_rate: float = Field(ge=0.0, le=1.0)
    effective_sample_size: int = Field(ge=0)
    confidence: float = Field(ge=0.0, le=1.0)
    direction: str

    @model_validator(mode="after")
    def _reason_id_is_known_leak(self) -> DetectedLeak:
        ontology = get_ontology()
        if not ontology.has(self.reason_id):
            raise ValueError(f"unknown reason id {self.reason_id!r}")
        if not ontology.is_valid(self.reason_id, namespace="LEAK"):
            raise ValueError(
                f"detected_leaks requires a LEAK_ reason id but got {self.reason_id!r}"
            )
        expected_label = ontology.get(self.reason_id).label
        if self.leak_type != expected_label:
            raise ValueError(
                f"leak_type {self.leak_type!r} does not match ontology label "
                f"{expected_label!r} for {self.reason_id!r}"
            )
        return self


class EvEstimate(BaseModel):
    """Expected-value estimates for the base / exploit / final policies (Spec 6.11).

    Per ADR-0008 the provenance of these numbers is explicit and only
    ``solver_exact`` values are cleared for explanations. Downstream explanation
    code MUST obtain EV numbers via :meth:`explanation_values` (or
    :meth:`DecisionProvenanceLog.ev_for_explanation`) rather than reading the raw
    fields, so that heuristic or estimated EVs never reach the reader.
    """

    model_config = ConfigDict(extra="forbid")

    base_ev: float
    exploit_ev: float
    final_ev: float
    worst_case_penalty: float | None = None
    ev_source: EvSource
    ev_unit: str = Field(min_length=1)
    ev_definition: str = Field(min_length=1)

    @model_validator(mode="after")
    def _worst_case_requires_solver(self) -> EvEstimate:
        # worst_case_penalty is defined as a Mode-2 (Hero fixed, opponent BR)
        # solver result (ADR-0008); a heuristic source cannot produce it.
        if self.worst_case_penalty is not None and self.ev_source == "heuristic":
            raise ValueError("worst_case_penalty must be null when ev_source is 'heuristic'")
        return self

    @property
    def gain_vs_base(self) -> float:
        """Final EV minus base EV (derived; not stored)."""
        return self.final_ev - self.base_ev

    @property
    def is_explanation_safe(self) -> bool:
        """True when these EVs may be cited in an explanation (ADR-0008)."""
        return self.ev_source == EXPLANATION_SAFE_EV_SOURCE

    def explanation_values(self) -> dict[str, float | None] | None:
        """EV payload permitted in an explanation, or ``None`` if not allowed.

        Returns ``None`` unless ``ev_source == "solver_exact"``. This is the only
        supported way for explanation code to read EV numbers (ADR-0008).
        """
        if not self.is_explanation_safe:
            return None
        return {
            "base_ev": self.base_ev,
            "exploit_ev": self.exploit_ev,
            "final_ev": self.final_ev,
            "worst_case_penalty": self.worst_case_penalty,
            "gain_vs_base": self.gain_vs_base,
        }


class DecisionProvenanceLog(BaseModel):
    """One decision's full provenance record (Spec 6.11; the project core)."""

    model_config = ConfigDict(extra="forbid")

    # --- identity / versioning ---
    hand_id: str
    session_id: str
    schema_version: str = DPL_SCHEMA_VERSION

    # --- situation ---
    state_cluster: str
    cluster_def_version: str
    hand_bucket: HandBucket

    # --- policies and adjustment ---
    base_policy: Policy
    detected_leaks: list[DetectedLeak] = Field(default_factory=list)
    trigger_reasons: list[str] = Field(default_factory=list)
    exploit_policy: Policy
    exploit_source: ExploitSource
    solver_result_id: str | None = None
    safety_alpha: float = Field(ge=0.0, le=1.0)
    final_policy: Policy

    # --- realised action ---
    selected_action: str
    sampling_seed: int | None

    # --- valuation and explanation contract ---
    ev_estimate: EvEstimate
    allowed_reason_ids: list[str]
    baseline_table_version: str

    @field_validator("schema_version")
    @classmethod
    def _supported_schema_version(cls, value: str) -> str:
        if value != DPL_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported DPL schema_version {value!r}; "
                f"this build writes {DPL_SCHEMA_VERSION!r}"
            )
        return value

    @field_validator("trigger_reasons")
    @classmethod
    def _trigger_reasons_are_trg(cls, value: list[str]) -> list[str]:
        return _validate_reason_ids(value, namespace="TRG", field_name="trigger_reasons")

    @field_validator("allowed_reason_ids")
    @classmethod
    def _allowed_reason_ids_known(cls, value: list[str]) -> list[str]:
        # allowed_reason_ids is the closed-world whitelist for the explanation
        # generator (Spec 6.10); ids may come from any namespace but must exist.
        return _validate_reason_ids(value, namespace=None, field_name="allowed_reason_ids")

    @model_validator(mode="after")
    def _cross_field_checks(self) -> DecisionProvenanceLog:
        if self.exploit_source == "nodelock_solver" and self.solver_result_id is None:
            raise ValueError(
                "solver_result_id is required when exploit_source is 'nodelock_solver'"
            )
        if self.selected_action not in self.final_policy:
            raise ValueError(
                f"selected_action {self.selected_action!r} is not a key of final_policy"
            )
        return self

    def ev_for_explanation(self) -> dict[str, float | None] | None:
        """EV payload the explanation may cite, or ``None`` (ADR-0008)."""
        return self.ev_estimate.explanation_values()
