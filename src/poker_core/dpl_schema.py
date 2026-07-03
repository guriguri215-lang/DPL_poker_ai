"""Decision Provenance Log (DPL) schema v1 -- the project's core contract.

The DPL is the structured, auditable record of *why* the AI adjusted its policy
on a single decision. Every downstream artefact (template explanations, the
future LLM surface layer, the Explanation Verifier and the paper's faithfulness
metrics) is defined against this schema, which is frozen in Phase 0 and may only
change with an ADR and a ``schema_version`` bump (ADR-0006).

Key contracts encoded here:

* Reason ids are namespace-separated (ADR-0001), stored in three separate fields:
  ``detected_leaks[].reason_id`` (``LEAK_*``), ``trigger_reasons`` (``TRG_*``) and
  ``mix_reasons`` (``MIX_*``, the execution reasons of Spec 6.9). Every id is
  resolved against :mod:`poker_core.reason_ontology`. ``allowed_reason_ids`` is the
  closed-world explanation whitelist and must be a subset of the reasons actually
  recorded in those three fields -- an explanation can only cite a reason the
  decision actually rests on.
* The realised policy is a genuine safety mix: ``final_policy`` must equal
  ``(1 - safety_alpha) * base_policy + safety_alpha * exploit_policy`` over the
  union of actions (within :data:`MIXING_ABS_TOL`), and ``selected_action`` must be
  an action carried with positive probability by ``final_policy`` (Spec 6.8/6.9).
* Both the ``hand_bucket`` and the concrete ``hero_combo`` are recorded (ADR-0005;
  ``hero_combo`` is a string until Phase 1 introduces a typed card/combo model).
* EV provenance is explicit (ADR-0008). ``ev_estimate.ev_source`` is required and
  **only** ``solver_exact`` EVs are cleared for use in explanations. Use
  :meth:`EvEstimate.explanation_values` / :meth:`DecisionProvenanceLog.ev_for_explanation`
  to obtain the EV payload an explanation is allowed to cite; a heuristic or
  estimate source yields ``None`` so no unverifiable number can reach the reader.
* Policies (base / exploit / final) are proper distributions that sum to 1.0.

The exported JSON Schema captures structure, enums, ranges and the reason-id
namespace patterns, but the cross-field semantics above are enforced only by this
pydantic model, which is the canonical validator.
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

#: Absolute tolerance for the "final == alpha-mix of base and exploit" check.
MIXING_ABS_TOL = 1e-6

HandBucket = Literal["nuts", "strong_value", "marginal", "weak_showdown", "air"]
ExploitSource = Literal["rule_based", "nodelock_solver"]
EvSource = Literal["solver_exact", "solver_estimate", "heuristic"]

#: The only ``ev_source`` whose EV values may appear in an explanation (ADR-0008).
EXPLANATION_SAFE_EV_SOURCE = "solver_exact"

# Reason-id string types carrying the namespace prefix as a JSON-Schema pattern
# (ADR-0001). The pattern gives structural namespace enforcement that survives
# export to JSON Schema; membership in the ontology is checked separately.
LeakReasonId = Annotated[str, Field(pattern=r"^LEAK_")]
TrgReasonId = Annotated[str, Field(pattern=r"^TRG_")]
MixReasonId = Annotated[str, Field(pattern=r"^MIX_")]
AnyReasonId = Annotated[str, Field(pattern=r"^(?:LEAK|TRG|MIX)_")]


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


def _validate_known_unique(reason_ids: list[str], field_name: str) -> list[str]:
    """Reject unknown (not in ontology) reason ids and duplicates.

    Namespace membership is enforced by the field's string pattern; this checks
    that each id is actually defined and appears at most once.
    """
    ontology = get_ontology()
    seen: set[str] = set()
    for rid in reason_ids:
        if rid in seen:
            raise ValueError(f"{field_name} contains duplicate reason id {rid!r}")
        seen.add(rid)
        if not ontology.has(rid):
            raise ValueError(f"{field_name} contains unknown reason id {rid!r}")
    return reason_ids


class DetectedLeak(BaseModel):
    """One opponent-leak hypothesis produced by the Leak Detector (Spec 6.6)."""

    model_config = ConfigDict(extra="forbid")

    reason_id: LeakReasonId
    leak_type: str
    situation_key: str
    observed_rate: float = Field(ge=0.0, le=1.0)
    baseline_rate: float = Field(ge=0.0, le=1.0)
    effective_sample_size: int = Field(ge=0)
    confidence: float = Field(ge=0.0, le=1.0)
    direction: str

    @model_validator(mode="after")
    def _reason_id_is_known_leak(self) -> DetectedLeak:
        # The ``^LEAK_`` pattern already guarantees the namespace; here we check
        # the id exists and that leak_type matches its ontology label.
        ontology = get_ontology()
        if not ontology.has(self.reason_id):
            raise ValueError(f"unknown reason id {self.reason_id!r}")
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
    hero_combo: str = Field(min_length=1)

    # --- policies and adjustment ---
    base_policy: Policy
    detected_leaks: list[DetectedLeak] = Field(default_factory=list)
    trigger_reasons: list[TrgReasonId] = Field(default_factory=list)
    mix_reasons: list[MixReasonId] = Field(default_factory=list)
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
    allowed_reason_ids: list[AnyReasonId]
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
    def _trigger_reasons_known(cls, value: list[str]) -> list[str]:
        return _validate_known_unique(value, field_name="trigger_reasons")

    @field_validator("mix_reasons")
    @classmethod
    def _mix_reasons_known(cls, value: list[str]) -> list[str]:
        return _validate_known_unique(value, field_name="mix_reasons")

    @field_validator("allowed_reason_ids")
    @classmethod
    def _allowed_reason_ids_known(cls, value: list[str]) -> list[str]:
        return _validate_known_unique(value, field_name="allowed_reason_ids")

    @model_validator(mode="after")
    def _cross_field_checks(self) -> DecisionProvenanceLog:
        if self.exploit_source == "nodelock_solver" and self.solver_result_id is None:
            raise ValueError(
                "solver_result_id is required when exploit_source is 'nodelock_solver'"
            )
        self._check_selected_action()
        self._check_mixing_consistency()
        self._check_allowed_reason_ids_backed()
        return self

    def _check_selected_action(self) -> None:
        if self.selected_action not in self.final_policy:
            raise ValueError(
                f"selected_action {self.selected_action!r} is not a key of final_policy"
            )
        if self.final_policy[self.selected_action] <= 0.0:
            raise ValueError(
                f"selected_action {self.selected_action!r} must have positive probability "
                f"in final_policy (got {self.final_policy[self.selected_action]})"
            )

    def _check_mixing_consistency(self) -> None:
        # final must be the alpha-mixture of base and exploit over the union of
        # actions (missing actions treated as probability 0), Spec 6.8.
        alpha = self.safety_alpha
        actions = set(self.base_policy) | set(self.exploit_policy) | set(self.final_policy)
        for action in actions:
            expected = (1.0 - alpha) * self.base_policy.get(action, 0.0) + alpha * (
                self.exploit_policy.get(action, 0.0)
            )
            actual = self.final_policy.get(action, 0.0)
            if abs(actual - expected) > MIXING_ABS_TOL:
                raise ValueError(
                    f"final_policy[{action!r}]={actual} does not match the alpha-mix "
                    f"{expected} of base/exploit at safety_alpha={alpha}"
                )

    def _check_allowed_reason_ids_backed(self) -> None:
        # Closed-world: an explanation may only cite reasons the decision records
        # (ADR-0001; Spec 6.10). allowed_reason_ids must be backed by an actually
        # recorded LEAK/TRG/MIX reason.
        recorded = (
            {leak.reason_id for leak in self.detected_leaks}
            | set(self.trigger_reasons)
            | set(self.mix_reasons)
        )
        unbacked = [rid for rid in self.allowed_reason_ids if rid not in recorded]
        if unbacked:
            raise ValueError(
                f"allowed_reason_ids {unbacked} are not backed by any recorded reason "
                f"(detected_leaks / trigger_reasons / mix_reasons)"
            )

    def ev_for_explanation(self) -> dict[str, float | None] | None:
        """EV payload the explanation may cite, or ``None`` (ADR-0008)."""
        return self.ev_estimate.explanation_values()
