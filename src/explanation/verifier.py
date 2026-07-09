"""Independent verification for structured explanation documents.

This module intentionally does not import the template generator. It accepts the
contract model as data, then re-resolves cited DPL and solver diagnostic facts
with its own source-path and derivation checks.
"""

from __future__ import annotations

import ast
import math
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ValidationError

from poker_core.dpl_schema import EXPLANATION_SAFE_EV_SOURCE, DecisionProvenanceLog
from poker_core.reason_ontology import get_ontology, namespace_of

from .contract import ExplanationDocument, NumericClaim, ReasonCitation, SolverDiagnostics

NUMERIC_ABS_TOL = 1e-9
NUMERIC_REL_TOL = 1e-9
SURFACE_PERCENT_DECIMALS = 1
SURFACE_EV_DECIMALS = 4

_FIELD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_DETECTED_CLAIM_RE = re.compile(
    r"detected_leaks\[(?P<index>\d+)\]\.(?P<field>observed_rate|baseline_rate|confidence)"
)
_SURFACE_REASON_RE = re.compile(r"\b(?:LEAK|TRG|MIX)_[A-Z0-9_]+\b")
_SURFACE_NUMERIC_RE = re.compile(
    r"(?P<value>[+-]?(?:\d+(?:\.\d*)?|\.\d+))\s*(?P<unit>%|bb)(?![A-Za-z0-9_])"
)

PathToken = tuple[str, str | int]


@dataclass(frozen=True)
class VerificationIssue:
    """One explanation verification failure."""

    code: str
    location: str
    message: str


@dataclass(frozen=True)
class VerificationResult:
    """Verification result with all failures found in one pass."""

    issues: tuple[VerificationIssue, ...] = ()

    @property
    def passed(self) -> bool:
        return not self.issues

    def raise_for_issues(self) -> None:
        if not self.passed:
            raise ExplanationVerificationError(self)


class ExplanationVerificationError(ValueError):
    """Raised when a caller requests exception-style verification."""

    def __init__(self, result: VerificationResult) -> None:
        self.result = result
        details = "; ".join(f"{issue.location}: {issue.message}" for issue in result.issues[:3])
        suffix = "" if len(result.issues) <= 3 else f"; ... {len(result.issues) - 3} more"
        super().__init__(f"explanation verification failed: {details}{suffix}")


def verify_explanation(
    explanation: ExplanationDocument | Mapping[str, Any],
    dpl: DecisionProvenanceLog | Mapping[str, Any],
    *,
    solver_diagnostics: SolverDiagnostics | Mapping[str, Any] | None = None,
) -> VerificationResult:
    """Verify an explanation against the DPL and optional solver diagnostics."""

    issues: list[VerificationIssue] = []
    try:
        dpl_model = _coerce_model(dpl, DecisionProvenanceLog)
    except ValidationError as exc:
        issues.append(_validation_issue("dpl", exc))
        return VerificationResult(tuple(issues))

    try:
        explanation_model = _coerce_model(explanation, ExplanationDocument)
    except ValidationError as exc:
        issues.append(_validation_issue("explanation", exc))
        return VerificationResult(tuple(issues))

    diagnostics_model = None
    if solver_diagnostics is not None:
        try:
            diagnostics_model = _coerce_model(solver_diagnostics, SolverDiagnostics)
        except ValidationError as exc:
            issues.append(_validation_issue("solver_diagnostics", exc))
            return VerificationResult(tuple(issues))

    verifier = _ExplanationVerifier(
        explanation=explanation_model,
        dpl=dpl_model,
        solver_diagnostics=diagnostics_model,
    )
    return verifier.run()


def verify_explanation_or_raise(
    explanation: ExplanationDocument | Mapping[str, Any],
    dpl: DecisionProvenanceLog | Mapping[str, Any],
    *,
    solver_diagnostics: SolverDiagnostics | Mapping[str, Any] | None = None,
) -> None:
    """Verify an explanation and raise with aggregated issues on failure."""

    verify_explanation(
        explanation,
        dpl,
        solver_diagnostics=solver_diagnostics,
    ).raise_for_issues()


class _ExplanationVerifier:
    def __init__(
        self,
        *,
        explanation: ExplanationDocument,
        dpl: DecisionProvenanceLog,
        solver_diagnostics: SolverDiagnostics | None,
    ) -> None:
        self.explanation = explanation
        self.dpl = dpl
        self.solver_diagnostics = solver_diagnostics
        self.issues: list[VerificationIssue] = []

    def run(self) -> VerificationResult:
        self._verify_metadata()
        self._verify_reason_validity()
        self._verify_numeric_claims()
        self._verify_rendered_text()
        return VerificationResult(tuple(self.issues))

    def _add(self, code: str, location: str, message: str) -> None:
        self.issues.append(VerificationIssue(code=code, location=location, message=message))

    def _verify_metadata(self) -> None:
        expected_ref = f"{self.dpl.session_id}:{self.dpl.hand_id}"
        if self.explanation.dpl_ref != expected_ref:
            self._add(
                "metadata_mismatch",
                "dpl_ref",
                f"expected {expected_ref!r}, got {self.explanation.dpl_ref!r}",
            )
        if self.explanation.source_dpl_schema_version != self.dpl.schema_version:
            self._add(
                "metadata_mismatch",
                "source_dpl_schema_version",
                (
                    f"expected {self.dpl.schema_version!r}, "
                    f"got {self.explanation.source_dpl_schema_version!r}"
                ),
            )
        ontology_version = get_ontology().ontology_version
        if self.explanation.reason_ontology_version != ontology_version:
            self._add(
                "metadata_mismatch",
                "reason_ontology_version",
                f"expected {ontology_version!r}, got {self.explanation.reason_ontology_version!r}",
            )
        if list(self.explanation.allowed_reason_ids) != list(self.dpl.allowed_reason_ids):
            self._add(
                "reason_allowed_mismatch",
                "allowed_reason_ids",
                "explanation allowed_reason_ids must match the DPL whitelist",
            )
        self._check_unique("allowed_reason_ids", self.explanation.allowed_reason_ids)

    def _verify_reason_validity(self) -> None:
        allowed = set(self.explanation.allowed_reason_ids)
        ontology = get_ontology()

        for reason_id in self.explanation.allowed_reason_ids:
            if not ontology.has(reason_id):
                self._add(
                    "reason_unknown",
                    "allowed_reason_ids",
                    f"{reason_id!r} is not defined in the ontology",
                )

        policy_leak_ids = [c.reason_id for c in self.explanation.policy_reasons.leak_reasons]
        policy_trigger_ids = [c.reason_id for c in self.explanation.policy_reasons.trigger_reasons]
        sampling_mix_ids = [c.reason_id for c in self.explanation.sampling_reasons.mix_reasons]
        self._check_unique("policy_reasons.leak_reasons", policy_leak_ids)
        self._check_unique("policy_reasons.trigger_reasons", policy_trigger_ids)
        self._check_unique("sampling_reasons.mix_reasons", sampling_mix_ids)

        expected_reason_ids = self._allowed_reason_ids_by_namespace()
        self._check_reason_set_matches(
            "policy_reasons.leak_reasons",
            policy_leak_ids,
            expected_reason_ids["LEAK"],
        )
        self._check_reason_set_matches(
            "policy_reasons.trigger_reasons",
            policy_trigger_ids,
            expected_reason_ids["TRG"],
        )
        self._check_reason_set_matches(
            "sampling_reasons.mix_reasons",
            sampling_mix_ids,
            expected_reason_ids["MIX"],
        )

        for index, citation in enumerate(self.explanation.policy_reasons.leak_reasons):
            self._verify_reason_citation(
                citation,
                location=f"policy_reasons.leak_reasons[{index}]",
                allowed=allowed,
                expected_namespace="LEAK",
            )
        for index, citation in enumerate(self.explanation.policy_reasons.trigger_reasons):
            self._verify_reason_citation(
                citation,
                location=f"policy_reasons.trigger_reasons[{index}]",
                allowed=allowed,
                expected_namespace="TRG",
            )
        for index, citation in enumerate(self.explanation.sampling_reasons.mix_reasons):
            self._verify_reason_citation(
                citation,
                location=f"sampling_reasons.mix_reasons[{index}]",
                allowed=allowed,
                expected_namespace="MIX",
            )

        if self.explanation.sampling_reasons.selected_action != self.dpl.selected_action:
            self._add(
                "selected_action_mismatch",
                "sampling_reasons.selected_action",
                (
                    f"expected {self.dpl.selected_action!r}, "
                    f"got {self.explanation.sampling_reasons.selected_action!r}"
                ),
            )

        stage_backing: dict[str, tuple[str | None, set[str]]] = {
            "observation": ("LEAK", set(policy_leak_ids)),
            "hypothesis": ("LEAK", set(policy_leak_ids)),
            "validation": ("TRG", set(policy_trigger_ids)),
            "adjustment": ("MIX", set(sampling_mix_ids)),
            "residual_risk": (None, set()),
        }
        stage_expected_reason_ids: dict[str, set[str]] = {
            "observation": expected_reason_ids["LEAK"],
            "hypothesis": expected_reason_ids["LEAK"],
            "validation": expected_reason_ids["TRG"],
            "adjustment": expected_reason_ids["MIX"],
            "residual_risk": set(),
        }
        for index, stage in enumerate(self.explanation.stages):
            location = f"stages[{index}].cited_reason_ids"
            self._check_unique(location, stage.cited_reason_ids)
            self._check_reason_set_matches(
                location,
                stage.cited_reason_ids,
                stage_expected_reason_ids[stage.stage],
                missing_code="stage_reason_missing",
                unexpected_code="stage_reason_unexpected",
            )
            expected_namespace, backed_ids = stage_backing[stage.stage]
            for reason_id in stage.cited_reason_ids:
                if reason_id not in allowed:
                    self._add(
                        "reason_not_allowed",
                        location,
                        f"{reason_id!r} is not in allowed_reason_ids",
                    )
                actual_namespace = namespace_of(reason_id)
                if expected_namespace is None:
                    self._add(
                        "stage_reason_namespace_mismatch",
                        location,
                        f"{stage.stage!r} must not cite reason ids",
                    )
                elif actual_namespace != expected_namespace:
                    self._add(
                        "stage_reason_namespace_mismatch",
                        location,
                        (
                            f"{stage.stage!r} may cite {expected_namespace}_ reasons, "
                            f"got {reason_id!r}"
                        ),
                    )
                elif reason_id not in backed_ids:
                    self._add(
                        "stage_reason_unbacked",
                        location,
                        f"{reason_id!r} is not present in the matching reason set",
                    )

    def _verify_reason_citation(
        self,
        citation: ReasonCitation,
        *,
        location: str,
        allowed: set[str],
        expected_namespace: str,
    ) -> None:
        ontology = get_ontology()
        if citation.reason_id not in allowed:
            self._add(
                "reason_not_allowed",
                f"{location}.reason_id",
                f"{citation.reason_id!r} is not in allowed_reason_ids",
            )
        actual_namespace = namespace_of(citation.reason_id)
        if citation.namespace != expected_namespace or actual_namespace != expected_namespace:
            self._add(
                "reason_namespace_mismatch",
                f"{location}.namespace",
                f"expected {expected_namespace!r} for {citation.reason_id!r}",
            )
        if not ontology.has(citation.reason_id):
            self._add(
                "reason_unknown",
                f"{location}.reason_id",
                f"{citation.reason_id!r} is not defined in the ontology",
            )
        else:
            entry = ontology.get(citation.reason_id)
            if citation.label != entry.label or citation.description != entry.description:
                self._add(
                    "reason_ontology_mismatch",
                    location,
                    f"{citation.reason_id!r} label or description does not match ontology",
                )
        if not _reason_source_shape_matches(citation.source_path, expected_namespace):
            self._add(
                "reason_source_path_mismatch",
                f"{location}.source_path",
                f"{citation.source_path!r} is not a {expected_namespace} reason source path",
            )
        try:
            resolved = _resolve_dpl_path(self.dpl, citation.source_path)
        except ValueError as exc:
            self._add("reason_source_unresolved", f"{location}.source_path", str(exc))
            return
        if resolved != citation.reason_id:
            self._add(
                "reason_source_value_mismatch",
                f"{location}.source_path",
                f"source resolves to {resolved!r}, not {citation.reason_id!r}",
            )

    def _verify_numeric_claims(self) -> None:
        self._verify_required_solver_diagnostic_claims()
        for location, claim in self._numeric_claims():
            self._verify_numeric_claim(location, claim)

    def _numeric_claims(self) -> Iterator[tuple[str, NumericClaim]]:
        yield (
            "sampling_reasons.selected_action_probability",
            self.explanation.sampling_reasons.selected_action_probability,
        )
        if self.explanation.sampling_reasons.sampling_seed is not None:
            yield "sampling_reasons.sampling_seed", self.explanation.sampling_reasons.sampling_seed

        for stage_index, stage in enumerate(self.explanation.stages):
            for claim_index, claim in enumerate(stage.numeric_claims):
                yield f"stages[{stage_index}].numeric_claims[{claim_index}]", claim

        ev_breakdown = self.explanation.ev_breakdown
        yield "ev_breakdown.base_ev", ev_breakdown.base_ev
        yield "ev_breakdown.exploit_ev", ev_breakdown.exploit_ev
        yield "ev_breakdown.final_ev", ev_breakdown.final_ev
        yield "ev_breakdown.exploit_ev_delta", ev_breakdown.exploit_ev_delta
        yield "ev_breakdown.decision_ev_delta", ev_breakdown.decision_ev_delta
        if ev_breakdown.worst_case_penalty is not None:
            yield "ev_breakdown.worst_case_penalty", ev_breakdown.worst_case_penalty
        if ev_breakdown.solver_ev_delta is not None:
            yield "ev_breakdown.solver_ev_delta", ev_breakdown.solver_ev_delta

        counterfactual = self.explanation.counterfactual
        yield (
            "counterfactual.baseline_selected_action_probability",
            counterfactual.baseline_selected_action_probability,
        )
        yield (
            "counterfactual.final_selected_action_probability",
            counterfactual.final_selected_action_probability,
        )
        yield "counterfactual.decision_ev_delta", counterfactual.decision_ev_delta

    def _verify_numeric_claim(self, location: str, claim: NumericClaim) -> None:
        if not math.isfinite(claim.value):
            self._add("numeric_non_finite", f"{location}.value", "value must be finite")
            return

        if claim.source_kind == "dpl":
            self._verify_direct_dpl_claim(location, claim)
        elif claim.source_kind == "dpl_derived":
            self._verify_derived_dpl_claim(location, claim)
        elif claim.source_kind == "solver_diagnostic":
            self._verify_solver_diagnostic_claim(location, claim)
        else:
            self._add(
                "numeric_source_kind_unknown",
                f"{location}.source_kind",
                f"unsupported source kind {claim.source_kind!r}",
            )

    def _verify_direct_dpl_claim(self, location: str, claim: NumericClaim) -> None:
        if claim.derivation is not None:
            self._add(
                "numeric_derivation_unexpected",
                f"{location}.derivation",
                "direct DPL claims must not carry a derivation",
            )
        if claim.name in {"decision_ev_delta", "exploit_ev_delta", "solver_ev_delta"}:
            self._add(
                "numeric_source_kind_mismatch",
                f"{location}.source_kind",
                f"{claim.name!r} is not a direct DPL field",
            )
        try:
            tokens = _parse_prefixed_path(claim.source_path, "dpl")
            expected_tokens = self._expected_direct_dpl_tokens(claim.name)
            if expected_tokens is None:
                self._add(
                    "numeric_claim_unknown",
                    f"{location}.name",
                    f"{claim.name!r} is not an allowed direct DPL numeric claim",
                )
            elif tokens != expected_tokens:
                self._add(
                    "numeric_source_path_mismatch",
                    f"{location}.source_path",
                    f"{claim.name!r} must cite {_format_dpl_tokens(expected_tokens)}",
                )
            detected_match = _DETECTED_CLAIM_RE.fullmatch(claim.name)
            if detected_match is not None:
                self._verify_detected_leak_numeric_claim_allowed(
                    location,
                    int(detected_match.group("index")),
                )
            resolved = _resolve_path_tokens(self.dpl, tokens)
        except ValueError as exc:
            self._add("numeric_source_unresolved", f"{location}.source_path", str(exc))
            return

        if not _is_number(resolved):
            self._add(
                "numeric_source_not_number",
                f"{location}.source_path",
                f"source resolves to non-numeric value {resolved!r}",
            )
            return
        if _tokens_are_ev_estimate(tokens):
            self._verify_exact_ev_source(location)
        self._compare_number(location, claim.value, float(resolved))
        expected_unit = self._expected_unit_for_direct_tokens(tokens)
        if expected_unit is not None and claim.unit != expected_unit:
            self._add(
                "numeric_unit_mismatch",
                f"{location}.unit",
                f"expected {expected_unit!r}, got {claim.unit!r}",
            )

    def _verify_derived_dpl_claim(self, location: str, claim: NumericClaim) -> None:
        expected: tuple[float, str, str, str] | None
        if claim.name == "decision_ev_delta":
            self._verify_exact_ev_source(location)
            expected = (
                self.dpl.ev_estimate.final_ev - self.dpl.ev_estimate.base_ev,
                self.dpl.ev_estimate.ev_unit,
                "dpl.ev_estimate.final_ev - dpl.ev_estimate.base_ev",
                "final_ev - base_ev",
            )
        elif claim.name == "exploit_ev_delta":
            self._verify_exact_ev_source(location)
            expected = (
                self.dpl.ev_estimate.exploit_ev - self.dpl.ev_estimate.base_ev,
                self.dpl.ev_estimate.ev_unit,
                "dpl.ev_estimate.exploit_ev - dpl.ev_estimate.base_ev",
                "exploit_ev - base_ev",
            )
        elif claim.name == "baseline_selected_action_probability":
            if self.dpl.selected_action in self.dpl.base_policy:
                self._add(
                    "numeric_derivation_unexpected",
                    f"{location}.source_kind",
                    "baseline selected-action probability is present in DPL base_policy",
                )
            expected = (
                0.0,
                "probability",
                "dpl.base_policy",
                "missing action treated as 0 by DPL mixing semantics",
            )
        elif claim.name == "final_selected_action_probability":
            if self.dpl.selected_action in self.dpl.final_policy:
                self._add(
                    "numeric_derivation_unexpected",
                    f"{location}.source_kind",
                    "final selected-action probability is present in DPL final_policy",
                )
            expected = (
                0.0,
                "probability",
                "dpl.final_policy",
                "missing action treated as 0 by DPL final-policy semantics",
            )
        else:
            self._add(
                "numeric_derivation_unknown",
                f"{location}.derivation",
                f"no independent derivation is allowed for {claim.name!r}",
            )
            return

        expected_value, expected_unit, expected_path, expected_derivation = expected
        if claim.source_path != expected_path:
            self._add(
                "numeric_source_path_mismatch",
                f"{location}.source_path",
                f"expected {expected_path!r}, got {claim.source_path!r}",
            )
        if claim.derivation != expected_derivation:
            self._add(
                "numeric_derivation_mismatch",
                f"{location}.derivation",
                f"expected {expected_derivation!r}, got {claim.derivation!r}",
            )
        self._compare_number(location, claim.value, expected_value)
        if claim.unit != expected_unit:
            self._add(
                "numeric_unit_mismatch",
                f"{location}.unit",
                f"expected {expected_unit!r}, got {claim.unit!r}",
            )

    def _verify_solver_diagnostic_claim(self, location: str, claim: NumericClaim) -> None:
        if self.solver_diagnostics is None:
            self._add(
                "solver_diagnostics_missing",
                location,
                "solver diagnostic claim requires solver_diagnostics input",
            )
            return
        if self.dpl.solver_result_id is None:
            self._add(
                "solver_result_missing",
                "dpl.solver_result_id",
                "solver diagnostics require a DPL solver_result_id",
            )
        elif self.solver_diagnostics.solver_result_id != self.dpl.solver_result_id:
            self._add(
                "solver_result_mismatch",
                "solver_diagnostics.solver_result_id",
                "solver diagnostics do not match DPL solver_result_id",
            )

        expected = self.solver_diagnostics.solver_ev_delta
        if claim.name != expected.name:
            self._add(
                "solver_claim_name_mismatch",
                f"{location}.name",
                f"expected {expected.name!r}, got {claim.name!r}",
            )
        if claim.source_path != expected.source_path:
            self._add(
                "solver_source_path_mismatch",
                f"{location}.source_path",
                f"expected {expected.source_path!r}, got {claim.source_path!r}",
            )
        if claim.derivation != expected.derivation:
            self._add(
                "solver_derivation_mismatch",
                f"{location}.derivation",
                f"expected {expected.derivation!r}, got {claim.derivation!r}",
            )
        self._compare_number(location, claim.value, expected.value)
        if claim.unit != expected.unit:
            self._add(
                "solver_unit_mismatch",
                f"{location}.unit",
                f"expected {expected.unit!r}, got {claim.unit!r}",
            )

    def _verify_required_solver_diagnostic_claims(self) -> None:
        if self.solver_diagnostics is None:
            return

        if self.explanation.ev_breakdown.solver_ev_delta is None:
            self._add(
                "solver_ev_delta_missing",
                "ev_breakdown.solver_ev_delta",
                "solver_diagnostics input requires ev_breakdown.solver_ev_delta",
            )

        residual_stage = next(
            (stage for stage in self.explanation.stages if stage.stage == "residual_risk"),
            None,
        )
        residual_has_solver_claim = residual_stage is not None and any(
            claim.name == "solver_ev_delta" for claim in residual_stage.numeric_claims
        )
        if not residual_has_solver_claim:
            self._add(
                "solver_stage_claim_missing",
                "stages.residual_risk.numeric_claims",
                "solver_diagnostics input requires a residual solver_ev_delta claim",
            )

    def _verify_exact_ev_source(self, location: str) -> None:
        if self.dpl.ev_estimate.ev_source != EXPLANATION_SAFE_EV_SOURCE:
            self._add(
                "unsafe_ev_source",
                location,
                (
                    f"EV claims require ev_source={EXPLANATION_SAFE_EV_SOURCE!r}, "
                    f"got {self.dpl.ev_estimate.ev_source!r}"
                ),
            )

    def _compare_number(self, location: str, actual: float, expected: float) -> None:
        if not math.isclose(actual, expected, rel_tol=NUMERIC_REL_TOL, abs_tol=NUMERIC_ABS_TOL):
            self._add(
                "numeric_value_mismatch",
                f"{location}.value",
                f"expected {expected!r}, got {actual!r}",
            )

    def _verify_rendered_text(self) -> None:
        expected = _expected_rendered_text(self.explanation)
        if self.explanation.rendered_text != expected:
            self._add(
                "rendered_text_mismatch",
                "rendered_text",
                "rendered_text must match the structured stage and counterfactual text",
            )

        for location, text in self._surface_texts():
            self._verify_surface_text(location, text)

    def _surface_texts(self) -> Iterator[tuple[str, str]]:
        yield "rendered_text", self.explanation.rendered_text
        for index, stage in enumerate(self.explanation.stages):
            yield f"stages[{index}].title", stage.title
            yield f"stages[{index}].text", stage.text
        yield "counterfactual.title", self.explanation.counterfactual.title
        yield "counterfactual.text", self.explanation.counterfactual.text

    def _verify_surface_text(self, location: str, text: str) -> None:
        allowed_reasons = set(self.explanation.allowed_reason_ids)
        for match in _SURFACE_REASON_RE.finditer(text):
            reason_id = match.group(0)
            if reason_id not in allowed_reasons:
                self._add(
                    "surface_reason_not_allowed",
                    location,
                    f"{reason_id!r} appears in surface text but is not allowed",
                )

        allowed_numbers = self._allowed_surface_numbers()
        for match in _SURFACE_NUMERIC_RE.finditer(text):
            value = float(match.group("value"))
            unit = match.group("unit")
            if not _surface_number_allowed(value, unit, allowed_numbers):
                self._add(
                    "surface_numeric_unbacked",
                    location,
                    f"{match.group(0)!r} appears in surface text without a matching claim",
                )

    def _allowed_surface_numbers(self) -> tuple[tuple[str, float], ...]:
        allowed: list[tuple[str, float]] = []
        for _location, claim in self._numeric_claims():
            if not self._claim_can_back_surface_number(claim):
                continue
            if claim.unit == "probability":
                allowed.append(
                    ("%", _rounded_surface_value(claim.value * 100.0, SURFACE_PERCENT_DECIMALS))
                )
            if claim.unit == self.dpl.ev_estimate.ev_unit:
                allowed.append(
                    (claim.unit, _rounded_surface_value(claim.value, SURFACE_EV_DECIMALS))
                )
        return tuple(allowed)

    def _claim_can_back_surface_number(self, claim: NumericClaim) -> bool:
        if claim.source_kind == "dpl":
            detected_match = _DETECTED_CLAIM_RE.fullmatch(claim.name)
            if detected_match is not None:
                return self._detected_leak_numeric_claim_allowed(int(detected_match.group("index")))
        return True

    def _expected_direct_dpl_tokens(self, claim_name: str) -> tuple[PathToken, ...] | None:
        action = self.dpl.selected_action
        selected_action_tokens = (("attr", "final_policy"), ("key", action))
        if (
            self.dpl.execution_sampling is not None
            and self.dpl.execution_sampling.exploration_fired
        ):
            selected_action_tokens = (
                ("attr", "execution_sampling"),
                ("attr", "execution_policy"),
                ("key", action),
            )
        fixed: dict[str, tuple[PathToken, ...]] = {
            "selected_action_probability": selected_action_tokens,
            "final_selected_action_probability": (("attr", "final_policy"), ("key", action)),
            "baseline_selected_action_probability": (("attr", "base_policy"), ("key", action)),
            "sampling_seed": (("attr", "sampling_seed"),),
            "safety_alpha": (("attr", "safety_alpha"),),
            "base_ev": (("attr", "ev_estimate"), ("attr", "base_ev")),
            "exploit_ev": (("attr", "ev_estimate"), ("attr", "exploit_ev")),
            "final_ev": (("attr", "ev_estimate"), ("attr", "final_ev")),
            "worst_case_penalty": (("attr", "ev_estimate"), ("attr", "worst_case_penalty")),
        }
        if claim_name in fixed:
            return fixed[claim_name]
        match = _DETECTED_CLAIM_RE.fullmatch(claim_name)
        if match is not None:
            return (
                ("attr", "detected_leaks"),
                ("index", int(match.group("index"))),
                ("attr", match.group("field")),
            )
        return None

    def _allowed_reason_ids_by_namespace(self) -> dict[str, set[str]]:
        reason_ids: dict[str, set[str]] = {"LEAK": set(), "TRG": set(), "MIX": set()}
        for reason_id in self.dpl.allowed_reason_ids:
            reason_ids[namespace_of(reason_id)].add(reason_id)
        return reason_ids

    def _check_reason_set_matches(
        self,
        location: str,
        actual_ids: list[str],
        expected_ids: set[str],
        *,
        missing_code: str = "reason_citation_missing",
        unexpected_code: str = "reason_citation_unexpected",
    ) -> None:
        actual_set = set(actual_ids)
        missing = sorted(expected_ids - actual_set)
        unexpected = sorted(actual_set - expected_ids)
        if missing:
            self._add(
                missing_code,
                location,
                f"missing required reason citation(s): {missing}",
            )
        if unexpected:
            self._add(
                unexpected_code,
                location,
                f"unexpected reason citation(s): {unexpected}",
            )

    def _expected_unit_for_direct_tokens(self, tokens: tuple[PathToken, ...]) -> str | None:
        if _tokens_are_ev_estimate(tokens):
            return self.dpl.ev_estimate.ev_unit
        if len(tokens) >= 1 and tokens[0] == ("attr", "safety_alpha"):
            return "mixing_weight"
        if len(tokens) >= 1 and tokens[0] == ("attr", "sampling_seed"):
            return "integer"
        if len(tokens) >= 1 and tokens[0] in {
            ("attr", "base_policy"),
            ("attr", "exploit_policy"),
            ("attr", "final_policy"),
        }:
            return "probability"
        if len(tokens) >= 2 and tokens[:2] == (
            ("attr", "execution_sampling"),
            ("attr", "execution_policy"),
        ):
            return "probability"
        if len(tokens) == 3 and tokens[0] == ("attr", "detected_leaks"):
            field = tokens[2]
            if field in {
                ("attr", "observed_rate"),
                ("attr", "baseline_rate"),
                ("attr", "confidence"),
            }:
                return "probability"
        return None

    def _verify_detected_leak_numeric_claim_allowed(self, location: str, index: int) -> None:
        if not self._detected_leak_numeric_claim_allowed(index):
            reason_id = self._detected_leak_reason_id(index)
            if reason_id is None:
                return
            self._add(
                "numeric_detected_leak_not_allowed",
                f"{location}.name",
                f"detected_leaks[{index}] reason {reason_id!r} is not an allowed LEAK reason",
            )

    def _detected_leak_numeric_claim_allowed(self, index: int) -> bool:
        reason_id = self._detected_leak_reason_id(index)
        if reason_id is None:
            return False
        return (
            namespace_of(reason_id) == "LEAK"
            and reason_id in set(self.dpl.allowed_reason_ids)
            and reason_id in set(self.explanation.allowed_reason_ids)
        )

    def _detected_leak_reason_id(self, index: int) -> str | None:
        if index < 0 or index >= len(self.dpl.detected_leaks):
            return None
        return self.dpl.detected_leaks[index].reason_id

    def _check_unique(self, location: str, values: list[str]) -> None:
        seen: set[str] = set()
        for value in values:
            if value in seen:
                self._add("duplicate_reason_id", location, f"duplicate reason id {value!r}")
            seen.add(value)


def _coerce_model[ModelT: BaseModel](
    value: ModelT | Mapping[str, Any],
    model_type: type[ModelT],
) -> ModelT:
    if isinstance(value, model_type):
        return value
    return model_type.model_validate(value)


def _validation_issue(location: str, exc: ValidationError) -> VerificationIssue:
    first_line = str(exc).splitlines()[0] if str(exc) else "validation failed"
    return VerificationIssue(
        code="contract_validation_failed",
        location=location,
        message=first_line,
    )


def _reason_source_shape_matches(source_path: str, namespace: str) -> bool:
    if namespace == "LEAK":
        return source_path.startswith("dpl.detected_leaks[") and source_path.endswith("].reason_id")
    if namespace == "TRG":
        return source_path.startswith("dpl.trigger_reasons[") and source_path.endswith("]")
    if namespace == "MIX":
        return source_path.startswith("dpl.mix_reasons[") and source_path.endswith("]")
    return False


def _parse_prefixed_path(path: str, prefix: str) -> tuple[PathToken, ...]:
    prefix_with_dot = f"{prefix}."
    if not path.startswith(prefix_with_dot):
        raise ValueError(f"source path {path!r} must start with {prefix_with_dot!r}")
    return _parse_path_tail(path[len(prefix_with_dot) :])


def _parse_path_tail(tail: str) -> tuple[PathToken, ...]:
    if not tail:
        raise ValueError("source path is missing a field after the prefix")
    tokens: list[PathToken] = []
    pos = 0
    while pos < len(tail):
        field_match = _FIELD_RE.match(tail, pos)
        if field_match is None:
            raise ValueError(f"invalid source path near {tail[pos:]!r}")
        tokens.append(("attr", field_match.group(0)))
        pos = field_match.end()

        while pos < len(tail) and tail[pos] == "[":
            end = tail.find("]", pos)
            if end == -1:
                raise ValueError(f"unterminated bracket in source path {tail!r}")
            raw_key = tail[pos + 1 : end]
            if raw_key.isdecimal():
                tokens.append(("index", int(raw_key)))
            else:
                try:
                    key = ast.literal_eval(raw_key)
                except (SyntaxError, ValueError) as exc:
                    raise ValueError(f"invalid bracket key [{raw_key}] in source path") from exc
                if not isinstance(key, str):
                    raise ValueError(f"source path key [{raw_key}] must be a string")
                tokens.append(("key", key))
            pos = end + 1

        if pos == len(tail):
            break
        if tail[pos] != ".":
            raise ValueError(f"invalid source path separator near {tail[pos:]!r}")
        pos += 1
    return tuple(tokens)


def _resolve_dpl_path(dpl: DecisionProvenanceLog, source_path: str) -> Any:
    return _resolve_path_tokens(dpl, _parse_prefixed_path(source_path, "dpl"))


def _resolve_path_tokens(root: Any, tokens: tuple[PathToken, ...]) -> Any:
    current = root
    for kind, value in tokens:
        if kind == "attr":
            current = _resolve_attr(current, str(value))
        elif kind == "index":
            current = _resolve_index(current, int(value))
        elif kind == "key":
            current = _resolve_key(current, str(value))
        else:
            raise ValueError(f"unsupported source path token kind {kind!r}")
    return current


def _resolve_attr(current: Any, name: str) -> Any:
    if isinstance(current, BaseModel):
        if name not in type(current).model_fields:
            raise ValueError(f"source path has no model field {name!r}")
        return getattr(current, name)
    if isinstance(current, Mapping):
        if name not in current:
            raise ValueError(f"source path has no mapping key {name!r}")
        return current[name]
    raise ValueError(f"source path cannot read field {name!r} from {type(current).__name__}")


def _resolve_index(current: Any, index: int) -> Any:
    if not isinstance(current, (list, tuple)):
        raise ValueError(f"source path cannot index {type(current).__name__}")
    try:
        return current[index]
    except IndexError as exc:
        raise ValueError(f"source path index {index} is out of range") from exc


def _resolve_key(current: Any, key: str) -> Any:
    if not isinstance(current, Mapping):
        raise ValueError(f"source path cannot read key {key!r} from {type(current).__name__}")
    if key not in current:
        raise ValueError(f"source path key {key!r} is missing")
    return current[key]


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _tokens_are_ev_estimate(tokens: tuple[PathToken, ...]) -> bool:
    return (
        len(tokens) == 2
        and tokens[0] == ("attr", "ev_estimate")
        and tokens[1]
        in {
            ("attr", "base_ev"),
            ("attr", "exploit_ev"),
            ("attr", "final_ev"),
            ("attr", "worst_case_penalty"),
        }
    )


def _format_dpl_tokens(tokens: tuple[PathToken, ...]) -> str:
    text = "dpl"
    for kind, value in tokens:
        if kind == "attr":
            text += f".{value}"
        elif kind == "index":
            text += f"[{value}]"
        elif kind == "key":
            text += f"[{value!r}]"
    return text


def _expected_rendered_text(explanation: ExplanationDocument) -> str:
    lines = [f"{stage.title}: {stage.text}" for stage in explanation.stages]
    lines.append(f"{explanation.counterfactual.title}: {explanation.counterfactual.text}")
    return "\n".join(lines)


def _surface_number_allowed(
    value: float,
    unit: str,
    allowed_numbers: tuple[tuple[str, float], ...],
) -> bool:
    return any(
        unit == allowed_unit
        and math.isclose(
            value,
            allowed_value,
            rel_tol=NUMERIC_REL_TOL,
            abs_tol=NUMERIC_ABS_TOL,
        )
        for allowed_unit, allowed_value in allowed_numbers
    )


def _rounded_surface_value(value: float, decimals: int) -> float:
    return float(f"{value:.{decimals}f}")


__all__ = [
    "ExplanationVerificationError",
    "VerificationIssue",
    "VerificationResult",
    "verify_explanation",
    "verify_explanation_or_raise",
]
