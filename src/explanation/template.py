"""Deterministic template explanation generation from a validated DPL."""

from __future__ import annotations

from collections.abc import Iterable

from poker_core.dpl_schema import DecisionProvenanceLog, DetectedLeak
from poker_core.reason_ontology import get_ontology

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


def generate_template_explanation(
    dpl: DecisionProvenanceLog,
    *,
    solver_diagnostics: SolverDiagnostics | None = None,
) -> ExplanationDocument:
    """Generate a structured, deterministic explanation for one DPL decision.

    The generator does not call an LLM and does not inspect raw EV fields directly.
    EV values enter through :meth:`DecisionProvenanceLog.ev_for_explanation`, which
    returns values only for ``solver_exact`` DPLs. Solver-level diagnostics are
    optional and remain in a separate field from the decision-level EV delta.
    """

    ev_values = dpl.ev_for_explanation()
    if ev_values is None:
        raise ValueError("DPL EV values are not cleared for explanation")
    if solver_diagnostics is not None:
        if dpl.solver_result_id is None:
            raise ValueError("solver diagnostics require a DPL solver_result_id")
        if solver_diagnostics.solver_result_id != dpl.solver_result_id:
            raise ValueError("solver diagnostics do not match the DPL solver_result_id")

    policy_reasons = _policy_reason_set(dpl)
    sampling_reasons = _sampling_reason_set(dpl)
    ev_breakdown = _ev_breakdown(dpl, ev_values, solver_diagnostics)
    counterfactual = _counterfactual(dpl, ev_breakdown.decision_ev_delta)
    stages = _stages(dpl, policy_reasons, sampling_reasons, ev_breakdown)
    rendered_text = _render(stages, counterfactual)

    return ExplanationDocument(
        schema_version=EXPLANATION_SCHEMA_VERSION,
        dpl_ref=_dpl_ref(dpl),
        source_dpl_schema_version=dpl.schema_version,
        reason_ontology_version=get_ontology().ontology_version,
        generator=TEMPLATE_GENERATOR,
        generator_version=TEMPLATE_GENERATOR_VERSION,
        allowed_reason_ids=list(dpl.allowed_reason_ids),
        policy_reasons=policy_reasons,
        sampling_reasons=sampling_reasons,
        stages=stages,
        ev_breakdown=ev_breakdown,
        counterfactual=counterfactual,
        rendered_text=rendered_text,
    )


def _policy_reason_set(dpl: DecisionProvenanceLog) -> PolicyReasonSet:
    leak_reasons = [
        _reason_citation(leak.reason_id, source_path=f"dpl.detected_leaks[{index}].reason_id")
        for index, leak in _allowed_detected_leaks(dpl)
    ]
    allowed = set(dpl.allowed_reason_ids)
    trigger_reasons = [
        _reason_citation(reason_id, source_path=f"dpl.trigger_reasons[{index}]")
        for index, reason_id in enumerate(dpl.trigger_reasons)
        if reason_id in allowed
    ]
    return PolicyReasonSet(leak_reasons=leak_reasons, trigger_reasons=trigger_reasons)


def _sampling_reason_set(dpl: DecisionProvenanceLog) -> SamplingReasonSet:
    allowed = set(dpl.allowed_reason_ids)
    mix_reasons = [
        _reason_citation(reason_id, source_path=f"dpl.mix_reasons[{index}]")
        for index, reason_id in enumerate(dpl.mix_reasons)
        if reason_id in allowed
    ]
    seed = None
    if dpl.sampling_seed is not None:
        seed = _claim(
            "sampling_seed",
            float(dpl.sampling_seed),
            unit="integer",
            source_kind="dpl",
            source_path="dpl.sampling_seed",
        )
    return SamplingReasonSet(
        selected_action=dpl.selected_action,
        selected_action_probability=_selected_action_probability(dpl),
        sampling_seed=seed,
        mix_reasons=mix_reasons,
    )


def _ev_breakdown(
    dpl: DecisionProvenanceLog,
    ev_values: dict[str, float | None],
    solver_diagnostics: SolverDiagnostics | None,
) -> EVBreakdown:
    unit = dpl.ev_estimate.ev_unit
    base_ev = _claim(
        "base_ev",
        _required_ev(ev_values, "base_ev"),
        unit=unit,
        source_kind="dpl",
        source_path="dpl.ev_estimate.base_ev",
    )
    exploit_ev = _claim(
        "exploit_ev",
        _required_ev(ev_values, "exploit_ev"),
        unit=unit,
        source_kind="dpl",
        source_path="dpl.ev_estimate.exploit_ev",
    )
    final_ev = _claim(
        "final_ev",
        _required_ev(ev_values, "final_ev"),
        unit=unit,
        source_kind="dpl",
        source_path="dpl.ev_estimate.final_ev",
    )
    exploit_ev_delta = _claim(
        "exploit_ev_delta",
        exploit_ev.value - base_ev.value,
        unit=unit,
        source_kind="dpl_derived",
        source_path="dpl.ev_estimate.exploit_ev - dpl.ev_estimate.base_ev",
        derivation="exploit_ev - base_ev",
    )
    decision_ev_delta = _claim(
        "decision_ev_delta",
        _required_ev(ev_values, "gain_vs_base"),
        unit=unit,
        source_kind="dpl_derived",
        source_path="dpl.ev_estimate.final_ev - dpl.ev_estimate.base_ev",
        derivation="final_ev - base_ev",
    )
    worst_case_penalty = None
    if ev_values.get("worst_case_penalty") is not None:
        worst_case_penalty = _claim(
            "worst_case_penalty",
            _required_ev(ev_values, "worst_case_penalty"),
            unit=unit,
            source_kind="dpl",
            source_path="dpl.ev_estimate.worst_case_penalty",
        )
    return EVBreakdown(
        base_ev=base_ev,
        exploit_ev=exploit_ev,
        final_ev=final_ev,
        exploit_ev_delta=exploit_ev_delta,
        decision_ev_delta=decision_ev_delta,
        worst_case_penalty=worst_case_penalty,
        solver_ev_delta=(
            solver_diagnostics.solver_ev_delta if solver_diagnostics is not None else None
        ),
    )


def _counterfactual(
    dpl: DecisionProvenanceLog,
    decision_ev_delta: NumericClaim,
) -> CounterfactualExplanation:
    baseline_probability_claim = _baseline_selected_action_probability(dpl)
    baseline_probability = baseline_probability_claim.value
    final_probability_claim = _final_selected_action_probability(dpl)
    final_probability = final_probability_claim.value
    text = (
        "Without the policy adjustment, the selected action would use the base-policy "
        f"probability {_fmt_pct(baseline_probability)} instead of the final-policy "
        f"probability {_fmt_pct(final_probability)}. The decision-level EV difference "
        f"is {_fmt_signed(decision_ev_delta.value)} {decision_ev_delta.unit}."
    )
    return CounterfactualExplanation(
        title="Counterfactual",
        text=text,
        baseline_selected_action_probability=baseline_probability_claim,
        final_selected_action_probability=final_probability_claim,
        decision_ev_delta=decision_ev_delta,
    )


def _stages(
    dpl: DecisionProvenanceLog,
    policy_reasons: PolicyReasonSet,
    sampling_reasons: SamplingReasonSet,
    ev_breakdown: EVBreakdown,
) -> tuple[
    ExplanationStage, ExplanationStage, ExplanationStage, ExplanationStage, ExplanationStage
]:
    allowed_detected_leaks = _allowed_detected_leaks(dpl)
    observation_claims = [
        _claim(
            "safety_alpha",
            dpl.safety_alpha,
            unit="mixing_weight",
            source_kind="dpl",
            source_path="dpl.safety_alpha",
        )
    ]
    for index, leak in allowed_detected_leaks:
        observation_claims.extend(
            [
                _claim(
                    f"detected_leaks[{index}].observed_rate",
                    leak.observed_rate,
                    unit="probability",
                    source_kind="dpl",
                    source_path=f"dpl.detected_leaks[{index}].observed_rate",
                ),
                _claim(
                    f"detected_leaks[{index}].baseline_rate",
                    leak.baseline_rate,
                    unit="probability",
                    source_kind="dpl",
                    source_path=f"dpl.detected_leaks[{index}].baseline_rate",
                ),
            ]
        )

    validation_claims = [
        ev_breakdown.base_ev,
        ev_breakdown.exploit_ev,
        ev_breakdown.exploit_ev_delta,
    ]
    for index, leak in allowed_detected_leaks:
        validation_claims.append(
            _claim(
                f"detected_leaks[{index}].confidence",
                leak.confidence,
                unit="probability",
                source_kind="dpl",
                source_path=f"dpl.detected_leaks[{index}].confidence",
            )
        )

    adjustment_claims = [
        ev_breakdown.final_ev,
        ev_breakdown.decision_ev_delta,
        sampling_reasons.selected_action_probability,
    ]
    if sampling_reasons.sampling_seed is not None:
        adjustment_claims.append(sampling_reasons.sampling_seed)

    residual_claims: list[NumericClaim] = []
    if ev_breakdown.worst_case_penalty is not None:
        residual_claims.append(ev_breakdown.worst_case_penalty)
    if ev_breakdown.solver_ev_delta is not None:
        residual_claims.append(ev_breakdown.solver_ev_delta)

    return (
        ExplanationStage(
            stage="observation",
            title="Observation",
            text=_observation_text(dpl, allowed_detected_leaks),
            cited_reason_ids=[citation.reason_id for citation in policy_reasons.leak_reasons],
            numeric_claims=observation_claims,
        ),
        ExplanationStage(
            stage="hypothesis",
            title="Hypothesis",
            text=_hypothesis_text(policy_reasons),
            cited_reason_ids=[citation.reason_id for citation in policy_reasons.leak_reasons],
            numeric_claims=[],
        ),
        ExplanationStage(
            stage="validation",
            title="Validation",
            text=_validation_text(policy_reasons, ev_breakdown),
            cited_reason_ids=[citation.reason_id for citation in policy_reasons.trigger_reasons],
            numeric_claims=validation_claims,
        ),
        ExplanationStage(
            stage="adjustment",
            title="Adjustment",
            text=_adjustment_text(dpl, sampling_reasons, ev_breakdown),
            cited_reason_ids=sampling_reasons.reason_ids,
            numeric_claims=adjustment_claims,
        ),
        ExplanationStage(
            stage="residual_risk",
            title="Residual Risk",
            text=_residual_text(dpl, ev_breakdown),
            cited_reason_ids=[],
            numeric_claims=residual_claims,
        ),
    )


def _allowed_detected_leaks(dpl: DecisionProvenanceLog) -> list[tuple[int, DetectedLeak]]:
    allowed = set(dpl.allowed_reason_ids)
    return [
        (index, leak) for index, leak in enumerate(dpl.detected_leaks) if leak.reason_id in allowed
    ]


def _baseline_selected_action_probability(dpl: DecisionProvenanceLog) -> NumericClaim:
    if dpl.selected_action in dpl.base_policy:
        return _claim(
            "baseline_selected_action_probability",
            dpl.base_policy[dpl.selected_action],
            unit="probability",
            source_kind="dpl",
            source_path=f"dpl.base_policy[{dpl.selected_action!r}]",
        )
    return _claim(
        "baseline_selected_action_probability",
        0.0,
        unit="probability",
        source_kind="dpl_derived",
        source_path="dpl.base_policy",
        derivation="missing action treated as 0 by DPL mixing semantics",
    )


def _final_selected_action_probability(dpl: DecisionProvenanceLog) -> NumericClaim:
    if dpl.selected_action in dpl.final_policy:
        return _claim(
            "final_selected_action_probability",
            dpl.final_policy[dpl.selected_action],
            unit="probability",
            source_kind="dpl",
            source_path=f"dpl.final_policy[{dpl.selected_action!r}]",
        )
    return _claim(
        "final_selected_action_probability",
        0.0,
        unit="probability",
        source_kind="dpl_derived",
        source_path="dpl.final_policy",
        derivation="missing action treated as 0 by DPL final-policy semantics",
    )


def _selected_action_probability(dpl: DecisionProvenanceLog) -> NumericClaim:
    if dpl.execution_sampling is not None and dpl.execution_sampling.exploration_fired:
        return _claim(
            "selected_action_probability",
            dpl.execution_sampling.execution_policy[dpl.selected_action],
            unit="probability",
            source_kind="dpl",
            source_path=(f"dpl.execution_sampling.execution_policy[{dpl.selected_action!r}]"),
        )
    return _claim(
        "selected_action_probability",
        dpl.final_policy[dpl.selected_action],
        unit="probability",
        source_kind="dpl",
        source_path=f"dpl.final_policy[{dpl.selected_action!r}]",
    )


def _observation_text(
    dpl: DecisionProvenanceLog,
    allowed_detected_leaks: list[tuple[int, DetectedLeak]],
) -> str:
    if not allowed_detected_leaks:
        leak_text = "No allowed detected leak is cited for this decision."
    else:
        parts = [
            (
                f"{leak.reason_id} in {leak.situation_key}: observed "
                f"{_fmt_pct(leak.observed_rate)} versus baseline {_fmt_pct(leak.baseline_rate)}"
            )
            for _index, leak in allowed_detected_leaks
        ]
        leak_text = "; ".join(parts) + "."
    return (
        f"Hand {dpl.hand_id} is in state cluster {dpl.state_cluster}; Hero combo "
        f"{dpl.hero_combo} is bucketed as {dpl.hand_bucket}. {leak_text}"
    )


def _hypothesis_text(policy_reasons: PolicyReasonSet) -> str:
    if not policy_reasons.leak_reasons:
        return "No leak reason is cited for the policy."
    labels = _join_labels(policy_reasons.leak_reasons)
    return f"The policy hypothesis cites opponent leak reason(s): {labels}."


def _validation_text(policy_reasons: PolicyReasonSet, ev_breakdown: EVBreakdown) -> str:
    if policy_reasons.trigger_reasons:
        trigger_text = f" Trigger reason(s): {_join_labels(policy_reasons.trigger_reasons)}."
    else:
        trigger_text = " No trigger reason is cited."
    return (
        f"The exploit policy is compared with the base policy using exact DPL EVs: "
        f"base {_fmt_number(ev_breakdown.base_ev.value)} {ev_breakdown.base_ev.unit}, "
        f"exploit {_fmt_number(ev_breakdown.exploit_ev.value)} {ev_breakdown.exploit_ev.unit}, "
        f"exploit-minus-base {_fmt_signed(ev_breakdown.exploit_ev_delta.value)} "
        f"{ev_breakdown.exploit_ev_delta.unit}.{trigger_text}"
    )


def _adjustment_text(
    dpl: DecisionProvenanceLog,
    sampling_reasons: SamplingReasonSet,
    ev_breakdown: EVBreakdown,
) -> str:
    solver_text = ""
    if dpl.exploit_source == "nodelock_solver":
        solver_text = f" Solver provenance is recorded as {dpl.solver_result_id}."
    mix_text = "No sampling reason is cited."
    if sampling_reasons.mix_reasons:
        mix_text = f" Sampling reason(s): {_join_labels(sampling_reasons.mix_reasons)}."
    if dpl.execution_sampling is not None and dpl.execution_sampling.exploration_fired:
        final_probability = _final_selected_action_probability(dpl).value
        return (
            f"The final policy is the safety mix with alpha {_fmt_number(dpl.safety_alpha)}. "
            f"It assigns {dpl.selected_action} final-policy probability "
            f"{_fmt_pct(final_probability)}. The realised action is {dpl.selected_action} "
            f"with execution-sampling probability "
            f"{_fmt_pct(sampling_reasons.selected_action_probability.value)} because "
            f"epsilon exploration fired. The decision-level final-minus-base EV is "
            f"{_fmt_signed(ev_breakdown.decision_ev_delta.value)} "
            f"{ev_breakdown.decision_ev_delta.unit}.{solver_text} {mix_text}"
        )
    return (
        f"The final policy is the safety mix with alpha {_fmt_number(dpl.safety_alpha)}. "
        f"The realised action is {dpl.selected_action} with final-policy probability "
        f"{_fmt_pct(sampling_reasons.selected_action_probability.value)}. "
        f"The decision-level final-minus-base EV is "
        f"{_fmt_signed(ev_breakdown.decision_ev_delta.value)} "
        f"{ev_breakdown.decision_ev_delta.unit}.{solver_text} {mix_text}"
    )


def _residual_text(dpl: DecisionProvenanceLog, ev_breakdown: EVBreakdown) -> str:
    if ev_breakdown.worst_case_penalty is None:
        worst_case_text = "No worst-case penalty is cited because it is null in the DPL."
    else:
        worst_case_text = (
            f"Worst-case penalty is {_fmt_signed(ev_breakdown.worst_case_penalty.value)} "
            f"{ev_breakdown.worst_case_penalty.unit}."
        )
    if ev_breakdown.solver_ev_delta is None:
        solver_text = "No solver-level EV delta is cited in this explanation."
    else:
        solver_text = (
            f"Solver-level EV delta is kept separate at "
            f"{_fmt_signed(ev_breakdown.solver_ev_delta.value)} "
            f"{ev_breakdown.solver_ev_delta.unit}."
        )
    return (
        f"{worst_case_text} {solver_text} Exploit source is {dpl.exploit_source}; "
        "this field is not used as a substitute for the decision-level EV delta."
    )


def _render(
    stages: Iterable[ExplanationStage],
    counterfactual: CounterfactualExplanation,
) -> str:
    lines: list[str] = []
    for stage in stages:
        lines.append(f"{stage.title}: {stage.text}")
    lines.append(f"{counterfactual.title}: {counterfactual.text}")
    return "\n".join(lines)


def _reason_citation(reason_id: str, *, source_path: str) -> ReasonCitation:
    ontology = get_ontology()
    entry = ontology.get(reason_id)
    return ReasonCitation(
        reason_id=entry.id,
        namespace=entry.namespace,
        label=entry.label,
        description=entry.description,
        source_path=source_path,
    )


def _claim(
    name: str,
    value: float,
    *,
    unit: str,
    source_kind: str,
    source_path: str,
    derivation: str | None = None,
) -> NumericClaim:
    return NumericClaim(
        name=name,
        value=float(value),
        unit=unit,
        source_kind=source_kind,
        source_path=source_path,
        derivation=derivation,
    )


def _required_ev(ev_values: dict[str, float | None], key: str) -> float:
    value = ev_values.get(key)
    if value is None:
        raise ValueError(f"required explanation EV value {key!r} is missing")
    return float(value)


def _dpl_ref(dpl: DecisionProvenanceLog) -> str:
    return f"{dpl.session_id}:{dpl.hand_id}"


def _join_labels(citations: list[ReasonCitation]) -> str:
    return ", ".join(f"{citation.reason_id} ({citation.label})" for citation in citations)


def _fmt_pct(value: float) -> str:
    return f"{100.0 * value:.1f}%"


def _fmt_number(value: float) -> str:
    return f"{value:.4f}"


def _fmt_signed(value: float) -> str:
    return f"{value:+.4f}"
