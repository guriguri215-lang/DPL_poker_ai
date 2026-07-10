"""Tests for the Phase 5 template explanation contract and generator."""

from __future__ import annotations

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from explanation import (
    ExplanationDocument,
    NumericClaim,
    SolverDiagnostics,
    generate_template_explanation,
)
from explanation.contract import STAGE_ORDER
from poker_core.dpl_schema import DecisionProvenanceLog, load_dpl
from poker_core.reason_ontology import get_ontology


def test_template_explanation_has_five_stages_and_counterfactual(valid_dpl):
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)

    explanation = generate_template_explanation(dpl)

    assert isinstance(explanation, ExplanationDocument)
    assert explanation.generator == "template"
    assert explanation.generator_version == "template-v1"
    assert tuple(stage.stage for stage in explanation.stages) == STAGE_ORDER
    assert explanation.counterfactual.title == "Counterfactual"
    assert "Counterfactual:" in explanation.rendered_text
    assert explanation.dpl_ref == "S0001:H000421"


def test_template_preserves_historical_v1_source_schema_version(valid_dpl):
    valid_dpl["schema_version"] = "1.0.0"
    legacy = load_dpl(valid_dpl)

    explanation = generate_template_explanation(legacy)

    assert legacy.schema_version == "1.0.0"
    assert explanation.source_dpl_schema_version == "1.0.0"


def test_explanation_contract_exports_valid_json_schema(valid_dpl):
    schema = ExplanationDocument.model_json_schema()
    Draft202012Validator.check_schema(schema)
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)
    explanation = generate_template_explanation(dpl)

    Draft202012Validator(schema).validate(explanation.model_dump(mode="json"))


def test_policy_and_sampling_reasons_are_structurally_separated(valid_dpl):
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)

    explanation = generate_template_explanation(dpl)

    assert [c.reason_id for c in explanation.policy_reasons.leak_reasons] == ["LEAK_R001"]
    assert [c.reason_id for c in explanation.policy_reasons.trigger_reasons] == [
        "TRG_R001",
        "TRG_R002",
        "TRG_R003",
    ]
    assert [c.reason_id for c in explanation.sampling_reasons.mix_reasons] == ["MIX_R001"]
    policy_ids = set(explanation.policy_reasons.reason_ids)
    sampling_ids = set(explanation.sampling_reasons.reason_ids)
    assert all(not reason_id.startswith("MIX_") for reason_id in policy_ids)
    assert all(reason_id.startswith("MIX_") for reason_id in sampling_ids)
    assert policy_ids.isdisjoint(sampling_ids)


def test_epsilon_explanation_separates_final_policy_from_execution(valid_dpl):
    valid_dpl["detected_leaks"] = []
    valid_dpl["trigger_reasons"] = []
    valid_dpl["mix_reasons"] = ["MIX_EPSILON"]
    valid_dpl["allowed_reason_ids"] = ["MIX_EPSILON"]
    valid_dpl["base_policy"] = {"CHECK": 1.0}
    valid_dpl["exploit_policy"] = {"CHECK": 1.0}
    valid_dpl["safety_alpha"] = 0.0
    valid_dpl["final_policy"] = {"CHECK": 1.0}
    valid_dpl["selected_action"] = "BET_75"
    valid_dpl["execution_sampling"] = {
        "sampler_version": "epsilon-uniform-v1",
        "epsilon": 1.0,
        "epsilon_distribution": {"CHECK": 0.5, "BET_75": 0.5},
        "execution_policy": {"CHECK": 0.5, "BET_75": 0.5},
        "exploration_fired": True,
    }
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)

    explanation = generate_template_explanation(dpl)

    assert explanation.policy_reasons.reason_ids == []
    assert [c.reason_id for c in explanation.sampling_reasons.mix_reasons] == ["MIX_EPSILON"]
    assert explanation.sampling_reasons.selected_action_probability.value == pytest.approx(0.5)
    assert explanation.sampling_reasons.selected_action_probability.source_path == (
        "dpl.execution_sampling.execution_policy['BET_75']"
    )
    assert explanation.counterfactual.final_selected_action_probability.value == pytest.approx(0.0)
    assert (
        explanation.counterfactual.final_selected_action_probability.derivation
        == "missing action treated as 0 by DPL final-policy semantics"
    )
    assert "epsilon exploration fired" in explanation.rendered_text
    assert "LEAK_" not in explanation.rendered_text
    assert "TRG_" not in explanation.rendered_text


def test_numeric_claims_have_sources_and_decision_ev_delta_is_dpl_derived(valid_dpl):
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)

    explanation = generate_template_explanation(dpl)

    assert explanation.ev_breakdown.base_ev.source_path == "dpl.ev_estimate.base_ev"
    assert explanation.ev_breakdown.final_ev.source_path == "dpl.ev_estimate.final_ev"
    assert explanation.ev_breakdown.decision_ev_delta.value == pytest.approx(4.27 - 4.12)
    assert explanation.ev_breakdown.decision_ev_delta.source_kind == "dpl_derived"
    assert explanation.ev_breakdown.decision_ev_delta.derivation == "final_ev - base_ev"
    assert explanation.ev_breakdown.solver_ev_delta is None
    for stage in explanation.stages:
        for claim in stage.numeric_claims:
            assert claim.source_path.startswith("dpl.") or claim.source_path.startswith(
                "solver_diagnostics."
            )


def test_allowed_outside_detected_leaks_are_not_rendered_or_claimed(valid_dpl):
    valid_dpl["detected_leaks"].append(
        {
            "reason_id": "LEAK_R002",
            "leak_type": "river_large_bet_overcall",
            "situation_key": "river_flush_complete:facing_CHECK",
            "observed_rate": 0.91,
            "baseline_rate": 0.12,
            "effective_sample_size": 21,
            "confidence": 0.83,
            "direction": "increase_call_frequency",
        }
    )
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)

    explanation = generate_template_explanation(dpl)

    payload = str(explanation.model_dump(mode="json"))
    assert "LEAK_R002" not in payload
    assert "detected_leaks[1]" not in payload
    assert "0.91" not in payload
    assert "0.12" not in payload
    assert "0.83" not in payload


def test_counterfactual_uses_base_and_final_selected_action_probabilities(valid_dpl):
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)

    explanation = generate_template_explanation(dpl)

    counterfactual = explanation.counterfactual
    assert counterfactual.baseline_selected_action_probability.value == pytest.approx(0.4)
    assert counterfactual.baseline_selected_action_probability.source_kind == "dpl"
    assert counterfactual.baseline_selected_action_probability.source_path == (
        "dpl.base_policy['BET_75']"
    )
    assert counterfactual.baseline_selected_action_probability.derivation is None
    assert counterfactual.final_selected_action_probability.value == pytest.approx(0.6)
    assert counterfactual.final_selected_action_probability.source_path == (
        "dpl.final_policy['BET_75']"
    )
    assert counterfactual.decision_ev_delta is explanation.ev_breakdown.decision_ev_delta


def test_counterfactual_derives_missing_base_selected_action_probability(valid_dpl):
    valid_dpl["base_policy"] = {"CHECK": 1.0}
    valid_dpl["exploit_policy"] = {"CHECK": 0.2, "BET_75": 0.8}
    valid_dpl["final_policy"] = {"CHECK": 0.6, "BET_75": 0.4}
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)

    explanation = generate_template_explanation(dpl)

    baseline_claim = explanation.counterfactual.baseline_selected_action_probability
    assert baseline_claim.value == pytest.approx(0.0)
    assert baseline_claim.source_kind == "dpl_derived"
    assert baseline_claim.source_path == "dpl.base_policy"
    assert baseline_claim.derivation == "missing action treated as 0 by DPL mixing semantics"
    assert "dpl.base_policy['BET_75']" not in baseline_claim.source_path


def test_nodelock_solver_diagnostic_ev_delta_is_kept_separate(valid_dpl):
    valid_dpl["exploit_source"] = "nodelock_solver"
    valid_dpl["solver_result_id"] = (
        "nodelock_solver:v1:allocation=baseline_scaled:lock_mode=HARD:"
        "unlocked_policy_mode=fix_to_baseline:digest=test"
    )
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)
    diagnostics = SolverDiagnostics(
        solver_result_id=dpl.solver_result_id or "",
        solver_ev_delta=NumericClaim(
            name="solver_ev_delta",
            value=9.5,
            unit="bb",
            source_kind="solver_diagnostic",
            source_path="solver_diagnostics.metrics.ev_delta",
        ),
    )

    explanation = generate_template_explanation(dpl, solver_diagnostics=diagnostics)

    assert explanation.ev_breakdown.decision_ev_delta.value == pytest.approx(4.27 - 4.12)
    assert explanation.ev_breakdown.decision_ev_delta.source_kind == "dpl_derived"
    assert explanation.ev_breakdown.solver_ev_delta is not None
    assert explanation.ev_breakdown.solver_ev_delta.value == pytest.approx(9.5)
    assert explanation.ev_breakdown.solver_ev_delta.source_kind == "solver_diagnostic"
    assert "Solver-level EV delta is kept separate" in explanation.rendered_text
    assert "decision-level final-minus-base EV" in explanation.rendered_text


def test_solver_diagnostics_require_matching_dpl_solver_result_id(valid_dpl):
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)
    diagnostics = SolverDiagnostics(
        solver_result_id="solve_other",
        solver_ev_delta=NumericClaim(
            name="solver_ev_delta",
            value=1.0,
            unit="bb",
            source_kind="solver_diagnostic",
            source_path="solver_diagnostics.metrics.ev_delta",
        ),
    )

    with pytest.raises(ValueError, match="require a DPL solver_result_id"):
        generate_template_explanation(dpl, solver_diagnostics=diagnostics)


def test_generator_rejects_non_exact_ev_source(valid_dpl):
    valid_dpl["ev_estimate"]["ev_source"] = "heuristic"
    valid_dpl["ev_estimate"]["worst_case_penalty"] = None
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)

    with pytest.raises(ValueError, match="not cleared for explanation"):
        generate_template_explanation(dpl)


def test_contract_rejects_sampling_reason_inside_policy_reasons(valid_dpl):
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)
    explanation = generate_template_explanation(dpl)
    payload = explanation.model_dump(mode="json")
    entry = get_ontology().get("MIX_R001")
    payload["policy_reasons"]["leak_reasons"].append(
        {
            "reason_id": entry.id,
            "namespace": entry.namespace,
            "label": entry.label,
            "description": entry.description,
            "source_path": "dpl.mix_reasons[0]",
        }
    )

    with pytest.raises(ValidationError, match="leak_reasons may only contain LEAK"):
        ExplanationDocument.model_validate(payload)


def test_contract_rejects_reason_outside_allowed_reason_ids(valid_dpl):
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)
    explanation = generate_template_explanation(dpl)
    payload = explanation.model_dump(mode="json")
    payload["stages"][0]["cited_reason_ids"] = ["LEAK_R002"]

    with pytest.raises(ValidationError, match="not in allowed_reason_ids"):
        ExplanationDocument.model_validate(payload)


def test_template_generation_is_deterministic(valid_dpl):
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)

    first = generate_template_explanation(dpl)
    second = generate_template_explanation(dpl)

    assert first.model_dump(mode="json") == second.model_dump(mode="json")
