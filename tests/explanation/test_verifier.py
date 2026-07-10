"""Tests for the independent Explanation Verifier."""

from __future__ import annotations

import ast
import copy
from pathlib import Path

import explanation.verifier as verifier_module
from explanation import (
    NumericClaim,
    SolverDiagnostics,
    generate_template_explanation,
    verify_explanation,
)
from poker_core.dpl_schema import DecisionProvenanceLog


def _codes(result) -> set[str]:
    return {issue.code for issue in result.issues}


def _valid_explanation_payload(valid_dpl):
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)
    explanation = generate_template_explanation(dpl)
    return dpl, explanation.model_dump(mode="json")


def _nodelock_dpl_and_diagnostics(valid_dpl):
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
    return dpl, diagnostics


def _append_unallowed_detected_leak(valid_dpl):
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


def _make_epsilon_dpl(valid_dpl):
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
    return DecisionProvenanceLog.model_validate(valid_dpl)


def _refresh_rendered_text(payload):
    lines = [f"{stage['title']}: {stage['text']}" for stage in payload["stages"]]
    lines.append(f"{payload['counterfactual']['title']}: {payload['counterfactual']['text']}")
    payload["rendered_text"] = "\n".join(lines)


def test_verifier_does_not_import_template_module():
    tree = ast.parse(Path(verifier_module.__file__).read_text(encoding="utf-8"))

    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }

    assert "template" not in imported_modules
    assert "explanation.template" not in imported_modules


def test_verifier_accepts_template_explanation(valid_dpl):
    dpl, payload = _valid_explanation_payload(valid_dpl)

    result = verify_explanation(payload, dpl)

    assert result.passed


def _confidence_claim(payload):
    return next(
        claim
        for claim in payload["stages"][2]["numeric_claims"]
        if claim["name"] == "detected_leaks[0].confidence"
    )


def test_verifier_requires_exactly_one_confidence_claim(valid_dpl):
    dpl, payload = _valid_explanation_payload(valid_dpl)
    payload["stages"][2]["numeric_claims"] = [
        claim
        for claim in payload["stages"][2]["numeric_claims"]
        if claim["name"] != "detected_leaks[0].confidence"
    ]

    missing = verify_explanation(payload, dpl)
    assert "confidence_claim_missing" in _codes(missing)

    _dpl, payload = _valid_explanation_payload(valid_dpl)
    payload["stages"][2]["numeric_claims"].append(copy.deepcopy(_confidence_claim(payload)))
    duplicate = verify_explanation(payload, dpl)
    assert "confidence_claim_duplicate" in _codes(duplicate)


def test_verifier_rejects_confidence_claim_outside_validation_stage(valid_dpl):
    dpl, payload = _valid_explanation_payload(valid_dpl)
    claim = _confidence_claim(payload)
    payload["stages"][2]["numeric_claims"].remove(claim)
    payload["stages"][0]["numeric_claims"].append(claim)

    result = verify_explanation(payload, dpl)
    assert "confidence_claim_wrong_stage" in _codes(result)


def test_verifier_rejects_confidence_wrong_index_path_and_unit(valid_dpl):
    dpl, payload = _valid_explanation_payload(valid_dpl)
    claim = _confidence_claim(payload)
    claim["name"] = "detected_leaks[1].confidence"
    claim["unit"] = "score"

    result = verify_explanation(payload, dpl)
    codes = _codes(result)
    assert "confidence_claim_wrong_index" in codes
    assert "numeric_unit_mismatch" in codes
    assert "confidence_claim_missing" in codes


def test_verifier_accepts_epsilon_exploration_explanation(valid_dpl):
    dpl = _make_epsilon_dpl(valid_dpl)
    explanation = generate_template_explanation(dpl)

    result = verify_explanation(explanation, dpl)

    assert result.passed, result.issues


def test_verifier_accepts_template_explanation_with_solver_diagnostics(valid_dpl):
    dpl, diagnostics = _nodelock_dpl_and_diagnostics(valid_dpl)
    explanation = generate_template_explanation(dpl, solver_diagnostics=diagnostics)

    result = verify_explanation(explanation, dpl, solver_diagnostics=diagnostics)

    assert result.passed


def test_verifier_accepts_template_explanation_with_rounded_surface_numbers(valid_dpl):
    valid_dpl["detected_leaks"][0]["observed_rate"] = 0.64123
    valid_dpl["detected_leaks"][0]["baseline_rate"] = 0.48765
    valid_dpl["detected_leaks"][0]["confidence"] = 0.74321
    valid_dpl["base_policy"] = {"CHECK": 0.56789, "BET_75": 0.43211}
    valid_dpl["exploit_policy"] = {"CHECK": 0.36543, "BET_75": 0.63457}
    valid_dpl["final_policy"] = {"CHECK": 0.46666, "BET_75": 0.53334}
    valid_dpl["ev_estimate"]["base_ev"] = 4.123456
    valid_dpl["ev_estimate"]["exploit_ev"] = 4.467891
    valid_dpl["ev_estimate"]["final_ev"] = 4.278912
    valid_dpl["ev_estimate"]["worst_case_penalty"] = -0.081234
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)
    explanation = generate_template_explanation(dpl)

    result = verify_explanation(explanation, dpl)

    assert result.passed, result.issues


def test_verifier_rejects_rendered_text_fabrication(valid_dpl):
    dpl, payload = _valid_explanation_payload(valid_dpl)
    payload["rendered_text"] += "\nFABRICATED LEAK_R002 says EV is 999 bb at 99.9%."

    result = verify_explanation(payload, dpl)

    assert not result.passed
    assert "rendered_text_mismatch" in _codes(result)
    assert "surface_reason_not_allowed" in _codes(result)
    assert "surface_numeric_unbacked" in _codes(result)


def test_verifier_flags_unallowed_mix_epsilon_surface_reason(valid_dpl):
    dpl, payload = _valid_explanation_payload(valid_dpl)
    payload["stages"][3]["text"] += " Unallowed MIX_EPSILON fired."
    _refresh_rendered_text(payload)

    result = verify_explanation(payload, dpl)

    assert not result.passed
    assert "surface_reason_not_allowed" in _codes(result)


def test_verifier_rejects_ev_value_tampering(valid_dpl):
    dpl, payload = _valid_explanation_payload(valid_dpl)
    payload["ev_breakdown"]["decision_ev_delta"]["value"] = 99.0

    result = verify_explanation(payload, dpl)

    assert not result.passed
    assert "numeric_value_mismatch" in _codes(result)


def test_verifier_rejects_probability_value_tampering(valid_dpl):
    dpl, payload = _valid_explanation_payload(valid_dpl)
    payload["sampling_reasons"]["selected_action_probability"]["value"] = 0.61

    result = verify_explanation(payload, dpl)

    assert not result.passed
    assert "numeric_value_mismatch" in _codes(result)


def test_verifier_rejects_reason_id_in_wrong_stage(valid_dpl):
    dpl, payload = _valid_explanation_payload(valid_dpl)
    payload["stages"][3]["cited_reason_ids"] = ["TRG_R001"]

    result = verify_explanation(payload, dpl)

    assert not result.passed
    assert "stage_reason_namespace_mismatch" in _codes(result)


def test_verifier_rejects_allowed_reason_whitelist_tampering(valid_dpl):
    dpl, payload = _valid_explanation_payload(valid_dpl)
    payload["allowed_reason_ids"] = list(reversed(payload["allowed_reason_ids"]))

    result = verify_explanation(payload, dpl)

    assert not result.passed
    assert "reason_allowed_mismatch" in _codes(result)


def test_verifier_rejects_missing_leak_reason_citations(valid_dpl):
    dpl, payload = _valid_explanation_payload(valid_dpl)
    payload["policy_reasons"]["leak_reasons"] = []
    payload["stages"][0]["cited_reason_ids"] = []
    payload["stages"][1]["cited_reason_ids"] = []

    result = verify_explanation(payload, dpl)

    assert not result.passed
    assert "reason_citation_missing" in _codes(result)
    assert "stage_reason_missing" in _codes(result)


def test_verifier_rejects_missing_trigger_reason_citations(valid_dpl):
    dpl, payload = _valid_explanation_payload(valid_dpl)
    payload["policy_reasons"]["trigger_reasons"] = []
    payload["stages"][2]["cited_reason_ids"] = []

    result = verify_explanation(payload, dpl)

    assert not result.passed
    assert "reason_citation_missing" in _codes(result)
    assert "stage_reason_missing" in _codes(result)


def test_verifier_rejects_missing_mix_reason_citations(valid_dpl):
    dpl, payload = _valid_explanation_payload(valid_dpl)
    payload["sampling_reasons"]["mix_reasons"] = []
    payload["stages"][3]["cited_reason_ids"] = []

    result = verify_explanation(payload, dpl)

    assert not result.passed
    assert "reason_citation_missing" in _codes(result)
    assert "stage_reason_missing" in _codes(result)


def test_verifier_rejects_numeric_source_path_tampering(valid_dpl):
    dpl, payload = _valid_explanation_payload(valid_dpl)
    payload["ev_breakdown"]["base_ev"]["source_path"] = "dpl.ev_estimate.final_ev"

    result = verify_explanation(payload, dpl)

    assert not result.passed
    assert "numeric_source_path_mismatch" in _codes(result)
    assert "numeric_value_mismatch" in _codes(result)


def test_verifier_rejects_direct_dpl_property_source_path(valid_dpl):
    dpl, payload = _valid_explanation_payload(valid_dpl)
    payload["stages"][4]["numeric_claims"].append(
        {
            "name": "fabricated_gain",
            "value": 0.15,
            "unit": "bb",
            "source_kind": "dpl",
            "source_path": "dpl.ev_estimate.gain_vs_base",
            "derivation": None,
        }
    )

    result = verify_explanation(payload, dpl)

    assert not result.passed
    assert "numeric_source_unresolved" in _codes(result)


def test_verifier_rejects_alias_claim_to_real_dpl_field(valid_dpl):
    dpl, payload = _valid_explanation_payload(valid_dpl)
    payload["stages"][4]["numeric_claims"].append(
        {
            "name": "fabricated_alias",
            "value": 0.5,
            "unit": "mixing_weight",
            "source_kind": "dpl",
            "source_path": "dpl.safety_alpha",
            "derivation": None,
        }
    )

    result = verify_explanation(payload, dpl)

    assert not result.passed
    assert "numeric_claim_unknown" in _codes(result)


def test_verifier_rejects_unallowed_detected_leak_numeric_claim(valid_dpl):
    _append_unallowed_detected_leak(valid_dpl)
    dpl, payload = _valid_explanation_payload(valid_dpl)
    payload["stages"][0]["numeric_claims"].append(
        {
            "name": "detected_leaks[1].observed_rate",
            "value": 0.91,
            "unit": "probability",
            "source_kind": "dpl",
            "source_path": "dpl.detected_leaks[1].observed_rate",
            "derivation": None,
        }
    )

    result = verify_explanation(payload, dpl)

    assert not result.passed
    assert "numeric_detected_leak_not_allowed" in _codes(result)


def test_verifier_rejects_unallowed_detected_leak_surface_number(valid_dpl):
    _append_unallowed_detected_leak(valid_dpl)
    dpl, payload = _valid_explanation_payload(valid_dpl)
    payload["stages"][0]["numeric_claims"].append(
        {
            "name": "detected_leaks[1].observed_rate",
            "value": 0.91,
            "unit": "probability",
            "source_kind": "dpl",
            "source_path": "dpl.detected_leaks[1].observed_rate",
            "derivation": None,
        }
    )
    payload["stages"][0]["text"] += " An uncited leak observed 91.0%."
    _refresh_rendered_text(payload)

    result = verify_explanation(payload, dpl)

    assert not result.passed
    assert "numeric_detected_leak_not_allowed" in _codes(result)
    assert "surface_numeric_unbacked" in _codes(result)


def test_verifier_rejects_missing_derivation(valid_dpl):
    dpl, payload = _valid_explanation_payload(valid_dpl)
    del payload["ev_breakdown"]["decision_ev_delta"]["derivation"]

    result = verify_explanation(payload, dpl)

    assert not result.passed
    assert "contract_validation_failed" in _codes(result)


def test_verifier_rejects_derivation_mismatch(valid_dpl):
    dpl, payload = _valid_explanation_payload(valid_dpl)
    payload["ev_breakdown"]["decision_ev_delta"]["derivation"] = "exploit_ev - base_ev"

    result = verify_explanation(payload, dpl)

    assert not result.passed
    assert "numeric_derivation_mismatch" in _codes(result)


def test_verifier_accepts_missing_base_action_derived_probability(valid_dpl):
    valid_dpl["base_policy"] = {"CHECK": 1.0}
    valid_dpl["exploit_policy"] = {"CHECK": 0.2, "BET_75": 0.8}
    valid_dpl["final_policy"] = {"CHECK": 0.6, "BET_75": 0.4}
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)
    explanation = generate_template_explanation(dpl)

    result = verify_explanation(explanation, dpl)

    assert result.passed


def test_verifier_rejects_nonexistent_direct_base_policy_path(valid_dpl):
    valid_dpl["base_policy"] = {"CHECK": 1.0}
    valid_dpl["exploit_policy"] = {"CHECK": 0.2, "BET_75": 0.8}
    valid_dpl["final_policy"] = {"CHECK": 0.6, "BET_75": 0.4}
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)
    explanation = generate_template_explanation(dpl)
    payload = explanation.model_dump(mode="json")
    baseline_claim = payload["counterfactual"]["baseline_selected_action_probability"]
    baseline_claim["source_kind"] = "dpl"
    baseline_claim["source_path"] = "dpl.base_policy['BET_75']"
    baseline_claim["derivation"] = None

    result = verify_explanation(payload, dpl)

    assert not result.passed
    assert "numeric_source_unresolved" in _codes(result)


def test_verifier_rejects_solver_diagnostic_value_tampering(valid_dpl):
    dpl, diagnostics = _nodelock_dpl_and_diagnostics(valid_dpl)
    explanation = generate_template_explanation(dpl, solver_diagnostics=diagnostics)
    payload = explanation.model_dump(mode="json")
    payload["ev_breakdown"]["solver_ev_delta"]["value"] = 9.7

    result = verify_explanation(payload, dpl, solver_diagnostics=diagnostics)

    assert not result.passed
    assert "numeric_value_mismatch" in _codes(result)


def test_verifier_rejects_solver_diagnostic_source_path_tampering(valid_dpl):
    dpl, diagnostics = _nodelock_dpl_and_diagnostics(valid_dpl)
    explanation = generate_template_explanation(dpl, solver_diagnostics=diagnostics)
    payload = explanation.model_dump(mode="json")
    payload["ev_breakdown"]["solver_ev_delta"]["source_path"] = (
        "solver_diagnostics.metrics.other_ev_delta"
    )

    result = verify_explanation(payload, dpl, solver_diagnostics=diagnostics)

    assert not result.passed
    assert "solver_source_path_mismatch" in _codes(result)


def test_verifier_requires_solver_diagnostics_input_for_solver_claims(valid_dpl):
    dpl, diagnostics = _nodelock_dpl_and_diagnostics(valid_dpl)
    explanation = generate_template_explanation(dpl, solver_diagnostics=diagnostics)

    result = verify_explanation(explanation, dpl)

    assert not result.passed
    assert "solver_diagnostics_missing" in _codes(result)


def test_verifier_requires_solver_claims_when_diagnostics_are_provided(valid_dpl):
    dpl, diagnostics = _nodelock_dpl_and_diagnostics(valid_dpl)
    explanation = generate_template_explanation(dpl, solver_diagnostics=diagnostics)
    payload = explanation.model_dump(mode="json")
    payload["ev_breakdown"]["solver_ev_delta"] = None
    residual_stage = payload["stages"][4]
    residual_stage["numeric_claims"] = [
        claim for claim in residual_stage["numeric_claims"] if claim["name"] != "solver_ev_delta"
    ]
    residual_stage["text"] = residual_stage["text"].replace(
        "Solver-level EV delta is kept separate at +9.5000 bb.",
        "No solver-level EV delta is cited in this explanation.",
    )
    _refresh_rendered_text(payload)

    result = verify_explanation(payload, dpl, solver_diagnostics=diagnostics)

    assert not result.passed
    assert "solver_ev_delta_missing" in _codes(result)
    assert "solver_stage_claim_missing" in _codes(result)
