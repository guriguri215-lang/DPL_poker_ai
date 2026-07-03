"""Tests for the Decision Provenance Log schema v1 (ADR-0001, ADR-0006, ADR-0008)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from poker_core.dpl_schema import (
    DPL_SCHEMA_VERSION,
    DecisionProvenanceLog,
    EvEstimate,
)


def test_valid_dpl_round_trips(valid_dpl):
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)
    assert dpl.schema_version == DPL_SCHEMA_VERSION
    assert dpl.selected_action in dpl.final_policy
    # JSON round-trip preserves the record
    again = DecisionProvenanceLog.model_validate_json(dpl.model_dump_json())
    assert again == dpl


# --- policy distribution validation ---------------------------------------


@pytest.mark.parametrize("field", ["base_policy", "exploit_policy", "final_policy"])
def test_policy_must_sum_to_one(valid_dpl, field):
    valid_dpl[field] = {"CHECK": 0.5, "BET_75": 0.4}  # sums to 0.9
    with pytest.raises(ValidationError, match="sum to 1.0"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_empty_policy_rejected(valid_dpl):
    valid_dpl["base_policy"] = {}
    with pytest.raises(ValidationError, match="must not be empty"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_policy_probability_out_of_range_rejected(valid_dpl):
    valid_dpl["final_policy"] = {"CHECK": -0.1, "BET_75": 1.1}
    with pytest.raises(ValidationError, match="out of"):
        DecisionProvenanceLog.model_validate(valid_dpl)


# --- reason-id namespace separation (ADR-0001) ----------------------------


def test_trg_id_in_detected_leaks_rejected(valid_dpl):
    """A TRG_ id must not appear in detected_leaks (LEAK_-only field)."""
    valid_dpl["detected_leaks"][0]["reason_id"] = "TRG_R001"
    with pytest.raises(ValidationError, match="LEAK_ reason id"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_mix_id_in_detected_leaks_rejected(valid_dpl):
    valid_dpl["detected_leaks"][0]["reason_id"] = "MIX_R001"
    with pytest.raises(ValidationError, match="LEAK_ reason id"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_leak_id_in_trigger_reasons_rejected(valid_dpl):
    """A LEAK_ id must not appear in trigger_reasons (TRG_-only field)."""
    valid_dpl["trigger_reasons"] = ["LEAK_R001"]
    with pytest.raises(ValidationError, match="TRG_ reason id"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_mix_id_in_trigger_reasons_rejected(valid_dpl):
    valid_dpl["trigger_reasons"] = ["MIX_R001"]
    with pytest.raises(ValidationError, match="TRG_ reason id"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_unknown_reason_id_rejected(valid_dpl):
    valid_dpl["detected_leaks"][0]["reason_id"] = "LEAK_R999"
    valid_dpl["detected_leaks"][0]["leak_type"] = "made_up"
    with pytest.raises(ValidationError, match="unknown reason id"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_leak_type_must_match_ontology_label(valid_dpl):
    valid_dpl["detected_leaks"][0]["leak_type"] = "wrong_label"
    with pytest.raises(ValidationError, match="does not match ontology label"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_allowed_reason_ids_reject_unknown(valid_dpl):
    valid_dpl["allowed_reason_ids"].append("TRG_R999")
    with pytest.raises(ValidationError, match="unknown reason id"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_allowed_reason_ids_accept_all_three_namespaces(valid_dpl):
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)
    prefixes = {rid.split("_")[0] for rid in dpl.allowed_reason_ids}
    assert prefixes == {"LEAK", "TRG", "MIX"}


def test_duplicate_trigger_reason_rejected(valid_dpl):
    valid_dpl["trigger_reasons"] = ["TRG_R001", "TRG_R001"]
    with pytest.raises(ValidationError, match="duplicate reason id"):
        DecisionProvenanceLog.model_validate(valid_dpl)


# --- cross-field integrity ------------------------------------------------


def test_selected_action_must_be_in_final_policy(valid_dpl):
    valid_dpl["selected_action"] = "FOLD"
    with pytest.raises(ValidationError, match="not a key of final_policy"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_nodelock_source_requires_solver_result_id(valid_dpl):
    valid_dpl["exploit_source"] = "nodelock_solver"
    valid_dpl["solver_result_id"] = None
    with pytest.raises(ValidationError, match="solver_result_id is required"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_nodelock_source_with_solver_result_id_ok(valid_dpl):
    valid_dpl["exploit_source"] = "nodelock_solver"
    valid_dpl["solver_result_id"] = "solve_abc123"
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)
    assert dpl.solver_result_id == "solve_abc123"


def test_extra_field_forbidden(valid_dpl):
    valid_dpl["surprise"] = 1
    with pytest.raises(ValidationError):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_unsupported_schema_version_rejected(valid_dpl):
    valid_dpl["schema_version"] = "0.9.0"
    with pytest.raises(ValidationError, match="unsupported DPL schema_version"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_invalid_hand_bucket_rejected(valid_dpl):
    valid_dpl["hand_bucket"] = "monster"
    with pytest.raises(ValidationError):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_safety_alpha_out_of_range_rejected(valid_dpl):
    valid_dpl["safety_alpha"] = 1.5
    with pytest.raises(ValidationError):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_detected_leak_rate_out_of_range_rejected(valid_dpl):
    valid_dpl["detected_leaks"][0]["observed_rate"] = 1.4
    with pytest.raises(ValidationError):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_no_leaks_is_valid(valid_dpl):
    valid_dpl["detected_leaks"] = []
    valid_dpl["trigger_reasons"] = []
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)
    assert dpl.detected_leaks == []


# --- EV provenance contract (ADR-0008) ------------------------------------


def test_solver_exact_ev_is_explanation_safe(valid_dpl):
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)
    payload = dpl.ev_for_explanation()
    assert payload is not None
    assert payload["final_ev"] == 4.27
    assert payload["gain_vs_base"] == pytest.approx(4.27 - 4.12)


@pytest.mark.parametrize("source", ["heuristic", "solver_estimate"])
def test_non_exact_ev_not_passed_to_explanation(valid_dpl, source):
    valid_dpl["ev_estimate"]["ev_source"] = source
    valid_dpl["ev_estimate"]["worst_case_penalty"] = None  # required for heuristic
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)
    assert dpl.ev_for_explanation() is None
    assert dpl.ev_estimate.is_explanation_safe is False


def test_heuristic_ev_may_not_carry_worst_case_penalty(valid_dpl):
    valid_dpl["ev_estimate"]["ev_source"] = "heuristic"
    # worst_case_penalty stays -0.08 -> should be rejected
    with pytest.raises(ValidationError, match="worst_case_penalty must be null"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_ev_unit_and_definition_required():
    with pytest.raises(ValidationError):
        EvEstimate.model_validate(
            {
                "base_ev": 1.0,
                "exploit_ev": 1.0,
                "final_ev": 1.0,
                "ev_source": "solver_exact",
                "ev_unit": "",
                "ev_definition": "incremental_ev_from_current_node",
            }
        )
