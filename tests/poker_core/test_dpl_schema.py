"""Tests for the Decision Provenance Log schema v1 (ADR-0001, ADR-0005/0006/0008)."""

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
    assert dpl.mix_reasons == ["MIX_R001"]
    assert dpl.hero_combo == "AhKh"
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


# --- alpha-mixing consistency (Spec 6.8) ----------------------------------


def test_final_policy_must_equal_alpha_mix(valid_dpl):
    # base/exploit/alpha imply final {CHECK:0.4, BET_75:0.6}; store a wrong final.
    valid_dpl["final_policy"] = {"CHECK": 0.5, "BET_75": 0.5}
    with pytest.raises(ValidationError, match="alpha-mix"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_mixing_checked_over_union_of_actions(valid_dpl):
    # exploit introduces an action absent from base/final; mix would require it.
    valid_dpl["exploit_policy"] = {"CHECK": 0.2, "BET_75": 0.6, "BET_150": 0.2}
    with pytest.raises(ValidationError, match="alpha-mix"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_selected_action_must_be_in_final_policy(valid_dpl):
    valid_dpl["selected_action"] = "FOLD"
    with pytest.raises(ValidationError, match="not a key of final_policy"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_selected_action_needs_positive_probability(valid_dpl):
    valid_dpl["final_policy"] = {"CHECK": 0.4, "BET_75": 0.6, "FOLD": 0.0}
    valid_dpl["selected_action"] = "FOLD"
    with pytest.raises(ValidationError, match="positive probability"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_epsilon_execution_allows_action_outside_final_policy(valid_dpl):
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

    assert dpl.selected_action == "BET_75"
    assert dpl.final_policy == {"CHECK": 1.0}
    assert dpl.execution_sampling is not None
    assert dpl.execution_sampling.execution_policy["BET_75"] == pytest.approx(0.5)


def test_mix_epsilon_requires_execution_sampling(valid_dpl):
    valid_dpl["mix_reasons"] = ["MIX_EPSILON"]
    valid_dpl["allowed_reason_ids"] = [
        "LEAK_R001",
        "TRG_R001",
        "TRG_R002",
        "TRG_R003",
        "MIX_EPSILON",
    ]
    with pytest.raises(ValidationError, match="MIX_EPSILON requires execution_sampling"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_execution_sampling_rejects_non_fired_record(valid_dpl):
    valid_dpl["execution_sampling"] = {
        "sampler_version": "epsilon-uniform-v1",
        "epsilon": 0.5,
        "epsilon_distribution": {"CHECK": 0.5, "BET_75": 0.5},
        "execution_policy": {"CHECK": 0.45, "BET_75": 0.55},
        "exploration_fired": False,
    }
    with pytest.raises(ValidationError, match="execution_sampling may only be recorded"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_execution_sampling_requires_mix_epsilon_reason(valid_dpl):
    valid_dpl["execution_sampling"] = {
        "sampler_version": "epsilon-uniform-v1",
        "epsilon": 0.5,
        "epsilon_distribution": {"CHECK": 0.5, "BET_75": 0.5},
        "execution_policy": {"CHECK": 0.45, "BET_75": 0.55},
        "exploration_fired": True,
    }
    with pytest.raises(ValidationError, match="execution_sampling requires MIX_EPSILON"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_execution_sampling_must_match_epsilon_mix(valid_dpl):
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
        "execution_policy": {"CHECK": 0.75, "BET_75": 0.25},
        "exploration_fired": True,
    }
    with pytest.raises(ValidationError, match="epsilon execution mix"):
        DecisionProvenanceLog.model_validate(valid_dpl)


# --- reason-id namespace separation (ADR-0001) ----------------------------


def test_trg_id_in_detected_leaks_rejected(valid_dpl):
    """A TRG_ id must not appear in detected_leaks (LEAK_-only field)."""
    valid_dpl["detected_leaks"][0]["reason_id"] = "TRG_R001"
    with pytest.raises(ValidationError, match="LEAK_"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_mix_id_in_detected_leaks_rejected(valid_dpl):
    valid_dpl["detected_leaks"][0]["reason_id"] = "MIX_R001"
    with pytest.raises(ValidationError, match="LEAK_"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_leak_id_in_trigger_reasons_rejected(valid_dpl):
    """A LEAK_ id must not appear in trigger_reasons (TRG_-only field)."""
    valid_dpl["trigger_reasons"] = ["LEAK_R001"]
    with pytest.raises(ValidationError, match="TRG_"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_non_mix_id_in_mix_reasons_rejected(valid_dpl):
    valid_dpl["mix_reasons"] = ["LEAK_R001"]
    with pytest.raises(ValidationError, match="MIX_"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_unknown_reason_id_rejected(valid_dpl):
    valid_dpl["detected_leaks"][0]["reason_id"] = "LEAK_R999"
    valid_dpl["detected_leaks"][0]["leak_type"] = "made_up"
    with pytest.raises(ValidationError, match="unknown reason id"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_unknown_mix_reason_rejected(valid_dpl):
    valid_dpl["mix_reasons"] = ["MIX_R999"]
    valid_dpl["allowed_reason_ids"] = ["LEAK_R001", "TRG_R001", "TRG_R002", "TRG_R003"]
    with pytest.raises(ValidationError, match="unknown reason id"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_leak_type_must_match_ontology_label(valid_dpl):
    valid_dpl["detected_leaks"][0]["leak_type"] = "wrong_label"
    with pytest.raises(ValidationError, match="does not match ontology label"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_duplicate_trigger_reason_rejected(valid_dpl):
    valid_dpl["trigger_reasons"] = ["TRG_R001", "TRG_R001"]
    with pytest.raises(ValidationError, match="duplicate reason id"):
        DecisionProvenanceLog.model_validate(valid_dpl)


# --- closed-world allowed_reason_ids (ADR-0001; Spec 6.10) -----------------


def test_allowed_reason_ids_reject_unknown(valid_dpl):
    valid_dpl["allowed_reason_ids"].append("TRG_R999")
    with pytest.raises(ValidationError, match="unknown reason id"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_allowed_reason_ids_must_be_backed(valid_dpl):
    # LEAK_R002 exists in the ontology but is not recorded on this decision.
    valid_dpl["allowed_reason_ids"].append("LEAK_R002")
    with pytest.raises(ValidationError, match="not backed by any recorded reason"):
        DecisionProvenanceLog.model_validate(valid_dpl)


def test_allowed_reason_ids_accept_all_three_namespaces(valid_dpl):
    dpl = DecisionProvenanceLog.model_validate(valid_dpl)
    prefixes = {rid.split("_")[0] for rid in dpl.allowed_reason_ids}
    assert prefixes == {"LEAK", "TRG", "MIX"}


# --- cross-field integrity ------------------------------------------------


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


def test_hero_combo_required(valid_dpl):
    valid_dpl["hero_combo"] = ""
    with pytest.raises(ValidationError):
        DecisionProvenanceLog.model_validate(valid_dpl)


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
    # A decision with no recorded reasons and an empty explanation whitelist.
    valid_dpl["detected_leaks"] = []
    valid_dpl["trigger_reasons"] = []
    valid_dpl["mix_reasons"] = []
    valid_dpl["allowed_reason_ids"] = []
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
