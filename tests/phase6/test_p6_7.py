"""Unit fixtures for the approved ADR-0022 P6-7 settings only."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from decimal import Decimal

import pytest

from opponents import load_training_catalog, load_validation_catalog
from phase6 import (
    COMPARATOR_ID,
    DRAW_DERIVATION_VERSION,
    EXECUTION_SAMPLER_VERSION,
    LEGAL_ACTION_ORDER,
    PRIMARY_SELECTION_KEYS,
    REPETITION_SEEDS,
    RESERVED_ALPHA_ABLATION_ID,
    RESERVED_ALPHA_ABLATION_REASON,
    SEED_DERIVATION_VERSION,
    STREAM_NAMES,
    CandidateSelectionMetrics,
    ExpectedGtoSelectionGroup,
    GtoSelectionGroup,
    ObservationNodeSpec,
    ObservationRegistry,
    alpha_050_comparator_plan,
    artifact_ref,
    build_catalog_fixture_evidence,
    build_r008_component_source_payloads,
    build_r008_coverage_contract,
    build_r008_fixture_payloads,
    canonical_json_bytes,
    canonical_legal_actions,
    derive_draw_digest,
    derive_stream_root,
    evaluate_coverage_semantics,
    p6_7_preregistration_payload,
    primary_candidate_grid,
    rank_primary_candidates,
    sample_execution_action,
    sample_observation_node,
    sampling_contract_payload,
    sampling_contract_sha256,
    uniform_action,
    validate_catalog_fixture,
    validate_primary_candidate_grid,
    validate_sampling_contract,
    weighted_categorical,
)


def _contract():
    registry_hash = hashlib.sha256(b"fixture-observation-registry-v1\n").hexdigest()
    payload = sampling_contract_payload(
        observation_registry_version="fixture-observation-registry-v1",
        observation_registry_sha256=registry_hash,
    )
    return payload, sampling_contract_sha256(payload)


def _grid():
    _payload, contract_hash = _contract()
    return primary_candidate_grid(sampling_contract_sha256=contract_hash)


def _metrics(candidates):
    eligible_keys = tuple(f"r{index:03d}:LEAK_R008" for index in range(1, 11))
    return [
        CandidateSelectionMetrics(
            candidate_id=item.candidate_id,
            validation_macro_brier=Decimal("0.2"),
            validation_micro_brier=Decimal("0.2"),
            gto_false_positives=1,
            gto_total_negatives=10,
            validation_macro_exploitation_efficiency=Decimal("0.4"),
            validation_macro_recall=Decimal("0.5"),
            validation_macro_precision=Decimal("0.6"),
            gto_groups=(
                GtoSelectionGroup(
                    "nl-val-gto-s640000",
                    50,
                    1,
                    10,
                    "defined",
                    eligible_keys,
                ),
            ),
        )
        for item in candidates
    ]


def _expected_gto_groups():
    eligible_keys = tuple(f"r{index:03d}:LEAK_R008" for index in range(1, 11))
    return (
        ExpectedGtoSelectionGroup(
            "nl-val-gto-s640000",
            50,
            eligible_keys,
        ),
    )


def _coverage_evaluation(tmp_path):
    sources = build_r008_component_source_payloads()
    fixtures = build_r008_fixture_payloads()
    source_refs = {}
    fixture_refs = {}
    for role, payload in sources.items():
        path = f"sources/{role}.json"
        destination = tmp_path / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(canonical_json_bytes(payload))
        source_refs[role] = artifact_ref(
            artifact_type="phase6_semantic_source",
            schema_version=payload["schema_version"],
            path=path,
            payload=payload,
        )
    for fixture_id, payload in fixtures.items():
        path = f"fixtures/{fixture_id}.json"
        destination = tmp_path / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(canonical_json_bytes(payload))
        fixture_refs[fixture_id] = artifact_ref(
            artifact_type="phase6_semantic_fixture",
            schema_version=payload["schema_version"],
            path=path,
            payload=payload,
        )
    coverage = build_r008_coverage_contract(source_refs, fixture_refs)
    return evaluate_coverage_semantics(coverage, tmp_path)


def _catalog_fixture(coverage_evaluation):
    configs = (*load_training_catalog(), *load_validation_catalog())
    return build_catalog_fixture_evidence(configs, coverage_evaluation=coverage_evaluation)


def test_digest_direct_v2_contract_is_closed_world_and_hash_bound():
    payload, contract_hash = _contract()

    validate_sampling_contract(payload, expected_sha256=contract_hash)
    assert payload["seed_derivation_version"] == SEED_DERIVATION_VERSION
    assert payload["draw_derivation_version"] == DRAW_DERIVATION_VERSION
    assert payload["execution_sampler_version"] == EXECUTION_SAMPLER_VERSION
    assert payload["stream_names"] == list(STREAM_NAMES)
    assert payload["stateful_prng"] is None

    forged = copy.deepcopy(payload)
    forged["seed_derivation_version"] = "phase6-domain-separated-sha256-v1"
    with pytest.raises(ValueError, match="digest-direct v2"):
        validate_sampling_contract(forged)
    with pytest.raises(ValueError, match="hash mismatch"):
        validate_sampling_contract(payload, expected_sha256="f" * 64)


def test_repetition_mapping_and_stream_root_are_exact_and_candidate_free():
    assert len(REPETITION_SEEDS) == 30
    assert REPETITION_SEEDS[0] == ("r001", 620001)
    assert REPETITION_SEEDS[-1] == ("r030", 620030)

    root = derive_stream_root(
        split="training",
        opponent_id="fixture-opponent",
        horizon=50,
        repetition_id="r001",
        stream_name="observation",
    )
    assert root.payload == {
        "derivation_version": SEED_DERIVATION_VERSION,
        "horizon": 50,
        "master_seed": 620001,
        "opponent_id": "fixture-opponent",
        "repetition_id": "r001",
        "split": "training",
        "stream_name": "observation",
    }
    assert set(root.payload).isdisjoint(
        {"candidate_id", "epsilon", "sample_floor", "confidence", "safety_alpha"}
    )
    assert (
        root.digest
        == derive_stream_root(
            split="training",
            opponent_id="fixture-opponent",
            horizon=50,
            repetition_id="r001",
            stream_name="observation",
        ).digest
    )
    with pytest.raises(ValueError, match="r001..r030"):
        derive_stream_root(
            split="training",
            opponent_id="fixture-opponent",
            horizon=50,
            repetition_id="r031",
            stream_name="observation",
        )


def test_draw_coordinates_are_direct_and_width_checked():
    root = derive_stream_root(
        split="training",
        opponent_id="fixture-opponent",
        horizon=50,
        repetition_id="r001",
        stream_name="hero_action",
    )
    first = derive_draw_digest(root, decision_index=0)
    assert first == derive_draw_digest(root, decision_index=0)
    assert first != derive_draw_digest(root, decision_index=1)
    assert first != derive_draw_digest(root, decision_index=0, variate_index=1)
    assert first != derive_draw_digest(root, decision_index=0, attempt_index=1)
    assert derive_draw_digest(root, decision_index=49)
    with pytest.raises(ValueError, match="stream root horizon"):
        derive_draw_digest(root, decision_index=50)
    with pytest.raises(ValueError, match="attempt_index"):
        derive_draw_digest(root, decision_index=0, attempt_index=-1)
    forged = replace(root, digest="f" * 64)
    with pytest.raises(ValueError, match="payload and digest"):
        derive_draw_digest(forged, decision_index=0)


def test_observation_registry_binds_ordered_outcomes_and_transition_variate():
    registry = ObservationRegistry(
        "fixture-observation-registry-v1",
        (
            ObservationNodeSpec(
                "deal_bucket",
                "deal-bucket-outcomes-v1",
                (("low", 0.25), ("high", 0.75)),
            ),
        ),
    )
    contract = sampling_contract_payload(
        observation_registry_version=registry.registry_version,
        observation_registry_sha256=registry.sha256,
    )
    validate_sampling_contract(contract)
    root = derive_stream_root(
        split="training",
        opponent_id="fixture-opponent",
        horizon=50,
        repetition_id="r001",
        stream_name="observation",
    )

    first = sample_observation_node(
        registry,
        node_id="deal_bucket",
        stream_root=root,
        decision_index=0,
        variate_index=0,
    )
    second = sample_observation_node(
        registry,
        node_id="deal_bucket",
        stream_root=root,
        decision_index=0,
        variate_index=1,
    )
    assert first.draw_digest != second.draw_digest
    assert first.selected_outcome_id in {"low", "high"}
    assert first.outcome_registry_version == "deal-bucket-outcomes-v1"
    with pytest.raises(ValueError, match="unknown observation node"):
        sample_observation_node(
            registry,
            node_id="caller-dict-order-fallback",
            stream_root=root,
            decision_index=0,
            variate_index=0,
        )


def test_action_order_and_exact_weighted_mapping_ignore_input_mapping_order():
    assert canonical_legal_actions(["CALL", "FOLD"]) == ("FOLD", "CALL")
    assert canonical_legal_actions(["BET_ALL_IN", "CHECK", "BET_33"]) == (
        "CHECK",
        "BET_33",
        "BET_ALL_IN",
    )
    assert weighted_categorical(("A", "B"), (0.0, 1.0), "0" * 64) == "B"
    assert weighted_categorical(("A", "B"), (1.0, 0.0), "f" * 64) == "A"
    with pytest.raises(ValueError, match="unknown legal"):
        canonical_legal_actions(["CHECK", "LIMP"])
    with pytest.raises(ValueError, match="positive"):
        weighted_categorical(("A", "B"), (0.0, 0.0), "0" * 64)


def test_uniform_action_requires_epsilon_action_stream_root():
    roots = {
        stream: derive_stream_root(
            split="training",
            opponent_id="fixture-opponent",
            horizon=50,
            repetition_id="r001",
            stream_name=stream,
        )
        for stream in ("epsilon_action", "hero_action")
    }

    action, digest, attempt = uniform_action(
        ["CALL", "FOLD"], roots["epsilon_action"], decision_index=0
    )
    assert action in {"CALL", "FOLD"}
    assert len(digest) == 64
    assert attempt >= 0

    with pytest.raises(ValueError, match="expected epsilon_action stream root"):
        uniform_action(["CALL", "FOLD"], roots["hero_action"], decision_index=0)


@pytest.mark.parametrize(
    "epsilon, branch_expected, hero_status, epsilon_status",
    [
        ("0", False, "used", "unused"),
        ("1", True, "unused", "used"),
    ],
)
def test_action_sampling_always_derives_reserved_draws_and_marks_unused(
    epsilon, branch_expected, hero_status, epsilon_status
):
    roots = {
        stream: derive_stream_root(
            split="training",
            opponent_id="fixture-opponent",
            horizon=50,
            repetition_id="r001",
            stream_name=stream,
        )
        for stream in ("hero_action", "epsilon_branch", "epsilon_action")
    }
    audit = sample_execution_action(
        final_policy={"CALL": 1.0, "FOLD": 0.0},
        legal_actions=["CALL", "FOLD"],
        epsilon=epsilon,
        decision_index=0,
        hero_stream_root=roots["hero_action"],
        epsilon_branch_stream_root=roots["epsilon_branch"],
        epsilon_action_stream_root=roots["epsilon_action"],
    )

    assert audit.branch_fired is branch_expected
    assert audit.hero_draw_status == hero_status
    assert audit.epsilon_action_draw_status == epsilon_status
    assert (
        len(
            {
                audit.hero_draw_digest,
                audit.epsilon_branch_draw_digest,
                audit.epsilon_action_draw_digest,
            }
        )
        == 3
    )
    assert audit.final_action == (audit.epsilon_action if branch_expected else audit.hero_action)

    swapped_root = derive_stream_root(
        split="training",
        opponent_id="different-opponent",
        horizon=50,
        repetition_id="r001",
        stream_name="epsilon_action",
    )
    with pytest.raises(ValueError, match="sampling identity"):
        sample_execution_action(
            final_policy={"CALL": 1.0, "FOLD": 0.0},
            legal_actions=["CALL", "FOLD"],
            epsilon=epsilon,
            decision_index=0,
            hero_stream_root=roots["hero_action"],
            epsilon_branch_stream_root=roots["epsilon_branch"],
            epsilon_action_stream_root=swapped_root,
        )


def test_primary_grid_is_exact_complete_product_without_epsilon_zero():
    candidates = _grid()
    validate_primary_candidate_grid(candidates)

    assert len(candidates) == 16
    assert {item.epsilon for item in candidates} == {"0.05", "0.1"}
    assert {item.sample_floor for item in candidates} == {10, 25}
    assert {item.detector_confidence for item in candidates} == {"0.9", "0.95"}
    assert all(item.provider_confidence == item.detector_confidence for item in candidates)
    assert {item.safety_alpha for item in candidates} == {"0.25", "0.5"}
    with pytest.raises(ValueError, match="exactly 16"):
        validate_primary_candidate_grid(candidates[:-1])
    forged = list(candidates)
    forged[0] = replace(forged[0], epsilon="0")
    with pytest.raises(ValueError, match="canonical approved"):
        validate_primary_candidate_grid(forged)


def test_primary_selection_uses_all_seven_keys_and_exact_gto_fraction():
    candidates = _grid()
    metrics = _metrics(candidates)
    first_id, second_id = sorted(item.candidate_id for item in candidates)[:2]
    metrics = [
        replace(
            item,
            gto_false_positives=2,
            gto_total_negatives=10,
            validation_macro_precision=None,
            gto_groups=(replace(item.gto_groups[0], false_positives=2),),
        )
        if item.candidate_id == first_id
        else replace(
            item,
            gto_false_positives=1,
            gto_total_negatives=10,
            validation_macro_precision=Decimal("0.7"),
        )
        if item.candidate_id == second_id
        else item
        for item in metrics
    ]
    ranked = rank_primary_candidates(
        candidates, metrics, expected_gto_groups=_expected_gto_groups()
    )

    assert len(PRIMARY_SELECTION_KEYS) == 7
    assert ranked[0].candidate_id == second_id
    assert ranked[-1].candidate_id == first_id
    undefined_gto = list(metrics)
    undefined_gto[0] = replace(
        undefined_gto[0],
        gto_false_positives=0,
        gto_total_negatives=0,
        gto_groups=(
            replace(
                undefined_gto[0].gto_groups[0],
                false_positives=0,
                total_negatives=0,
                status="no_eligible_records",
            ),
        ),
    )
    with pytest.raises(ValueError, match="zero/partial-undefined"):
        rank_primary_candidates(
            candidates, undefined_gto, expected_gto_groups=_expected_gto_groups()
        )


def test_primary_selection_rejects_partial_missing_and_mismatched_gto_groups():
    candidates = _grid()
    metrics = _metrics(candidates)
    partial = list(metrics)
    partial[0] = replace(
        partial[0],
        gto_groups=(replace(partial[0].gto_groups[0], status="no_eligible_records"),),
    )
    with pytest.raises(ValueError, match="partial-undefined group"):
        rank_primary_candidates(candidates, partial, expected_gto_groups=_expected_gto_groups())

    missing = list(metrics)
    missing[0] = replace(missing[0], gto_groups=())
    with pytest.raises(ValueError, match="group set"):
        rank_primary_candidates(candidates, missing, expected_gto_groups=_expected_gto_groups())

    mismatched = list(metrics)
    mismatched[0] = replace(
        mismatched[0],
        gto_groups=(replace(mismatched[0].gto_groups[0], eligible_keys=("different-key",)),),
    )
    with pytest.raises(ValueError, match="eligible key set"):
        rank_primary_candidates(candidates, mismatched, expected_gto_groups=_expected_gto_groups())


def test_alpha_comparator_is_separate_and_uses_existing_grid_candidate():
    candidates = _grid()
    selected_025 = next(item for item in candidates if item.safety_alpha == "0.25")
    plan = alpha_050_comparator_plan(selected_025, candidates)

    assert plan.comparator_id == COMPARATOR_ID
    assert plan.comparator_status == "existing_grid_candidate"
    peer = next(item for item in candidates if item.candidate_id == plan.comparator_candidate_id)
    assert peer.safety_alpha == "0.5"
    assert peer.epsilon == selected_025.epsilon
    assert peer.sample_floor == selected_025.sample_floor
    assert peer.detector_confidence == selected_025.detector_confidence

    selected_050 = peer
    degenerate = alpha_050_comparator_plan(selected_050, candidates)
    assert degenerate.comparator_status == "degenerate_equal_to_primary"
    assert degenerate.comparator_candidate_id == selected_050.candidate_id
    assert degenerate.exact_delta == "0"


def test_fixed_alpha_ablation_is_reserved_but_never_instantiated():
    _payload, contract_hash = _contract()
    preregistration = p6_7_preregistration_payload(sampling_contract_sha256=contract_hash)

    assert preregistration["comparator_id"] == COMPARATOR_ID
    assert preregistration["reserved_uninstantiated"] == {
        "id": RESERVED_ALPHA_ABLATION_ID,
        "reason": RESERVED_ALPHA_ABLATION_REASON,
    }
    assert all(
        RESERVED_ALPHA_ABLATION_ID not in candidate_id
        for candidate_id in preregistration["primary_candidate_ids"]
    )
    assert preregistration["gto_fpr_hard_constraint"] is None
    assert preregistration["worst_case_penalty_usage"] == "excluded"


def test_catalog_fixture_satisfies_approved_coverage_and_identity_gates(tmp_path):
    coverage = _coverage_evaluation(tmp_path)
    evidence = _catalog_fixture(coverage)

    validate_catalog_fixture(evidence, coverage_evaluation=coverage)

    duplicate_strategy = list(evidence)
    leak_indexes = [
        index for index, item in enumerate(duplicate_strategy) if item.config.leak_vector
    ]
    duplicate_strategy[leak_indexes[1]] = replace(
        duplicate_strategy[leak_indexes[1]],
        strategy_sha256=duplicate_strategy[leak_indexes[0]].strategy_sha256,
    )
    with pytest.raises(ValueError, match="reconstructed provenance"):
        validate_catalog_fixture(duplicate_strategy, coverage_evaluation=coverage)


def test_catalog_fixture_rejects_tampered_truth_role_semantic_and_coverage(tmp_path):
    coverage = _coverage_evaluation(tmp_path)
    evidence = _catalog_fixture(coverage)
    without_control = [
        replace(item, control_role=None) if item.control_role == "gto_negative_control" else item
        for item in evidence
    ]
    with pytest.raises(ValueError, match="reconstructed provenance"):
        validate_catalog_fixture(without_control, coverage_evaluation=coverage)

    without_r008_e2e = [replace(item, end_to_end_coverage=False) for item in evidence]
    with pytest.raises(ValueError, match="reconstructed provenance"):
        validate_catalog_fixture(without_r008_e2e, coverage_evaluation=coverage)

    wrong_semantic = [
        replace(item, r008_semantic_id="wrong") if item.r008_semantic_id else item
        for item in evidence
    ]
    with pytest.raises(ValueError, match="reconstructed provenance"):
        validate_catalog_fixture(wrong_semantic, coverage_evaluation=coverage)

    wrong_delta = list(evidence)
    target = next(
        index for index, item in enumerate(wrong_delta) if "LEAK_R008" in item.config.leak_amounts
    )
    wrong_delta[target] = replace(
        wrong_delta[target],
        primary_true_deltas=(("LEAK_R007", Decimal(0)), ("LEAK_R008", Decimal("0.319"))),
    )
    with pytest.raises(ValueError, match="reconstructed provenance"):
        validate_catalog_fixture(wrong_delta, coverage_evaluation=coverage)

    invalid_coverage = replace(coverage, end_to_end_coverage=False)
    with pytest.raises(ValueError, match="coverage provenance"):
        validate_catalog_fixture(evidence, coverage_evaluation=invalid_coverage)


def test_no_v1_or_alpha_ablation_is_exposed_as_an_approved_runtime_setting():
    payload, _contract_hash = _contract()
    serialized = repr(payload)

    assert "phase6-domain-separated-sha256-v1" not in serialized
    assert "phase6-event-v1" not in serialized
    assert "python-random-mt19937-v1" not in serialized
    assert "random.Random" not in serialized
    assert RESERVED_ALPHA_ABLATION_ID not in serialized
    assert LEGAL_ACTION_ORDER == (
        "CHECK",
        "BET",
        "BET_33",
        "BET_75",
        "BET_ALL_IN",
        "FOLD",
        "CALL",
        "RAISE_ALL_IN",
    )
