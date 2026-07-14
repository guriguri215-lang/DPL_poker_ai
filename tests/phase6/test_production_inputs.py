"""Fixture-only regression for P6-7 production Training input contracts."""

from __future__ import annotations

import copy
import json
from dataclasses import replace

import pytest

from opponents import load_training_catalog
from opponents.synthesis import synthesize_opponent
from phase6 import (
    COMPONENT_ROLES,
    COVERAGE_CONTRACT_SCHEMA_VERSION,
    PREREGISTRATION_SCHEMA_VERSION,
    SELECTION_CONTRACT_SCHEMA_VERSION,
    SEMANTIC_FIXTURE_SCHEMA_VERSION,
    SEMANTIC_SOURCE_SCHEMA_VERSION,
    SERIES_REFERENCE_SCHEMA_VERSION,
    ComponentCoverageResult,
    CoverageEvaluation,
    ObservationNodeSpec,
    ObservationRegistry,
    PolicySlice,
    TrainingExactEvInput,
    TrainingSessionKey,
    TrainingTerminalInput,
    ValidatedPhase6ContractBundle,
    artifact_ref,
    build_production_calibration_inputs,
    build_production_observation_registry,
    build_r008_coverage_contract,
    canonical_json_bytes,
    evaluate_exact_ev,
    primary_candidate_grid,
    sampling_contract_payload,
    sampling_contract_sha256,
    selection_metric_contract_payload,
    sha256_bytes,
    validate_production_observation_registry,
    verify_production_calibration_inputs,
)
from phase6.p6_7 import REPETITION_SEEDS
from phase6.training_runner import HORIZONS
from poker_solver.game import Game


def _ref(artifact_type, schema_version, label):
    return artifact_ref(
        artifact_type=artifact_type,
        schema_version=schema_version,
        path=f"contract/{label}.json",
        payload={"label": label},
    )


def _contract_bundle():
    source_refs = {
        role: _ref("phase6_semantic_source", SEMANTIC_SOURCE_SCHEMA_VERSION, role)
        for role in COMPONENT_ROLES
    }
    fixture_refs = {
        fixture_id: _ref(
            "phase6_semantic_fixture",
            SEMANTIC_FIXTURE_SCHEMA_VERSION,
            fixture_id,
        )
        for fixture_id in (
            "r008-ground-truth-positive-v1",
            "r008-ground-truth-negative-action-v1",
        )
    }
    coverage = build_r008_coverage_contract(source_refs, fixture_refs)
    coverage_evaluation = CoverageEvaluation(
        tuple(
            ComponentCoverageResult(role, source_refs[role]["sha256"], True, ())
            for role in COMPONENT_ROLES
        ),
        True,
        True,
    )
    preregistration = _ref(
        "phase6_evaluation_preregistration",
        PREREGISTRATION_SCHEMA_VERSION,
        "preregistration",
    )
    coverage_ref = _ref(
        "coverage_semantics_contract",
        COVERAGE_CONTRACT_SCHEMA_VERSION,
        "coverage",
    )
    selection_ref = _ref(
        "selection_metric_contract",
        SELECTION_CONTRACT_SCHEMA_VERSION,
        "selection",
    )
    series_ref = _ref(
        "phase6_evaluation_series_reference",
        SERIES_REFERENCE_SCHEMA_VERSION,
        "series",
    )
    selection = selection_metric_contract_payload()
    return ValidatedPhase6ContractBundle(
        root_manifest={
            "preregistration": preregistration,
            "coverage_semantics_contract": coverage_ref,
            "selection_metric_contract": selection_ref,
            "series_reference": series_ref,
        },
        preregistration={},
        coverage_contract=coverage,
        selection_contract=selection,
        series_reference={},
        validation_batch_reference={},
        selection_report_reference={},
        coverage_evaluation=coverage_evaluation,
    )


@pytest.fixture(scope="module")
def synthesized_opponents():
    return tuple(synthesize_opponent(config=config) for config in load_training_catalog())


@pytest.fixture(scope="module")
def production_fixture(synthesized_opponents):
    registry = build_production_observation_registry(synthesized_opponents[0].game)
    contract = sampling_contract_payload(
        observation_registry_version=registry.registry_version,
        observation_registry_sha256=registry.sha256,
    )
    candidate = primary_candidate_grid(sampling_contract_sha256=sampling_contract_sha256(contract))[
        0
    ]
    ordered = tuple(sorted(synthesized_opponents, key=lambda item: item.config.opponent_id))
    terminal_inputs = []
    exact_inputs = []
    cells = {item.config.opponent_id: _exact_cell(item) for item in ordered}
    for item in ordered:
        for horizon in HORIZONS:
            for repetition_id, _seed in REPETITION_SEEDS:
                key = TrainingSessionKey(
                    candidate.candidate_id,
                    item.config.opponent_id,
                    horizon,
                    repetition_id,
                )
                terminal_inputs.append(TrainingTerminalInput(key, {"CHECK": horizon, "BET": 0}))
                exact_inputs.append(TrainingExactEvInput(key, cells[item.config.opponent_id]))
    return {
        "bundle": _contract_bundle(),
        "registry": registry,
        "contract": contract,
        "candidate": candidate,
        "opponents": ordered,
        "terminal": tuple(terminal_inputs),
        "exact": tuple(exact_inputs),
    }


def _exact_cell(opponent):
    game = opponent.game
    hero_player = 0 if opponent.config.opponent_position == "IP" else 1
    opponent_player = 1 - hero_player
    opponent_policy = {
        infoset: opponent.strategy[infoset] for infoset in game.infosets_of(opponent_player)
    }
    base_policy = {
        infoset: opponent.equilibrium_strategy[infoset] for infoset in game.infosets_of(hero_player)
    }
    return evaluate_exact_ev(
        game,
        hero_player=hero_player,
        opponent_policy=PolicySlice(game.name, opponent.config.opponent_id, opponent_policy),
        base_hero_policy=PolicySlice(game.name, opponent.config.opponent_id, base_policy),
        final_hero_policy=PolicySlice(game.name, opponent.config.opponent_id, {}),
    )


def _build(values):
    return build_production_calibration_inputs(
        contract_bundle=values["bundle"],
        candidate=values["candidate"],
        sampling_contract=values["contract"],
        observation_registry=values["registry"],
        opponents=values["opponents"],
        terminal_inputs=values["terminal"],
        exact_ev_inputs=values["exact"],
    )


def _mutated_opponent_profile(opponent, profile):
    hero_player = 0 if opponent.config.opponent_position == "IP" else 1
    infoset = opponent.game.infosets_of(1 - hero_player)[0]
    actions = opponent.game.actions_of(infoset)
    selected = actions[-1] if profile[infoset][actions[-1]] != 1.0 else actions[0]
    mutated = copy.deepcopy(profile)
    mutated[infoset] = {action: 1.0 if action == selected else 0.0 for action in actions}
    assert mutated != profile
    return mutated


def test_observation_registry_is_complete_deterministic_and_game_bound(
    synthesized_opponents,
):
    first = build_production_observation_registry(synthesized_opponents[0].game)
    rebuilt = build_production_observation_registry(synthesized_opponents[0].game)
    assert first == rebuilt
    assert first.registry_version == "phase6-river-observation-registry-v1"
    assert first.nodes
    assert all(
        node.outcome_registry_version == "phase6-river-chance-outcomes-v1" for node in first.nodes
    )
    assert all(
        [outcome for outcome, _weight in node.ordered_outcomes]
        == [branch[2] for branch in synthesized_opponents[0].game.root.branches]
        for node in first.nodes
    )
    for opponent in synthesized_opponents:
        validate_production_observation_registry(opponent.game, first)

    first_node = first.nodes[0]
    tampered_node = ObservationNodeSpec(
        first_node.node_id,
        first_node.outcome_registry_version,
        tuple(reversed(first_node.ordered_outcomes)),
    )
    tampered = ObservationRegistry(first.registry_version, (tampered_node, *first.nodes[1:]))
    with pytest.raises(ValueError, match="does not match the frozen game"):
        validate_production_observation_registry(synthesized_opponents[0].game, tampered)


def test_production_builder_emits_complete_canonical_inputs(production_fixture):
    inputs = _build(production_fixture)
    evaluation = verify_production_calibration_inputs(production_fixture["bundle"], inputs)

    assert inputs.builder_version == "p6-7-production-training-inputs-v1"
    assert inputs.series_descriptor["config"]["split"] == "training"
    assert inputs.series_descriptor["config"]["horizon_set"] == [50, 200, 1000]
    assert len(inputs.series_descriptor["opponents"]) == 9
    assert len(inputs.exact_ev_observations) == 9 * 3 * 30
    terminal = json.loads(inputs.terminal_snapshots.raw)
    truth = json.loads(inputs.ground_truth.raw)
    assert len(terminal["records"]) == len(truth["records"]) == 9 * 3 * 30
    assert inputs.terminal_snapshots.raw == canonical_json_bytes(terminal)
    assert inputs.ground_truth.raw == canonical_json_bytes(truth)
    assert sha256_bytes(inputs.terminal_snapshots.raw) == inputs.terminal_snapshots.expected_sha256
    assert sha256_bytes(inputs.ground_truth.raw) == inputs.ground_truth.expected_sha256
    assert len(evaluation.series) == 1


def test_production_builder_is_byte_deterministic(production_fixture):
    first = _build(production_fixture)
    second = _build(production_fixture)
    assert first.series_descriptor == second.series_descriptor
    assert first.terminal_snapshots == second.terminal_snapshots
    assert first.ground_truth == second.ground_truth
    assert first.exact_ev_observations == second.exact_ev_observations


def test_production_builder_rejects_registry_session_and_exact_ev_substitution(
    production_fixture,
):
    values = dict(production_fixture)
    contract = copy.deepcopy(values["contract"])
    contract["observation_registry_sha256"] = "0" * 64
    values["contract"] = contract
    with pytest.raises(ValueError, match="does not join"):
        _build(values)

    values = dict(production_fixture)
    values["terminal"] = values["terminal"][:-1]
    with pytest.raises(ValueError, match="do not exactly match the approved session order"):
        _build(values)

    values = dict(production_fixture)
    wrong = values["exact"][0]
    other = values["exact"][90]
    values["exact"] = (
        replace(wrong, cell=other.cell),
        *values["exact"][1:],
    )
    with pytest.raises(ValueError, match="opponent identity does not join"):
        _build(values)


def test_production_builder_rejects_noncanonical_primary_candidates(production_fixture):
    candidate = production_fixture["candidate"]
    other_confidence = "0.95" if candidate.detector_confidence == "0.9" else "0.9"
    mutations = (
        replace(candidate, sample_floor=11),
        replace(candidate, candidate_id=f"primary_bb_v2__{'0' * 64}"),
        replace(candidate, epsilon="0"),
        replace(candidate, provider_confidence=other_confidence),
    )
    for mutated in mutations:
        values = dict(production_fixture)
        values["candidate"] = mutated
        with pytest.raises(ValueError, match="canonical approved primary grid member"):
            _build(values)


def test_production_builder_rejects_noncanonical_synthesis_and_game(production_fixture):
    opponents = production_fixture["opponents"]
    gto = next(item for item in opponents if not item.config.leak_vector)
    non_gto = next(item for item in opponents if item.config.leak_vector)

    gto_profile = _mutated_opponent_profile(gto, gto.strategy)
    gto_mutation = replace(
        gto,
        equilibrium_strategy=gto_profile,
        strategy=gto_profile,
    )
    non_gto_mutation = replace(
        non_gto,
        strategy=_mutated_opponent_profile(non_gto, non_gto.strategy),
    )
    game_mutation = replace(non_gto, game=Game(non_gto.game.root, name="river-mutated"))

    for original, mutated in (
        (gto, gto_mutation),
        (non_gto, non_gto_mutation),
        (non_gto, game_mutation),
    ):
        values = dict(production_fixture)
        values["opponents"] = tuple(
            mutated if item.config.opponent_id == original.config.opponent_id else item
            for item in opponents
        )
        with pytest.raises(ValueError, match="synthesized opponent"):
            _build(values)


def test_production_builder_rejects_exact_ev_opponent_profile_substitution(
    production_fixture,
):
    values = dict(production_fixture)
    source = values["exact"][0]
    opponent = next(
        item for item in values["opponents"] if item.config.opponent_id == source.key.opponent_id
    )
    cell = source.cell
    profiles = replace(
        cell.profiles,
        base=_mutated_opponent_profile(opponent, cell.profiles.base),
        final=_mutated_opponent_profile(opponent, cell.profiles.final),
        oracle_br=_mutated_opponent_profile(opponent, cell.profiles.oracle_br),
    )
    values["exact"] = (
        replace(source, cell=replace(cell, profiles=profiles)),
        *values["exact"][1:],
    )
    with pytest.raises(ValueError, match="opponent profile does not join frozen strategy"):
        _build(values)


def test_verifier_rejects_ground_truth_self_rewrite(production_fixture):
    inputs = _build(production_fixture)
    payload = json.loads(inputs.ground_truth.raw)
    payload["records"][0]["true_rate"] = "1"
    raw = canonical_json_bytes(payload)
    forged = replace(
        inputs,
        ground_truth=replace(
            inputs.ground_truth,
            raw=raw,
            expected_sha256=sha256_bytes(raw),
        ),
    )
    with pytest.raises(ValueError, match="ground truth"):
        verify_production_calibration_inputs(production_fixture["bundle"], forged)


def test_verifier_rejects_complete_opponent_ground_truth_rewrite(production_fixture):
    inputs = _build(production_fixture)
    opponent_id = next(
        item.config.opponent_id for item in inputs.opponents if item.config.leak_vector
    )
    payload = json.loads(inputs.ground_truth.raw)
    changed = 0
    for record in payload["records"]:
        if record["opponent_id"] == opponent_id:
            record["true_rate"] = "0.123"
            record["reach_weight"] = "0.456"
            changed += 1
    assert changed == 3 * 30
    raw = canonical_json_bytes(payload)
    forged = replace(
        inputs,
        ground_truth=replace(inputs.ground_truth, raw=raw, expected_sha256=sha256_bytes(raw)),
    )
    with pytest.raises(ValueError, match="ground truth does not reconstruct"):
        verify_production_calibration_inputs(production_fixture["bundle"], forged)


def test_verifier_rejects_posterior_confidence_and_gate_rewrite(production_fixture):
    inputs = _build(production_fixture)
    payload = json.loads(inputs.terminal_snapshots.raw)
    record = payload["records"][0]
    record["posterior_confidence"] = "0.95"
    record["candidate_eligibility"]["confidence_gate"] = True
    record["candidate_eligibility"]["emitted"] = all(
        value for key, value in record["candidate_eligibility"].items() if key != "emitted"
    )
    raw = canonical_json_bytes(payload)
    forged = replace(
        inputs,
        terminal_snapshots=replace(
            inputs.terminal_snapshots,
            raw=raw,
            expected_sha256=sha256_bytes(raw),
        ),
    )
    with pytest.raises(ValueError, match="terminal snapshots do not reconstruct"):
        verify_production_calibration_inputs(production_fixture["bundle"], forged)
