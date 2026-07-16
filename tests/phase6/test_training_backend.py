"""Unit and in-memory fixture regression for the concrete P6-7 backend."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from decimal import Decimal

import pytest

import phase6.training_backend as training_backend
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
    ProductionTrainingExecutionBackend,
    TrainingCandidateRequest,
    TrainingSessionKey,
    TrainingSessionRequest,
    ValidatedPhase6ContractBundle,
    artifact_ref,
    build_production_observation_registry,
    build_r008_coverage_contract,
    canonical_json_bytes,
    derive_stream_root,
    primary_candidate_grid,
    sampling_contract_payload,
    sampling_contract_sha256,
    selection_metric_contract_payload,
)
from phase6.p6_7 import REPETITION_SEEDS, STREAM_NAMES
from phase6.training_runner import HORIZONS


def _ref(artifact_type: str, schema_version: str, label: str):
    return artifact_ref(
        artifact_type=artifact_type,
        schema_version=schema_version,
        path=f"contract/{label}.json",
        payload={"label": label},
    )


def _contract_bundle() -> ValidatedPhase6ContractBundle:
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
    return ValidatedPhase6ContractBundle(
        root_manifest={
            "preregistration": _ref(
                "phase6_evaluation_preregistration",
                PREREGISTRATION_SCHEMA_VERSION,
                "preregistration",
            ),
            "coverage_semantics_contract": _ref(
                "coverage_semantics_contract",
                COVERAGE_CONTRACT_SCHEMA_VERSION,
                "coverage",
            ),
            "selection_metric_contract": _ref(
                "selection_metric_contract",
                SELECTION_CONTRACT_SCHEMA_VERSION,
                "selection",
            ),
            "series_reference": _ref(
                "phase6_evaluation_series_reference",
                SERIES_REFERENCE_SCHEMA_VERSION,
                "series",
            ),
        },
        preregistration={},
        coverage_contract=coverage,
        selection_contract=selection_metric_contract_payload(),
        series_reference={},
        validation_batch_reference={},
        selection_report_reference={},
        coverage_evaluation=coverage_evaluation,
    )


@pytest.fixture(scope="module")
def backend_fixture():
    configs = tuple(sorted(load_training_catalog(), key=lambda item: item.opponent_id))
    first = synthesize_opponent(config=configs[0])
    registry = build_production_observation_registry(first.game)
    sampling_contract = sampling_contract_payload(
        observation_registry_version=registry.registry_version,
        observation_registry_sha256=registry.sha256,
    )
    candidates = primary_candidate_grid(
        sampling_contract_sha256=sampling_contract_sha256(sampling_contract)
    )
    backend = ProductionTrainingExecutionBackend(
        contract_bundle=_contract_bundle(),
        sampling_contract=sampling_contract,
    )
    return backend, sampling_contract, candidates, configs


def _request(candidate, opponent, horizon=50, repetition_id="r001"):
    key = TrainingSessionKey(
        candidate.candidate_id,
        opponent.opponent_id,
        horizon,
        repetition_id,
    )
    return TrainingSessionRequest(
        key=key,
        candidate=candidate,
        opponent=opponent,
        stream_roots=tuple(
            derive_stream_root(
                split="training",
                opponent_id=opponent.opponent_id,
                horizon=horizon,
                repetition_id=repetition_id,
                stream_name=stream_name,
            )
            for stream_name in STREAM_NAMES
        ),
    )


@pytest.fixture(scope="module")
def one_session(backend_fixture):
    backend, _contract, candidates, configs = backend_fixture
    request = _request(candidates[0], configs[0])
    return request, backend.run_sessions((request,))[0]


@pytest.fixture(scope="module")
def complete_candidate_sessions(backend_fixture):
    backend, _contract, candidates, configs = backend_fixture
    candidate = candidates[0]
    requests = tuple(
        _request(candidate, opponent, horizon, repetition_id)
        for opponent in configs
        for horizon in HORIZONS
        for repetition_id, _seed in REPETITION_SEEDS
    )
    return candidate, tuple(backend.run_sessions(requests))


def test_concrete_backend_runs_one_canonical_session_deterministically(
    backend_fixture,
    one_session,
):
    backend, _contract, _candidates, _configs = backend_fixture
    request, result = one_session
    rebuilt = backend.run_sessions((request,))[0]

    assert backend.backend_id == "phase6-river-training"
    assert backend.backend_version == "p6-7-concrete-training-backend-v1"
    assert result == rebuilt
    assert result.split == "training"
    assert result.key == request.key
    assert result.stream_roots == request.stream_roots
    assert result.terminal_candidate_snapshot["opportunity_count"] == request.key.horizon
    assert sum(result.terminal_candidate_snapshot["action_counts"].values()) == 50
    assert (
        result.hero_policy_snapshot["source_terminal_sha256"]
        == hashlib.sha256(canonical_json_bytes(result.terminal_candidate_snapshot)).hexdigest()
    )
    assert (
        result.exact_ev_cell["source_hero_policy_sha256"]
        == hashlib.sha256(canonical_json_bytes(result.hero_policy_snapshot)).hexdigest()
    )
    canonical_json_bytes(result.exact_ev_cell)


def test_concrete_backend_rejects_noncanonical_request_provenance(backend_fixture):
    backend, _contract, candidates, configs = backend_fixture
    request = _request(candidates[0], configs[0])

    with pytest.raises(ValueError, match="canonical primary candidate"):
        backend.run_sessions((replace(request, candidate=replace(candidates[0], epsilon="0")),))

    with pytest.raises(ValueError, match="approved Training catalog"):
        backend.run_sessions((replace(request, opponent=configs[1]),))

    validation_roots = tuple(
        derive_stream_root(
            split="validation",
            opponent_id=request.key.opponent_id,
            horizon=request.key.horizon,
            repetition_id=request.key.repetition_id,
            stream_name=stream_name,
        )
        for stream_name in STREAM_NAMES
    )
    with pytest.raises(ValueError, match="approved Training identity"):
        backend.run_sessions((replace(request, stream_roots=validation_roots),))

    second = _request(candidates[0], configs[0], repetition_id="r002")
    with pytest.raises(ValueError, match="canonical order"):
        backend.run_sessions((second, request))


def test_concrete_backend_evaluates_complete_candidate_via_production_contracts(
    backend_fixture,
    complete_candidate_sessions,
    monkeypatch,
):
    backend, _contract, _candidates, _configs = backend_fixture
    candidate, sessions = complete_candidate_sessions
    request = TrainingCandidateRequest(
        candidate=candidate,
        session_results=sessions,
        session_join_sha256=hashlib.sha256(b"fixture-session-join").hexdigest(),
    )
    original_decimal_wire = training_backend._decimal_wire
    converted_decimals = []

    def checked_decimal_wire(value):
        wire_value = original_decimal_wire(value)
        assert Decimal(wire_value) == value
        converted_decimals.append((value, wire_value))
        return wire_value

    monkeypatch.setattr(training_backend, "_decimal_wire", checked_decimal_wire)
    result = backend.evaluate_candidates((request,))[0]

    assert converted_decimals
    assert result.split == "training"
    assert result.candidate_id == candidate.candidate_id
    assert result.session_join_sha256 == request.session_join_sha256
    assert result.calibration_cell["schema_version"] == ("phase6-training-calibration-result-v1")
    assert result.calibration_cell["evaluator_version"] == "all-candidate-calibration-v1"
    assert len(result.calibration_cell["cells"]) == 9 * 3 * 30
    assert result.aggregate_metrics["schema_version"] == ("phase6-training-aggregate-result-v1")
    assert len(result.aggregate_metrics["atomic_groups"]) == 9 * 3
    assert len(result.aggregate_metrics["exact_ev_sha256s"]) == 9 * 3 * 30
    canonical_json_bytes(result.calibration_cell)
    canonical_json_bytes(result.aggregate_metrics)


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (Decimal("10"), "10"),
        (Decimal("20"), "20"),
        (Decimal("-10"), "-10"),
        (Decimal("10.0"), "10"),
        (Decimal("1.2300"), "1.23"),
        (Decimal("0.0012300"), "0.00123"),
    ),
)
def test_decimal_wire_preserves_integer_zeros_and_numeric_value(value, expected):
    wire_value = training_backend._decimal_wire(value)

    assert wire_value == expected
    assert Decimal(wire_value) == value


def test_concrete_backend_rejects_incomplete_and_tampered_candidate_sessions(
    backend_fixture,
    complete_candidate_sessions,
):
    backend, _contract, _candidates, _configs = backend_fixture
    candidate, sessions = complete_candidate_sessions
    join = hashlib.sha256(b"fixture-session-join").hexdigest()

    with pytest.raises(ValueError, match="approved session order"):
        backend.evaluate_candidates((TrainingCandidateRequest(candidate, sessions[:-1], join),))

    tampered_payload = copy.deepcopy(sessions[0].terminal_candidate_snapshot)
    tampered_payload["action_counts"]["BET"] += 1
    tampered = replace(sessions[0], terminal_candidate_snapshot=tampered_payload)
    with pytest.raises(ValueError, match="does not reconstruct"):
        backend.evaluate_candidates(
            (TrainingCandidateRequest(candidate, (tampered, *sessions[1:]), join),)
        )

    with pytest.raises(ValueError, match="lowercase SHA-256"):
        backend.evaluate_candidates((TrainingCandidateRequest(candidate, sessions, "A" * 64),))
