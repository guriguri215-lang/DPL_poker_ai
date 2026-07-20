"""P6-9A Validation-only execution, artifact, and selection boundaries.

The module accepts only a verified P6-8A Validation plan.  It deliberately has
no production CLI, freeze, attempt reservation, or Training/Test compatibility
path.  A backend supplies results from the approved P6-5 and P6-6 evaluators;
the adapter binds those results to the P6-7 sampling and ranking contracts.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass
from decimal import ROUND_HALF_EVEN, Decimal, localcontext
from pathlib import Path
from typing import Protocol

from opponents import load_validation_catalog
from opponents.ground_truth import extract_independent_action_rates
from opponents.model import OpponentModelConfig
from opponents.synthesis import SynthesizedOpponent, synthesize_opponent
from poker_ai.exploit import nodelock_config_from_leaks
from poker_ai.leak import (
    ActionBaselineTable,
    ActionLeakRule,
    LeakDetector,
    LeakDetectorConfig,
    beta_binomial_upper_tail,
)
from poker_ai.mixer import safety_mix
from poker_ai.observation import ActionStats
from poker_solver.best_response import best_response_strategy
from poker_solver.nodelock import apply_node_locks, river_infoset_reach_weights
from poker_solver.strategy import StrategyProfile

from .calibration import (
    BOUNDARY_ABS_TOLERANCE_WIRE,
    CALIBRATION_EVALUATOR_VERSION,
    DECIMAL_PRECISION,
    DECIMAL_ROUNDING,
    EXACT_EV_INPUT_VERSION,
    GROUND_TRUTH_SCHEMA_VERSION,
    TERMINAL_SNAPSHOT_SCHEMA_VERSION,
    CanonicalCalibrationArtifact,
    ConfidenceValueReplacement,
    ExactEvObservation,
    SeriesCalibrationResult,
    calibration_series_id,
    evaluate_all_candidate_calibration,
    exact_ev_observation_sha256,
    rebind_series_calibration,
    revalue_series_confidence,
)
from .contracts import (
    ValidatedPhase6ContractBundle,
    canonical_json_bytes,
    load_phase6_contract_bundle,
    sha256_bytes,
)
from .exact_ev import ExactEvCell, PolicySlice, evaluate_exact_ev
from .p6_7 import (
    EXECUTION_SAMPLER_VERSION,
    PRIMARY_SELECTION_KEYS,
    STREAM_NAMES,
    CandidateSelectionMetrics,
    ExpectedGtoSelectionGroup,
    GtoSelectionGroup,
    PrimaryCandidate,
    StreamRoot,
    derive_stream_root,
    primary_candidate_grid,
    rank_primary_candidates,
)
from .production_inputs import GROUND_TRUTH_EXTRACTOR_VERSION
from .training_runner import HORIZONS
from .validation_runner import (
    ValidationBatchPlan,
    ValidationSessionKey,
    verify_validation_batch_plan,
)

PolicyValidator = Callable[
    [PrimaryCandidate, object, object, SynthesizedOpponent, Mapping[str, object]],
    tuple[StrategyProfile, StrategyProfile],
]

VALIDATION_EXECUTION_ADAPTER_VERSION = "p6-9a-validation-execution-adapter-v1"
VALIDATION_EXECUTION_RECORD_SCHEMA_VERSION = "phase6-validation-execution-record-v1"
VALIDATION_EXECUTION_ARTIFACT_SCHEMA_VERSION = "phase6-validation-execution-artifact-v1"
VALIDATION_ROOT_MANIFEST_SCHEMA_VERSION = "phase6-validation-result-root-v1"
VALIDATION_TERMINAL_RESULT_SCHEMA_VERSION = "phase6-validation-terminal-result-v1"
VALIDATION_HERO_POLICY_RESULT_SCHEMA_VERSION = "phase6-validation-hero-policy-result-v1"
VALIDATION_EXACT_EV_RESULT_SCHEMA_VERSION = "phase6-validation-exact-ev-result-v1"
VALIDATION_CALIBRATION_RESULT_SCHEMA_VERSION = "phase6-validation-calibration-result-v1"
VALIDATION_AGGREGATE_RESULT_SCHEMA_VERSION = "phase6-validation-aggregate-result-v1"
PRIMARY_SELECTION_REPORT_SCHEMA_VERSION = "phase6-primary-selection-report-v1"
SELECTED_CONFIG_LOCK_SCHEMA_VERSION = "phase6-selected-config-lock-v1"
VALIDATION_WRITER_VERSION = "p6-9a-validation-writer-v1"
VALIDATION_ARTIFACT_BASE_DIRECTORY = "validation-artifacts"
VALIDATION_PHYSICAL_DIRECTORY = "validation"

_ARTIFACT_TYPES = (
    "validation_terminal_candidate_snapshots",
    "validation_hero_policy_snapshots",
    "validation_exact_ev_cells",
    "validation_calibration_cells",
    "validation_aggregate_metrics",
)
_SESSION_ARTIFACT_TYPE_ORDER = _ARTIFACT_TYPES[:3]
_CANDIDATE_ARTIFACT_TYPE_ORDER = _ARTIFACT_TYPES[3:]
_SESSION_ARTIFACT_TYPES = frozenset(_SESSION_ARTIFACT_TYPE_ORDER)
_CANDIDATE_ARTIFACT_TYPES = frozenset(_CANDIDATE_ARTIFACT_TYPE_ORDER)
_RESULT_NAMES = (
    "terminal_candidate_snapshot",
    "hero_policy_snapshot",
    "exact_ev_cell",
)
_SHA256 = frozenset("0123456789abcdef")
_BACKEND_ID = re.compile(r"phase6-validation-[a-z0-9]+(?:[._-][a-z0-9]+)*")
_BACKEND_VERSION = re.compile(
    r"p6-[0-9]+[a-z]?(?:-[a-z0-9]+)*-validation(?:-[a-z0-9]+)*-v[1-9][0-9]*"
)
_FOREIGN_NAMESPACE = re.compile(
    r"^(?:training|test)[-_](?:output|outputs|result|results|artifact|artifacts|run|runs|data)(?:[-_].*)?$"
)
_R008_REASON_ID = "LEAK_R008"
_R008_SITUATION_KEY = "river_vs_check"
_R008_LEAK_TYPE = "bet_too_often_when_checked_to"
_R008_DIRECTION = "decrease_bet_frequency_when_checked_to"
_TAU_WIRE = "0.25"
_EXPLOIT_PROVIDER_VERSION = "nodelock-provider-r008-v2"
_CARDINALITY = {
    "candidate_count": 16,
    "session_count": 12960,
    "session_record_count_per_type": 12960,
    "candidate_record_count_per_type": 16,
    "ranked_candidate_count": 16,
    "selected_config_count": 1,
}


@dataclass(frozen=True, slots=True)
class ValidationArtifactRecord:
    candidate_id: str
    payload_sha256: str
    payload: object
    opponent_id: str | None = None
    horizon: int | None = None
    repetition_id: str | None = None

    def session_key(self) -> ValidationSessionKey:
        if self.opponent_id is None or self.horizon is None or self.repetition_id is None:
            raise ValueError("Validation session record is missing its complete key")
        return ValidationSessionKey(
            self.candidate_id, self.opponent_id, self.horizon, self.repetition_id
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "horizon": self.horizon,
            "opponent_id": self.opponent_id,
            "payload": self.payload,
            "payload_sha256": self.payload_sha256,
            "repetition_id": self.repetition_id,
        }


@dataclass(frozen=True, slots=True)
class ValidationSessionRequest:
    key: ValidationSessionKey
    candidate: PrimaryCandidate
    opponent: OpponentModelConfig
    stream_roots: tuple[StreamRoot, ...]


@dataclass(frozen=True, slots=True)
class ValidationSessionResult:
    split: str
    key: ValidationSessionKey
    stream_roots: tuple[StreamRoot, ...]
    terminal_candidate_snapshot: object
    hero_policy_snapshot: object
    exact_ev_cell: object


@dataclass(frozen=True, slots=True)
class ValidationCandidateRequest:
    candidate: PrimaryCandidate
    session_results: tuple[ValidationSessionResult, ...]
    session_join_sha256: str


@dataclass(frozen=True, slots=True)
class ValidationCandidateResult:
    split: str
    candidate_id: str
    session_join_sha256: str
    calibration_cell: object
    aggregate_metrics: object


class ValidationExecutionBackend(Protocol):
    """Validation-only bridge to approved session and evaluator execution."""

    backend_id: str
    backend_version: str

    def run_sessions(
        self, requests: Sequence[ValidationSessionRequest]
    ) -> Sequence[ValidationSessionResult]: ...

    def evaluate_candidates(
        self, requests: Sequence[ValidationCandidateRequest]
    ) -> Sequence[ValidationCandidateResult]: ...


@dataclass(frozen=True, slots=True)
class ValidationArtifactBundle:
    root: Path
    root_manifest_path: Path
    root_manifest_sha256: str


def run_validation_execution_adapter(
    plan: ValidationBatchPlan,
    backend: ValidationExecutionBackend,
    *,
    repo_root: Path | str,
) -> dict[str, tuple[ValidationArtifactRecord, ...]]:
    """Run the complete approved Validation product and bind every result."""
    verify_validation_batch_plan(plan, repo_root=repo_root)
    backend_identity = _backend_identity(backend)
    evaluation_context = _evaluation_context(plan, Path(repo_root).resolve())
    candidates = {item.candidate_id: item for item in plan.candidates}
    opponents = {
        opponent_id: item.config for opponent_id, item in evaluation_context.opponents.items()
    }
    if set(opponents) != {
        item["opponent_id"] for item in plan.manifest["validation_catalog_index"]["opponents"]
    }:
        raise ValueError("Validation backend catalog differs from the verified plan")
    requests = tuple(
        ValidationSessionRequest(
            key,
            candidates[key.candidate_id],
            opponents[key.opponent_id],
            _stream_roots(key),
        )
        for key in plan.sessions
    )
    results = tuple(backend.run_sessions(requests))
    if len(results) != len(requests) or [
        item.key for item in results if isinstance(item, ValidationSessionResult)
    ] != [item.key for item in requests]:
        raise ValueError("Validation session results are missing, duplicate, or out of order")

    session_records = {name: [] for name in _SESSION_ARTIFACT_TYPE_ORDER}
    normalized: list[ValidationSessionResult] = []
    for request, result in zip(requests, results, strict=True):
        if not isinstance(result, ValidationSessionResult):
            raise TypeError("Validation backend must return ValidationSessionResult values")
        if result.split != "validation":
            raise ValueError("Validation backend returned a non-Validation split")
        if result.key != request.key or result.stream_roots != request.stream_roots:
            raise ValueError("Validation session provenance does not match its request")
        values = tuple(_canonical_result(getattr(result, field)) for field in _RESULT_NAMES)
        _validate_session_result_envelopes(request.key, values)
        _validate_reconstructed_hero_policy(
            request.candidate,
            values[0],
            values[1],
            evaluation_context.opponents[request.key.opponent_id],
            evaluation_context.dimension,
        )
        normalized.append(
            ValidationSessionResult("validation", result.key, result.stream_roots, *values)
        )
        for artifact_type, value in zip(_SESSION_ARTIFACT_TYPE_ORDER, values, strict=True):
            payload = _session_payload(plan, request, artifact_type, value, backend_identity)
            session_records[artifact_type].append(_session_record(request.key, payload))

    by_candidate = {item.candidate_id: [] for item in plan.candidates}
    for result in normalized:
        by_candidate[result.key.candidate_id].append(result)
    candidate_requests = tuple(
        ValidationCandidateRequest(
            candidate,
            tuple(by_candidate[candidate.candidate_id]),
            _session_join_sha256(candidate.candidate_id, session_records),
        )
        for candidate in plan.candidates
    )
    candidate_results = tuple(backend.evaluate_candidates(candidate_requests))
    if len(candidate_results) != len(candidate_requests) or [
        item.candidate_id
        for item in candidate_results
        if isinstance(item, ValidationCandidateResult)
    ] != [item.candidate.candidate_id for item in candidate_requests]:
        raise ValueError("Validation candidate results are missing, duplicate, or out of order")

    candidate_records = {name: [] for name in _CANDIDATE_ARTIFACT_TYPE_ORDER}
    for request, result in zip(candidate_requests, candidate_results, strict=True):
        if not isinstance(result, ValidationCandidateResult):
            raise TypeError("Validation backend must return ValidationCandidateResult values")
        if result.split != "validation":
            raise ValueError("Validation candidate result has a non-Validation split")
        if (
            result.candidate_id != request.candidate.candidate_id
            or result.session_join_sha256 != request.session_join_sha256
        ):
            raise ValueError("Validation candidate provenance does not match its request")
        calibration = _canonical_result(result.calibration_cell)
        aggregate = _canonical_result(result.aggregate_metrics)
        _validate_candidate_result_envelopes(request, calibration, aggregate)
        for artifact_type, value in (
            ("validation_calibration_cells", calibration),
            ("validation_aggregate_metrics", aggregate),
        ):
            payload = _candidate_payload(plan, request, artifact_type, value, backend_identity)
            candidate_records[artifact_type].append(
                _candidate_record(request.candidate.candidate_id, payload)
            )

    records = {
        name: tuple(session_records.get(name, candidate_records.get(name, ())))
        for name in _ARTIFACT_TYPES
    }
    verify_validation_execution_records(plan, records, repo_root=repo_root)
    return records


def run_single_validation_candidate_execution(
    plan: ValidationBatchPlan,
    candidate: PrimaryCandidate,
    backend: ValidationExecutionBackend,
    *,
    repo_root: Path | str,
    policy_validator: PolicyValidator | None = None,
) -> dict[str, tuple[ValidationArtifactRecord, ...]]:
    """Run one separately identified Validation-series candidate.

    This additive boundary is intentionally outside the P6-9 complete-grid
    adapter.  It preserves the verified P6-9 catalog, session coordinates,
    sampling roots, evaluator, and record envelopes while keeping the supplied
    candidate in a distinct series.  The P6-9 adapter and verifier continue to
    require their original 16-candidate product.
    """
    verify_validation_batch_plan(plan, repo_root=repo_root)
    validate_policy = policy_validator or _validate_reconstructed_hero_policy
    if not isinstance(candidate, PrimaryCandidate):
        raise TypeError("single Validation execution requires a PrimaryCandidate")
    if candidate.candidate_id in {item.candidate_id for item in plan.candidates}:
        raise ValueError("single Validation candidate must be distinct from the P6-9 grid")
    backend_identity = _backend_identity(backend)
    context = _evaluation_context(plan, Path(repo_root).resolve())
    opponents = {key: value.config for key, value in context.opponents.items()}
    keys = _single_candidate_session_keys(plan, candidate.candidate_id)
    requests = tuple(
        ValidationSessionRequest(
            key,
            candidate,
            opponents[key.opponent_id],
            _stream_roots(key),
        )
        for key in keys
    )
    results = tuple(backend.run_sessions(requests))
    if (
        len(results) != len(requests)
        or tuple(item.key for item in results if isinstance(item, ValidationSessionResult)) != keys
    ):
        raise ValueError("single Validation session results are incomplete or out of order")

    session_records: dict[str, list[ValidationArtifactRecord]] = {
        name: [] for name in _SESSION_ARTIFACT_TYPE_ORDER
    }
    normalized: list[ValidationSessionResult] = []
    for request, result in zip(requests, results, strict=True):
        if not isinstance(result, ValidationSessionResult):
            raise TypeError("Validation backend must return ValidationSessionResult values")
        if (
            result.split != "validation"
            or result.key != request.key
            or result.stream_roots != request.stream_roots
        ):
            raise ValueError("single Validation session provenance differs from its request")
        values = tuple(_canonical_result(getattr(result, field)) for field in _RESULT_NAMES)
        _validate_session_result_envelopes(request.key, values)
        validate_policy(
            candidate,
            values[0],
            values[1],
            context.opponents[request.key.opponent_id],
            context.dimension,
        )
        normalized.append(
            ValidationSessionResult("validation", result.key, result.stream_roots, *values)
        )
        for artifact_type, value in zip(_SESSION_ARTIFACT_TYPE_ORDER, values, strict=True):
            payload = _session_payload(plan, request, artifact_type, value, backend_identity)
            session_records[artifact_type].append(_session_record(request.key, payload))

    candidate_request = ValidationCandidateRequest(
        candidate,
        tuple(normalized),
        _session_join_sha256(candidate.candidate_id, session_records),
    )
    candidate_results = tuple(backend.evaluate_candidates((candidate_request,)))
    if len(candidate_results) != 1 or not isinstance(
        candidate_results[0], ValidationCandidateResult
    ):
        raise ValueError("single Validation candidate result is missing or invalid")
    candidate_result = candidate_results[0]
    if (
        candidate_result.split != "validation"
        or candidate_result.candidate_id != candidate.candidate_id
        or candidate_result.session_join_sha256 != candidate_request.session_join_sha256
    ):
        raise ValueError("single Validation candidate provenance differs from its request")
    calibration = _canonical_result(candidate_result.calibration_cell)
    aggregate = _canonical_result(candidate_result.aggregate_metrics)
    _validate_candidate_result_envelopes(candidate_request, calibration, aggregate)
    candidate_records = {
        "validation_calibration_cells": (
            _candidate_record(
                candidate.candidate_id,
                _candidate_payload(
                    plan,
                    candidate_request,
                    "validation_calibration_cells",
                    calibration,
                    backend_identity,
                ),
            ),
        ),
        "validation_aggregate_metrics": (
            _candidate_record(
                candidate.candidate_id,
                _candidate_payload(
                    plan,
                    candidate_request,
                    "validation_aggregate_metrics",
                    aggregate,
                    backend_identity,
                ),
            ),
        ),
    }
    records = {
        name: tuple(session_records.get(name, candidate_records.get(name, ())))
        for name in _ARTIFACT_TYPES
    }
    verify_single_validation_candidate_records(
        plan,
        candidate,
        records,
        repo_root=repo_root,
        policy_validator=validate_policy,
    )
    return records


def run_p6_10b_candidate_execution(
    plan: ValidationBatchPlan,
    candidate: PrimaryCandidate,
    backend: ValidationExecutionBackend,
    *,
    repo_root: Path | str,
    p6_10b_series_id: str,
    confidence_values: (
        Mapping[ValidationSessionKey, tuple[Decimal, bool]]
        | Callable[[ValidationSessionKey], tuple[Decimal, bool]]
        | None
    ) = None,
) -> dict[str, tuple[ValidationArtifactRecord, ...]]:
    """Run one P6-10B series and optionally replace only its confidence values."""
    policy_validator = getattr(backend, "validate_p6_10b_saved_policy", None)
    if not callable(policy_validator):
        raise TypeError("P6-10B backend must expose its additive policy verifier")
    records = run_single_validation_candidate_execution(
        plan,
        candidate,
        backend,
        repo_root=repo_root,
        policy_validator=policy_validator,
    )
    resolved_values = None
    if confidence_values is not None:
        resolved_values = (
            {
                key: confidence_values(key)
                for key in _single_candidate_session_keys(plan, candidate.candidate_id)
            }
            if callable(confidence_values)
            else confidence_values
        )
    request, source_series = _p6_10b_source_series(
        plan,
        candidate,
        records,
        repo_root=repo_root,
        policy_validator=policy_validator,
    )
    series = rebind_series_calibration(source_series, p6_10b_series_id)
    if resolved_values is not None:
        coordinate_values = {
            (key.opponent_id, key.horizon, key.repetition_id): value
            for key, value in resolved_values.items()
            if key.candidate_id == candidate.candidate_id
        }
        if len(coordinate_values) != len(resolved_values) or len(coordinate_values) != 810:
            raise ValueError("P6-10B confidence values must cover exactly one 810-session series")
        replacements = []
        for cell in series.cells:
            coordinate = (cell.key[1], cell.key[4], cell.key[5])
            try:
                confidence, emitted = coordinate_values[coordinate]
            except KeyError as exc:
                raise ValueError("P6-10B confidence values do not join calibration cells") from exc
            replacements.append(ConfidenceValueReplacement(cell.key, confidence, emitted))
        series = revalue_series_confidence(series, replacements)
    calibration, aggregate = _p6_10b_candidate_payloads(request, series)
    updated = dict(records)
    for artifact_type, result in (
        ("validation_calibration_cells", calibration),
        ("validation_aggregate_metrics", aggregate),
    ):
        original = records[artifact_type][0].payload
        payload = {**original, "result": result}
        updated[artifact_type] = (_candidate_record(candidate.candidate_id, payload),)
    result_records = {name: updated[name] for name in _ARTIFACT_TYPES}
    verify_p6_10b_candidate_records(
        plan,
        candidate,
        result_records,
        repo_root=repo_root,
        p6_10b_series_id=p6_10b_series_id,
        confidence_values=resolved_values,
        policy_validator=policy_validator,
    )
    return result_records


def verify_p6_10b_candidate_records(
    plan: ValidationBatchPlan,
    candidate: PrimaryCandidate,
    records_by_type: Mapping[str, Sequence[ValidationArtifactRecord]],
    *,
    repo_root: Path | str,
    p6_10b_series_id: str,
    confidence_values: Mapping[ValidationSessionKey, tuple[Decimal, bool]] | None = None,
    policy_validator: PolicyValidator | None = None,
) -> dict[str, object]:
    """Verify additive P6-10B records while preserving the P6-9 verifier."""
    if policy_validator is None:
        raise TypeError("P6-10B verification requires its additive policy verifier")
    records = {name: tuple(records_by_type[name]) for name in _ARTIFACT_TYPES}
    request, source_series = _p6_10b_source_series(
        plan,
        candidate,
        records,
        repo_root=repo_root,
        policy_validator=policy_validator,
        accept_revalued=True,
    )
    expected_series = rebind_series_calibration(source_series, p6_10b_series_id)
    if confidence_values is not None:
        coordinate_values = {
            (key.opponent_id, key.horizon, key.repetition_id): value
            for key, value in confidence_values.items()
            if key.candidate_id == candidate.candidate_id
        }
        if len(coordinate_values) != len(confidence_values) or len(coordinate_values) != 810:
            raise ValueError("P6-10B confidence verifier requires exactly 810 values")
        replacements = []
        for cell in expected_series.cells:
            coordinate = (cell.key[1], cell.key[4], cell.key[5])
            if coordinate not in coordinate_values:
                raise ValueError("P6-10B confidence verifier has an incomplete coordinate set")
            confidence, emitted = coordinate_values[coordinate]
            replacements.append(ConfidenceValueReplacement(cell.key, confidence, emitted))
        expected_series = revalue_series_confidence(expected_series, replacements)
    expected_calibration, expected_aggregate = _p6_10b_candidate_payloads(request, expected_series)
    calibration = records["validation_calibration_cells"][0].payload["result"]
    aggregate = records["validation_aggregate_metrics"][0].payload["result"]
    if calibration != expected_calibration or aggregate != expected_aggregate:
        raise ValueError("P6-10B confidence metrics do not independently reconstruct")

    normal_calibration, normal_aggregate, _ = _candidate_products(
        plan,
        request,
        _evaluation_context(plan, Path(repo_root).resolve()),
        policy_validator=policy_validator,
    )
    normal = dict(records)
    for artifact_type, result in (
        ("validation_calibration_cells", normal_calibration),
        ("validation_aggregate_metrics", normal_aggregate),
    ):
        original = records[artifact_type][0].payload
        normal[artifact_type] = (
            _candidate_record(candidate.candidate_id, {**original, "result": result}),
        )
    verified = verify_single_validation_candidate_records(
        plan,
        candidate,
        normal,
        repo_root=repo_root,
        policy_validator=policy_validator,
    )
    return {
        **verified,
        "series_id": p6_10b_series_id,
        "confidence_semantics": (
            "bounded_legacy_score_not_probability"
            if confidence_values is not None
            else "posterior_probability"
        ),
    }


def _p6_10b_source_series(
    plan: ValidationBatchPlan,
    candidate: PrimaryCandidate,
    records: Mapping[str, Sequence[ValidationArtifactRecord]],
    *,
    repo_root: Path | str,
    policy_validator: PolicyValidator,
    accept_revalued: bool = False,
) -> tuple[ValidationCandidateRequest, SeriesCalibrationResult]:
    session_records = {name: tuple(records[name]) for name in _SESSION_ARTIFACT_TYPE_ORDER}
    expected_keys = _single_candidate_session_keys(plan, candidate.candidate_id)
    by_type = {
        name: {record.session_key(): record for record in values}
        for name, values in session_records.items()
    }
    session_results = []
    for key in expected_keys:
        values = tuple(
            by_type[name][key].payload["result"] for name in _SESSION_ARTIFACT_TYPE_ORDER
        )
        _validate_session_result_envelopes(key, values)
        session_results.append(
            ValidationSessionResult("validation", key, _stream_roots(key), *values)
        )
    request = ValidationCandidateRequest(
        candidate,
        tuple(session_results),
        _session_join_sha256(candidate.candidate_id, session_records),
    )
    calibration, aggregate, series = _candidate_products(
        plan,
        request,
        _evaluation_context(plan, Path(repo_root).resolve()),
        policy_validator=policy_validator,
    )
    if not accept_revalued:
        actual_calibration = records["validation_calibration_cells"][0].payload["result"]
        actual_aggregate = records["validation_aggregate_metrics"][0].payload["result"]
        if actual_calibration != calibration or actual_aggregate != aggregate:
            raise ValueError("P6-10B source series differs from default reconstruction")
    return request, series


def _p6_10b_candidate_payloads(
    request: ValidationCandidateRequest,
    series: SeriesCalibrationResult,
) -> tuple[dict[str, object], dict[str, object]]:
    common = {
        "evaluator_version": CALIBRATION_EVALUATOR_VERSION,
        "candidate_id": request.candidate.candidate_id,
        "source_session_join_sha256": request.session_join_sha256,
        "series_id": series.series_id,
    }
    calibration = {
        "schema_version": VALIDATION_CALIBRATION_RESULT_SCHEMA_VERSION,
        **common,
        "cells": _json_ready(series.cells),
    }
    aggregate = {
        "schema_version": VALIDATION_AGGREGATE_RESULT_SCHEMA_VERSION,
        **common,
        "terminal_snapshot_sha256": series.terminal_snapshot_sha256,
        "ground_truth_sha256": series.ground_truth_sha256,
        "exact_ev_sha256s": list(series.exact_ev_sha256s),
        "atomic_groups": _json_ready(series.atomic_groups),
        "macro": _json_ready(series.macro),
        "micro": _json_ready(series.micro),
        "gto_fpr": _json_ready(series.gto_fpr),
    }
    return calibration, aggregate


def verify_single_validation_candidate_records(
    plan: ValidationBatchPlan,
    candidate: PrimaryCandidate,
    records_by_type: Mapping[str, Sequence[ValidationArtifactRecord]],
    *,
    repo_root: Path | str,
    policy_validator: PolicyValidator | None = None,
) -> dict[str, object]:
    """Independently reconstruct one non-P6-9 Validation series."""
    verify_validation_batch_plan(plan, repo_root=repo_root)
    validate_policy = policy_validator or _validate_reconstructed_hero_policy
    if not isinstance(candidate, PrimaryCandidate):
        raise TypeError("single Validation verifier requires a PrimaryCandidate")
    if candidate.candidate_id in {item.candidate_id for item in plan.candidates}:
        raise ValueError("single Validation candidate must remain outside the P6-9 grid")
    if tuple(records_by_type) != _ARTIFACT_TYPES:
        raise ValueError("single Validation records must use the canonical five-type order")
    context = _evaluation_context(plan, Path(repo_root).resolve())
    catalog = {
        item["opponent_id"]: item for item in plan.manifest["validation_catalog_index"]["opponents"]
    }
    expected_keys = _single_candidate_session_keys(plan, candidate.candidate_id)
    expected_set = set(expected_keys)
    candidate_entry = _candidate_entry(candidate)
    backend: dict[str, str] | None = None
    session_records: dict[str, tuple[ValidationArtifactRecord, ...]] = {}
    candidate_records: dict[str, tuple[ValidationArtifactRecord, ...]] = {}
    for artifact_type in _ARTIFACT_TYPES:
        records = tuple(records_by_type[artifact_type])
        expected_count = len(expected_keys) if artifact_type in _SESSION_ARTIFACT_TYPES else 1
        if len(records) != expected_count or any(
            not isinstance(record, ValidationArtifactRecord) for record in records
        ):
            raise ValueError("single Validation artifact cardinality is invalid")
        if [record.candidate_id for record in records] != [candidate.candidate_id] * len(records):
            raise ValueError("single Validation artifact mixes candidate identities")
        if artifact_type in _SESSION_ARTIFACT_TYPES:
            keys = tuple(record.session_key() for record in records)
            if keys != expected_keys or set(keys) != expected_set:
                raise ValueError("single Validation session keys are incomplete or out of order")
        elif any(
            record.opponent_id is not None
            or record.horizon is not None
            or record.repetition_id is not None
            for record in records
        ):
            raise ValueError("single Validation candidate artifact has session coordinates")
        for record in records:
            payload = record.payload
            if not isinstance(payload, dict) or record.payload_sha256 != sha256_bytes(
                canonical_json_bytes(payload)
            ):
                raise ValueError("single Validation record payload hash mismatch")
            common = {
                "schema_version",
                "adapter_version",
                "artifact_type",
                "validation_batch_manifest_sha256",
                "split",
                "candidate",
                "backend",
                "result",
            }
            expected_fields = (
                common | {"session", "opponent", "stream_roots"}
                if artifact_type in _SESSION_ARTIFACT_TYPES
                else common | {"source_session_join_sha256"}
            )
            if set(payload) != expected_fields or (
                payload["schema_version"] != VALIDATION_EXECUTION_RECORD_SCHEMA_VERSION
                or payload["adapter_version"] != VALIDATION_EXECUTION_ADAPTER_VERSION
                or payload["artifact_type"] != artifact_type
                or payload["validation_batch_manifest_sha256"] != plan.manifest_sha256
                or payload["split"] != "validation"
                or payload["candidate"] != candidate_entry
            ):
                raise ValueError("single Validation record provenance mismatch")
            current_backend = payload["backend"]
            _validate_backend_identity(current_backend)
            if backend is None:
                backend = current_backend
            elif current_backend != backend:
                raise ValueError("single Validation records mix backend identities")
            if artifact_type in _SESSION_ARTIFACT_TYPES:
                key = record.session_key()
                if (
                    payload["session"] != key.canonical_payload()
                    or payload["opponent"] != catalog[key.opponent_id]
                    or payload["stream_roots"] != _stream_root_entries(key)
                ):
                    raise ValueError("single Validation session provenance does not reconstruct")
            elif payload["source_session_join_sha256"] != _session_join_sha256(
                candidate.candidate_id, session_records
            ):
                raise ValueError("single Validation candidate result is not bound to all sessions")
        if artifact_type in _SESSION_ARTIFACT_TYPES:
            session_records[artifact_type] = records
        else:
            candidate_records[artifact_type] = records

    session_results: list[ValidationSessionResult] = []
    by_type = {
        name: {record.session_key(): record for record in records}
        for name, records in session_records.items()
    }
    for key in expected_keys:
        values = tuple(
            by_type[name][key].payload["result"] for name in _SESSION_ARTIFACT_TYPE_ORDER
        )
        _validate_session_result_envelopes(key, values)
        validate_policy(
            candidate,
            values[0],
            values[1],
            context.opponents[key.opponent_id],
            context.dimension,
        )
        session_results.append(
            ValidationSessionResult("validation", key, _stream_roots(key), *values)
        )
    request = ValidationCandidateRequest(
        candidate,
        tuple(session_results),
        _session_join_sha256(candidate.candidate_id, session_records),
    )
    calibration = candidate_records["validation_calibration_cells"][0].payload["result"]
    aggregate = candidate_records["validation_aggregate_metrics"][0].payload["result"]
    _validate_candidate_result_envelopes(request, calibration, aggregate)
    expected_calibration, expected_aggregate, series = _candidate_products(
        plan,
        request,
        context,
        policy_validator=validate_policy,
    )
    if calibration != expected_calibration or aggregate != expected_aggregate:
        raise ValueError("single Validation calibration/aggregate does not reconstruct")
    return {
        "backend": backend,
        "candidate_id": candidate.candidate_id,
        "series_id": series.series_id,
        "session_count": len(expected_keys),
    }


def _single_candidate_session_keys(
    plan: ValidationBatchPlan,
    candidate_id: str,
) -> tuple[ValidationSessionKey, ...]:
    if not isinstance(candidate_id, str) or not candidate_id or not candidate_id.isascii():
        raise ValueError("single Validation candidate ID must be non-empty ASCII")
    coordinates = sorted(
        {(key.opponent_id, key.horizon, key.repetition_id) for key in plan.sessions}
    )
    keys = tuple(
        ValidationSessionKey(candidate_id, opponent_id, horizon, repetition_id)
        for opponent_id, horizon, repetition_id in coordinates
    )
    if len(keys) != 810:
        raise ValueError("single Validation series must contain exactly 810 sessions")
    return keys


def verify_validation_execution_records(
    plan: ValidationBatchPlan,
    records_by_type: Mapping[str, Sequence[ValidationArtifactRecord]],
    *,
    repo_root: Path | str,
) -> None:
    """Reconstruct the Validation execution envelopes and five-way joins."""
    verify_validation_batch_plan(plan, repo_root=repo_root)
    if tuple(records_by_type) != _ARTIFACT_TYPES:
        raise ValueError("Validation records must use the canonical five-type order")
    expected_sessions = set(plan.sessions)
    candidate_ids = {item.candidate_id for item in plan.candidates}
    candidates = {item.candidate_id: item for item in plan.candidates}
    catalog = {
        item["opponent_id"]: item for item in plan.manifest["validation_catalog_index"]["opponents"]
    }
    backend: dict[str, str] | None = None
    session_records: dict[str, Sequence[ValidationArtifactRecord]] = {}
    candidate_records: dict[str, Sequence[ValidationArtifactRecord]] = {}
    for artifact_type in _ARTIFACT_TYPES:
        records = tuple(records_by_type[artifact_type])
        _validate_records(
            artifact_type,
            records,
            expected_sessions=expected_sessions,
            candidate_ids=candidate_ids,
        )
        for record in records:
            payload = record.payload
            if not isinstance(payload, dict):
                raise ValueError("Validation execution payload must be an object")
            common = {
                "schema_version",
                "adapter_version",
                "artifact_type",
                "validation_batch_manifest_sha256",
                "split",
                "candidate",
                "backend",
                "result",
            }
            expected_fields = (
                common | {"session", "opponent", "stream_roots"}
                if artifact_type in _SESSION_ARTIFACT_TYPES
                else common | {"source_session_join_sha256"}
            )
            if set(payload) != expected_fields:
                raise ValueError("Validation execution payload is not closed-world")
            if (
                payload["schema_version"] != VALIDATION_EXECUTION_RECORD_SCHEMA_VERSION
                or payload["adapter_version"] != VALIDATION_EXECUTION_ADAPTER_VERSION
                or payload["artifact_type"] != artifact_type
                or payload["validation_batch_manifest_sha256"] != plan.manifest_sha256
                or payload["split"] != "validation"
                or payload["candidate"] != _candidate_entry(candidates[record.candidate_id])
            ):
                raise ValueError("Validation execution payload provenance mismatch")
            current_backend = payload["backend"]
            if not isinstance(current_backend, dict):
                raise ValueError("Validation backend identity must be an object")
            _validate_backend_identity(current_backend)
            if backend is None:
                backend = current_backend
            elif current_backend != backend:
                raise ValueError("Validation records mix backend identities")
            if artifact_type in _SESSION_ARTIFACT_TYPES:
                key = record.session_key()
                if (
                    payload["session"] != key.canonical_payload()
                    or payload["opponent"] != catalog[key.opponent_id]
                    or payload["stream_roots"] != _stream_root_entries(key)
                ):
                    raise ValueError("Validation session provenance does not reconstruct")
            elif payload["source_session_join_sha256"] != _session_join_sha256(
                record.candidate_id, session_records
            ):
                raise ValueError("Validation candidate result is not bound to all sessions")
            _canonical_result(payload["result"])
        if artifact_type in _SESSION_ARTIFACT_TYPES:
            session_records[artifact_type] = records
        else:
            candidate_records[artifact_type] = records
    return _rank_from_saved_records(
        plan,
        session_records,
        candidate_records,
        repo_root=repo_root,
    )


def write_validation_artifact_bundle(
    plan: ValidationBatchPlan,
    records_by_type: Mapping[str, Sequence[ValidationArtifactRecord]],
    validation_root: Path | str,
    *,
    repo_root: Path | str,
) -> ValidationArtifactBundle:
    """Write one immutable Validation-only bundle and verify it from its root."""
    ranked = verify_validation_execution_records(plan, records_by_type, repo_root=repo_root)
    root = _validation_root(Path(validation_root))
    root.mkdir(parents=False, exist_ok=False)
    payloads: dict[str, bytes] = {
        "validation_batch_manifest": plan.manifest_bytes,
    }
    backend: dict[str, str] | None = None
    for artifact_type in _ARTIFACT_TYPES:
        records = tuple(records_by_type[artifact_type])
        current = records[0].payload["backend"]
        backend = current if backend is None else backend
        if current != backend:
            raise ValueError("Validation artifact types mix backend identities")
        payloads[artifact_type] = canonical_json_bytes(
            {
                "schema_version": VALIDATION_EXECUTION_ARTIFACT_SCHEMA_VERSION,
                "artifact_type": artifact_type,
                "validation_batch_manifest_sha256": plan.manifest_sha256,
                "split": "validation",
                "records": [record.canonical_payload() for record in records],
            }
        )
    aggregate_hash = sha256_bytes(payloads["validation_aggregate_metrics"])
    report = _selection_report(plan, ranked, aggregate_hash)
    payloads["primary_selection_report"] = canonical_json_bytes(report)
    report_hash = sha256_bytes(payloads["primary_selection_report"])
    payloads["selected_config_lock"] = canonical_json_bytes(
        _selected_lock(plan, ranked[0], report_hash)
    )
    references: list[dict[str, object]] = []
    for name, raw in payloads.items():
        path = root / f"{name}.json"
        _write_exclusive(path, raw)
        references.append(
            {
                "name": name,
                "path": path.name,
                "sha256": sha256_bytes(raw),
                "size_bytes": len(raw),
            }
        )
    root_payload = {
        "schema_version": VALIDATION_ROOT_MANIFEST_SCHEMA_VERSION,
        "artifact_type": "validation_result_root",
        "writer_version": VALIDATION_WRITER_VERSION,
        "split": "validation",
        "physical_directory": VALIDATION_PHYSICAL_DIRECTORY,
        "validation_batch_manifest_sha256": plan.manifest_sha256,
        "backend": backend,
        "selection_contract_sha256": plan.manifest["selection_metric_contract"]["sha256"],
        "expected_cardinality": dict(_CARDINALITY),
        "artifacts": references,
    }
    root_raw = canonical_json_bytes(root_payload)
    root_path = root / "validation_result_root.json"
    _write_exclusive(root_path, root_raw)
    root_hash = sha256_bytes(root_raw)
    verify_validation_artifact_root(
        root_path,
        expected_sha256=root_hash,
        repo_root=repo_root,
    )
    return ValidationArtifactBundle(root, root_path, root_hash)


def verify_validation_artifact_root(
    root_manifest_path: Path | str,
    *,
    expected_sha256: str,
    repo_root: Path | str,
) -> dict[str, object]:
    """Reconstruct all saved Validation records, hashes, selection, and lock."""
    _validate_sha256(expected_sha256, "Validation root expected hash")
    root_path = Path(root_manifest_path).resolve()
    root = _validation_root(root_path.parent)
    if root_path != root / "validation_result_root.json":
        raise ValueError("Validation root manifest has a noncanonical physical path")
    root_raw = root_path.read_bytes()
    if sha256_bytes(root_raw) != expected_sha256:
        raise ValueError("Validation root manifest hash mismatch")
    manifest = _strict_object(root_raw, "Validation root manifest")
    if set(manifest) != {
        "schema_version",
        "artifact_type",
        "writer_version",
        "split",
        "physical_directory",
        "validation_batch_manifest_sha256",
        "backend",
        "selection_contract_sha256",
        "expected_cardinality",
        "artifacts",
    }:
        raise ValueError("Validation root manifest is not closed-world")
    if (
        manifest["schema_version"] != VALIDATION_ROOT_MANIFEST_SCHEMA_VERSION
        or manifest["artifact_type"] != "validation_result_root"
        or manifest["writer_version"] != VALIDATION_WRITER_VERSION
        or manifest["split"] != "validation"
        or manifest["physical_directory"] != VALIDATION_PHYSICAL_DIRECTORY
        or manifest["expected_cardinality"] != _CARDINALITY
    ):
        raise ValueError("Validation root manifest identity/cardinality is invalid")
    _validate_backend_identity(manifest["backend"])
    expected_names = (
        "validation_batch_manifest",
        *_ARTIFACT_TYPES,
        "primary_selection_report",
        "selected_config_lock",
    )
    references = manifest["artifacts"]
    if not isinstance(references, list) or [item.get("name") for item in references] != list(
        expected_names
    ):
        raise ValueError("Validation root artifact set/order is invalid")
    payloads: dict[str, dict[str, object]] = {}
    raw_by_name: dict[str, bytes] = {}
    for reference in references:
        if set(reference) != {"name", "path", "sha256", "size_bytes"}:
            raise ValueError("Validation artifact reference is not closed-world")
        name = reference["name"]
        if reference["path"] != f"{name}.json":
            raise ValueError("Validation artifact path is not canonical")
        _validate_sha256(reference["sha256"], "Validation artifact hash")
        path = _child(root, reference["path"])
        raw = path.read_bytes()
        if len(raw) != reference["size_bytes"] or sha256_bytes(raw) != reference["sha256"]:
            raise ValueError("Validation artifact size/hash mismatch")
        payloads[name] = _strict_object(raw, f"Validation artifact {name}")
        raw_by_name[name] = raw

    batch = payloads["validation_batch_manifest"]
    batch_raw = raw_by_name["validation_batch_manifest"]
    batch_hash = sha256_bytes(batch_raw)
    if batch_hash != manifest["validation_batch_manifest_sha256"]:
        raise ValueError("Validation batch reference mismatch")
    sampling_hash = batch["sampling_contract"]["sha256"]
    candidates = primary_candidate_grid(sampling_contract_sha256=sampling_hash)
    sessions = tuple(
        ValidationSessionKey(
            item["candidate_id"],
            item["opponent_id"],
            item["horizon"],
            item["repetition_id"],
        )
        for item in batch["sessions"]
    )
    plan = ValidationBatchPlan(batch, batch_raw, batch_hash, candidates, sessions)
    verify_validation_batch_plan(plan, repo_root=repo_root)
    if manifest["selection_contract_sha256"] != batch["selection_metric_contract"]["sha256"]:
        raise ValueError("Validation root selection contract mismatch")

    records_by_type: dict[str, tuple[ValidationArtifactRecord, ...]] = {}
    for artifact_type in _ARTIFACT_TYPES:
        payload = payloads[artifact_type]
        if set(payload) != {
            "schema_version",
            "artifact_type",
            "validation_batch_manifest_sha256",
            "split",
            "records",
        } or (
            payload["schema_version"] != VALIDATION_EXECUTION_ARTIFACT_SCHEMA_VERSION
            or payload["artifact_type"] != artifact_type
            or payload["validation_batch_manifest_sha256"] != batch_hash
            or payload["split"] != "validation"
            or not isinstance(payload["records"], list)
        ):
            raise ValueError("Validation result artifact provenance is invalid")
        records_by_type[artifact_type] = tuple(
            _record_from_payload(item) for item in payload["records"]
        )
    ranked = verify_validation_execution_records(plan, records_by_type, repo_root=repo_root)
    if any(
        record.payload["backend"] != manifest["backend"]
        for records in records_by_type.values()
        for record in records
    ):
        raise ValueError("Validation root backend differs from saved records")
    report = _selection_report(
        plan, ranked, sha256_bytes(raw_by_name["validation_aggregate_metrics"])
    )
    if payloads["primary_selection_report"] != report:
        raise ValueError("Primary selection report does not reconstruct from aggregate")
    report_hash = sha256_bytes(raw_by_name["primary_selection_report"])
    lock = _selected_lock(plan, ranked[0], report_hash)
    if payloads["selected_config_lock"] != lock:
        raise ValueError("Selected config lock does not reconstruct from the report")
    return manifest


def _session_payload(plan, request, artifact_type, result, backend):
    return {
        "schema_version": VALIDATION_EXECUTION_RECORD_SCHEMA_VERSION,
        "adapter_version": VALIDATION_EXECUTION_ADAPTER_VERSION,
        "artifact_type": artifact_type,
        "validation_batch_manifest_sha256": plan.manifest_sha256,
        "split": "validation",
        "candidate": _candidate_entry(request.candidate),
        "session": request.key.canonical_payload(),
        "opponent": next(
            item
            for item in plan.manifest["validation_catalog_index"]["opponents"]
            if item["opponent_id"] == request.key.opponent_id
        ),
        "stream_roots": [
            {"digest": item.digest, "payload": item.payload} for item in request.stream_roots
        ],
        "backend": backend,
        "result": result,
    }


def _candidate_payload(plan, request, artifact_type, result, backend):
    return {
        "schema_version": VALIDATION_EXECUTION_RECORD_SCHEMA_VERSION,
        "adapter_version": VALIDATION_EXECUTION_ADAPTER_VERSION,
        "artifact_type": artifact_type,
        "validation_batch_manifest_sha256": plan.manifest_sha256,
        "split": "validation",
        "candidate": _candidate_entry(request.candidate),
        "source_session_join_sha256": request.session_join_sha256,
        "backend": backend,
        "result": result,
    }


@dataclass(frozen=True, slots=True)
class _EvaluationContext:
    bundle: ValidatedPhase6ContractBundle
    opponents: dict[str, SynthesizedOpponent]
    opponent_rows: tuple[dict[str, object], ...]
    dimension: dict[str, object]
    truth: dict[str, tuple[Decimal, Decimal]]
    strategy_sha256s: dict[str, str]
    opponent_catalog_sha256: str
    sampling_contract_sha256: str


def _validate_session_result_envelopes(key: ValidationSessionKey, values: Sequence[object]) -> None:
    terminal, policy, exact = values
    terminal_fields = {
        "schema_version",
        "evaluator_version",
        "session",
        "action_counts",
        "opportunity_count",
        "transcript_sha256",
    }
    if not isinstance(terminal, dict) or set(terminal) != terminal_fields:
        raise ValueError("Validation terminal result is not closed-world")
    counts = terminal["action_counts"]
    if (
        terminal["schema_version"] != VALIDATION_TERMINAL_RESULT_SCHEMA_VERSION
        or terminal["evaluator_version"] != CALIBRATION_EVALUATOR_VERSION
        or terminal["session"] != key.canonical_payload()
        or not isinstance(counts, dict)
        or set(counts) != {"BET", "CHECK"}
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in counts.values()
        )
        or terminal["opportunity_count"] != key.horizon
        or sum(counts.values()) != key.horizon
    ):
        raise ValueError("Validation terminal result does not reconstruct its session")
    _validate_sha256(terminal["transcript_sha256"], "Validation transcript hash")

    policy_fields = {
        "schema_version",
        "exact_ev_evaluator_version",
        "session",
        "source_terminal_sha256",
        "game_id",
        "opponent_id",
        "hero_player",
        "base_hero_policy",
        "final_hero_policy",
    }
    if not isinstance(policy, dict) or set(policy) != policy_fields:
        raise ValueError("Validation Hero policy result is not closed-world")
    if (
        policy["schema_version"] != VALIDATION_HERO_POLICY_RESULT_SCHEMA_VERSION
        or policy["exact_ev_evaluator_version"] != EXACT_EV_INPUT_VERSION
        or policy["session"] != key.canonical_payload()
        or policy["source_terminal_sha256"] != sha256_bytes(canonical_json_bytes(terminal))
        or not isinstance(policy["game_id"], str)
        or not policy["game_id"]
        or policy["opponent_id"] != key.opponent_id
        or policy["hero_player"] != 0
    ):
        raise ValueError("Validation Hero policy provenance does not reconstruct")
    _policy_from_payload(policy["base_hero_policy"], "base Hero policy")
    _policy_from_payload(policy["final_hero_policy"], "final Hero policy")

    exact_fields = {
        "schema_version",
        "exact_ev_evaluator_version",
        "session",
        "source_terminal_sha256",
        "source_hero_policy_sha256",
        "cell",
    }
    if not isinstance(exact, dict) or set(exact) != exact_fields:
        raise ValueError("Validation exact-EV result is not closed-world")
    if (
        exact["schema_version"] != VALIDATION_EXACT_EV_RESULT_SCHEMA_VERSION
        or exact["exact_ev_evaluator_version"] != EXACT_EV_INPUT_VERSION
        or exact["session"] != key.canonical_payload()
        or exact["source_terminal_sha256"] != sha256_bytes(canonical_json_bytes(terminal))
        or exact["source_hero_policy_sha256"] != sha256_bytes(canonical_json_bytes(policy))
        or not isinstance(exact["cell"], dict)
    ):
        raise ValueError("Validation exact-EV provenance does not reconstruct")


def _validate_candidate_result_envelopes(
    request: ValidationCandidateRequest,
    calibration: object,
    aggregate: object,
) -> None:
    calibration_fields = {
        "schema_version",
        "evaluator_version",
        "candidate_id",
        "source_session_join_sha256",
        "series_id",
        "cells",
    }
    aggregate_fields = {
        "schema_version",
        "evaluator_version",
        "candidate_id",
        "source_session_join_sha256",
        "series_id",
        "terminal_snapshot_sha256",
        "ground_truth_sha256",
        "exact_ev_sha256s",
        "atomic_groups",
        "macro",
        "micro",
        "gto_fpr",
    }
    candidate_id = request.candidate.candidate_id
    if not isinstance(calibration, dict) or set(calibration) != calibration_fields:
        raise ValueError("Validation calibration result is not closed-world")
    if not isinstance(aggregate, dict) or set(aggregate) != aggregate_fields:
        raise ValueError("Validation aggregate result is not closed-world")
    if (
        calibration["schema_version"] != VALIDATION_CALIBRATION_RESULT_SCHEMA_VERSION
        or aggregate["schema_version"] != VALIDATION_AGGREGATE_RESULT_SCHEMA_VERSION
        or calibration["evaluator_version"] != CALIBRATION_EVALUATOR_VERSION
        or aggregate["evaluator_version"] != CALIBRATION_EVALUATOR_VERSION
        or calibration["candidate_id"] != candidate_id
        or aggregate["candidate_id"] != candidate_id
        or calibration["source_session_join_sha256"] != request.session_join_sha256
        or aggregate["source_session_join_sha256"] != request.session_join_sha256
        or calibration["series_id"] != aggregate["series_id"]
        or not isinstance(calibration["series_id"], str)
        or re.fullmatch(r"[0-9a-f]{64}", calibration["series_id"]) is None
        or not isinstance(calibration["cells"], list)
        or not isinstance(aggregate["exact_ev_sha256s"], list)
    ):
        raise ValueError("Validation candidate result identity/provenance is invalid")


def _rank_from_saved_records(
    plan: ValidationBatchPlan,
    session_records: Mapping[str, Sequence[ValidationArtifactRecord]],
    candidate_records: Mapping[str, Sequence[ValidationArtifactRecord]],
    *,
    repo_root: Path | str,
) -> tuple[CandidateSelectionMetrics, ...]:
    context = _evaluation_context(plan, Path(repo_root).resolve())
    session_by_type = {
        artifact_type: {record.session_key(): record for record in records}
        for artifact_type, records in session_records.items()
    }
    candidate_by_type = {
        artifact_type: {record.candidate_id: record for record in records}
        for artifact_type, records in candidate_records.items()
    }
    metrics: list[CandidateSelectionMetrics] = []
    expected_sets: list[tuple[ExpectedGtoSelectionGroup, ...]] = []
    for candidate in plan.candidates:
        keys = tuple(key for key in plan.sessions if key.candidate_id == candidate.candidate_id)
        join_sha256 = _session_join_sha256(candidate.candidate_id, session_records)
        request = ValidationCandidateRequest(
            candidate,
            tuple(
                ValidationSessionResult(
                    "validation",
                    key,
                    _stream_roots(key),
                    session_by_type["validation_terminal_candidate_snapshots"][key].payload[
                        "result"
                    ],
                    session_by_type["validation_hero_policy_snapshots"][key].payload["result"],
                    session_by_type["validation_exact_ev_cells"][key].payload["result"],
                )
                for key in keys
            ),
            join_sha256,
        )
        calibration = candidate_by_type["validation_calibration_cells"][
            candidate.candidate_id
        ].payload["result"]
        aggregate = candidate_by_type["validation_aggregate_metrics"][
            candidate.candidate_id
        ].payload["result"]
        _validate_candidate_result_envelopes(request, calibration, aggregate)
        expected_calibration, expected_aggregate, series = _candidate_products(
            plan,
            request,
            context,
        )
        if calibration != expected_calibration or aggregate != expected_aggregate:
            raise ValueError(
                "Validation P6-6 calibration/aggregate does not independently reconstruct"
            )
        item, expected = _selection_from_series(candidate.candidate_id, series, plan)
        metrics.append(item)
        expected_sets.append(expected)
    if not expected_sets or any(value != expected_sets[0] for value in expected_sets[1:]):
        raise ValueError("Validation GTO eligible-key provenance differs across candidates")
    return rank_primary_candidates(
        plan.candidates,
        metrics,
        expected_gto_groups=expected_sets[0],
    )


def _candidate_products(
    plan: ValidationBatchPlan,
    request: ValidationCandidateRequest,
    context: _EvaluationContext,
    *,
    policy_validator: PolicyValidator | None = None,
) -> tuple[dict[str, object], dict[str, object], SeriesCalibrationResult]:
    descriptor = _validation_series_descriptor(request.candidate, context)
    terminal_records: list[dict[str, object]] = []
    truth_records: list[dict[str, object]] = []
    exact_observations: list[ExactEvObservation] = []
    dimension = descriptor["candidate_dimensions"][0]
    config = descriptor["config"]
    assert isinstance(dimension, dict) and isinstance(config, dict)
    for supplied in request.session_results:
        values = (
            supplied.terminal_candidate_snapshot,
            supplied.hero_policy_snapshot,
            supplied.exact_ev_cell,
        )
        _validate_session_result_envelopes(supplied.key, values)
        opponent = context.opponents[supplied.key.opponent_id]
        cell = _recompute_exact_ev(
            supplied.key,
            values,
            opponent,
            request.candidate,
            context.dimension,
            policy_validator=policy_validator,
        )
        terminal_records.append(
            _terminal_record(
                descriptor["series_id"],
                supplied.key,
                supplied.terminal_candidate_snapshot,
                dimension=dimension,
                config=config,
            )
        )
        truth_records.append(
            _ground_truth_record(
                descriptor["series_id"],
                supplied.key,
                dimension=dimension,
                truth=context.truth[supplied.key.opponent_id],
                strategy_sha256=context.strategy_sha256s[supplied.key.opponent_id],
            )
        )
        observation_fields = {
            "series_id": descriptor["series_id"],
            "opponent_id": supplied.key.opponent_id,
            "horizon": supplied.key.horizon,
            "repetition_id": supplied.key.repetition_id,
            "cell": cell,
        }
        exact_observations.append(
            ExactEvObservation(
                **observation_fields,
                sha256=exact_ev_observation_sha256(**observation_fields),
            )
        )
    contract_refs = _contract_refs(context.bundle)
    terminal_payload = {
        "schema_version": TERMINAL_SNAPSHOT_SCHEMA_VERSION,
        "artifact_type": "terminal_candidate_snapshots",
        "contract_refs": contract_refs,
        "series": [descriptor],
        "records": terminal_records,
    }
    descriptor_hash = sha256_bytes(canonical_json_bytes(descriptor))
    truth_payload = {
        "schema_version": GROUND_TRUTH_SCHEMA_VERSION,
        "artifact_type": "calibration_ground_truth",
        "contract_refs": contract_refs,
        "series_descriptor_sha256s": {descriptor["series_id"]: descriptor_hash},
        "records": truth_records,
    }
    terminal_artifact = _canonical_calibration_artifact(terminal_payload)
    truth_artifact = _canonical_calibration_artifact(truth_payload)
    evaluation = evaluate_all_candidate_calibration(
        context.bundle,
        terminal_artifact,
        truth_artifact,
        exact_observations,
    )
    if evaluation.evaluator_version != CALIBRATION_EVALUATOR_VERSION or len(evaluation.series) != 1:
        raise ValueError("Validation P6-6 evaluator returned a noncanonical series set")
    series = evaluation.series[0]
    if series.series_id != descriptor["series_id"]:
        raise ValueError("Validation P6-6 series does not join the reconstructed descriptor")
    common = {
        "evaluator_version": evaluation.evaluator_version,
        "candidate_id": request.candidate.candidate_id,
        "source_session_join_sha256": request.session_join_sha256,
        "series_id": series.series_id,
    }
    calibration = {
        "schema_version": VALIDATION_CALIBRATION_RESULT_SCHEMA_VERSION,
        **common,
        "cells": _json_ready(series.cells),
    }
    aggregate = {
        "schema_version": VALIDATION_AGGREGATE_RESULT_SCHEMA_VERSION,
        **common,
        "terminal_snapshot_sha256": series.terminal_snapshot_sha256,
        "ground_truth_sha256": series.ground_truth_sha256,
        "exact_ev_sha256s": list(series.exact_ev_sha256s),
        "atomic_groups": _json_ready(series.atomic_groups),
        "macro": _json_ready(series.macro),
        "micro": _json_ready(series.micro),
        "gto_fpr": _json_ready(series.gto_fpr),
    }
    return calibration, aggregate, series


def _selection_from_series(
    candidate_id: str,
    series: SeriesCalibrationResult,
    plan: ValidationBatchPlan,
) -> tuple[CandidateSelectionMetrics, tuple[ExpectedGtoSelectionGroup, ...]]:
    macro_brier = series.macro.brier.value
    micro_brier = series.micro.calibration.brier.value
    if macro_brier is None or micro_brier is None:
        raise ValueError("Validation Brier selection metrics must be defined")
    gto_ids = [
        item["opponent_id"]
        for item in plan.manifest["validation_catalog_index"]["opponents"]
        if item["control_role"] == "gto_negative_control"
    ]
    if len(gto_ids) != 1:
        raise ValueError("Validation selection requires exactly one GTO control")
    gto_id = gto_ids[0]
    group_by_key = {(group.opponent_id, group.horizon): group for group in series.gto_fpr.groups}
    groups: list[GtoSelectionGroup] = []
    expected: list[ExpectedGtoSelectionGroup] = []
    for horizon in HORIZONS:
        eligible_keys = tuple(
            _gto_eligible_key(cell.key)
            for cell in series.cells
            if cell.key[1] == gto_id and cell.key[4] == horizon and cell.label is not None
        )
        group = group_by_key.get((gto_id, horizon))
        if group is None or group.rate.denominator != len(eligible_keys):
            raise ValueError("Validation GTO group/count does not reconstruct from P6-6 cells")
        groups.append(
            GtoSelectionGroup(
                gto_id,
                horizon,
                group.rate.numerator,
                group.rate.denominator,
                group.rate.status,
                eligible_keys,
            )
        )
        expected.append(ExpectedGtoSelectionGroup(gto_id, horizon, eligible_keys))
    micro = series.gto_fpr.micro
    metrics = CandidateSelectionMetrics(
        candidate_id=candidate_id,
        validation_macro_brier=macro_brier,
        validation_micro_brier=micro_brier,
        gto_false_positives=micro.numerator,
        gto_total_negatives=micro.denominator,
        validation_macro_exploitation_efficiency=series.macro.mean_cell_efficiency.value,
        validation_macro_recall=series.macro.recall.value,
        validation_macro_precision=series.macro.precision.value,
        gto_groups=tuple(groups),
    )
    return metrics, tuple(expected)


def _gto_eligible_key(key: tuple[str, str, str, str, int, str]) -> str:
    payload = {
        "opponent_id": key[1],
        "rule_id": key[2],
        "situation_key": key[3],
        "horizon": key[4],
        "repetition_id": key[5],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _evaluation_context(plan: ValidationBatchPlan, repo_root: Path) -> _EvaluationContext:
    bundle = _contract_bundle_for_plan(plan, repo_root)
    configs = tuple(sorted(load_validation_catalog(), key=lambda item: item.opponent_id))
    synthesized = tuple(synthesize_opponent(config=config) for config in configs)
    opponents = {item.config.opponent_id: item for item in synthesized}
    if len(opponents) != 9:
        raise ValueError("Validation evaluation requires nine unique synthesized opponents")
    gto = [item for item in synthesized if not item.config.leak_vector]
    if len(gto) != 1:
        raise ValueError("Validation evaluation requires exactly one GTO negative control")
    semantic = next(
        (
            item
            for item in bundle.coverage_contract["reason_rows"]
            if item["reason_id"] == _R008_REASON_ID
        ),
        None,
    )
    if semantic is None:
        raise ValueError("P6-4 R008 semantic contract is missing")
    action_row = next(
        (
            item
            for item in bundle.coverage_contract["action_family_registry"]["rows"]
            if item["action_family_id"] == semantic["action_family_id"]
        ),
        None,
    )
    if action_row is None:
        raise ValueError("P6-4 R008 action-family contract is missing")
    baseline = extract_independent_action_rates(
        gto[0].game,
        gto[0].equilibrium_strategy,
        gto[0].config,
        reason_ids=(_R008_REASON_ID,),
    )[0]
    dimension = {
        "rule_id": _R008_REASON_ID,
        "situation_key": semantic["situation_id"],
        "semantic_id": semantic["semantic_id"],
        "action_family_id": semantic["action_family_id"],
        "opportunity_event_id": semantic["opportunity_event_id"],
        "action_group": action_row["detector_encodings"],
        "baseline_rate": _decimal_wire(baseline.action_rate),
    }
    plan_entries = {
        item["opponent_id"]: item for item in plan.manifest["validation_catalog_index"]["opponents"]
    }
    rows: list[dict[str, object]] = []
    truth: dict[str, tuple[Decimal, Decimal]] = {}
    strategy_sha256s: dict[str, str] = {}
    for item in synthesized:
        opponent_id = item.config.opponent_id
        is_gto = not item.config.leak_vector
        plan_entry = plan_entries.get(opponent_id)
        expected_plan_role = "gto_negative_control" if is_gto else None
        if plan_entry is None or plan_entry["control_role"] != expected_plan_role:
            raise ValueError("Validation synthesized opponent provenance differs from the plan")
        strategy_sha256 = (
            plan_entry["equilibrium_artifact_sha256"] if is_gto else plan_entry["strategy_sha256"]
        )
        _validate_sha256(strategy_sha256, "Validation opponent strategy hash")
        measurement = extract_independent_action_rates(
            item.game,
            item.strategy,
            item.config,
            reason_ids=(_R008_REASON_ID,),
        )[0]
        truth[opponent_id] = (measurement.action_rate, measurement.opportunity_reach)
        strategy_sha256s[opponent_id] = strategy_sha256
        rows.append(
            {
                "opponent_id": opponent_id,
                "control_role": "gto_negative_control" if is_gto else "evaluation",
                "strategy_artifact_sha256": strategy_sha256,
                "equilibrium_artifact_sha256": (
                    item.equilibrium_artifact_sha256 if is_gto else None
                ),
            }
        )
    sampling_hash = plan.manifest["sampling_contract"]["sha256"]
    _validate_sha256(sampling_hash, "Validation sampling contract hash")
    return _EvaluationContext(
        bundle=bundle,
        opponents=opponents,
        opponent_rows=tuple(rows),
        dimension=dimension,
        truth=truth,
        strategy_sha256s=strategy_sha256s,
        opponent_catalog_sha256=sha256_bytes(
            canonical_json_bytes([item.canonical_payload() for item in configs])
        ),
        sampling_contract_sha256=sampling_hash,
    )


def _validation_series_descriptor(
    candidate: PrimaryCandidate,
    context: _EvaluationContext,
) -> dict[str, object]:
    config = {
        "split": "validation",
        "opponent_catalog_sha256": context.opponent_catalog_sha256,
        "estimator_method_version": "beta-binomial-upper-tail-v1",
        "estimator_config_sha256": sha256_bytes(
            canonical_json_bytes(
                {
                    "method_version": "beta-binomial-upper-tail-v1",
                    "alpha0": "1",
                    "beta0": "1",
                    "tail": "upper",
                    "tau": _TAU_WIRE,
                    "sample_floor": candidate.sample_floor,
                    "detector_threshold": candidate.detector_confidence,
                    "provider_threshold": candidate.provider_confidence,
                }
            )
        ),
        "baseline_table_sha256": sha256_bytes(
            canonical_json_bytes(
                {
                    "reason_id": _R008_REASON_ID,
                    "situation_key": _R008_SITUATION_KEY,
                    "baseline_rate": context.dimension["baseline_rate"],
                    "action_group": context.dimension["action_group"],
                }
            )
        ),
        "tau": _TAU_WIRE,
        "sample_floor": candidate.sample_floor,
        "detector_threshold": candidate.detector_confidence,
        "provider_threshold": candidate.provider_confidence,
        "exploit_provider": _EXPLOIT_PROVIDER_VERSION,
        "safety_alpha": candidate.safety_alpha,
        "execution_sampler_version": EXECUTION_SAMPLER_VERSION,
        "epsilon": candidate.epsilon,
        "epsilon_distribution_sha256": sha256_bytes(
            canonical_json_bytes(
                {
                    "distribution": "legal_uniform",
                    "epsilon": candidate.epsilon,
                    "sampling_contract_sha256": context.sampling_contract_sha256,
                }
            )
        ),
        "horizon_set": list(HORIZONS),
        "repetition_set": [f"r{index:03d}" for index in range(1, 31)],
        "evaluator_version": CALIBRATION_EVALUATOR_VERSION,
        "boundary_abs_tolerance": BOUNDARY_ABS_TOLERANCE_WIRE,
        "decimal_precision": DECIMAL_PRECISION,
        "decimal_rounding": DECIMAL_ROUNDING,
        "game_id": next(iter(context.opponents.values())).game.name,
        "ground_truth_extractor_version": GROUND_TRUTH_EXTRACTOR_VERSION,
        "exact_ev_evaluator_version": EXACT_EV_INPUT_VERSION,
    }
    opponents = [dict(item) for item in context.opponent_rows]
    dimensions = [dict(context.dimension)]
    return {
        "series_id": calibration_series_id(config, opponents, dimensions),
        "config": config,
        "opponents": opponents,
        "candidate_dimensions": dimensions,
    }


def _terminal_record(
    series_id: str,
    key: ValidationSessionKey,
    terminal: object,
    *,
    dimension: Mapping[str, object],
    config: Mapping[str, object],
) -> dict[str, object]:
    assert isinstance(terminal, dict)
    counts = dict(sorted(terminal["action_counts"].items()))
    n = sum(counts.values())
    action_group = dimension["action_group"]
    assert isinstance(action_group, list)
    k = sum(counts.get(action, 0) for action in action_group)
    baseline = Decimal(str(dimension["baseline_rate"]))
    tau = Decimal(_TAU_WIRE)
    with localcontext() as decimal_context:
        decimal_context.prec = DECIMAL_PRECISION
        decimal_context.rounding = ROUND_HALF_EVEN
        q = baseline + tau
        observed = Decimal(k) / Decimal(n) if n else Decimal(0)
    confidence = beta_binomial_upper_tail(
        k=k,
        n=n,
        baseline_rate=float(baseline),
        tau=float(tau),
    )
    confidence_wire = _decimal_wire(Decimal(str(confidence)))
    eligibility = {
        "structurally_eligible": Decimal(0) < q < Decimal(1),
        "sample_gate": n >= config["sample_floor"],
        "deviation_gate": observed - baseline >= tau,
        "confidence_gate": Decimal(confidence_wire) >= Decimal(str(config["detector_threshold"])),
    }
    eligibility["emitted"] = all(eligibility.values())
    return {
        "series_id": series_id,
        "opponent_id": key.opponent_id,
        "rule_id": dimension["rule_id"],
        "situation_key": dimension["situation_key"],
        "horizon": key.horizon,
        "repetition_id": key.repetition_id,
        "action_counts": counts,
        "action_group": action_group,
        "n": n,
        "k": k,
        "baseline_rate": dimension["baseline_rate"],
        "tau": _TAU_WIRE,
        "q": _decimal_wire(q),
        "posterior_confidence": confidence_wire,
        "candidate_eligibility": eligibility,
    }


def _ground_truth_record(
    series_id: str,
    key: ValidationSessionKey,
    *,
    dimension: Mapping[str, object],
    truth: tuple[Decimal, Decimal],
    strategy_sha256: str,
) -> dict[str, object]:
    return {
        "series_id": series_id,
        "opponent_id": key.opponent_id,
        "rule_id": dimension["rule_id"],
        "situation_key": dimension["situation_key"],
        "horizon": key.horizon,
        "repetition_id": key.repetition_id,
        "semantic_id": dimension["semantic_id"],
        "action_family_id": dimension["action_family_id"],
        "opportunity_event_id": dimension["opportunity_event_id"],
        "action_group": dimension["action_group"],
        "true_rate": _decimal_wire(truth[0]),
        "reach_weight": _decimal_wire(truth[1]),
        "strategy_artifact_sha256": strategy_sha256,
        "ground_truth_extractor_version": GROUND_TRUTH_EXTRACTOR_VERSION,
    }


def _recompute_exact_ev(
    key: ValidationSessionKey,
    values: Sequence[object],
    opponent: SynthesizedOpponent,
    candidate: PrimaryCandidate,
    dimension: Mapping[str, object],
    *,
    policy_validator: PolicyValidator | None = None,
) -> ExactEvCell:
    terminal, policy, exact = values
    assert isinstance(terminal, dict)
    assert isinstance(policy, dict)
    assert isinstance(exact, dict)
    if (
        policy["game_id"] != opponent.game.name
        or policy["opponent_id"] != opponent.config.opponent_id
        or key.opponent_id != opponent.config.opponent_id
    ):
        raise ValueError("Validation Hero policy does not join the synthesized opponent/game")
    validate_policy = policy_validator or _validate_reconstructed_hero_policy
    base_policy, final_policy = validate_policy(
        candidate,
        terminal,
        policy,
        opponent,
        dimension,
    )
    opponent_policy = {
        infoset: opponent.strategy[infoset] for infoset in opponent.game.infosets_of(1)
    }
    cell = evaluate_exact_ev(
        opponent.game,
        hero_player=0,
        opponent_policy=PolicySlice(
            opponent.game.name,
            opponent.config.opponent_id,
            opponent_policy,
        ),
        base_hero_policy=PolicySlice(
            opponent.game.name,
            opponent.config.opponent_id,
            base_policy,
        ),
        final_hero_policy=PolicySlice(
            opponent.game.name,
            opponent.config.opponent_id,
            final_policy,
        ),
    )
    if exact["cell"] != _exact_ev_payload(cell):
        raise ValueError("Validation exact-EV cell does not independently reconstruct through P6-5")
    return cell


def _validate_reconstructed_hero_policy(
    candidate: PrimaryCandidate,
    terminal: object,
    policy: object,
    opponent: SynthesizedOpponent,
    dimension: Mapping[str, object],
) -> tuple[StrategyProfile, StrategyProfile]:
    if not isinstance(terminal, dict) or not isinstance(policy, dict):
        raise ValueError("Validation Hero policy reconstruction requires canonical session results")
    saved_base = _policy_from_payload(policy["base_hero_policy"], "base Hero policy")
    saved_final = _policy_from_payload(policy["final_hero_policy"], "final Hero policy")
    expected_base, expected_final = _reconstruct_hero_policies(
        candidate,
        terminal,
        opponent,
        dimension,
    )
    if saved_base != expected_base:
        raise ValueError("Validation base Hero policy differs from frozen equilibrium")
    if saved_final != expected_final:
        raise ValueError(
            "Validation final Hero policy does not independently reconstruct from terminal counts"
        )
    return expected_base, expected_final


def _reconstruct_hero_policies(
    candidate: PrimaryCandidate,
    terminal: Mapping[str, object],
    opponent: SynthesizedOpponent,
    dimension: Mapping[str, object],
) -> tuple[StrategyProfile, StrategyProfile]:
    counts = terminal["action_counts"]
    action_group = dimension["action_group"]
    baseline_wire = dimension["baseline_rate"]
    if (
        not isinstance(counts, dict)
        or not isinstance(action_group, list)
        or not action_group
        or any(not isinstance(action, str) or not action for action in action_group)
        or not isinstance(baseline_wire, str)
    ):
        raise ValueError("Validation R008 policy reconstruction inputs are invalid")
    baseline_rate = float(Decimal(baseline_wire))
    baseline_table = ActionBaselineTable(
        table_version="phase6-frozen-r008-baseline-v1",
        rules=(
            ActionLeakRule(
                reason_id=_R008_REASON_ID,
                leak_type=_R008_LEAK_TYPE,
                action_group=tuple(action_group),
                baseline_rate=baseline_rate,
                direction=_R008_DIRECTION,
                situation_overrides={_R008_SITUATION_KEY: baseline_rate},
            ),
        ),
    )
    detector_config = LeakDetectorConfig(
        min_effective_sample_size=candidate.sample_floor,
        min_deviation=float(Decimal(_TAU_WIRE)),
        min_confidence=float(Decimal(candidate.detector_confidence)),
        rule_exploit_min_confidence=float(Decimal(candidate.provider_confidence)),
        nodelock_exploit_min_confidence=float(Decimal(candidate.provider_confidence)),
    )
    stats = ActionStats(
        _R008_SITUATION_KEY,
        terminal["opportunity_count"],
        counts,
    )
    leaks = LeakDetector(baseline_table, detector_config).detect_for_situation(
        (stats,),
        _R008_SITUATION_KEY,
    )
    node_lock = nodelock_config_from_leaks(
        leaks,
        hero_position="OOP",
        min_confidence=float(Decimal(candidate.provider_confidence)),
    )
    game = opponent.game
    hero_infosets = game.infosets_of(0)
    base = {infoset: dict(opponent.equilibrium_strategy[infoset]) for infoset in hero_infosets}
    exploit = {infoset: dict(distribution) for infoset, distribution in base.items()}
    if node_lock is not None:
        application = apply_node_locks(
            game,
            opponent.equilibrium_strategy,
            node_lock,
            reach_weights=river_infoset_reach_weights(
                game,
                opponent.equilibrium_strategy,
            ),
        )
        best_actions = best_response_strategy(game, 0, application.profile)
        for infoset in hero_infosets:
            if infoset.endswith(":vs_bet"):
                exploit[infoset] = {
                    action: float(action == best_actions[infoset])
                    for action in game.actions_of(infoset)
                }
    final = {
        infoset: safety_mix(
            base[infoset],
            exploit[infoset],
            float(Decimal(candidate.safety_alpha)),
        )
        for infoset in hero_infosets
    }
    return base, final


def _policy_from_payload(payload: object, label: str) -> dict[str, dict[str, float]]:
    if not isinstance(payload, dict) or not payload:
        raise ValueError(f"Validation {label} must be a non-empty object")
    result: dict[str, dict[str, float]] = {}
    for infoset, distribution in payload.items():
        if not isinstance(infoset, str) or not infoset or not isinstance(distribution, dict):
            raise ValueError(f"Validation {label} is not a closed strategy mapping")
        if not distribution:
            raise ValueError(f"Validation {label} contains an empty distribution")
        parsed: dict[str, float] = {}
        for action, wire in distribution.items():
            if not isinstance(action, str) or not action or not isinstance(wire, str):
                raise ValueError(f"Validation {label} action distribution is invalid")
            try:
                value = float.fromhex(wire)
            except ValueError as exc:
                raise ValueError(f"Validation {label} probability is not binary64 hex") from exc
            if not math.isfinite(value) or value < 0 or value.hex() != wire:
                raise ValueError(f"Validation {label} probability is not canonical finite binary64")
            parsed[action] = value
        result[infoset] = parsed
    return result


def _profile_payload(profile: Mapping[str, Mapping[str, float]]) -> dict[str, object]:
    return {
        infoset: {
            action: probability.hex() for action, probability in sorted(profile[infoset].items())
        }
        for infoset in sorted(profile)
    }


def _exact_ev_payload(cell: ExactEvCell) -> dict[str, object]:
    return {
        "game_id": cell.profiles.game_id,
        "opponent_id": cell.profiles.opponent_id,
        "hero_player": cell.profiles.hero_player,
        "profiles": {
            "base": _profile_payload(cell.profiles.base),
            "final": _profile_payload(cell.profiles.final),
            "oracle_br": _profile_payload(cell.profiles.oracle_br),
        },
        "base_ev": _ev_paths_payload(cell.base_ev.production, cell.base_ev.independent_leaves),
        "final_ev": _ev_paths_payload(
            cell.final_ev.production,
            cell.final_ev.independent_leaves,
        ),
        "oracle_br_ev": _ev_paths_payload(
            cell.oracle_br_ev.production,
            cell.oracle_br_ev.independent_leaves,
        ),
        "gain_binary64_hex": cell.gain.hex(),
        "opportunity_binary64_hex": cell.opportunity.hex(),
        "efficiency_binary64_hex": None if cell.efficiency is None else cell.efficiency.hex(),
        "efficiency_status": cell.efficiency_status,
    }


def _ev_paths_payload(production: float, independent: float) -> dict[str, str]:
    return {
        "production_binary64_hex": production.hex(),
        "independent_leaves_binary64_hex": independent.hex(),
    }


def _json_ready(value: object) -> object:
    if isinstance(value, Decimal):
        return _decimal_wire(value)
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _json_ready(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_json_ready(item) for item in value]
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    raise TypeError(f"unsupported Validation result value {type(value).__name__}")


def _canonical_calibration_artifact(payload: dict[str, object]) -> CanonicalCalibrationArtifact:
    raw = canonical_json_bytes(payload)
    return CanonicalCalibrationArtifact(raw, sha256_bytes(raw))


def _contract_refs(bundle: ValidatedPhase6ContractBundle) -> dict[str, object]:
    return {
        "preregistration": bundle.root_manifest["preregistration"],
        "coverage_semantics_contract": bundle.root_manifest["coverage_semantics_contract"],
        "selection_metric_contract": bundle.root_manifest["selection_metric_contract"],
        "series_reference": bundle.root_manifest["series_reference"],
    }


def _contract_bundle_for_plan(
    plan: ValidationBatchPlan,
    repo_root: Path,
) -> ValidatedPhase6ContractBundle:
    run_reference = plan.manifest["training_source"]["run_manifest"]
    if not isinstance(run_reference, dict) or set(run_reference) != {"path", "sha256"}:
        raise ValueError("Validation plan Training run reference is not closed-world")
    run_path = _repo_relative_path(repo_root, run_reference["path"], "Training run manifest")
    run_raw = run_path.read_bytes()
    if sha256_bytes(run_raw) != run_reference["sha256"]:
        raise ValueError("Validation plan Training run manifest hash mismatch")
    run = _strict_object(run_raw, "Training run manifest")
    inputs = run.get("inputs")
    if not isinstance(inputs, dict):
        raise ValueError("Training run manifest inputs are invalid")
    reference = inputs.get("phase6_contract_manifest")
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
        raise ValueError("Phase 6 contract manifest reference is not closed-world")
    contract_path = _repo_relative_path(
        repo_root,
        reference["path"],
        "Phase 6 contract manifest",
    )
    return load_phase6_contract_bundle(contract_path, expected_sha256=reference["sha256"])


def _repo_relative_path(root: Path, relative: object, label: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError(f"{label} path must be POSIX relative")
    value = Path(relative)
    if value.is_absolute() or ".." in value.parts:
        raise ValueError(f"{label} path escapes the repository")
    resolved = (root / value).resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"{label} path escapes the repository")
    return resolved


def _selection_report(plan, ranked, aggregate_hash):
    candidate_map = {item.candidate_id: item for item in plan.candidates}
    return {
        "schema_version": PRIMARY_SELECTION_REPORT_SCHEMA_VERSION,
        "artifact_type": "primary_selection_report",
        "split": "validation",
        "validation_batch_manifest_sha256": plan.manifest_sha256,
        "aggregate_metrics_sha256": aggregate_hash,
        "selection_contract_sha256": plan.manifest["selection_metric_contract"]["sha256"],
        "selection_keys": [
            {"metric_id": metric_id, "direction": direction}
            for metric_id, direction in PRIMARY_SELECTION_KEYS
        ],
        "candidate_count": 16,
        "ranked_candidates": [
            {
                "rank": index,
                "candidate": _candidate_entry(candidate_map[item.candidate_id]),
                "sort_keys": {
                    "validation_macro_brier": _decimal_wire(item.validation_macro_brier),
                    "validation_micro_brier": _decimal_wire(item.validation_micro_brier),
                    "gto_negative_control_micro_fpr_v1": {
                        "false_positives": item.gto_false_positives,
                        "total_negatives": item.gto_total_negatives,
                    },
                    "validation_macro_exploitation_efficiency": _optional_decimal_wire(
                        item.validation_macro_exploitation_efficiency
                    ),
                    "validation_macro_recall": _optional_decimal_wire(item.validation_macro_recall),
                    "validation_macro_precision": _optional_decimal_wire(
                        item.validation_macro_precision
                    ),
                    "canonical_candidate_id": item.candidate_id,
                },
            }
            for index, item in enumerate(ranked, start=1)
        ],
        "selected_candidate_id": ranked[0].candidate_id,
    }


def _selected_lock(plan, selected, report_hash):
    candidate = next(item for item in plan.candidates if item.candidate_id == selected.candidate_id)
    config = candidate.canonical_payload()
    return {
        "schema_version": SELECTED_CONFIG_LOCK_SCHEMA_VERSION,
        "artifact_type": "selected_config_lock",
        "split": "validation",
        "validation_batch_manifest_sha256": plan.manifest_sha256,
        "primary_selection_report_sha256": report_hash,
        "selected_config_count": 1,
        "selected_candidate_id": candidate.candidate_id,
        "selected_config": config,
        "selected_config_sha256": sha256_bytes(canonical_json_bytes(config)),
        "manual_override": False,
    }


def _backend_identity(backend):
    identity = {
        "backend_id": getattr(backend, "backend_id", None),
        "backend_version": getattr(backend, "backend_version", None),
    }
    _validate_backend_identity(identity)
    return identity


def _validate_backend_identity(identity):
    if not isinstance(identity, dict) or set(identity) != {"backend_id", "backend_version"}:
        raise ValueError("Validation backend identity is not closed-world")
    if (
        any(
            not isinstance(value, str)
            or not value
            or not value.isascii()
            or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for character in value
            )
            for value in identity.values()
        )
        or _BACKEND_ID.fullmatch(identity["backend_id"]) is None
        or _BACKEND_VERSION.fullmatch(identity["backend_version"]) is None
        or any(
            token in {"training", "test"}
            for value in identity.values()
            for token in re.split(r"[^a-z0-9]+", value)
        )
    ):
        raise ValueError("Validation backend identity is not Validation-only")


def _stream_roots(key):
    return tuple(
        derive_stream_root(
            split="validation",
            opponent_id=key.opponent_id,
            horizon=key.horizon,
            repetition_id=key.repetition_id,
            stream_name=name,
        )
        for name in STREAM_NAMES
    )


def _stream_root_entries(key):
    return [{"digest": item.digest, "payload": item.payload} for item in _stream_roots(key)]


def _candidate_entry(candidate):
    return {"candidate_id": candidate.candidate_id, "config": candidate.canonical_payload()}


def _session_record(key, payload):
    return ValidationArtifactRecord(
        key.candidate_id,
        sha256_bytes(canonical_json_bytes(payload)),
        payload,
        key.opponent_id,
        key.horizon,
        key.repetition_id,
    )


def _candidate_record(candidate_id, payload):
    return ValidationArtifactRecord(
        candidate_id, sha256_bytes(canonical_json_bytes(payload)), payload
    )


def _session_join_sha256(candidate_id, records_by_type):
    return sha256_bytes(
        canonical_json_bytes(
            {
                "candidate_id": candidate_id,
                "session_artifacts": [
                    {
                        "artifact_type": artifact_type,
                        "records": [
                            {
                                "session": record.session_key().canonical_payload(),
                                "payload_sha256": record.payload_sha256,
                            }
                            for record in records_by_type[artifact_type]
                            if record.candidate_id == candidate_id
                        ],
                    }
                    for artifact_type in _SESSION_ARTIFACT_TYPE_ORDER
                ],
            }
        )
    )


def _validate_records(artifact_type, records, *, expected_sessions, candidate_ids):
    if any(not isinstance(item, ValidationArtifactRecord) for item in records):
        raise TypeError("Validation artifacts require ValidationArtifactRecord values")
    for record in records:
        _validate_sha256(record.payload_sha256, "Validation record payload hash")
        if sha256_bytes(canonical_json_bytes(record.payload)) != record.payload_sha256:
            raise ValueError("Validation record payload hash mismatch")
    if artifact_type in _SESSION_ARTIFACT_TYPES:
        keys = [item.session_key() for item in records]
        if keys != list(sorted(expected_sessions)) or len(set(keys)) != 12960:
            raise ValueError("Validation session artifact does not match the complete product")
    else:
        ids = [item.candidate_id for item in records]
        if ids != sorted(candidate_ids) or any(
            value is not None
            for item in records
            for value in (item.opponent_id, item.horizon, item.repetition_id)
        ):
            raise ValueError("Validation candidate artifact does not match all candidates")


def _record_from_payload(payload):
    if not isinstance(payload, dict) or set(payload) != {
        "candidate_id",
        "horizon",
        "opponent_id",
        "payload",
        "payload_sha256",
        "repetition_id",
    }:
        raise ValueError("Validation artifact record is not closed-world")
    return ValidationArtifactRecord(
        payload["candidate_id"],
        payload["payload_sha256"],
        payload["payload"],
        payload["opponent_id"],
        payload["horizon"],
        payload["repetition_id"],
    )


def _canonical_result(value):
    try:
        return json.loads(canonical_json_bytes(value))
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Validation backend result is not canonical-JSON compatible") from exc


def _decimal_wire(value):
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ValueError("Selection metric must be a finite Decimal")
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return "0" if text == "-0" else text


def _optional_decimal_wire(value):
    return None if value is None else _decimal_wire(value)


def _validation_root(path):
    resolved = path.resolve()
    foreign_namespace = any(
        part.lower() in {"training", "test"}
        or _FOREIGN_NAMESPACE.fullmatch(part.lower()) is not None
        for part in resolved.parts[:-2]
    )
    if (
        resolved.name != VALIDATION_PHYSICAL_DIRECTORY
        or resolved.parent.name != VALIDATION_ARTIFACT_BASE_DIRECTORY
        or foreign_namespace
    ):
        raise ValueError("Validation artifacts require an isolated validation directory")
    return resolved


def _child(root, relative):
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("Validation artifact path must be POSIX relative")
    value = Path(relative)
    if value.is_absolute() or len(value.parts) != 1 or ".." in value.parts:
        raise ValueError("Validation artifact path must be a direct child")
    resolved = (root / value).resolve()
    if resolved.parent != root:
        raise ValueError("Validation artifact path escapes its root")
    return resolved


def _write_exclusive(path, raw):
    with path.open("xb") as handle:
        handle.write(raw)


def _strict_object(raw, label):
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise ValueError(f"{label} bytes are not canonical")
    return value


def _validate_sha256(value, label):
    if not isinstance(value, str) or len(value) != 64 or any(char not in _SHA256 for char in value):
        raise ValueError(f"{label} must be lowercase SHA-256")


__all__ = [
    "PRIMARY_SELECTION_REPORT_SCHEMA_VERSION",
    "SELECTED_CONFIG_LOCK_SCHEMA_VERSION",
    "VALIDATION_AGGREGATE_RESULT_SCHEMA_VERSION",
    "VALIDATION_ARTIFACT_BASE_DIRECTORY",
    "VALIDATION_CALIBRATION_RESULT_SCHEMA_VERSION",
    "VALIDATION_EXECUTION_ADAPTER_VERSION",
    "VALIDATION_EXECUTION_ARTIFACT_SCHEMA_VERSION",
    "VALIDATION_EXECUTION_RECORD_SCHEMA_VERSION",
    "VALIDATION_EXACT_EV_RESULT_SCHEMA_VERSION",
    "VALIDATION_HERO_POLICY_RESULT_SCHEMA_VERSION",
    "VALIDATION_PHYSICAL_DIRECTORY",
    "VALIDATION_ROOT_MANIFEST_SCHEMA_VERSION",
    "VALIDATION_TERMINAL_RESULT_SCHEMA_VERSION",
    "VALIDATION_WRITER_VERSION",
    "ValidationArtifactBundle",
    "ValidationArtifactRecord",
    "ValidationCandidateRequest",
    "ValidationCandidateResult",
    "ValidationExecutionBackend",
    "ValidationSessionRequest",
    "ValidationSessionResult",
    "run_single_validation_candidate_execution",
    "run_validation_execution_adapter",
    "verify_single_validation_candidate_records",
    "verify_validation_artifact_root",
    "verify_validation_execution_records",
    "write_validation_artifact_bundle",
]
