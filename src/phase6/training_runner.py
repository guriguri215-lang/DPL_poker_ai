"""Training-only P6-7 batch planning and canonical artifact writing.

The module never opens the Validation catalog and contains no league execution
backend.  A caller supplies completed session records; this boundary lets unit
fixtures exercise the orchestration and artifact contract without running
Training.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from opponents import load_training_catalog
from opponents.model import OpponentModelConfig

from .contracts import canonical_json_bytes, sha256_bytes
from .p6_7 import (
    REPETITION_SEEDS,
    STREAM_NAMES,
    PrimaryCandidate,
    StreamRoot,
    derive_stream_root,
    primary_candidate_grid,
    validate_primary_candidate_grid,
    validate_sampling_contract,
)

TRAINING_BATCH_SCHEMA_VERSION = "phase6-training-batch-manifest-v1"
TRAINING_ARTIFACT_SCHEMA_VERSION = "phase6-training-artifact-v1"
TRAINING_EXECUTION_ARTIFACT_SCHEMA_VERSION = "phase6-training-execution-artifact-v1"
TRAINING_SELECTION_SCHEMA_VERSION = "phase6-training-selection-report-v1"
TRAINING_RUNNER_VERSION = "p6-7-training-only-runner-v1"
TRAINING_EXECUTION_ADAPTER_VERSION = "p6-7-training-execution-adapter-v1"
TRAINING_EXECUTION_RECORD_SCHEMA_VERSION = "phase6-training-execution-record-v1"
HORIZONS = (50, 200, 1000)

_ARTIFACT_TYPES = (
    "terminal_candidate_snapshots",
    "hero_policy_snapshots",
    "exact_ev_cells",
    "calibration_cells",
    "aggregate_metrics",
)
_SESSION_ARTIFACT_TYPES = frozenset(_ARTIFACT_TYPES[:3])
_CANDIDATE_ARTIFACT_TYPES = frozenset(_ARTIFACT_TYPES[3:])
_SHA256_CHARS = frozenset("0123456789abcdef")
_TRAINING_EXECUTION_BUNDLE_KIND = "training_execution"


@dataclass(frozen=True, order=True, slots=True)
class TrainingSessionKey:
    candidate_id: str
    opponent_id: str
    horizon: int
    repetition_id: str

    def canonical_payload(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "horizon": self.horizon,
            "opponent_id": self.opponent_id,
            "repetition_id": self.repetition_id,
        }


@dataclass(frozen=True, slots=True)
class TrainingArtifactRecord:
    """A canonical payload and its hash for one approved result key."""

    candidate_id: str
    payload_sha256: str
    payload: object
    opponent_id: str | None = None
    horizon: int | None = None
    repetition_id: str | None = None

    def session_key(self) -> TrainingSessionKey:
        if self.opponent_id is None or self.horizon is None or self.repetition_id is None:
            raise ValueError("session artifact record is missing its complete session key")
        return TrainingSessionKey(
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
class TrainingBatchPlan:
    manifest: dict[str, object]
    manifest_bytes: bytes
    manifest_sha256: str
    candidates: tuple[PrimaryCandidate, ...]
    sessions: tuple[TrainingSessionKey, ...]


@dataclass(frozen=True, slots=True)
class TrainingArtifactBundle:
    root: Path
    references: dict[str, dict[str, object]]


@dataclass(frozen=True, slots=True)
class TrainingSessionRequest:
    """One approved Training session with all candidate-independent stream roots."""

    key: TrainingSessionKey
    candidate: PrimaryCandidate
    opponent: OpponentModelConfig
    stream_roots: tuple[StreamRoot, ...]


@dataclass(frozen=True, slots=True)
class TrainingSessionResult:
    """The three session-level products returned by a Training execution backend."""

    split: str
    key: TrainingSessionKey
    stream_roots: tuple[StreamRoot, ...]
    terminal_candidate_snapshot: object
    hero_policy_snapshot: object
    exact_ev_cell: object


@dataclass(frozen=True, slots=True)
class TrainingCandidateRequest:
    """All completed session products required to evaluate one candidate."""

    candidate: PrimaryCandidate
    session_results: tuple[TrainingSessionResult, ...]
    session_join_sha256: str


@dataclass(frozen=True, slots=True)
class TrainingCandidateResult:
    """The two candidate-level products returned by a Training execution backend."""

    split: str
    candidate_id: str
    session_join_sha256: str
    calibration_cell: object
    aggregate_metrics: object


class TrainingExecutionBackend(Protocol):
    """Training-only bridge to existing session, solver, and evaluator execution."""

    backend_id: str
    backend_version: str

    def run_sessions(
        self, requests: Sequence[TrainingSessionRequest]
    ) -> Sequence[TrainingSessionResult]: ...

    def evaluate_candidates(
        self, requests: Sequence[TrainingCandidateRequest]
    ) -> Sequence[TrainingCandidateResult]: ...


def run_training_execution_adapter(
    plan: TrainingBatchPlan,
    backend: TrainingExecutionBackend,
) -> dict[str, tuple[TrainingArtifactRecord, ...]]:
    """Execute an approved plan through a Training-only backend and bind provenance."""
    _validate_plan(plan)
    backend_identity = _backend_identity(backend)
    opponents = {item.opponent_id: item for item in load_training_catalog()}
    candidates = {item.candidate_id: item for item in plan.candidates}
    requests = tuple(
        TrainingSessionRequest(
            key=key,
            candidate=candidates[key.candidate_id],
            opponent=opponents[key.opponent_id],
            stream_roots=tuple(
                derive_stream_root(
                    split="training",
                    opponent_id=key.opponent_id,
                    horizon=key.horizon,
                    repetition_id=key.repetition_id,
                    stream_name=stream_name,
                )
                for stream_name in STREAM_NAMES
            ),
        )
        for key in plan.sessions
    )
    session_results = tuple(backend.run_sessions(requests))
    if [item.key for item in session_results if isinstance(item, TrainingSessionResult)] != [
        item.key for item in requests
    ] or len(session_results) != len(requests):
        raise ValueError("Training backend session results are missing, duplicate, or out of order")

    session_records: dict[str, list[TrainingArtifactRecord]] = {
        artifact_type: [] for artifact_type in _SESSION_ARTIFACT_TYPES
    }
    normalized_results: list[TrainingSessionResult] = []
    for request, result in zip(requests, session_results, strict=True):
        if not isinstance(result, TrainingSessionResult):
            raise TypeError("Training backend must return TrainingSessionResult values")
        if result.split != "training":
            raise ValueError("Training backend returned a non-Training split")
        if result.key != request.key or result.stream_roots != request.stream_roots:
            raise ValueError("Training backend session provenance does not match its request")
        values = {
            "terminal_candidate_snapshots": _canonical_backend_payload(
                result.terminal_candidate_snapshot
            ),
            "hero_policy_snapshots": _canonical_backend_payload(result.hero_policy_snapshot),
            "exact_ev_cells": _canonical_backend_payload(result.exact_ev_cell),
        }
        normalized = TrainingSessionResult(
            result.split,
            result.key,
            result.stream_roots,
            values["terminal_candidate_snapshots"],
            values["hero_policy_snapshots"],
            values["exact_ev_cells"],
        )
        normalized_results.append(normalized)
        for artifact_type, value in values.items():
            payload = _session_execution_payload(
                plan, request, artifact_type, value, backend_identity
            )
            session_records[artifact_type].append(_record_for_payload(request.key, payload))

    results_by_candidate: dict[str, list[TrainingSessionResult]] = {
        candidate.candidate_id: [] for candidate in plan.candidates
    }
    for result in normalized_results:
        results_by_candidate[result.key.candidate_id].append(result)
    candidate_requests = tuple(
        TrainingCandidateRequest(
            candidate,
            tuple(results_by_candidate[candidate.candidate_id]),
            _candidate_session_join_sha256(candidate.candidate_id, session_records),
        )
        for candidate in plan.candidates
    )
    candidate_results = tuple(backend.evaluate_candidates(candidate_requests))
    if [
        item.candidate_id for item in candidate_results if isinstance(item, TrainingCandidateResult)
    ] != [item.candidate.candidate_id for item in candidate_requests] or len(
        candidate_results
    ) != len(candidate_requests):
        raise ValueError(
            "Training backend candidate results are missing, duplicate, or out of order"
        )

    candidate_records: dict[str, list[TrainingArtifactRecord]] = {
        artifact_type: [] for artifact_type in _CANDIDATE_ARTIFACT_TYPES
    }
    for request, result in zip(candidate_requests, candidate_results, strict=True):
        if not isinstance(result, TrainingCandidateResult):
            raise TypeError("Training backend must return TrainingCandidateResult values")
        if result.split != "training":
            raise ValueError("Training backend returned a non-Training split")
        if (
            result.candidate_id != request.candidate.candidate_id
            or result.session_join_sha256 != request.session_join_sha256
        ):
            raise ValueError("Training backend candidate provenance does not match its request")
        values = {
            "calibration_cells": _canonical_backend_payload(result.calibration_cell),
            "aggregate_metrics": _canonical_backend_payload(result.aggregate_metrics),
        }
        for artifact_type, value in values.items():
            payload = _candidate_execution_payload(
                plan, request, artifact_type, value, backend_identity
            )
            candidate_records[artifact_type].append(
                _candidate_record_for_payload(request.candidate.candidate_id, payload)
            )

    records = {
        artifact_type: tuple(
            session_records[artifact_type]
            if artifact_type in session_records
            else candidate_records[artifact_type]
        )
        for artifact_type in _ARTIFACT_TYPES
    }
    verify_training_execution_records(plan, records)
    return records


def verify_training_execution_records(
    plan: TrainingBatchPlan,
    records_by_type: Mapping[str, Sequence[TrainingArtifactRecord]],
) -> None:
    """Independently reconstruct every adapter envelope and five-way Training join."""
    _validate_plan(plan)
    if set(records_by_type) != set(_ARTIFACT_TYPES):
        raise ValueError("Training execution records must contain exactly five result types")
    expected_sessions = set(plan.sessions)
    candidate_ids = {candidate.candidate_id for candidate in plan.candidates}
    candidates = {item.candidate_id: item for item in plan.candidates}
    opponents = {item.opponent_id: item for item in load_training_catalog()}
    backend_identity: dict[str, str] | None = None
    session_records: dict[str, list[TrainingArtifactRecord]] = {}

    for artifact_type in _ARTIFACT_TYPES:
        records = tuple(records_by_type[artifact_type])
        _validate_artifact_records(
            artifact_type,
            records,
            expected_sessions=expected_sessions,
            candidate_ids=candidate_ids,
        )
        for record in records:
            payload = record.payload
            if not isinstance(payload, dict):
                raise ValueError("Training execution payload must be an object")
            common_fields = {
                "schema_version",
                "adapter_version",
                "artifact_type",
                "training_batch_manifest_sha256",
                "split",
                "candidate",
                "backend",
                "result",
            }
            expected_fields = (
                common_fields | {"session", "opponent", "stream_roots"}
                if artifact_type in _SESSION_ARTIFACT_TYPES
                else common_fields | {"source_session_join_sha256"}
            )
            if set(payload) != expected_fields:
                raise ValueError("Training execution payload fields are not closed-world")
            if (
                payload["schema_version"] != TRAINING_EXECUTION_RECORD_SCHEMA_VERSION
                or payload["adapter_version"] != TRAINING_EXECUTION_ADAPTER_VERSION
                or payload["artifact_type"] != artifact_type
                or payload["training_batch_manifest_sha256"] != plan.manifest_sha256
                or payload["split"] != "training"
            ):
                raise ValueError("Training execution payload provenance mismatch")
            current_backend = payload["backend"]
            if not isinstance(current_backend, dict):
                raise ValueError("Training execution backend identity must be an object")
            _validate_backend_identity(current_backend)
            if backend_identity is None:
                backend_identity = current_backend
            elif current_backend != backend_identity:
                raise ValueError("Training execution records mix backend identities")
            expected_candidate = candidates[record.candidate_id]
            if payload["candidate"] != _candidate_entry(expected_candidate):
                raise ValueError("Training execution candidate provenance mismatch")
            _canonical_backend_payload(payload["result"])
            if artifact_type in _SESSION_ARTIFACT_TYPES:
                key = record.session_key()
                expected_roots = _stream_root_entries(key)
                if (
                    payload["session"] != key.canonical_payload()
                    or payload["opponent"] != _opponent_entry(opponents[key.opponent_id])
                    or payload["stream_roots"] != expected_roots
                ):
                    raise ValueError("Training execution session provenance mismatch")
        if artifact_type in _SESSION_ARTIFACT_TYPES:
            session_records[artifact_type] = list(records)

    for artifact_type in _CANDIDATE_ARTIFACT_TYPES:
        for record in records_by_type[artifact_type]:
            expected_join = _candidate_session_join_sha256(record.candidate_id, session_records)
            if record.payload["source_session_join_sha256"] != expected_join:
                raise ValueError(
                    "Training candidate result is not bound to its complete session join"
                )


def _backend_identity(backend: TrainingExecutionBackend) -> dict[str, str]:
    identity = {
        "backend_id": getattr(backend, "backend_id", None),
        "backend_version": getattr(backend, "backend_version", None),
    }
    _validate_backend_identity(identity)
    return identity


def _validate_backend_identity(identity: Mapping[str, object]) -> None:
    if set(identity) != {"backend_id", "backend_version"} or any(
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for character in value)
        for value in identity.values()
    ):
        raise ValueError("Training backend identity must use lowercase stable identifiers")


def _canonical_backend_payload(payload: object) -> object:
    try:
        raw = canonical_json_bytes(payload)
        return json.loads(raw)
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Training backend payload is not canonical-JSON compatible") from exc


def _candidate_entry(candidate: PrimaryCandidate) -> dict[str, object]:
    return {"candidate_id": candidate.candidate_id, "config": candidate.canonical_payload()}


def _opponent_entry(opponent: OpponentModelConfig) -> dict[str, object]:
    return {
        "opponent_id": opponent.opponent_id,
        "config_sha256": opponent.config_sha256,
        "config": opponent.canonical_payload(),
    }


def _stream_root_entries(key: TrainingSessionKey) -> list[dict[str, object]]:
    return [
        {"digest": root.digest, "payload": root.payload}
        for stream_name in STREAM_NAMES
        for root in (
            derive_stream_root(
                split="training",
                opponent_id=key.opponent_id,
                horizon=key.horizon,
                repetition_id=key.repetition_id,
                stream_name=stream_name,
            ),
        )
    ]


def _session_execution_payload(
    plan: TrainingBatchPlan,
    request: TrainingSessionRequest,
    artifact_type: str,
    result: object,
    backend_identity: dict[str, str],
) -> dict[str, object]:
    return {
        "schema_version": TRAINING_EXECUTION_RECORD_SCHEMA_VERSION,
        "adapter_version": TRAINING_EXECUTION_ADAPTER_VERSION,
        "artifact_type": artifact_type,
        "training_batch_manifest_sha256": plan.manifest_sha256,
        "split": "training",
        "candidate": _candidate_entry(request.candidate),
        "session": request.key.canonical_payload(),
        "opponent": _opponent_entry(request.opponent),
        "stream_roots": [
            {"digest": root.digest, "payload": root.payload} for root in request.stream_roots
        ],
        "backend": backend_identity,
        "result": result,
    }


def _candidate_execution_payload(
    plan: TrainingBatchPlan,
    request: TrainingCandidateRequest,
    artifact_type: str,
    result: object,
    backend_identity: dict[str, str],
) -> dict[str, object]:
    return {
        "schema_version": TRAINING_EXECUTION_RECORD_SCHEMA_VERSION,
        "adapter_version": TRAINING_EXECUTION_ADAPTER_VERSION,
        "artifact_type": artifact_type,
        "training_batch_manifest_sha256": plan.manifest_sha256,
        "split": "training",
        "candidate": _candidate_entry(request.candidate),
        "source_session_join_sha256": request.session_join_sha256,
        "backend": backend_identity,
        "result": result,
    }


def _record_for_payload(
    key: TrainingSessionKey, payload: dict[str, object]
) -> TrainingArtifactRecord:
    return TrainingArtifactRecord(
        candidate_id=key.candidate_id,
        opponent_id=key.opponent_id,
        horizon=key.horizon,
        repetition_id=key.repetition_id,
        payload=payload,
        payload_sha256=sha256_bytes(canonical_json_bytes(payload)),
    )


def _candidate_record_for_payload(
    candidate_id: str, payload: dict[str, object]
) -> TrainingArtifactRecord:
    return TrainingArtifactRecord(
        candidate_id=candidate_id,
        payload=payload,
        payload_sha256=sha256_bytes(canonical_json_bytes(payload)),
    )


def _candidate_session_join_sha256(
    candidate_id: str,
    records_by_type: Mapping[str, Sequence[TrainingArtifactRecord]],
) -> str:
    hashes_by_type: dict[str, dict[TrainingSessionKey, str]] = {}
    for artifact_type in _SESSION_ARTIFACT_TYPES:
        hashes_by_type[artifact_type] = {
            record.session_key(): record.payload_sha256
            for record in records_by_type[artifact_type]
            if record.candidate_id == candidate_id
        }
    keys = sorted(hashes_by_type["terminal_candidate_snapshots"])
    if not keys or any(set(values) != set(keys) for values in hashes_by_type.values()):
        raise ValueError("Training candidate session join is incomplete")
    payload = {
        "candidate_id": candidate_id,
        "sessions": [
            {
                "session": key.canonical_payload(),
                "terminal_candidate_snapshot_sha256": hashes_by_type[
                    "terminal_candidate_snapshots"
                ][key],
                "hero_policy_snapshot_sha256": hashes_by_type["hero_policy_snapshots"][key],
                "exact_ev_cell_sha256": hashes_by_type["exact_ev_cells"][key],
            }
            for key in keys
        ],
    }
    return sha256_bytes(canonical_json_bytes(payload))


def build_training_batch_plan(
    sampling_contract: Mapping[str, object],
    *,
    catalog_root: Path | str | None = None,
) -> TrainingBatchPlan:
    """Build the approved 16 x 9 x 3 x 30 Training plan without executing it."""
    validate_sampling_contract(sampling_contract)
    sampling_hash = sha256_bytes(canonical_json_bytes(dict(sampling_contract)))
    candidates = primary_candidate_grid(sampling_contract_sha256=sampling_hash)
    validate_primary_candidate_grid(candidates)
    kwargs = {} if catalog_root is None else {"catalog_root": catalog_root}
    opponents = load_training_catalog(**kwargs)
    _validate_training_catalog(opponents)

    sessions = tuple(
        sorted(
            TrainingSessionKey(candidate.candidate_id, opponent.opponent_id, horizon, repetition)
            for candidate in candidates
            for opponent in opponents
            for horizon in HORIZONS
            for repetition, _seed in REPETITION_SEEDS
        )
    )
    stream_roots = []
    seen_digests: set[str] = set()
    for opponent in opponents:
        for horizon in HORIZONS:
            for repetition, _seed in REPETITION_SEEDS:
                for stream_name in STREAM_NAMES:
                    root = derive_stream_root(
                        split="training",
                        opponent_id=opponent.opponent_id,
                        horizon=horizon,
                        repetition_id=repetition,
                        stream_name=stream_name,
                    )
                    if root.digest in seen_digests:
                        raise ValueError("Training stream-root digest collision")
                    seen_digests.add(root.digest)
                    stream_roots.append({"digest": root.digest, "payload": root.payload})

    manifest = {
        "schema_version": TRAINING_BATCH_SCHEMA_VERSION,
        "artifact_type": "training_batch_manifest",
        "runner_version": TRAINING_RUNNER_VERSION,
        "split": "training",
        "sampling_contract_sha256": sampling_hash,
        "opponents": [
            {
                "config_sha256": opponent.config_sha256,
                "equilibrium_artifact_sha256": opponent.equilibrium_artifact_sha256,
                "opponent_id": opponent.opponent_id,
            }
            for opponent in opponents
        ],
        "candidates": [
            {"candidate_id": candidate.candidate_id, "config": candidate.canonical_payload()}
            for candidate in candidates
        ],
        "horizons": list(HORIZONS),
        "repetitions": [
            {"master_seed": seed, "repetition_id": repetition}
            for repetition, seed in REPETITION_SEEDS
        ],
        "sessions": [session.canonical_payload() for session in sessions],
        "stream_roots": stream_roots,
        "expected_cardinality": {
            "candidate_count": 16,
            "opponent_count": 9,
            "horizon_count": 3,
            "repetition_count": 30,
            "session_count": 12960,
            "stream_root_count": 3240,
        },
        "artifact_bundle": _training_execution_artifact_bundle_contract(),
        "performance_based_top_n": None,
    }
    raw = canonical_json_bytes(manifest)
    return TrainingBatchPlan(manifest, raw, sha256_bytes(raw), candidates, sessions)


def write_training_artifact_bundle(
    plan: TrainingBatchPlan,
    records_by_type: Mapping[str, Sequence[TrainingArtifactRecord]],
    output_root: Path | str,
) -> TrainingArtifactBundle:
    """Validate a complete Training result join and write immutable canonical files."""
    _validate_plan(plan)
    if set(records_by_type) != set(_ARTIFACT_TYPES):
        raise ValueError(
            "Training artifact set must contain exactly the five approved result types"
        )
    root = Path(output_root)
    expected_sessions = set(plan.sessions)
    candidate_ids = {candidate.candidate_id for candidate in plan.candidates}
    payloads: dict[str, bytes] = {"training_batch_manifest": plan.manifest_bytes}
    execution_record_flags = [
        _is_execution_record_candidate(artifact_type, record.payload)
        for artifact_type in _ARTIFACT_TYPES
        for record in records_by_type[artifact_type]
    ]
    if not all(execution_record_flags):
        raise ValueError("Training execution manifest requires execution records")
    verify_training_execution_records(plan, records_by_type)
    artifact_schema_version = TRAINING_EXECUTION_ARTIFACT_SCHEMA_VERSION

    for artifact_type in _ARTIFACT_TYPES:
        records = tuple(records_by_type[artifact_type])
        _validate_artifact_records(
            artifact_type, records, expected_sessions=expected_sessions, candidate_ids=candidate_ids
        )
        records = tuple(
            sorted(
                records,
                key=lambda record: (
                    record.candidate_id,
                    record.opponent_id or "",
                    record.horizon if record.horizon is not None else -1,
                    record.repetition_id or "",
                ),
            )
        )
        payload = {
            "schema_version": artifact_schema_version,
            "artifact_type": artifact_type,
            "training_batch_manifest_sha256": plan.manifest_sha256,
            "records": [record.canonical_payload() for record in records],
        }
        payloads[artifact_type] = canonical_json_bytes(payload)

    selection = {
        "schema_version": TRAINING_SELECTION_SCHEMA_VERSION,
        "artifact_type": "training_selection_report",
        "training_batch_manifest_sha256": plan.manifest_sha256,
        "selection_policy": "retain_all_hard_gate_passing_candidates",
        "performance_based_top_n": None,
        "input_candidate_ids": sorted(candidate_ids),
        "retained_candidate_ids": sorted(candidate_ids),
        "excluded_candidates": [],
        "p6_8_candidate_count": 16,
    }
    payloads["training_selection_report"] = canonical_json_bytes(selection)

    references: dict[str, dict[str, object]] = {}
    for name, raw in payloads.items():
        relative_path = f"{name}.json"
        target = _resolve_output(root, relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() != raw:
            raise ValueError(f"refusing to overwrite immutable artifact {relative_path!r}")
        target.write_bytes(raw)
        references[name] = {
            "name": name,
            "path": relative_path,
            "sha256": sha256_bytes(raw),
        }
    return TrainingArtifactBundle(root.resolve(), references)


def verify_training_artifact_bundle(bundle: TrainingArtifactBundle) -> None:
    """Rehash every output and reject noncanonical bytes or reference substitution."""
    if set(bundle.references) != {
        "training_batch_manifest",
        *_ARTIFACT_TYPES,
        "training_selection_report",
    }:
        raise ValueError("Training bundle reference set is not closed-world")
    payloads: dict[str, dict[str, object]] = {}
    raw_by_name: dict[str, bytes] = {}
    for name, reference in bundle.references.items():
        if set(reference) != {"name", "path", "sha256"} or reference["name"] != name:
            raise ValueError("Training bundle reference shape mismatch")
        _validate_sha256(reference["sha256"], "artifact reference hash")
        path = _resolve_output(bundle.root, reference["path"])
        raw = path.read_bytes()
        if sha256_bytes(raw) != reference["sha256"]:
            raise ValueError("Training artifact hash mismatch")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Training artifact is not strict UTF-8 JSON") from exc
        if canonical_json_bytes(payload) != raw:
            raise ValueError("Training artifact bytes are not canonical")
        if not isinstance(payload, dict):
            raise ValueError("Training artifact root must be an object")
        payloads[name] = payload
        raw_by_name[name] = raw

    manifest = payloads["training_batch_manifest"]
    candidate_ids, expected_sessions = _validate_manifest_payload(manifest)
    manifest_hash = sha256_bytes(raw_by_name["training_batch_manifest"])
    records_by_type: dict[str, tuple[TrainingArtifactRecord, ...]] = {}
    bundle_contract = manifest["artifact_bundle"]
    expected_artifact_schemas = {
        item["artifact_type"]: item["schema_version"] for item in bundle_contract["artifacts"]
    }
    for artifact_type in _ARTIFACT_TYPES:
        payload = payloads[artifact_type]
        if set(payload) != {
            "schema_version",
            "artifact_type",
            "training_batch_manifest_sha256",
            "records",
        }:
            raise ValueError("Training result artifact fields are not closed-world")
        if (
            payload["schema_version"] != expected_artifact_schemas[artifact_type]
            or payload["artifact_type"] != artifact_type
            or payload["training_batch_manifest_sha256"] != manifest_hash
            or not isinstance(payload["records"], list)
        ):
            raise ValueError("Training result artifact provenance mismatch")
        records = tuple(_record_from_payload(item) for item in payload["records"])
        records_by_type[artifact_type] = records
        _validate_artifact_records(
            artifact_type,
            records,
            expected_sessions=expected_sessions,
            candidate_ids=candidate_ids,
        )

    verified_plan = TrainingBatchPlan(
        manifest=manifest,
        manifest_bytes=raw_by_name["training_batch_manifest"],
        manifest_sha256=manifest_hash,
        candidates=primary_candidate_grid(
            sampling_contract_sha256=manifest["sampling_contract_sha256"]
        ),
        sessions=tuple(sorted(expected_sessions)),
    )
    verify_training_execution_records(verified_plan, records_by_type)

    selection = payloads["training_selection_report"]
    if set(selection) != {
        "schema_version",
        "artifact_type",
        "training_batch_manifest_sha256",
        "selection_policy",
        "performance_based_top_n",
        "input_candidate_ids",
        "retained_candidate_ids",
        "excluded_candidates",
        "p6_8_candidate_count",
    }:
        raise ValueError("Training selection report fields are not closed-world")
    ordered_ids = sorted(candidate_ids)
    expected_selection = {
        "schema_version": TRAINING_SELECTION_SCHEMA_VERSION,
        "artifact_type": "training_selection_report",
        "training_batch_manifest_sha256": manifest_hash,
        "selection_policy": "retain_all_hard_gate_passing_candidates",
        "performance_based_top_n": None,
        "input_candidate_ids": ordered_ids,
        "retained_candidate_ids": ordered_ids,
        "excluded_candidates": [],
        "p6_8_candidate_count": 16,
    }
    if selection != expected_selection:
        raise ValueError("Training selection report changes the approved retain-all policy")


def _validate_training_catalog(opponents: Sequence[OpponentModelConfig]) -> None:
    if len(opponents) != 9 or any(item.split != "training" for item in opponents):
        raise ValueError("Training runner requires exactly nine Training opponents")
    if len({item.opponent_id for item in opponents}) != 9:
        raise ValueError("Training opponent IDs must be unique")
    if len({item.config_sha256 for item in opponents}) != 9:
        raise ValueError("Training opponent configs must be unique")
    if _training_opponent_entries(opponents) != _approved_training_opponent_entries():
        raise ValueError("Training catalog differs from the approved repository catalog")


def _training_opponent_entries(
    opponents: Sequence[OpponentModelConfig],
) -> list[dict[str, object]]:
    return [
        {
            "config_sha256": opponent.config_sha256,
            "equilibrium_artifact_sha256": opponent.equilibrium_artifact_sha256,
            "opponent_id": opponent.opponent_id,
        }
        for opponent in opponents
    ]


def _approved_training_opponent_entries() -> list[dict[str, object]]:
    approved = load_training_catalog()
    if len(approved) != 9 or any(item.split != "training" for item in approved):
        raise ValueError("approved repository Training catalog is invalid")
    return _training_opponent_entries(approved)


def _validate_plan(plan: TrainingBatchPlan) -> None:
    if sha256_bytes(plan.manifest_bytes) != plan.manifest_sha256:
        raise ValueError("Training manifest hash mismatch")
    if canonical_json_bytes(plan.manifest) != plan.manifest_bytes:
        raise ValueError("Training manifest bytes are not canonical")
    if plan.manifest.get("split") != "training" or len(plan.sessions) != 12960:
        raise ValueError("Training plan split or cardinality is invalid")
    if len(set(plan.sessions)) != len(plan.sessions):
        raise ValueError("Training plan contains duplicate session keys")
    validate_primary_candidate_grid(plan.candidates)
    candidate_ids, expected_sessions = _validate_manifest_payload(plan.manifest)
    if candidate_ids != {candidate.candidate_id for candidate in plan.candidates}:
        raise ValueError("Training manifest candidate set differs from the plan")
    if expected_sessions != set(plan.sessions):
        raise ValueError("Training manifest session set differs from the plan")
    if plan.manifest["sessions"] != [session.canonical_payload() for session in plan.sessions]:
        raise ValueError("Training manifest session order differs from the plan")


def _validate_artifact_records(
    artifact_type: str,
    records: Sequence[TrainingArtifactRecord],
    *,
    expected_sessions: set[TrainingSessionKey],
    candidate_ids: set[str],
) -> None:
    if any(not isinstance(record, TrainingArtifactRecord) for record in records):
        raise TypeError("Training artifacts require TrainingArtifactRecord values")
    for record in records:
        _validate_sha256(record.payload_sha256, "record payload hash")
        try:
            payload_sha256 = sha256_bytes(canonical_json_bytes(record.payload))
        except (TypeError, ValueError) as exc:
            raise ValueError("record payload is not canonical-JSON compatible") from exc
        if payload_sha256 != record.payload_sha256:
            raise ValueError("record payload hash does not match its canonical payload")
    if artifact_type in _SESSION_ARTIFACT_TYPES:
        keys = [record.session_key() for record in records]
        if len(keys) != len(set(keys)) or set(keys) != expected_sessions:
            raise ValueError(f"{artifact_type} does not exactly join the Training session set")
    elif artifact_type in _CANDIDATE_ARTIFACT_TYPES:
        if any(
            record.opponent_id is not None
            or record.horizon is not None
            or record.repetition_id is not None
            for record in records
        ):
            raise ValueError(f"{artifact_type} records must be candidate-level")
        ids = [record.candidate_id for record in records]
        if len(ids) != len(set(ids)) or set(ids) != candidate_ids:
            raise ValueError(f"{artifact_type} does not exactly join the candidate set")


def _is_execution_record_candidate(artifact_type: str, payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    marker_fields = {
        "adapter_version",
        "training_batch_manifest_sha256",
        "backend",
        "stream_roots",
        "source_session_join_sha256",
    }
    common_fields = {
        "schema_version",
        "adapter_version",
        "artifact_type",
        "training_batch_manifest_sha256",
        "split",
        "candidate",
        "backend",
        "result",
    }
    expected_fields = (
        common_fields | {"session", "opponent", "stream_roots"}
        if artifact_type in _SESSION_ARTIFACT_TYPES
        else common_fields | {"source_session_join_sha256"}
    )
    return (
        payload.get("schema_version") == TRAINING_EXECUTION_RECORD_SCHEMA_VERSION
        or bool(set(payload) & marker_fields)
        or set(payload) == expected_fields
    )


def _training_execution_artifact_bundle_contract() -> dict[str, object]:
    return {
        "bundle_kind": _TRAINING_EXECUTION_BUNDLE_KIND,
        "artifacts": [
            {
                "artifact_type": artifact_type,
                "schema_version": TRAINING_EXECUTION_ARTIFACT_SCHEMA_VERSION,
            }
            for artifact_type in _ARTIFACT_TYPES
        ],
    }


def _validate_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _SHA256_CHARS for character in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _record_from_payload(payload: object) -> TrainingArtifactRecord:
    if not isinstance(payload, dict) or set(payload) != {
        "candidate_id",
        "horizon",
        "opponent_id",
        "payload",
        "payload_sha256",
        "repetition_id",
    }:
        raise ValueError("Training artifact record fields are not closed-world")
    return TrainingArtifactRecord(
        candidate_id=payload["candidate_id"],
        payload_sha256=payload["payload_sha256"],
        payload=payload["payload"],
        opponent_id=payload["opponent_id"],
        horizon=payload["horizon"],
        repetition_id=payload["repetition_id"],
    )


def _validate_manifest_payload(
    manifest: Mapping[str, object],
) -> tuple[set[str], set[TrainingSessionKey]]:
    if set(manifest) != {
        "schema_version",
        "artifact_type",
        "runner_version",
        "split",
        "sampling_contract_sha256",
        "opponents",
        "candidates",
        "horizons",
        "repetitions",
        "sessions",
        "stream_roots",
        "expected_cardinality",
        "artifact_bundle",
        "performance_based_top_n",
    }:
        raise ValueError("Training batch manifest fields are not closed-world")
    if (
        manifest["schema_version"] != TRAINING_BATCH_SCHEMA_VERSION
        or manifest["artifact_type"] != "training_batch_manifest"
        or manifest["runner_version"] != TRAINING_RUNNER_VERSION
        or manifest["split"] != "training"
        or manifest["artifact_bundle"] != _training_execution_artifact_bundle_contract()
        or manifest["performance_based_top_n"] is not None
    ):
        raise ValueError("Training batch manifest version or split is invalid")
    sampling_hash = _validate_sha256(manifest["sampling_contract_sha256"], "sampling contract hash")
    opponents = manifest["opponents"]
    candidates = manifest["candidates"]
    repetitions = manifest["repetitions"]
    sessions = manifest["sessions"]
    stream_roots = manifest["stream_roots"]
    if not all(
        isinstance(value, list)
        for value in (opponents, candidates, repetitions, sessions, stream_roots)
    ):
        raise ValueError("Training batch manifest collections must be arrays")
    expected_opponents = _approved_training_opponent_entries()
    if opponents != expected_opponents:
        raise ValueError("Training manifest catalog is not the approved repository catalog")
    expected_candidates = primary_candidate_grid(sampling_contract_sha256=sampling_hash)
    expected_candidate_entries = [
        {"candidate_id": item.candidate_id, "config": item.canonical_payload()}
        for item in expected_candidates
    ]
    if candidates != expected_candidate_entries:
        raise ValueError("Training manifest candidates are not the approved canonical grid")
    opponent_ids = [item["opponent_id"] for item in expected_opponents]
    candidate_ids = [item.candidate_id for item in expected_candidates]
    if manifest["horizons"] != list(HORIZONS) or repetitions != [
        {"master_seed": seed, "repetition_id": repetition} for repetition, seed in REPETITION_SEEDS
    ]:
        raise ValueError("Training horizon or repetition mapping is not approved")
    cardinality = {
        "candidate_count": 16,
        "opponent_count": 9,
        "horizon_count": 3,
        "repetition_count": 30,
        "session_count": 12960,
        "stream_root_count": 3240,
    }
    if manifest["expected_cardinality"] != cardinality or len(stream_roots) != 3240:
        raise ValueError("Training manifest expected cardinality is invalid")
    expected_session_order = tuple(
        sorted(
            TrainingSessionKey(candidate_id, opponent_id, horizon, repetition)
            for candidate_id in candidate_ids
            for opponent_id in opponent_ids
            for horizon in HORIZONS
            for repetition, _seed in REPETITION_SEEDS
        )
    )
    if sessions != [session.canonical_payload() for session in expected_session_order]:
        raise ValueError("Training sessions do not exactly match the approved product")
    expected_roots = []
    for opponent_id in opponent_ids:
        for horizon in HORIZONS:
            for repetition, _seed in REPETITION_SEEDS:
                for stream_name in STREAM_NAMES:
                    root = derive_stream_root(
                        split="training",
                        opponent_id=opponent_id,
                        horizon=horizon,
                        repetition_id=repetition,
                        stream_name=stream_name,
                    )
                    expected_roots.append({"digest": root.digest, "payload": root.payload})
    if stream_roots != expected_roots:
        raise ValueError("Training stream roots do not exactly match the approved product")
    return set(candidate_ids), set(expected_session_order)


def _resolve_output(root: Path, relative_path: object) -> Path:
    if not isinstance(relative_path, str) or not relative_path or "\\" in relative_path:
        raise ValueError("artifact path must be a non-empty POSIX relative path")
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("artifact path must remain below the bundle root")
    resolved_root = root.resolve()
    resolved = (resolved_root / relative).resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ValueError("artifact path escapes the bundle root")
    return resolved


__all__ = [
    "HORIZONS",
    "TRAINING_ARTIFACT_SCHEMA_VERSION",
    "TRAINING_BATCH_SCHEMA_VERSION",
    "TRAINING_EXECUTION_ADAPTER_VERSION",
    "TRAINING_EXECUTION_ARTIFACT_SCHEMA_VERSION",
    "TRAINING_EXECUTION_RECORD_SCHEMA_VERSION",
    "TRAINING_RUNNER_VERSION",
    "TRAINING_SELECTION_SCHEMA_VERSION",
    "TrainingArtifactBundle",
    "TrainingArtifactRecord",
    "TrainingBatchPlan",
    "TrainingCandidateRequest",
    "TrainingCandidateResult",
    "TrainingExecutionBackend",
    "TrainingSessionKey",
    "TrainingSessionRequest",
    "TrainingSessionResult",
    "build_training_batch_plan",
    "run_training_execution_adapter",
    "verify_training_execution_records",
    "verify_training_artifact_bundle",
    "write_training_artifact_bundle",
]
