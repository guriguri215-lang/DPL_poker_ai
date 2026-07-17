"""Repo-only P6-8A Validation batch planning and independent verification.

This module reads and verifies completed Training provenance, reconstructs the
approved Validation inputs, and returns an in-memory plan. It has no execution
backend, command surface, artifact writer, or directory creation path.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from opponents import load_training_catalog, load_validation_catalog
from opponents.model import OpponentModelConfig

from .contracts import (
    FULL_SELECTION_CONTRACT_SCHEMA_VERSION,
    FULL_SELECTION_PREREGISTRATION_SCHEMA_VERSION,
    CoverageEvaluation,
    canonical_json_bytes,
    full_selection_metric_contract_v2_payload,
    full_selection_preregistration_v2_payload,
    load_phase6_contract_bundle,
    sha256_bytes,
    validate_full_selection_metric_contract_v2,
    validate_full_selection_preregistration_v2,
)
from .p6_7 import (
    PRIMARY_SELECTION_KEYS,
    REPETITION_SEEDS,
    SAMPLING_CONTRACT_SCHEMA_VERSION,
    STREAM_NAMES,
    PrimaryCandidate,
    build_catalog_fixture_evidence,
    derive_stream_root,
    primary_candidate_grid,
    validate_catalog_fixture,
    validate_primary_candidate_grid,
    validate_sampling_contract,
)
from .training_cli import verify_training_run_manifest
from .training_runner import HORIZONS, TRAINING_SELECTION_SCHEMA_VERSION

VALIDATION_BATCH_SCHEMA_VERSION = "phase6-validation-batch-manifest-v1"
VALIDATION_CATALOG_INDEX_SCHEMA_VERSION = "phase6-validation-catalog-index-v1"
VALIDATION_SERIES_SCHEMA_VERSION = "phase6-validation-series-v1"
VALIDATION_RUNNER_VERSION = "p6-8a-validation-plan-v1"

_SHA256_CHARS = frozenset("0123456789abcdef")
_EXPECTED_CARDINALITY = {
    "candidate_count": 16,
    "opponent_count": 9,
    "horizon_count": 3,
    "repetition_count": 30,
    "session_count": 12960,
    "stream_root_count": 3240,
}


@dataclass(frozen=True, order=True, slots=True)
class ValidationSessionKey:
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
class ValidationBatchPlan:
    manifest: dict[str, object]
    manifest_bytes: bytes
    manifest_sha256: str
    candidates: tuple[PrimaryCandidate, ...]
    sessions: tuple[ValidationSessionKey, ...]


@dataclass(frozen=True, slots=True)
class _VerifiedTrainingSource:
    run_manifest_reference: dict[str, str]
    selection_report_reference: dict[str, str]
    git: dict[str, object]
    training_batch_manifest_sha256: str
    sampling_contract: dict[str, object]
    sampling_contract_sha256: str
    candidate_ids: tuple[str, ...]
    coverage_evaluation: CoverageEvaluation

    def manifest_projection(self) -> dict[str, object]:
        return {
            "run_manifest": self.run_manifest_reference,
            "selection_report": self.selection_report_reference,
            "git": self.git,
            "training_batch_manifest_sha256": self.training_batch_manifest_sha256,
        }


def build_validation_batch_plan(
    training_run_manifest_path: Path | str,
    *,
    expected_training_run_manifest_sha256: str,
    repo_root: Path | str,
    catalog_root: Path | str | None = None,
) -> ValidationBatchPlan:
    """Build the approved Validation product in memory without executing a session."""
    repository_root = Path(repo_root).resolve()
    source = _verify_training_source(
        Path(training_run_manifest_path),
        expected_sha256=expected_training_run_manifest_sha256,
        repo_root=repository_root,
    )
    candidates = primary_candidate_grid(sampling_contract_sha256=source.sampling_contract_sha256)
    validate_primary_candidate_grid(candidates)
    if tuple(candidate.candidate_id for candidate in candidates) != source.candidate_ids:
        raise ValueError("Training selection does not exactly match the canonical candidate grid")

    opponents = _validation_catalog_entries(
        coverage_evaluation=source.coverage_evaluation,
        catalog_root=catalog_root,
    )
    sessions = _validation_sessions(candidates, opponents)
    stream_roots = _validation_stream_roots(opponents)
    selection_contract, selection_hash, preregistration, preregistration_hash = (
        _full_selection_contracts(source.sampling_contract_sha256)
    )
    series = _validation_series(
        selection_contract_sha256=selection_hash,
        preregistration_sha256=preregistration_hash,
        sampling_contract_sha256=source.sampling_contract_sha256,
    )
    manifest = {
        "schema_version": VALIDATION_BATCH_SCHEMA_VERSION,
        "artifact_type": "validation_batch_manifest",
        "runner_version": VALIDATION_RUNNER_VERSION,
        "split": "validation",
        "selection_metric_contract": {
            "payload": selection_contract,
            "sha256": selection_hash,
        },
        "preregistration": {
            "payload": preregistration,
            "sha256": preregistration_hash,
        },
        "training_source": source.manifest_projection(),
        "sampling_contract": {
            "payload": source.sampling_contract,
            "sha256": source.sampling_contract_sha256,
        },
        "series": series,
        "validation_catalog_index": {
            "schema_version": VALIDATION_CATALOG_INDEX_SCHEMA_VERSION,
            "split": "validation",
            "opponents": opponents,
        },
        "candidates": [_candidate_entry(candidate) for candidate in candidates],
        "horizons": list(HORIZONS),
        "repetitions": [
            {"master_seed": seed, "repetition_id": repetition_id}
            for repetition_id, seed in REPETITION_SEEDS
        ],
        "sessions": [session.canonical_payload() for session in sessions],
        "stream_roots": stream_roots,
        "expected_cardinality": dict(_EXPECTED_CARDINALITY),
    }
    raw = canonical_json_bytes(manifest)
    return ValidationBatchPlan(
        manifest=manifest,
        manifest_bytes=raw,
        manifest_sha256=sha256_bytes(raw),
        candidates=candidates,
        sessions=sessions,
    )


def verify_validation_batch_plan(
    plan: ValidationBatchPlan,
    *,
    repo_root: Path | str,
    catalog_root: Path | str | None = None,
) -> None:
    """Independently reconstruct every source, product key, and stream root."""
    if not isinstance(plan, ValidationBatchPlan):
        raise TypeError("Validation plan must be a ValidationBatchPlan")
    if canonical_json_bytes(plan.manifest) != plan.manifest_bytes:
        raise ValueError("Validation manifest bytes are not canonical")
    if sha256_bytes(plan.manifest_bytes) != plan.manifest_sha256:
        raise ValueError("Validation manifest hash mismatch")
    manifest = plan.manifest
    expected_fields = {
        "schema_version",
        "artifact_type",
        "runner_version",
        "split",
        "selection_metric_contract",
        "preregistration",
        "training_source",
        "sampling_contract",
        "series",
        "validation_catalog_index",
        "candidates",
        "horizons",
        "repetitions",
        "sessions",
        "stream_roots",
        "expected_cardinality",
    }
    if set(manifest) != expected_fields:
        raise ValueError("Validation batch manifest fields are not closed-world")
    if (
        manifest["schema_version"] != VALIDATION_BATCH_SCHEMA_VERSION
        or manifest["artifact_type"] != "validation_batch_manifest"
        or manifest["runner_version"] != VALIDATION_RUNNER_VERSION
        or manifest["split"] != "validation"
    ):
        raise ValueError("Validation batch manifest identity is invalid")
    if manifest["expected_cardinality"] != _EXPECTED_CARDINALITY:
        raise ValueError("Validation expected cardinality is invalid")

    selection_container = _closed_payload_reference(
        manifest["selection_metric_contract"], "selection metric contract"
    )
    selection_contract = validate_full_selection_metric_contract_v2(
        selection_container["payload"], expected_sha256=selection_container["sha256"]
    )
    preregistration_container = _closed_payload_reference(
        manifest["preregistration"], "preregistration"
    )
    preregistration = validate_full_selection_preregistration_v2(
        preregistration_container["payload"],
        selection_contract=selection_contract,
        expected_sha256=preregistration_container["sha256"],
    )
    sampling_container = _closed_payload_reference(
        manifest["sampling_contract"], "sampling contract"
    )
    sampling_payload = sampling_container["payload"]
    if not isinstance(sampling_payload, dict):
        raise ValueError("Validation sampling contract payload must be an object")
    validate_sampling_contract(
        sampling_payload,
        expected_sha256=sampling_container["sha256"],
    )
    expected_contract, expected_selection_hash, expected_preregistration, expected_prereg_hash = (
        _full_selection_contracts(sampling_container["sha256"])
    )
    if (
        selection_contract != expected_contract
        or selection_container["sha256"] != expected_selection_hash
        or preregistration != expected_preregistration
        or preregistration_container["sha256"] != expected_prereg_hash
    ):
        raise ValueError("Validation full-selection preregistration does not reconstruct")

    training_source = manifest["training_source"]
    if not isinstance(training_source, dict) or set(training_source) != {
        "run_manifest",
        "selection_report",
        "git",
        "training_batch_manifest_sha256",
    }:
        raise ValueError("Validation Training source is not closed-world")
    run_reference = _closed_path_reference(training_source["run_manifest"], "run manifest")
    repository_root = Path(repo_root).resolve()
    run_path = _resolve_repo_relative(repository_root, run_reference["path"], "run manifest")
    reconstructed_source = _verify_training_source(
        run_path,
        expected_sha256=run_reference["sha256"],
        repo_root=repository_root,
    )
    if training_source != reconstructed_source.manifest_projection():
        raise ValueError("Validation Training source references do not reconstruct")
    if sampling_payload != reconstructed_source.sampling_contract:
        raise ValueError("Validation sampling contract differs from verified Training provenance")

    candidates = primary_candidate_grid(
        sampling_contract_sha256=reconstructed_source.sampling_contract_sha256
    )
    validate_primary_candidate_grid(candidates)
    if (
        tuple(candidate.candidate_id for candidate in candidates)
        != reconstructed_source.candidate_ids
    ):
        raise ValueError("Validation candidates differ from verified Training selection")
    candidate_entries = [_candidate_entry(candidate) for candidate in candidates]
    if manifest["candidates"] != candidate_entries:
        raise ValueError("Validation candidate order/config does not reconstruct")

    opponents = _validation_catalog_entries(
        coverage_evaluation=reconstructed_source.coverage_evaluation,
        catalog_root=catalog_root,
    )
    expected_catalog_index = {
        "schema_version": VALIDATION_CATALOG_INDEX_SCHEMA_VERSION,
        "split": "validation",
        "opponents": opponents,
    }
    if manifest["validation_catalog_index"] != expected_catalog_index:
        raise ValueError("Validation catalog index does not reconstruct from repository configs")
    if manifest["horizons"] != list(HORIZONS) or manifest["repetitions"] != [
        {"master_seed": seed, "repetition_id": repetition_id}
        for repetition_id, seed in REPETITION_SEEDS
    ]:
        raise ValueError("Validation horizon/repetition order is not approved")
    sessions = _validation_sessions(candidates, opponents)
    if manifest["sessions"] != [session.canonical_payload() for session in sessions]:
        raise ValueError("Validation sessions do not match the ordered complete product")
    stream_roots = _validation_stream_roots(opponents)
    if manifest["stream_roots"] != stream_roots:
        raise ValueError("Validation stream roots do not reconstruct with split=validation")
    expected_series = _validation_series(
        selection_contract_sha256=expected_selection_hash,
        preregistration_sha256=expected_prereg_hash,
        sampling_contract_sha256=reconstructed_source.sampling_contract_sha256,
    )
    if manifest["series"] != expected_series:
        raise ValueError("Validation series provenance does not reconstruct")
    if plan.candidates != candidates or plan.sessions != sessions:
        raise ValueError("Validation plan objects differ from the verified manifest")


def _verify_training_source(
    manifest_path: Path,
    *,
    expected_sha256: str,
    repo_root: Path,
) -> _VerifiedTrainingSource:
    _validate_sha256(expected_sha256, "Training run manifest expected hash")
    resolved_path = manifest_path.resolve()
    run_relative = _repo_relative(repo_root, resolved_path, "Training run manifest")
    raw = resolved_path.read_bytes()
    if sha256_bytes(raw) != expected_sha256:
        raise ValueError("Training run manifest hash mismatch")
    payload = _strict_canonical_object(raw, "Training run manifest")
    verified = verify_training_run_manifest(resolved_path, repo_root=repo_root)
    if verified != payload:
        raise ValueError("Training run verifier returned a different manifest")

    git = payload.get("git")
    if not isinstance(git, dict) or set(git) != {"expected_commit", "actual_commit", "dirty"}:
        raise ValueError("Training run git provenance is not closed-world")
    expected_commit = git["expected_commit"]
    actual_commit = git["actual_commit"]
    if (
        not _is_git_commit(expected_commit)
        or not _is_git_commit(actual_commit)
        or expected_commit != actual_commit
        or git["dirty"] is not False
    ):
        raise ValueError("Training run git provenance is not clean and commit-pinned")

    inputs = payload.get("inputs")
    if not isinstance(inputs, dict) or set(inputs) != {
        "phase6_contract_manifest",
        "dependency_lock",
        "sampling_contract",
        "training_batch_manifest_sha256",
    }:
        raise ValueError("Training run input provenance is not closed-world")
    sampling = _closed_payload_reference(inputs["sampling_contract"], "Training sampling contract")
    if not isinstance(sampling["payload"], dict):
        raise ValueError("Training sampling contract payload must be an object")
    validate_sampling_contract(sampling["payload"], expected_sha256=sampling["sha256"])
    training_batch_hash = _validate_sha256(
        inputs["training_batch_manifest_sha256"], "Training batch manifest hash"
    )

    outputs = payload.get("outputs")
    if not isinstance(outputs, dict) or "training_selection_report" not in outputs:
        raise ValueError("Training run is missing the selection report reference")
    output_reference = outputs["training_selection_report"]
    if (
        not isinstance(output_reference, dict)
        or set(output_reference) != {"name", "path", "sha256"}
        or output_reference["name"] != "training_selection_report"
    ):
        raise ValueError("Training selection report reference is not closed-world")
    _validate_sha256(output_reference["sha256"], "Training selection report hash")
    selection_path = _resolve_child(
        resolved_path.parent,
        output_reference["path"],
        "Training selection report",
    )
    selection_relative = _repo_relative(repo_root, selection_path, "Training selection report")
    selection_raw = selection_path.read_bytes()
    if sha256_bytes(selection_raw) != output_reference["sha256"]:
        raise ValueError("Training selection report hash mismatch")
    selection = _strict_canonical_object(selection_raw, "Training selection report")
    candidate_ids = _validate_training_selection(
        selection,
        sampling_contract_sha256=sampling["sha256"],
        training_batch_manifest_sha256=training_batch_hash,
    )

    contract_reference = _closed_path_reference(
        inputs["phase6_contract_manifest"], "Phase 6 contract manifest"
    )
    contract_path = _resolve_repo_relative(
        repo_root,
        contract_reference["path"],
        "Phase 6 contract manifest",
    )
    contract_bundle = load_phase6_contract_bundle(
        contract_path,
        expected_sha256=contract_reference["sha256"],
    )
    return _VerifiedTrainingSource(
        run_manifest_reference={"path": run_relative, "sha256": expected_sha256},
        selection_report_reference={
            "path": selection_relative,
            "sha256": output_reference["sha256"],
        },
        git=dict(git),
        training_batch_manifest_sha256=training_batch_hash,
        sampling_contract=dict(sampling["payload"]),
        sampling_contract_sha256=sampling["sha256"],
        candidate_ids=candidate_ids,
        coverage_evaluation=contract_bundle.coverage_evaluation,
    )


def _validate_training_selection(
    payload: Mapping[str, object],
    *,
    sampling_contract_sha256: str,
    training_batch_manifest_sha256: str,
) -> tuple[str, ...]:
    expected_fields = {
        "schema_version",
        "artifact_type",
        "training_batch_manifest_sha256",
        "selection_policy",
        "performance_based_top_n",
        "input_candidate_ids",
        "retained_candidate_ids",
        "excluded_candidates",
        "p6_8_candidate_count",
    }
    if set(payload) != expected_fields:
        raise ValueError("Training selection report fields are not closed-world")
    candidates = primary_candidate_grid(sampling_contract_sha256=sampling_contract_sha256)
    validate_primary_candidate_grid(candidates)
    ordered_ids = tuple(candidate.candidate_id for candidate in candidates)
    expected = {
        "schema_version": TRAINING_SELECTION_SCHEMA_VERSION,
        "artifact_type": "training_selection_report",
        "training_batch_manifest_sha256": training_batch_manifest_sha256,
        "selection_policy": "retain_all_hard_gate_passing_candidates",
        "performance_based_top_n": None,
        "input_candidate_ids": list(ordered_ids),
        "retained_candidate_ids": list(ordered_ids),
        "excluded_candidates": [],
        "p6_8_candidate_count": 16,
    }
    if payload != expected:
        raise ValueError("Training selection report does not retain the canonical 16 candidates")
    return ordered_ids


def _validation_catalog_entries(
    *,
    coverage_evaluation: CoverageEvaluation,
    catalog_root: Path | str | None,
) -> list[dict[str, object]]:
    kwargs = {} if catalog_root is None else {"catalog_root": catalog_root}
    training = load_training_catalog(**kwargs)
    validation = load_validation_catalog(**kwargs)
    approved_training = load_training_catalog()
    approved_validation = load_validation_catalog()
    if _config_entries(training) != _config_entries(approved_training):
        raise ValueError("Training catalog differs from the approved repository catalog")
    if _config_entries(validation) != _config_entries(approved_validation):
        raise ValueError("Validation catalog differs from the approved repository catalog")
    evidence = build_catalog_fixture_evidence(
        (*training, *validation),
        coverage_evaluation=coverage_evaluation,
    )
    validate_catalog_fixture(evidence, coverage_evaluation=coverage_evaluation)
    validation_evidence = [item for item in evidence if item.config.split == "validation"]
    entries = [
        {
            "opponent_id": item.config.opponent_id,
            "config_sha256": item.config.config_sha256,
            "config": item.config.canonical_payload(),
            "equilibrium_artifact_sha256": item.config.equilibrium_artifact_sha256,
            "strategy_sha256": item.strategy_sha256,
            "control_role": item.control_role,
            "primary_true_deltas": [
                {"reason_id": reason_id, "value": _decimal_wire(value)}
                for reason_id, value in item.primary_true_deltas
            ],
            "coverage": {
                "end_to_end_coverage": item.end_to_end_coverage,
                "r008_semantic_id": item.r008_semantic_id,
            },
        }
        for item in validation_evidence
    ]
    if (
        len(entries) != 9
        or sum(item["control_role"] == "gto_negative_control" for item in entries) != 1
    ):
        raise ValueError("Validation catalog index requires nine opponents and one GTO control")
    return entries


def _config_entries(configs: Sequence[OpponentModelConfig]) -> list[dict[str, object]]:
    return [
        {
            "config": config.canonical_payload(),
            "config_sha256": config.config_sha256,
        }
        for config in configs
    ]


def _validation_sessions(
    candidates: Sequence[PrimaryCandidate],
    opponents: Sequence[Mapping[str, object]],
) -> tuple[ValidationSessionKey, ...]:
    sessions = tuple(
        sorted(
            ValidationSessionKey(
                candidate.candidate_id,
                str(opponent["opponent_id"]),
                horizon,
                repetition_id,
            )
            for candidate in candidates
            for opponent in opponents
            for horizon in HORIZONS
            for repetition_id, _seed in REPETITION_SEEDS
        )
    )
    if len(sessions) != 12960 or len(set(sessions)) != 12960:
        raise ValueError("Validation sessions do not form the approved 16 x 9 x 3 x 30 product")
    return sessions


def _validation_stream_roots(
    opponents: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    roots: list[dict[str, object]] = []
    seen: set[str] = set()
    for opponent in opponents:
        for horizon in HORIZONS:
            for repetition_id, _seed in REPETITION_SEEDS:
                for stream_name in STREAM_NAMES:
                    root = derive_stream_root(
                        split="validation",
                        opponent_id=str(opponent["opponent_id"]),
                        horizon=horizon,
                        repetition_id=repetition_id,
                        stream_name=stream_name,
                    )
                    if root.digest in seen:
                        raise ValueError("Validation stream-root digest collision")
                    seen.add(root.digest)
                    roots.append({"digest": root.digest, "payload": root.payload})
    if len(roots) != 3240:
        raise ValueError("Validation stream roots do not have approved cardinality")
    return roots


def _full_selection_contracts(
    sampling_contract_sha256: str,
) -> tuple[dict[str, Any], str, dict[str, Any], str]:
    selection = full_selection_metric_contract_v2_payload()
    selection_hash = sha256_bytes(canonical_json_bytes(selection))
    validate_full_selection_metric_contract_v2(selection, expected_sha256=selection_hash)
    preregistration = full_selection_preregistration_v2_payload(
        selection_contract_sha256=selection_hash,
        sampling_contract_sha256=sampling_contract_sha256,
    )
    preregistration_hash = sha256_bytes(canonical_json_bytes(preregistration))
    validate_full_selection_preregistration_v2(
        preregistration,
        selection_contract=selection,
        expected_sha256=preregistration_hash,
    )
    selection_keys = tuple(
        (item["metric_id"], item["direction"]) for item in selection["selection_keys"]
    )
    if selection_keys != PRIMARY_SELECTION_KEYS:
        raise ValueError("v2 selection contract differs from the approved P6-7 rank order")
    return selection, selection_hash, preregistration, preregistration_hash


def _validation_series(
    *,
    selection_contract_sha256: str,
    preregistration_sha256: str,
    sampling_contract_sha256: str,
) -> dict[str, object]:
    return {
        "schema_version": VALIDATION_SERIES_SCHEMA_VERSION,
        "split": "validation",
        "selection_contract_schema_version": FULL_SELECTION_CONTRACT_SCHEMA_VERSION,
        "selection_contract_sha256": selection_contract_sha256,
        "preregistration_schema_version": FULL_SELECTION_PREREGISTRATION_SCHEMA_VERSION,
        "preregistration_sha256": preregistration_sha256,
        "sampling_contract_schema_version": SAMPLING_CONTRACT_SCHEMA_VERSION,
        "sampling_contract_sha256": sampling_contract_sha256,
    }


def _candidate_entry(candidate: PrimaryCandidate) -> dict[str, object]:
    return {"candidate_id": candidate.candidate_id, "config": candidate.canonical_payload()}


def _closed_payload_reference(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"payload", "sha256"}:
        raise ValueError(f"{label} payload reference is not closed-world")
    _validate_sha256(value["sha256"], f"{label} hash")
    if sha256_bytes(canonical_json_bytes(value["payload"])) != value["sha256"]:
        raise ValueError(f"{label} hash mismatch")
    return value


def _closed_path_reference(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise ValueError(f"{label} path reference is not closed-world")
    path = value["path"]
    if not isinstance(path, str) or not path or "\\" in path:
        raise ValueError(f"{label} path must be a POSIX repository-relative path")
    _validate_sha256(value["sha256"], f"{label} hash")
    return value


def _resolve_repo_relative(repo_root: Path, relative_path: object, label: str) -> Path:
    if not isinstance(relative_path, str) or not relative_path or "\\" in relative_path:
        raise ValueError(f"{label} path must be a POSIX repository-relative path")
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} path must remain below the repository root")
    resolved = (repo_root / relative).resolve()
    if resolved != repo_root and repo_root not in resolved.parents:
        raise ValueError(f"{label} path escapes the repository root")
    return resolved


def _resolve_child(root: Path, relative_path: object, label: str) -> Path:
    if not isinstance(relative_path, str) or not relative_path or "\\" in relative_path:
        raise ValueError(f"{label} path must be a POSIX relative path")
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} path must remain below its bundle root")
    resolved = (root / relative).resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"{label} path escapes its bundle root")
    return resolved


def _repo_relative(repo_root: Path, path: Path, label: str) -> str:
    try:
        relative = path.relative_to(repo_root)
    except ValueError as exc:
        raise ValueError(f"{label} must remain below the repository root") from exc
    value = relative.as_posix()
    if not value or value == ".":
        raise ValueError(f"{label} must name a repository file")
    return value


def _strict_canonical_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ValueError(f"{label} bytes are not canonical")
    return payload


def _validate_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _SHA256_CHARS for character in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _is_git_commit(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(character in _SHA256_CHARS for character in value)
    )


def _decimal_wire(value: object) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return "0" if text in {"-0", ""} else text


__all__ = [
    "VALIDATION_BATCH_SCHEMA_VERSION",
    "VALIDATION_CATALOG_INDEX_SCHEMA_VERSION",
    "VALIDATION_RUNNER_VERSION",
    "VALIDATION_SERIES_SCHEMA_VERSION",
    "ValidationBatchPlan",
    "ValidationSessionKey",
    "build_validation_batch_plan",
    "verify_validation_batch_plan",
]
