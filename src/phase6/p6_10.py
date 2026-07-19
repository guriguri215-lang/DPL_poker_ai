"""Closed-world P6-10A comparator and epsilon-zero ablation execution.

This module consumes only the pinned P6-9 Validation result.  It derives the
base-policy and oracle-BR comparators from saved exact-EV cells, records the
degenerate alpha-0.50 comparator without a run, and executes exactly one
separate epsilon-zero series when called through the frozen production CLI.
It does not implement the unresolved confidence/provider ablations or any
Gate-B/Test transition.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import subprocess
import sys
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_HALF_EVEN, Decimal, localcontext
from pathlib import Path
from typing import Any

from .calibration import DECIMAL_PRECISION
from .contracts import canonical_json_bytes, sha256_bytes
from .exact_ev import EV_CONSISTENCY_ABS_TOLERANCE
from .p6_7 import (
    REPETITION_SEEDS,
    RESERVED_ALPHA_ABLATION_REASON,
    STREAM_NAMES,
    PrimaryCandidate,
    derive_draw_digest,
    derive_stream_root,
    epsilon_branch_fires,
    uniform_action,
    weighted_categorical,
)
from .training_runner import HORIZONS
from .validation_backend import ProductionValidationExecutionBackend, _chance_child
from .validation_cli import verify_validation_run_manifest
from .validation_execution import (
    ValidationArtifactRecord,
    _evaluation_context,
    _reconstruct_hero_policies,
    run_single_validation_candidate_execution,
    verify_single_validation_candidate_records,
)
from .validation_runner import (
    ValidationBatchPlan,
    ValidationSessionKey,
    verify_validation_batch_plan,
)

P6_10A_CLI_VERSION = "phase6-p6-10a-cli-v1"
P6_10A_ENTRYPOINT = "cli/phase6_p6_10_v1.py"
P6_10A_ATTEMPT_ID = "p6-10a-comparator-ablation-attempt-001"
P6_10A_ATTEMPT_MARKER = "p6_10a_attempt_in_progress.json"
P6_10A_RUN_MANIFEST = "phase6_p6_10a_run_manifest.json"
P6_10A_BATCH_MANIFEST = "p6_10a_batch_manifest.json"
P6_10A_RESULT_ROOT = "p6_10a_result_root.json"
P6_10A_ARTIFACT_DIRECTORY = "p6-10a-artifacts"
P6_10A_PHYSICAL_DIRECTORY = "comparator-ablation"

P6_10A_BATCH_SCHEMA_VERSION = "phase6-p6-10a-batch-manifest-v1"
P6_10A_ARTIFACT_SCHEMA_VERSION = "phase6-p6-10a-artifact-v1"
P6_10A_RESULT_ROOT_SCHEMA_VERSION = "phase6-p6-10a-result-root-v1"
P6_10A_REPORT_SCHEMA_VERSION = "phase6-p6-10a-comparator-ablation-report-v1"
P6_10A_GAP_PACKET_SCHEMA_VERSION = "phase6-gate-b-readiness-gap-packet-v1"
P6_10A_RUN_SCHEMA_VERSION = "phase6-p6-10a-run-manifest-v1"
P6_10A_ATTEMPT_MARKER_SCHEMA_VERSION = "phase6-p6-10a-attempt-marker-v1"

CMP_BASE_POLICY_ID = "cmp_base_policy__v1"
CMP_ORACLE_BR_ID = "cmp_oracle_br__v1"
CMP_SAFETY_ALPHA_050_ID = "cmp_safety_alpha_050__v1"
ABL_EPSILON_ZERO_ID = "abl_epsilon_zero__v1"
ABL_ALPHA_FIXED_ID = "abl_alpha_fixed__v1"
ABL_CONFIDENCE_MVP_ID = "abl_confidence_mvp__v1"
ABL_PROVIDER_RULE_ID = "abl_provider_rule__v1"

P6_9_BASELINE = "c21ff7180e3417e0f418e1e993e5eaacdd3bb5cf"
P6_9_RUN_MANIFEST_SHA256 = "39d18561709e6e1f5d16464b4e6d61cb712d900efff510e5301d5c14a84dfd3f"
P6_9_RESULT_ROOT_SHA256 = "b0a16209a143be697a38506fc4ad465a30a5cac8630ba86a42fcbb36830a8ba8"
P6_9_SELECTION_REPORT_SHA256 = "36a2e11a7fe1a1d60f0f639e29e68554a3936cec8d80d613d3dbdbd63cc27b59"
P6_9_SELECTED_CONFIG_SHA256 = "05c1e5a2ddbdc979ef7998cdda57af73f1b2ed8d540fe3fa37565e167ac0c54a"
P6_9_SELECTED_LOCK_SHA256 = "bc4387bd1306add4a2d48bb4cc0acaa3fa5404d672940df30891a7d31395485d"
P6_9_VALIDATION_BATCH_SHA256 = "71eda21f82849ba0ee519705d607af79300fca621dd34c1072d3b37f25c8d64b"
P6_9_EXACT_EV_CELLS_SHA256 = "422d45135f52d06f6ddf92b3b2875243a6d64c6d95c15d379d062038c19f938b"
P6_9_DEPENDENCY_LOCK_SHA256 = "ad56a49af345f5f768cc49b9400c039191b98267bf415c4b0e3d372b81ed65d6"

_STANDARD_ARTIFACT_TYPES = (
    "validation_terminal_candidate_snapshots",
    "validation_hero_policy_snapshots",
    "validation_exact_ev_cells",
    "validation_calibration_cells",
    "validation_aggregate_metrics",
)
_EPSILON_ARTIFACT_NAMES = (
    "epsilon_zero_terminal_candidate_snapshots",
    "epsilon_zero_hero_policy_snapshots",
    "epsilon_zero_exact_ev_cells",
    "epsilon_zero_calibration_cells",
    "epsilon_zero_aggregate_metrics",
)
_RESULT_ARTIFACT_NAMES = (
    P6_10A_BATCH_MANIFEST.removesuffix(".json"),
    *_EPSILON_ARTIFACT_NAMES,
    "comparator_ablation_report",
    "gate_b_readiness_gap_packet",
)
_EXPECTED_CARDINALITY = {
    "candidate_count": 1,
    "opponent_count": 9,
    "horizon_count": 3,
    "repetition_count": 30,
    "session_count": 810,
    "stream_root_count": 3240,
    "session_record_count_per_type": 810,
    "candidate_record_count_per_type": 1,
}
_SHA256_CHARS = frozenset("0123456789abcdef")
_P6_10A_REPO_ALLOWLIST = frozenset(
    {
        "cli/phase6_p6_10_freeze_v1.py",
        "cli/phase6_p6_10_v1.py",
        "src/phase6/__init__.py",
        "src/phase6/p6_10.py",
        "src/phase6/p6_10_freeze.py",
        "src/phase6/validation_backend.py",
        "src/phase6/validation_execution.py",
        "src/phase6/validation_runner.py",
        "tests/phase6/test_p6_10.py",
        "tests/phase6/test_p6_10_freeze.py",
    }
)


@dataclass(frozen=True, slots=True)
class P69Snapshot:
    repo_root: Path
    run_manifest_path: Path
    run_manifest: dict[str, Any]
    result_root_path: Path
    result_root: dict[str, Any]
    artifact_root: Path
    artifact_payloads: dict[str, dict[str, Any]]
    artifact_raw: dict[str, bytes]
    plan: ValidationBatchPlan
    selected_candidate: PrimaryCandidate
    selected_lock: dict[str, Any]
    selection_report: dict[str, Any]
    pinned_verifier_mode: str = "fixture_or_unspecified"
    verified_repository_commit: str = P6_9_BASELINE


@dataclass(frozen=True, slots=True)
class P610ABatchPlan:
    manifest: dict[str, Any]
    manifest_bytes: bytes
    manifest_sha256: str
    candidate: PrimaryCandidate
    config_sha256: str
    sessions: tuple[ValidationSessionKey, ...]


@dataclass(frozen=True, slots=True)
class P610AResultBundle:
    root: Path
    root_manifest_path: Path
    root_manifest_sha256: str
    report_path: Path
    gap_packet_path: Path


def load_p6_9_snapshot(
    run_manifest_path: Path | str,
    *,
    repo_root: Path | str,
) -> P69Snapshot:
    """Verify and load only the fixed P6-9 source snapshot."""
    repository_root = Path(repo_root).resolve()
    run_path = Path(run_manifest_path).resolve()
    run_raw = run_path.read_bytes()
    if sha256_bytes(run_raw) != P6_9_RUN_MANIFEST_SHA256:
        raise ValueError("P6-9 run manifest hash differs from the approved snapshot")
    run = _strict_object(run_raw, "P6-9 run manifest")
    verified, verifier_mode, verified_commit = _run_pinned_p6_9_verifier(
        run_path,
        repo_root=repository_root,
    )
    if verified != run:
        raise ValueError("P6-9 pinned verifier returned different manifest bytes")
    inputs = _closed_object(
        run.get("inputs"),
        {
            "dependency_lock",
            "qv5_manifest",
            "training_source",
            "validation_batch_manifest",
            "validation_freeze_manifest",
        },
        "P6-9 inputs",
    )
    if inputs["dependency_lock"].get("sha256") != P6_9_DEPENDENCY_LOCK_SHA256:
        raise ValueError("P6-9 dependency lock hash differs from the approved snapshot")
    if inputs["validation_batch_manifest"].get("sha256") != P6_9_VALIDATION_BATCH_SHA256:
        raise ValueError("P6-9 Validation batch hash differs from the approved snapshot")
    outputs = _closed_object(run.get("outputs"), {"validation_result_root"}, "P6-9 outputs")
    root_reference = _closed_object(
        outputs["validation_result_root"],
        {"name", "path", "sha256", "size_bytes"},
        "P6-9 result root reference",
    )
    if root_reference["sha256"] != P6_9_RESULT_ROOT_SHA256:
        raise ValueError("P6-9 result root hash differs from the approved snapshot")
    result_path = _safe_child(run_path.parent, root_reference["path"], "P6-9 result root")
    result_raw = result_path.read_bytes()
    if (
        len(result_raw) != root_reference["size_bytes"]
        or sha256_bytes(result_raw) != P6_9_RESULT_ROOT_SHA256
    ):
        raise ValueError("P6-9 result root bytes differ from the approved snapshot")
    result = _strict_object(result_raw, "P6-9 result root")
    artifact_root = result_path.parent
    references = result.get("artifacts")
    if not isinstance(references, list):
        raise ValueError("P6-9 result root artifact references are invalid")
    payloads: dict[str, dict[str, Any]] = {}
    raw_by_name: dict[str, bytes] = {}
    for reference in references:
        ref = _closed_object(
            reference,
            {"name", "path", "sha256", "size_bytes"},
            "P6-9 artifact reference",
        )
        path = _safe_child(artifact_root, ref["path"], f"P6-9 artifact {ref['name']}")
        raw = path.read_bytes()
        if len(raw) != ref["size_bytes"] or sha256_bytes(raw) != ref["sha256"]:
            raise ValueError("P6-9 artifact size/hash mismatch")
        payloads[ref["name"]] = _strict_object(raw, f"P6-9 artifact {ref['name']}")
        raw_by_name[ref["name"]] = raw
    required = {
        "validation_batch_manifest",
        "validation_exact_ev_cells",
        "validation_aggregate_metrics",
        "primary_selection_report",
        "selected_config_lock",
    }
    if not required <= set(payloads):
        raise ValueError("P6-9 result root lacks required P6-10A sources")
    fixed = {
        "validation_batch_manifest": P6_9_VALIDATION_BATCH_SHA256,
        "validation_exact_ev_cells": P6_9_EXACT_EV_CELLS_SHA256,
        "primary_selection_report": P6_9_SELECTION_REPORT_SHA256,
        "selected_config_lock": P6_9_SELECTED_LOCK_SHA256,
    }
    for name, expected in fixed.items():
        if sha256_bytes(raw_by_name[name]) != expected:
            raise ValueError(f"P6-9 {name} hash differs from the approved snapshot")

    batch = payloads["validation_batch_manifest"]
    candidates = tuple(_candidate_from_entry(item) for item in batch["candidates"])
    sessions = tuple(
        ValidationSessionKey(
            item["candidate_id"],
            item["opponent_id"],
            item["horizon"],
            item["repetition_id"],
        )
        for item in batch["sessions"]
    )
    plan = ValidationBatchPlan(
        batch,
        raw_by_name["validation_batch_manifest"],
        P6_9_VALIDATION_BATCH_SHA256,
        candidates,
        sessions,
    )
    verify_validation_batch_plan(plan, repo_root=repository_root)
    lock = payloads["selected_config_lock"]
    if (
        lock.get("selected_config_count") != 1
        or lock.get("manual_override") is not False
        or lock.get("selected_config_sha256") != P6_9_SELECTED_CONFIG_SHA256
        or lock.get("primary_selection_report_sha256") != P6_9_SELECTION_REPORT_SHA256
        or lock.get("validation_batch_manifest_sha256") != P6_9_VALIDATION_BATCH_SHA256
    ):
        raise ValueError("P6-9 selected lock differs from the approved selection")
    selected = next(
        (item for item in candidates if item.candidate_id == lock.get("selected_candidate_id")),
        None,
    )
    if selected is None or selected.canonical_payload() != lock.get("selected_config"):
        raise ValueError("P6-9 selected candidate does not join the Validation batch")
    if selected.safety_alpha != "0.5":
        raise ValueError("P6-10A requires selected safety alpha exactly 0.5")
    if (
        sha256_bytes(canonical_json_bytes(selected.canonical_payload()))
        != P6_9_SELECTED_CONFIG_SHA256
    ):
        raise ValueError("P6-9 selected config hash does not reconstruct")
    selection = payloads["primary_selection_report"]
    ranked = selection.get("ranked_candidates")
    if not isinstance(ranked, list) or len(ranked) != 16:
        raise ValueError("P6-9 primary selection report cardinality is invalid")
    top = ranked[:4]
    first_six = tuple(_first_six_selection_keys(item) for item in top)
    ids = [item["candidate"]["candidate_id"] for item in top]
    if any(value != first_six[0] for value in first_six[1:]) or ids != sorted(ids):
        raise ValueError("P6-9 top four do not preserve the six-key tie and ID tie-break")
    return P69Snapshot(
        repository_root,
        run_path,
        run,
        result_path,
        result,
        artifact_root,
        payloads,
        raw_by_name,
        plan,
        selected,
        lock,
        selection,
        verifier_mode,
        verified_commit,
    )


def build_p6_10a_batch(snapshot: P69Snapshot) -> P610ABatchPlan:
    """Build the fixed 1 x 9 x 3 x 30 epsilon-zero product."""
    selected = snapshot.selected_candidate
    config = dict(selected.canonical_payload())
    config["epsilon"] = "0"
    config_sha256 = sha256_bytes(canonical_json_bytes(config))
    candidate = PrimaryCandidate(
        f"{ABL_EPSILON_ZERO_ID}__{config_sha256}",
        "0",
        selected.sample_floor,
        selected.detector_confidence,
        selected.provider_confidence,
        selected.safety_alpha,
        selected.sampling_contract_sha256,
    )
    if candidate.canonical_payload() != config:
        raise ValueError("epsilon-zero candidate changes a field other than epsilon")
    coordinates = sorted(
        {
            (key.opponent_id, key.horizon, key.repetition_id)
            for key in snapshot.plan.sessions
            if key.candidate_id == selected.candidate_id
        }
    )
    sessions = tuple(
        ValidationSessionKey(candidate.candidate_id, opponent_id, horizon, repetition_id)
        for opponent_id, horizon, repetition_id in coordinates
    )
    if len(sessions) != 810:
        raise ValueError("epsilon-zero plan must contain exactly 810 sessions")
    roots: list[dict[str, object]] = []
    for opponent_id, horizon, repetition_id in coordinates:
        for stream_name in STREAM_NAMES:
            root = derive_stream_root(
                split="validation",
                opponent_id=opponent_id,
                horizon=horizon,
                repetition_id=repetition_id,
                stream_name=stream_name,
            )
            roots.append({"payload": root.payload, "digest": root.digest})
    if len(roots) != 3240:
        raise ValueError("epsilon-zero plan must contain exactly 3,240 stream roots")
    manifest = {
        "schema_version": P6_10A_BATCH_SCHEMA_VERSION,
        "artifact_type": "p6_10a_batch_manifest",
        "scope": "p6_10a_comparator_ablation",
        "source_snapshot": _source_snapshot_projection(snapshot),
        "selected_primary": {
            "candidate_id": selected.candidate_id,
            "config": selected.canonical_payload(),
            "config_sha256": P6_9_SELECTED_CONFIG_SHA256,
            "manual_override": False,
        },
        "epsilon_zero_candidate": {
            "ablation_id": ABL_EPSILON_ZERO_ID,
            "candidate_id": candidate.candidate_id,
            "config": config,
            "config_sha256": config_sha256,
            "changed_fields": {"epsilon": {"from": selected.epsilon, "to": "0"}},
        },
        "sampling_contract": snapshot.plan.manifest["sampling_contract"],
        "expected_cardinality": dict(_EXPECTED_CARDINALITY),
        "series_non_pooling": {
            "pool_with_selected_series": False,
            "candidate_id_distinct": True,
            "config_sha256_distinct": config_sha256 != P6_9_SELECTED_CONFIG_SHA256,
        },
        "horizons": list(HORIZONS),
        "repetitions": [
            {"repetition_id": repetition_id, "master_seed": seed}
            for repetition_id, seed in REPETITION_SEEDS
        ],
        "sessions": [key.canonical_payload() for key in sessions],
        "stream_roots": roots,
        "manual_override": False,
        "primary_selection_recomputed": False,
    }
    raw = canonical_json_bytes(manifest)
    plan = P610ABatchPlan(
        manifest,
        raw,
        sha256_bytes(raw),
        candidate,
        config_sha256,
        sessions,
    )
    verify_p6_10a_batch(plan, snapshot=snapshot)
    return plan


def verify_p6_10a_batch(plan: P610ABatchPlan, *, snapshot: P69Snapshot) -> None:
    """Reconstruct the complete epsilon-zero plan from the fixed P6-9 source."""
    if not isinstance(plan, P610ABatchPlan):
        raise TypeError("P6-10A batch verifier requires P610ABatchPlan")
    if canonical_json_bytes(plan.manifest) != plan.manifest_bytes or (
        sha256_bytes(plan.manifest_bytes) != plan.manifest_sha256
    ):
        raise ValueError("P6-10A batch bytes/hash are not canonical")
    manifest = plan.manifest
    expected_fields = {
        "schema_version",
        "artifact_type",
        "scope",
        "source_snapshot",
        "selected_primary",
        "epsilon_zero_candidate",
        "sampling_contract",
        "expected_cardinality",
        "series_non_pooling",
        "horizons",
        "repetitions",
        "sessions",
        "stream_roots",
        "manual_override",
        "primary_selection_recomputed",
    }
    if set(manifest) != expected_fields or (
        manifest["schema_version"] != P6_10A_BATCH_SCHEMA_VERSION
        or manifest["artifact_type"] != "p6_10a_batch_manifest"
        or manifest["scope"] != "p6_10a_comparator_ablation"
        or manifest["source_snapshot"] != _source_snapshot_projection(snapshot)
        or manifest["sampling_contract"] != snapshot.plan.manifest["sampling_contract"]
        or manifest["expected_cardinality"] != _EXPECTED_CARDINALITY
        or manifest["horizons"] != list(HORIZONS)
        or manifest["repetitions"]
        != [
            {"repetition_id": repetition_id, "master_seed": seed}
            for repetition_id, seed in REPETITION_SEEDS
        ]
        or manifest["manual_override"] is not False
        or manifest["primary_selection_recomputed"] is not False
    ):
        raise ValueError("P6-10A batch identity/provenance is invalid")
    selected = snapshot.selected_candidate
    selected_projection = {
        "candidate_id": selected.candidate_id,
        "config": selected.canonical_payload(),
        "config_sha256": P6_9_SELECTED_CONFIG_SHA256,
        "manual_override": False,
    }
    if manifest["selected_primary"] != selected_projection:
        raise ValueError("P6-10A batch selected primary differs from P6-9")
    config = dict(selected.canonical_payload())
    config["epsilon"] = "0"
    config_hash = sha256_bytes(canonical_json_bytes(config))
    candidate_id = f"{ABL_EPSILON_ZERO_ID}__{config_hash}"
    candidate_projection = {
        "ablation_id": ABL_EPSILON_ZERO_ID,
        "candidate_id": candidate_id,
        "config": config,
        "config_sha256": config_hash,
        "changed_fields": {"epsilon": {"from": selected.epsilon, "to": "0"}},
    }
    if manifest["epsilon_zero_candidate"] != candidate_projection:
        raise ValueError("P6-10A epsilon-zero candidate is not the exact one-field replacement")
    if plan.candidate.candidate_id != candidate_id or plan.candidate.canonical_payload() != config:
        raise ValueError("P6-10A candidate object differs from its manifest")
    if plan.config_sha256 != config_hash:
        raise ValueError("P6-10A config hash does not reconstruct")
    coordinates = sorted(
        {
            (key.opponent_id, key.horizon, key.repetition_id)
            for key in snapshot.plan.sessions
            if key.candidate_id == selected.candidate_id
        }
    )
    expected_sessions = tuple(
        ValidationSessionKey(candidate_id, opponent_id, horizon, repetition_id)
        for opponent_id, horizon, repetition_id in coordinates
    )
    if plan.sessions != expected_sessions or manifest["sessions"] != [
        key.canonical_payload() for key in expected_sessions
    ]:
        raise ValueError("P6-10A session product does not reconstruct")
    expected_roots = []
    for opponent_id, horizon, repetition_id in coordinates:
        for stream_name in STREAM_NAMES:
            root = derive_stream_root(
                split="validation",
                opponent_id=opponent_id,
                horizon=horizon,
                repetition_id=repetition_id,
                stream_name=stream_name,
            )
            expected_roots.append({"payload": root.payload, "digest": root.digest})
    if manifest["stream_roots"] != expected_roots:
        raise ValueError("P6-10A stream roots do not reconstruct")
    if manifest["series_non_pooling"] != {
        "pool_with_selected_series": False,
        "candidate_id_distinct": True,
        "config_sha256_distinct": True,
    }:
        raise ValueError("P6-10A batch does not enforce series non-pooling")


def execute_p6_10a(
    snapshot: P69Snapshot,
    batch: P610ABatchPlan,
    result_root: Path | str,
    *,
    repo_root: Path | str,
) -> P610AResultBundle:
    """Execute and exclusively save the single approved epsilon-zero series."""
    verify_p6_10a_batch(batch, snapshot=snapshot)
    root = Path(result_root).resolve()
    if root.name != P6_10A_PHYSICAL_DIRECTORY or root.parent.name != P6_10A_ARTIFACT_DIRECTORY:
        raise ValueError("P6-10A result root has a noncanonical physical namespace")
    root.mkdir(parents=False, exist_ok=False)
    backend = ProductionValidationExecutionBackend(
        snapshot.plan,
        repo_root=repo_root,
        additional_candidates=(batch.candidate,),
    )
    records = run_single_validation_candidate_execution(
        snapshot.plan,
        batch.candidate,
        backend,
        repo_root=repo_root,
    )
    payloads: dict[str, bytes] = {P6_10A_BATCH_MANIFEST.removesuffix(".json"): batch.manifest_bytes}
    for standard_name, output_name in zip(
        _STANDARD_ARTIFACT_TYPES, _EPSILON_ARTIFACT_NAMES, strict=True
    ):
        rows = []
        for record in records[standard_name]:
            row: dict[str, object] = {"record": record.canonical_payload()}
            if standard_name == "validation_terminal_candidate_snapshots":
                key = record.session_key()
                row["execution_events"] = list(backend.execution_events(key))
                row["action_draw_audits"] = list(backend.action_draw_audits(key))
            rows.append(row)
        payloads[output_name] = canonical_json_bytes(
            {
                "schema_version": P6_10A_ARTIFACT_SCHEMA_VERSION,
                "artifact_type": output_name,
                "ablation_id": ABL_EPSILON_ZERO_ID,
                "p6_10a_batch_manifest_sha256": batch.manifest_sha256,
                "source_validation_batch_manifest_sha256": P6_9_VALIDATION_BATCH_SHA256,
                "candidate_id": batch.candidate.candidate_id,
                "config_sha256": batch.config_sha256,
                "series_pooling": False,
                "records": rows,
            }
        )
    artifact_refs = _write_payloads_exclusive(root, payloads)
    report = _comparator_ablation_report(snapshot, batch, artifact_refs, records)
    gap = _gate_b_gap_packet(snapshot, batch)
    for name, payload in (
        ("comparator_ablation_report", report),
        ("gate_b_readiness_gap_packet", gap),
    ):
        raw = canonical_json_bytes(payload)
        _write_exclusive(root / f"{name}.json", raw)
        artifact_refs.append(_reference(name, f"{name}.json", raw))
    result = {
        "schema_version": P6_10A_RESULT_ROOT_SCHEMA_VERSION,
        "artifact_type": "p6_10a_result_root",
        "scope": "p6_10a_comparator_ablation",
        "physical_directory": P6_10A_PHYSICAL_DIRECTORY,
        "source_snapshot": _source_snapshot_projection(snapshot),
        "p6_10a_batch_manifest_sha256": batch.manifest_sha256,
        "expected_cardinality": dict(_EXPECTED_CARDINALITY),
        "manual_override": False,
        "series_pooling": False,
        "p6_10_complete": False,
        "gate_b_ready": False,
        "artifacts": artifact_refs,
    }
    raw = canonical_json_bytes(result)
    path = root / P6_10A_RESULT_ROOT
    _write_exclusive(path, raw)
    digest = sha256_bytes(raw)
    verify_p6_10a_result_root(path, expected_sha256=digest, repo_root=repo_root, snapshot=snapshot)
    return P610AResultBundle(
        root,
        path,
        digest,
        root / "comparator_ablation_report.json",
        root / "gate_b_readiness_gap_packet.json",
    )


def verify_p6_10a_result_root(
    root_manifest_path: Path | str,
    *,
    expected_sha256: str,
    repo_root: Path | str,
    snapshot: P69Snapshot | None = None,
) -> dict[str, Any]:
    """Independently rehash and reconstruct the complete P6-10A result."""
    _validate_sha256(expected_sha256, "P6-10A result root hash")
    repository_root = Path(repo_root).resolve()
    path = Path(root_manifest_path).resolve()
    root = path.parent
    if (
        path.name != P6_10A_RESULT_ROOT
        or root.name != P6_10A_PHYSICAL_DIRECTORY
        or root.parent.name != P6_10A_ARTIFACT_DIRECTORY
    ):
        raise ValueError("P6-10A result root path is noncanonical")
    raw = path.read_bytes()
    if sha256_bytes(raw) != expected_sha256:
        raise ValueError("P6-10A result root hash mismatch")
    manifest = _strict_object(raw, "P6-10A result root")
    fields = {
        "schema_version",
        "artifact_type",
        "scope",
        "physical_directory",
        "source_snapshot",
        "p6_10a_batch_manifest_sha256",
        "expected_cardinality",
        "manual_override",
        "series_pooling",
        "p6_10_complete",
        "gate_b_ready",
        "artifacts",
    }
    if set(manifest) != fields or (
        manifest["schema_version"] != P6_10A_RESULT_ROOT_SCHEMA_VERSION
        or manifest["artifact_type"] != "p6_10a_result_root"
        or manifest["scope"] != "p6_10a_comparator_ablation"
        or manifest["physical_directory"] != P6_10A_PHYSICAL_DIRECTORY
        or manifest["expected_cardinality"] != _EXPECTED_CARDINALITY
        or manifest["manual_override"] is not False
        or manifest["series_pooling"] is not False
        or manifest["p6_10_complete"] is not False
        or manifest["gate_b_ready"] is not False
    ):
        raise ValueError("P6-10A result root identity is invalid")
    if snapshot is None:
        source_path = _safe_repo_relative(
            repository_root,
            manifest["source_snapshot"]["p6_9_run_manifest"]["path"],
            "P6-9 run manifest",
        )
        snapshot = load_p6_9_snapshot(source_path, repo_root=repository_root)
    if manifest["source_snapshot"] != _source_snapshot_projection(snapshot):
        raise ValueError("P6-10A result source snapshot mismatch")
    refs = manifest["artifacts"]
    if not isinstance(refs, list) or [item.get("name") for item in refs] != list(
        _RESULT_ARTIFACT_NAMES
    ):
        raise ValueError("P6-10A result artifact set/order is invalid")
    expected_result_names = {P6_10A_RESULT_ROOT} | {
        f"{name}.json" for name in _RESULT_ARTIFACT_NAMES
    }
    if {item.name for item in root.iterdir()} != expected_result_names or any(
        not item.is_file() for item in root.iterdir()
    ):
        raise ValueError("P6-10A result directory is not closed-world")
    payloads: dict[str, dict[str, Any]] = {}
    raw_by_name: dict[str, bytes] = {}
    for value in refs:
        ref = _closed_object(
            value,
            {"name", "path", "sha256", "size_bytes"},
            "P6-10A artifact reference",
        )
        if ref["path"] != f"{ref['name']}.json":
            raise ValueError("P6-10A artifact path is noncanonical")
        artifact_path = _safe_child(root, ref["path"], f"P6-10A artifact {ref['name']}")
        artifact_raw = artifact_path.read_bytes()
        if len(artifact_raw) != ref["size_bytes"] or sha256_bytes(artifact_raw) != ref["sha256"]:
            raise ValueError("P6-10A artifact size/hash mismatch")
        payloads[ref["name"]] = _strict_object(artifact_raw, f"P6-10A artifact {ref['name']}")
        raw_by_name[ref["name"]] = artifact_raw
    batch_payload = payloads[P6_10A_BATCH_MANIFEST.removesuffix(".json")]
    candidate_entry = batch_payload["epsilon_zero_candidate"]
    candidate = _candidate_from_p6_10a_entry(candidate_entry)
    sessions = tuple(
        ValidationSessionKey(
            item["candidate_id"], item["opponent_id"], item["horizon"], item["repetition_id"]
        )
        for item in batch_payload["sessions"]
    )
    batch = P610ABatchPlan(
        batch_payload,
        raw_by_name[P6_10A_BATCH_MANIFEST.removesuffix(".json")],
        sha256_bytes(raw_by_name[P6_10A_BATCH_MANIFEST.removesuffix(".json")]),
        candidate,
        candidate_entry["config_sha256"],
        sessions,
    )
    if manifest["p6_10a_batch_manifest_sha256"] != batch.manifest_sha256:
        raise ValueError("P6-10A result batch hash mismatch")
    verify_p6_10a_batch(batch, snapshot=snapshot)

    records: dict[str, tuple[ValidationArtifactRecord, ...]] = {}
    terminal_rows: list[dict[str, Any]] | None = None
    for standard_name, output_name in zip(
        _STANDARD_ARTIFACT_TYPES, _EPSILON_ARTIFACT_NAMES, strict=True
    ):
        artifact = payloads[output_name]
        expected_fields = {
            "schema_version",
            "artifact_type",
            "ablation_id",
            "p6_10a_batch_manifest_sha256",
            "source_validation_batch_manifest_sha256",
            "candidate_id",
            "config_sha256",
            "series_pooling",
            "records",
        }
        if set(artifact) != expected_fields or (
            artifact["schema_version"] != P6_10A_ARTIFACT_SCHEMA_VERSION
            or artifact["artifact_type"] != output_name
            or artifact["ablation_id"] != ABL_EPSILON_ZERO_ID
            or artifact["p6_10a_batch_manifest_sha256"] != batch.manifest_sha256
            or artifact["source_validation_batch_manifest_sha256"] != P6_9_VALIDATION_BATCH_SHA256
            or artifact["candidate_id"] != candidate.candidate_id
            or artifact["config_sha256"] != batch.config_sha256
            or artifact["series_pooling"] is not False
            or not isinstance(artifact["records"], list)
        ):
            raise ValueError("P6-10A epsilon-zero artifact identity is invalid")
        rows = artifact["records"]
        expected_count = 810 if standard_name in _STANDARD_ARTIFACT_TYPES[:3] else 1
        if len(rows) != expected_count:
            raise ValueError("P6-10A epsilon-zero artifact cardinality is invalid")
        parsed: list[ValidationArtifactRecord] = []
        for row in rows:
            row_fields = (
                {"record", "execution_events", "action_draw_audits"}
                if standard_name == "validation_terminal_candidate_snapshots"
                else {"record"}
            )
            if not isinstance(row, dict) or set(row) != row_fields:
                raise ValueError("P6-10A epsilon-zero record wrapper is not closed-world")
            parsed.append(_artifact_record(row["record"]))
        records[standard_name] = tuple(parsed)
        if standard_name == "validation_terminal_candidate_snapshots":
            terminal_rows = rows
    verified = verify_single_validation_candidate_records(
        snapshot.plan,
        candidate,
        records,
        repo_root=repository_root,
    )
    if verified["session_count"] != 810:
        raise ValueError("P6-10A epsilon-zero verifier returned wrong cardinality")
    assert terminal_rows is not None
    _verify_epsilon_zero_draws(
        terminal_rows,
        records["validation_terminal_candidate_snapshots"],
        snapshot=snapshot,
        candidate=candidate,
        repo_root=repository_root,
    )
    selected_series = _selected_series_id(snapshot)
    if verified["series_id"] == selected_series:
        raise ValueError("P6-10A epsilon-zero series was pooled with the selected series")
    references = {item["name"]: item for item in refs}
    expected_report = _comparator_ablation_report(snapshot, batch, references, records)
    if payloads["comparator_ablation_report"] != expected_report:
        raise ValueError("P6-10A comparator/ablation report does not reconstruct")
    if payloads["gate_b_readiness_gap_packet"] != _gate_b_gap_packet(snapshot, batch):
        raise ValueError("P6-10A Gate B readiness gap packet does not reconstruct")
    return manifest


def run_p6_10a_from_freeze(
    freeze_manifest_path: Path | str,
    freeze_hash_sidecar_path: Path | str,
    *,
    repo_root: Path | str,
) -> Path:
    """Reserve and execute the one frozen P6-10A production attempt."""
    from .p6_10_freeze import verify_p6_10a_freeze_manifest

    repository_root = Path(repo_root).resolve()
    verified = verify_p6_10a_freeze_manifest(
        freeze_manifest_path,
        freeze_hash_sidecar_path,
        repo_root=repository_root,
    )
    output_root = Path(verified["paths"]["output_root"]).resolve()
    if os.path.lexists(output_root):
        raise FileExistsError("P6-10A production output must remain fresh")
    output_root.mkdir(parents=False, exist_ok=False)
    marker = {
        "schema_version": P6_10A_ATTEMPT_MARKER_SCHEMA_VERSION,
        "artifact_type": "p6_10a_attempt_marker",
        "attempt_id": P6_10A_ATTEMPT_ID,
        "attempt_number": 1,
        "retry_count": 0,
        "status": "in_progress",
        "freeze_manifest_sha256": verified["manifest_sha256"],
        "p6_10a_batch_manifest_sha256": verified["p6_10a_batch_manifest"]["sha256"],
        "output_root": str(output_root),
        "partial_retention": "preserve_without_cleanup",
    }
    marker_raw = canonical_json_bytes(marker)
    marker_path = output_root / P6_10A_ATTEMPT_MARKER
    _write_exclusive(marker_path, marker_raw)
    started = _utc_now()
    snapshot = load_p6_9_snapshot(
        _safe_repo_relative(
            repository_root,
            verified["source_snapshot"]["p6_9_run_manifest"]["path"],
            "P6-9 run manifest",
        ),
        repo_root=repository_root,
    )
    batch_path = Path(verified["p6_10a_batch_manifest"]["path"])
    batch_raw = batch_path.read_bytes()
    batch_payload = _strict_object(batch_raw, "frozen P6-10A batch")
    candidate = _candidate_from_p6_10a_entry(batch_payload["epsilon_zero_candidate"])
    batch = P610ABatchPlan(
        batch_payload,
        batch_raw,
        sha256_bytes(batch_raw),
        candidate,
        batch_payload["epsilon_zero_candidate"]["config_sha256"],
        tuple(
            ValidationSessionKey(
                item["candidate_id"],
                item["opponent_id"],
                item["horizon"],
                item["repetition_id"],
            )
            for item in batch_payload["sessions"]
        ),
    )
    result_parent = output_root / P6_10A_ARTIFACT_DIRECTORY
    result_parent.mkdir(exist_ok=False)
    bundle = execute_p6_10a(
        snapshot,
        batch,
        result_parent / P6_10A_PHYSICAL_DIRECTORY,
        repo_root=repository_root,
    )
    finished = _utc_now()
    sidecar_path = Path(freeze_hash_sidecar_path).resolve()
    freeze_path = Path(freeze_manifest_path).resolve()
    run_manifest = {
        "schema_version": P6_10A_RUN_SCHEMA_VERSION,
        "artifact_type": "phase6_p6_10a_run_manifest",
        "cli_version": P6_10A_CLI_VERSION,
        "status": "completed_and_verified",
        "scope": "p6_10a_comparator_ablation",
        "git": verified["git"],
        "runtime": verified["runtime"],
        "timing": {"started_at_utc": started, "finished_at_utc": finished},
        "inputs": {
            "freeze_manifest": _absolute_reference(freeze_path),
            "freeze_hash_sidecar": _absolute_reference(sidecar_path),
            "dependency_lock": verified["dependency_lock"],
            "p6_10a_batch_manifest": verified["p6_10a_batch_manifest"],
            "source_snapshot": verified["source_snapshot"],
        },
        "attempt": {
            "attempt_id": P6_10A_ATTEMPT_ID,
            "attempt_number": 1,
            "retry_count": 0,
            "marker": _relative_reference(output_root, marker_path),
        },
        "outputs": {
            "p6_10a_result_root": _relative_reference(output_root, bundle.root_manifest_path)
        },
        "p6_10_complete": False,
        "gate_b_ready": False,
    }
    run_path = output_root / P6_10A_RUN_MANIFEST
    _write_exclusive(run_path, canonical_json_bytes(run_manifest))
    verify_p6_10a_run_manifest(run_path, repo_root=repository_root)
    return run_path


def verify_p6_10a_run_manifest(
    manifest_path: Path | str,
    *,
    repo_root: Path | str,
) -> dict[str, Any]:
    """Verify the completed run, freeze, marker, result root, and source."""
    from .p6_10_freeze import verify_p6_10a_freeze_manifest

    repository_root = Path(repo_root).resolve()
    path = Path(manifest_path).resolve()
    root = path.parent
    if path.name != P6_10A_RUN_MANIFEST:
        raise ValueError("P6-10A run manifest name is noncanonical")
    payload = _strict_object(path.read_bytes(), "P6-10A run manifest")
    fields = {
        "schema_version",
        "artifact_type",
        "cli_version",
        "status",
        "scope",
        "git",
        "runtime",
        "timing",
        "inputs",
        "attempt",
        "outputs",
        "p6_10_complete",
        "gate_b_ready",
    }
    if set(payload) != fields or (
        payload["schema_version"] != P6_10A_RUN_SCHEMA_VERSION
        or payload["artifact_type"] != "phase6_p6_10a_run_manifest"
        or payload["cli_version"] != P6_10A_CLI_VERSION
        or payload["status"] != "completed_and_verified"
        or payload["scope"] != "p6_10a_comparator_ablation"
        or payload["p6_10_complete"] is not False
        or payload["gate_b_ready"] is not False
    ):
        raise ValueError("P6-10A run manifest identity is invalid")
    timing = payload["timing"]
    if not isinstance(timing, dict) or set(timing) != {"started_at_utc", "finished_at_utc"}:
        raise ValueError("P6-10A run timing is not closed-world")
    started = _parse_utc(timing["started_at_utc"], "P6-10A start time")
    finished = _parse_utc(timing["finished_at_utc"], "P6-10A finish time")
    if finished < started:
        raise ValueError("P6-10A run finished before it started")
    inputs = payload["inputs"]
    if not isinstance(inputs, dict) or set(inputs) != {
        "freeze_manifest",
        "freeze_hash_sidecar",
        "dependency_lock",
        "p6_10a_batch_manifest",
        "source_snapshot",
    }:
        raise ValueError("P6-10A run inputs are not closed-world")
    freeze_path = Path(inputs["freeze_manifest"]["path"])
    sidecar_path = Path(inputs["freeze_hash_sidecar"]["path"])
    _verify_absolute_reference(inputs["freeze_manifest"], "P6-10A freeze manifest")
    _verify_absolute_reference(inputs["freeze_hash_sidecar"], "P6-10A freeze sidecar")
    freeze = verify_p6_10a_freeze_manifest(
        freeze_path,
        sidecar_path,
        repo_root=repository_root,
        allow_existing_output=True,
    )
    if (
        payload["git"] != freeze["git"]
        or payload["runtime"] != freeze["runtime"]
        or inputs["dependency_lock"] != freeze["dependency_lock"]
        or inputs["p6_10a_batch_manifest"] != freeze["p6_10a_batch_manifest"]
        or inputs["source_snapshot"] != freeze["source_snapshot"]
        or root != Path(freeze["paths"]["output_root"]).resolve()
    ):
        raise ValueError("P6-10A run does not join its frozen provenance")
    attempt = payload["attempt"]
    if (
        not isinstance(attempt, dict)
        or set(attempt)
        != {
            "attempt_id",
            "attempt_number",
            "retry_count",
            "marker",
        }
        or (
            attempt["attempt_id"] != P6_10A_ATTEMPT_ID
            or attempt["attempt_number"] != 1
            or attempt["retry_count"] != 0
        )
    ):
        raise ValueError("P6-10A run attempt provenance is invalid")
    marker_path = _safe_child(root, attempt["marker"]["path"], "P6-10A attempt marker")
    _verify_relative_reference(root, marker_path, attempt["marker"], "P6-10A attempt marker")
    marker = _strict_object(marker_path.read_bytes(), "P6-10A attempt marker")
    expected_marker = {
        "schema_version": P6_10A_ATTEMPT_MARKER_SCHEMA_VERSION,
        "artifact_type": "p6_10a_attempt_marker",
        "attempt_id": P6_10A_ATTEMPT_ID,
        "attempt_number": 1,
        "retry_count": 0,
        "status": "in_progress",
        "freeze_manifest_sha256": freeze["manifest_sha256"],
        "p6_10a_batch_manifest_sha256": freeze["p6_10a_batch_manifest"]["sha256"],
        "output_root": str(root),
        "partial_retention": "preserve_without_cleanup",
    }
    if marker != expected_marker:
        raise ValueError("P6-10A attempt marker is invalid")
    outputs = _closed_object(payload["outputs"], {"p6_10a_result_root"}, "P6-10A outputs")
    result_ref = outputs["p6_10a_result_root"]
    result_path = _safe_child(root, result_ref["path"], "P6-10A result root")
    _verify_relative_reference(root, result_path, result_ref, "P6-10A result root")
    snapshot = load_p6_9_snapshot(
        _safe_repo_relative(
            repository_root,
            inputs["source_snapshot"]["p6_9_run_manifest"]["path"],
            "P6-9 run manifest",
        ),
        repo_root=repository_root,
    )
    verify_p6_10a_result_root(
        result_path,
        expected_sha256=result_ref["sha256"],
        repo_root=repository_root,
        snapshot=snapshot,
    )
    artifact_parent = root / P6_10A_ARTIFACT_DIRECTORY
    if {item.name for item in root.iterdir()} != {
        P6_10A_ATTEMPT_MARKER,
        P6_10A_ARTIFACT_DIRECTORY,
        P6_10A_RUN_MANIFEST,
    } or not artifact_parent.is_dir():
        raise ValueError("P6-10A output root is not closed-world")
    if {item.name for item in artifact_parent.iterdir()} != {P6_10A_PHYSICAL_DIRECTORY} or not (
        artifact_parent / P6_10A_PHYSICAL_DIRECTORY
    ).is_dir():
        raise ValueError("P6-10A artifact namespace is not closed-world")
    return payload


def _comparator_ablation_report(
    snapshot: P69Snapshot,
    batch: P610ABatchPlan,
    artifact_references: Sequence[Mapping[str, object]] | Mapping[str, Mapping[str, object]],
    epsilon_records: Mapping[str, Sequence[ValidationArtifactRecord]],
) -> dict[str, Any]:
    source_records = snapshot.artifact_payloads["validation_exact_ev_cells"]["records"]
    selected_records = [
        item
        for item in source_records
        if item.get("candidate_id") == snapshot.selected_candidate.candidate_id
    ]
    if len(selected_records) != 810:
        raise ValueError("P6-10A comparators require exactly 810 selected exact-EV cells")
    refs = (
        dict(artifact_references)
        if isinstance(artifact_references, Mapping)
        else {item["name"]: item for item in artifact_references}
    )
    epsilon_refs = {
        name: {
            "path": refs[name]["path"],
            "sha256": refs[name]["sha256"],
            "size_bytes": refs[name]["size_bytes"],
        }
        for name in _EPSILON_ARTIFACT_NAMES
    }
    epsilon_aggregate = epsilon_records["validation_aggregate_metrics"][0].payload["result"]
    selected_series = _selected_series_id(snapshot)
    epsilon_series = epsilon_aggregate["series_id"]
    if epsilon_series == selected_series:
        raise ValueError("epsilon-zero report cannot pool with the selected series")
    zero_groups = [
        {
            "opponent_id": opponent_id,
            "horizon": horizon,
            "ev_delta": "0",
        }
        for opponent_id in sorted({key.opponent_id for key in batch.sessions})
        for horizon in HORIZONS
    ]
    zero_cells = [
        {
            "opponent_id": key.opponent_id,
            "horizon": key.horizon,
            "repetition_id": key.repetition_id,
            "ev_delta": "0",
        }
        for key in batch.sessions
    ]
    return {
        "schema_version": P6_10A_REPORT_SCHEMA_VERSION,
        "artifact_type": "p6_10a_comparator_ablation_report",
        "scope": "p6_10a_only",
        "source_snapshot": _source_snapshot_projection(snapshot),
        "selected_primary": {
            "candidate_id": snapshot.selected_candidate.candidate_id,
            "config_sha256": P6_9_SELECTED_CONFIG_SHA256,
            "series_id": selected_series,
            "manual_override": False,
            "primary_selection_recomputed": False,
        },
        "comparators": [
            {
                "comparator_id": CMP_BASE_POLICY_ID,
                "status": "derived_from_saved_exact_ev_cells",
                "source_value": "EV(pi_base)",
                "new_run": False,
                "aggregation": _ev_summary(selected_records, "base_ev"),
            },
            {
                "comparator_id": CMP_ORACLE_BR_ID,
                "status": "derived_from_saved_exact_ev_cells",
                "source_value": "EV(oracle_br)",
                "new_run": False,
                "aggregation": _ev_summary(selected_records, "oracle_br_ev"),
            },
            {
                "comparator_id": CMP_SAFETY_ALPHA_050_ID,
                "comparator_status": "degenerate_equal_to_primary",
                "selected_alpha": "0.5",
                "source_candidate_id": snapshot.selected_candidate.candidate_id,
                "source_config_sha256": P6_9_SELECTED_CONFIG_SHA256,
                "new_run": False,
                "closed_world_deltas": {
                    "cells": zero_cells,
                    "atomic_groups": zero_groups,
                    "macro_ev_delta": "0",
                    "micro_ev_delta": "0",
                },
                "interpretation_limits": [
                    "does_not_establish_alpha_superiority",
                    "does_not_establish_low_sensitivity",
                    "does_not_establish_optimality",
                    "does_not_establish_robustness",
                ],
            },
        ],
        "ablations": [
            {
                "ablation_id": ABL_EPSILON_ZERO_ID,
                "status": "executed_separate_series",
                "candidate_id": batch.candidate.candidate_id,
                "config_sha256": batch.config_sha256,
                "series_id": epsilon_series,
                "selected_series_id": selected_series,
                "series_pooling": False,
                "expected_session_count": 810,
                "expected_stream_root_count": 3240,
                "artifact_references": epsilon_refs,
            },
            {
                "ablation_id": ABL_ALPHA_FIXED_ID,
                "status": "reserved_uninstantiated",
                "reserved_uninstantiated_reason": RESERVED_ALPHA_ABLATION_REASON,
            },
        ],
        "out_of_scope_uninstantiated": [ABL_CONFIDENCE_MVP_ID, ABL_PROVIDER_RULE_ID],
        "top_four_selection_tie": {
            "keys_1_through_6_equal": True,
            "deciding_key": "canonical_candidate_id",
            "direction": "lexicographic_ascending",
        },
        "manual_override": False,
        "p6_10_complete": False,
        "gate_b_ready": False,
    }


def _gate_b_gap_packet(snapshot: P69Snapshot, batch: P610ABatchPlan) -> dict[str, Any]:
    return {
        "schema_version": P6_10A_GAP_PACKET_SCHEMA_VERSION,
        "artifact_type": "gate_b_readiness_gap_packet",
        "scope": "p6_10a_only",
        "source_snapshot": _source_snapshot_projection(snapshot),
        "p6_10a_batch_manifest_sha256": batch.manifest_sha256,
        "p6_10a_report_complete": True,
        "p6_10_complete": False,
        "gate_b_ready": False,
        "human_approval_required": True,
        "unresolved_gaps": [
            {
                "id": ABL_CONFIDENCE_MVP_ID,
                "status": "out_of_scope_uninstantiated",
                "missing_contract_fields": [
                    "estimand",
                    "retained_and_replaced_boundaries",
                    "cardinality",
                    "schema",
                    "production_discipline",
                ],
            },
            {
                "id": ABL_PROVIDER_RULE_ID,
                "status": "out_of_scope_uninstantiated",
                "missing_contract_fields": [
                    "estimand",
                    "retained_and_replaced_boundaries",
                    "cardinality",
                    "schema",
                    "production_discipline",
                ],
            },
        ],
        "prohibited_next_steps": [
            "declare_p6_10_complete",
            "declare_gate_b_ready",
            "prepare_or_open_capital_t_test",
            "generate_capital_t_test_batch_or_ledger",
            "execute_capital_t_test",
        ],
        "next_gate": "human_approval",
    }


def _ev_summary(records: Sequence[Mapping[str, Any]], field: str) -> dict[str, Any]:
    groups: dict[tuple[str, int], list[Decimal]] = defaultdict(list)
    cells: dict[tuple[str, int, str], Decimal] = {}
    seen: set[tuple[str, int, str]] = set()
    for record in records:
        key = (record["opponent_id"], record["horizon"], record["repetition_id"])
        if key in seen:
            raise ValueError("P6-10A comparator exact-EV cell key is duplicated")
        seen.add(key)
        cell = record["payload"]["result"]["cell"]
        paths = cell[field]
        production = _canonical_binary64(paths["production_binary64_hex"], "production EV")
        independent = _canonical_binary64(
            paths["independent_leaves_binary64_hex"], "independent EV"
        )
        if not math.isclose(
            production,
            independent,
            rel_tol=0.0,
            abs_tol=EV_CONSISTENCY_ABS_TOLERANCE,
        ):
            raise ValueError("P6-10A comparator source EV paths disagree")
        value = Decimal.from_float(production)
        groups[(record["opponent_id"], record["horizon"])].append(value)
        cells[key] = value
    if (
        len(seen) != 810
        or len(groups) != 27
        or any(len(values) != 30 for values in groups.values())
    ):
        raise ValueError("P6-10A comparator cells do not form the approved atomic groups")
    atomic = [
        {
            "opponent_id": opponent_id,
            "horizon": horizon,
            "cell_count": len(groups[(opponent_id, horizon)]),
            "mean_ev": _decimal_wire(_mean(groups[(opponent_id, horizon)])),
        }
        for opponent_id, horizon in sorted(groups)
    ]
    group_means = [Decimal(item["mean_ev"]) for item in atomic]
    all_values = [value for key in sorted(groups) for value in groups[key]]
    return {
        "aggregation_rule": "approved_atomic_group_equal_weight_macro_and_cell_pool_micro",
        "cell_count": 810,
        "cells": [
            {
                "opponent_id": opponent_id,
                "horizon": horizon,
                "repetition_id": repetition_id,
                "ev": _decimal_wire(cells[(opponent_id, horizon, repetition_id)]),
            }
            for opponent_id, horizon, repetition_id in sorted(cells)
        ],
        "atomic_group_count": 27,
        "atomic_groups": atomic,
        "macro_mean_ev": _decimal_wire(_mean(group_means)),
        "micro_mean_ev": _decimal_wire(_mean(all_values)),
        "decimal_precision": DECIMAL_PRECISION,
        "decimal_rounding": "ROUND_HALF_EVEN",
        "new_observations": False,
        "reweighted": False,
    }


def _verify_epsilon_zero_draws(
    rows: Sequence[Mapping[str, Any]],
    terminal_records: Sequence[ValidationArtifactRecord],
    *,
    snapshot: P69Snapshot,
    candidate: PrimaryCandidate,
    repo_root: Path,
) -> None:
    if len(rows) != 810 or len(terminal_records) != 810:
        raise ValueError("epsilon-zero draw verifier requires 810 terminal records")
    context = _evaluation_context(snapshot.plan, Path(repo_root).resolve())
    for row, record in zip(rows, terminal_records, strict=True):
        key = record.session_key()
        result = record.payload["result"]
        events = row["execution_events"]
        audits = row["action_draw_audits"]
        if not isinstance(events, list) or len(events) != key.horizon:
            raise ValueError("epsilon-zero execution events do not cover the horizon")
        transcript = hashlib.sha256()
        extracted: list[dict[str, Any]] = []
        counts: Counter[str] = Counter()
        prefix_counts: dict[int, dict[str, int]] = {}
        for index, event in enumerate(events):
            if (
                not isinstance(event, dict)
                or set(event)
                != {
                    "decision_index",
                    "deal_draw_digest",
                    "deal_outcome_id",
                    "opponent_action_draw_digest",
                    "opponent_action",
                    "hero_action",
                }
                or event["decision_index"] != index
            ):
                raise ValueError("epsilon-zero execution event is not closed-world/canonical")
            transcript.update(canonical_json_bytes(event))
            counts[event["opponent_action"]] += 1
            if event["opponent_action"] == "BET":
                prefix_counts[index] = {"BET": counts["BET"], "CHECK": counts["CHECK"]}
                action = event["hero_action"]
                if not isinstance(action, dict):
                    raise ValueError("epsilon-zero BET event lacks a Hero action audit")
                extracted.append(
                    {
                        "decision_index": index,
                        "legal_actions": ["FOLD", "CALL"],
                        "audit": action,
                    }
                )
            elif event["opponent_action"] != "CHECK" or event["hero_action"] is not None:
                raise ValueError("epsilon-zero opponent/Hero action event is invalid")
        if (
            transcript.hexdigest() != result["transcript_sha256"]
            or extracted != audits
            or result["action_counts"] != {"BET": counts["BET"], "CHECK": counts["CHECK"]}
        ):
            raise ValueError("epsilon-zero transcript/action audit hash does not reconstruct")
        if len(audits) != result["action_counts"]["BET"]:
            raise ValueError("epsilon-zero action audits do not match Hero opportunities")
        roots = {
            name: derive_stream_root(
                split="validation",
                opponent_id=key.opponent_id,
                horizon=key.horizon,
                repetition_id=key.repetition_id,
                stream_name=name,
            )
            for name in ("hero_action", "epsilon_branch", "epsilon_action")
        }
        for wrapper in audits:
            if not isinstance(wrapper, dict) or set(wrapper) != {
                "decision_index",
                "legal_actions",
                "audit",
            }:
                raise ValueError("epsilon-zero action draw wrapper is not closed-world")
            decision_index = wrapper["decision_index"]
            legal_actions = wrapper["legal_actions"]
            audit = wrapper["audit"]
            expected_fields = {
                "final_action",
                "branch_fired",
                "hero_action",
                "epsilon_action",
                "hero_draw_digest",
                "epsilon_branch_draw_digest",
                "epsilon_action_draw_digest",
                "hero_draw_status",
                "epsilon_action_draw_status",
                "epsilon_action_attempt",
            }
            if not isinstance(audit, dict) or set(audit) != expected_fields:
                raise ValueError("epsilon-zero action draw audit is not closed-world")
            if (
                audit["branch_fired"] is not False
                or audit["hero_draw_status"] != "used"
                or audit["epsilon_action_draw_status"] != "unused"
                or audit["final_action"] != audit["hero_action"]
            ):
                raise ValueError("epsilon-zero branch/use status is invalid")
            if audit["hero_draw_digest"] != derive_draw_digest(
                roots["hero_action"], decision_index=decision_index
            ) or audit["epsilon_branch_draw_digest"] != derive_draw_digest(
                roots["epsilon_branch"], decision_index=decision_index
            ):
                raise ValueError("epsilon-zero Hero/branch draws do not reconstruct")
            if epsilon_branch_fires(audit["epsilon_branch_draw_digest"], candidate.epsilon):
                raise ValueError("epsilon-zero branch unexpectedly fired")
            opponent = context.opponents[key.opponent_id]
            start = _chance_child(opponent.game.root, events[decision_index]["deal_outcome_id"])
            opponent_node = start.child_of("CHECK")
            response = opponent_node.child_of("BET")
            _base, final = _reconstruct_hero_policies(
                candidate,
                {
                    "action_counts": prefix_counts[decision_index],
                    "opportunity_count": decision_index + 1,
                },
                opponent,
                context.dimension,
            )
            ordered = tuple(legal_actions)
            if tuple(sorted(final[response.infoset])) != tuple(sorted(ordered)):
                raise ValueError("epsilon-zero Hero policy does not cover the legal actions")
            expected_hero_action = weighted_categorical(
                ordered,
                [final[response.infoset][action] for action in ordered],
                audit["hero_draw_digest"],
            )
            if audit["hero_action"] != expected_hero_action:
                raise ValueError("epsilon-zero Hero action draw does not reconstruct")
            epsilon_action, digest, attempt = uniform_action(
                legal_actions,
                roots["epsilon_action"],
                decision_index=decision_index,
            )
            if (
                audit["epsilon_action"] != epsilon_action
                or audit["epsilon_action_draw_digest"] != digest
                or audit["epsilon_action_attempt"] != attempt
            ):
                raise ValueError("epsilon-zero unused epsilon action draw does not reconstruct")


def _source_snapshot_projection(snapshot: P69Snapshot) -> dict[str, object]:
    return {
        "baseline_commit": P6_9_BASELINE,
        "pinned_verifier": {
            "mode": snapshot.pinned_verifier_mode,
            "verified_repository_commit": snapshot.verified_repository_commit,
            "historical_repository_commit": P6_9_BASELINE,
            "existing_verifier_semantics_changed": False,
        },
        "p6_9_run_manifest": {
            "path": snapshot.run_manifest_path.relative_to(snapshot.repo_root).as_posix(),
            "sha256": P6_9_RUN_MANIFEST_SHA256,
        },
        "p6_9_result_root": {
            "path": snapshot.result_root_path.relative_to(snapshot.repo_root).as_posix(),
            "sha256": P6_9_RESULT_ROOT_SHA256,
        },
        "primary_selection_report_sha256": P6_9_SELECTION_REPORT_SHA256,
        "selected_config_sha256": P6_9_SELECTED_CONFIG_SHA256,
        "selected_config_lock_sha256": P6_9_SELECTED_LOCK_SHA256,
        "validation_batch_manifest_sha256": P6_9_VALIDATION_BATCH_SHA256,
        "exact_ev_cells_sha256": P6_9_EXACT_EV_CELLS_SHA256,
        "p6_9_dependency_lock_sha256": P6_9_DEPENDENCY_LOCK_SHA256,
    }


def _run_pinned_p6_9_verifier(
    run_manifest_path: Path,
    *,
    repo_root: Path,
) -> tuple[dict[str, Any], str, str]:
    """Run the unchanged P6-9 verifier at its baseline or one approved child.

    The historical verifier correctly pins its run to the P6-9 baseline, so it
    also rejects every later repository commit.  At the P6-10A target only, we
    first verify the actual clean, pushed, direct-child Git state and the exact
    changed-path allowlist.  We then adapt only the historical repository-state
    observation while running the unchanged verifier.  All frozen inputs,
    dependency/runtime checks, output bytes, schemas, cardinalities, and
    backend reconstruction remain on the existing verifier path.
    """
    from . import validation_cli as validation_cli_module
    from . import validation_freeze as validation_freeze_module
    from .validation_freeze import ValidationRepositoryState

    state = validation_freeze_module._read_repository_state(repo_root)
    if state.head_commit == P6_9_BASELINE:
        verified = verify_validation_run_manifest(run_manifest_path, repo_root=repo_root)
        return verified, "unchanged_p6_9_verifier_at_baseline", P6_9_BASELINE
    if (
        state.branch != "main"
        or state.head_commit != state.local_main_commit
        or state.head_commit != state.cached_origin_main_commit
        or state.dirty
    ):
        raise RuntimeError("P6-10A target must be clean pushed main before P6-9 verification")
    parents = _git_stdout(repo_root, "rev-list", "--parents", "-n", "1", state.head_commit).split()
    if parents != [state.head_commit, P6_9_BASELINE]:
        raise RuntimeError("P6-10A target must be the direct child of the P6-9 baseline")
    changed = frozenset(
        line
        for line in _git_stdout(
            repo_root,
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            state.head_commit,
        ).splitlines()
        if line
    )
    if not changed or not changed <= _P6_10A_REPO_ALLOWLIST:
        raise RuntimeError("P6-10A target commit changed paths outside its repository allowlist")

    historical = ValidationRepositoryState(
        "main",
        P6_9_BASELINE,
        P6_9_BASELINE,
        P6_9_BASELINE,
        False,
    )
    original_cli_reader = validation_cli_module._read_repository_state
    original_freeze_reader = validation_freeze_module._read_repository_state
    try:
        validation_cli_module._read_repository_state = lambda _root: historical
        validation_freeze_module._read_repository_state = lambda _root: historical
        verified = verify_validation_run_manifest(run_manifest_path, repo_root=repo_root)
    finally:
        validation_cli_module._read_repository_state = original_cli_reader
        validation_freeze_module._read_repository_state = original_freeze_reader
    return verified, "unchanged_p6_9_verifier_with_direct_child_git_adapter", state.head_commit


def _git_stdout(repo_root: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-c", "core.quotepath=false", *arguments],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        raise RuntimeError("cannot independently verify the P6-10A Git target") from exc
    return completed.stdout.strip()


def _selected_series_id(snapshot: P69Snapshot) -> str:
    records = snapshot.artifact_payloads["validation_aggregate_metrics"]["records"]
    matches = [
        item
        for item in records
        if item.get("candidate_id") == snapshot.selected_candidate.candidate_id
    ]
    if len(matches) != 1:
        raise ValueError("P6-9 selected aggregate series is missing or duplicated")
    series_id = matches[0]["payload"]["result"]["series_id"]
    _validate_sha256(series_id, "P6-9 selected series ID")
    return series_id


def _first_six_selection_keys(row: Mapping[str, Any]) -> tuple[object, ...]:
    keys = row["sort_keys"]
    return (
        keys["validation_macro_brier"],
        keys["validation_micro_brier"],
        keys["gto_negative_control_micro_fpr_v1"]["false_positives"],
        keys["gto_negative_control_micro_fpr_v1"]["total_negatives"],
        keys["validation_macro_exploitation_efficiency"],
        keys["validation_macro_recall"],
        keys["validation_macro_precision"],
    )


def _candidate_from_entry(value: object) -> PrimaryCandidate:
    entry = _closed_object(value, {"candidate_id", "config"}, "Validation candidate entry")
    config = _closed_object(
        entry["config"],
        {
            "grid_version",
            "epsilon",
            "sample_floor",
            "detector_confidence",
            "provider_confidence",
            "safety_alpha",
            "sampling_contract_sha256",
        },
        "Validation candidate config",
    )
    return PrimaryCandidate(
        entry["candidate_id"],
        config["epsilon"],
        config["sample_floor"],
        config["detector_confidence"],
        config["provider_confidence"],
        config["safety_alpha"],
        config["sampling_contract_sha256"],
    )


def _candidate_from_p6_10a_entry(value: object) -> PrimaryCandidate:
    entry = _closed_object(
        value,
        {"ablation_id", "candidate_id", "config", "config_sha256", "changed_fields"},
        "P6-10A candidate entry",
    )
    return _candidate_from_entry({"candidate_id": entry["candidate_id"], "config": entry["config"]})


def _artifact_record(value: object) -> ValidationArtifactRecord:
    payload = _closed_object(
        value,
        {
            "candidate_id",
            "horizon",
            "opponent_id",
            "payload",
            "payload_sha256",
            "repetition_id",
        },
        "P6-10A wrapped Validation record",
    )
    return ValidationArtifactRecord(
        payload["candidate_id"],
        payload["payload_sha256"],
        payload["payload"],
        payload["opponent_id"],
        payload["horizon"],
        payload["repetition_id"],
    )


def _write_payloads_exclusive(root: Path, payloads: Mapping[str, bytes]) -> list[dict[str, object]]:
    references = []
    for name, raw in payloads.items():
        path = root / f"{name}.json"
        _write_exclusive(path, raw)
        references.append(_reference(name, path.name, raw))
    return references


def _reference(name: str, relative_path: str, raw: bytes) -> dict[str, object]:
    return {
        "name": name,
        "path": relative_path,
        "sha256": sha256_bytes(raw),
        "size_bytes": len(raw),
    }


def _absolute_reference(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    return {"path": str(path.resolve()), "sha256": sha256_bytes(raw), "size_bytes": len(raw)}


def _relative_reference(root: Path, path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256_bytes(raw),
        "size_bytes": len(raw),
    }


def _verify_absolute_reference(reference: object, label: str) -> None:
    ref = _closed_object(reference, {"path", "sha256", "size_bytes"}, label)
    path = Path(ref["path"])
    if not path.is_absolute():
        raise ValueError(f"{label} path must be absolute")
    raw = path.read_bytes()
    if len(raw) != ref["size_bytes"] or sha256_bytes(raw) != ref["sha256"]:
        raise ValueError(f"{label} size/hash mismatch")


def _verify_relative_reference(root: Path, path: Path, reference: object, label: str) -> None:
    ref = _closed_object(reference, {"path", "sha256", "size_bytes"}, label)
    raw = path.read_bytes()
    if len(raw) != ref["size_bytes"] or sha256_bytes(raw) != ref["sha256"]:
        raise ValueError(f"{label} size/hash mismatch")
    if path.relative_to(root).as_posix() != ref["path"]:
        raise ValueError(f"{label} relative path mismatch")


def _safe_repo_relative(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"{label} must be a POSIX repository-relative path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} escapes the repository")
    return _safe_child(root, value, label)


def _safe_child(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} path must be non-empty")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} path must be relative and contained")
    resolved_root = root.resolve()
    resolved = (resolved_root / relative).resolve()
    if resolved_root not in resolved.parents:
        raise ValueError(f"{label} path escapes its root")
    return resolved


def _closed_object(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} is not closed-world")
    return value


def _strict_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ValueError(f"{label} bytes are not a canonical JSON object")
    return payload


def _validate_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _SHA256_CHARS for character in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _canonical_binary64(value: object, label: str) -> float:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be canonical binary64 hex")
    try:
        parsed = float.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be canonical binary64 hex") from exc
    if not math.isfinite(parsed) or parsed.hex() != value:
        raise ValueError(f"{label} must be canonical finite binary64")
    return parsed


def _mean(values: Sequence[Decimal]) -> Decimal:
    if not values:
        raise ValueError("P6-10A mean requires at least one value")
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        total = Decimal(0)
        for value in values:
            total += value
        return total / Decimal(len(values))


def _decimal_wire(value: Decimal) -> str:
    if not value.is_finite():
        raise ValueError("P6-10A Decimal value must be finite")
    wire = format(value, "f").rstrip("0").rstrip(".")
    return "0" if wire in {"", "-0"} else wire


def _write_exclusive(path: Path, raw: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _parse_utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo != UTC:
        raise ValueError(f"{label} must be UTC")
    return parsed


def _parse_args(raw_argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze-manifest", required=True, type=Path)
    parser.add_argument("--freeze-hash-sidecar", required=True, type=Path)
    return parser.parse_args(list(raw_argv))


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    repo_root = Path(__file__).resolve().parents[2]
    run_path = run_p6_10a_from_freeze(
        args.freeze_manifest,
        args.freeze_hash_sidecar,
        repo_root=repo_root,
    )
    print(f"P6-10A production completed and verified: {run_path}")
    print(f"run_manifest_sha256={sha256_bytes(run_path.read_bytes())}")
    print("P6-10 overall completion and Gate B readiness remain false")
    return 0


__all__ = [
    "ABL_ALPHA_FIXED_ID",
    "ABL_CONFIDENCE_MVP_ID",
    "ABL_EPSILON_ZERO_ID",
    "ABL_PROVIDER_RULE_ID",
    "CMP_BASE_POLICY_ID",
    "CMP_ORACLE_BR_ID",
    "CMP_SAFETY_ALPHA_050_ID",
    "P6_10A_ATTEMPT_ID",
    "P6_10A_BATCH_MANIFEST",
    "P6_10A_CLI_VERSION",
    "P6_10A_ENTRYPOINT",
    "P6_10A_RESULT_ROOT",
    "P6_10A_RUN_MANIFEST",
    "P610ABatchPlan",
    "P610AResultBundle",
    "P69Snapshot",
    "build_p6_10a_batch",
    "execute_p6_10a",
    "load_p6_9_snapshot",
    "main",
    "run_p6_10a_from_freeze",
    "verify_p6_10a_batch",
    "verify_p6_10a_result_root",
    "verify_p6_10a_run_manifest",
]
