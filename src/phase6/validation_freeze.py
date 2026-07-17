"""Fail-closed P6-8B Validation freeze and read-only preflight boundaries.

QV5 values are supplied only through a canonical external manifest. The
preflight path performs no filesystem writes. Freeze and attempt reservation
APIs are explicit so production use can remain separately human-approved.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import sysconfig
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .contracts import canonical_json_bytes, sha256_bytes
from .training_cli import _runtime_payload
from .validation_runner import (
    ValidationBatchPlan,
    build_validation_batch_plan,
    verify_validation_batch_plan,
)

VALIDATION_FREEZE_CLI_VERSION = "phase6-validation-freeze-cli-v1"
VALIDATION_FREEZE_ENTRYPOINT = "cli/phase6_validation_freeze_v1.py"
VALIDATION_FREEZE_QV5_SCHEMA_VERSION = "phase6-validation-freeze-qv5-v1"
VALIDATION_FREEZE_MANIFEST_SCHEMA_VERSION = "phase6-validation-freeze-manifest-v1"
VALIDATION_ATTEMPT_MARKER_SCHEMA_VERSION = "phase6-validation-attempt-marker-v1"
VALIDATION_FREEZE_MANIFEST_NAME = "phase6_validation_freeze_manifest.json"
VALIDATION_BATCH_MANIFEST_NAME = "validation_batch_manifest.json"
VALIDATION_QV5_MANIFEST_NAME = "validation_freeze_qv5.json"
VALIDATION_ATTEMPT_MARKER_NAME = "validation_attempt_in_progress.json"

REPO_ROOT = Path(__file__).resolve().parents[2]

_SHA256_CHARS = frozenset("0123456789abcdef")
_ATTEMPT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_RUNTIME_FIELDS = {
    "python_implementation",
    "python_version",
    "python_compiler",
    "platform",
    "system",
    "release",
    "version",
    "machine",
}
_ATTEMPT_POLICY = {
    "planned_attempt_count": 1,
    "fresh_output_directory_required": True,
    "atomic_directory_reservation_required": True,
    "in_progress_marker_name": VALIDATION_ATTEMPT_MARKER_NAME,
    "partial_attempt_retention": "preserve_read_only",
    "same_path_retry_allowed": False,
    "stale_marker_auto_release_allowed": False,
    "retry_authorization": "separate_human_approval",
}


@dataclass(frozen=True, slots=True)
class ValidationFreezeSpec:
    payload: dict[str, Any]
    raw_bytes: bytes
    sha256: str
    attempt_id: str
    expected_commit: str
    cached_origin_main_commit: str
    training_run_manifest: Path
    training_run_manifest_sha256: str
    expected_validation_batch_sha256: str
    dependency_lock: Path
    dependency_lock_sha256: str
    python_executable: Path
    python_executable_sha256: str
    base_executable: Path
    base_executable_sha256: str
    runtime_fingerprint: dict[str, str]
    validation_input_dir: Path
    validation_output_dir: Path
    minimum_free_space_bytes: int
    planned_validation_command: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ValidationRepositoryState:
    branch: str
    head_commit: str
    local_main_commit: str
    cached_origin_main_commit: str
    dirty: bool

    def canonical_payload(self) -> dict[str, object]:
        return {
            "branch": self.branch,
            "head_commit": self.head_commit,
            "local_main_commit": self.local_main_commit,
            "cached_origin_main_commit": self.cached_origin_main_commit,
            "dirty": self.dirty,
            "live_remote_queried": False,
        }


@dataclass(frozen=True, slots=True)
class ValidationFreezePreflight:
    spec: ValidationFreezeSpec
    repository_root: Path
    repository_state: ValidationRepositoryState
    validation_plan: ValidationBatchPlan
    validation_input_parent_free_bytes: int
    validation_output_parent_free_bytes: int


@dataclass(frozen=True, slots=True)
class VerifiedValidationFreeze:
    manifest_path: Path
    manifest_payload: dict[str, Any]
    manifest_sha256: str
    spec: ValidationFreezeSpec
    validation_plan: ValidationBatchPlan


def _sha256(value: str) -> str:
    try:
        _validate_sha256(value, "SHA-256")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return value


def _parse_args(raw_argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for operation in ("preflight", "freeze"):
        child = subparsers.add_parser(operation)
        child.add_argument("--qv5-manifest", required=True, type=Path)
        child.add_argument("--qv5-manifest-sha256", required=True, type=_sha256)
    return parser.parse_args(raw_argv)


def load_validation_freeze_spec(
    manifest_path: Path | str,
    *,
    expected_sha256: str,
) -> ValidationFreezeSpec:
    """Load a canonical external QV5 manifest without selecting any values."""
    _validate_sha256(expected_sha256, "QV5 manifest expected hash")
    path = Path(manifest_path).resolve()
    raw = path.read_bytes()
    if sha256_bytes(raw) != expected_sha256:
        raise ValueError("QV5 manifest hash mismatch")
    payload = _strict_canonical_object(raw, "QV5 manifest")
    return validate_validation_freeze_spec(payload, expected_sha256=expected_sha256)


def validate_validation_freeze_spec(
    payload: Mapping[str, object],
    *,
    expected_sha256: str | None = None,
) -> ValidationFreezeSpec:
    """Validate the closed-world QV5 input contract and return typed paths."""
    if not isinstance(payload, dict):
        raise ValueError("QV5 manifest must be an object")
    raw = canonical_json_bytes(payload)
    actual_sha256 = sha256_bytes(raw)
    if expected_sha256 is not None:
        _validate_sha256(expected_sha256, "QV5 manifest expected hash")
        if actual_sha256 != expected_sha256:
            raise ValueError("QV5 manifest canonical hash mismatch")
    expected_fields = {
        "schema_version",
        "artifact_type",
        "attempt_id",
        "attempt_policy",
        "git",
        "training_source",
        "validation_plan",
        "runtime",
        "dependency_lock",
        "paths",
        "minimum_free_space_bytes",
        "planned_validation_command",
    }
    if set(payload) != expected_fields:
        raise ValueError("QV5 manifest fields are not closed-world")
    if (
        payload["schema_version"] != VALIDATION_FREEZE_QV5_SCHEMA_VERSION
        or payload["artifact_type"] != "validation_freeze_qv5"
    ):
        raise ValueError("QV5 manifest identity is invalid")

    attempt_id = payload["attempt_id"]
    if not isinstance(attempt_id, str) or _ATTEMPT_ID.fullmatch(attempt_id) is None:
        raise ValueError("QV5 attempt_id must use the approved lowercase ASCII form")
    if payload["attempt_policy"] != _ATTEMPT_POLICY:
        raise ValueError("QV5 attempt policy differs from the approved exactly-one discipline")

    git = _closed_mapping(
        payload["git"], {"branch", "expected_commit", "cached_origin_main_commit"}, "QV5 git"
    )
    if git["branch"] != "main":
        raise ValueError("QV5 git branch must be main")
    expected_commit = _validate_git_commit(git["expected_commit"], "QV5 expected commit")
    cached_commit = _validate_git_commit(
        git["cached_origin_main_commit"], "QV5 cached origin/main commit"
    )
    if cached_commit != expected_commit:
        raise ValueError("QV5 cached origin/main trust anchor must equal the expected commit")

    training = _closed_mapping(payload["training_source"], {"run_manifest"}, "QV5 Training source")
    training_reference = _path_reference(training["run_manifest"], "Training run manifest")
    validation_plan = _closed_mapping(
        payload["validation_plan"], {"expected_manifest_sha256"}, "QV5 Validation plan"
    )
    expected_plan_hash = _validate_sha256(
        validation_plan["expected_manifest_sha256"], "Validation batch manifest hash"
    )

    runtime = _closed_mapping(
        payload["runtime"],
        {"python_executable", "base_executable", "runtime_fingerprint"},
        "QV5 runtime",
    )
    python_reference = _path_reference(runtime["python_executable"], "Python executable")
    base_reference = _path_reference(runtime["base_executable"], "base executable")
    fingerprint = _closed_mapping(
        runtime["runtime_fingerprint"], _RUNTIME_FIELDS, "QV5 runtime fingerprint"
    )
    if any(not isinstance(value, str) or not value for value in fingerprint.values()):
        raise ValueError("QV5 runtime fingerprint values must be non-empty strings")

    dependency_reference = _path_reference(payload["dependency_lock"], "dependency lock")
    paths = _closed_mapping(
        payload["paths"], {"validation_input_dir", "validation_output_dir"}, "QV5 paths"
    )
    input_dir = _absolute_path(paths["validation_input_dir"], "Validation input directory")
    output_dir = _absolute_path(paths["validation_output_dir"], "Validation output directory")
    if (
        input_dir == output_dir
        or input_dir in output_dir.parents
        or output_dir in input_dir.parents
    ):
        raise ValueError("Validation input/output directories must be distinct and non-nested")

    minimum_free = payload["minimum_free_space_bytes"]
    if isinstance(minimum_free, bool) or not isinstance(minimum_free, int) or minimum_free <= 0:
        raise ValueError("QV5 minimum free space must be a positive integer byte count")
    command = payload["planned_validation_command"]
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(item, str) or not item or "\x00" in item for item in command)
    ):
        raise ValueError("QV5 planned Validation command must be a non-empty string argv")
    for required in (str(input_dir), str(output_dir), attempt_id):
        if command.count(required) != 1:
            raise ValueError(
                "QV5 planned Validation command must bind each path and attempt exactly once"
            )

    return ValidationFreezeSpec(
        payload=dict(payload),
        raw_bytes=raw,
        sha256=actual_sha256,
        attempt_id=attempt_id,
        expected_commit=expected_commit,
        cached_origin_main_commit=cached_commit,
        training_run_manifest=training_reference[0],
        training_run_manifest_sha256=training_reference[1],
        expected_validation_batch_sha256=expected_plan_hash,
        dependency_lock=dependency_reference[0],
        dependency_lock_sha256=dependency_reference[1],
        python_executable=python_reference[0],
        python_executable_sha256=python_reference[1],
        base_executable=base_reference[0],
        base_executable_sha256=base_reference[1],
        runtime_fingerprint=dict(fingerprint),
        validation_input_dir=input_dir,
        validation_output_dir=output_dir,
        minimum_free_space_bytes=minimum_free,
        planned_validation_command=tuple(command),
    )


def preflight_validation_freeze(
    spec: ValidationFreezeSpec,
    *,
    repo_root: Path | str = REPO_ROOT,
) -> ValidationFreezePreflight:
    """Run the complete P6-8B preflight without creating any path or artifact."""
    return _preflight_validation_freeze(spec, Path(repo_root).resolve(), frozen_input_root=None)


def freeze_validation_inputs(
    preflight: ValidationFreezePreflight,
    *,
    raw_argv: list[str],
    frozen_at_utc: str,
) -> Path:
    """Atomically reserve a fresh input bundle and write verified freeze inputs.

    Any failure after directory creation deliberately preserves the partial
    directory. There is no cleanup or overwrite path.
    """
    _parse_utc(frozen_at_utc, "frozen_at_utc")
    spec = preflight.spec
    input_root = spec.validation_input_dir
    if os.path.lexists(input_root):
        raise FileExistsError("Validation input directory must remain fresh")
    os.mkdir(input_root)
    qv5_path = input_root / VALIDATION_QV5_MANIFEST_NAME
    batch_path = input_root / VALIDATION_BATCH_MANIFEST_NAME
    manifest_path = input_root / VALIDATION_FREEZE_MANIFEST_NAME
    _write_bytes_exclusive(qv5_path, spec.raw_bytes)
    _write_bytes_exclusive(batch_path, preflight.validation_plan.manifest_bytes)
    payload = _freeze_manifest_payload(
        preflight,
        raw_argv=raw_argv,
        frozen_at_utc=frozen_at_utc,
    )
    _write_bytes_exclusive(manifest_path, canonical_json_bytes(payload))
    verify_validation_freeze_manifest(
        manifest_path,
        expected_sha256=sha256_bytes(manifest_path.read_bytes()),
        repo_root=preflight.repository_root,
    )
    return manifest_path


def verify_validation_freeze_manifest(
    manifest_path: Path | str,
    *,
    expected_sha256: str,
    repo_root: Path | str = REPO_ROOT,
) -> VerifiedValidationFreeze:
    """Rehash and independently reconstruct a frozen Validation input bundle."""
    _validate_sha256(expected_sha256, "Validation freeze manifest expected hash")
    path = Path(manifest_path).resolve()
    raw = path.read_bytes()
    if sha256_bytes(raw) != expected_sha256:
        raise ValueError("Validation freeze manifest hash mismatch")
    payload = _strict_canonical_object(raw, "Validation freeze manifest")
    expected_fields = {
        "schema_version",
        "artifact_type",
        "cli_version",
        "status",
        "split",
        "git",
        "invocation",
        "frozen_at_utc",
        "qv5_manifest",
        "validation_batch_manifest",
        "training_source",
        "runtime",
        "dependency_lock",
        "paths",
        "free_space_preflight",
        "attempt",
    }
    if set(payload) != expected_fields:
        raise ValueError("Validation freeze manifest fields are not closed-world")
    if (
        payload["schema_version"] != VALIDATION_FREEZE_MANIFEST_SCHEMA_VERSION
        or payload["artifact_type"] != "validation_freeze_manifest"
        or payload["cli_version"] != VALIDATION_FREEZE_CLI_VERSION
        or payload["status"] != "frozen_and_verified"
        or payload["split"] != "validation"
    ):
        raise ValueError("Validation freeze manifest identity is invalid")
    _parse_utc(payload["frozen_at_utc"], "frozen_at_utc")
    root = path.parent
    qv5_path, qv5_hash = _bundle_reference(root, payload["qv5_manifest"], "QV5 manifest")
    spec = load_validation_freeze_spec(qv5_path, expected_sha256=qv5_hash)
    repository_root = Path(repo_root).resolve()
    preflight = _preflight_validation_freeze(spec, repository_root, frozen_input_root=root)
    batch_path, batch_hash = _bundle_reference(
        root, payload["validation_batch_manifest"], "Validation batch manifest"
    )
    if batch_hash != preflight.validation_plan.manifest_sha256:
        raise ValueError("frozen Validation batch manifest hash is not the verified plan")
    if batch_path.read_bytes() != preflight.validation_plan.manifest_bytes:
        raise ValueError("frozen Validation batch manifest bytes do not reconstruct")
    invocation = _closed_mapping(
        payload["invocation"], {"entrypoint", "argv"}, "Validation freeze invocation"
    )
    if (
        invocation["entrypoint"] != VALIDATION_FREEZE_ENTRYPOINT
        or not isinstance(invocation["argv"], list)
        or any(not isinstance(item, str) for item in invocation["argv"])
    ):
        raise ValueError("Validation freeze invocation provenance is invalid")
    free_space = _closed_mapping(
        payload["free_space_preflight"],
        {
            "minimum_required_bytes",
            "validation_input_parent_free_bytes",
            "validation_output_parent_free_bytes",
        },
        "Validation freeze free-space provenance",
    )
    if (
        free_space["minimum_required_bytes"] != spec.minimum_free_space_bytes
        or isinstance(free_space["validation_input_parent_free_bytes"], bool)
        or not isinstance(free_space["validation_input_parent_free_bytes"], int)
        or isinstance(free_space["validation_output_parent_free_bytes"], bool)
        or not isinstance(free_space["validation_output_parent_free_bytes"], int)
        or free_space["validation_input_parent_free_bytes"] < spec.minimum_free_space_bytes
        or free_space["validation_output_parent_free_bytes"] < spec.minimum_free_space_bytes
    ):
        raise ValueError("Validation freeze free-space provenance is below the approved threshold")
    expected_projection = _freeze_manifest_payload(
        preflight,
        raw_argv=list(invocation["argv"]),
        frozen_at_utc=payload["frozen_at_utc"],
        recorded_free_space=dict(free_space),
    )
    if payload != expected_projection:
        raise ValueError("Validation freeze manifest provenance does not reconstruct")
    return VerifiedValidationFreeze(path, payload, expected_sha256, spec, preflight.validation_plan)


def reserve_validation_attempt(
    verified_freeze: VerifiedValidationFreeze,
    *,
    started_at_utc: str,
) -> Path:
    """Atomically reserve the exactly-one output path and create its marker."""
    _parse_utc(started_at_utc, "started_at_utc")
    spec = verified_freeze.spec
    output_root = spec.validation_output_dir
    if os.path.lexists(output_root):
        raise FileExistsError(
            "Validation output directory is not fresh; same-path retry is forbidden"
        )
    os.mkdir(output_root)
    marker_path = output_root / VALIDATION_ATTEMPT_MARKER_NAME
    marker = {
        "schema_version": VALIDATION_ATTEMPT_MARKER_SCHEMA_VERSION,
        "artifact_type": "validation_attempt_in_progress",
        "attempt_id": spec.attempt_id,
        "attempt_number": 1,
        "qv5_manifest_sha256": spec.sha256,
        "validation_freeze_manifest_sha256": verified_freeze.manifest_sha256,
        "validation_batch_manifest_sha256": verified_freeze.validation_plan.manifest_sha256,
        "git_commit": spec.expected_commit,
        "validation_input_dir": str(spec.validation_input_dir),
        "validation_output_dir": str(spec.validation_output_dir),
        "started_at_utc": started_at_utc,
        "retry_authorization": "separate_human_approval",
    }
    _write_bytes_exclusive(marker_path, canonical_json_bytes(marker))
    verify_validation_attempt_marker(marker_path, verified_freeze=verified_freeze)
    return marker_path


def verify_validation_attempt_marker(
    marker_path: Path | str,
    *,
    verified_freeze: VerifiedValidationFreeze,
) -> dict[str, Any]:
    path = Path(marker_path).resolve()
    payload = _strict_canonical_object(path.read_bytes(), "Validation attempt marker")
    spec = verified_freeze.spec
    expected_fields = {
        "schema_version",
        "artifact_type",
        "attempt_id",
        "attempt_number",
        "qv5_manifest_sha256",
        "validation_freeze_manifest_sha256",
        "validation_batch_manifest_sha256",
        "git_commit",
        "validation_input_dir",
        "validation_output_dir",
        "started_at_utc",
        "retry_authorization",
    }
    if set(payload) != expected_fields:
        raise ValueError("Validation attempt marker fields are not closed-world")
    _parse_utc(payload["started_at_utc"], "started_at_utc")
    expected = {
        "schema_version": VALIDATION_ATTEMPT_MARKER_SCHEMA_VERSION,
        "artifact_type": "validation_attempt_in_progress",
        "attempt_id": spec.attempt_id,
        "attempt_number": 1,
        "qv5_manifest_sha256": spec.sha256,
        "validation_freeze_manifest_sha256": verified_freeze.manifest_sha256,
        "validation_batch_manifest_sha256": verified_freeze.validation_plan.manifest_sha256,
        "git_commit": spec.expected_commit,
        "validation_input_dir": str(spec.validation_input_dir),
        "validation_output_dir": str(spec.validation_output_dir),
        "started_at_utc": payload["started_at_utc"],
        "retry_authorization": "separate_human_approval",
    }
    if payload != expected:
        raise ValueError("Validation attempt marker provenance does not reconstruct")
    if path.parent != spec.validation_output_dir or path.name != VALIDATION_ATTEMPT_MARKER_NAME:
        raise ValueError("Validation attempt marker is not at the approved output path")
    return payload


def _preflight_validation_freeze(
    spec: ValidationFreezeSpec,
    repo_root: Path,
    *,
    frozen_input_root: Path | None,
) -> ValidationFreezePreflight:
    state = _require_repository_state(repo_root, spec)
    _verify_file_reference(
        spec.training_run_manifest,
        spec.training_run_manifest_sha256,
        "Training run manifest",
    )
    _verify_runtime_and_dependency_lock(spec, repo_root)
    _validate_planned_directory(
        spec.validation_input_dir,
        repo_root,
        "Validation input directory",
        allowed_existing=frozen_input_root,
    )
    _validate_planned_directory(
        spec.validation_output_dir,
        repo_root,
        "Validation output directory",
        allowed_existing=None,
    )
    plan = build_validation_batch_plan(
        spec.training_run_manifest,
        expected_training_run_manifest_sha256=spec.training_run_manifest_sha256,
        repo_root=repo_root,
    )
    verify_validation_batch_plan(plan, repo_root=repo_root)
    if plan.manifest_sha256 != spec.expected_validation_batch_sha256:
        raise ValueError("Validation batch plan hash does not match the external QV5 value")
    input_free = _free_bytes(spec.validation_input_dir.parent)
    output_free = _free_bytes(spec.validation_output_dir.parent)
    if input_free < spec.minimum_free_space_bytes or output_free < spec.minimum_free_space_bytes:
        raise OSError("Validation input/output parent free space is below the QV5 threshold")
    return ValidationFreezePreflight(spec, repo_root, state, plan, input_free, output_free)


def _verify_runtime_and_dependency_lock(spec: ValidationFreezeSpec, repo_root: Path) -> None:
    _verify_file_reference(
        spec.python_executable, spec.python_executable_sha256, "Python executable"
    )
    _verify_file_reference(spec.base_executable, spec.base_executable_sha256, "base executable")
    _verify_file_reference(spec.dependency_lock, spec.dependency_lock_sha256, "dependency lock")
    actual_python, actual_base = _current_executable_paths()
    if actual_python != spec.python_executable or actual_base != spec.base_executable:
        raise ValueError("current Python executable/base executable differs from QV5")
    actual_runtime = _runtime_payload()
    if actual_runtime != spec.runtime_fingerprint:
        raise ValueError("current runtime/platform fingerprint differs from QV5")

    lock = _strict_canonical_object(spec.dependency_lock.read_bytes(), "dependency lock")
    if set(lock) != {"schema_version", "lock_scope", "distributions", "project", "python"}:
        raise ValueError("dependency lock fields are not closed-world")
    if (
        lock["schema_version"] != "phase6-production-dependency-lock-v1"
        or lock["lock_scope"] != "complete-installed-environment-snapshot"
    ):
        raise ValueError("dependency lock identity is invalid")
    project = _closed_mapping(
        lock["project"],
        {"name", "version", "source", "repository_path", "git_commit"},
        "dependency lock project",
    )
    if (
        project["source"] != "repository"
        or project["repository_path"] != "."
        or project["git_commit"] != spec.expected_commit
        or not isinstance(project["name"], str)
        or not isinstance(project["version"], str)
        or _installed_project_version(project["name"]) != project["version"]
    ):
        raise ValueError("dependency lock local project does not match QV5/git")
    distributions = lock["distributions"]
    if not isinstance(distributions, list):
        raise ValueError("dependency lock distributions must be a list")
    expected_distributions: list[tuple[str, str]] = []
    for item in distributions:
        entry = _closed_mapping(item, {"name", "version"}, "dependency distribution")
        name = entry["name"]
        version = entry["version"]
        if (
            not isinstance(name, str)
            or _normalize_distribution_name(name) != name
            or not isinstance(version, str)
            or not version
        ):
            raise ValueError("dependency distribution identity is not canonical")
        expected_distributions.append((name, version))
    if expected_distributions != sorted(set(expected_distributions)):
        raise ValueError("dependency lock distributions are not unique canonical order")
    if tuple(expected_distributions) != _installed_distributions(project["name"]):
        raise ValueError("installed distribution snapshot differs from dependency lock")

    python = _closed_mapping(
        lock["python"],
        {
            "implementation",
            "version",
            "compiler",
            "platform",
            "venv_executable_path",
            "venv_executable_sha256",
            "base_executable_path",
            "base_executable_sha256",
            "pyvenv_cfg_path",
            "pyvenv_cfg_sha256",
            "site_packages_path",
        },
        "dependency lock Python",
    )
    locked_venv = _repo_relative_file(repo_root, python["venv_executable_path"], "venv executable")
    locked_base = _absolute_path(python["base_executable_path"], "locked base executable")
    locked_cfg = _repo_relative_file(repo_root, python["pyvenv_cfg_path"], "pyvenv.cfg")
    site_packages = _repo_relative_path(
        repo_root, python["site_packages_path"], "site-packages directory"
    )
    active_cfg, active_site_packages = _current_environment_paths()
    if not site_packages.is_dir():
        raise ValueError("dependency lock site-packages directory does not exist")
    if (
        locked_venv != spec.python_executable
        or python["venv_executable_sha256"] != spec.python_executable_sha256
        or locked_base != spec.base_executable
        or python["base_executable_sha256"] != spec.base_executable_sha256
        or locked_cfg != active_cfg
        or site_packages != active_site_packages
        or sha256_bytes(locked_cfg.read_bytes()) != python["pyvenv_cfg_sha256"]
        or python["implementation"] != actual_runtime["python_implementation"]
        or python["version"] != actual_runtime["python_version"]
        or python["compiler"] != actual_runtime["python_compiler"]
        or python["platform"] != actual_runtime["platform"]
    ):
        raise ValueError("dependency lock Python/runtime provenance differs from QV5")


def _freeze_manifest_payload(
    preflight: ValidationFreezePreflight,
    *,
    raw_argv: list[str],
    frozen_at_utc: str,
    recorded_free_space: dict[str, object] | None = None,
) -> dict[str, object]:
    spec = preflight.spec
    free_space = recorded_free_space or {
        "minimum_required_bytes": spec.minimum_free_space_bytes,
        "validation_input_parent_free_bytes": preflight.validation_input_parent_free_bytes,
        "validation_output_parent_free_bytes": preflight.validation_output_parent_free_bytes,
    }
    return {
        "schema_version": VALIDATION_FREEZE_MANIFEST_SCHEMA_VERSION,
        "artifact_type": "validation_freeze_manifest",
        "cli_version": VALIDATION_FREEZE_CLI_VERSION,
        "status": "frozen_and_verified",
        "split": "validation",
        "git": preflight.repository_state.canonical_payload(),
        "invocation": {"entrypoint": VALIDATION_FREEZE_ENTRYPOINT, "argv": list(raw_argv)},
        "frozen_at_utc": frozen_at_utc,
        "qv5_manifest": {
            "name": "validation_freeze_qv5",
            "path": VALIDATION_QV5_MANIFEST_NAME,
            "sha256": spec.sha256,
        },
        "validation_batch_manifest": {
            "name": "validation_batch_manifest",
            "path": VALIDATION_BATCH_MANIFEST_NAME,
            "sha256": preflight.validation_plan.manifest_sha256,
        },
        "training_source": preflight.validation_plan.manifest["training_source"],
        "runtime": spec.payload["runtime"],
        "dependency_lock": spec.payload["dependency_lock"],
        "paths": spec.payload["paths"],
        "free_space_preflight": free_space,
        "attempt": {
            "attempt_id": spec.attempt_id,
            "policy": dict(_ATTEMPT_POLICY),
            "planned_validation_command": list(spec.planned_validation_command),
        },
    }


def _require_repository_state(
    repo_root: Path, spec: ValidationFreezeSpec
) -> ValidationRepositoryState:
    state = _read_repository_state(repo_root)
    if (
        state.branch != "main"
        or state.head_commit != spec.expected_commit
        or state.local_main_commit != spec.expected_commit
        or state.cached_origin_main_commit != spec.cached_origin_main_commit
        or state.dirty
    ):
        raise RuntimeError("repository state does not match the clean QV5 main trust anchor")
    return state


def _read_repository_state(repo_root: Path) -> ValidationRepositoryState:
    branch = _git(repo_root, "branch", "--show-current").strip()
    head = _git(repo_root, "rev-parse", "HEAD").strip()
    local_main = _git(repo_root, "rev-parse", "refs/heads/main").strip()
    cached = _git(repo_root, "rev-parse", "refs/remotes/origin/main").strip()
    for value, label in (
        (head, "HEAD"),
        (local_main, "local main"),
        (cached, "cached origin/main"),
    ):
        _validate_git_commit(value, label)
    dirty = bool(_git(repo_root, "status", "--porcelain=v1", "--untracked-files=all").strip())
    return ValidationRepositoryState(branch, head, local_main, cached, dirty)


def _git(repo_root: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            _git_command(repo_root, *arguments),
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        raise RuntimeError("cannot verify the Validation repository state") from exc
    return completed.stdout


def _validate_planned_directory(
    path: Path,
    repo_root: Path,
    label: str,
    *,
    allowed_existing: Path | None,
) -> None:
    repository_root = repo_root.resolve()
    try:
        path.relative_to(repository_root)
    except ValueError as exc:
        raise ValueError(f"{label} must remain within the repository root") from exc
    if path == repository_root or repository_root / ".git" in (path, *path.parents):
        raise ValueError(f"{label} must not be the repository root or .git")
    if allowed_existing is None:
        if os.path.lexists(path):
            raise FileExistsError(f"{label} must be fresh")
    elif path != allowed_existing.resolve() or not path.is_dir():
        raise ValueError(f"{label} is not the verified frozen input root")
    if not path.parent.is_dir():
        raise ValueError(f"{label} parent must already exist")
    if not _is_git_ignored(repo_root, path):
        raise ValueError(f"{label} must be ignored by Git")


def _is_git_ignored(repo_root: Path, path: Path) -> bool:
    relative = path.relative_to(repo_root.resolve()).as_posix()
    try:
        completed = subprocess.run(
            _git_command(repo_root, "check-ignore", "-q", "--", relative),
            cwd=repo_root,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        raise RuntimeError("cannot verify Validation path ignore status") from exc
    if completed.returncode not in {0, 1}:
        raise RuntimeError("git check-ignore failed during Validation preflight")
    return completed.returncode == 0


def _git_command(repo_root: Path, *arguments: str) -> list[str]:
    return [
        "git",
        "--no-optional-locks",
        "-c",
        f"safe.directory={repo_root.as_posix()}",
        *arguments,
    ]


def _current_executable_paths() -> tuple[Path, Path]:
    return (
        Path(sys.executable).resolve(),
        Path(getattr(sys, "_base_executable", sys.executable)).resolve(),
    )


def _current_environment_paths() -> tuple[Path, Path]:
    purelib = sysconfig.get_path("purelib")
    if not purelib:
        raise RuntimeError("cannot derive active Python purelib path")
    return (
        (Path(sys.prefix) / "pyvenv.cfg").resolve(),
        Path(purelib).resolve(),
    )


def _installed_distributions(local_project_name: str) -> tuple[tuple[str, str], ...]:
    local_name = _normalize_distribution_name(local_project_name)
    values: list[tuple[str, str]] = []
    for distribution in importlib.metadata.distributions():
        raw_name = distribution.metadata.get("Name")
        if not raw_name:
            raise ValueError("installed distribution is missing its canonical name")
        name = _normalize_distribution_name(raw_name)
        if name != local_name:
            values.append((name, distribution.version))
    if len(values) != len(set(values)):
        raise ValueError("installed environment contains duplicate distribution identities")
    return tuple(sorted(values))


def _installed_project_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError as exc:
        raise ValueError("locked local project is not installed") from exc


def _normalize_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _free_bytes(path: Path) -> int:
    return shutil.disk_usage(path).free


def _write_bytes_exclusive(path: Path, raw: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def _strict_canonical_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ValueError(f"{label} bytes are not a canonical object")
    return payload


def _closed_mapping(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} fields are not closed-world")
    return value


def _path_reference(value: object, label: str) -> tuple[Path, str]:
    reference = _closed_mapping(value, {"path", "sha256"}, label)
    return (
        _absolute_path(reference["path"], f"{label} path"),
        _validate_sha256(reference["sha256"], f"{label} hash"),
    )


def _bundle_reference(root: Path, value: object, label: str) -> tuple[Path, str]:
    reference = _closed_mapping(value, {"name", "path", "sha256"}, label)
    relative = reference["path"]
    if (
        not isinstance(reference["name"], str)
        or not isinstance(relative, str)
        or not relative
        or "\\" in relative
        or Path(relative).is_absolute()
        or ".." in Path(relative).parts
    ):
        raise ValueError(f"{label} reference is invalid")
    path = (root / relative).resolve()
    if root != path and root not in path.parents:
        raise ValueError(f"{label} path escapes the freeze bundle")
    expected_hash = _validate_sha256(reference["sha256"], f"{label} hash")
    _verify_file_reference(path, expected_hash, label)
    return path, expected_hash


def _absolute_path(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{label} must be a non-empty absolute path string")
    candidate = Path(value)
    if not candidate.is_absolute():
        raise ValueError(f"{label} must be absolute")
    resolved = candidate.resolve()
    if str(resolved) != value:
        raise ValueError(f"{label} must use its resolved canonical absolute form")
    return resolved


def _repo_relative_path(repo_root: Path, value: object, label: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or Path(value).is_absolute()
        or ".." in Path(value).parts
    ):
        raise ValueError(f"{label} must be a safe repository-relative path")
    path = (repo_root / value).resolve()
    try:
        path.relative_to(repo_root)
    except ValueError as exc:
        raise ValueError(f"{label} escapes the repository") from exc
    return path


def _repo_relative_file(repo_root: Path, value: object, label: str) -> Path:
    path = _repo_relative_path(repo_root, value, label)
    if not path.is_file():
        raise ValueError(f"{label} must be an existing regular file")
    return path


def _verify_file_reference(path: Path, expected_sha256: str, label: str) -> None:
    if not path.is_file():
        raise ValueError(f"{label} must be an existing regular file")
    if sha256_bytes(path.read_bytes()) != expected_sha256:
        raise ValueError(f"{label} hash mismatch")


def _validate_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _SHA256_CHARS for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase 64-character SHA-256")
    return value


def _validate_git_commit(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in _SHA256_CHARS for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase 40-character git commit")
    return value


def _parse_utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} must be an explicit UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} is not an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo != UTC:
        raise ValueError(f"{label} must be UTC")
    return parsed


def _utc_now_wire() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = _parse_args(raw_argv)
    spec = load_validation_freeze_spec(
        args.qv5_manifest,
        expected_sha256=args.qv5_manifest_sha256,
    )
    preflight = preflight_validation_freeze(spec, repo_root=REPO_ROOT)
    if args.operation == "preflight":
        print("Validation freeze preflight verified (read-only; no path reserved)")
        print(f"qv5_manifest_sha256={spec.sha256}")
        print(f"validation_batch_manifest_sha256={preflight.validation_plan.manifest_sha256}")
        print(f"validation_input_parent_free_bytes={preflight.validation_input_parent_free_bytes}")
        print(
            f"validation_output_parent_free_bytes={preflight.validation_output_parent_free_bytes}"
        )
        return 0
    manifest_path = freeze_validation_inputs(
        preflight,
        raw_argv=raw_argv,
        frozen_at_utc=_utc_now_wire(),
    )
    print(f"Validation inputs frozen and verified: {manifest_path.parent}")
    print(f"freeze_manifest_sha256={sha256_bytes(manifest_path.read_bytes())}")
    print("Validation execution not started; output attempt path remains unreserved")
    return 0


__all__ = [
    "VALIDATION_ATTEMPT_MARKER_NAME",
    "VALIDATION_ATTEMPT_MARKER_SCHEMA_VERSION",
    "VALIDATION_BATCH_MANIFEST_NAME",
    "VALIDATION_FREEZE_CLI_VERSION",
    "VALIDATION_FREEZE_ENTRYPOINT",
    "VALIDATION_FREEZE_MANIFEST_NAME",
    "VALIDATION_FREEZE_MANIFEST_SCHEMA_VERSION",
    "VALIDATION_FREEZE_QV5_SCHEMA_VERSION",
    "VALIDATION_QV5_MANIFEST_NAME",
    "ValidationFreezePreflight",
    "ValidationFreezeSpec",
    "ValidationRepositoryState",
    "VerifiedValidationFreeze",
    "freeze_validation_inputs",
    "load_validation_freeze_spec",
    "main",
    "preflight_validation_freeze",
    "reserve_validation_attempt",
    "validate_validation_freeze_spec",
    "verify_validation_attempt_marker",
    "verify_validation_freeze_manifest",
]
