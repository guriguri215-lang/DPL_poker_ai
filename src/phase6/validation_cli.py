"""Versioned P6-9B production Validation run orchestration and provenance.

The CLI exposes only the frozen input path, fresh output path, and exactly-one
attempt ID already fixed by QV5. It has no experiment-axis options. Production
execution is reachable only after the P6-8B freeze and repository gates pass.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opponents import load_validation_catalog
from opponents.ground_truth import extract_independent_action_rates
from opponents.synthesis import synthesize_opponent
from poker_ai.leak import BET_ACTIONS
from poker_core.dpl_schema import DPL_SCHEMA_VERSION
from poker_core.reason_ontology import get_ontology

from .calibration import CALIBRATION_EVALUATOR_VERSION, EXACT_EV_INPUT_VERSION
from .contracts import ROOT_MANIFEST_SCHEMA_VERSION, canonical_json_bytes, sha256_bytes
from .exact_ev import (
    EV_CONSISTENCY_ABS_TOLERANCE_WIRE,
    EV_DENOMINATOR_ABS_TOLERANCE_WIRE,
)
from .p6_7 import EXECUTION_SAMPLER_VERSION, REPETITION_SEEDS, validate_sampling_contract
from .production_inputs import (
    EXPLOIT_PROVIDER_VERSION,
    GROUND_TRUTH_EXTRACTOR_VERSION,
    PRODUCTION_INPUT_BUILDER_VERSION,
    build_production_observation_registry,
)
from .training_cli import (
    CANONICALIZER_VERSION,
    PRODUCTION_BASELINE_TABLE_VERSION,
    PRODUCTION_ESTIMATOR_VERSION,
    PRODUCTION_SAFETY_MIXER_VERSION,
    _decimal_wire,
    _game_sha256,
    _strategy_sha256,
)
from .training_runner import HORIZONS
from .validation_backend import (
    PRODUCTION_VALIDATION_BACKEND_ID,
    PRODUCTION_VALIDATION_BACKEND_VERSION,
    ProductionValidationExecutionBackend,
)
from .validation_execution import (
    _ARTIFACT_TYPES,
    _CARDINALITY,
    VALIDATION_ARTIFACT_BASE_DIRECTORY,
    VALIDATION_EXECUTION_ADAPTER_VERSION,
    VALIDATION_EXECUTION_ARTIFACT_SCHEMA_VERSION,
    VALIDATION_PHYSICAL_DIRECTORY,
    VALIDATION_ROOT_MANIFEST_SCHEMA_VERSION,
    VALIDATION_WRITER_VERSION,
    ValidationArtifactBundle,
    ValidationArtifactRecord,
    _selected_lock,
    _selection_report,
    _validation_root,
    run_validation_execution_adapter,
    verify_validation_artifact_root,
    verify_validation_execution_records,
)
from .validation_freeze import (
    VALIDATION_ATTEMPT_MARKER_NAME,
    VALIDATION_BATCH_MANIFEST_NAME,
    VALIDATION_FREEZE_CLI_VERSION,
    VALIDATION_FREEZE_ENTRYPOINT,
    VALIDATION_FREEZE_MANIFEST_NAME,
    VALIDATION_FREEZE_MANIFEST_SCHEMA_VERSION,
    VALIDATION_QV5_MANIFEST_NAME,
    VerifiedValidationFreeze,
    _read_repository_state,
    _verify_runtime_and_dependency_lock,
    load_validation_freeze_spec,
    reserve_validation_attempt,
    verify_validation_attempt_marker,
    verify_validation_freeze_manifest,
)
from .validation_freeze import (
    _parse_args as _parse_freeze_args,
)
from .validation_runner import (
    VALIDATION_RUNNER_VERSION,
    build_validation_batch_plan,
    verify_validation_batch_plan,
)

PRODUCTION_VALIDATION_CLI_VERSION = "phase6-production-validation-cli-v1"
PRODUCTION_VALIDATION_RUN_SCHEMA_VERSION = "phase6-production-validation-run-manifest-v1"
PRODUCTION_VALIDATION_ENTRYPOINT = "cli/phase6_validation_v1.py"
PRODUCTION_VALIDATION_RUN_MANIFEST = "phase6_validation_run_manifest.json"

REPO_ROOT = Path(__file__).resolve().parents[2]

_SHA256_CHARS = frozenset("0123456789abcdef")
_ATTEMPT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
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
class PreparedValidationRun:
    raw_argv: tuple[str, ...]
    verified_freeze: VerifiedValidationFreeze
    freeze_manifest_sha256: str


def _is_reparse_or_symlink(path: Path) -> bool:
    metadata = path.lstat()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & reparse_flag
    )


def _reject_reparse_chain(path: Path) -> None:
    current = path.absolute()
    while True:
        if os.path.lexists(current) and _is_reparse_or_symlink(current):
            raise ValueError("Validation output path contains a symlink or reparse point")
        if current.parent == current:
            return
        current = current.parent


def _directory_identity(path: Path) -> tuple[int, int]:
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or _is_reparse_or_symlink(path):
        raise ValueError("Validation output path must be a physical directory")
    return metadata.st_dev, metadata.st_ino


class _PinnedDirectory:
    """Hold a physical directory open and reject path-to-inode substitution."""

    def __init__(self, path: Path) -> None:
        self.path = path.absolute()
        _reject_reparse_chain(self.path)
        self.identity = _directory_identity(self.path)
        self._fd: int | None = None
        self._windows_handle: int | None = None
        self._anchor_fds: list[int] = []
        self._anchor_windows_handles: list[int] = []
        if os.name == "nt":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            create_file = kernel32.CreateFileW
            create_file.argtypes = (
                ctypes.c_wchar_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
            )
            create_file.restype = ctypes.c_void_p
            handle = create_file(
                str(self.path),
                0x00000080,
                0x00000001 | 0x00000002,
                None,
                3,
                0x02000000 | 0x00200000,
                None,
            )
            invalid_handle = ctypes.c_void_p(-1).value
            if handle in (None, invalid_handle):
                raise OSError(ctypes.get_last_error(), "cannot pin Validation directory")
            self._windows_handle = int(handle)
        else:
            flags = os.O_RDONLY
            flags |= getattr(os, "O_DIRECTORY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            self._fd = os.open(self.path, flags)
        self.verify()

    def __enter__(self) -> _PinnedDirectory:
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()

    def close(self) -> None:
        while self._anchor_fds:
            os.close(self._anchor_fds.pop())
        if self._anchor_windows_handles:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            close_handle = kernel32.CloseHandle
            close_handle.argtypes = (ctypes.c_void_p,)
            close_handle.restype = ctypes.c_int
            while self._anchor_windows_handles:
                handle = self._anchor_windows_handles.pop()
                if not close_handle(ctypes.c_void_p(handle)):
                    raise OSError(ctypes.get_last_error(), "cannot close Validation file pin")
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        if self._windows_handle is not None:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            close_handle = kernel32.CloseHandle
            close_handle.argtypes = (ctypes.c_void_p,)
            close_handle.restype = ctypes.c_int
            if not close_handle(ctypes.c_void_p(self._windows_handle)):
                raise OSError(ctypes.get_last_error(), "cannot close Validation directory pin")
            self._windows_handle = None

    def pin_regular_file(self, name: str) -> Path:
        if not name or Path(name).name != name:
            raise ValueError("Validation anchor file name must be direct")
        self.verify()
        path = self.path / name
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or _is_reparse_or_symlink(path):
            raise ValueError("Validation anchor must be a physical regular file")
        if os.name == "nt":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            create_file = kernel32.CreateFileW
            create_file.argtypes = (
                ctypes.c_wchar_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
            )
            create_file.restype = ctypes.c_void_p
            handle = create_file(
                str(path),
                0x00000080,
                0x00000001 | 0x00000002,
                None,
                3,
                0x00200000,
                None,
            )
            invalid_handle = ctypes.c_void_p(-1).value
            if handle in (None, invalid_handle):
                raise OSError(ctypes.get_last_error(), "cannot pin Validation anchor file")
            self._anchor_windows_handles.append(int(handle))
        else:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            if self._fd is not None and os.open in os.supports_dir_fd:
                descriptor = os.open(name, flags, dir_fd=self._fd)
            else:
                descriptor = os.open(path, flags)
            self._anchor_fds.append(descriptor)
        after = path.lstat()
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise RuntimeError("Validation anchor file identity changed while pinning")
        self.verify()
        return path

    def verify(self) -> None:
        _reject_reparse_chain(self.path)
        if _directory_identity(self.path) != self.identity:
            raise RuntimeError("reserved Validation directory identity changed")

    def stable_path(self) -> Path:
        if self._fd is not None:
            for base in (Path("/proc/self/fd"), Path("/dev/fd")):
                candidate = base / str(self._fd)
                if candidate.exists():
                    return candidate
        return self.path

    def mkdir(self, name: str) -> Path:
        if not name or Path(name).name != name:
            raise ValueError("Validation child directory name must be direct")
        self.verify()
        if self._fd is not None and os.mkdir in os.supports_dir_fd:
            os.mkdir(name, dir_fd=self._fd)
        else:
            os.mkdir(self.path / name)
        self.verify()
        child = self.path / name
        _reject_reparse_chain(child)
        _directory_identity(child)
        return child

    def mkdir_pinned(self, name: str) -> _PinnedDirectory:
        """Create and immediately pin one physical direct child directory."""
        child = self.mkdir(name)
        try:
            pin = _PinnedDirectory(child)
        except BaseException:
            self.verify()
            raise
        self.verify()
        return pin

    def write_exclusive(self, name: str, raw: bytes) -> Path:
        if not name or Path(name).name != name:
            raise ValueError("Validation output file name must be direct")
        self.verify()
        descriptor = self._open_exclusive(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
        self.verify()
        return self.path / name

    def create_exclusive_pinned(self, name: str) -> tuple[Path, int]:
        """Create one direct file and retain its no-delete handle until close."""
        if not name or Path(name).name != name:
            raise ValueError("Validation output file name must be direct")
        self.verify()
        descriptor = self._open_exclusive(name)
        self._anchor_fds.append(descriptor)
        self.verify()
        return self.path / name, descriptor

    def write_pinned(self, descriptor: int, raw: bytes) -> None:
        if descriptor not in self._anchor_fds:
            raise ValueError("Validation artifact descriptor is not pinned")
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("cannot write complete Validation artifact")
            view = view[written:]
        self.verify()

    def _open_exclusive(self, name: str) -> int:
        if os.name == "nt":
            import msvcrt

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            create_file = kernel32.CreateFileW
            create_file.argtypes = (
                ctypes.c_wchar_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
            )
            create_file.restype = ctypes.c_void_p
            handle = create_file(
                str(self.path / name),
                0x40000000,
                0x00000001 | 0x00000002,
                None,
                1,
                0x00000080 | 0x00200000,
                None,
            )
            invalid_handle = ctypes.c_void_p(-1).value
            if handle in (None, invalid_handle):
                raise OSError(ctypes.get_last_error(), "cannot create Validation artifact")
            try:
                return msvcrt.open_osfhandle(
                    int(handle),
                    os.O_WRONLY | getattr(os, "O_BINARY", 0),
                )
            except BaseException:
                kernel32.CloseHandle(ctypes.c_void_p(handle))
                raise
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        if self._fd is not None and os.open in os.supports_dir_fd:
            return os.open(name, flags, 0o600, dir_fd=self._fd)
        return os.open(self.path / name, flags, 0o600)


def _validate_prospective_validation_root(verified: VerifiedValidationFreeze) -> Path:
    output_root = verified.spec.validation_output_dir
    _reject_reparse_chain(output_root.parent)
    prospective = output_root / VALIDATION_ARTIFACT_BASE_DIRECTORY / VALIDATION_PHYSICAL_DIRECTORY
    physical_root = _validation_root(prospective)
    expected = output_root / VALIDATION_ARTIFACT_BASE_DIRECTORY / VALIDATION_PHYSICAL_DIRECTORY
    if physical_root != expected:
        raise ValueError("prospective Validation artifact root escapes the approved output root")
    try:
        physical_root.relative_to(output_root)
    except ValueError as exc:
        raise ValueError(
            "prospective Validation artifact root escapes the approved output root"
        ) from exc
    return physical_root


def _verify_pinned_marker(pin: _PinnedDirectory, marker_path: Path) -> None:
    pin.verify()
    if marker_path.absolute() != pin.path / VALIDATION_ATTEMPT_MARKER_NAME:
        raise ValueError("Validation attempt marker is outside the reserved output root")
    if _is_reparse_or_symlink(marker_path) or not marker_path.is_file():
        raise ValueError("Validation attempt marker must be a physical regular file")


def _verify_validation_write_boundary(
    validation_pin: _PinnedDirectory,
    completed_file_count: int,
) -> None:
    """Fail closed at every final-directory artifact write boundary."""
    if not isinstance(completed_file_count, int) or completed_file_count < 0:
        raise ValueError("Validation completed file count is invalid")
    validation_pin.verify()


def _write_pinned_bundle_files(
    validation_pin: _PinnedDirectory,
    payloads: Mapping[str, bytes],
    root_payload_prefix: Mapping[str, object],
) -> tuple[Path, str]:
    """Write a complete bundle below one pinned final directory handle."""
    if "artifacts" in root_payload_prefix:
        raise ValueError("Validation root prefix must not supply artifact references")
    references: list[dict[str, object]] = []
    for completed_file_count, (name, raw) in enumerate(payloads.items()):
        if not isinstance(name, str) or not isinstance(raw, bytes):
            raise TypeError("Validation artifact payloads must be named bytes")
        path, descriptor = validation_pin.create_exclusive_pinned(f"{name}.json")
        _verify_validation_write_boundary(validation_pin, completed_file_count)
        validation_pin.write_pinned(descriptor, raw)
        references.append(
            {
                "name": name,
                "path": path.name,
                "sha256": sha256_bytes(raw),
                "size_bytes": len(raw),
            }
        )
    root_payload = {**root_payload_prefix, "artifacts": references}
    root_raw = canonical_json_bytes(root_payload)
    root_path, root_descriptor = validation_pin.create_exclusive_pinned(
        "validation_result_root.json"
    )
    _verify_validation_write_boundary(validation_pin, len(payloads))
    validation_pin.write_pinned(root_descriptor, root_raw)
    validation_pin.verify()
    return root_path, sha256_bytes(root_raw)


def _prepare_validation_artifact_bundle(
    plan: Any,
    records_by_type: Mapping[str, Sequence[ValidationArtifactRecord]],
    *,
    repo_root: Path | str,
) -> tuple[dict[str, bytes], dict[str, object]]:
    """Reconstruct all P6-9A bytes before creating the final directory."""
    ranked = verify_validation_execution_records(plan, records_by_type, repo_root=repo_root)
    payloads: dict[str, bytes] = {"validation_batch_manifest": plan.manifest_bytes}
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
    root_prefix = {
        "schema_version": VALIDATION_ROOT_MANIFEST_SCHEMA_VERSION,
        "artifact_type": "validation_result_root",
        "writer_version": VALIDATION_WRITER_VERSION,
        "split": "validation",
        "physical_directory": VALIDATION_PHYSICAL_DIRECTORY,
        "validation_batch_manifest_sha256": plan.manifest_sha256,
        "backend": backend,
        "selection_contract_sha256": plan.manifest["selection_metric_contract"]["sha256"],
        "expected_cardinality": dict(_CARDINALITY),
    }
    return payloads, root_prefix


def _write_prepared_validation_artifact_bundle(
    validation_pin: _PinnedDirectory,
    prepared_bundle: tuple[Mapping[str, bytes], Mapping[str, object]],
    *,
    repo_root: Path | str,
) -> ValidationArtifactBundle:
    """Persist already-reconstructed P6-9A bytes through pinned handles."""
    payloads, root_prefix = prepared_bundle
    root_path, root_hash = _write_pinned_bundle_files(
        validation_pin,
        payloads,
        root_prefix,
    )
    stable_root_path = validation_pin.stable_path() / root_path.name
    verify_validation_artifact_root(
        stable_root_path,
        expected_sha256=root_hash,
        repo_root=repo_root,
    )
    validation_pin.verify()
    return ValidationArtifactBundle(validation_pin.path, root_path, root_hash)


def _write_validation_artifact_bundle_pinned(
    plan: Any,
    records_by_type: Mapping[str, Sequence[ValidationArtifactRecord]],
    validation_pin: _PinnedDirectory,
    *,
    repo_root: Path | str,
) -> ValidationArtifactBundle:
    """Serialize the P6-9A bundle through a verified final-directory handle."""
    prepared_bundle = _prepare_validation_artifact_bundle(
        plan,
        records_by_type,
        repo_root=repo_root,
    )
    return _write_prepared_validation_artifact_bundle(
        validation_pin,
        prepared_bundle,
        repo_root=repo_root,
    )


def _attempt_id(value: str) -> str:
    if _ATTEMPT_ID.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("attempt ID must use lowercase ASCII")
    return value


def _parse_args(raw_argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validation-input-dir", required=True, type=Path)
    parser.add_argument("--validation-output-dir", required=True, type=Path)
    parser.add_argument("--attempt-id", required=True, type=_attempt_id)
    return parser.parse_args(raw_argv)


def _canonical_argv(verified: VerifiedValidationFreeze) -> tuple[str, ...]:
    spec = verified.spec
    return (
        "--validation-input-dir",
        str(spec.validation_input_dir),
        "--validation-output-dir",
        str(spec.validation_output_dir),
        "--attempt-id",
        spec.attempt_id,
    )


def _planned_command(
    verified: VerifiedValidationFreeze,
    raw_argv: tuple[str, ...],
    repo_root: Path,
) -> tuple[str, ...]:
    return (
        str(verified.spec.python_executable),
        str((repo_root / PRODUCTION_VALIDATION_ENTRYPOINT).resolve()),
        *raw_argv,
    )


def prepare_validation_run(
    raw_argv: list[str],
    *,
    repo_root: Path | str = REPO_ROOT,
    allow_existing_output: bool = False,
) -> PreparedValidationRun:
    """Verify the frozen run inputs and exact approved CLI projection."""
    args = _parse_args(raw_argv)
    repository_root = Path(repo_root).resolve()
    input_dir = args.validation_input_dir.resolve()
    output_dir = args.validation_output_dir.resolve()
    if not args.validation_input_dir.is_absolute() or not args.validation_output_dir.is_absolute():
        raise ValueError("Validation run paths must be absolute")
    freeze_path = input_dir / VALIDATION_FREEZE_MANIFEST_NAME
    if not freeze_path.is_file():
        raise ValueError("Validation input directory lacks the frozen manifest")
    freeze_hash = sha256_bytes(freeze_path.read_bytes())
    if allow_existing_output:
        verified = _verify_frozen_inputs_after_reservation(
            freeze_path,
            expected_sha256=freeze_hash,
            repo_root=repository_root,
        )
    else:
        verified = verify_validation_freeze_manifest(
            freeze_path,
            expected_sha256=freeze_hash,
            repo_root=repository_root,
        )
    spec = verified.spec
    if (
        input_dir != spec.validation_input_dir
        or output_dir != spec.validation_output_dir
        or args.attempt_id != spec.attempt_id
    ):
        raise ValueError("Validation CLI arguments differ from the frozen QV5 values")
    canonical_argv = _canonical_argv(verified)
    if tuple(raw_argv) != canonical_argv:
        raise ValueError("Validation CLI argv is not in the canonical approved order")
    if spec.planned_validation_command != _planned_command(
        verified,
        canonical_argv,
        repository_root,
    ):
        raise ValueError("Validation CLI invocation differs from the frozen planned command")
    _validate_prospective_validation_root(verified)
    return PreparedValidationRun(canonical_argv, verified, freeze_hash)


def _component_entry(name: str, version: str, content: object) -> dict[str, str]:
    return {
        "name": name,
        "version": version,
        "content_sha256": sha256_bytes(canonical_json_bytes(content)),
    }


def _component_hash_entry(name: str, version: str, content_sha256: str) -> dict[str, str]:
    _validate_sha256(content_sha256, f"{name} component hash")
    return {
        "name": name,
        "version": version,
        "content_sha256": content_sha256,
    }


def _component_provenance(verified: VerifiedValidationFreeze) -> list[dict[str, str]]:
    plan = verified.validation_plan
    manifest = plan.manifest
    sampling = manifest.get("sampling_contract")
    selection = manifest.get("selection_metric_contract")
    preregistration = manifest.get("preregistration")
    if (
        not isinstance(sampling, dict)
        or set(sampling) != {"payload", "sha256"}
        or not isinstance(sampling["payload"], dict)
        or not isinstance(sampling["sha256"], str)
    ):
        raise ValueError("component provenance requires a closed-world sampling contract")
    validate_sampling_contract(sampling["payload"], expected_sha256=sampling["sha256"])
    for value, label in (
        (selection, "selection metric contract"),
        (preregistration, "preregistration"),
    ):
        if (
            not isinstance(value, dict)
            or set(value) != {"payload", "sha256"}
            or not isinstance(value["payload"], dict)
            or not isinstance(value["sha256"], str)
            or sha256_bytes(canonical_json_bytes(value["payload"])) != value["sha256"]
        ):
            raise ValueError(f"component provenance requires a verified {label}")

    ontology = get_ontology()
    configs = tuple(sorted(load_validation_catalog(), key=lambda item: item.opponent_id))
    if len(configs) != 9 or any(config.split != "validation" for config in configs):
        raise ValueError("component provenance requires nine approved Validation opponents")
    opponents = tuple(synthesize_opponent(config=config) for config in configs)
    game_hashes = {
        _game_sha256(opponent.game.root, game_name=opponent.game.name) for opponent in opponents
    }
    if len(game_hashes) != 1:
        raise ValueError("approved Validation opponents do not share one frozen game")
    equilibrium_entries = {
        (opponent.equilibrium_version, opponent.equilibrium_artifact_sha256)
        for opponent in opponents
    }
    if len(equilibrium_entries) != 1:
        raise ValueError("approved Validation opponents do not share one frozen equilibrium")
    equilibrium_version, equilibrium_sha256 = next(iter(equilibrium_entries))
    registries = tuple(build_production_observation_registry(item.game) for item in opponents)
    registry = registries[0]
    if any(candidate != registry for candidate in registries[1:]):
        raise ValueError("approved Validation opponents do not share one observation registry")
    if (
        sampling["payload"]["observation_registry_version"] != registry.registry_version
        or sampling["payload"]["observation_registry_sha256"] != registry.sha256
    ):
        raise ValueError("verified sampling contract uses a foreign observation registry")
    gto = [opponent for opponent in opponents if not opponent.config.leak_vector]
    if len(gto) != 1:
        raise ValueError("component provenance requires one Validation GTO control")
    baseline = extract_independent_action_rates(
        gto[0].game,
        gto[0].equilibrium_strategy,
        gto[0].config,
        reason_ids=("LEAK_R008",),
    )[0]
    baseline_payload = {
        "table_version": PRODUCTION_BASELINE_TABLE_VERSION,
        "reason_id": "LEAK_R008",
        "situation_key": "river_vs_check",
        "action_group": list(BET_ACTIONS),
        "baseline_rate": _decimal_wire(baseline.action_rate),
    }
    if len(plan.candidates) != 16:
        raise ValueError("component provenance requires the canonical 16 Validation candidates")
    estimator_index = [
        {
            "candidate_id": candidate.candidate_id,
            "method_version": PRODUCTION_ESTIMATOR_VERSION,
            "alpha0": "1",
            "beta0": "1",
            "tail": "upper",
            "tau": "0.25",
            "sample_floor": candidate.sample_floor,
            "detector_threshold": candidate.detector_confidence,
            "provider_threshold": candidate.provider_confidence,
        }
        for candidate in plan.candidates
    ]
    opponent_artifacts = [
        {
            "opponent_id": opponent.config.opponent_id,
            "opponent_version": opponent.config.opponent_version,
            "config": opponent.config.canonical_payload(),
            "config_sha256": opponent.config_sha256,
            "equilibrium_artifact_sha256": opponent.equilibrium_artifact_sha256,
            "strategy_sha256": _strategy_sha256(opponent.strategy),
        }
        for opponent in opponents
    ]
    versioned_components = (
        (
            "production_validation_cli",
            PRODUCTION_VALIDATION_CLI_VERSION,
            {
                "entrypoint": PRODUCTION_VALIDATION_ENTRYPOINT,
                "run_schema": PRODUCTION_VALIDATION_RUN_SCHEMA_VERSION,
            },
        ),
        (
            "canonicalizer",
            CANONICALIZER_VERSION,
            {"encoding": "canonical UTF-8 JSON with trailing LF"},
        ),
        ("dpl_schema", DPL_SCHEMA_VERSION, {"schema_version": DPL_SCHEMA_VERSION}),
        (
            "validation_runner",
            VALIDATION_RUNNER_VERSION,
            {"validation_batch_manifest_sha256": plan.manifest_sha256},
        ),
        (
            "validation_execution_adapter",
            VALIDATION_EXECUTION_ADAPTER_VERSION,
            {"validation_batch_manifest_sha256": plan.manifest_sha256},
        ),
        (
            PRODUCTION_VALIDATION_BACKEND_ID,
            PRODUCTION_VALIDATION_BACKEND_VERSION,
            {
                "backend_id": PRODUCTION_VALIDATION_BACKEND_ID,
                "backend_version": PRODUCTION_VALIDATION_BACKEND_VERSION,
            },
        ),
        (
            "validation_artifact_writer",
            VALIDATION_WRITER_VERSION,
            {"root_schema": VALIDATION_ROOT_MANIFEST_SCHEMA_VERSION},
        ),
        (
            "validation_freeze_boundary",
            VALIDATION_FREEZE_CLI_VERSION,
            {
                "entrypoint": VALIDATION_FREEZE_ENTRYPOINT,
                "freeze_schema": VALIDATION_FREEZE_MANIFEST_SCHEMA_VERSION,
            },
        ),
        ("execution_sampler", EXECUTION_SAMPLER_VERSION, sampling["payload"]),
        (
            "exploit_provider",
            EXPLOIT_PROVIDER_VERSION,
            {"reason_id": "LEAK_R008", "provider": "node_lock_best_response"},
        ),
        (
            "production_input_builder",
            PRODUCTION_INPUT_BUILDER_VERSION,
            {"split": "validation"},
        ),
        (
            "ground_truth_extractor",
            GROUND_TRUTH_EXTRACTOR_VERSION,
            {"split": "validation", "reason_ids": ["LEAK_R007", "LEAK_R008"]},
        ),
        (
            "exact_ev_evaluator",
            EXACT_EV_INPUT_VERSION,
            {
                "implementation": "phase6.exact_ev.evaluate_exact_ev",
                "hero_player": 0,
                "consistency_abs_tolerance": EV_CONSISTENCY_ABS_TOLERANCE_WIRE,
                "denominator_abs_tolerance": EV_DENOMINATOR_ABS_TOLERANCE_WIRE,
                "paths": ["production", "independent_leaves"],
            },
        ),
        (
            "calibration_evaluator",
            CALIBRATION_EVALUATOR_VERSION,
            {
                "exact_ev_input_version": EXACT_EV_INPUT_VERSION,
                "selection_metric_contract_sha256": selection["sha256"],
                "preregistration_sha256": preregistration["sha256"],
                "split": "validation",
            },
        ),
    )
    components = [
        _component_entry(name, version, content) for name, version, content in versioned_components
    ]
    components.extend(
        (
            _component_entry(
                "phase6_evaluation_contract",
                ROOT_MANIFEST_SCHEMA_VERSION,
                {
                    "selection_metric_contract": selection,
                    "preregistration": preregistration,
                },
            ),
            _component_entry(
                "reason_ontology",
                ontology.ontology_version,
                ontology.model_dump(mode="json"),
            ),
            _component_hash_entry(
                "frozen_validation_game",
                equilibrium_version,
                next(iter(game_hashes)),
            ),
            _component_hash_entry(
                "frozen_equilibrium_artifact",
                equilibrium_version,
                equilibrium_sha256,
            ),
            _component_entry(
                "approved_validation_opponent_artifacts",
                configs[0].generator_version,
                opponent_artifacts,
            ),
            _component_entry(
                "approved_validation_catalog",
                configs[0].generator_version,
                [config.canonical_payload() for config in configs],
            ),
            _component_entry(
                "approved_candidate_grid",
                plan.candidates[0].canonical_payload()["grid_version"],
                manifest["candidates"],
            ),
            _component_entry(
                "baseline_table",
                PRODUCTION_BASELINE_TABLE_VERSION,
                baseline_payload,
            ),
            _component_entry(
                "estimator_config_index",
                PRODUCTION_ESTIMATOR_VERSION,
                estimator_index,
            ),
            _component_hash_entry(
                "observation_registry",
                registry.registry_version,
                registry.sha256,
            ),
            _component_hash_entry(
                "verified_sampling_contract",
                sampling["payload"]["schema_version"],
                sampling["sha256"],
            ),
            _component_entry(
                "safety_mixer",
                PRODUCTION_SAFETY_MIXER_VERSION,
                {
                    "formula": "final=(1-alpha)*base+alpha*exploit",
                    "action_union": "stable",
                    "candidate_alpha": [
                        {
                            "candidate_id": candidate.candidate_id,
                            "safety_alpha": candidate.safety_alpha,
                        }
                        for candidate in plan.candidates
                    ],
                },
            ),
            _component_entry(
                "validation_session_product",
                VALIDATION_RUNNER_VERSION,
                {
                    "horizons": list(HORIZONS),
                    "repetitions": [
                        {"master_seed": seed, "repetition_id": repetition_id}
                        for repetition_id, seed in REPETITION_SEEDS
                    ],
                    "root_payload_fields": sampling["payload"]["root_payload_fields"],
                },
            ),
        )
    )
    if len({component["name"] for component in components}) != len(components):
        raise ValueError("component provenance names must be unique")
    return components


def _absolute_reference(path: Path, name: str) -> dict[str, object]:
    raw = path.read_bytes()
    return {
        "name": name,
        "path": str(path.resolve()),
        "sha256": sha256_bytes(raw),
        "size_bytes": len(raw),
    }


def _relative_reference(root: Path, path: Path, name: str) -> dict[str, object]:
    raw = path.read_bytes()
    return {
        "name": name,
        "path": path.resolve().relative_to(root.resolve()).as_posix(),
        "sha256": sha256_bytes(raw),
        "size_bytes": len(raw),
    }


def _iso_utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("Validation run timestamps must be timezone-aware UTC")
    return value.isoformat().replace("+00:00", "Z")


def _parse_utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp") from exc
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError(f"{label} must be UTC")
    return parsed


def _run_manifest_payload(
    prepared: PreparedValidationRun,
    *,
    marker_path: Path,
    result_root_path: Path,
    result_root_sha256: str,
    started_at: datetime,
    finished_at: datetime,
) -> dict[str, object]:
    verified = prepared.verified_freeze
    spec = verified.spec
    input_root = spec.validation_input_dir
    output_root = spec.validation_output_dir
    return {
        "schema_version": PRODUCTION_VALIDATION_RUN_SCHEMA_VERSION,
        "artifact_type": "phase6_validation_run_manifest",
        "cli_version": PRODUCTION_VALIDATION_CLI_VERSION,
        "status": "completed_and_verified",
        "split": "validation",
        "git": verified.manifest_payload["git"],
        "invocation": {
            "entrypoint": PRODUCTION_VALIDATION_ENTRYPOINT,
            "argv": list(prepared.raw_argv),
            "planned_command": list(spec.planned_validation_command),
        },
        "runtime": verified.manifest_payload["runtime"],
        "timing": {
            "started_at_utc": _iso_utc(started_at),
            "finished_at_utc": _iso_utc(finished_at),
        },
        "inputs": {
            "validation_freeze_manifest": _absolute_reference(
                verified.manifest_path,
                "validation_freeze_manifest",
            ),
            "qv5_manifest": _absolute_reference(
                input_root / VALIDATION_QV5_MANIFEST_NAME,
                "qv5_manifest",
            ),
            "validation_batch_manifest": _absolute_reference(
                input_root / VALIDATION_BATCH_MANIFEST_NAME,
                "validation_batch_manifest",
            ),
            "training_source": verified.manifest_payload["training_source"],
            "dependency_lock": spec.payload["dependency_lock"],
        },
        "attempt": {
            "attempt_id": spec.attempt_id,
            "attempt_number": 1,
            "policy": dict(_ATTEMPT_POLICY),
            "marker": _relative_reference(
                output_root,
                marker_path,
                "validation_attempt_in_progress",
            ),
        },
        "components": _component_provenance(verified),
        "outputs": {
            "validation_result_root": {
                **_relative_reference(
                    output_root,
                    result_root_path,
                    "validation_result_root",
                ),
                "sha256": result_root_sha256,
            }
        },
    }


def _write_exclusive(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)


def _load_canonical_object(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ValueError(f"{label} bytes are not canonical")
    return payload, raw


def _validate_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _SHA256_CHARS for character in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _verify_reference(path: Path, reference: object, name: str) -> None:
    if not isinstance(reference, dict) or set(reference) != {
        "name",
        "path",
        "sha256",
        "size_bytes",
    }:
        raise ValueError(f"{name} reference is not closed-world")
    _validate_sha256(reference["sha256"], f"{name} hash")
    raw = path.read_bytes()
    if (
        reference["name"] != name
        or reference["path"] != str(path.resolve())
        or reference["size_bytes"] != len(raw)
        or reference["sha256"] != sha256_bytes(raw)
    ):
        raise ValueError(f"{name} reference does not match its bytes")


def _verify_frozen_inputs_after_reservation(
    manifest_path: Path,
    *,
    expected_sha256: str,
    repo_root: Path,
) -> VerifiedValidationFreeze:
    """Verify P6-8B frozen bytes after the approved output path now exists."""
    _validate_sha256(expected_sha256, "Validation freeze manifest hash")
    payload, raw = _load_canonical_object(manifest_path, "Validation freeze manifest")
    if sha256_bytes(raw) != expected_sha256:
        raise ValueError("Validation freeze manifest hash mismatch")
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
    if set(payload) != expected_fields or (
        payload["schema_version"] != VALIDATION_FREEZE_MANIFEST_SCHEMA_VERSION
        or payload["artifact_type"] != "validation_freeze_manifest"
        or payload["cli_version"] != VALIDATION_FREEZE_CLI_VERSION
        or payload["status"] != "frozen_and_verified"
        or payload["split"] != "validation"
    ):
        raise ValueError("Validation freeze manifest identity is invalid")
    _parse_utc(payload["frozen_at_utc"], "frozen_at_utc")
    input_root = manifest_path.parent.resolve()
    qv5_reference = payload["qv5_manifest"]
    batch_reference = payload["validation_batch_manifest"]
    if (
        not isinstance(qv5_reference, dict)
        or set(qv5_reference) != {"name", "path", "sha256"}
        or qv5_reference["name"] != "validation_freeze_qv5"
        or qv5_reference["path"] != VALIDATION_QV5_MANIFEST_NAME
    ):
        raise ValueError("frozen QV5 reference is invalid")
    qv5_hash = _validate_sha256(qv5_reference["sha256"], "frozen QV5 hash")
    qv5_path = input_root / VALIDATION_QV5_MANIFEST_NAME
    if sha256_bytes(qv5_path.read_bytes()) != qv5_hash:
        raise ValueError("frozen QV5 hash mismatch")
    spec = load_validation_freeze_spec(qv5_path, expected_sha256=qv5_hash)
    if input_root != spec.validation_input_dir:
        raise ValueError("frozen input root differs from QV5")

    state = _read_repository_state(repo_root)
    if (
        state.branch != "main"
        or state.head_commit != spec.expected_commit
        or state.local_main_commit != spec.expected_commit
        or state.cached_origin_main_commit != spec.cached_origin_main_commit
        or state.dirty
        or payload["git"] != state.canonical_payload()
    ):
        raise RuntimeError("repository state differs from the frozen clean trust anchor")
    _verify_runtime_and_dependency_lock(spec, repo_root)
    training_path = spec.training_run_manifest
    if sha256_bytes(training_path.read_bytes()) != spec.training_run_manifest_sha256:
        raise ValueError("frozen Training source hash mismatch")
    plan = build_validation_batch_plan(
        training_path,
        expected_training_run_manifest_sha256=spec.training_run_manifest_sha256,
        repo_root=repo_root,
    )
    verify_validation_batch_plan(plan, repo_root=repo_root)
    if plan.manifest_sha256 != spec.expected_validation_batch_sha256:
        raise ValueError("frozen Validation batch hash differs from QV5")
    if not isinstance(batch_reference, dict) or batch_reference != {
        "name": "validation_batch_manifest",
        "path": VALIDATION_BATCH_MANIFEST_NAME,
        "sha256": plan.manifest_sha256,
    }:
        raise ValueError("frozen Validation batch reference is invalid")
    batch_path = input_root / VALIDATION_BATCH_MANIFEST_NAME
    if batch_path.read_bytes() != plan.manifest_bytes:
        raise ValueError("frozen Validation batch bytes do not reconstruct")

    invocation = payload["invocation"]
    if (
        not isinstance(invocation, dict)
        or set(invocation) != {"entrypoint", "argv"}
        or invocation["entrypoint"] != VALIDATION_FREEZE_ENTRYPOINT
        or not isinstance(invocation["argv"], list)
        or any(not isinstance(item, str) for item in invocation["argv"])
    ):
        raise ValueError("Validation freeze invocation provenance is invalid")
    try:
        _parse_freeze_args(invocation["argv"])
    except SystemExit as exc:
        raise ValueError("Validation freeze argv is not approved") from exc
    free_space = payload["free_space_preflight"]
    if not isinstance(free_space, dict) or set(free_space) != {
        "minimum_required_bytes",
        "validation_input_parent_free_bytes",
        "validation_output_parent_free_bytes",
    }:
        raise ValueError("Validation freeze free-space provenance is invalid")
    if free_space["minimum_required_bytes"] != spec.minimum_free_space_bytes or any(
        isinstance(free_space[name], bool)
        or not isinstance(free_space[name], int)
        or free_space[name] < spec.minimum_free_space_bytes
        for name in (
            "validation_input_parent_free_bytes",
            "validation_output_parent_free_bytes",
        )
    ):
        raise ValueError("Validation freeze recorded free space is invalid")
    if (
        payload["training_source"] != plan.manifest["training_source"]
        or payload["runtime"] != spec.payload["runtime"]
        or payload["dependency_lock"] != spec.payload["dependency_lock"]
        or payload["paths"] != spec.payload["paths"]
        or payload["attempt"]
        != {
            "attempt_id": spec.attempt_id,
            "policy": dict(_ATTEMPT_POLICY),
            "planned_validation_command": list(spec.planned_validation_command),
        }
    ):
        raise ValueError("Validation freeze provenance does not reconstruct after reservation")
    return VerifiedValidationFreeze(manifest_path, payload, expected_sha256, spec, plan)


def verify_validation_run_manifest(
    manifest_path: Path | str,
    *,
    repo_root: Path | str = REPO_ROOT,
) -> dict[str, Any]:
    """Independently rehash the completed Validation run and all frozen inputs."""
    path = Path(manifest_path).resolve()
    payload, _raw = _load_canonical_object(path, "Validation run manifest")
    expected_fields = {
        "schema_version",
        "artifact_type",
        "cli_version",
        "status",
        "split",
        "git",
        "invocation",
        "runtime",
        "timing",
        "inputs",
        "attempt",
        "components",
        "outputs",
    }
    if set(payload) != expected_fields or (
        payload["schema_version"] != PRODUCTION_VALIDATION_RUN_SCHEMA_VERSION
        or payload["artifact_type"] != "phase6_validation_run_manifest"
        or payload["cli_version"] != PRODUCTION_VALIDATION_CLI_VERSION
        or payload["status"] != "completed_and_verified"
        or payload["split"] != "validation"
    ):
        raise ValueError("Validation run manifest identity is invalid")
    invocation = payload["invocation"]
    if (
        not isinstance(invocation, dict)
        or set(invocation) != {"entrypoint", "argv", "planned_command"}
        or invocation["entrypoint"] != PRODUCTION_VALIDATION_ENTRYPOINT
        or not isinstance(invocation["argv"], list)
        or any(not isinstance(item, str) for item in invocation["argv"])
    ):
        raise ValueError("Validation run invocation is invalid")
    prepared = prepare_validation_run(
        list(invocation["argv"]),
        repo_root=repo_root,
        allow_existing_output=True,
    )
    verified = prepared.verified_freeze
    spec = verified.spec
    if path != spec.validation_output_dir / PRODUCTION_VALIDATION_RUN_MANIFEST:
        raise ValueError("Validation run manifest is outside the approved output root")
    timing = payload["timing"]
    if not isinstance(timing, dict) or set(timing) != {
        "started_at_utc",
        "finished_at_utc",
    }:
        raise ValueError("Validation run timing provenance is invalid")
    started = _parse_utc(timing["started_at_utc"], "started_at_utc")
    finished = _parse_utc(timing["finished_at_utc"], "finished_at_utc")
    if finished < started:
        raise ValueError("Validation run finished before it started")

    inputs = payload["inputs"]
    if not isinstance(inputs, dict) or set(inputs) != {
        "validation_freeze_manifest",
        "qv5_manifest",
        "validation_batch_manifest",
        "training_source",
        "dependency_lock",
    }:
        raise ValueError("Validation run inputs are not closed-world")
    _verify_reference(
        verified.manifest_path,
        inputs["validation_freeze_manifest"],
        "validation_freeze_manifest",
    )
    _verify_reference(
        spec.validation_input_dir / VALIDATION_QV5_MANIFEST_NAME,
        inputs["qv5_manifest"],
        "qv5_manifest",
    )
    _verify_reference(
        spec.validation_input_dir / VALIDATION_BATCH_MANIFEST_NAME,
        inputs["validation_batch_manifest"],
        "validation_batch_manifest",
    )
    if (
        inputs["training_source"] != verified.manifest_payload["training_source"]
        or inputs["dependency_lock"] != spec.payload["dependency_lock"]
    ):
        raise ValueError("Validation run input provenance differs from the freeze")

    attempt = payload["attempt"]
    if not isinstance(attempt, dict) or set(attempt) != {
        "attempt_id",
        "attempt_number",
        "policy",
        "marker",
    }:
        raise ValueError("Validation run attempt provenance is not closed-world")
    marker_path = spec.validation_output_dir / VALIDATION_ATTEMPT_MARKER_NAME
    marker = attempt["marker"]
    if not isinstance(marker, dict) or set(marker) != {"name", "path", "sha256", "size_bytes"}:
        raise ValueError("Validation attempt marker reference is invalid")
    _validate_sha256(marker["sha256"], "Validation attempt marker hash")
    marker_raw = marker_path.read_bytes()
    if (
        marker["name"] != "validation_attempt_in_progress"
        or marker["path"] != VALIDATION_ATTEMPT_MARKER_NAME
        or marker["sha256"] != sha256_bytes(marker_raw)
        or marker["size_bytes"] != len(marker_raw)
    ):
        raise ValueError("Validation attempt marker reference does not reconstruct")
    verify_validation_attempt_marker(marker_path, verified_freeze=verified)

    outputs = payload["outputs"]
    if not isinstance(outputs, dict) or set(outputs) != {"validation_result_root"}:
        raise ValueError("Validation run outputs are not closed-world")
    result_reference = outputs["validation_result_root"]
    if not isinstance(result_reference, dict) or set(result_reference) != {
        "name",
        "path",
        "sha256",
        "size_bytes",
    }:
        raise ValueError("Validation result root reference is invalid")
    if (
        result_reference["name"] != "validation_result_root"
        or result_reference["path"] != "validation-artifacts/validation/validation_result_root.json"
    ):
        raise ValueError("Validation result root path is not canonical")
    _validate_sha256(result_reference["sha256"], "Validation result root hash")
    result_path = (spec.validation_output_dir / result_reference["path"]).resolve()
    try:
        result_path.relative_to(spec.validation_output_dir.resolve())
    except ValueError as exc:
        raise ValueError("Validation result root escapes the approved output root") from exc
    result_raw = result_path.read_bytes()
    if result_reference["sha256"] != sha256_bytes(result_raw) or result_reference[
        "size_bytes"
    ] != len(result_raw):
        raise ValueError("Validation result root reference does not reconstruct")
    result_manifest = verify_validation_artifact_root(
        result_path,
        expected_sha256=result_reference["sha256"],
        repo_root=repo_root,
    )
    if result_manifest["backend"] != {
        "backend_id": PRODUCTION_VALIDATION_BACKEND_ID,
        "backend_version": PRODUCTION_VALIDATION_BACKEND_VERSION,
    }:
        raise ValueError("Validation result root is not bound to the production backend")

    expected = _run_manifest_payload(
        prepared,
        marker_path=marker_path,
        result_root_path=result_path,
        result_root_sha256=result_reference["sha256"],
        started_at=started,
        finished_at=finished,
    )
    if payload != expected:
        raise ValueError("Validation run manifest provenance does not reconstruct")
    return payload


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    repo_root = REPO_ROOT.resolve()
    prepared = prepare_validation_run(raw_argv, repo_root=repo_root)
    verified = prepared.verified_freeze
    backend = ProductionValidationExecutionBackend(
        verified.validation_plan,
        repo_root=repo_root,
    )
    repeated = prepare_validation_run(raw_argv, repo_root=repo_root)
    if repeated != prepared:
        raise RuntimeError("Validation freeze or repository state changed during preflight")

    started_at = datetime.now(UTC)
    marker_path = reserve_validation_attempt(
        verified,
        started_at_utc=_iso_utc(started_at),
    )
    with _PinnedDirectory(verified.spec.validation_output_dir) as output_pin:
        output_pin.pin_regular_file(VALIDATION_ATTEMPT_MARKER_NAME)
        _verify_pinned_marker(output_pin, marker_path)
        verify_validation_attempt_marker(marker_path, verified_freeze=verified)
        artifact_parent = output_pin.mkdir(VALIDATION_ARTIFACT_BASE_DIRECTORY)
        with _PinnedDirectory(artifact_parent) as artifact_pin:
            output_pin.verify()
            artifact_pin.verify()
            records = run_validation_execution_adapter(
                verified.validation_plan,
                backend,
                repo_root=repo_root,
            )
            output_pin.verify()
            artifact_pin.verify()
            prepared_bundle = _prepare_validation_artifact_bundle(
                verified.validation_plan,
                records,
                repo_root=repo_root,
            )
            output_pin.verify()
            artifact_pin.verify()
            with artifact_pin.mkdir_pinned(VALIDATION_PHYSICAL_DIRECTORY) as validation_pin:
                output_pin.verify()
                artifact_pin.verify()
                _verify_validation_write_boundary(validation_pin, 0)
                bundle = _write_prepared_validation_artifact_bundle(
                    validation_pin,
                    prepared_bundle,
                    repo_root=repo_root,
                )
                output_pin.verify()
                artifact_pin.verify()
                validation_pin.verify()
                verify_validation_artifact_root(
                    validation_pin.stable_path() / bundle.root_manifest_path.name,
                    expected_sha256=bundle.root_manifest_sha256,
                    repo_root=repo_root,
                )
                output_pin.verify()
                artifact_pin.verify()
                validation_pin.verify()
                finished_at = datetime.now(UTC)
                payload = _run_manifest_payload(
                    prepared,
                    marker_path=marker_path,
                    result_root_path=bundle.root_manifest_path,
                    result_root_sha256=bundle.root_manifest_sha256,
                    started_at=started_at,
                    finished_at=finished_at,
                )
                output_pin.verify()
                artifact_pin.verify()
                validation_pin.verify()
                run_path = output_pin.write_exclusive(
                    PRODUCTION_VALIDATION_RUN_MANIFEST,
                    canonical_json_bytes(payload),
                )
    verify_validation_run_manifest(run_path, repo_root=repo_root)
    print(f"verified 12,960-session Validation bundle: {verified.spec.validation_output_dir}")
    print(f"run_manifest_sha256={sha256_bytes(run_path.read_bytes())}")
    return 0


__all__ = [
    "PRODUCTION_VALIDATION_CLI_VERSION",
    "PRODUCTION_VALIDATION_ENTRYPOINT",
    "PRODUCTION_VALIDATION_RUN_MANIFEST",
    "PRODUCTION_VALIDATION_RUN_SCHEMA_VERSION",
    "PreparedValidationRun",
    "main",
    "prepare_validation_run",
    "verify_validation_run_manifest",
]
