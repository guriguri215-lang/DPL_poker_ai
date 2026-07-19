"""Freeze the target commit and inputs for the single P6-10A attempt."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .contracts import canonical_json_bytes, sha256_bytes
from .p6_10 import (
    P6_10A_ATTEMPT_ID,
    P6_10A_BATCH_MANIFEST,
    P6_10A_ENTRYPOINT,
    build_p6_10a_batch,
    load_p6_9_snapshot,
)
from .validation_freeze import (
    _current_environment_paths,
    _current_executable_paths,
    _installed_distributions,
    _installed_project_version,
    _is_git_ignored,
    _read_repository_state,
    _runtime_payload,
)

P6_10A_FREEZE_CLI_VERSION = "phase6-p6-10a-freeze-cli-v1"
P6_10A_FREEZE_ENTRYPOINT = "cli/phase6_p6_10_freeze_v1.py"
P6_10A_FREEZE_SCHEMA_VERSION = "phase6-p6-10a-freeze-manifest-v1"
P6_10A_FREEZE_SIDECAR_SCHEMA_VERSION = "phase6-p6-10a-freeze-hash-sidecar-v1"
P6_10A_FREEZE_MANIFEST = "phase6_p6_10a_freeze_manifest.json"
P6_10A_FREEZE_HASH_SIDECAR = "phase6_p6_10a_freeze_manifest.sha256.json"
P6_10A_DEPENDENCY_LOCK = "dependency-lock.json"
P6_10A_INPUT_ROOT_NAME = "p6_10a_comparator_ablation_inputs_20260719"
P6_10A_OUTPUT_ROOT_NAME = "p6_10a_comparator_ablation_run_20260719"

_PROJECT_NAME = "poker-xai"
_ATTEMPT_POLICY = {
    "planned_attempt_count": 1,
    "retry_count": 0,
    "fresh_output_required": True,
    "separate_from_p6_9_namespace": True,
    "partial_retention": "preserve_without_cleanup",
    "second_attempt_allowed": False,
}
_SHA256_CHARS = frozenset("0123456789abcdef")


def create_p6_10a_freeze(
    *,
    expected_commit: str,
    p6_9_run_manifest: Path | str,
    input_root: Path | str,
    output_root: Path | str,
    repo_root: Path | str,
    invocation_argv: Sequence[str],
) -> tuple[Path, Path]:
    """Create exactly one fresh dependency lock and P6-10A freeze bundle."""
    repository_root = Path(repo_root).resolve()
    _validate_commit(expected_commit, "expected commit")
    state = _read_repository_state(repository_root)
    if (
        state.branch != "main"
        or state.head_commit != expected_commit
        or state.local_main_commit != expected_commit
        or state.cached_origin_main_commit != expected_commit
        or state.dirty
    ):
        raise RuntimeError("repository state differs from the clean target commit")
    input_path = Path(input_root).resolve()
    output_path = Path(output_root).resolve()
    _validate_canonical_roots(input_path, output_path, repository_root)
    _validate_fresh_sibling(input_path, repository_root, "P6-10A input root")
    _validate_fresh_sibling(output_path, repository_root, "P6-10A output root")
    if input_path == output_path:
        raise ValueError("P6-10A input and output roots must be different")
    snapshot = load_p6_9_snapshot(p6_9_run_manifest, repo_root=repository_root)
    batch = build_p6_10a_batch(snapshot)
    input_path.mkdir(parents=False, exist_ok=False)
    dependency_path = input_path / P6_10A_DEPENDENCY_LOCK
    dependency_raw = canonical_json_bytes(
        _dependency_lock_payload(repository_root, expected_commit=expected_commit)
    )
    _write_exclusive(dependency_path, dependency_raw)
    batch_path = input_path / P6_10A_BATCH_MANIFEST
    _write_exclusive(batch_path, batch.manifest_bytes)
    manifest_path = input_path / P6_10A_FREEZE_MANIFEST
    sidecar_path = input_path / P6_10A_FREEZE_HASH_SIDECAR
    python_executable, base_executable = _current_executable_paths()
    runtime = {
        "python_executable": _absolute_reference(python_executable),
        "base_executable": _absolute_reference(base_executable),
        "runtime_fingerprint": _runtime_payload(),
    }
    command = [
        str(python_executable),
        "-B",
        "-X",
        "utf8",
        str((repository_root / P6_10A_ENTRYPOINT).resolve()),
        "--freeze-manifest",
        str(manifest_path),
        "--freeze-hash-sidecar",
        str(sidecar_path),
    ]
    manifest = {
        "schema_version": P6_10A_FREEZE_SCHEMA_VERSION,
        "artifact_type": "p6_10a_freeze_manifest",
        "cli_version": P6_10A_FREEZE_CLI_VERSION,
        "status": "frozen_and_verified",
        "scope": "p6_10a_comparator_ablation",
        "frozen_at_utc": _utc_now(),
        "git": {
            **state.canonical_payload(),
            "expected_target_commit": expected_commit,
        },
        "runtime": runtime,
        "dependency_lock": _absolute_reference(dependency_path),
        "source_snapshot": batch.manifest["source_snapshot"],
        "selected_primary": batch.manifest["selected_primary"],
        "epsilon_zero_candidate": batch.manifest["epsilon_zero_candidate"],
        "p6_10a_batch_manifest": _absolute_reference(batch_path),
        "expected_cardinality": batch.manifest["expected_cardinality"],
        "paths": {
            "input_root": str(input_path),
            "output_root": str(output_path),
        },
        "attempt": {
            "attempt_id": P6_10A_ATTEMPT_ID,
            "policy": dict(_ATTEMPT_POLICY),
            "planned_command": command,
        },
        "invocation": {
            "entrypoint": P6_10A_FREEZE_ENTRYPOINT,
            "argv": list(invocation_argv),
        },
        "p6_10_complete": False,
        "gate_b_ready": False,
    }
    manifest_raw = canonical_json_bytes(manifest)
    _write_exclusive(manifest_path, manifest_raw)
    sidecar = {
        "schema_version": P6_10A_FREEZE_SIDECAR_SCHEMA_VERSION,
        "artifact_type": "p6_10a_freeze_hash_sidecar",
        "freeze_manifest_path": str(manifest_path),
        "freeze_manifest_sha256": sha256_bytes(manifest_raw),
        "freeze_manifest_size_bytes": len(manifest_raw),
    }
    _write_exclusive(sidecar_path, canonical_json_bytes(sidecar))
    verify_p6_10a_freeze_manifest(
        manifest_path,
        sidecar_path,
        repo_root=repository_root,
    )
    return manifest_path, sidecar_path


def verify_p6_10a_freeze_manifest(
    manifest_path: Path | str,
    sidecar_path: Path | str,
    *,
    repo_root: Path | str,
    allow_existing_output: bool = False,
) -> dict[str, Any]:
    """Verify the target commit, environment, source, batch, and command."""
    repository_root = Path(repo_root).resolve()
    path = Path(manifest_path).resolve()
    side_path = Path(sidecar_path).resolve()
    if path.name != P6_10A_FREEZE_MANIFEST or side_path.name != P6_10A_FREEZE_HASH_SIDECAR:
        raise ValueError("P6-10A freeze filenames are noncanonical")
    if path.parent != side_path.parent:
        raise ValueError("P6-10A freeze manifest and sidecar must share one root")
    sidecar = _strict_object(side_path.read_bytes(), "P6-10A freeze hash sidecar")
    if set(sidecar) != {
        "schema_version",
        "artifact_type",
        "freeze_manifest_path",
        "freeze_manifest_sha256",
        "freeze_manifest_size_bytes",
    } or (
        sidecar["schema_version"] != P6_10A_FREEZE_SIDECAR_SCHEMA_VERSION
        or sidecar["artifact_type"] != "p6_10a_freeze_hash_sidecar"
        or sidecar["freeze_manifest_path"] != str(path)
    ):
        raise ValueError("P6-10A freeze sidecar identity is invalid")
    _validate_sha256(sidecar["freeze_manifest_sha256"], "freeze manifest hash")
    raw = path.read_bytes()
    if (
        len(raw) != sidecar["freeze_manifest_size_bytes"]
        or sha256_bytes(raw) != sidecar["freeze_manifest_sha256"]
    ):
        raise ValueError("P6-10A freeze manifest differs from its sidecar")
    payload = _strict_object(raw, "P6-10A freeze manifest")
    fields = {
        "schema_version",
        "artifact_type",
        "cli_version",
        "status",
        "scope",
        "frozen_at_utc",
        "git",
        "runtime",
        "dependency_lock",
        "source_snapshot",
        "selected_primary",
        "epsilon_zero_candidate",
        "p6_10a_batch_manifest",
        "expected_cardinality",
        "paths",
        "attempt",
        "invocation",
        "p6_10_complete",
        "gate_b_ready",
    }
    if set(payload) != fields or (
        payload["schema_version"] != P6_10A_FREEZE_SCHEMA_VERSION
        or payload["artifact_type"] != "p6_10a_freeze_manifest"
        or payload["cli_version"] != P6_10A_FREEZE_CLI_VERSION
        or payload["status"] != "frozen_and_verified"
        or payload["scope"] != "p6_10a_comparator_ablation"
        or payload["p6_10_complete"] is not False
        or payload["gate_b_ready"] is not False
    ):
        raise ValueError("P6-10A freeze manifest identity is invalid")
    try:
        datetime.fromisoformat(payload["frozen_at_utc"].replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError("P6-10A freeze timestamp is invalid") from exc
    git = payload["git"]
    if not isinstance(git, dict) or set(git) != {
        "branch",
        "head_commit",
        "local_main_commit",
        "cached_origin_main_commit",
        "dirty",
        "live_remote_queried",
        "expected_target_commit",
    }:
        raise ValueError("P6-10A freeze Git state is not closed-world")
    expected_commit = git["expected_target_commit"]
    _validate_commit(expected_commit, "P6-10A target commit")
    state = _read_repository_state(repository_root)
    if git != {**state.canonical_payload(), "expected_target_commit": expected_commit} or (
        state.branch != "main"
        or state.head_commit != expected_commit
        or state.local_main_commit != expected_commit
        or state.cached_origin_main_commit != expected_commit
        or state.dirty
    ):
        raise RuntimeError("repository state differs from the frozen P6-10A target")
    paths = payload["paths"]
    if not isinstance(paths, dict) or set(paths) != {"input_root", "output_root"}:
        raise ValueError("P6-10A freeze paths are not closed-world")
    input_root = Path(paths["input_root"]).resolve()
    output_root = Path(paths["output_root"]).resolve()
    _validate_canonical_roots(input_root, output_root, repository_root)
    if input_root != path.parent or not input_root.is_dir():
        raise ValueError("P6-10A freeze input root does not contain the manifest")
    _validate_existing_sibling(input_root, repository_root, "P6-10A input root")
    if allow_existing_output:
        _validate_existing_sibling(output_root, repository_root, "P6-10A output root")
    else:
        _validate_fresh_sibling(output_root, repository_root, "P6-10A output root")
    expected_names = {
        P6_10A_DEPENDENCY_LOCK,
        P6_10A_BATCH_MANIFEST,
        P6_10A_FREEZE_MANIFEST,
        P6_10A_FREEZE_HASH_SIDECAR,
    }
    if {item.name for item in input_root.iterdir()} != expected_names or any(
        not item.is_file() for item in input_root.iterdir()
    ):
        raise ValueError("P6-10A freeze input file set is not closed-world")
    dependency_path = input_root / P6_10A_DEPENDENCY_LOCK
    batch_path = input_root / P6_10A_BATCH_MANIFEST
    _verify_absolute_reference(payload["dependency_lock"], dependency_path, "dependency lock")
    _verify_absolute_reference(
        payload["p6_10a_batch_manifest"], batch_path, "P6-10A batch manifest"
    )
    expected_lock = _dependency_lock_payload(repository_root, expected_commit=expected_commit)
    if _strict_object(dependency_path.read_bytes(), "P6-10A dependency lock") != expected_lock:
        raise ValueError("installed environment differs from the P6-10A dependency lock")
    python_executable, base_executable = _current_executable_paths()
    expected_runtime = {
        "python_executable": _absolute_reference(python_executable),
        "base_executable": _absolute_reference(base_executable),
        "runtime_fingerprint": _runtime_payload(),
    }
    if payload["runtime"] != expected_runtime:
        raise ValueError("current runtime differs from the P6-10A freeze")
    source = payload["source_snapshot"]
    if not isinstance(source, dict):
        raise ValueError("P6-10A source snapshot is invalid")
    run_path = _repo_relative(repository_root, source["p6_9_run_manifest"]["path"])
    snapshot = load_p6_9_snapshot(run_path, repo_root=repository_root)
    rebuilt = build_p6_10a_batch(snapshot)
    if (
        batch_path.read_bytes() != rebuilt.manifest_bytes
        or payload["p6_10a_batch_manifest"]["sha256"] != rebuilt.manifest_sha256
        or payload["source_snapshot"] != rebuilt.manifest["source_snapshot"]
        or payload["selected_primary"] != rebuilt.manifest["selected_primary"]
        or payload["epsilon_zero_candidate"] != rebuilt.manifest["epsilon_zero_candidate"]
        or payload["expected_cardinality"] != rebuilt.manifest["expected_cardinality"]
    ):
        raise ValueError("P6-10A frozen batch/source/config does not reconstruct")
    attempt = payload["attempt"]
    if (
        not isinstance(attempt, dict)
        or set(attempt)
        != {
            "attempt_id",
            "policy",
            "planned_command",
        }
        or (attempt["attempt_id"] != P6_10A_ATTEMPT_ID or attempt["policy"] != _ATTEMPT_POLICY)
    ):
        raise ValueError("P6-10A frozen attempt policy is invalid")
    expected_command = [
        str(python_executable),
        "-B",
        "-X",
        "utf8",
        str((repository_root / P6_10A_ENTRYPOINT).resolve()),
        "--freeze-manifest",
        str(path),
        "--freeze-hash-sidecar",
        str(side_path),
    ]
    if attempt["planned_command"] != expected_command:
        raise ValueError("P6-10A planned command does not reconstruct")
    invocation = payload["invocation"]
    if (
        not isinstance(invocation, dict)
        or set(invocation) != {"entrypoint", "argv"}
        or (
            invocation["entrypoint"] != P6_10A_FREEZE_ENTRYPOINT
            or not isinstance(invocation["argv"], list)
            or any(not isinstance(item, str) for item in invocation["argv"])
        )
    ):
        raise ValueError("P6-10A freeze invocation provenance is invalid")
    return {**payload, "manifest_sha256": sidecar["freeze_manifest_sha256"]}


def _dependency_lock_payload(repo_root: Path, *, expected_commit: str) -> dict[str, object]:
    python_executable, base_executable = _current_executable_paths()
    pyvenv_cfg, site_packages = _current_environment_paths()
    runtime = _runtime_payload()
    return {
        "schema_version": "phase6-production-dependency-lock-v1",
        "lock_scope": "complete-installed-environment-snapshot",
        "distributions": [
            {"name": name, "version": version}
            for name, version in _installed_distributions(_PROJECT_NAME)
        ],
        "project": {
            "git_commit": expected_commit,
            "name": _PROJECT_NAME,
            "repository_path": ".",
            "source": "repository",
            "version": _installed_project_version(_PROJECT_NAME),
        },
        "python": {
            "base_executable_path": str(base_executable),
            "base_executable_sha256": sha256_bytes(base_executable.read_bytes()),
            "compiler": runtime["python_compiler"],
            "implementation": runtime["python_implementation"],
            "platform": runtime["platform"],
            "pyvenv_cfg_path": pyvenv_cfg.relative_to(repo_root).as_posix(),
            "pyvenv_cfg_sha256": sha256_bytes(pyvenv_cfg.read_bytes()),
            "site_packages_path": site_packages.relative_to(repo_root).as_posix(),
            "venv_executable_path": python_executable.relative_to(repo_root).as_posix(),
            "venv_executable_sha256": sha256_bytes(python_executable.read_bytes()),
            "version": runtime["python_version"],
        },
    }


def _validate_fresh_sibling(path: Path, repo_root: Path, label: str) -> None:
    _validate_sibling(path, repo_root, label)
    if os.path.lexists(path):
        raise FileExistsError(f"{label} must be fresh")


def _validate_canonical_roots(input_root: Path, output_root: Path, repo_root: Path) -> None:
    parent = (repo_root / "experiments_output").resolve()
    if input_root != parent / P6_10A_INPUT_ROOT_NAME:
        raise ValueError("P6-10A input root is not the single canonical attempt namespace")
    if output_root != parent / P6_10A_OUTPUT_ROOT_NAME:
        raise ValueError("P6-10A output root is not the single canonical attempt namespace")


def _validate_existing_sibling(path: Path, repo_root: Path, label: str) -> None:
    _validate_sibling(path, repo_root, label)
    if not path.is_dir():
        raise ValueError(f"{label} must be an existing directory")


def _validate_sibling(path: Path, repo_root: Path, label: str) -> None:
    parent = (repo_root / "experiments_output").resolve()
    if path.parent != parent or path == parent or not parent.is_dir():
        raise ValueError(f"{label} must be a direct experiments_output child")
    if not path.name.startswith("p6_10a_") or not path.name.isascii():
        raise ValueError(f"{label} must use the P6-10A ASCII namespace")
    if not _is_git_ignored(repo_root, path):
        raise ValueError(f"{label} must be ignored by Git")


def _absolute_reference(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    return {"path": str(path.resolve()), "sha256": sha256_bytes(raw), "size_bytes": len(raw)}


def _verify_absolute_reference(reference: object, path: Path, label: str) -> None:
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256", "size_bytes"}:
        raise ValueError(f"{label} reference is not closed-world")
    raw = path.read_bytes()
    if (
        reference["path"] != str(path.resolve())
        or reference["size_bytes"] != len(raw)
        or reference["sha256"] != sha256_bytes(raw)
    ):
        raise ValueError(f"{label} reference differs from its bytes")


def _repo_relative(root: Path, value: object) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("repository-relative path must be POSIX")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("repository-relative path escapes the repository")
    path = (root / relative).resolve()
    if root not in path.parents:
        raise ValueError("repository-relative path escapes the repository")
    return path


def _strict_object(raw: bytes, label: str) -> dict[str, Any]:
    import json

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ValueError(f"{label} bytes are not canonical JSON")
    return payload


def _validate_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _SHA256_CHARS for character in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _validate_commit(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in _SHA256_CHARS for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase 40-character commit")
    return value


def _write_exclusive(path: Path, raw: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _parse_args(raw_argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--p6-9-run-manifest", required=True, type=Path)
    parser.add_argument("--input-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    return parser.parse_args(list(raw_argv))


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    args = _parse_args(raw)
    repo_root = Path(__file__).resolve().parents[2]
    manifest, sidecar = create_p6_10a_freeze(
        expected_commit=args.expected_commit,
        p6_9_run_manifest=args.p6_9_run_manifest,
        input_root=args.input_root,
        output_root=args.output_root,
        repo_root=repo_root,
        invocation_argv=raw,
    )
    print(f"P6-10A freeze completed and verified: {manifest}")
    print(f"freeze_manifest_sha256={sha256_bytes(manifest.read_bytes())}")
    print(f"freeze_hash_sidecar={sidecar}")
    print("P6-10A production attempt has not started")
    return 0


__all__ = [
    "P6_10A_DEPENDENCY_LOCK",
    "P6_10A_FREEZE_HASH_SIDECAR",
    "P6_10A_FREEZE_MANIFEST",
    "P6_10A_INPUT_ROOT_NAME",
    "P6_10A_OUTPUT_ROOT_NAME",
    "create_p6_10a_freeze",
    "main",
    "verify_p6_10a_freeze_manifest",
]
