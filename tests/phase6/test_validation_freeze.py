from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import phase6.validation_freeze as validation_freeze
from phase6.contracts import canonical_json_bytes, sha256_bytes
from phase6.validation_freeze import (
    VALIDATION_ATTEMPT_MARKER_NAME,
    VALIDATION_BATCH_MANIFEST_NAME,
    VALIDATION_FREEZE_MANIFEST_NAME,
    VALIDATION_FREEZE_QV5_SCHEMA_VERSION,
    VALIDATION_QV5_MANIFEST_NAME,
    ValidationRepositoryState,
    freeze_validation_inputs,
    load_validation_freeze_spec,
    preflight_validation_freeze,
    reserve_validation_attempt,
    validate_validation_freeze_spec,
    verify_validation_freeze_manifest,
)
from phase6.validation_runner import ValidationBatchPlan


@pytest.fixture
def freeze_fixture(tmp_path, monkeypatch):
    real_read_repository_state = validation_freeze._read_repository_state
    real_is_git_ignored = validation_freeze._is_git_ignored
    repo_root = (tmp_path / "repo").resolve()
    output_parent = repo_root / "experiments_output"
    output_parent.mkdir(parents=True)
    training_root = output_parent / "training"
    training_root.mkdir()
    training_manifest = training_root / "phase6_training_run_manifest.json"
    training_manifest.write_bytes(canonical_json_bytes({"fixture": "verified-training"}))

    python_executable = repo_root / "venv" / "Scripts" / "python.exe"
    python_executable.parent.mkdir(parents=True)
    python_executable.write_bytes(b"fixture-python\n")
    base_executable = (tmp_path / "runtime" / "python.exe").resolve()
    base_executable.parent.mkdir()
    base_executable.write_bytes(b"fixture-base-python\n")
    pyvenv_cfg = repo_root / "venv" / "pyvenv.cfg"
    pyvenv_cfg.write_bytes(b"home = fixture\n")
    site_packages = repo_root / "venv" / "Lib" / "site-packages"
    site_packages.mkdir(parents=True)

    commit = "a" * 40
    runtime = {
        "python_implementation": "CPython",
        "python_version": "3.12.0",
        "python_compiler": "fixture-compiler",
        "platform": "fixture-platform",
        "system": "Windows",
        "release": "fixture-release",
        "version": "fixture-version",
        "machine": "AMD64",
    }
    distributions = (("fixture-package", "1.0"),)
    dependency_lock = output_parent / "dependency-lock.json"
    dependency_payload = {
        "schema_version": "phase6-production-dependency-lock-v1",
        "lock_scope": "complete-installed-environment-snapshot",
        "distributions": [{"name": name, "version": version} for name, version in distributions],
        "project": {
            "name": "poker-xai",
            "version": "0.0.0",
            "source": "repository",
            "repository_path": ".",
            "git_commit": commit,
        },
        "python": {
            "implementation": runtime["python_implementation"],
            "version": runtime["python_version"],
            "compiler": runtime["python_compiler"],
            "platform": runtime["platform"],
            "venv_executable_path": "venv/Scripts/python.exe",
            "venv_executable_sha256": sha256_bytes(python_executable.read_bytes()),
            "base_executable_path": str(base_executable),
            "base_executable_sha256": sha256_bytes(base_executable.read_bytes()),
            "pyvenv_cfg_path": "venv/pyvenv.cfg",
            "pyvenv_cfg_sha256": sha256_bytes(pyvenv_cfg.read_bytes()),
            "site_packages_path": "venv/Lib/site-packages",
        },
    }
    dependency_lock.write_bytes(canonical_json_bytes(dependency_payload))

    plan_manifest = {
        "schema_version": "phase6-validation-batch-manifest-v1",
        "training_source": {"fixture": "verified-read-only"},
    }
    plan_raw = canonical_json_bytes(plan_manifest)
    plan = ValidationBatchPlan(
        manifest=plan_manifest,
        manifest_bytes=plan_raw,
        manifest_sha256=sha256_bytes(plan_raw),
        candidates=(),
        sessions=(),
    )
    calls = {"build": 0, "verify": 0}

    def fake_build(path, *, expected_training_run_manifest_sha256, repo_root):
        calls["build"] += 1
        assert Path(path).resolve() == training_manifest
        assert expected_training_run_manifest_sha256 == sha256_bytes(training_manifest.read_bytes())
        assert Path(repo_root).resolve() == repo_root_path
        return plan

    def fake_verify(candidate, *, repo_root):
        calls["verify"] += 1
        assert candidate is plan
        assert Path(repo_root).resolve() == repo_root_path

    repo_root_path = repo_root
    monkeypatch.setattr(validation_freeze, "build_validation_batch_plan", fake_build)
    monkeypatch.setattr(validation_freeze, "verify_validation_batch_plan", fake_verify)
    monkeypatch.setattr(
        validation_freeze,
        "_read_repository_state",
        lambda _root: ValidationRepositoryState("main", commit, commit, commit, False),
    )
    monkeypatch.setattr(validation_freeze, "_is_git_ignored", lambda _root, _path: True)
    monkeypatch.setattr(validation_freeze, "_runtime_payload", lambda: dict(runtime))
    monkeypatch.setattr(
        validation_freeze,
        "_current_executable_paths",
        lambda: (python_executable.resolve(), base_executable),
    )
    monkeypatch.setattr(
        validation_freeze,
        "_current_environment_paths",
        lambda: (pyvenv_cfg.resolve(), site_packages.resolve()),
    )
    monkeypatch.setattr(
        validation_freeze,
        "_installed_distributions",
        lambda _name: distributions,
    )
    monkeypatch.setattr(validation_freeze, "_installed_project_version", lambda _name: "0.0.0")
    monkeypatch.setattr(validation_freeze, "_free_bytes", lambda _path: 10_000_000)
    monkeypatch.setattr(validation_freeze, "REPO_ROOT", repo_root)

    input_dir = (output_parent / "validation-input").resolve()
    output_dir = (output_parent / "validation-attempt-001").resolve()
    attempt_id = "validation-attempt-001"
    qv5_payload = {
        "schema_version": VALIDATION_FREEZE_QV5_SCHEMA_VERSION,
        "artifact_type": "validation_freeze_qv5",
        "attempt_id": attempt_id,
        "attempt_policy": {
            "planned_attempt_count": 1,
            "fresh_output_directory_required": True,
            "atomic_directory_reservation_required": True,
            "in_progress_marker_name": VALIDATION_ATTEMPT_MARKER_NAME,
            "partial_attempt_retention": "preserve_read_only",
            "same_path_retry_allowed": False,
            "stale_marker_auto_release_allowed": False,
            "retry_authorization": "separate_human_approval",
        },
        "git": {
            "branch": "main",
            "expected_commit": commit,
            "cached_origin_main_commit": commit,
        },
        "training_source": {
            "run_manifest": {
                "path": str(training_manifest.resolve()),
                "sha256": sha256_bytes(training_manifest.read_bytes()),
            }
        },
        "validation_plan": {"expected_manifest_sha256": plan.manifest_sha256},
        "runtime": {
            "python_executable": {
                "path": str(python_executable.resolve()),
                "sha256": sha256_bytes(python_executable.read_bytes()),
            },
            "base_executable": {
                "path": str(base_executable),
                "sha256": sha256_bytes(base_executable.read_bytes()),
            },
            "runtime_fingerprint": runtime,
        },
        "dependency_lock": {
            "path": str(dependency_lock.resolve()),
            "sha256": sha256_bytes(dependency_lock.read_bytes()),
        },
        "paths": {
            "validation_input_dir": str(input_dir),
            "validation_output_dir": str(output_dir),
        },
        "minimum_free_space_bytes": 1_000_000,
        "planned_validation_command": [
            "python",
            "future_validation_cli.py",
            "--input-dir",
            str(input_dir),
            "--output-dir",
            str(output_dir),
            "--attempt-id",
            attempt_id,
        ],
    }
    qv5_path = output_parent / "qv5-fixture.json"
    qv5_path.write_bytes(canonical_json_bytes(qv5_payload))
    qv5_hash = sha256_bytes(qv5_path.read_bytes())
    spec = load_validation_freeze_spec(qv5_path, expected_sha256=qv5_hash)
    return {
        "repo_root": repo_root,
        "qv5_payload": qv5_payload,
        "qv5_path": qv5_path,
        "qv5_hash": qv5_hash,
        "spec": spec,
        "dependency_lock": dependency_lock,
        "dependency_payload": dependency_payload,
        "pyvenv_cfg": pyvenv_cfg,
        "site_packages": site_packages,
        "input_dir": input_dir,
        "output_dir": output_dir,
        "plan": plan,
        "calls": calls,
        "real_read_repository_state": real_read_repository_state,
        "real_is_git_ignored": real_is_git_ignored,
    }


def test_read_only_preflight_reuses_verified_plan_and_cli_surface(freeze_fixture, capsys):
    preflight = preflight_validation_freeze(
        freeze_fixture["spec"], repo_root=freeze_fixture["repo_root"]
    )
    assert preflight.validation_plan is freeze_fixture["plan"]
    assert freeze_fixture["calls"] == {"build": 1, "verify": 1}
    assert not freeze_fixture["input_dir"].exists()
    assert not freeze_fixture["output_dir"].exists()

    assert (
        validation_freeze.main(
            [
                "preflight",
                "--qv5-manifest",
                str(freeze_fixture["qv5_path"]),
                "--qv5-manifest-sha256",
                freeze_fixture["qv5_hash"],
            ]
        )
        == 0
    )
    assert "read-only; no path reserved" in capsys.readouterr().out
    assert not freeze_fixture["input_dir"].exists()
    assert not freeze_fixture["output_dir"].exists()


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda p: p["attempt_policy"].update(planned_attempt_count=2), "exactly-one"),
        (lambda p: p["attempt_policy"].update(same_path_retry_allowed=True), "exactly-one"),
        (
            lambda p: p["attempt_policy"].update(stale_marker_auto_release_allowed=True),
            "exactly-one",
        ),
        (lambda p: p["git"].update(cached_origin_main_commit="b" * 40), "trust anchor"),
        (lambda p: p.update(minimum_free_space_bytes=0), "positive integer"),
        (lambda p: p["planned_validation_command"].pop(), "bind each path"),
        (lambda p: p.update(unapproved_default="forbidden"), "closed-world"),
    ],
)
def test_qv5_contract_rejects_policy_and_unknown_value_mutations(freeze_fixture, mutation, match):
    payload = copy.deepcopy(freeze_fixture["qv5_payload"])
    mutation(payload)
    with pytest.raises(ValueError, match=match):
        validate_validation_freeze_spec(payload)


def test_preflight_fails_closed_on_repo_runtime_fresh_path_and_free_space(
    freeze_fixture, monkeypatch
):
    spec = freeze_fixture["spec"]
    root = freeze_fixture["repo_root"]
    monkeypatch.setattr(
        validation_freeze,
        "_read_repository_state",
        lambda _root: ValidationRepositoryState(
            "main", spec.expected_commit, spec.expected_commit, spec.expected_commit, True
        ),
    )
    with pytest.raises(RuntimeError, match="repository state"):
        preflight_validation_freeze(spec, repo_root=root)

    monkeypatch.setattr(
        validation_freeze,
        "_read_repository_state",
        lambda _root: ValidationRepositoryState(
            "main", spec.expected_commit, spec.expected_commit, spec.expected_commit, False
        ),
    )
    monkeypatch.setattr(validation_freeze, "_runtime_payload", lambda: {"wrong": "runtime"})
    with pytest.raises(ValueError, match="runtime/platform"):
        preflight_validation_freeze(spec, repo_root=root)

    monkeypatch.setattr(
        validation_freeze, "_runtime_payload", lambda: dict(spec.runtime_fingerprint)
    )
    freeze_fixture["output_dir"].mkdir()
    with pytest.raises(FileExistsError, match="fresh"):
        preflight_validation_freeze(spec, repo_root=root)
    freeze_fixture["output_dir"].rmdir()

    monkeypatch.setattr(validation_freeze, "_free_bytes", lambda _path: 1)
    with pytest.raises(OSError, match="free space"):
        preflight_validation_freeze(spec, repo_root=root)


@pytest.mark.parametrize("locked_path", ["pyvenv_cfg_path", "site_packages_path"])
def test_preflight_rejects_rehashed_foreign_active_environment_paths(freeze_fixture, locked_path):
    root = freeze_fixture["repo_root"]
    dependency_payload = copy.deepcopy(freeze_fixture["dependency_payload"])
    if locked_path == "pyvenv_cfg_path":
        foreign = root / "foreign" / "pyvenv.cfg"
        foreign.parent.mkdir()
        foreign.write_bytes(b"home = foreign\n")
        dependency_payload["python"]["pyvenv_cfg_sha256"] = sha256_bytes(foreign.read_bytes())
    else:
        foreign = root / "foreign" / "site-packages"
        foreign.mkdir(parents=True)
    dependency_payload["python"][locked_path] = foreign.relative_to(root).as_posix()
    dependency_lock = freeze_fixture["dependency_lock"]
    dependency_lock.write_bytes(canonical_json_bytes(dependency_payload))

    qv5_payload = copy.deepcopy(freeze_fixture["qv5_payload"])
    qv5_payload["dependency_lock"]["sha256"] = sha256_bytes(dependency_lock.read_bytes())
    qv5_path = freeze_fixture["qv5_path"]
    qv5_path.write_bytes(canonical_json_bytes(qv5_payload))
    spec = load_validation_freeze_spec(
        qv5_path,
        expected_sha256=sha256_bytes(qv5_path.read_bytes()),
    )

    with pytest.raises(ValueError, match="Python/runtime provenance"):
        preflight_validation_freeze(spec, repo_root=root)


def test_real_git_preflight_preserves_stale_index_and_creates_no_lock(freeze_fixture, monkeypatch):
    root = freeze_fixture["repo_root"]
    tracked = root / ".gitignore"
    tracked.write_text("experiments_output/\nvenv/\n", encoding="ascii", newline="\n")

    git_env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}

    def run_git(*arguments):
        return subprocess.run(
            ["git", *arguments],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
            env=git_env,
            timeout=30,
        ).stdout.strip()

    run_git("init", "-b", "main")
    run_git("config", "user.name", "Validation Freeze Fixture")
    run_git("config", "user.email", "validation-freeze@example.invalid")
    run_git("add", ".gitignore")
    run_git("commit", "-m", "Create validation freeze fixture")
    commit = run_git("rev-parse", "HEAD")
    run_git("update-ref", "refs/remotes/origin/main", commit)

    dependency_payload = copy.deepcopy(freeze_fixture["dependency_payload"])
    dependency_payload["project"]["git_commit"] = commit
    dependency_lock = freeze_fixture["dependency_lock"]
    dependency_lock.write_bytes(canonical_json_bytes(dependency_payload))
    qv5_payload = copy.deepcopy(freeze_fixture["qv5_payload"])
    qv5_payload["git"]["expected_commit"] = commit
    qv5_payload["git"]["cached_origin_main_commit"] = commit
    qv5_payload["dependency_lock"]["sha256"] = sha256_bytes(dependency_lock.read_bytes())
    qv5_path = freeze_fixture["qv5_path"]
    qv5_path.write_bytes(canonical_json_bytes(qv5_payload))
    spec = load_validation_freeze_spec(
        qv5_path,
        expected_sha256=sha256_bytes(qv5_path.read_bytes()),
    )

    tracked_stat = tracked.stat()
    os.utime(
        tracked,
        ns=(tracked_stat.st_atime_ns, tracked_stat.st_mtime_ns + 2_000_000_000),
    )
    monkeypatch.setattr(
        validation_freeze,
        "_read_repository_state",
        freeze_fixture["real_read_repository_state"],
    )
    monkeypatch.setattr(
        validation_freeze,
        "_is_git_ignored",
        freeze_fixture["real_is_git_ignored"],
    )

    index = root / ".git" / "index"
    index_lock = root / ".git" / "index.lock"
    before_bytes = index.read_bytes()
    before_stat = index.stat()
    before_metadata = (
        before_stat.st_mode,
        before_stat.st_size,
        before_stat.st_mtime_ns,
        before_stat.st_ctime_ns,
    )
    assert not index_lock.exists()

    preflight = preflight_validation_freeze(spec, repo_root=root)

    after_bytes = index.read_bytes()
    after_stat = index.stat()
    after_metadata = (
        after_stat.st_mode,
        after_stat.st_size,
        after_stat.st_mtime_ns,
        after_stat.st_ctime_ns,
    )
    assert preflight.repository_state.dirty is False
    assert after_bytes == before_bytes
    assert after_metadata == before_metadata
    assert not index_lock.exists()


def test_tmp_freeze_bundle_is_atomic_verified_and_does_not_start_attempt(freeze_fixture):
    raw_argv = [
        "freeze",
        "--qv5-manifest",
        str(freeze_fixture["qv5_path"]),
        "--qv5-manifest-sha256",
        freeze_fixture["qv5_hash"],
    ]
    preflight = preflight_validation_freeze(
        freeze_fixture["spec"], repo_root=freeze_fixture["repo_root"]
    )
    assert validation_freeze.main(raw_argv) == 0
    manifest_path = freeze_fixture["input_dir"] / VALIDATION_FREEZE_MANIFEST_NAME
    assert manifest_path.name == VALIDATION_FREEZE_MANIFEST_NAME
    assert (freeze_fixture["input_dir"] / VALIDATION_QV5_MANIFEST_NAME).is_file()
    assert (freeze_fixture["input_dir"] / VALIDATION_BATCH_MANIFEST_NAME).is_file()
    assert not freeze_fixture["output_dir"].exists()
    verified = verify_validation_freeze_manifest(
        manifest_path,
        expected_sha256=sha256_bytes(manifest_path.read_bytes()),
        repo_root=freeze_fixture["repo_root"],
    )
    assert verified.validation_plan.manifest_sha256 == freeze_fixture["plan"].manifest_sha256
    with pytest.raises(FileExistsError, match="fresh"):
        freeze_validation_inputs(
            preflight,
            raw_argv=raw_argv,
            frozen_at_utc="2026-07-17T00:00:01.000000Z",
        )


def test_partial_freeze_is_preserved_without_cleanup(freeze_fixture, monkeypatch):
    preflight = preflight_validation_freeze(
        freeze_fixture["spec"], repo_root=freeze_fixture["repo_root"]
    )
    real_write = validation_freeze._write_bytes_exclusive
    writes = 0

    def fail_second_write(path, raw):
        nonlocal writes
        writes += 1
        if writes == 2:
            raise OSError("fixture write failure")
        real_write(path, raw)

    monkeypatch.setattr(validation_freeze, "_write_bytes_exclusive", fail_second_write)
    with pytest.raises(OSError, match="fixture write failure"):
        freeze_validation_inputs(
            preflight,
            raw_argv=["freeze"],
            frozen_at_utc="2026-07-17T00:00:00.000000Z",
        )
    assert freeze_fixture["input_dir"].is_dir()
    assert (freeze_fixture["input_dir"] / VALIDATION_QV5_MANIFEST_NAME).is_file()
    assert not (freeze_fixture["input_dir"] / VALIDATION_FREEZE_MANIFEST_NAME).exists()


def test_attempt_reservation_is_exactly_once_and_marker_bound(freeze_fixture):
    preflight = preflight_validation_freeze(
        freeze_fixture["spec"], repo_root=freeze_fixture["repo_root"]
    )
    manifest_path = freeze_validation_inputs(
        preflight,
        raw_argv=["freeze"],
        frozen_at_utc="2026-07-17T00:00:00.000000Z",
    )
    verified = verify_validation_freeze_manifest(
        manifest_path,
        expected_sha256=sha256_bytes(manifest_path.read_bytes()),
        repo_root=freeze_fixture["repo_root"],
    )
    marker_path = reserve_validation_attempt(
        verified,
        started_at_utc="2026-07-17T00:01:00.000000Z",
    )
    marker = json.loads(marker_path.read_bytes())
    assert marker["attempt_number"] == 1
    assert marker["attempt_id"] == freeze_fixture["spec"].attempt_id
    assert marker_path.parent == freeze_fixture["output_dir"]
    before = marker_path.read_bytes()
    with pytest.raises(FileExistsError, match="same-path retry"):
        reserve_validation_attempt(
            verified,
            started_at_utc="2026-07-17T00:02:00.000000Z",
        )
    assert marker_path.read_bytes() == before


def test_partial_attempt_directory_survives_marker_failure(freeze_fixture, monkeypatch):
    preflight = preflight_validation_freeze(
        freeze_fixture["spec"], repo_root=freeze_fixture["repo_root"]
    )
    manifest_path = freeze_validation_inputs(
        preflight,
        raw_argv=["freeze"],
        frozen_at_utc="2026-07-17T00:00:00.000000Z",
    )
    verified = verify_validation_freeze_manifest(
        manifest_path,
        expected_sha256=sha256_bytes(manifest_path.read_bytes()),
        repo_root=freeze_fixture["repo_root"],
    )

    def fail_marker(path, raw):
        raise OSError("marker failure")

    monkeypatch.setattr(validation_freeze, "_write_bytes_exclusive", fail_marker)
    with pytest.raises(OSError, match="marker failure"):
        reserve_validation_attempt(
            verified,
            started_at_utc="2026-07-17T00:01:00.000000Z",
        )
    assert freeze_fixture["output_dir"].is_dir()
    assert list(freeze_fixture["output_dir"].iterdir()) == []


def test_cli_help_smoke_exposes_only_preflight_and_freeze():
    repo_root = Path(__file__).resolve().parents[2]
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(repo_root / "cli" / "phase6_validation_freeze_v1.py"),
            "--help",
        ],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert "preflight" in completed.stdout
    assert "freeze" in completed.stdout
    assert "--epsilon" not in completed.stdout
    assert "--candidate" not in completed.stdout
