"""Unit/tmp fixtures for the P6-10A target-commit freeze boundary."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import phase6.p6_10_freeze as p6_10_freeze
from phase6 import canonical_json_bytes, sha256_bytes


def _freeze_fixture(tmp_path, monkeypatch):
    repo_root = tmp_path / "repo"
    experiments = repo_root / "experiments_output"
    experiments.mkdir(parents=True)
    source = repo_root / "source" / "run.json"
    source.parent.mkdir()
    source.write_bytes(b"{}\n")
    venv_python = repo_root / "venv" / "Scripts" / "python.exe"
    pyvenv_cfg = repo_root / "venv" / "pyvenv.cfg"
    site_packages = repo_root / "venv" / "Lib" / "site-packages"
    venv_python.parent.mkdir(parents=True)
    site_packages.mkdir(parents=True)
    venv_python.write_bytes(b"fixture-python")
    pyvenv_cfg.write_bytes(b"home = fixture\n")
    base_python = tmp_path / "base-python.exe"
    base_python.write_bytes(b"fixture-base")
    commit = "1" * 40
    state = SimpleNamespace(
        branch="main",
        head_commit=commit,
        local_main_commit=commit,
        cached_origin_main_commit=commit,
        dirty=False,
        canonical_payload=lambda: {
            "branch": "main",
            "head_commit": commit,
            "local_main_commit": commit,
            "cached_origin_main_commit": commit,
            "dirty": False,
            "live_remote_queried": False,
        },
    )
    source_projection = {"p6_9_run_manifest": {"path": "source/run.json", "sha256": "2" * 64}}
    batch_payload = {
        "source_snapshot": source_projection,
        "selected_primary": {"fixture": "selected"},
        "epsilon_zero_candidate": {"fixture": "epsilon-zero"},
        "expected_cardinality": {"session_count": 810, "stream_root_count": 3240},
    }
    batch_raw = canonical_json_bytes(batch_payload)
    batch = SimpleNamespace(
        manifest=batch_payload,
        manifest_bytes=batch_raw,
        manifest_sha256=sha256_bytes(batch_raw),
    )
    snapshot = SimpleNamespace(fixture=True)
    monkeypatch.setattr(p6_10_freeze, "_read_repository_state", lambda _root: state)
    monkeypatch.setattr(p6_10_freeze, "_is_git_ignored", lambda _root, _path: True)
    monkeypatch.setattr(
        p6_10_freeze,
        "_current_executable_paths",
        lambda: (venv_python.resolve(), base_python.resolve()),
    )
    monkeypatch.setattr(
        p6_10_freeze,
        "_current_environment_paths",
        lambda: (pyvenv_cfg.resolve(), site_packages.resolve()),
    )
    monkeypatch.setattr(
        p6_10_freeze,
        "_runtime_payload",
        lambda: {
            "machine": "fixture",
            "platform": "fixture-platform",
            "python_compiler": "fixture-compiler",
            "python_implementation": "CPython",
            "python_version": "3.12.0",
            "release": "fixture",
            "system": "fixture",
            "version": "fixture",
        },
    )
    monkeypatch.setattr(
        p6_10_freeze,
        "_installed_distributions",
        lambda _name: (("pytest", "9.0.0"),),
    )
    monkeypatch.setattr(p6_10_freeze, "_installed_project_version", lambda _name: "0.0.0")
    monkeypatch.setattr(
        p6_10_freeze,
        "load_p6_9_snapshot",
        lambda _path, *, repo_root: snapshot,
    )
    monkeypatch.setattr(p6_10_freeze, "build_p6_10a_batch", lambda _snapshot: batch)
    return {
        "repo_root": repo_root,
        "source": source,
        "commit": commit,
        "input_root": experiments / p6_10_freeze.P6_10A_INPUT_ROOT_NAME,
        "output_root": experiments / p6_10_freeze.P6_10A_OUTPUT_ROOT_NAME,
        "batch": batch,
    }


def test_freeze_creates_one_closed_world_lock_batch_manifest_and_sidecar(tmp_path, monkeypatch):
    fixture = _freeze_fixture(tmp_path, monkeypatch)
    argv = [
        "--expected-commit",
        fixture["commit"],
        "--p6-9-run-manifest",
        str(fixture["source"]),
        "--input-root",
        str(fixture["input_root"]),
        "--output-root",
        str(fixture["output_root"]),
    ]

    manifest_path, sidecar_path = p6_10_freeze.create_p6_10a_freeze(
        expected_commit=fixture["commit"],
        p6_9_run_manifest=fixture["source"],
        input_root=fixture["input_root"],
        output_root=fixture["output_root"],
        repo_root=fixture["repo_root"],
        invocation_argv=argv,
    )

    assert {item.name for item in fixture["input_root"].iterdir()} == {
        p6_10_freeze.P6_10A_DEPENDENCY_LOCK,
        p6_10_freeze.P6_10A_FREEZE_MANIFEST,
        p6_10_freeze.P6_10A_FREEZE_HASH_SIDECAR,
        "p6_10a_batch_manifest.json",
    }
    assert not fixture["output_root"].exists()
    verified = p6_10_freeze.verify_p6_10a_freeze_manifest(
        manifest_path,
        sidecar_path,
        repo_root=fixture["repo_root"],
    )
    assert verified["attempt"]["attempt_id"] == ("p6-10a-comparator-ablation-attempt-001")
    assert verified["attempt"]["policy"]["retry_count"] == 0
    assert verified["p6_10_complete"] is False
    assert verified["gate_b_ready"] is False

    with pytest.raises(FileExistsError, match="must be fresh"):
        p6_10_freeze.create_p6_10a_freeze(
            expected_commit=fixture["commit"],
            p6_9_run_manifest=fixture["source"],
            input_root=fixture["input_root"],
            output_root=fixture["output_root"],
            repo_root=fixture["repo_root"],
            invocation_argv=argv,
        )


def test_freeze_sidecar_tamper_is_fail_closed(tmp_path, monkeypatch):
    fixture = _freeze_fixture(tmp_path, monkeypatch)
    manifest_path, sidecar_path = p6_10_freeze.create_p6_10a_freeze(
        expected_commit=fixture["commit"],
        p6_9_run_manifest=fixture["source"],
        input_root=fixture["input_root"],
        output_root=fixture["output_root"],
        repo_root=fixture["repo_root"],
        invocation_argv=[],
    )
    sidecar = json.loads(sidecar_path.read_bytes())
    sidecar["freeze_manifest_sha256"] = "f" * 64
    sidecar_path.write_bytes(canonical_json_bytes(sidecar))

    with pytest.raises(ValueError, match="differs from its sidecar"):
        p6_10_freeze.verify_p6_10a_freeze_manifest(
            manifest_path,
            sidecar_path,
            repo_root=fixture["repo_root"],
        )


def test_freeze_rejects_alternate_attempt_namespace(tmp_path, monkeypatch):
    fixture = _freeze_fixture(tmp_path, monkeypatch)

    with pytest.raises(ValueError, match="single canonical attempt namespace"):
        p6_10_freeze.create_p6_10a_freeze(
            expected_commit=fixture["commit"],
            p6_9_run_manifest=fixture["source"],
            input_root=fixture["input_root"].with_name("p6_10a_alternate_inputs"),
            output_root=fixture["output_root"].with_name("p6_10a_alternate_output"),
            repo_root=fixture["repo_root"],
            invocation_argv=[],
        )
