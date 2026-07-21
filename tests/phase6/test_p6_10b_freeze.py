"""tmp-only freshness, tamper, and single-attempt fixtures for P6-10B."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import phase6.p6_10b_freeze as p6_10b_freeze
from phase6 import canonical_json_bytes, sha256_bytes


def test_freeze_namespace_and_attempt_id_are_exact_precision_fix_values():
    assert (
        p6_10b_freeze.P6_10B_INPUT_ROOT_NAME
        == "p6_10b_confidence_provider_precision_fix_inputs_20260720"
    )
    assert (
        p6_10b_freeze.P6_10B_OUTPUT_ROOT_NAME
        == "p6_10b_confidence_provider_precision_fix_run_20260720"
    )
    assert p6_10b_freeze.P6_10B_ATTEMPT_ID == "p6-10b-confidence-provider-precision-fix-attempt-001"


def _freeze_fixture(tmp_path, monkeypatch):
    repo_root = tmp_path / "repo"
    experiments = repo_root / "experiments_output"
    experiments.mkdir(parents=True)
    source = repo_root / "source" / "run.json"
    source.parent.mkdir()
    source.write_bytes(b"{}\n")
    venv_python = repo_root / "venv" / "Scripts" / "python.exe"
    venv_python.parent.mkdir(parents=True)
    venv_python.write_bytes(b"fixture-python")
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
    source_projection = {"p6_10a_run_manifest": {"path": "source/run.json", "sha256": "2" * 64}}
    batch_payload = {
        "source_snapshot": source_projection,
        "selected_primary": {"fixture": "selected"},
        "ablation_configs": [
            {"ablation_id": "abl_confidence_mvp__v1"},
            {"ablation_id": "abl_provider_rule__v1"},
        ],
        "expected_cardinality": {"session_count": 1620, "artifact_file_count": 10},
    }
    batch_raw = canonical_json_bytes(batch_payload)
    batch = SimpleNamespace(
        manifest=batch_payload,
        manifest_bytes=batch_raw,
        manifest_sha256=sha256_bytes(batch_raw),
    )
    snapshot = SimpleNamespace(fixture=True)
    monkeypatch.setattr(p6_10b_freeze, "_read_repository_state", lambda _root: state)
    monkeypatch.setattr(p6_10b_freeze, "_is_git_ignored", lambda _root, _path: True)
    monkeypatch.setattr(
        p6_10b_freeze,
        "_current_executable_paths",
        lambda: (venv_python.resolve(), base_python.resolve()),
    )
    monkeypatch.setattr(
        p6_10b_freeze,
        "_runtime_payload",
        lambda: {
            "platform": "fixture",
            "python_compiler": "fixture",
            "python_implementation": "CPython",
            "python_version": "3.12.0",
        },
    )
    monkeypatch.setattr(
        p6_10b_freeze,
        "_dependency_lock_payload",
        lambda _root, *, expected_commit: {
            "schema_version": "fixture-lock-v1",
            "target_commit": expected_commit,
        },
    )
    monkeypatch.setattr(
        p6_10b_freeze,
        "load_p6_10a_snapshot",
        lambda _path, *, repo_root: snapshot,
    )
    monkeypatch.setattr(p6_10b_freeze, "build_p6_10b_batch", lambda _snapshot: batch)
    return {
        "repo_root": repo_root,
        "source": source,
        "commit": commit,
        "input_root": experiments / p6_10b_freeze.P6_10B_INPUT_ROOT_NAME,
        "output_root": experiments / p6_10b_freeze.P6_10B_OUTPUT_ROOT_NAME,
    }


def test_freeze_is_closed_world_and_does_not_reserve_attempt(tmp_path, monkeypatch):
    fixture = _freeze_fixture(tmp_path, monkeypatch)
    manifest_path, sidecar_path = p6_10b_freeze.create_p6_10b_freeze(
        expected_commit=fixture["commit"],
        p6_10a_run_manifest=fixture["source"],
        input_root=fixture["input_root"],
        output_root=fixture["output_root"],
        repo_root=fixture["repo_root"],
        invocation_argv=[],
    )

    assert {item.name for item in fixture["input_root"].iterdir()} == {
        p6_10b_freeze.P6_10B_DEPENDENCY_LOCK,
        p6_10b_freeze.P6_10B_BATCH_MANIFEST,
        p6_10b_freeze.P6_10B_FREEZE_MANIFEST,
        p6_10b_freeze.P6_10B_FREEZE_HASH_SIDECAR,
    }
    assert not fixture["output_root"].exists()
    verified = p6_10b_freeze.verify_p6_10b_freeze_manifest(
        manifest_path, sidecar_path, repo_root=fixture["repo_root"]
    )
    assert verified["attempt"]["policy"]["planned_attempt_count"] == 1
    assert verified["attempt"]["policy"]["retry_count"] == 0
    assert verified["attempt"]["policy"]["atomic_ablation_count"] == 2
    assert verified["p6_10_complete"] is False
    assert verified["gate_b_ready"] is False
    assert verified["human_approval_required"] is True


def test_freeze_sidecar_tamper_and_existing_namespace_fail_closed(tmp_path, monkeypatch):
    fixture = _freeze_fixture(tmp_path, monkeypatch)
    manifest_path, sidecar_path = p6_10b_freeze.create_p6_10b_freeze(
        expected_commit=fixture["commit"],
        p6_10a_run_manifest=fixture["source"],
        input_root=fixture["input_root"],
        output_root=fixture["output_root"],
        repo_root=fixture["repo_root"],
        invocation_argv=[],
    )
    sidecar = json.loads(sidecar_path.read_bytes())
    sidecar["freeze_manifest_sha256"] = "f" * 64
    sidecar_path.write_bytes(canonical_json_bytes(sidecar))

    with pytest.raises(ValueError, match="differs from its sidecar"):
        p6_10b_freeze.verify_p6_10b_freeze_manifest(
            manifest_path, sidecar_path, repo_root=fixture["repo_root"]
        )
    with pytest.raises(FileExistsError, match="must be fresh"):
        p6_10b_freeze.create_p6_10b_freeze(
            expected_commit=fixture["commit"],
            p6_10a_run_manifest=fixture["source"],
            input_root=fixture["input_root"],
            output_root=fixture["output_root"],
            repo_root=fixture["repo_root"],
            invocation_argv=[],
        )


@pytest.mark.parametrize(
    ("input_name", "output_name"),
    (
        (
            "p6_10b_confidence_provider_inputs_20260719",
            "p6_10b_confidence_provider_run_20260719",
        ),
        ("p6_10b_other_inputs", "p6_10b_other_output"),
    ),
)
def test_freeze_rejects_alternate_namespace(tmp_path, monkeypatch, input_name, output_name):
    fixture = _freeze_fixture(tmp_path, monkeypatch)

    with pytest.raises(ValueError, match="not canonical"):
        p6_10b_freeze.create_p6_10b_freeze(
            expected_commit=fixture["commit"],
            p6_10a_run_manifest=fixture["source"],
            input_root=fixture["input_root"].with_name(input_name),
            output_root=fixture["output_root"].with_name(output_name),
            repo_root=fixture["repo_root"],
            invocation_argv=[],
        )
