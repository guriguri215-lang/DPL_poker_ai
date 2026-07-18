from __future__ import annotations

import os
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import pytest

import phase6.validation_backend as validation_backend
import phase6.validation_cli as validation_cli
import phase6.validation_execution as validation_execution
from opponents import load_validation_catalog
from opponents.synthesis import synthesize_opponent
from phase6 import (
    PRODUCTION_VALIDATION_BACKEND_ID,
    PRODUCTION_VALIDATION_BACKEND_VERSION,
    PRODUCTION_VALIDATION_ENTRYPOINT,
    PRODUCTION_VALIDATION_RUN_MANIFEST,
    VALIDATION_ATTEMPT_MARKER_NAME,
    VALIDATION_BATCH_MANIFEST_NAME,
    VALIDATION_FREEZE_MANIFEST_NAME,
    VALIDATION_QV5_MANIFEST_NAME,
    ValidationArtifactBundle,
    ValidationBatchPlan,
    ValidationCandidateRequest,
    ValidationFreezeSpec,
    ValidationSessionKey,
    ValidationSessionRequest,
    VerifiedValidationFreeze,
    canonical_json_bytes,
    derive_stream_root,
    primary_candidate_grid,
    sampling_contract_payload,
    sha256_bytes,
)
from phase6.p6_7 import REPETITION_SEEDS, STREAM_NAMES
from phase6.production_inputs import build_production_observation_registry
from phase6.training_runner import HORIZONS


def _sampling_reference(configs):
    game = synthesize_opponent(config=configs[0]).game
    registry = build_production_observation_registry(game)
    payload = sampling_contract_payload(
        observation_registry_version=registry.registry_version,
        observation_registry_sha256=registry.sha256,
    )
    return {"payload": payload, "sha256": sha256_bytes(canonical_json_bytes(payload))}


def _written_json_artifacts(directory):
    return [path for path in directory.glob("*.json") if path.stat().st_size > 0]


@pytest.fixture
def prepared_fixture(tmp_path, monkeypatch):
    repo_root = (tmp_path / "repo").resolve()
    input_root = repo_root / "experiments_output" / "validation-input"
    output_root = repo_root / "experiments_output" / "validation-attempt-001"
    input_root.mkdir(parents=True)
    python_path = repo_root / "venv" / "Scripts" / "python.exe"
    python_path.parent.mkdir(parents=True)
    python_path.write_bytes(b"fixture-python\n")
    base_path = repo_root / "runtime" / "python.exe"
    base_path.parent.mkdir()
    base_path.write_bytes(b"fixture-base\n")
    dependency_path = repo_root / "experiments_output" / "dependency-lock.json"
    dependency_path.write_bytes(canonical_json_bytes({"fixture": "dependency"}))
    training_path = repo_root / "experiments_output" / "training-run.json"
    training_path.write_bytes(canonical_json_bytes({"fixture": "training"}))

    qv5_path = input_root / VALIDATION_QV5_MANIFEST_NAME
    qv5_path.write_bytes(canonical_json_bytes({"fixture": "qv5"}))
    configs = tuple(sorted(load_validation_catalog(), key=lambda item: item.opponent_id))
    sampling = _sampling_reference(configs)
    candidates = primary_candidate_grid(sampling_contract_sha256=sampling["sha256"])
    selection_payload = {"schema_version": "phase6-full-selection-metrics-v2"}
    preregistration_payload = {"schema_version": "phase6-full-selection-preregistration-v2"}
    batch_manifest = {
        "sampling_contract": sampling,
        "selection_metric_contract": {
            "payload": selection_payload,
            "sha256": sha256_bytes(canonical_json_bytes(selection_payload)),
        },
        "preregistration": {
            "payload": preregistration_payload,
            "sha256": sha256_bytes(canonical_json_bytes(preregistration_payload)),
        },
        "training_source": {"run_manifest_sha256": "3" * 64},
        "candidates": [candidate.canonical_payload() for candidate in candidates],
        "horizons": list(HORIZONS),
        "repetitions": [
            {"master_seed": seed, "repetition_id": repetition_id}
            for repetition_id, seed in REPETITION_SEEDS
        ],
    }
    batch_raw = canonical_json_bytes(batch_manifest)
    (input_root / VALIDATION_BATCH_MANIFEST_NAME).write_bytes(batch_raw)
    plan = ValidationBatchPlan(
        batch_manifest,
        batch_raw,
        sha256_bytes(batch_raw),
        candidates,
        (),
    )
    freeze_path = input_root / VALIDATION_FREEZE_MANIFEST_NAME
    freeze_path.write_bytes(canonical_json_bytes({"fixture": "freeze"}))
    freeze_hash = sha256_bytes(freeze_path.read_bytes())
    raw_argv = (
        "--validation-input-dir",
        str(input_root),
        "--validation-output-dir",
        str(output_root),
        "--attempt-id",
        "validation-attempt-001",
    )
    runtime = {
        "python_executable": {
            "path": str(python_path),
            "sha256": sha256_bytes(python_path.read_bytes()),
        },
        "base_executable": {
            "path": str(base_path),
            "sha256": sha256_bytes(base_path.read_bytes()),
        },
        "runtime_fingerprint": {"python_version": "fixture"},
    }
    dependency_reference = {
        "path": str(dependency_path),
        "sha256": sha256_bytes(dependency_path.read_bytes()),
    }
    spec_payload = {
        "runtime": runtime,
        "dependency_lock": dependency_reference,
    }
    spec = ValidationFreezeSpec(
        payload=spec_payload,
        raw_bytes=qv5_path.read_bytes(),
        sha256=sha256_bytes(qv5_path.read_bytes()),
        attempt_id="validation-attempt-001",
        expected_commit="a" * 40,
        cached_origin_main_commit="a" * 40,
        training_run_manifest=training_path,
        training_run_manifest_sha256=sha256_bytes(training_path.read_bytes()),
        expected_validation_batch_sha256=plan.manifest_sha256,
        dependency_lock=dependency_path,
        dependency_lock_sha256=dependency_reference["sha256"],
        python_executable=python_path,
        python_executable_sha256=sha256_bytes(python_path.read_bytes()),
        base_executable=base_path,
        base_executable_sha256=sha256_bytes(base_path.read_bytes()),
        runtime_fingerprint={"python_version": "fixture"},
        validation_input_dir=input_root,
        validation_output_dir=output_root,
        minimum_free_space_bytes=1,
        planned_validation_command=(
            str(python_path),
            str((repo_root / PRODUCTION_VALIDATION_ENTRYPOINT).resolve()),
            *raw_argv,
        ),
    )
    manifest_payload = {
        "git": {
            "branch": "main",
            "head_commit": "a" * 40,
            "local_main_commit": "a" * 40,
            "cached_origin_main_commit": "a" * 40,
            "dirty": False,
            "live_remote_queried": False,
        },
        "runtime": runtime,
        "training_source": batch_manifest["training_source"],
    }
    verified = VerifiedValidationFreeze(
        freeze_path,
        manifest_payload,
        freeze_hash,
        spec,
        plan,
    )
    monkeypatch.setattr(validation_cli, "REPO_ROOT", repo_root)
    monkeypatch.setattr(
        validation_cli,
        "verify_validation_freeze_manifest",
        lambda path, *, expected_sha256, repo_root: verified,
    )
    monkeypatch.setattr(
        validation_cli,
        "_verify_frozen_inputs_after_reservation",
        lambda path, *, expected_sha256, repo_root: verified,
    )
    return {
        "repo_root": repo_root,
        "input_root": input_root,
        "output_root": output_root,
        "raw_argv": raw_argv,
        "verified": verified,
    }


def test_prepare_validation_run_requires_exact_frozen_command(prepared_fixture):
    prepared = validation_cli.prepare_validation_run(
        list(prepared_fixture["raw_argv"]),
        repo_root=prepared_fixture["repo_root"],
    )
    assert prepared.verified_freeze is prepared_fixture["verified"]
    assert prepared.raw_argv == prepared_fixture["raw_argv"]
    reordered = list(prepared_fixture["raw_argv"])
    reordered[0:4] = reordered[2:4] + reordered[0:2]
    with pytest.raises(ValueError, match="canonical approved order"):
        validation_cli.prepare_validation_run(
            reordered,
            repo_root=prepared_fixture["repo_root"],
        )


def test_cli_help_has_no_experiment_axes(capsys):
    with pytest.raises(SystemExit) as exc_info:
        validation_cli.main(["--help"])
    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "--validation-input-dir" in output
    assert "--validation-output-dir" in output
    assert "--attempt-id" in output
    for forbidden in ("candidate", "opponent", "horizon", "repetition", "seed", "epsilon"):
        assert f"--{forbidden}" not in output


@pytest.mark.parametrize(
    "namespace",
    ("training-output-direct", "test-results-direct", "training-artifacts-foreign"),
)
def test_preflight_rejects_foreign_output_namespace_without_reservation(
    prepared_fixture,
    monkeypatch,
    namespace,
):
    original = prepared_fixture["verified"]
    output_root = prepared_fixture["repo_root"] / "experiments_output" / namespace
    raw_argv = (
        "--validation-input-dir",
        str(prepared_fixture["input_root"]),
        "--validation-output-dir",
        str(output_root),
        "--attempt-id",
        "validation-attempt-001",
    )
    spec = replace(
        original.spec,
        validation_output_dir=output_root,
        planned_validation_command=(
            str(original.spec.python_executable),
            str((prepared_fixture["repo_root"] / PRODUCTION_VALIDATION_ENTRYPOINT).resolve()),
            *raw_argv,
        ),
    )
    verified = replace(original, spec=spec)
    monkeypatch.setattr(
        validation_cli,
        "verify_validation_freeze_manifest",
        lambda path, *, expected_sha256, repo_root: verified,
    )
    with pytest.raises(ValueError, match="isolated validation directory"):
        validation_cli.prepare_validation_run(
            list(raw_argv),
            repo_root=prepared_fixture["repo_root"],
        )
    assert not output_root.exists()
    assert not (output_root / VALIDATION_ATTEMPT_MARKER_NAME).exists()


def test_directory_swap_is_rejected_before_backend_or_writer_and_cannot_escape(
    prepared_fixture,
    monkeypatch,
):
    verified = prepared_fixture["verified"]
    output_root = prepared_fixture["output_root"]
    outside = prepared_fixture["repo_root"] / "outside-approved-root"
    outside.mkdir()
    calls = {"adapter": 0, "writer": 0}

    class FixtureBackend:
        backend_id = PRODUCTION_VALIDATION_BACKEND_ID
        backend_version = PRODUCTION_VALIDATION_BACKEND_VERSION

        def __init__(self, plan, *, repo_root):
            assert plan is verified.validation_plan

    def reserve(candidate, *, started_at_utc):
        assert candidate is verified
        output_root.mkdir()
        marker = output_root / VALIDATION_ATTEMPT_MARKER_NAME
        marker.write_bytes(canonical_json_bytes({"fixture": "marker"}))
        return marker

    original_marker_check = validation_cli._verify_pinned_marker

    def inject_swap(pin, marker_path):
        original = output_root.with_name("reserved-original")
        try:
            output_root.rename(original)
        except OSError as exc:
            raise RuntimeError("directory swap blocked by the pinned handle") from exc
        output_root.mkdir()
        original_marker_check(pin, marker_path)

    def adapter(*args, **kwargs):
        calls["adapter"] += 1
        return {"fixture": ()}

    def writer(*args, **kwargs):
        calls["writer"] += 1
        raise AssertionError("writer must not be reached after directory swap")

    monkeypatch.setattr(validation_cli, "ProductionValidationExecutionBackend", FixtureBackend)
    monkeypatch.setattr(validation_cli, "reserve_validation_attempt", reserve)
    monkeypatch.setattr(validation_cli, "_verify_pinned_marker", inject_swap)
    monkeypatch.setattr(validation_cli, "run_validation_execution_adapter", adapter)
    monkeypatch.setattr(
        validation_cli,
        "_write_prepared_validation_artifact_bundle",
        writer,
    )
    with pytest.raises(
        (RuntimeError, ValueError),
        match="directory swap blocked|directory identity changed|symlink or reparse point",
    ):
        validation_cli.main(list(prepared_fixture["raw_argv"]))
    if os.name == "nt":
        assert not output_root.with_name("reserved-original").exists()
    assert calls == {"adapter": 0, "writer": 0}
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("completed_file_count", (0, 1))
def test_written_artifact_count_excludes_next_zero_byte_file(tmp_path, completed_file_count):
    artifact_root = tmp_path / "validation"
    artifact_root.mkdir()
    for index in range(completed_file_count):
        (artifact_root / f"completed-{index}.json").write_bytes(
            canonical_json_bytes({"fixture": index})
        )
    next_artifact = artifact_root / "next.json"
    next_artifact.touch()

    written = _written_json_artifacts(artifact_root)
    assert len(written) == completed_file_count
    assert next_artifact not in written


@pytest.mark.parametrize("swap_after_file_count", (0, 1))
def test_final_validation_directory_swap_cannot_escape_or_create_run_manifest(
    prepared_fixture,
    monkeypatch,
    swap_after_file_count,
):
    verified = prepared_fixture["verified"]
    output_root = prepared_fixture["output_root"]
    outside = prepared_fixture["repo_root"] / "outside-final-validation-root"
    outside.mkdir()
    calls = {"adapter": 0, "injection": 0}
    moved = {"path": None}

    class FixtureBackend:
        backend_id = PRODUCTION_VALIDATION_BACKEND_ID
        backend_version = PRODUCTION_VALIDATION_BACKEND_VERSION

        def __init__(self, plan, *, repo_root):
            assert plan is verified.validation_plan

    class FixtureRecord:
        payload = {
            "backend": {
                "backend_id": PRODUCTION_VALIDATION_BACKEND_ID,
                "backend_version": PRODUCTION_VALIDATION_BACKEND_VERSION,
            }
        }

        @staticmethod
        def canonical_payload():
            return {"fixture": "record"}

    records = {
        artifact_type: (FixtureRecord(),) for artifact_type in validation_cli._ARTIFACT_TYPES
    }

    def reserve(candidate, *, started_at_utc):
        assert candidate is verified
        output_root.mkdir()
        marker = output_root / VALIDATION_ATTEMPT_MARKER_NAME
        marker.write_bytes(canonical_json_bytes({"fixture": "marker"}))
        return marker

    def adapter(*args, **kwargs):
        calls["adapter"] += 1
        return records

    original_boundary = validation_cli._verify_validation_write_boundary

    def inject_final_swap(pin, completed_file_count):
        if completed_file_count == swap_after_file_count and calls["injection"] == 0:
            calls["injection"] += 1
            original = pin.path.with_name(f"validation-original-{swap_after_file_count}")
            moved["path"] = original
            try:
                pin.path.rename(original)
            except OSError as exc:
                raise RuntimeError("final directory swap blocked by pinned handle") from exc
            try:
                pin.path.symlink_to(outside, target_is_directory=True)
            except OSError:
                pin.path.mkdir()
        original_boundary(pin, completed_file_count)

    monkeypatch.setattr(validation_cli, "ProductionValidationExecutionBackend", FixtureBackend)
    monkeypatch.setattr(validation_cli, "reserve_validation_attempt", reserve)
    monkeypatch.setattr(
        validation_cli,
        "verify_validation_attempt_marker",
        lambda path, *, verified_freeze: {"fixture": "marker"},
    )
    monkeypatch.setattr(validation_cli, "run_validation_execution_adapter", adapter)
    monkeypatch.setattr(
        validation_cli,
        "verify_validation_execution_records",
        lambda plan, records_by_type, *, repo_root: (SimpleNamespace(candidate_id="fixture"),),
    )
    monkeypatch.setattr(
        validation_cli,
        "_selection_report",
        lambda plan, ranked, aggregate_hash: {"fixture": "selection"},
    )
    monkeypatch.setattr(
        validation_cli,
        "_selected_lock",
        lambda plan, selected, report_hash: {"fixture": "lock"},
    )
    monkeypatch.setattr(
        validation_cli,
        "_verify_validation_write_boundary",
        inject_final_swap,
    )

    with pytest.raises(
        (RuntimeError, ValueError),
        match="final directory swap blocked|identity changed|symlink or reparse point",
    ):
        validation_cli.main(list(prepared_fixture["raw_argv"]))

    assert calls == {"adapter": 1, "injection": 1}
    assert list(outside.iterdir()) == []
    assert not (output_root / PRODUCTION_VALIDATION_RUN_MANIFEST).exists()
    if os.name != "nt":
        written = _written_json_artifacts(moved["path"])
        assert len(written) == swap_after_file_count


def test_pinned_writer_preserves_p6_9a_canonical_bundle_bytes(tmp_path, monkeypatch):
    plan = SimpleNamespace(
        manifest_bytes=canonical_json_bytes({"fixture": "plan"}),
        manifest_sha256="7" * 64,
        manifest={"selection_metric_contract": {"sha256": "8" * 64}},
    )

    class FixtureRecord:
        payload = {
            "backend": {
                "backend_id": PRODUCTION_VALIDATION_BACKEND_ID,
                "backend_version": PRODUCTION_VALIDATION_BACKEND_VERSION,
            }
        }

        @staticmethod
        def canonical_payload():
            return {"fixture": "record"}

    records = {
        artifact_type: (FixtureRecord(),) for artifact_type in validation_cli._ARTIFACT_TYPES
    }
    ranked = (SimpleNamespace(candidate_id="fixture"),)

    def verify_records(plan, records_by_type, *, repo_root):
        return ranked

    def selection_report(plan, ranked, aggregate_hash):
        return {"fixture": "selection"}

    def selected_lock(plan, selected, report_hash):
        return {"fixture": "lock"}

    monkeypatch.setattr(
        validation_execution,
        "verify_validation_execution_records",
        verify_records,
    )
    monkeypatch.setattr(validation_execution, "_selection_report", selection_report)
    monkeypatch.setattr(validation_execution, "_selected_lock", selected_lock)
    monkeypatch.setattr(
        validation_execution,
        "verify_validation_artifact_root",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(validation_cli, "verify_validation_execution_records", verify_records)
    monkeypatch.setattr(validation_cli, "_selection_report", selection_report)
    monkeypatch.setattr(validation_cli, "_selected_lock", selected_lock)
    monkeypatch.setattr(
        validation_cli,
        "verify_validation_artifact_root",
        lambda *args, **kwargs: None,
    )

    baseline_parent = tmp_path / "baseline" / "validation-artifacts"
    baseline_parent.mkdir(parents=True)
    baseline = validation_execution.write_validation_artifact_bundle(
        plan,
        records,
        baseline_parent / "validation",
        repo_root=tmp_path,
    )
    pinned_parent = tmp_path / "pinned" / "validation-artifacts"
    pinned_parent.mkdir(parents=True)
    with (
        validation_cli._PinnedDirectory(pinned_parent) as parent_pin,
        parent_pin.mkdir_pinned("validation") as validation_pin,
    ):
        pinned = validation_cli._write_validation_artifact_bundle_pinned(
            plan,
            records,
            validation_pin,
            repo_root=tmp_path,
        )

    baseline_files = {
        path.name: path.read_bytes() for path in baseline.root.iterdir() if path.is_file()
    }
    pinned_files = {
        path.name: path.read_bytes() for path in pinned.root.iterdir() if path.is_file()
    }
    assert pinned_files == baseline_files
    assert pinned.root_manifest_sha256 == baseline.root_manifest_sha256


def test_tmp_run_writes_and_independently_verifies_provenance(
    prepared_fixture,
    monkeypatch,
):
    verified = prepared_fixture["verified"]
    output_root = prepared_fixture["output_root"]

    class FixtureBackend:
        backend_id = PRODUCTION_VALIDATION_BACKEND_ID
        backend_version = PRODUCTION_VALIDATION_BACKEND_VERSION

        def __init__(self, plan, *, repo_root):
            assert plan is verified.validation_plan

    def reserve(candidate, *, started_at_utc):
        assert candidate is verified
        output_root.mkdir()
        marker_path = output_root / VALIDATION_ATTEMPT_MARKER_NAME
        marker_path.write_bytes(canonical_json_bytes({"fixture": "marker"}))
        return marker_path

    def prepare_bundle(plan, records, *, repo_root):
        assert plan is verified.validation_plan
        assert records == {"fixture": ()}
        return {"fixture": "prepared"}

    def write_bundle(validation_pin, prepared_bundle, *, repo_root):
        assert prepared_bundle == {"fixture": "prepared"}
        root_payload = {
            "backend": {
                "backend_id": PRODUCTION_VALIDATION_BACKEND_ID,
                "backend_version": PRODUCTION_VALIDATION_BACKEND_VERSION,
            }
        }
        root_path = validation_pin.write_exclusive(
            "validation_result_root.json",
            canonical_json_bytes(root_payload),
        )
        return ValidationArtifactBundle(
            validation_pin.path,
            root_path,
            sha256_bytes(canonical_json_bytes(root_payload)),
        )

    monkeypatch.setattr(validation_cli, "ProductionValidationExecutionBackend", FixtureBackend)
    monkeypatch.setattr(
        validation_cli,
        "run_validation_execution_adapter",
        lambda plan, backend, *, repo_root: {"fixture": ()},
    )
    monkeypatch.setattr(
        validation_cli,
        "_prepare_validation_artifact_bundle",
        prepare_bundle,
    )
    monkeypatch.setattr(
        validation_cli,
        "_write_prepared_validation_artifact_bundle",
        write_bundle,
    )
    monkeypatch.setattr(validation_cli, "reserve_validation_attempt", reserve)
    monkeypatch.setattr(
        validation_cli,
        "verify_validation_attempt_marker",
        lambda path, *, verified_freeze: {"fixture": "marker"},
    )
    monkeypatch.setattr(
        validation_cli,
        "verify_validation_artifact_root",
        lambda path, *, expected_sha256, repo_root: {
            "backend": {
                "backend_id": PRODUCTION_VALIDATION_BACKEND_ID,
                "backend_version": PRODUCTION_VALIDATION_BACKEND_VERSION,
            }
        },
    )

    assert validation_cli.main(list(prepared_fixture["raw_argv"])) == 0
    run_path = output_root / PRODUCTION_VALIDATION_RUN_MANIFEST
    payload = validation_cli.verify_validation_run_manifest(
        run_path,
        repo_root=prepared_fixture["repo_root"],
    )
    assert payload["status"] == "completed_and_verified"
    assert payload["invocation"]["argv"] == list(prepared_fixture["raw_argv"])
    assert payload["attempt"]["attempt_number"] == 1
    assert payload["outputs"]["validation_result_root"]["path"] == (
        "validation-artifacts/validation/validation_result_root.json"
    )
    assert any(
        item["name"] == PRODUCTION_VALIDATION_BACKEND_ID
        and item["version"] == PRODUCTION_VALIDATION_BACKEND_VERSION
        for item in payload["components"]
    )
    component_names = {item["name"] for item in payload["components"]}
    assert {
        "approved_validation_opponent_artifacts",
        "baseline_table",
        "calibration_evaluator",
        "canonicalizer",
        "dpl_schema",
        "estimator_config_index",
        "exact_ev_evaluator",
        "exploit_provider",
        "frozen_equilibrium_artifact",
        "frozen_validation_game",
        "ground_truth_extractor",
        "observation_registry",
        "reason_ontology",
        "safety_mixer",
        "verified_sampling_contract",
    } <= component_names

    original = run_path.read_bytes()
    mutations = []
    missing = deepcopy(payload)
    missing["components"].pop()
    mutations.append(missing)
    added = deepcopy(payload)
    added["components"].append(
        {"name": "foreign_component", "version": "v1", "content_sha256": "f" * 64}
    )
    mutations.append(added)
    replaced_version = deepcopy(payload)
    replaced_version["components"][0]["version"] = "foreign-v1"
    mutations.append(replaced_version)
    replaced_hash = deepcopy(payload)
    replaced_hash["components"][0]["content_sha256"] = "e" * 64
    mutations.append(replaced_hash)
    for mutation in mutations:
        run_path.write_bytes(canonical_json_bytes(mutation))
        with pytest.raises(ValueError, match="provenance does not reconstruct"):
            validation_cli.verify_validation_run_manifest(
                run_path,
                repo_root=prepared_fixture["repo_root"],
            )
    run_path.write_bytes(original)


def test_saved_run_rejects_nonproduction_backend(prepared_fixture, monkeypatch):
    output_root = prepared_fixture["output_root"]
    output_root.mkdir()
    marker = output_root / VALIDATION_ATTEMPT_MARKER_NAME
    marker.write_bytes(canonical_json_bytes({"fixture": "marker"}))
    result_root = output_root / "validation-artifacts" / "validation"
    result_root.mkdir(parents=True)
    root_path = result_root / "validation_result_root.json"
    root_path.write_bytes(canonical_json_bytes({"fixture": "root"}))
    prepared = validation_cli.prepare_validation_run(
        list(prepared_fixture["raw_argv"]),
        repo_root=prepared_fixture["repo_root"],
        allow_existing_output=True,
    )
    payload = validation_cli._run_manifest_payload(
        prepared,
        marker_path=marker,
        result_root_path=root_path,
        result_root_sha256=sha256_bytes(root_path.read_bytes()),
        started_at=validation_cli.datetime.now(validation_cli.UTC),
        finished_at=validation_cli.datetime.now(validation_cli.UTC),
    )
    run_path = output_root / PRODUCTION_VALIDATION_RUN_MANIFEST
    run_path.write_bytes(canonical_json_bytes(payload))
    monkeypatch.setattr(
        validation_cli,
        "verify_validation_attempt_marker",
        lambda path, *, verified_freeze: {"fixture": "marker"},
    )
    monkeypatch.setattr(
        validation_cli,
        "verify_validation_artifact_root",
        lambda path, *, expected_sha256, repo_root: {
            "backend": {
                "backend_id": "phase6-validation-fixture",
                "backend_version": "p6-9a-validation-fixture-v1",
            }
        },
    )
    with pytest.raises(ValueError, match="production backend"):
        validation_cli.verify_validation_run_manifest(
            run_path,
            repo_root=prepared_fixture["repo_root"],
        )


def test_concrete_backend_runs_deterministic_validation_session(monkeypatch, tmp_path):
    configs = tuple(sorted(load_validation_catalog(), key=lambda item: item.opponent_id))
    sampling = _sampling_reference(configs)
    opponents = {
        item.config.opponent_id: item
        for item in (synthesize_opponent(config=config) for config in configs)
    }
    candidate = primary_candidate_grid(sampling_contract_sha256=sampling["sha256"])[0]
    opponent_id = configs[0].opponent_id
    key = ValidationSessionKey(candidate.candidate_id, opponent_id, 10, "r001")
    plan = ValidationBatchPlan(
        {"fixture": "plan", "sampling_contract": sampling},
        canonical_json_bytes({"fixture": "plan"}),
        "5" * 64,
        (candidate,),
        (key,),
    )
    context = SimpleNamespace(
        opponents=opponents,
        dimension={
            "action_group": ["BET", "BET_ALL_IN", "BET_33", "BET_75", "RAISE_ALL_IN"],
            "baseline_rate": "0.5",
        },
    )
    monkeypatch.setattr(validation_backend, "verify_validation_batch_plan", lambda *a, **k: None)
    monkeypatch.setattr(validation_backend, "_evaluation_context", lambda *a, **k: context)
    monkeypatch.setattr(validation_backend, "HORIZONS", (10,))
    backend = validation_backend.ProductionValidationExecutionBackend(
        plan,
        repo_root=tmp_path,
    )
    roots = tuple(
        derive_stream_root(
            split="validation",
            opponent_id=opponent_id,
            horizon=10,
            repetition_id="r001",
            stream_name=stream_name,
        )
        for stream_name in STREAM_NAMES
    )
    request = ValidationSessionRequest(key, candidate, configs[0], roots)
    first = tuple(backend.run_sessions((request,)))
    second = tuple(backend.run_sessions((request,)))
    assert first == second
    terminal = first[0].terminal_candidate_snapshot
    assert terminal["session"] == key.canonical_payload()
    assert sum(terminal["action_counts"].values()) == 10
    assert first[0].hero_policy_snapshot["opponent_id"] == opponent_id
    assert first[0].exact_ev_cell["source_hero_policy_sha256"] == sha256_bytes(
        canonical_json_bytes(first[0].hero_policy_snapshot)
    )

    monkeypatch.setattr(
        validation_backend,
        "_candidate_products",
        lambda plan, request, context: ({"fixture": "calibration"}, {"fixture": "aggregate"}, None),
    )
    candidate_result = backend.evaluate_candidates(
        (
            ValidationCandidateRequest(
                candidate,
                first,
                "6" * 64,
            ),
        )
    )[0]
    assert candidate_result.split == "validation"
    assert candidate_result.calibration_cell == {"fixture": "calibration"}


def test_concrete_backend_rejects_training_stream_root(monkeypatch, tmp_path):
    configs = tuple(sorted(load_validation_catalog(), key=lambda item: item.opponent_id))
    sampling = _sampling_reference(configs)
    opponents = {
        item.config.opponent_id: item
        for item in (synthesize_opponent(config=config) for config in configs)
    }
    candidate = primary_candidate_grid(sampling_contract_sha256=sampling["sha256"])[0]
    opponent_id = configs[0].opponent_id
    key = ValidationSessionKey(candidate.candidate_id, opponent_id, 10, "r001")
    plan = ValidationBatchPlan(
        {"fixture": "plan", "sampling_contract": sampling},
        canonical_json_bytes({"fixture": "plan"}),
        "8" * 64,
        (candidate,),
        (key,),
    )
    monkeypatch.setattr(validation_backend, "verify_validation_batch_plan", lambda *a, **k: None)
    monkeypatch.setattr(
        validation_backend,
        "_evaluation_context",
        lambda *a, **k: SimpleNamespace(
            opponents=opponents,
            dimension={"action_group": ["BET"], "baseline_rate": "0.5"},
        ),
    )
    monkeypatch.setattr(validation_backend, "HORIZONS", (10,))
    backend = validation_backend.ProductionValidationExecutionBackend(plan, repo_root=tmp_path)
    training_roots = tuple(
        derive_stream_root(
            split="training",
            opponent_id=opponent_id,
            horizon=10,
            repetition_id="r001",
            stream_name=stream_name,
        )
        for stream_name in STREAM_NAMES
    )
    request = ValidationSessionRequest(key, candidate, configs[0], training_roots)
    with pytest.raises(ValueError, match="stream roots"):
        backend.run_sessions((request,))


def test_concrete_backend_rejects_foreign_observation_registry_before_sessions(
    monkeypatch,
    tmp_path,
):
    configs = tuple(sorted(load_validation_catalog(), key=lambda item: item.opponent_id))
    sampling = _sampling_reference(configs)
    opponents = {
        item.config.opponent_id: item
        for item in (synthesize_opponent(config=config) for config in configs)
    }
    candidate = primary_candidate_grid(sampling_contract_sha256=sampling["sha256"])[0]
    plan = ValidationBatchPlan(
        {"fixture": "plan", "sampling_contract": sampling},
        canonical_json_bytes({"fixture": "plan"}),
        "9" * 64,
        (candidate,),
        (),
    )
    real_registry = build_production_observation_registry(next(iter(opponents.values())).game)
    foreign_registry = replace(real_registry, registry_version="foreign-registry-v1")
    monkeypatch.setattr(validation_backend, "verify_validation_batch_plan", lambda *a, **k: None)
    monkeypatch.setattr(
        validation_backend,
        "_evaluation_context",
        lambda *a, **k: SimpleNamespace(
            opponents=opponents,
            dimension={"action_group": ["BET"], "baseline_rate": "0.5"},
        ),
    )
    monkeypatch.setattr(
        validation_backend,
        "build_production_observation_registry",
        lambda game: foreign_registry,
    )
    with pytest.raises(ValueError, match="differs from the verified sampling contract"):
        validation_backend.ProductionValidationExecutionBackend(plan, repo_root=tmp_path)
