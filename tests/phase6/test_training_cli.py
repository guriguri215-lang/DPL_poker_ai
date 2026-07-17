"""Unit/tmp regression for the fail-closed P6-7 production Training CLI."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import phase6.training_cli as training_cli
from phase6 import canonical_json_bytes, sampling_contract_payload, sha256_bytes
from phase6.training_runner import TrainingArtifactBundle

EXPECTED_COMMIT = "a6b0fa28aeefce3d80521cbafa010392e14a5630"


def _sampling_contract():
    return sampling_contract_payload(
        observation_registry_version="fixture-registry-v1",
        observation_registry_sha256=sha256_bytes(b"fixture-registry\n"),
    )


def _write_fixture_bundle(plan, output_root: Path) -> TrainingArtifactBundle:
    backend = {
        "backend_id": training_cli.PRODUCTION_TRAINING_BACKEND_ID,
        "backend_version": training_cli.PRODUCTION_TRAINING_BACKEND_VERSION,
    }
    raw_by_name = {
        "training_batch_manifest": plan.manifest_bytes,
        **{
            name: canonical_json_bytes(
                {
                    "schema_version": "fixture-artifact-v1",
                    "artifact_type": name,
                    "training_batch_manifest_sha256": plan.manifest_sha256,
                    "records": [
                        {
                            "candidate_id": "fixture-candidate",
                            "horizon": None,
                            "opponent_id": None,
                            "payload": {
                                "artifact_type": name,
                                "backend": backend,
                                "training_batch_manifest_sha256": plan.manifest_sha256,
                            },
                            "payload_sha256": sha256_bytes(
                                canonical_json_bytes(
                                    {
                                        "artifact_type": name,
                                        "backend": backend,
                                        "training_batch_manifest_sha256": plan.manifest_sha256,
                                    }
                                )
                            ),
                            "repetition_id": None,
                        }
                    ],
                }
            )
            for name in training_cli._BUNDLE_OUTPUT_NAMES
            if name not in {"training_batch_manifest", "training_selection_report"}
        },
        "training_selection_report": canonical_json_bytes(
            {
                "fixture": "training_selection_report",
                "training_batch_manifest_sha256": plan.manifest_sha256,
            }
        ),
    }
    references = {}
    for name, raw in raw_by_name.items():
        path = output_root / f"{name}.json"
        path.write_bytes(raw)
        references[name] = {
            "name": name,
            "path": path.name,
            "sha256": sha256_bytes(raw),
        }
    return TrainingArtifactBundle(output_root.resolve(), references)


def _rewrite_output(payload, output_root: Path, name: str, artifact: object) -> None:
    raw = canonical_json_bytes(artifact)
    path = output_root / payload["outputs"][name]["path"]
    path.write_bytes(raw)
    payload["outputs"][name]["sha256"] = sha256_bytes(raw)


@pytest.fixture
def cli_fixture(tmp_path, monkeypatch):
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    contract_path = repo_root / "phase6_contract_manifest.json"
    contract_path.write_bytes(canonical_json_bytes({"fixture": "phase6-contract"}))
    lock_path = repo_root / "dependency.lock"
    lock_path.write_bytes(b"fixture-package==1.0 --hash=sha256:fixture\n")
    output_root = tmp_path / "training-output"
    sampling = _sampling_contract()
    calls = []

    monkeypatch.setattr(training_cli, "REPO_ROOT", repo_root)
    monkeypatch.setattr(
        training_cli,
        "_read_repository_state",
        lambda _root: training_cli.RepositoryState(EXPECTED_COMMIT, False),
    )
    monkeypatch.setattr(training_cli, "load_phase6_contract_bundle", lambda *args, **kwargs: {})
    monkeypatch.setattr(training_cli, "_approved_sampling_contract", lambda: sampling)

    class FakeBackend:
        def __init__(self, *, contract_bundle, sampling_contract):
            calls.append(("backend", contract_bundle, sampling_contract))

    monkeypatch.setattr(training_cli, "ProductionTrainingExecutionBackend", FakeBackend)

    def fake_run(plan, backend):
        calls.append(("run", plan, backend))
        return {"fixture": ()}

    def fake_write(plan, records, root):
        calls.append(("write", plan, records, root))
        return _write_fixture_bundle(plan, root)

    def fake_verify(bundle):
        calls.append(("verify", bundle))

    monkeypatch.setattr(training_cli, "run_training_execution_adapter", fake_run)
    monkeypatch.setattr(training_cli, "write_training_artifact_bundle", fake_write)
    monkeypatch.setattr(training_cli, "verify_training_artifact_bundle", fake_verify)
    monkeypatch.setattr(
        training_cli,
        "_runtime_payload",
        lambda: {
            "python_implementation": "FixturePython",
            "python_version": "3.12.0",
            "python_compiler": "fixture-compiler",
            "platform": "fixture-platform",
            "system": "FixtureOS",
            "release": "1",
            "version": "1.0",
            "machine": "fixture-machine",
        },
    )
    times = iter(
        (
            datetime(2026, 7, 16, 1, 2, 3, tzinfo=UTC),
            datetime(2026, 7, 16, 1, 2, 4, tzinfo=UTC),
        )
    )
    monkeypatch.setattr(training_cli, "_utc_now", lambda: next(times))

    argv = [
        "--expected-commit",
        EXPECTED_COMMIT,
        "--phase6-contract-manifest",
        contract_path.name,
        "--phase6-contract-manifest-sha256",
        sha256_bytes(contract_path.read_bytes()),
        "--dependency-lock",
        lock_path.name,
        "--dependency-lock-sha256",
        sha256_bytes(lock_path.read_bytes()),
        "--output-dir",
        str(output_root),
    ]
    return {
        "repo_root": repo_root,
        "contract_path": contract_path,
        "lock_path": lock_path,
        "output_root": output_root,
        "sampling": sampling,
        "argv": argv,
        "calls": calls,
    }


def test_cli_orchestrates_only_the_approved_training_product(cli_fixture):
    assert training_cli.main(cli_fixture["argv"]) == 0

    manifest_path = cli_fixture["output_root"] / training_cli.PRODUCTION_TRAINING_RUN_MANIFEST
    raw = manifest_path.read_bytes()
    payload = json.loads(raw)
    assert raw == canonical_json_bytes(payload)
    assert payload["split"] == "training"
    assert payload["git"] == {
        "actual_commit": EXPECTED_COMMIT,
        "dirty": False,
        "expected_commit": EXPECTED_COMMIT,
    }
    assert payload["invocation"] == {
        "entrypoint": "cli/phase6_training_v1.py",
        "argv": cli_fixture["argv"],
    }
    assert payload["approved_plan"]["expected_cardinality"]["session_count"] == 12960
    assert payload["approved_plan"]["horizons"] == [50, 200, 1000]
    assert len(payload["approved_plan"]["repetitions"]) == 30
    assert payload["approved_plan"]["performance_based_top_n"] is None
    assert payload["inputs"]["sampling_contract"]["payload"] == cli_fixture["sampling"]
    assert set(payload["outputs"]) == training_cli._BUNDLE_OUTPUT_NAMES
    assert [item[0] for item in cli_fixture["calls"][:4]] == [
        "backend",
        "run",
        "write",
        "verify",
    ]
    training_cli.verify_training_run_manifest(
        manifest_path,
        repo_root=cli_fixture["repo_root"],
    )


@pytest.mark.parametrize(
    "forbidden_option",
    [
        "--candidate",
        "--opponent",
        "--horizon",
        "--repetition",
        "--seed",
        "--sampling",
        "--metric",
        "--selection",
    ],
)
def test_cli_exposes_no_experiment_axis_options(cli_fixture, forbidden_option):
    with pytest.raises(SystemExit):
        training_cli.main([*cli_fixture["argv"], forbidden_option, "changed"])
    assert not cli_fixture["calls"]
    assert not cli_fixture["output_root"].exists()


@pytest.mark.parametrize(
    ("state", "message"),
    [
        (training_cli.RepositoryState("0" * 40, False), "expected-commit"),
        (training_cli.RepositoryState(EXPECTED_COMMIT, True), "dirty=false"),
    ],
)
def test_cli_rejects_repository_state_before_backend(
    cli_fixture,
    monkeypatch,
    state,
    message,
):
    monkeypatch.setattr(training_cli, "_read_repository_state", lambda _root: state)
    with pytest.raises(RuntimeError, match=message):
        training_cli.main(cli_fixture["argv"])
    assert not cli_fixture["calls"]
    assert not cli_fixture["output_root"].exists()


def test_cli_rejects_nonfresh_output_before_backend(cli_fixture):
    cli_fixture["output_root"].mkdir()
    with pytest.raises(FileExistsError, match="fresh"):
        training_cli.main(cli_fixture["argv"])
    assert not cli_fixture["calls"]


@pytest.mark.parametrize("input_name", ["contract_path", "lock_path"])
def test_cli_rejects_input_hash_mismatch_before_backend(cli_fixture, input_name):
    cli_fixture[input_name].write_bytes(b"tampered\n")
    with pytest.raises(ValueError, match="hash"):
        training_cli.main(cli_fixture["argv"])
    assert not cli_fixture["calls"]
    assert not cli_fixture["output_root"].exists()


def test_cli_rejects_nontraining_plan_before_backend(cli_fixture, monkeypatch):
    original = training_cli.build_training_batch_plan

    def validation_plan(contract):
        plan = original(contract)
        manifest = {**plan.manifest, "split": "validation"}
        raw = canonical_json_bytes(manifest)
        return replace(
            plan, manifest=manifest, manifest_bytes=raw, manifest_sha256=sha256_bytes(raw)
        )

    monkeypatch.setattr(training_cli, "build_training_batch_plan", validation_plan)
    with pytest.raises(ValueError, match="approved inputs|approved 12,960"):
        training_cli.main(cli_fixture["argv"])
    assert not cli_fixture["calls"]
    assert not cli_fixture["output_root"].exists()


def test_cli_rechecks_repository_after_reserving_output(cli_fixture, monkeypatch):
    states = iter(
        (
            training_cli.RepositoryState(EXPECTED_COMMIT, False),
            training_cli.RepositoryState(EXPECTED_COMMIT, True),
        )
    )
    monkeypatch.setattr(training_cli, "_read_repository_state", lambda _root: next(states))
    with pytest.raises(RuntimeError, match="dirty=false"):
        training_cli.main(cli_fixture["argv"])
    assert [item[0] for item in cli_fixture["calls"]] == ["backend"]
    assert not cli_fixture["output_root"].exists()


def test_run_manifest_verifier_rejects_output_hash_tampering(cli_fixture):
    training_cli.main(cli_fixture["argv"])
    manifest_path = cli_fixture["output_root"] / training_cli.PRODUCTION_TRAINING_RUN_MANIFEST
    (cli_fixture["output_root"] / "aggregate_metrics.json").write_bytes(b"tampered\n")
    with pytest.raises(ValueError, match="output hash"):
        training_cli.verify_training_run_manifest(
            manifest_path,
            repo_root=cli_fixture["repo_root"],
        )


def test_run_manifest_verifier_rejects_provenance_rehash(cli_fixture):
    training_cli.main(cli_fixture["argv"])
    manifest_path = cli_fixture["output_root"] / training_cli.PRODUCTION_TRAINING_RUN_MANIFEST
    payload = json.loads(manifest_path.read_bytes())
    payload["git"]["expected_commit"] = "1" * 40
    manifest_path.write_bytes(canonical_json_bytes(payload))
    with pytest.raises(ValueError, match="clean and commit-pinned"):
        training_cli.verify_training_run_manifest(
            manifest_path,
            repo_root=cli_fixture["repo_root"],
        )


def test_run_manifest_verifier_rejects_argv_provenance_substitution(cli_fixture):
    training_cli.main(cli_fixture["argv"])
    manifest_path = cli_fixture["output_root"] / training_cli.PRODUCTION_TRAINING_RUN_MANIFEST
    payload = json.loads(manifest_path.read_bytes())
    output_index = payload["invocation"]["argv"].index("--output-dir") + 1
    payload["invocation"]["argv"][output_index] = str(cli_fixture["output_root"] / "other")
    manifest_path.write_bytes(canonical_json_bytes(payload))
    with pytest.raises(ValueError, match="argv does not join"):
        training_cli.verify_training_run_manifest(
            manifest_path,
            repo_root=cli_fixture["repo_root"],
        )


def test_run_manifest_verifier_rejects_inverted_timing(cli_fixture):
    training_cli.main(cli_fixture["argv"])
    manifest_path = cli_fixture["output_root"] / training_cli.PRODUCTION_TRAINING_RUN_MANIFEST
    payload = json.loads(manifest_path.read_bytes())
    start = datetime.fromisoformat(payload["timing"]["started_at_utc"].replace("Z", "+00:00"))
    payload["timing"]["finished_at_utc"] = (
        (start - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    )
    manifest_path.write_bytes(canonical_json_bytes(payload))
    with pytest.raises(ValueError, match="finished before"):
        training_cli.verify_training_run_manifest(
            manifest_path,
            repo_root=cli_fixture["repo_root"],
        )


def test_run_manifest_verifier_rejects_foreign_registry_after_full_rehash(cli_fixture):
    training_cli.main(cli_fixture["argv"])
    output_root = cli_fixture["output_root"]
    manifest_path = output_root / training_cli.PRODUCTION_TRAINING_RUN_MANIFEST
    payload = json.loads(manifest_path.read_bytes())
    foreign_sampling = sampling_contract_payload(
        observation_registry_version="foreign-registry-v1",
        observation_registry_sha256="0" * 64,
    )
    foreign_plan = training_cli.build_training_batch_plan(foreign_sampling)
    foreign_sampling_sha256 = sha256_bytes(canonical_json_bytes(foreign_sampling))
    payload["inputs"]["sampling_contract"] = {
        "payload": foreign_sampling,
        "sha256": foreign_sampling_sha256,
    }
    payload["inputs"]["training_batch_manifest_sha256"] = foreign_plan.manifest_sha256
    payload["components"] = training_cli._component_provenance(
        foreign_plan,
        contract_manifest_sha256=payload["inputs"]["phase6_contract_manifest"]["sha256"],
    )
    _rewrite_output(
        payload,
        output_root,
        "training_batch_manifest",
        foreign_plan.manifest,
    )
    for name in (
        "terminal_candidate_snapshots",
        "hero_policy_snapshots",
        "exact_ev_cells",
        "calibration_cells",
        "aggregate_metrics",
    ):
        artifact_path = output_root / payload["outputs"][name]["path"]
        artifact = json.loads(artifact_path.read_bytes())
        artifact["training_batch_manifest_sha256"] = foreign_plan.manifest_sha256
        for record in artifact["records"]:
            record["payload"]["training_batch_manifest_sha256"] = foreign_plan.manifest_sha256
            record["payload_sha256"] = sha256_bytes(canonical_json_bytes(record["payload"]))
        _rewrite_output(payload, output_root, name, artifact)
    selection_path = output_root / payload["outputs"]["training_selection_report"]["path"]
    selection = json.loads(selection_path.read_bytes())
    selection["training_batch_manifest_sha256"] = foreign_plan.manifest_sha256
    _rewrite_output(payload, output_root, "training_selection_report", selection)
    manifest_path.write_bytes(canonical_json_bytes(payload))

    with pytest.raises(ValueError, match="independently reconstructed approved registry"):
        training_cli.verify_training_run_manifest(
            manifest_path,
            repo_root=cli_fixture["repo_root"],
        )


def test_run_manifest_verifier_rejects_foreign_backend_after_all_record_rehashes(
    cli_fixture,
):
    training_cli.main(cli_fixture["argv"])
    output_root = cli_fixture["output_root"]
    manifest_path = output_root / training_cli.PRODUCTION_TRAINING_RUN_MANIFEST
    payload = json.loads(manifest_path.read_bytes())
    foreign_backend = {"backend_id": "foreign-backend", "backend_version": "foreign-v1"}
    for name in (
        "terminal_candidate_snapshots",
        "hero_policy_snapshots",
        "exact_ev_cells",
        "calibration_cells",
        "aggregate_metrics",
    ):
        artifact_path = output_root / payload["outputs"][name]["path"]
        artifact = json.loads(artifact_path.read_bytes())
        for record in artifact["records"]:
            record["payload"]["backend"] = foreign_backend
            record["payload_sha256"] = sha256_bytes(canonical_json_bytes(record["payload"]))
        _rewrite_output(payload, output_root, name, artifact)
    manifest_path.write_bytes(canonical_json_bytes(payload))

    with pytest.raises(ValueError, match="backend identity is not the production backend"):
        training_cli.verify_training_run_manifest(
            manifest_path,
            repo_root=cli_fixture["repo_root"],
        )


_MANDATORY_CONTENT_COMPONENTS = (
    "frozen_training_game",
    "frozen_equilibrium_artifact",
    "approved_opponent_artifacts",
    "baseline_table",
    "estimator_config_index",
    "safety_mixer",
    "exact_ev_evaluator",
)


@pytest.mark.parametrize("component_name", _MANDATORY_CONTENT_COMPONENTS)
@pytest.mark.parametrize("mutation", ["missing", "changed", "foreign_rehash"])
def test_run_manifest_verifier_rejects_mandatory_component_mutation(
    cli_fixture,
    component_name,
    mutation,
):
    training_cli.main(cli_fixture["argv"])
    manifest_path = cli_fixture["output_root"] / training_cli.PRODUCTION_TRAINING_RUN_MANIFEST
    payload = json.loads(manifest_path.read_bytes())
    component = next(item for item in payload["components"] if item["name"] == component_name)
    if mutation == "missing":
        payload["components"].remove(component)
    elif mutation == "changed":
        component["version"] = f"{component['version']}-changed"
    else:
        component["sha256"] = sha256_bytes(
            canonical_json_bytes({"foreign_component_content": component_name})
        )
    manifest_path.write_bytes(canonical_json_bytes(payload))

    with pytest.raises(ValueError, match="component provenance"):
        training_cli.verify_training_run_manifest(
            manifest_path,
            repo_root=cli_fixture["repo_root"],
        )
