"""Unit/tmp fixtures for the repo-only P6-8A Validation plan boundary."""

from __future__ import annotations

import copy
import json
import shutil
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import phase6.validation_runner as validation_runner
from phase6 import (
    COMPONENT_ROLES,
    VALIDATION_BATCH_SCHEMA_VERSION,
    ComponentCoverageResult,
    CoverageEvaluation,
    ValidationBatchPlan,
    build_validation_batch_plan,
    canonical_json_bytes,
    primary_candidate_grid,
    sampling_contract_payload,
    sha256_bytes,
    verify_validation_batch_plan,
)


def _coverage_evaluation() -> CoverageEvaluation:
    return CoverageEvaluation(
        component_results=tuple(
            ComponentCoverageResult(role, "c" * 64, True, ()) for role in COMPONENT_ROLES
        ),
        matrix_matches_reconstruction=True,
        end_to_end_coverage=True,
    )


@pytest.fixture
def training_source(tmp_path, monkeypatch):
    repo_root = tmp_path / "repo"
    input_root = repo_root / "inputs"
    output_root = repo_root / "training-output"
    input_root.mkdir(parents=True)
    output_root.mkdir(parents=True)
    contract_path = input_root / "phase6-evaluation-manifest.json"
    dependency_path = input_root / "dependency-lock.json"
    contract_path.write_bytes(b"{}\n")
    dependency_path.write_bytes(b"{}\n")

    sampling = sampling_contract_payload(
        observation_registry_version="fixture-observation-registry-v1",
        observation_registry_sha256="a" * 64,
    )
    sampling_hash = sha256_bytes(canonical_json_bytes(sampling))
    candidate_ids = [
        candidate.candidate_id
        for candidate in primary_candidate_grid(sampling_contract_sha256=sampling_hash)
    ]
    training_batch_hash = "b" * 64
    selection = {
        "schema_version": "phase6-training-selection-report-v1",
        "artifact_type": "training_selection_report",
        "training_batch_manifest_sha256": training_batch_hash,
        "selection_policy": "retain_all_hard_gate_passing_candidates",
        "performance_based_top_n": None,
        "input_candidate_ids": candidate_ids,
        "retained_candidate_ids": candidate_ids,
        "excluded_candidates": [],
        "p6_8_candidate_count": 16,
    }
    selection_path = output_root / "training_selection_report.json"
    selection_path.write_bytes(canonical_json_bytes(selection))
    selection_hash = sha256_bytes(selection_path.read_bytes())
    run_payload = {
        "git": {
            "expected_commit": "1" * 40,
            "actual_commit": "1" * 40,
            "dirty": False,
        },
        "inputs": {
            "phase6_contract_manifest": {
                "path": contract_path.relative_to(repo_root).as_posix(),
                "sha256": sha256_bytes(contract_path.read_bytes()),
            },
            "dependency_lock": {
                "path": dependency_path.relative_to(repo_root).as_posix(),
                "sha256": sha256_bytes(dependency_path.read_bytes()),
            },
            "sampling_contract": {"payload": sampling, "sha256": sampling_hash},
            "training_batch_manifest_sha256": training_batch_hash,
        },
        "outputs": {
            "training_selection_report": {
                "name": "training_selection_report",
                "path": selection_path.name,
                "sha256": selection_hash,
            }
        },
    }
    run_path = output_root / "phase6_training_run_manifest.json"
    run_path.write_bytes(canonical_json_bytes(run_payload))

    calls = {"training_verifier": 0, "contract_loader": 0}

    def verified_manifest(path, *, repo_root):
        calls["training_verifier"] += 1
        raw = Path(path).read_bytes()
        return json.loads(raw)

    def loaded_contract(path, *, expected_sha256):
        calls["contract_loader"] += 1
        assert Path(path).resolve() == contract_path.resolve()
        assert expected_sha256 == sha256_bytes(contract_path.read_bytes())
        return SimpleNamespace(coverage_evaluation=_coverage_evaluation())

    monkeypatch.setattr(validation_runner, "verify_training_run_manifest", verified_manifest)
    monkeypatch.setattr(validation_runner, "load_phase6_contract_bundle", loaded_contract)
    return {
        "repo_root": repo_root,
        "run_path": run_path,
        "run_sha256": sha256_bytes(run_path.read_bytes()),
        "selection_path": selection_path,
        "calls": calls,
    }


def _build(source) -> ValidationBatchPlan:
    return build_validation_batch_plan(
        source["run_path"],
        expected_training_run_manifest_sha256=source["run_sha256"],
        repo_root=source["repo_root"],
    )


def _replace_manifest(plan: ValidationBatchPlan, manifest: dict[str, Any]) -> ValidationBatchPlan:
    raw = canonical_json_bytes(manifest)
    return replace(
        plan,
        manifest=manifest,
        manifest_bytes=raw,
        manifest_sha256=sha256_bytes(raw),
    )


def test_validation_plan_is_complete_read_only_and_independently_verified(
    training_source, monkeypatch
):
    before = sorted(
        path.relative_to(training_source["repo_root"])
        for path in training_source["repo_root"].rglob("*")
    )
    plan = _build(training_source)

    assert plan.manifest["schema_version"] == VALIDATION_BATCH_SCHEMA_VERSION
    assert plan.manifest["split"] == "validation"
    assert plan.manifest["expected_cardinality"] == {
        "candidate_count": 16,
        "opponent_count": 9,
        "horizon_count": 3,
        "repetition_count": 30,
        "session_count": 12960,
        "stream_root_count": 3240,
    }
    assert len(plan.candidates) == 16
    assert len(plan.sessions) == 12960
    assert len(plan.manifest["stream_roots"]) == 3240
    assert all(root["payload"]["split"] == "validation" for root in plan.manifest["stream_roots"])
    catalog = plan.manifest["validation_catalog_index"]
    assert len(catalog["opponents"]) == 9
    assert [item["control_role"] for item in catalog["opponents"]].count(
        "gto_negative_control"
    ) == 1
    assert plan.manifest["series"]["split"] == "validation"
    assert plan.manifest["training_source"]["git"]["dirty"] is False

    expected_catalog = copy.deepcopy(catalog["opponents"])
    monkeypatch.setattr(
        validation_runner,
        "_validation_catalog_entries",
        lambda **_kwargs: copy.deepcopy(expected_catalog),
    )
    verify_validation_batch_plan(plan, repo_root=training_source["repo_root"])
    after = sorted(
        path.relative_to(training_source["repo_root"])
        for path in training_source["repo_root"].rglob("*")
    )

    assert before == after
    assert training_source["calls"] == {"training_verifier": 2, "contract_loader": 2}


@pytest.mark.parametrize(
    "mutation",
    [
        "candidate_missing",
        "candidate_extra",
        "candidate_duplicate",
        "excluded",
        "top_n",
        "batch_hash",
    ],
)
def test_builder_rejects_training_selection_mutations(training_source, mutation):
    selection_path = training_source["selection_path"]
    selection = json.loads(selection_path.read_bytes())
    if mutation == "candidate_missing":
        selection["retained_candidate_ids"].pop()
    elif mutation == "candidate_extra":
        selection["retained_candidate_ids"].append("primary_bb_v2__" + "0" * 64)
    elif mutation == "candidate_duplicate":
        selection["retained_candidate_ids"][-1] = selection["retained_candidate_ids"][0]
    elif mutation == "excluded":
        selection["excluded_candidates"] = [
            {"candidate_id": selection["retained_candidate_ids"].pop(), "reason": "fixture"}
        ]
    elif mutation == "top_n":
        selection["performance_based_top_n"] = 8
    else:
        selection["training_batch_manifest_sha256"] = "d" * 64
    selection_path.write_bytes(canonical_json_bytes(selection))

    run_path = training_source["run_path"]
    run_payload = json.loads(run_path.read_bytes())
    run_payload["outputs"]["training_selection_report"]["sha256"] = sha256_bytes(
        selection_path.read_bytes()
    )
    run_path.write_bytes(canonical_json_bytes(run_payload))

    with pytest.raises(ValueError, match="canonical 16 candidates"):
        build_validation_batch_plan(
            run_path,
            expected_training_run_manifest_sha256=sha256_bytes(run_path.read_bytes()),
            repo_root=training_source["repo_root"],
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "candidate_config",
        "catalog_role",
        "catalog_config_hash",
        "catalog_strategy",
        "catalog_coverage",
        "horizon_order",
        "repetition_seed",
        "session_order",
        "stream_split",
        "stream_digest",
        "cardinality",
        "series_split",
        "sampling_hash",
        "source_commit",
        "source_dirty",
        "source_path",
        "source_reference",
    ],
)
def test_verifier_rejects_plan_and_provenance_mutations(training_source, mutation, monkeypatch):
    plan = _build(training_source)
    manifest = copy.deepcopy(plan.manifest)
    expected_catalog = copy.deepcopy(manifest["validation_catalog_index"]["opponents"])
    monkeypatch.setattr(
        validation_runner,
        "_validation_catalog_entries",
        lambda **_kwargs: copy.deepcopy(expected_catalog),
    )
    if mutation == "candidate_config":
        manifest["candidates"][0]["config"]["epsilon"] = "0"
    elif mutation == "catalog_role":
        manifest["validation_catalog_index"]["opponents"][0]["control_role"] = None
    elif mutation == "catalog_config_hash":
        manifest["validation_catalog_index"]["opponents"][0]["config_sha256"] = "8" * 64
    elif mutation == "catalog_strategy":
        manifest["validation_catalog_index"]["opponents"][0]["strategy_sha256"] = "e" * 64
    elif mutation == "catalog_coverage":
        manifest["validation_catalog_index"]["opponents"][-1]["coverage"]["end_to_end_coverage"] = (
            False
        )
    elif mutation == "horizon_order":
        manifest["horizons"].reverse()
    elif mutation == "repetition_seed":
        manifest["repetitions"][0]["master_seed"] += 1
    elif mutation == "session_order":
        manifest["sessions"][0], manifest["sessions"][1] = (
            manifest["sessions"][1],
            manifest["sessions"][0],
        )
    elif mutation == "stream_split":
        manifest["stream_roots"][0]["payload"]["split"] = "training"
    elif mutation == "stream_digest":
        manifest["stream_roots"][0]["digest"] = "f" * 64
    elif mutation == "cardinality":
        manifest["expected_cardinality"]["session_count"] = 1
    elif mutation == "series_split":
        manifest["series"]["split"] = "training"
    elif mutation == "sampling_hash":
        manifest["sampling_contract"]["sha256"] = "7" * 64
    elif mutation == "source_commit":
        manifest["training_source"]["git"]["actual_commit"] = "2" * 40
    elif mutation == "source_dirty":
        manifest["training_source"]["git"]["dirty"] = True
    elif mutation == "source_path":
        manifest["training_source"]["run_manifest"]["path"] = (
            training_source["run_path"].resolve().as_posix()
        )
    else:
        manifest["training_source"]["selection_report"]["sha256"] = "0" * 64

    with pytest.raises(ValueError):
        verify_validation_batch_plan(
            _replace_manifest(plan, manifest),
            repo_root=training_source["repo_root"],
        )


@pytest.mark.parametrize("mutation", ["missing", "split", "equilibrium"])
def test_builder_rejects_nonrepository_validation_catalog(training_source, tmp_path, mutation):
    source_root = Path(validation_runner.__file__).resolve().parents[2] / "configs" / "opponents"
    catalog_root = tmp_path / "catalog"
    shutil.copytree(source_root / "training", catalog_root / "training")
    shutil.copytree(source_root / "validation", catalog_root / "validation")
    paths = sorted((catalog_root / "validation").glob("*.opponent.json"))
    if mutation == "missing":
        paths[-1].unlink()
    else:
        payload = json.loads(paths[-1].read_bytes())
        if mutation == "split":
            payload["split"] = "training"
        else:
            payload["equilibrium_artifact_sha256"] = "9" * 64
        paths[-1].write_bytes(canonical_json_bytes(payload))

    with pytest.raises(ValueError):
        build_validation_batch_plan(
            training_source["run_path"],
            expected_training_run_manifest_sha256=training_source["run_sha256"],
            repo_root=training_source["repo_root"],
            catalog_root=catalog_root,
        )
