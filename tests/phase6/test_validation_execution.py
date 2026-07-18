"""Unit/in-memory/tmp fixtures for the P6-9A Validation-only boundary."""

from __future__ import annotations

import copy
import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

import phase6.validation_execution as validation_execution
import phase6.validation_runner as validation_runner
from opponents.synthesis import synthesize_opponent
from phase6 import (
    COMPONENT_ROLES,
    COVERAGE_CONTRACT_SCHEMA_VERSION,
    PREREGISTRATION_SCHEMA_VERSION,
    ROOT_MANIFEST_SCHEMA_VERSION,
    SELECTION_CONTRACT_SCHEMA_VERSION,
    SELECTION_REPORT_REFERENCE_SCHEMA_VERSION,
    SEMANTIC_FIXTURE_SCHEMA_VERSION,
    SEMANTIC_SOURCE_SCHEMA_VERSION,
    SERIES_REFERENCE_SCHEMA_VERSION,
    VALIDATION_AGGREGATE_RESULT_SCHEMA_VERSION,
    VALIDATION_BATCH_REFERENCE_SCHEMA_VERSION,
    VALIDATION_CALIBRATION_RESULT_SCHEMA_VERSION,
    VALIDATION_EXACT_EV_RESULT_SCHEMA_VERSION,
    VALIDATION_HERO_POLICY_RESULT_SCHEMA_VERSION,
    VALIDATION_TERMINAL_RESULT_SCHEMA_VERSION,
    ComponentCoverageResult,
    CoverageEvaluation,
    PolicySlice,
    ValidationCandidateResult,
    ValidationSessionResult,
    artifact_ref,
    build_r008_component_source_payloads,
    build_r008_coverage_contract,
    build_r008_fixture_payloads,
    build_validation_batch_plan,
    canonical_json_bytes,
    evaluate_exact_ev,
    primary_candidate_grid,
    run_validation_execution_adapter,
    sampling_contract_payload,
    selection_metric_contract_payload,
    sha256_bytes,
    verify_validation_artifact_root,
    verify_validation_execution_records,
    write_validation_artifact_bundle,
)


def _coverage_evaluation() -> CoverageEvaluation:
    return CoverageEvaluation(
        component_results=tuple(
            ComponentCoverageResult(role, "c" * 64, True, ()) for role in COMPONENT_ROLES
        ),
        matrix_matches_reconstruction=True,
        end_to_end_coverage=True,
    )


def _write_contract_artifact(
    root: Path,
    relative_path: str,
    payload: object,
    *,
    artifact_type: str,
    schema_version: str,
) -> dict[str, str]:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(payload))
    return artifact_ref(
        artifact_type=artifact_type,
        schema_version=schema_version,
        path=relative_path,
        payload=payload,
    )


def _contract_manifest(root: Path) -> tuple[Path, str]:
    source_refs = {
        role: _write_contract_artifact(
            root,
            f"sources/{role}.json",
            payload,
            artifact_type="phase6_semantic_source",
            schema_version=SEMANTIC_SOURCE_SCHEMA_VERSION,
        )
        for role, payload in build_r008_component_source_payloads().items()
    }
    fixture_refs = {
        fixture_id: _write_contract_artifact(
            root,
            f"fixtures/{fixture_id}.json",
            payload,
            artifact_type="phase6_semantic_fixture",
            schema_version=SEMANTIC_FIXTURE_SCHEMA_VERSION,
        )
        for fixture_id, payload in build_r008_fixture_payloads().items()
    }
    coverage = build_r008_coverage_contract(source_refs, fixture_refs)
    coverage_ref = _write_contract_artifact(
        root,
        "contracts/coverage.json",
        coverage,
        artifact_type="coverage_semantics_contract",
        schema_version=COVERAGE_CONTRACT_SCHEMA_VERSION,
    )
    selection = selection_metric_contract_payload()
    selection_ref = _write_contract_artifact(
        root,
        "contracts/selection.json",
        selection,
        artifact_type="selection_metric_contract",
        schema_version=SELECTION_CONTRACT_SCHEMA_VERSION,
    )
    preregistration = {
        "schema_version": PREREGISTRATION_SCHEMA_VERSION,
        "artifact_type": "phase6_evaluation_preregistration",
        "coverage_semantics_contract": coverage_ref,
        "selection_metric_contract": selection_ref,
    }
    preregistration_ref = _write_contract_artifact(
        root,
        "references/preregistration.json",
        preregistration,
        artifact_type="phase6_evaluation_preregistration",
        schema_version=PREREGISTRATION_SCHEMA_VERSION,
    )
    common = {
        "preregistration": preregistration_ref,
        "coverage_semantics_contract": coverage_ref,
        "selection_metric_contract": selection_ref,
    }
    series_ref = _write_contract_artifact(
        root,
        "references/series.json",
        {
            "schema_version": SERIES_REFERENCE_SCHEMA_VERSION,
            "artifact_type": "phase6_evaluation_series_reference",
            **copy.deepcopy(common),
        },
        artifact_type="phase6_evaluation_series_reference",
        schema_version=SERIES_REFERENCE_SCHEMA_VERSION,
    )
    batch_ref = _write_contract_artifact(
        root,
        "references/validation-batch.json",
        {
            "schema_version": VALIDATION_BATCH_REFERENCE_SCHEMA_VERSION,
            "artifact_type": "phase6_validation_batch_reference",
            **copy.deepcopy(common),
        },
        artifact_type="phase6_validation_batch_reference",
        schema_version=VALIDATION_BATCH_REFERENCE_SCHEMA_VERSION,
    )
    report_ref = _write_contract_artifact(
        root,
        "references/selection-report.json",
        {
            "schema_version": SELECTION_REPORT_REFERENCE_SCHEMA_VERSION,
            "artifact_type": "phase6_selection_report_reference",
            **copy.deepcopy(common),
            "selection_metric_id": "gto_negative_control_micro_fpr_v1",
        },
        artifact_type="phase6_selection_report_reference",
        schema_version=SELECTION_REPORT_REFERENCE_SCHEMA_VERSION,
    )
    manifest = {
        "schema_version": ROOT_MANIFEST_SCHEMA_VERSION,
        "artifact_type": "phase6_evaluation_manifest",
        "preregistration": preregistration_ref,
        "coverage_semantics_contract": coverage_ref,
        "selection_metric_contract": selection_ref,
        "series_reference": series_ref,
        "validation_batch_reference": batch_ref,
        "selection_report_reference": report_ref,
    }
    path = root / "phase6-evaluation-manifest.json"
    raw = canonical_json_bytes(manifest)
    path.write_bytes(raw)
    return path, sha256_bytes(raw)


@pytest.fixture(scope="module")
def validation_plan(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("validation-execution-plan")
    monkeypatch = pytest.MonkeyPatch()
    repo_root = tmp_path / "repo"
    input_root = repo_root / "inputs"
    output_root = repo_root / "training-output"
    input_root.mkdir(parents=True)
    output_root.mkdir()
    contract_path, contract_hash = _contract_manifest(input_root)
    dependency_path = input_root / "dependency-lock.json"
    dependency_path.write_bytes(b"{}\n")
    sampling = sampling_contract_payload(
        observation_registry_version="fixture-observation-registry-v1",
        observation_registry_sha256="a" * 64,
    )
    sampling_hash = sha256_bytes(canonical_json_bytes(sampling))
    candidate_ids = [
        item.candidate_id for item in primary_candidate_grid(sampling_contract_sha256=sampling_hash)
    ]
    batch_hash = "b" * 64
    selection = {
        "schema_version": "phase6-training-selection-report-v1",
        "artifact_type": "training_selection_report",
        "training_batch_manifest_sha256": batch_hash,
        "selection_policy": "retain_all_hard_gate_passing_candidates",
        "performance_based_top_n": None,
        "input_candidate_ids": candidate_ids,
        "retained_candidate_ids": candidate_ids,
        "excluded_candidates": [],
        "p6_8_candidate_count": 16,
    }
    selection_path = output_root / "training_selection_report.json"
    selection_path.write_bytes(canonical_json_bytes(selection))
    run = {
        "git": {"expected_commit": "1" * 40, "actual_commit": "1" * 40, "dirty": False},
        "inputs": {
            "phase6_contract_manifest": {
                "path": contract_path.relative_to(repo_root).as_posix(),
                "sha256": contract_hash,
            },
            "dependency_lock": {
                "path": dependency_path.relative_to(repo_root).as_posix(),
                "sha256": sha256_bytes(dependency_path.read_bytes()),
            },
            "sampling_contract": {"payload": sampling, "sha256": sampling_hash},
            "training_batch_manifest_sha256": batch_hash,
        },
        "outputs": {
            "training_selection_report": {
                "name": "training_selection_report",
                "path": selection_path.name,
                "sha256": sha256_bytes(selection_path.read_bytes()),
            }
        },
    }
    run_path = output_root / "phase6_training_run_manifest.json"
    run_path.write_bytes(canonical_json_bytes(run))

    monkeypatch.setattr(
        validation_runner,
        "verify_training_run_manifest",
        lambda path, *, repo_root: json.loads(Path(path).read_bytes()),
    )
    plan = build_validation_batch_plan(
        run_path,
        expected_training_run_manifest_sha256=sha256_bytes(run_path.read_bytes()),
        repo_root=repo_root,
    )
    validation_runner.verify_validation_batch_plan(plan, repo_root=repo_root)
    calls = {"plan_verifier": 0}

    def verified(candidate_plan, *, repo_root):
        calls["plan_verifier"] += 1
        assert Path(repo_root).resolve() == repo_root_path
        if (
            candidate_plan.manifest["split"] != "validation"
            or candidate_plan.manifest["expected_cardinality"]["session_count"] != 12960
            or len(candidate_plan.candidates) != 16
            or len(candidate_plan.sessions) != 12960
            or canonical_json_bytes(candidate_plan.manifest) != candidate_plan.manifest_bytes
            or sha256_bytes(candidate_plan.manifest_bytes) != candidate_plan.manifest_sha256
        ):
            raise ValueError("fixture plan verifier rejected an invalid P6-8A plan")

    repo_root_path = repo_root.resolve()
    monkeypatch.setattr(validation_execution, "verify_validation_batch_plan", verified)
    yield plan, repo_root, calls
    monkeypatch.undo()


class _FixtureValidationBackend:
    backend_id = "phase6-validation-fixture"
    backend_version = "p6-9a-validation-fixture-v1"

    def __init__(self, plan, repo_root, *, session_mode="ok", candidate_mode="ok"):
        self.plan = plan
        self.repo_root = repo_root
        self.session_mode = session_mode
        self.candidate_mode = candidate_mode
        self.session_request_count = 0
        self.candidate_request_count = 0
        self.opponents = {
            item.config.opponent_id: item
            for item in (
                synthesize_opponent(config=config)
                for config in validation_execution.load_validation_catalog()
            )
        }
        self.cells = {}
        self.context = validation_execution._evaluation_context(plan, repo_root.resolve())

    def _session_products(self, request):
        opponent = self.opponents[request.key.opponent_id]
        game = opponent.game
        base = {infoset: opponent.equilibrium_strategy[infoset] for infoset in game.infosets_of(0)}
        final = {infoset: dict(distribution) for infoset, distribution in base.items()}
        terminal = {
            "schema_version": VALIDATION_TERMINAL_RESULT_SCHEMA_VERSION,
            "evaluator_version": "all-candidate-calibration-v1",
            "session": request.key.canonical_payload(),
            "action_counts": {"BET": 0, "CHECK": request.key.horizon},
            "opportunity_count": request.key.horizon,
            "transcript_sha256": sha256_bytes(
                canonical_json_bytes({"fixture_transcript": request.key.canonical_payload()})
            ),
        }
        policy = {
            "schema_version": VALIDATION_HERO_POLICY_RESULT_SCHEMA_VERSION,
            "exact_ev_evaluator_version": "p6-5-exact-ev-cell-v2",
            "session": request.key.canonical_payload(),
            "source_terminal_sha256": sha256_bytes(canonical_json_bytes(terminal)),
            "game_id": game.name,
            "opponent_id": request.key.opponent_id,
            "hero_player": 0,
            "base_hero_policy": validation_execution._profile_payload(base),
            "final_hero_policy": validation_execution._profile_payload(final),
        }
        cell = self.cells.get(request.key.opponent_id)
        if cell is None:
            opponent_policy = {
                infoset: opponent.strategy[infoset] for infoset in game.infosets_of(1)
            }
            cell = evaluate_exact_ev(
                game,
                hero_player=0,
                opponent_policy=PolicySlice(
                    game.name,
                    request.key.opponent_id,
                    opponent_policy,
                ),
                base_hero_policy=PolicySlice(game.name, request.key.opponent_id, base),
                final_hero_policy=PolicySlice(game.name, request.key.opponent_id, final),
            )
            self.cells[request.key.opponent_id] = cell
        exact = {
            "schema_version": VALIDATION_EXACT_EV_RESULT_SCHEMA_VERSION,
            "exact_ev_evaluator_version": "p6-5-exact-ev-cell-v2",
            "session": request.key.canonical_payload(),
            "source_terminal_sha256": sha256_bytes(canonical_json_bytes(terminal)),
            "source_hero_policy_sha256": sha256_bytes(canonical_json_bytes(policy)),
            "cell": validation_execution._exact_ev_payload(cell),
        }
        return terminal, policy, exact

    def run_sessions(self, requests):
        self.session_request_count = len(requests)
        results = [
            ValidationSessionResult(
                "validation",
                request.key,
                request.stream_roots,
                *self._session_products(request),
            )
            for request in requests
        ]
        if self.session_mode == "training_split":
            results[0] = replace(results[0], split="training")
        elif self.session_mode == "missing":
            results.pop()
        elif self.session_mode == "reverse":
            results.reverse()
        return results

    def evaluate_candidates(self, requests):
        self.candidate_request_count = len(requests)
        results = []
        for request in requests:
            calibration, aggregate, _series = validation_execution._candidate_products(
                self.plan,
                request,
                self.context,
            )
            results.append(
                ValidationCandidateResult(
                    "validation",
                    request.candidate.candidate_id,
                    request.session_join_sha256,
                    calibration,
                    aggregate,
                )
            )
        if self.candidate_mode == "test_split":
            results[0] = replace(results[0], split="test")
        elif self.candidate_mode == "missing":
            results.pop()
        return results


@pytest.fixture(scope="module")
def execution(validation_plan):
    plan, repo_root, calls = validation_plan
    backend = _FixtureValidationBackend(plan, repo_root)
    records = run_validation_execution_adapter(plan, backend, repo_root=repo_root)
    return plan, repo_root, calls, backend, records


def test_adapter_executes_complete_validation_product_and_reuses_approved_boundaries(execution):
    plan, repo_root, calls, backend, records = execution
    assert backend.session_request_count == 12960
    assert backend.candidate_request_count == 16
    assert [len(records[name]) for name in records] == [12960, 12960, 12960, 16, 16]
    assert all(
        record.payload["split"] == "validation"
        and record.payload["backend"]["backend_id"].startswith("phase6-validation-")
        for values in records.values()
        for record in values
    )
    assert records["validation_exact_ev_cells"][0].payload["result"]["schema_version"] == (
        VALIDATION_EXACT_EV_RESULT_SCHEMA_VERSION
    )
    assert (
        records["validation_aggregate_metrics"][0].payload["result"]["evaluator_version"]
        == "all-candidate-calibration-v1"
    )
    verify_validation_execution_records(plan, records, repo_root=repo_root)
    assert calls["plan_verifier"] >= 2


@pytest.mark.parametrize(
    ("session_mode", "candidate_mode", "match"),
    [
        ("training_split", "ok", "non-Validation"),
        ("missing", "ok", "missing, duplicate, or out of order"),
        ("reverse", "ok", "missing, duplicate, or out of order"),
        ("ok", "test_split", "non-Validation"),
        ("ok", "missing", "missing, duplicate, or out of order"),
    ],
)
def test_adapter_rejects_cross_split_and_incomplete_backend_results(
    validation_plan, session_mode, candidate_mode, match
):
    plan, repo_root, _calls = validation_plan
    backend = _FixtureValidationBackend(
        plan,
        repo_root,
        session_mode=session_mode,
        candidate_mode=candidate_mode,
    )
    with pytest.raises(ValueError, match=match):
        run_validation_execution_adapter(plan, backend, repo_root=repo_root)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("backend_id", "phase6-training-fixture"),
        ("backend_version", "p6-9a-training-fixture-v1"),
        ("backend_version", "p6-9a-test-fixture-v1"),
        ("backend_version", "p6-9a-fixture-v1"),
    ],
)
def test_backend_identity_is_validation_only(validation_plan, field, value):
    plan, repo_root, _calls = validation_plan
    backend = _FixtureValidationBackend(plan, repo_root)
    setattr(backend, field, value)
    with pytest.raises(ValueError, match="Validation-only"):
        run_validation_execution_adapter(plan, backend, repo_root=repo_root)


def _replace_record_result(records, artifact_type, index, mutate):
    changed = {name: list(values) for name, values in records.items()}
    record = changed[artifact_type][index]
    payload = copy.deepcopy(record.payload)
    mutate(payload["result"])
    changed[artifact_type][index] = replace(
        record,
        payload=payload,
        payload_sha256=sha256_bytes(canonical_json_bytes(payload)),
    )
    return changed


@pytest.mark.parametrize(
    ("artifact_type", "expected_schema"),
    [
        ("validation_terminal_candidate_snapshots", VALIDATION_TERMINAL_RESULT_SCHEMA_VERSION),
        ("validation_hero_policy_snapshots", VALIDATION_HERO_POLICY_RESULT_SCHEMA_VERSION),
        ("validation_exact_ev_cells", VALIDATION_EXACT_EV_RESULT_SCHEMA_VERSION),
        ("validation_calibration_cells", VALIDATION_CALIBRATION_RESULT_SCHEMA_VERSION),
        ("validation_aggregate_metrics", VALIDATION_AGGREGATE_RESULT_SCHEMA_VERSION),
    ],
)
@pytest.mark.parametrize(
    "schema_case",
    ["phase6-training-result-v1", "phase6-test-result-v1", "unknown-v1", None],
)
def test_record_verifier_rejects_non_validation_or_missing_inner_result_schema(
    execution,
    artifact_type,
    expected_schema,
    schema_case,
):
    plan, repo_root, _calls, _backend, records = execution

    def mutate(result):
        assert result["schema_version"] == expected_schema
        if schema_case is None:
            del result["schema_version"]
        else:
            result["schema_version"] = schema_case

    changed = _replace_record_result(records, artifact_type, 0, mutate)
    with pytest.raises(ValueError):
        verify_validation_execution_records(plan, changed, repo_root=repo_root)


def test_record_verifier_rejects_rehashed_p6_5_profile_and_ev_tampering(execution):
    plan, repo_root, _calls, _backend, records = execution

    def mutate_policy(result):
        infoset = next(iter(result["base_hero_policy"]))
        distribution = result["base_hero_policy"][infoset]
        actions = list(distribution)
        distribution[actions[0]] = float(1).hex()
        distribution[actions[1]] = float(0).hex()

    changed = _replace_record_result(
        records,
        "validation_hero_policy_snapshots",
        0,
        mutate_policy,
    )
    hero_record = changed["validation_hero_policy_snapshots"][0]
    exact_record = changed["validation_exact_ev_cells"][0]
    exact_payload = copy.deepcopy(exact_record.payload)
    exact_payload["result"]["source_hero_policy_sha256"] = sha256_bytes(
        canonical_json_bytes(hero_record.payload["result"])
    )
    exact_payload["result"]["cell"]["base_ev"]["production_binary64_hex"] = float(99).hex()
    changed["validation_exact_ev_cells"][0] = replace(
        exact_record,
        payload=exact_payload,
        payload_sha256=sha256_bytes(canonical_json_bytes(exact_payload)),
    )
    candidate_id = hero_record.candidate_id
    rewritten_join = validation_execution._session_join_sha256(candidate_id, changed)
    for artifact_type in ("validation_calibration_cells", "validation_aggregate_metrics"):
        candidate_record = next(
            item for item in changed[artifact_type] if item.candidate_id == candidate_id
        )
        candidate_payload = copy.deepcopy(candidate_record.payload)
        candidate_payload["source_session_join_sha256"] = rewritten_join
        candidate_payload["result"]["source_session_join_sha256"] = rewritten_join
        position = changed[artifact_type].index(candidate_record)
        changed[artifact_type][position] = replace(
            candidate_record,
            payload=candidate_payload,
            payload_sha256=sha256_bytes(canonical_json_bytes(candidate_payload)),
        )
    with pytest.raises(ValueError):
        verify_validation_execution_records(plan, changed, repo_root=repo_root)


def test_record_verifier_rejects_all_candidate_selection_and_gto_chain_rewrite(execution):
    plan, repo_root, _calls, _backend, records = execution
    changed = {name: list(values) for name, values in records.items()}
    for index, record in enumerate(changed["validation_aggregate_metrics"]):
        payload = copy.deepcopy(record.payload)
        payload["result"]["macro"]["brier"]["value"] = str(index + 10)
        payload["result"]["gto_fpr"]["micro"]["numerator"] = 1
        changed["validation_aggregate_metrics"][index] = replace(
            record,
            payload=payload,
            payload_sha256=sha256_bytes(canonical_json_bytes(payload)),
        )
    for index, record in enumerate(changed["validation_calibration_cells"]):
        payload = copy.deepcopy(record.payload)
        payload["result"]["cells"][0]["label"] = 1
        changed["validation_calibration_cells"][index] = replace(
            record,
            payload=payload,
            payload_sha256=sha256_bytes(canonical_json_bytes(payload)),
        )
    with pytest.raises(ValueError, match="independently reconstruct"):
        verify_validation_execution_records(plan, changed, repo_root=repo_root)


def _validation_target(tmp_path: Path) -> Path:
    base = tmp_path / "validation-artifacts"
    base.mkdir()
    return base / "validation"


@pytest.fixture(scope="module")
def artifact_bundle(execution, tmp_path_factory):
    plan, repo_root, _calls, _backend, records = execution
    root = tmp_path_factory.mktemp("validation-artifact-template")
    return write_validation_artifact_bundle(
        plan,
        records,
        _validation_target(root),
        repo_root=repo_root,
    )


def _copy_artifact_bundle(bundle, tmp_path):
    target = _validation_target(tmp_path)
    shutil.copytree(bundle.root, target)
    return replace(
        bundle,
        root=target,
        root_manifest_path=target / "validation_result_root.json",
    )


def test_writer_and_root_verifier_reconstruct_all_records_selection_and_exact_lock(
    execution, artifact_bundle
):
    plan, repo_root, _calls, _backend, records = execution
    bundle = artifact_bundle
    verified = json.loads(bundle.root_manifest_path.read_bytes())
    report = json.loads((bundle.root / "primary_selection_report.json").read_bytes())
    lock = json.loads((bundle.root / "selected_config_lock.json").read_bytes())
    assert verified["expected_cardinality"]["session_count"] == 12960
    assert [row["rank"] for row in report["ranked_candidates"]] == list(range(1, 17))
    assert len({row["candidate"]["candidate_id"] for row in report["ranked_candidates"]}) == 16
    assert lock["selected_config_count"] == 1
    assert lock["selected_candidate_id"] == report["selected_candidate_id"]
    assert lock["manual_override"] is False
    assert all(bundle.root in path.parents for path in bundle.root.rglob("*"))
    with pytest.raises(FileExistsError):
        write_validation_artifact_bundle(plan, records, bundle.root, repo_root=repo_root)


def _rehash_artifact(root: Path, name: str, payload: dict[str, object]) -> str:
    path = root / f"{name}.json"
    raw = canonical_json_bytes(payload)
    path.write_bytes(raw)
    root_path = root / "validation_result_root.json"
    root_payload = json.loads(root_path.read_bytes())
    reference = next(item for item in root_payload["artifacts"] if item["name"] == name)
    reference["sha256"] = sha256_bytes(raw)
    reference["size_bytes"] = len(raw)
    root_raw = canonical_json_bytes(root_payload)
    root_path.write_bytes(root_raw)
    return sha256_bytes(root_raw)


@pytest.mark.parametrize("target", ["aggregate", "report", "lock"])
def test_root_verifier_rejects_rehashed_aggregate_report_and_lock_tampering(
    execution, artifact_bundle, tmp_path, target
):
    _plan, repo_root, _calls, _backend, _records = execution
    bundle = _copy_artifact_bundle(artifact_bundle, tmp_path)
    if target == "aggregate":
        name = "validation_aggregate_metrics"
        payload = json.loads((bundle.root / f"{name}.json").read_bytes())
        record = payload["records"][0]
        record["payload"]["result"]["macro"]["brier"]["value"] = "99"
        record["payload_sha256"] = sha256_bytes(canonical_json_bytes(record["payload"]))
    elif target == "report":
        name = "primary_selection_report"
        payload = json.loads((bundle.root / f"{name}.json").read_bytes())
        payload["selected_candidate_id"] = payload["ranked_candidates"][-1]["candidate"][
            "candidate_id"
        ]
    else:
        name = "selected_config_lock"
        payload = json.loads((bundle.root / f"{name}.json").read_bytes())
        payload["selected_config_count"] = 2
    root_hash = _rehash_artifact(bundle.root, name, payload)
    with pytest.raises(ValueError):
        verify_validation_artifact_root(
            bundle.root_manifest_path,
            expected_sha256=root_hash,
            repo_root=repo_root,
        )


def test_root_verifier_rejects_fully_rehashed_selection_report_lock_chain(
    execution,
    artifact_bundle,
    tmp_path,
):
    _plan, repo_root, _calls, _backend, _records = execution
    bundle = _copy_artifact_bundle(artifact_bundle, tmp_path)
    aggregate_name = "validation_aggregate_metrics"
    aggregate = json.loads((bundle.root / f"{aggregate_name}.json").read_bytes())
    forged_brier = {}
    for index, record in enumerate(aggregate["records"]):
        value = str(index + 10)
        forged_brier[record["candidate_id"]] = value
        record["payload"]["result"]["macro"]["brier"]["value"] = value
        record["payload"]["result"]["gto_fpr"]["micro"]["numerator"] = 1
        record["payload_sha256"] = sha256_bytes(canonical_json_bytes(record["payload"]))
    _rehash_artifact(bundle.root, aggregate_name, aggregate)
    aggregate_hash = sha256_bytes((bundle.root / f"{aggregate_name}.json").read_bytes())

    report_name = "primary_selection_report"
    report = json.loads((bundle.root / f"{report_name}.json").read_bytes())
    report["aggregate_metrics_sha256"] = aggregate_hash
    for row in report["ranked_candidates"]:
        candidate_id = row["candidate"]["candidate_id"]
        row["sort_keys"]["validation_macro_brier"] = forged_brier[candidate_id]
        row["sort_keys"]["gto_negative_control_micro_fpr_v1"]["false_positives"] = 1
    _rehash_artifact(bundle.root, report_name, report)
    report_hash = sha256_bytes((bundle.root / f"{report_name}.json").read_bytes())

    lock_name = "selected_config_lock"
    lock = json.loads((bundle.root / f"{lock_name}.json").read_bytes())
    lock["primary_selection_report_sha256"] = report_hash
    root_hash = _rehash_artifact(bundle.root, lock_name, lock)
    with pytest.raises(ValueError, match="independently reconstruct"):
        verify_validation_artifact_root(
            bundle.root_manifest_path,
            expected_sha256=root_hash,
            repo_root=repo_root,
        )


def _saved_records(root: Path):
    return {
        artifact_type: [
            validation_execution._record_from_payload(item)
            for item in json.loads((root / f"{artifact_type}.json").read_bytes())["records"]
        ]
        for artifact_type in validation_execution._ARTIFACT_TYPES
    }


def _replace_saved_record(records, artifact_type, replacement):
    index = next(
        index
        for index, record in enumerate(records[artifact_type])
        if record.candidate_id == replacement.candidate_id
        and record.opponent_id == replacement.opponent_id
        and record.horizon == replacement.horizon
        and record.repetition_id == replacement.repetition_id
    )
    records[artifact_type][index] = replacement


def _alternate_complete_policy(policy):
    changed = copy.deepcopy(policy)
    infoset = next(key for key, distribution in changed.items() if len(distribution) >= 2)
    distribution = changed[infoset]
    actions = sorted(distribution)
    selected = actions[0]
    if distribution[selected] == float(1).hex():
        selected = actions[1]
    changed[infoset] = {action: float(action == selected).hex() for action in actions}
    assert changed != policy
    return changed


def test_root_verifier_rejects_fully_consistent_final_policy_chain_rewrite(
    execution,
    artifact_bundle,
    tmp_path,
    monkeypatch,
):
    plan, repo_root, _calls, _backend, _original_records = execution
    bundle = _copy_artifact_bundle(artifact_bundle, tmp_path)
    records = _saved_records(bundle.root)
    terminal_raw_before = (
        bundle.root / "validation_terminal_candidate_snapshots.json"
    ).read_bytes()

    hero_record = records["validation_hero_policy_snapshots"][0]
    key = hero_record.session_key()
    candidate = next(item for item in plan.candidates if item.candidate_id == key.candidate_id)
    hero_payload = copy.deepcopy(hero_record.payload)
    saved_base = copy.deepcopy(hero_payload["result"]["base_hero_policy"])
    forged_final = _alternate_complete_policy(hero_payload["result"]["final_hero_policy"])
    hero_payload["result"]["final_hero_policy"] = forged_final
    forged_hero_record = replace(
        hero_record,
        payload=hero_payload,
        payload_sha256=sha256_bytes(canonical_json_bytes(hero_payload)),
    )
    _replace_saved_record(
        records,
        "validation_hero_policy_snapshots",
        forged_hero_record,
    )

    context = validation_execution._evaluation_context(plan, repo_root.resolve())
    opponent = context.opponents[key.opponent_id]
    base_policy = validation_execution._policy_from_payload(saved_base, "base Hero policy")
    final_policy = validation_execution._policy_from_payload(
        forged_final,
        "forged final Hero policy",
    )
    opponent_policy = {
        infoset: opponent.strategy[infoset] for infoset in opponent.game.infosets_of(1)
    }
    forged_cell = evaluate_exact_ev(
        opponent.game,
        hero_player=0,
        opponent_policy=PolicySlice(
            opponent.game.name,
            key.opponent_id,
            opponent_policy,
        ),
        base_hero_policy=PolicySlice(opponent.game.name, key.opponent_id, base_policy),
        final_hero_policy=PolicySlice(opponent.game.name, key.opponent_id, final_policy),
    )
    exact_record = next(
        item for item in records["validation_exact_ev_cells"] if item.session_key() == key
    )
    exact_payload = copy.deepcopy(exact_record.payload)
    exact_payload["result"]["source_hero_policy_sha256"] = sha256_bytes(
        canonical_json_bytes(hero_payload["result"])
    )
    exact_payload["result"]["cell"] = validation_execution._exact_ev_payload(forged_cell)
    _replace_saved_record(
        records,
        "validation_exact_ev_cells",
        replace(
            exact_record,
            payload=exact_payload,
            payload_sha256=sha256_bytes(canonical_json_bytes(exact_payload)),
        ),
    )

    original_reconstruct = validation_execution._reconstruct_hero_policies

    def accept_forged_policy(current_candidate, terminal, current_opponent, dimension):
        if (
            current_candidate.candidate_id == candidate.candidate_id
            and terminal["session"] == key.canonical_payload()
        ):
            return base_policy, final_policy
        return original_reconstruct(current_candidate, terminal, current_opponent, dimension)

    with monkeypatch.context() as forge_context:
        forge_context.setattr(
            validation_execution,
            "_reconstruct_hero_policies",
            accept_forged_policy,
        )
        session_records = {
            artifact_type: records[artifact_type]
            for artifact_type in validation_execution._SESSION_ARTIFACT_TYPE_ORDER
        }
        join_sha256 = validation_execution._session_join_sha256(
            candidate.candidate_id,
            session_records,
        )
        session_by_type = {
            artifact_type: {record.session_key(): record for record in values}
            for artifact_type, values in session_records.items()
        }
        candidate_keys = tuple(
            item for item in plan.sessions if item.candidate_id == candidate.candidate_id
        )
        request = validation_execution.ValidationCandidateRequest(
            candidate,
            tuple(
                ValidationSessionResult(
                    "validation",
                    session_key,
                    validation_execution._stream_roots(session_key),
                    session_by_type["validation_terminal_candidate_snapshots"][session_key].payload[
                        "result"
                    ],
                    session_by_type["validation_hero_policy_snapshots"][session_key].payload[
                        "result"
                    ],
                    session_by_type["validation_exact_ev_cells"][session_key].payload["result"],
                )
                for session_key in candidate_keys
            ),
            join_sha256,
        )
        calibration, aggregate, _series = validation_execution._candidate_products(
            plan,
            request,
            context,
        )
        for artifact_type, result in (
            ("validation_calibration_cells", calibration),
            ("validation_aggregate_metrics", aggregate),
        ):
            record = next(
                item
                for item in records[artifact_type]
                if item.candidate_id == candidate.candidate_id
            )
            payload = copy.deepcopy(record.payload)
            payload["source_session_join_sha256"] = join_sha256
            payload["result"] = result
            _replace_saved_record(
                records,
                artifact_type,
                replace(
                    record,
                    payload=payload,
                    payload_sha256=sha256_bytes(canonical_json_bytes(payload)),
                ),
            )
        candidate_records = {
            artifact_type: records[artifact_type]
            for artifact_type in validation_execution._CANDIDATE_ARTIFACT_TYPE_ORDER
        }
        ranked = validation_execution._rank_from_saved_records(
            plan,
            session_records,
            candidate_records,
            repo_root=repo_root,
        )

    for artifact_type in validation_execution._ARTIFACT_TYPES:
        artifact = json.loads((bundle.root / f"{artifact_type}.json").read_bytes())
        artifact["records"] = [record.canonical_payload() for record in records[artifact_type]]
        _rehash_artifact(bundle.root, artifact_type, artifact)
    assert (
        bundle.root / "validation_terminal_candidate_snapshots.json"
    ).read_bytes() == terminal_raw_before

    aggregate_hash = sha256_bytes((bundle.root / "validation_aggregate_metrics.json").read_bytes())
    report = validation_execution._selection_report(plan, ranked, aggregate_hash)
    _rehash_artifact(bundle.root, "primary_selection_report", report)
    report_hash = sha256_bytes((bundle.root / "primary_selection_report.json").read_bytes())
    lock = validation_execution._selected_lock(plan, ranked[0], report_hash)
    root_hash = _rehash_artifact(bundle.root, "selected_config_lock", lock)

    with pytest.raises(
        ValueError,
        match="final Hero policy does not independently reconstruct",
    ):
        verify_validation_artifact_root(
            bundle.root_manifest_path,
            expected_sha256=root_hash,
            repo_root=repo_root,
        )


def test_execution_record_verifier_rejects_schema_backend_and_join_rehash(execution):
    plan, repo_root, _calls, _backend, records = execution
    for mutation in ("schema", "backend", "backend_version", "join"):
        changed = {name: list(values) for name, values in records.items()}
        artifact_type = (
            "validation_terminal_candidate_snapshots"
            if mutation != "join"
            else "validation_aggregate_metrics"
        )
        record = changed[artifact_type][0]
        payload = copy.deepcopy(record.payload)
        if mutation == "schema":
            payload["schema_version"] = "phase6-training-execution-record-v1"
        elif mutation == "backend":
            payload["backend"]["backend_id"] = "phase6-test-fixture"
        elif mutation == "backend_version":
            payload["backend"]["backend_version"] = "p6-9a-training-fixture-v1"
        else:
            payload["source_session_join_sha256"] = "f" * 64
        changed[artifact_type][0] = replace(
            record,
            payload=payload,
            payload_sha256=sha256_bytes(canonical_json_bytes(payload)),
        )
        with pytest.raises(ValueError):
            verify_validation_execution_records(plan, changed, repo_root=repo_root)


@pytest.mark.parametrize(
    "path",
    [
        Path("training") / "validation",
        Path("test") / "validation",
        Path("training-output") / "validation-artifacts" / "validation",
        Path("test-results") / "validation-artifacts" / "validation",
        Path("other") / "validation",
        Path("validation-results"),
    ],
)
def test_writer_rejects_training_test_and_noncanonical_physical_paths(execution, tmp_path, path):
    plan, repo_root, _calls, _backend, records = execution
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValueError, match="isolated validation directory"):
        write_validation_artifact_bundle(plan, records, target, repo_root=repo_root)
