"""Fixture-only tests for the P6-4 evaluation contract foundation."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from phase6 import (
    COMPONENT_ROLES,
    COVERAGE_CONTRACT_SCHEMA_VERSION,
    FULL_SELECTION_CONTRACT_SCHEMA_VERSION,
    FULL_SELECTION_PREREGISTRATION_SCHEMA_VERSION,
    GTO_FPR_METRIC_ID,
    PREREGISTRATION_SCHEMA_VERSION,
    PRIMARY_SELECTION_KEYS,
    ROOT_MANIFEST_SCHEMA_VERSION,
    SELECTION_CONTRACT_SCHEMA_VERSION,
    SELECTION_REPORT_REFERENCE_SCHEMA_VERSION,
    SEMANTIC_FIXTURE_SCHEMA_VERSION,
    SEMANTIC_SOURCE_SCHEMA_VERSION,
    SERIES_REFERENCE_SCHEMA_VERSION,
    VALIDATION_BATCH_REFERENCE_SCHEMA_VERSION,
    artifact_ref,
    build_r008_component_source_payloads,
    build_r008_coverage_contract,
    build_r008_fixture_payloads,
    canonical_json_bytes,
    evaluate_coverage_semantics,
    full_selection_metric_contract_v2_payload,
    full_selection_preregistration_v2_payload,
    load_full_selection_preregistration_v2,
    load_phase6_contract_bundle,
    selection_metric_contract_payload,
    sha256_bytes,
    validate_full_selection_metric_contract_v2,
    validate_full_selection_preregistration_v2,
    validate_selection_metric_contract,
)
from phase6.contracts import (
    CanonicalPhase6ContractArtifact,
    ValidatedPhase6ContractBundleEvidence,
    load_phase6_contract_bundle_evidence,
    load_phase6_contract_bundle_evidence_from_canonical_artifacts,
    validate_phase6_contract_bundle_evidence,
)

Mutator = Callable[[dict[str, Any]], None]


def _write_artifact(
    root: Path,
    relative_path: str,
    payload: dict[str, Any],
    *,
    artifact_type: str,
    schema_version: str,
) -> dict[str, str]:
    target = root / Path(relative_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(canonical_json_bytes(payload))
    return artifact_ref(
        artifact_type=artifact_type,
        schema_version=schema_version,
        path=relative_path,
        payload=payload,
    )


def _build_bundle(
    root: Path,
    *,
    source_mutator: Callable[[dict[str, dict[str, Any]]], None] | None = None,
    fixture_mutator: Callable[[dict[str, dict[str, Any]]], None] | None = None,
    coverage_mutator: Mutator | None = None,
    selection_mutator: Mutator | None = None,
    series_mutator: Mutator | None = None,
    report_mutator: Mutator | None = None,
) -> dict[str, Any]:
    source_payloads = build_r008_component_source_payloads()
    if source_mutator is not None:
        source_mutator(source_payloads)
    source_refs: dict[str, dict[str, str]] = {}
    source_paths: dict[str, Path] = {}
    for role in COMPONENT_ROLES:
        relative_path = f"sources/{role}.json"
        source_refs[role] = _write_artifact(
            root,
            relative_path,
            source_payloads[role],
            artifact_type="phase6_semantic_source",
            schema_version=SEMANTIC_SOURCE_SCHEMA_VERSION,
        )
        source_paths[role] = root / relative_path

    fixture_payloads = build_r008_fixture_payloads()
    if fixture_mutator is not None:
        fixture_mutator(fixture_payloads)
    fixture_refs: dict[str, dict[str, str]] = {}
    fixture_paths: dict[str, Path] = {}
    for fixture_id, payload in fixture_payloads.items():
        relative_path = f"fixtures/{fixture_id}.json"
        fixture_refs[fixture_id] = _write_artifact(
            root,
            relative_path,
            payload,
            artifact_type="phase6_semantic_fixture",
            schema_version=SEMANTIC_FIXTURE_SCHEMA_VERSION,
        )
        fixture_paths[fixture_id] = root / relative_path

    coverage = build_r008_coverage_contract(source_refs, fixture_refs)
    if coverage_mutator is not None:
        coverage_mutator(coverage)
    coverage_ref = _write_artifact(
        root,
        "contracts/coverage.json",
        coverage,
        artifact_type="coverage_semantics_contract",
        schema_version=COVERAGE_CONTRACT_SCHEMA_VERSION,
    )

    selection = selection_metric_contract_payload()
    if selection_mutator is not None:
        selection_mutator(selection)
    selection_ref = _write_artifact(
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
    preregistration_ref = _write_artifact(
        root,
        "references/preregistration.json",
        preregistration,
        artifact_type="phase6_evaluation_preregistration",
        schema_version=PREREGISTRATION_SCHEMA_VERSION,
    )
    common_refs = {
        "preregistration": preregistration_ref,
        "coverage_semantics_contract": coverage_ref,
        "selection_metric_contract": selection_ref,
    }
    series = {
        "schema_version": SERIES_REFERENCE_SCHEMA_VERSION,
        "artifact_type": "phase6_evaluation_series_reference",
        **copy.deepcopy(common_refs),
    }
    if series_mutator is not None:
        series_mutator(series)
    series_ref = _write_artifact(
        root,
        "references/series.json",
        series,
        artifact_type="phase6_evaluation_series_reference",
        schema_version=SERIES_REFERENCE_SCHEMA_VERSION,
    )
    batch = {
        "schema_version": VALIDATION_BATCH_REFERENCE_SCHEMA_VERSION,
        "artifact_type": "phase6_validation_batch_reference",
        **copy.deepcopy(common_refs),
    }
    batch_ref = _write_artifact(
        root,
        "references/validation-batch.json",
        batch,
        artifact_type="phase6_validation_batch_reference",
        schema_version=VALIDATION_BATCH_REFERENCE_SCHEMA_VERSION,
    )
    report = {
        "schema_version": SELECTION_REPORT_REFERENCE_SCHEMA_VERSION,
        "artifact_type": "phase6_selection_report_reference",
        **copy.deepcopy(common_refs),
        "selection_metric_id": GTO_FPR_METRIC_ID,
    }
    if report_mutator is not None:
        report_mutator(report)
    report_ref = _write_artifact(
        root,
        "references/selection-report.json",
        report,
        artifact_type="phase6_selection_report_reference",
        schema_version=SELECTION_REPORT_REFERENCE_SCHEMA_VERSION,
    )
    root_manifest = {
        "schema_version": ROOT_MANIFEST_SCHEMA_VERSION,
        "artifact_type": "phase6_evaluation_manifest",
        "preregistration": preregistration_ref,
        "coverage_semantics_contract": coverage_ref,
        "selection_metric_contract": selection_ref,
        "series_reference": series_ref,
        "validation_batch_reference": batch_ref,
        "selection_report_reference": report_ref,
    }
    root_path = root / "phase6-evaluation-manifest.json"
    root_bytes = canonical_json_bytes(root_manifest)
    root_path.write_bytes(root_bytes)
    return {
        "root_path": root_path,
        "root_sha256": sha256_bytes(root_bytes),
        "artifact_relative_paths": [
            *(f"sources/{role}.json" for role in COMPONENT_ROLES),
            *(f"fixtures/{fixture_id}.json" for fixture_id in fixture_payloads),
            "contracts/coverage.json",
            "contracts/selection.json",
            "references/preregistration.json",
            "references/series.json",
            "references/validation-batch.json",
            "references/selection-report.json",
        ],
        "coverage": coverage,
        "coverage_path": root / "contracts/coverage.json",
        "selection": selection,
        "source_paths": source_paths,
        "fixture_paths": fixture_paths,
    }


def test_fixture_bundle_reconstructs_all_five_r008_components(tmp_path):
    bundle = _build_bundle(tmp_path)

    loaded = load_phase6_contract_bundle(bundle["root_path"], expected_sha256=bundle["root_sha256"])

    assert loaded.coverage_evaluation.end_to_end_coverage is True
    assert [
        result.component_role for result in loaded.coverage_evaluation.component_results
    ] == list(COMPONENT_ROLES)
    assert all(result.matched for result in loaded.coverage_evaluation.component_results)
    provider_raw = build_r008_component_source_payloads()["exploit_provider"]["records"][0]["raw"]
    assert provider_raw == {
        "reason_id": "LEAK_R008",
        "subject_actor": "opponent",
        "street": "river",
        "phase": "vs_check",
        "action": "BET",
        "target_source": "observed_rate",
        "hero_response_phase": "vs_bet",
    }
    assert loaded.selection_contract["selection_keys"] == [
        {"position": 3, "metric_id": GTO_FPR_METRIC_ID, "direction": "ascending"}
    ]
    assert loaded.selection_contract["gto_fpr"]["hard_constraint"] is None
    assert loaded.selection_contract["worst_case_penalty_usage"] == "excluded"
    matrix = loaded.coverage_contract["coverage_matrix"]
    assert matrix["positive_fixture_count"] == 1
    assert matrix["negative_fixture_count"] == 1
    assert [row["fixture_kind"] for row in matrix["fixture_evidence"]] == [
        "positive",
        "negative",
    ]


@pytest.mark.parametrize(
    "field, forged_count",
    [
        ("positive_fixture_count", 2),
        ("positive_fixture_count", 999),
        ("negative_fixture_count", 2),
        ("negative_fixture_count", 999),
    ],
)
def test_fixture_counts_are_derived_from_validated_evidence(tmp_path, field, forged_count):
    bundle = _build_bundle(
        tmp_path,
        coverage_mutator=lambda coverage: coverage["coverage_matrix"].update({field: forged_count}),
    )

    with pytest.raises(ValueError, match="coverage semantics hard gate"):
        load_phase6_contract_bundle(bundle["root_path"], expected_sha256=bundle["root_sha256"])


@pytest.mark.parametrize(
    "mutator",
    [
        lambda coverage: coverage["coverage_matrix"]["fixture_evidence"].pop(),
        lambda coverage: coverage["coverage_matrix"]["fixture_evidence"].__setitem__(
            1, copy.deepcopy(coverage["coverage_matrix"]["fixture_evidence"][0])
        ),
        lambda coverage: coverage["coverage_matrix"]["fixture_evidence"][1][
            "fixture_artifact"
        ].update({"sha256": "f" * 64}),
    ],
    ids=["missing-negative", "duplicate-negative", "negative-hash-mismatch"],
)
def test_negative_fixture_reference_is_closed_world_and_hash_bound(tmp_path, mutator):
    bundle = _build_bundle(tmp_path, coverage_mutator=mutator)

    with pytest.raises(ValueError):
        load_phase6_contract_bundle(bundle["root_path"], expected_sha256=bundle["root_sha256"])


@pytest.mark.parametrize(
    "mutator",
    [
        lambda fixtures: fixtures["r008-ground-truth-negative-action-v1"].update(
            {"input_sha256": "f" * 64}
        ),
        lambda fixtures: fixtures["r008-ground-truth-negative-action-v1"]["expected_result"].update(
            {"matched": True}
        ),
        lambda fixtures: fixtures["r008-ground-truth-negative-action-v1"]["observed_result"].update(
            {"matched": True}
        ),
    ],
    ids=["input-hash", "expected-result", "observed-result"],
)
def test_fixture_input_expectation_and_observation_are_revalidated(tmp_path, mutator):
    bundle = _build_bundle(tmp_path, fixture_mutator=mutator)

    with pytest.raises(ValueError, match="coverage semantics hard gate"):
        load_phase6_contract_bundle(bundle["root_path"], expected_sha256=bundle["root_sha256"])


@pytest.mark.parametrize("invalid_matched", [1, 0, "true"])
def test_coverage_matrix_matched_requires_a_json_boolean(tmp_path, invalid_matched):
    def mutate(coverage):
        coverage["coverage_matrix"]["component_results"][0]["matched"] = invalid_matched

    bundle = _build_bundle(tmp_path, coverage_mutator=mutate)

    with pytest.raises(ValueError, match="matched must be a JSON boolean"):
        load_phase6_contract_bundle(bundle["root_path"], expected_sha256=bundle["root_sha256"])


@pytest.mark.parametrize(
    "field, invalid_value, message",
    [
        ("component_role", 1, "component_role must be a known string"),
        ("source_sha256", 1, "source_sha256 must be lowercase hexadecimal"),
        ("mismatch_fields", [1], "entries must be non-empty strings"),
    ],
)
def test_coverage_matrix_component_result_wire_types_are_strict(
    tmp_path, field, invalid_value, message
):
    def mutate(coverage):
        coverage["coverage_matrix"]["component_results"][0][field] = invalid_value

    bundle = _build_bundle(tmp_path, coverage_mutator=mutate)

    with pytest.raises(ValueError, match=message):
        load_phase6_contract_bundle(bundle["root_path"], expected_sha256=bundle["root_sha256"])


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_canonical_writer_rejects_nonfinite_numbers(value):
    with pytest.raises(ValueError, match="Out of range float values"):
        canonical_json_bytes({"value": value})


@pytest.mark.parametrize("token", [b"NaN", b"Infinity", b"-Infinity"])
def test_canonical_loader_rejects_nonfinite_tokens(tmp_path, token):
    bundle = _build_bundle(tmp_path)
    root_path = bundle["root_path"]
    raw = root_path.read_bytes()
    forged_raw = raw[:-2] + b',"unexpected":' + token + b"}\n"
    root_path.write_bytes(forged_raw)

    with pytest.raises(ValueError, match="root manifest is not valid JSON"):
        load_phase6_contract_bundle(root_path, expected_sha256=sha256_bytes(forged_raw))


@pytest.mark.parametrize(
    "mutator, expected_mismatch",
    [
        (
            lambda sources: sources["ground_truth"]["records"][0]["raw"].update({"action": "FOLD"}),
            "raw",
        ),
        (
            lambda sources: sources["exploit_provider"]["records"][0].update(
                {"adapter_semantic_id": "forged_adapter_semantic_id"}
            ),
            "adapter_semantic_id",
        ),
    ],
)
def test_raw_or_adapter_claim_mismatch_makes_coverage_false(tmp_path, mutator, expected_mismatch):
    bundle = _build_bundle(tmp_path, source_mutator=mutator)

    evaluation = evaluate_coverage_semantics(bundle["coverage"], tmp_path)

    assert evaluation.end_to_end_coverage is False
    assert any(
        expected_mismatch in result.mismatch_fields for result in evaluation.component_results
    )
    with pytest.raises(ValueError, match="coverage semantics hard gate"):
        load_phase6_contract_bundle(bundle["root_path"], expected_sha256=bundle["root_sha256"])


def test_component_artifact_rehash_mismatch_makes_coverage_false(tmp_path):
    bundle = _build_bundle(tmp_path)
    source_path = bundle["source_paths"]["opponent_synthesis"]
    payload = build_r008_component_source_payloads()["opponent_synthesis"]
    payload["records"][0]["adapter_semantic_id"] = "tampered"
    source_path.write_bytes(canonical_json_bytes(payload))

    evaluation = evaluate_coverage_semantics(bundle["coverage"], tmp_path)

    assert evaluation.end_to_end_coverage is False
    synthesis = next(
        result
        for result in evaluation.component_results
        if result.component_role == "opponent_synthesis"
    )
    assert "source_sha256" in synthesis.mismatch_fields
    with pytest.raises(ValueError, match="coverage semantics hard gate"):
        load_phase6_contract_bundle(bundle["root_path"], expected_sha256=bundle["root_sha256"])


def test_crosswalk_mismatch_makes_coverage_false(tmp_path):
    def mutate(coverage):
        coverage["crosswalk_registry"]["rows"][2]["raw_sha256"] = "f" * 64

    bundle = _build_bundle(tmp_path, coverage_mutator=mutate)

    evaluation = evaluate_coverage_semantics(bundle["coverage"], tmp_path)

    assert evaluation.end_to_end_coverage is False
    ground_truth = next(
        result for result in evaluation.component_results if result.component_role == "ground_truth"
    )
    assert "normalization_crosswalk.raw_sha256" in ground_truth.mismatch_fields


def test_missing_duplicate_or_unknown_component_is_rejected(tmp_path):
    bundle = _build_bundle(tmp_path)
    missing = copy.deepcopy(bundle["coverage"])
    missing["components"].pop()
    with pytest.raises(ValueError, match="exactly five components"):
        evaluate_coverage_semantics(missing, tmp_path)

    duplicate = copy.deepcopy(bundle["coverage"])
    duplicate["components"][-1] = copy.deepcopy(duplicate["components"][0])
    with pytest.raises(ValueError, match="exactly once"):
        evaluate_coverage_semantics(duplicate, tmp_path)

    unknown = copy.deepcopy(bundle["coverage"])
    unknown["components"][0]["unexpected"] = True
    with pytest.raises(ValueError, match="extra=.*unexpected"):
        evaluate_coverage_semantics(unknown, tmp_path)


def test_artifact_rehash_mismatch_is_rejected_before_contract_use(tmp_path):
    bundle = _build_bundle(tmp_path)
    bundle["coverage_path"].write_bytes(bundle["coverage_path"].read_bytes() + b" ")

    with pytest.raises(ValueError, match="coverage_semantics_contract hash mismatch"):
        load_phase6_contract_bundle(bundle["root_path"], expected_sha256=bundle["root_sha256"])


def test_manifest_to_contract_hash_mismatch_is_rejected(tmp_path):
    def mutate(series):
        series["coverage_semantics_contract"]["sha256"] = "e" * 64

    bundle = _build_bundle(tmp_path, series_mutator=mutate)

    with pytest.raises(ValueError, match="version/hash reference mismatch"):
        load_phase6_contract_bundle(bundle["root_path"], expected_sha256=bundle["root_sha256"])


def test_selection_report_metric_substitution_is_rejected(tmp_path):
    bundle = _build_bundle(
        tmp_path,
        report_mutator=lambda report: report.update(
            {"selection_metric_id": "gto_negative_control_macro_fpr_v1"}
        ),
    )

    with pytest.raises(ValueError, match="substituted"):
        load_phase6_contract_bundle(bundle["root_path"], expected_sha256=bundle["root_sha256"])


@pytest.mark.parametrize("field", ["selection_keys", "hard_constraints"])
def test_worst_case_penalty_cannot_enter_primary_selection(field):
    payload = selection_metric_contract_payload()
    payload[field].append({"metric_id": "worst_case_penalty"})

    with pytest.raises(ValueError, match="worst_case_penalty is excluded"):
        validate_selection_metric_contract(payload)


@pytest.mark.parametrize(
    "mutator, message",
    [
        (lambda payload: payload.update({"schema_version": "selection-metrics-v2"}), "unsupported"),
        (lambda payload: payload.pop("undefined_policy"), "missing"),
        (lambda payload: payload.update({"unexpected": True}), "extra"),
        (
            lambda payload: payload["gto_fpr"].update(
                {"metric_id": "gto_negative_control_macro_fpr_v1"}
            ),
            "does not match",
        ),
    ],
)
def test_selection_contract_is_closed_world(mutator, message):
    payload = selection_metric_contract_payload()
    mutator(payload)

    with pytest.raises(ValueError, match=message):
        validate_selection_metric_contract(payload)


def test_v1_selection_bytes_hash_and_loader_semantics_remain_frozen(tmp_path):
    payload = selection_metric_contract_payload()
    raw = canonical_json_bytes(payload)

    assert len(raw) == 770
    assert sha256_bytes(raw) == "65171acaa55ae63e2b4d29b1f2c6141e0d93298201e788211c799ef628a381ce"
    assert validate_selection_metric_contract(payload) == payload

    bundle = _build_bundle(tmp_path)
    loaded = load_phase6_contract_bundle(bundle["root_path"], expected_sha256=bundle["root_sha256"])
    assert loaded.selection_contract == payload


def test_additive_v2_full_selection_contract_and_preregistration_join(tmp_path):
    selection = full_selection_metric_contract_v2_payload()
    selection_raw = canonical_json_bytes(selection)
    selection_hash = sha256_bytes(selection_raw)
    keys = tuple((item["metric_id"], item["direction"]) for item in selection["selection_keys"])

    assert selection["schema_version"] == FULL_SELECTION_CONTRACT_SCHEMA_VERSION
    assert keys == PRIMARY_SELECTION_KEYS
    assert selection["gto_fpr"]["hard_constraint"] is None
    assert selection["hard_constraints"] == []
    assert selection["worst_case_penalty_usage"] == "excluded"
    assert (
        validate_full_selection_metric_contract_v2(selection, expected_sha256=selection_hash)
        == selection
    )

    preregistration = full_selection_preregistration_v2_payload(
        selection_contract_sha256=selection_hash,
        sampling_contract_sha256="a" * 64,
    )
    preregistration_raw = canonical_json_bytes(preregistration)
    preregistration_hash = sha256_bytes(preregistration_raw)
    assert preregistration["schema_version"] == FULL_SELECTION_PREREGISTRATION_SCHEMA_VERSION
    assert (
        validate_full_selection_preregistration_v2(
            preregistration,
            selection_contract=selection,
            expected_sha256=preregistration_hash,
        )
        == preregistration
    )

    selection_path = tmp_path / "selection-v2.json"
    preregistration_path = tmp_path / "preregistration-v2.json"
    selection_path.write_bytes(selection_raw)
    preregistration_path.write_bytes(preregistration_raw)
    loaded = load_full_selection_preregistration_v2(
        preregistration_path,
        expected_sha256=preregistration_hash,
        selection_contract_path=selection_path,
        expected_selection_contract_sha256=selection_hash,
    )
    assert loaded.selection_contract == selection
    assert loaded.preregistration == preregistration


@pytest.mark.parametrize(
    "mutator",
    [
        lambda payload: payload["selection_keys"].pop(),
        lambda payload: payload["selection_keys"].reverse(),
        lambda payload: payload["selection_keys"][0].update({"direction": "descending"}),
        lambda payload: payload["selection_keys"][1].update({"metric_id": "validation_ece"}),
        lambda payload: payload["gto_fpr"].update({"hard_constraint": "0.1"}),
        lambda payload: payload["hard_constraints"].append(
            {"metric_id": GTO_FPR_METRIC_ID, "maximum": "0.1"}
        ),
        lambda payload: payload["selection_keys"].append(
            {"position": 8, "metric_id": "worst_case_penalty", "direction": "ascending"}
        ),
    ],
)
def test_v2_rejects_selection_key_threshold_and_worst_case_mutations(mutator):
    payload = full_selection_metric_contract_v2_payload()
    mutator(payload)

    with pytest.raises(ValueError):
        validate_full_selection_metric_contract_v2(payload)


def test_v2_preregistration_rejects_v1_or_mismatched_contract_reference():
    selection = full_selection_metric_contract_v2_payload()
    selection_hash = sha256_bytes(canonical_json_bytes(selection))
    preregistration = full_selection_preregistration_v2_payload(
        selection_contract_sha256=selection_hash,
        sampling_contract_sha256="b" * 64,
    )
    preregistration["selection_metric_contract"]["schema_version"] = (
        SELECTION_CONTRACT_SCHEMA_VERSION
    )

    with pytest.raises(ValueError, match="version/hash mismatch"):
        validate_full_selection_preregistration_v2(
            preregistration,
            selection_contract=selection,
        )


def _canonical_bundle_artifacts(
    bundle: dict[str, Any],
) -> tuple[CanonicalPhase6ContractArtifact, ...]:
    root = bundle["root_path"].parent
    return tuple(
        CanonicalPhase6ContractArtifact(
            relative_path=relative_path,
            raw=(root / relative_path).read_bytes(),
            expected_sha256=sha256_bytes((root / relative_path).read_bytes()),
        )
        for relative_path in bundle["artifact_relative_paths"]
    )


def test_path_and_bytes_bundle_evidence_are_equivalent_and_fresh(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path)
    root_raw = bundle["root_path"].read_bytes()
    artifacts = _canonical_bundle_artifacts(bundle)

    path_evidence = load_phase6_contract_bundle_evidence(
        bundle["root_path"], expected_sha256=bundle["root_sha256"]
    )
    bytes_evidence = load_phase6_contract_bundle_evidence_from_canonical_artifacts(
        root_raw,
        expected_sha256=bundle["root_sha256"],
        artifacts=artifacts,
    )

    assert path_evidence.root_manifest_raw == bytes_evidence.root_manifest_raw
    assert path_evidence.root_manifest_sha256 == bytes_evidence.root_manifest_sha256
    assert path_evidence.artifacts == bytes_evidence.artifacts
    assert path_evidence.provenance_sha256 == bytes_evidence.provenance_sha256
    first = validate_phase6_contract_bundle_evidence(bytes_evidence)
    second = validate_phase6_contract_bundle_evidence(bytes_evidence)
    assert first == second
    assert first is not second
    assert first.root_manifest is not second.root_manifest
    assert first.coverage_contract is not second.coverage_contract
    first.coverage_contract["coverage_matrix"]["provider_semantics_status"] = "mutated"
    object.__setattr__(first.coverage_evaluation, "end_to_end_coverage", False)
    assert second.coverage_contract["coverage_matrix"]["provider_semantics_status"] == "match"
    third = validate_phase6_contract_bundle_evidence(bytes_evidence)
    assert third.coverage_evaluation.end_to_end_coverage is True
    assert third.coverage_evaluation is not first.coverage_evaluation
    assert (
        load_phase6_contract_bundle(bundle["root_path"], expected_sha256=bundle["root_sha256"])
        == second
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda artifacts: artifacts[:-1],
        lambda artifacts: (
            *artifacts,
            CanonicalPhase6ContractArtifact(
                relative_path="extra.json",
                raw=canonical_json_bytes(
                    {"artifact_type": "phase6_semantic_source", "schema_version": "x"}
                ),
                expected_sha256=sha256_bytes(
                    canonical_json_bytes(
                        {"artifact_type": "phase6_semantic_source", "schema_version": "x"}
                    )
                ),
            ),
        ),
        lambda artifacts: (
            artifacts[0],
            CanonicalPhase6ContractArtifact(
                artifacts[0].relative_path,
                artifacts[0].raw,
                artifacts[0].expected_sha256,
            ),
            *artifacts[1:],
        ),
        lambda artifacts: (
            CanonicalPhase6ContractArtifact(
                "../escape.json",
                artifacts[0].raw,
                artifacts[0].expected_sha256,
            ),
            *artifacts[1:],
        ),
        lambda artifacts: (
            CanonicalPhase6ContractArtifact(
                artifacts[0].relative_path,
                artifacts[0].raw + b" ",
                sha256_bytes(artifacts[0].raw + b" "),
            ),
            *artifacts[1:],
        ),
    ],
)
def test_bytes_bundle_evidence_rejects_nonclosed_or_noncanonical_maps(
    tmp_path: Path,
    mutation,
) -> None:
    bundle = _build_bundle(tmp_path)
    artifacts = _canonical_bundle_artifacts(bundle)
    with pytest.raises(ValueError):
        load_phase6_contract_bundle_evidence_from_canonical_artifacts(
            bundle["root_path"].read_bytes(),
            expected_sha256=bundle["root_sha256"],
            artifacts=mutation(artifacts),
        )


def test_bundle_evidence_rejects_forgery_and_retained_mutation(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path)
    evidence = load_phase6_contract_bundle_evidence(
        bundle["root_path"], expected_sha256=bundle["root_sha256"]
    )
    forged = object.__new__(ValidatedPhase6ContractBundleEvidence)
    for field in (
        "_root_manifest_raw",
        "_root_manifest_sha256",
        "_artifacts",
        "_provenance_sha256",
        "_loader_token",
    ):
        object.__setattr__(forged, field, getattr(evidence, field))
    with pytest.raises(ValueError, match="provenance"):
        validate_phase6_contract_bundle_evidence(forged)
    with pytest.raises(TypeError):
        ValidatedPhase6ContractBundleEvidence()
    direct = validate_phase6_contract_bundle_evidence(evidence)
    with pytest.raises(ValueError):
        validate_phase6_contract_bundle_evidence(direct)  # type: ignore[arg-type]
    object.__setattr__(evidence, "_provenance_sha256", "f" * 64)
    with pytest.raises(ValueError, match="provenance"):
        validate_phase6_contract_bundle_evidence(evidence)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("artifact_type", "wrong"),
        ("schema_version", "wrong"),
        ("path", "sources/opponent_synthesis.json"),
        ("sha256", "f" * 64),
    ],
)
def test_bytes_bundle_evidence_rejects_every_nested_reference_join(
    tmp_path: Path,
    field: str,
    invalid: str,
) -> None:
    def mutate(coverage: dict[str, Any]) -> None:
        coverage["components"][0]["source_artifact"][field] = invalid

    bundle = _build_bundle(tmp_path, coverage_mutator=mutate)
    with pytest.raises(ValueError):
        load_phase6_contract_bundle_evidence_from_canonical_artifacts(
            bundle["root_path"].read_bytes(),
            expected_sha256=bundle["root_sha256"],
            artifacts=_canonical_bundle_artifacts(bundle),
        )


def test_bytes_bundle_evidence_rejects_duplicate_root_and_artifact_keys(
    tmp_path: Path,
) -> None:
    bundle = _build_bundle(tmp_path)
    root_raw = bundle["root_path"].read_bytes()
    duplicate_root = root_raw.replace(
        b'{"artifact_type":',
        b'{"artifact_type":"phase6_evaluation_manifest","artifact_type":',
        1,
    )
    with pytest.raises(ValueError):
        load_phase6_contract_bundle_evidence_from_canonical_artifacts(
            duplicate_root,
            expected_sha256=sha256_bytes(duplicate_root),
            artifacts=_canonical_bundle_artifacts(bundle),
        )

    artifacts = list(_canonical_bundle_artifacts(bundle))
    target = next(
        artifact for artifact in artifacts if artifact.relative_path == "contracts/selection.json"
    )
    selection_payload = json.loads(target.raw)
    duplicate_artifact = target.raw.replace(
        b'{"artifact_type":',
        (
            b'{"artifact_type":'
            + json.dumps(selection_payload["artifact_type"]).encode("ascii")
            + b',"artifact_type":'
        ),
        1,
    )
    artifacts[artifacts.index(target)] = CanonicalPhase6ContractArtifact(
        relative_path=target.relative_path,
        raw=duplicate_artifact,
        expected_sha256=sha256_bytes(duplicate_artifact),
    )
    with pytest.raises(ValueError):
        load_phase6_contract_bundle_evidence_from_canonical_artifacts(
            root_raw,
            expected_sha256=bundle["root_sha256"],
            artifacts=artifacts,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "root_raw",
        "root_hash",
        "artifact_tuple",
        "artifact_path",
        "artifact_raw",
        "artifact_hash",
        "provenance_hash",
    ],
)
def test_bundle_evidence_rejects_every_retained_value_mismatch(
    tmp_path: Path,
    mutation: str,
) -> None:
    bundle = _build_bundle(tmp_path)
    evidence = load_phase6_contract_bundle_evidence(
        bundle["root_path"],
        expected_sha256=bundle["root_sha256"],
    )
    if mutation == "root_raw":
        object.__setattr__(evidence, "_root_manifest_raw", evidence.root_manifest_raw + b" ")
    elif mutation == "root_hash":
        object.__setattr__(evidence, "_root_manifest_sha256", "f" * 64)
    elif mutation == "artifact_tuple":
        object.__setattr__(evidence, "_artifacts", evidence.artifacts[:-1])
    elif mutation == "provenance_hash":
        object.__setattr__(evidence, "_provenance_sha256", "f" * 64)
    else:
        artifact = evidence.artifacts[0]
        if mutation == "artifact_path":
            object.__setattr__(artifact, "relative_path", "forged.json")
        elif mutation == "artifact_raw":
            object.__setattr__(artifact, "raw", artifact.raw + b" ")
        else:
            object.__setattr__(artifact, "expected_sha256", "f" * 64)
    with pytest.raises(ValueError, match="provenance"):
        validate_phase6_contract_bundle_evidence(evidence)
