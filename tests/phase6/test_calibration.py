"""Fixture-only regression tests for the Phase 6 all-candidate evaluator."""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import replace
from decimal import Decimal, localcontext
from pathlib import Path
from typing import Any

import pytest

from phase6.calibration import (
    BOUNDARY_ABS_TOLERANCE_WIRE,
    CALIBRATION_EVALUATOR_VERSION,
    DECIMAL_PRECISION,
    DECIMAL_ROUNDING,
    ECE_BIN_EDGES_WIRE,
    EXACT_EV_INPUT_VERSION,
    GROUND_TRUTH_SCHEMA_VERSION,
    METRIC_STATUS_DEFINED,
    METRIC_STATUS_NO_ACTUAL_POSITIVES,
    METRIC_STATUS_NO_DEFINED_GROUPS,
    METRIC_STATUS_NO_PREDICTED_POSITIVES,
    TERMINAL_SNAPSHOT_SCHEMA_VERSION,
    CanonicalCalibrationArtifact,
    ExactEvObservation,
    calibration_series_id,
    evaluate_all_candidate_calibration,
    exact_ev_observation_sha256,
)
from phase6.contracts import (
    COMPONENT_ROLES,
    COVERAGE_CONTRACT_SCHEMA_VERSION,
    PREREGISTRATION_SCHEMA_VERSION,
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
    load_phase6_contract_bundle,
    selection_metric_contract_payload,
    sha256_bytes,
)
from phase6.exact_ev import PolicySlice, evaluate_exact_ev
from poker_solver.games.toy import build_toy_coin

PayloadMutator = Callable[[dict[str, Any]], None]
RecordsMutator = Callable[[list[dict[str, Any]]], None]

_ACTION_GROUP = ["BET", "BET_ALL_IN", "BET_33", "BET_75", "RAISE_ALL_IN"]
_HASHES = {str(index): str(index) * 64 for index in range(1, 9)}
_CONFIDENCES = ["0", "0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "1", "0.55"]


def _write(
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


def _contract_bundle(root: Path):
    source_payloads = build_r008_component_source_payloads()
    source_refs = {
        role: _write(
            root,
            f"sources/{role}.json",
            source_payloads[role],
            artifact_type="phase6_semantic_source",
            schema_version=SEMANTIC_SOURCE_SCHEMA_VERSION,
        )
        for role in COMPONENT_ROLES
    }
    fixture_payloads = build_r008_fixture_payloads()
    fixture_refs = {
        fixture_id: _write(
            root,
            f"fixtures/{fixture_id}.json",
            payload,
            artifact_type="phase6_semantic_fixture",
            schema_version=SEMANTIC_FIXTURE_SCHEMA_VERSION,
        )
        for fixture_id, payload in fixture_payloads.items()
    }
    coverage = build_r008_coverage_contract(source_refs, fixture_refs)
    coverage_ref = _write(
        root,
        "contracts/coverage.json",
        coverage,
        artifact_type="coverage_semantics_contract",
        schema_version=COVERAGE_CONTRACT_SCHEMA_VERSION,
    )
    selection = selection_metric_contract_payload()
    selection_ref = _write(
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
    preregistration_ref = _write(
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
    series_ref = _write(
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
    batch_ref = _write(
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
    report_ref = _write(
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
    return load_phase6_contract_bundle(path, expected_sha256=sha256_bytes(raw))


def _series_descriptor(
    *,
    epsilon: str = "0",
    baseline_rate: str = "0.2",
    detector_threshold: str = "0.5",
) -> dict[str, Any]:
    config = {
        "split": "fixture",
        "opponent_catalog_sha256": _HASHES["1"],
        "estimator_method_version": "beta-binomial-upper-tail-v1",
        "estimator_config_sha256": _HASHES["2"],
        "baseline_table_sha256": _HASHES["3"],
        "tau": "0.25",
        "sample_floor": 10,
        "detector_threshold": detector_threshold,
        "provider_threshold": "0.95",
        "exploit_provider": "nodelock-provider-r008-v2",
        "safety_alpha": "0.5",
        "execution_sampler_version": "execution-sampler-v1",
        "epsilon": epsilon,
        "epsilon_distribution_sha256": _HASHES["4"] if epsilon == "0" else _HASHES["8"],
        "horizon_set": [50],
        "repetition_set": [f"r{index:03d}" for index in range(1, 7)],
        "evaluator_version": CALIBRATION_EVALUATOR_VERSION,
        "boundary_abs_tolerance": BOUNDARY_ABS_TOLERANCE_WIRE,
        "decimal_precision": DECIMAL_PRECISION,
        "decimal_rounding": DECIMAL_ROUNDING,
        "game_id": "toy_coin",
        "ground_truth_extractor_version": "fixture-ground-truth-v1",
        "exact_ev_evaluator_version": EXACT_EV_INPUT_VERSION,
    }
    opponents = [
        {
            "opponent_id": "eval-1",
            "control_role": "evaluation",
            "strategy_artifact_sha256": _HASHES["6"],
            "equilibrium_artifact_sha256": None,
        },
        {
            "opponent_id": "gto-1",
            "control_role": "gto_negative_control",
            "strategy_artifact_sha256": _HASHES["5"],
            "equilibrium_artifact_sha256": _HASHES["5"],
        },
    ]
    dimensions = [
        {
            "rule_id": "LEAK_R008",
            "situation_key": "river_vs_check",
            "semantic_id": "leak_r008_opponent_river_vs_check_bet_upper_v1",
            "action_family_id": "bet_when_checked_to_v1",
            "opportunity_event_id": "opponent_river_decision_after_hero_check_v1",
            "action_group": _ACTION_GROUP,
            "baseline_rate": baseline_rate,
        }
    ]
    return {
        "series_id": calibration_series_id(config, opponents, dimensions),
        "config": config,
        "opponents": opponents,
        "candidate_dimensions": dimensions,
    }


def _canonical_sum(left: str, right: str) -> str:
    value = Decimal(left) + Decimal(right)
    text = format(value, "f").rstrip("0").rstrip(".")
    return text or "0"


def _eligibility(
    *, n: int, k: int, baseline: str, tau: str, confidence: str, config: dict[str, Any]
) -> dict[str, bool]:
    q = Decimal(baseline) + Decimal(tau)
    observed = Decimal(k) / Decimal(n) if n else Decimal(0)
    result = {
        "structurally_eligible": Decimal(0) < q < Decimal(1),
        "sample_gate": n >= config["sample_floor"],
        "deviation_gate": observed - Decimal(baseline) >= Decimal(tau),
        "confidence_gate": Decimal(confidence) >= Decimal(config["detector_threshold"]),
    }
    result["emitted"] = all(result.values())
    return result


def _records_for(
    descriptor: dict[str, Any], confidences: list[str]
) -> tuple[list[dict], list[dict]]:
    config = descriptor["config"]
    dimension = descriptor["candidate_dimensions"][0]
    baseline = dimension["baseline_rate"]
    q = _canonical_sum(baseline, config["tau"])
    terminal: list[dict] = []
    truth: list[dict] = []
    index = 0
    for opponent in descriptor["opponents"]:
        true_rate = "0.8" if opponent["opponent_id"] == "eval-1" else "0.2"
        for horizon in config["horizon_set"]:
            for repetition_id in config["repetition_set"]:
                confidence = confidences[index]
                index += 1
                n = 10
                k = 5
                key = {
                    "series_id": descriptor["series_id"],
                    "opponent_id": opponent["opponent_id"],
                    "rule_id": dimension["rule_id"],
                    "situation_key": dimension["situation_key"],
                    "horizon": horizon,
                    "repetition_id": repetition_id,
                }
                terminal.append(
                    {
                        **key,
                        "action_counts": {"BET": k, "CHECK": n - k},
                        "action_group": _ACTION_GROUP,
                        "n": n,
                        "k": k,
                        "baseline_rate": baseline,
                        "tau": config["tau"],
                        "q": q,
                        "posterior_confidence": confidence,
                        "candidate_eligibility": _eligibility(
                            n=n,
                            k=k,
                            baseline=baseline,
                            tau=config["tau"],
                            confidence=confidence,
                            config=config,
                        ),
                    }
                )
                truth.append(
                    {
                        **key,
                        "semantic_id": dimension["semantic_id"],
                        "action_family_id": dimension["action_family_id"],
                        "opportunity_event_id": dimension["opportunity_event_id"],
                        "action_group": _ACTION_GROUP,
                        "true_rate": true_rate,
                        "reach_weight": "0.5",
                        "strategy_artifact_sha256": opponent["strategy_artifact_sha256"],
                        "ground_truth_extractor_version": config["ground_truth_extractor_version"],
                    }
                )
    return terminal, truth


def _policy(policy: dict, opponent_id: str) -> PolicySlice:
    return PolicySlice(game_id="toy_coin", opponent_id=opponent_id, policy=policy)


def _ev_cell(opponent_id: str):
    if opponent_id == "gto-1":
        opponent = {"P1": {"X": 0.5, "Y": 0.5}}
        final = {}
    else:
        opponent = {"P1": {"X": 1.0, "Y": 0.0}}
        final = {"P0": {"A": 1.0, "B": 0.0}}
    return evaluate_exact_ev(
        build_toy_coin(),
        hero_player=0,
        opponent_policy=_policy(opponent, opponent_id),
        base_hero_policy=_policy({"P0": {"A": 0.5, "B": 0.5}}, opponent_id),
        final_hero_policy=_policy(final, opponent_id),
    )


def _exact_ev_observations(descriptors: list[dict[str, Any]]) -> list[ExactEvObservation]:
    observations = []
    for descriptor in descriptors:
        for opponent in descriptor["opponents"]:
            cell = _ev_cell(opponent["opponent_id"])
            for horizon in descriptor["config"]["horizon_set"]:
                for repetition_id in descriptor["config"]["repetition_set"]:
                    fields = {
                        "series_id": descriptor["series_id"],
                        "opponent_id": opponent["opponent_id"],
                        "horizon": horizon,
                        "repetition_id": repetition_id,
                        "cell": cell,
                    }
                    observations.append(
                        ExactEvObservation(
                            **fields,
                            sha256=exact_ev_observation_sha256(**fields),
                        )
                    )
    return observations


def _artifact(payload: dict[str, Any]) -> CanonicalCalibrationArtifact:
    raw = canonical_json_bytes(payload)
    return CanonicalCalibrationArtifact(raw=raw, expected_sha256=sha256_bytes(raw))


def _fixture(
    tmp_path: Path,
    *,
    descriptors: list[dict[str, Any]] | None = None,
    confidences: list[str] | None = None,
    terminal_mutator: RecordsMutator | None = None,
    truth_mutator: RecordsMutator | None = None,
    terminal_root_mutator: PayloadMutator | None = None,
    truth_root_mutator: PayloadMutator | None = None,
):
    bundle = _contract_bundle(tmp_path / "contract")
    descriptors = descriptors or [_series_descriptor()]
    confidences = confidences or _CONFIDENCES
    terminal_records: list[dict] = []
    truth_records: list[dict] = []
    for descriptor in descriptors:
        terminal, truth = _records_for(descriptor, confidences)
        terminal_records.extend(terminal)
        truth_records.extend(truth)
    terminal_records.sort(key=_record_key)
    truth_records.sort(key=_record_key)
    if terminal_mutator is not None:
        terminal_mutator(terminal_records)
    if truth_mutator is not None:
        truth_mutator(truth_records)
    refs = {
        "preregistration": bundle.root_manifest["preregistration"],
        "coverage_semantics_contract": bundle.root_manifest["coverage_semantics_contract"],
        "selection_metric_contract": bundle.root_manifest["selection_metric_contract"],
        "series_reference": bundle.root_manifest["series_reference"],
    }
    terminal_payload = {
        "schema_version": TERMINAL_SNAPSHOT_SCHEMA_VERSION,
        "artifact_type": "terminal_candidate_snapshots",
        "contract_refs": copy.deepcopy(refs),
        "series": descriptors,
        "records": terminal_records,
    }
    truth_payload = {
        "schema_version": GROUND_TRUTH_SCHEMA_VERSION,
        "artifact_type": "calibration_ground_truth",
        "contract_refs": copy.deepcopy(refs),
        "series_descriptor_sha256s": {
            descriptor["series_id"]: sha256_bytes(canonical_json_bytes(descriptor))
            for descriptor in descriptors
        },
        "records": truth_records,
    }
    if terminal_root_mutator is not None:
        terminal_root_mutator(terminal_payload)
    if truth_root_mutator is not None:
        truth_root_mutator(truth_payload)
    return (
        bundle,
        _artifact(terminal_payload),
        _artifact(truth_payload),
        _exact_ev_observations(descriptors),
    )


def _record_key(record: dict[str, Any]):
    return (
        record["series_id"],
        record["opponent_id"],
        record["rule_id"],
        record["situation_key"],
        record["horizon"],
        record["repetition_id"],
    )


def _evaluate(inputs):
    return evaluate_all_candidate_calibration(*inputs)


def test_all_candidate_metrics_reliability_and_exact_ev_aggregation(tmp_path):
    result = _evaluate(_fixture(tmp_path))

    assert result.evaluator_version == CALIBRATION_EVALUATOR_VERSION
    assert len(result.series) == 1
    series = result.series[0]
    assert len(series.cells) == 12
    assert len(series.atomic_groups) == 2
    assert len(series.exact_ev_sha256s) == 12
    reliability = series.micro.calibration.reliability
    assert len(reliability) == 10
    assert ECE_BIN_EDGES_WIRE == (
        "0",
        "0.1",
        "0.2",
        "0.3",
        "0.4",
        "0.5",
        "0.6",
        "0.7",
        "0.8",
        "0.9",
        "1",
    )
    assert [item.index for item in reliability] == list(range(10))
    assert [item.count for item in reliability] == [1, 1, 1, 1, 1, 2, 1, 1, 1, 2]
    assert reliability[0].lower == Decimal("0")
    assert reliability[0].upper == Decimal("0.1")
    assert reliability[0].upper_inclusive is False
    assert reliability[9].upper == Decimal("1")
    assert reliability[9].upper_inclusive is True
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        assert (
            sum((item.contribution for item in reliability), start=Decimal(0))
            == series.micro.calibration.ece.value
        )

    confidences = [Decimal(value) for value in _CONFIDENCES]
    labels = [Decimal(1)] * 6 + [Decimal(0)] * 6
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        expected_brier = sum(
            (
                (confidence - label) ** 2
                for confidence, label in zip(confidences, labels, strict=True)
            ),
            start=Decimal(0),
        ) / Decimal(12)
    assert series.micro.calibration.brier.value == expected_brier
    assert series.micro.calibration.confusion.tp == 1
    assert series.micro.calibration.confusion.fp == 6
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        assert series.micro.calibration.precision.value == Decimal(1) / Decimal(7)
        assert series.micro.calibration.recall.value == Decimal(1) / Decimal(6)
    assert series.gto_fpr.micro.numerator == 6
    assert series.gto_fpr.micro.denominator == 6
    assert series.gto_fpr.micro.value == Decimal(1)
    assert series.macro.undefined_efficiency_groups == 1
    assert series.macro.mean_cell_efficiency.value == Decimal(1)
    assert series.micro.micro_mean_cell_efficiency.value == Decimal(1)


def test_empty_bins_are_retained_with_null_diagnostics(tmp_path):
    inputs = _fixture(tmp_path, confidences=["0.55"] * 12)
    reliability = _evaluate(inputs).series[0].micro.calibration.reliability

    for index, item in enumerate(reliability):
        if index == 5:
            assert item.count == 12
            assert item.mean_confidence == Decimal("0.55")
        else:
            assert item.count == 0
            assert item.mean_confidence is None
            assert item.empirical_rate is None
            assert item.gap is None
            assert item.contribution == 0


def test_all_decimal_bin_edges_are_exact_beyond_context_precision(tmp_path):
    below_edges = [(f"0.{index - 1}{'9' * 60}", index - 1) for index in range(1, 10)]
    exact_edges = [("0", 0), *[(f"0.{index}", index) for index in range(1, 10)]]
    confidence_bins = [*below_edges, *exact_edges, ("1", 9)]
    descriptor = _series_descriptor()
    descriptor["config"]["repetition_set"] = [
        f"r{index:03d}" for index in range(1, len(confidence_bins) + 1)
    ]
    descriptor["series_id"] = calibration_series_id(
        descriptor["config"], descriptor["opponents"], descriptor["candidate_dimensions"]
    )

    result = _evaluate(
        _fixture(
            tmp_path,
            descriptors=[descriptor],
            confidences=[value for value, _ in confidence_bins] * 2,
        )
    )

    expected = {Decimal(value): bin_index for value, bin_index in confidence_bins}
    assert len(result.series[0].cells) == len(confidence_bins) * 2
    assert all(cell.bin_index == expected[cell.confidence] for cell in result.series[0].cells)


def test_unreached_and_boundary_records_are_excluded_with_weights(tmp_path):
    def terminal_mutator(records):
        record = next(item for item in records if item["opponent_id"] == "gto-1")
        record["action_counts"] = {"BET": 0, "CHECK": 0}
        record["n"] = 0
        record["k"] = 0
        record["candidate_eligibility"] = {
            "structurally_eligible": True,
            "sample_gate": False,
            "deviation_gate": False,
            "confidence_gate": Decimal(record["posterior_confidence"]) >= Decimal("0.5"),
            "emitted": False,
        }

    def truth_mutator(records):
        for record in records:
            if record["opponent_id"] == "eval-1":
                record["true_rate"] = "0.45"

    series = _evaluate(
        _fixture(
            tmp_path,
            terminal_mutator=terminal_mutator,
            truth_mutator=truth_mutator,
        )
    ).series[0]

    exclusions = series.micro.calibration.exclusions
    assert exclusions.total == 12
    assert exclusions.eligible == 5
    assert exclusions.unreached == 1
    assert exclusions.boundary_indifference == 6
    assert exclusions.structurally_ineligible == 0
    assert exclusions.unreached_weight == Decimal("0.5")
    assert exclusions.boundary_indifference_weight == Decimal("3")
    assert series.macro.undefined_brier_groups == 1
    assert series.macro.undefined_recall_groups == 2
    assert series.macro.recall.status == METRIC_STATUS_NO_DEFINED_GROUPS


def test_precision_and_recall_keep_explicit_undefined_status(tmp_path):
    descriptor = _series_descriptor(detector_threshold="1")
    inputs = _fixture(
        tmp_path,
        descriptors=[descriptor],
        confidences=["0.9"] * 12,
    )
    metrics = _evaluate(inputs).series[0].micro.calibration

    assert metrics.precision.value is None
    assert metrics.precision.status == METRIC_STATUS_NO_PREDICTED_POSITIVES
    assert metrics.recall.value == Decimal(0)
    assert metrics.recall.status == METRIC_STATUS_DEFINED
    gto_group = next(
        group for group in _evaluate(inputs).series[0].atomic_groups if group.opponent_id == "gto-1"
    )
    assert gto_group.calibration.recall.value is None
    assert gto_group.calibration.recall.status == METRIC_STATUS_NO_ACTUAL_POSITIVES


def test_macro_is_equal_group_weight_and_micro_pools_records(tmp_path):
    def terminal_mutator(records):
        eval_records = [item for item in records if item["opponent_id"] == "eval-1"]
        for record in eval_records[:-1]:
            record["action_counts"] = {"BET": 0, "CHECK": 0}
            record["n"] = 0
            record["k"] = 0
            record["candidate_eligibility"] = {
                "structurally_eligible": True,
                "sample_gate": False,
                "deviation_gate": False,
                "confidence_gate": Decimal(record["posterior_confidence"]) >= Decimal("0.5"),
                "emitted": False,
            }

    series = _evaluate(_fixture(tmp_path, terminal_mutator=terminal_mutator)).series[0]

    group_values = [group.calibration.brier.value for group in series.atomic_groups]
    assert all(value is not None for value in group_values)
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        assert series.macro.brier.value == sum(group_values, start=Decimal(0)) / Decimal(2)
    assert series.micro.calibration.brier.record_count == 7
    assert series.macro.brier.value != series.micro.calibration.brier.value


def test_epsilon_and_config_series_are_never_pooled(tmp_path):
    descriptors = [_series_descriptor(epsilon="0"), _series_descriptor(epsilon="0.1")]
    descriptors.sort(key=lambda item: item["series_id"])
    result = _evaluate(_fixture(tmp_path, descriptors=descriptors))

    assert len(result.series) == 2
    assert result.series[0].series_id != result.series[1].series_id
    assert [item.micro.calibration.brier.record_count for item in result.series] == [12, 12]


@pytest.mark.parametrize(
    ("terminal_mutator", "truth_mutator", "match"),
    [
        (lambda records: records.pop(), None, "candidate key sets differ"),
        (
            lambda records: records.append(copy.deepcopy(records[-1])),
            None,
            "duplicate terminal candidate key",
        ),
        (
            None,
            lambda records: records[0].__setitem__("action_family_id", "wrong"),
            "does not join candidate semantics",
        ),
        (
            None,
            lambda records: records[0].__setitem__("true_rate", "0.7"),
            "varies across horizon or repetition",
        ),
        (
            lambda records: records[0].__setitem__("baseline_rate", "0.3"),
            None,
            "does not join candidate dimension",
        ),
        (
            lambda records: records[0]["candidate_eligibility"].__setitem__("emitted", True),
            None,
            "cannot be reconstructed",
        ),
    ],
)
def test_closed_world_candidate_ground_truth_and_gate_joins_fail_closed(
    tmp_path, terminal_mutator, truth_mutator, match
):
    with pytest.raises(ValueError, match=match):
        _evaluate(
            _fixture(
                tmp_path,
                terminal_mutator=terminal_mutator,
                truth_mutator=truth_mutator,
            )
        )


@pytest.mark.parametrize("bad_q", ["0.450", 0.45, "4.5e-1"])
def test_decimal_tokens_must_be_canonical_fixed_point_strings(tmp_path, bad_q):
    def terminal_mutator(records):
        records[0]["q"] = bad_q

    with pytest.raises(ValueError, match="canonical fixed-point"):
        _evaluate(_fixture(tmp_path, terminal_mutator=terminal_mutator))


def test_approved_decimal_context_and_boundary_are_hard_gates(tmp_path):
    descriptor = _series_descriptor()
    descriptor["config"]["boundary_abs_tolerance"] = "0.00000000001"

    with pytest.raises(ValueError, match="approved value"):
        _evaluate(_fixture(tmp_path, descriptors=[descriptor]))


def test_rehashed_artifact_with_wrong_contract_reference_is_rejected(tmp_path):
    def mutate(payload):
        payload["contract_refs"]["series_reference"]["sha256"] = "0" * 64

    with pytest.raises(ValueError, match="contract provenance"):
        _evaluate(_fixture(tmp_path, terminal_root_mutator=mutate))


def test_external_artifact_hash_is_required_even_for_canonical_bytes(tmp_path):
    bundle, terminal, truth, ev = _fixture(tmp_path)
    forged = replace(terminal, expected_sha256="0" * 64)

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        evaluate_all_candidate_calibration(bundle, forged, truth, ev)


def test_structural_exclusion_cannot_make_gto_fpr_partially_defined(tmp_path):
    descriptor = _series_descriptor(baseline_rate="0.8")

    with pytest.raises(ValueError, match="undefined FPR"):
        _evaluate(_fixture(tmp_path, descriptors=[descriptor]))


def test_positive_gto_label_fails_closed(tmp_path):
    def mutate(records):
        for record in records:
            if record["opponent_id"] == "gto-1":
                record["true_rate"] = "0.8"

    with pytest.raises(ValueError, match="GTO negative-control record has a positive label"):
        _evaluate(_fixture(tmp_path, truth_mutator=mutate))


def test_exact_ev_session_set_hash_and_p6_5_recalculation_are_hard_gates(tmp_path):
    bundle, terminal, truth, observations = _fixture(tmp_path)
    with pytest.raises(ValueError, match="closed-world expected session key set"):
        evaluate_all_candidate_calibration(bundle, terminal, truth, observations[:-1])

    first = observations[0]
    forged_cell = replace(first.cell, efficiency=0.5)
    forged = replace(
        first,
        cell=forged_cell,
        sha256=exact_ev_observation_sha256(
            series_id=first.series_id,
            opponent_id=first.opponent_id,
            horizon=first.horizon,
            repetition_id=first.repetition_id,
            cell=forged_cell,
        ),
    )
    with pytest.raises(ValueError, match="derived values do not reconstruct"):
        evaluate_all_candidate_calibration(bundle, terminal, truth, [forged, *observations[1:]])


def test_exact_ev_observation_order_and_hash_are_fail_closed(tmp_path):
    bundle, terminal, truth, observations = _fixture(tmp_path)
    reordered = [observations[1], observations[0], *observations[2:]]
    with pytest.raises(ValueError, match="fixed session-key order"):
        evaluate_all_candidate_calibration(bundle, terminal, truth, reordered)

    forged = [replace(observations[0], sha256="0" * 64), *observations[1:]]
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        evaluate_all_candidate_calibration(bundle, terminal, truth, forged)


def test_exact_ev_observation_hash_covers_all_complete_policy_profiles(tmp_path):
    for profile_name in ("base", "final", "oracle_br"):
        bundle, terminal, truth, observations = _fixture(tmp_path / profile_name)
        getattr(observations[0].cell.profiles, profile_name).clear()

        with pytest.raises(ValueError, match="SHA-256 mismatch"):
            evaluate_all_candidate_calibration(bundle, terminal, truth, observations)
