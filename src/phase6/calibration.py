"""Fixture-only all-candidate calibration evaluation for Phase 6.

The evaluator consumes two independently hashed canonical artifacts: terminal
candidate snapshots and ground-truth rates.  It joins them closed-world against
an already validated P6-4 contract bundle and requires one P6-5 exact-EV cell
per terminal session.  It never loads a catalog, runs a league, selects a
candidate, or reads Training, Validation, or Test data.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal, localcontext
from typing import Any

from .contracts import (
    GTO_FPR_METRIC_ID,
    ValidatedPhase6ContractBundle,
    canonical_json_bytes,
    sha256_bytes,
)
from .exact_ev import (
    EV_CONSISTENCY_ABS_TOLERANCE,
    ExactEvCell,
    calculate_efficiency,
)

CALIBRATION_EVALUATOR_VERSION = "all-candidate-calibration-v1"
EXACT_EV_INPUT_VERSION = "p6-5-exact-ev-cell-v2"
TERMINAL_SNAPSHOT_SCHEMA_VERSION = "phase6-terminal-candidate-snapshots-v1"
GROUND_TRUTH_SCHEMA_VERSION = "phase6-calibration-ground-truth-v1"
BOUNDARY_ABS_TOLERANCE_WIRE = "0.000000000001"
DECIMAL_PRECISION = 50
DECIMAL_ROUNDING = "ROUND_HALF_EVEN"
ECE_BIN_EDGES_WIRE = (
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

METRIC_STATUS_DEFINED = "defined"
METRIC_STATUS_NO_ELIGIBLE_RECORDS = "undefined_no_eligible_records"
METRIC_STATUS_NO_PREDICTED_POSITIVES = "undefined_no_predicted_positive"
METRIC_STATUS_NO_ACTUAL_POSITIVES = "undefined_no_actual_positive"
METRIC_STATUS_NO_DEFINED_GROUPS = "undefined_no_defined_groups"
METRIC_STATUS_NO_DEFINED_EFFICIENCY = "undefined_no_defined_efficiency_cells"

EXCLUSION_ELIGIBLE = "eligible"
EXCLUSION_UNREACHED = "unreached"
EXCLUSION_STRUCTURAL = "structurally_ineligible"
EXCLUSION_BOUNDARY = "boundary_indifference"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$")
_SERIES_CONFIG_FIELDS = {
    "split",
    "opponent_catalog_sha256",
    "estimator_method_version",
    "estimator_config_sha256",
    "baseline_table_sha256",
    "tau",
    "sample_floor",
    "detector_threshold",
    "provider_threshold",
    "exploit_provider",
    "safety_alpha",
    "execution_sampler_version",
    "epsilon",
    "epsilon_distribution_sha256",
    "horizon_set",
    "repetition_set",
    "evaluator_version",
    "boundary_abs_tolerance",
    "decimal_precision",
    "decimal_rounding",
    "game_id",
    "ground_truth_extractor_version",
    "exact_ev_evaluator_version",
}
_OPPONENT_FIELDS = {
    "opponent_id",
    "control_role",
    "strategy_artifact_sha256",
    "equilibrium_artifact_sha256",
}
_DIMENSION_FIELDS = {
    "rule_id",
    "situation_key",
    "semantic_id",
    "action_family_id",
    "opportunity_event_id",
    "action_group",
    "baseline_rate",
}
_TERMINAL_RECORD_FIELDS = {
    "series_id",
    "opponent_id",
    "rule_id",
    "situation_key",
    "horizon",
    "repetition_id",
    "action_counts",
    "action_group",
    "n",
    "k",
    "baseline_rate",
    "tau",
    "q",
    "posterior_confidence",
    "candidate_eligibility",
}
_ELIGIBILITY_FIELDS = {
    "structurally_eligible",
    "sample_gate",
    "deviation_gate",
    "confidence_gate",
    "emitted",
}
_GROUND_TRUTH_RECORD_FIELDS = {
    "series_id",
    "opponent_id",
    "rule_id",
    "situation_key",
    "horizon",
    "repetition_id",
    "semantic_id",
    "action_family_id",
    "opportunity_event_id",
    "action_group",
    "true_rate",
    "reach_weight",
    "strategy_artifact_sha256",
    "ground_truth_extractor_version",
}

CandidateKey = tuple[str, str, str, str, int, str]
ExactEvKey = tuple[str, str, int, str]


@dataclass(frozen=True, slots=True)
class CanonicalCalibrationArtifact:
    """Exact stored bytes plus their external lowercase SHA-256 trust anchor."""

    raw: bytes
    expected_sha256: str


@dataclass(frozen=True, slots=True)
class ExactEvObservation:
    """One P6-5 exact-EV cell joined to a terminal-session identity."""

    series_id: str
    opponent_id: str
    horizon: int
    repetition_id: str
    cell: ExactEvCell
    sha256: str


@dataclass(frozen=True, slots=True)
class MetricValue:
    """A Decimal metric with an explicit defined/undefined status."""

    value: Decimal | None
    status: str
    record_count: int


@dataclass(frozen=True, slots=True)
class ReliabilityBin:
    """One fixed equal-width reliability bin."""

    index: int
    lower: Decimal
    upper: Decimal
    upper_inclusive: bool
    count: int
    mean_confidence: Decimal | None
    empirical_rate: Decimal | None
    gap: Decimal | None
    contribution: Decimal


@dataclass(frozen=True, slots=True)
class ConfusionCounts:
    """Integer classification counts for eligible candidate records."""

    tp: int
    fp: int
    fn: int
    tn: int


@dataclass(frozen=True, slots=True)
class ExclusionSummary:
    """Counts and independent ground-truth reach weights by record status."""

    total: int
    eligible: int
    unreached: int
    structurally_ineligible: int
    boundary_indifference: int
    eligible_weight: Decimal
    unreached_weight: Decimal
    structurally_ineligible_weight: Decimal
    boundary_indifference_weight: Decimal


@dataclass(frozen=True, slots=True)
class CalibrationCell:
    """Joined label and score inputs for one all-candidate terminal record."""

    key: CandidateKey
    q: Decimal
    true_rate: Decimal
    reach_weight: Decimal
    confidence: Decimal
    structurally_eligible: bool
    predicted_positive: bool
    label: int | None
    exclusion_status: str
    brier_component: Decimal | None
    bin_index: int | None


@dataclass(frozen=True, slots=True)
class CalibrationMetricSet:
    """Metrics computed directly over one record pool."""

    brier: MetricValue
    ece: MetricValue
    precision: MetricValue
    recall: MetricValue
    confusion: ConfusionCounts
    reliability: tuple[ReliabilityBin, ...]
    exclusions: ExclusionSummary


@dataclass(frozen=True, slots=True)
class AtomicGroupMetrics:
    """All metrics for one ADR-0020 atomic group."""

    opponent_id: str
    horizon: int
    calibration: CalibrationMetricSet
    mean_cell_efficiency: MetricValue


@dataclass(frozen=True, slots=True)
class MacroMetrics:
    """Equal-weight means over defined atomic groups."""

    brier: MetricValue
    ece: MetricValue
    precision: MetricValue
    recall: MetricValue
    mean_cell_efficiency: MetricValue
    undefined_brier_groups: int
    undefined_ece_groups: int
    undefined_precision_groups: int
    undefined_recall_groups: int
    undefined_efficiency_groups: int


@dataclass(frozen=True, slots=True)
class MicroMetrics:
    """Pooled all-record metrics and the separately named cell-efficiency mean."""

    calibration: CalibrationMetricSet
    micro_mean_cell_efficiency: MetricValue


@dataclass(frozen=True, slots=True)
class RateFraction:
    """An exact count ratio retained with its integer numerator and denominator."""

    numerator: int
    denominator: int
    value: Decimal | None
    status: str


@dataclass(frozen=True, slots=True)
class GtoFprGroup:
    """One GTO negative-control atomic-group FPR."""

    opponent_id: str
    horizon: int
    rate: RateFraction


@dataclass(frozen=True, slots=True)
class GtoFprSummary:
    """ADR-0021 GTO FPR diagnostics without any threshold or selection logic."""

    metric_id: str
    groups: tuple[GtoFprGroup, ...]
    macro: MetricValue
    micro: RateFraction


@dataclass(frozen=True, slots=True)
class SeriesCalibrationResult:
    """One strictly isolated epsilon/config series result."""

    series_id: str
    terminal_snapshot_sha256: str
    ground_truth_sha256: str
    exact_ev_sha256s: tuple[str, ...]
    cells: tuple[CalibrationCell, ...]
    atomic_groups: tuple[AtomicGroupMetrics, ...]
    macro: MacroMetrics
    micro: MicroMetrics
    gto_fpr: GtoFprSummary


@dataclass(frozen=True, slots=True)
class CalibrationEvaluation:
    """All series, intentionally kept separate and ordered by series ID."""

    evaluator_version: str
    series: tuple[SeriesCalibrationResult, ...]


def calibration_series_id(
    config: Mapping[str, object],
    opponents: Sequence[Mapping[str, object]],
    candidate_dimensions: Sequence[Mapping[str, object]],
) -> str:
    """Hash the full series descriptor body without selecting any config values."""
    body = {
        "config": dict(config),
        "opponents": [dict(item) for item in opponents],
        "candidate_dimensions": [dict(item) for item in candidate_dimensions],
    }
    return sha256_bytes(canonical_json_bytes(body))


def exact_ev_observation_sha256(
    *,
    series_id: str,
    opponent_id: str,
    horizon: int,
    repetition_id: str,
    cell: ExactEvCell,
) -> str:
    """Hash the complete policy, numeric, and identity surface of one P6-5 cell."""
    payload = {
        "schema_version": EXACT_EV_INPUT_VERSION,
        "series_id": series_id,
        "opponent_id": opponent_id,
        "horizon": horizon,
        "repetition_id": repetition_id,
        "game_id": cell.profiles.game_id,
        "cell_opponent_id": cell.profiles.opponent_id,
        "hero_player": cell.profiles.hero_player,
        "profiles": {
            "base": _strategy_profile_payload(cell.profiles.base, "base"),
            "final": _strategy_profile_payload(cell.profiles.final, "final"),
            "oracle_br": _strategy_profile_payload(cell.profiles.oracle_br, "oracle BR"),
        },
        "base_ev": _ev_paths_payload(cell.base_ev.production, cell.base_ev.independent_leaves),
        "final_ev": _ev_paths_payload(cell.final_ev.production, cell.final_ev.independent_leaves),
        "oracle_br_ev": _ev_paths_payload(
            cell.oracle_br_ev.production, cell.oracle_br_ev.independent_leaves
        ),
        "gain": _float_decimal_wire(cell.gain),
        "opportunity": _float_decimal_wire(cell.opportunity),
        "efficiency": None if cell.efficiency is None else _float_decimal_wire(cell.efficiency),
        "efficiency_status": cell.efficiency_status,
    }
    return sha256_bytes(canonical_json_bytes(payload))


def evaluate_all_candidate_calibration(
    contract_bundle: ValidatedPhase6ContractBundle,
    terminal_snapshots: CanonicalCalibrationArtifact,
    ground_truth: CanonicalCalibrationArtifact,
    exact_ev_observations: Sequence[ExactEvObservation],
) -> CalibrationEvaluation:
    """Validate, join, label, and aggregate fixture-only Phase 6 inputs."""
    _validate_contract_bundle(contract_bundle)
    terminal = _load_canonical_artifact(
        terminal_snapshots,
        expected_schema=TERMINAL_SNAPSHOT_SCHEMA_VERSION,
        expected_type="terminal_candidate_snapshots",
    )
    truth = _load_canonical_artifact(
        ground_truth,
        expected_schema=GROUND_TRUTH_SCHEMA_VERSION,
        expected_type="calibration_ground_truth",
    )
    expected_refs = _contract_refs(contract_bundle)
    if terminal["contract_refs"] != expected_refs or truth["contract_refs"] != expected_refs:
        raise ValueError("calibration artifact contract provenance does not join P6-4 bundle")

    descriptors = _validate_series_descriptors(terminal["series"], contract_bundle)
    descriptor_hashes = {
        series_id: sha256_bytes(canonical_json_bytes(descriptor))
        for series_id, descriptor in descriptors.items()
    }
    if truth["series_descriptor_sha256s"] != descriptor_hashes:
        raise ValueError("ground truth series descriptor hashes do not join terminal artifact")

    terminal_records = _validate_terminal_records(terminal["records"], descriptors)
    truth_records = _validate_ground_truth_records(truth["records"], descriptors)
    if set(terminal_records) != set(truth_records):
        raise ValueError("terminal snapshot and ground-truth candidate key sets differ")

    expected_candidate_keys: set[CandidateKey] = set()
    expected_ev_keys: set[ExactEvKey] = set()
    for series_id, descriptor in descriptors.items():
        candidate_keys, ev_keys = _expected_keys(series_id, descriptor)
        expected_candidate_keys.update(candidate_keys)
        expected_ev_keys.update(ev_keys)
    if set(terminal_records) != expected_candidate_keys:
        raise ValueError("terminal snapshot records are not the closed-world expected key set")

    exact_ev = _validate_exact_ev_observations(exact_ev_observations, descriptors)
    if set(exact_ev) != expected_ev_keys:
        raise ValueError("exact-EV observations are not the closed-world expected session key set")

    results = []
    for series_id in sorted(descriptors):
        series_terminal = {
            key: record for key, record in terminal_records.items() if key[0] == series_id
        }
        series_truth = {key: record for key, record in truth_records.items() if key[0] == series_id}
        series_ev = {key: item for key, item in exact_ev.items() if key[0] == series_id}
        results.append(
            _evaluate_series(
                series_id,
                descriptors[series_id],
                series_terminal,
                series_truth,
                series_ev,
                terminal_snapshots.expected_sha256,
                ground_truth.expected_sha256,
            )
        )
    return CalibrationEvaluation(CALIBRATION_EVALUATOR_VERSION, tuple(results))


def _evaluate_series(
    series_id: str,
    descriptor: dict[str, Any],
    terminal: dict[CandidateKey, dict[str, Any]],
    truth: dict[CandidateKey, dict[str, Any]],
    exact_ev: dict[ExactEvKey, ExactEvObservation],
    terminal_sha256: str,
    truth_sha256: str,
) -> SeriesCalibrationResult:
    tolerance = Decimal(BOUNDARY_ABS_TOLERANCE_WIRE)
    cells: list[CalibrationCell] = []
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        for key in sorted(terminal):
            snapshot = terminal[key]
            independent_truth = truth[key]
            q = _decimal(snapshot["q"], "terminal q")
            confidence = _decimal(snapshot["posterior_confidence"], "posterior confidence")
            true_rate = _decimal(independent_truth["true_rate"], "ground-truth true_rate")
            reach_weight = _decimal(independent_truth["reach_weight"], "ground-truth reach_weight")
            structural = snapshot["candidate_eligibility"]["structurally_eligible"]
            predicted = snapshot["candidate_eligibility"]["emitted"]
            if snapshot["n"] == 0:
                status = EXCLUSION_UNREACHED
                label = None
            elif not structural:
                status = EXCLUSION_STRUCTURAL
                label = None
            elif abs(true_rate - q) <= tolerance:
                status = EXCLUSION_BOUNDARY
                label = None
            elif true_rate > q + tolerance:
                status = EXCLUSION_ELIGIBLE
                label = 1
            elif true_rate < q - tolerance:
                status = EXCLUSION_ELIGIBLE
                label = 0
            else:  # Defensive completeness around Decimal comparison semantics.
                raise ValueError("ground-truth label could not be resolved")
            brier = None
            bin_index = None
            if label is not None:
                brier = (confidence - Decimal(label)) ** 2
                bin_index = _bin_index(confidence)
            cells.append(
                CalibrationCell(
                    key=key,
                    q=q,
                    true_rate=true_rate,
                    reach_weight=reach_weight,
                    confidence=confidence,
                    structurally_eligible=structural,
                    predicted_positive=predicted,
                    label=label,
                    exclusion_status=status,
                    brier_component=brier,
                    bin_index=bin_index,
                )
            )

    opponents = {item["opponent_id"]: item for item in descriptor["opponents"]}
    for cell in cells:
        if opponents[cell.key[1]]["control_role"] == "gto_negative_control" and cell.label == 1:
            raise ValueError("eligible GTO negative-control record has a positive label")

    group_results: list[AtomicGroupMetrics] = []
    config = descriptor["config"]
    for opponent_id in sorted(opponents):
        for horizon in config["horizon_set"]:
            group_cells = [
                cell for cell in cells if cell.key[1] == opponent_id and cell.key[4] == horizon
            ]
            group_ev = [
                item.cell
                for key, item in sorted(exact_ev.items())
                if key[1] == opponent_id and key[2] == horizon
            ]
            group_results.append(
                AtomicGroupMetrics(
                    opponent_id=opponent_id,
                    horizon=horizon,
                    calibration=_metric_set(group_cells),
                    mean_cell_efficiency=_efficiency_metric(group_ev),
                )
            )

    all_ev_cells = [item.cell for _, item in sorted(exact_ev.items())]
    micro = MicroMetrics(
        calibration=_metric_set(cells),
        micro_mean_cell_efficiency=_efficiency_metric(all_ev_cells),
    )
    macro = _macro_metrics(group_results)
    gto_fpr = _gto_fpr(cells, descriptor)
    return SeriesCalibrationResult(
        series_id=series_id,
        terminal_snapshot_sha256=terminal_sha256,
        ground_truth_sha256=truth_sha256,
        exact_ev_sha256s=tuple(item.sha256 for _, item in sorted(exact_ev.items())),
        cells=tuple(cells),
        atomic_groups=tuple(group_results),
        macro=macro,
        micro=micro,
        gto_fpr=gto_fpr,
    )


def _metric_set(cells: Sequence[CalibrationCell]) -> CalibrationMetricSet:
    eligible = [cell for cell in cells if cell.label is not None]
    brier = _mean_metric(
        [cell.brier_component for cell in eligible if cell.brier_component is not None],
        METRIC_STATUS_NO_ELIGIBLE_RECORDS,
    )
    reliability, ece = _reliability(eligible)
    confusion = ConfusionCounts(
        tp=sum(cell.predicted_positive and cell.label == 1 for cell in eligible),
        fp=sum(cell.predicted_positive and cell.label == 0 for cell in eligible),
        fn=sum(not cell.predicted_positive and cell.label == 1 for cell in eligible),
        tn=sum(not cell.predicted_positive and cell.label == 0 for cell in eligible),
    )
    precision_denominator = confusion.tp + confusion.fp
    recall_denominator = confusion.tp + confusion.fn
    precision = _ratio_metric(
        confusion.tp,
        precision_denominator,
        METRIC_STATUS_NO_PREDICTED_POSITIVES,
    )
    recall = _ratio_metric(
        confusion.tp,
        recall_denominator,
        METRIC_STATUS_NO_ACTUAL_POSITIVES,
    )
    return CalibrationMetricSet(
        brier=brier,
        ece=ece,
        precision=precision,
        recall=recall,
        confusion=confusion,
        reliability=reliability,
        exclusions=_exclusions(cells),
    )


def _macro_metrics(groups: Sequence[AtomicGroupMetrics]) -> MacroMetrics:
    brier = [group.calibration.brier for group in groups]
    ece = [group.calibration.ece for group in groups]
    precision = [group.calibration.precision for group in groups]
    recall = [group.calibration.recall for group in groups]
    efficiency = [group.mean_cell_efficiency for group in groups]
    return MacroMetrics(
        brier=_mean_defined_metrics(brier),
        ece=_mean_defined_metrics(ece),
        precision=_mean_defined_metrics(precision),
        recall=_mean_defined_metrics(recall),
        mean_cell_efficiency=_mean_defined_metrics(efficiency),
        undefined_brier_groups=sum(item.value is None for item in brier),
        undefined_ece_groups=sum(item.value is None for item in ece),
        undefined_precision_groups=sum(item.value is None for item in precision),
        undefined_recall_groups=sum(item.value is None for item in recall),
        undefined_efficiency_groups=sum(item.value is None for item in efficiency),
    )


def _gto_fpr(cells: Sequence[CalibrationCell], descriptor: dict[str, Any]) -> GtoFprSummary:
    gto_ids = [
        item["opponent_id"]
        for item in descriptor["opponents"]
        if item["control_role"] == "gto_negative_control"
    ]
    groups: list[GtoFprGroup] = []
    total_fp = 0
    total_denominator = 0
    for opponent_id in gto_ids:
        for horizon in descriptor["config"]["horizon_set"]:
            eligible = [
                cell
                for cell in cells
                if cell.key[1] == opponent_id and cell.key[4] == horizon and cell.label is not None
            ]
            if any(cell.label != 0 for cell in eligible):
                raise ValueError("GTO FPR scope contains a non-negative-control label")
            fp = sum(cell.predicted_positive for cell in eligible)
            denominator = len(eligible)
            if denominator == 0:
                raise ValueError("GTO negative-control atomic group has undefined FPR")
            rate = _rate_fraction(fp, denominator)
            groups.append(GtoFprGroup(opponent_id, horizon, rate))
            total_fp += fp
            total_denominator += denominator
    macro = _mean_metric(
        [group.rate.value for group in groups if group.rate.value is not None],
        METRIC_STATUS_NO_DEFINED_GROUPS,
    )
    return GtoFprSummary(
        metric_id=GTO_FPR_METRIC_ID,
        groups=tuple(groups),
        macro=macro,
        micro=_rate_fraction(total_fp, total_denominator),
    )


def _validate_contract_bundle(bundle: ValidatedPhase6ContractBundle) -> None:
    if not isinstance(bundle, ValidatedPhase6ContractBundle):
        raise TypeError("contract_bundle must be a validated P6-4 contract bundle")
    if not bundle.coverage_evaluation.end_to_end_coverage:
        raise ValueError("P6-4 coverage hard gate is not satisfied")
    if bundle.selection_contract.get("gto_fpr", {}).get("metric_id") != GTO_FPR_METRIC_ID:
        raise ValueError("P6-4 GTO FPR metric provenance is inconsistent")


def _contract_refs(bundle: ValidatedPhase6ContractBundle) -> dict[str, Any]:
    return {
        "preregistration": bundle.root_manifest["preregistration"],
        "coverage_semantics_contract": bundle.root_manifest["coverage_semantics_contract"],
        "selection_metric_contract": bundle.root_manifest["selection_metric_contract"],
        "series_reference": bundle.root_manifest["series_reference"],
    }


def _load_canonical_artifact(
    artifact: CanonicalCalibrationArtifact,
    *,
    expected_schema: str,
    expected_type: str,
) -> dict[str, Any]:
    if not isinstance(artifact, CanonicalCalibrationArtifact):
        raise TypeError("calibration inputs must be CanonicalCalibrationArtifact values")
    if not isinstance(artifact.raw, bytes):
        raise TypeError("canonical artifact raw value must be bytes")
    _validate_sha256(artifact.expected_sha256, "artifact expected SHA-256")
    if sha256_bytes(artifact.raw) != artifact.expected_sha256:
        raise ValueError("calibration artifact SHA-256 mismatch")
    try:
        payload = json.loads(
            artifact.raw,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON token {token!r} is forbidden")
            ),
        )
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("calibration artifact is not strict JSON") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != artifact.raw:
        raise ValueError("calibration artifact is not canonical JSON")
    expected_fields = {
        "schema_version",
        "artifact_type",
        "contract_refs",
        "records",
        "series"
        if expected_type == "terminal_candidate_snapshots"
        else "series_descriptor_sha256s",
    }
    _require_fields(payload, expected_fields, f"{expected_type} artifact")
    if payload["schema_version"] != expected_schema or payload["artifact_type"] != expected_type:
        raise ValueError(f"unsupported {expected_type} schema/type")
    return payload


def _validate_series_descriptors(
    payload: object, bundle: ValidatedPhase6ContractBundle
) -> dict[str, dict[str, Any]]:
    if not isinstance(payload, list) or not payload:
        raise ValueError("terminal artifact series must be a non-empty list")
    reason_rows = {row["reason_id"]: row for row in bundle.coverage_contract["reason_rows"]}
    action_rows = {
        row["action_family_id"]: row
        for row in bundle.coverage_contract["action_family_registry"]["rows"]
    }
    descriptors: dict[str, dict[str, Any]] = {}
    for descriptor in payload:
        _require_fields(
            descriptor, {"series_id", "config", "opponents", "candidate_dimensions"}, "series"
        )
        assert isinstance(descriptor, dict)
        config = descriptor["config"]
        _require_fields(config, _SERIES_CONFIG_FIELDS, "series config")
        assert isinstance(config, dict)
        _validate_series_config(config)
        opponents = _validate_opponents(descriptor["opponents"])
        dimensions = _validate_dimensions(
            descriptor["candidate_dimensions"], reason_rows, action_rows
        )
        series_id = descriptor["series_id"]
        if not isinstance(series_id, str) or not _SHA256.fullmatch(series_id):
            raise ValueError("series_id must be a lowercase SHA-256")
        reconstructed = calibration_series_id(config, opponents, dimensions)
        if series_id != reconstructed:
            raise ValueError("series_id does not match canonical series descriptor")
        if series_id in descriptors:
            raise ValueError("duplicate series_id")
        descriptors[series_id] = descriptor
    if [item["series_id"] for item in payload] != sorted(descriptors):
        raise ValueError("series descriptors must be in fixed series_id order")
    return descriptors


def _validate_series_config(config: dict[str, Any]) -> None:
    for field in (
        "split",
        "estimator_method_version",
        "exploit_provider",
        "execution_sampler_version",
        "game_id",
        "ground_truth_extractor_version",
        "exact_ev_evaluator_version",
    ):
        if not isinstance(config[field], str) or not config[field]:
            raise ValueError(f"series config {field} must be a non-empty string")
    for field in (
        "opponent_catalog_sha256",
        "estimator_config_sha256",
        "baseline_table_sha256",
        "epsilon_distribution_sha256",
    ):
        _validate_sha256(config[field], f"series config {field}")
    for field in ("tau", "detector_threshold", "provider_threshold", "safety_alpha", "epsilon"):
        value = _decimal(config[field], f"series config {field}")
        if not Decimal(0) <= value <= Decimal(1):
            raise ValueError(f"series config {field} must be in [0, 1]")
    if _decimal(config["tau"], "series config tau") <= 0:
        raise ValueError("series config tau must be positive")
    if not _is_positive_int(config["sample_floor"]):
        raise ValueError("series config sample_floor must be a positive integer")
    if config["evaluator_version"] != CALIBRATION_EVALUATOR_VERSION:
        raise ValueError("series config evaluator_version is unsupported")
    if config["exact_ev_evaluator_version"] != EXACT_EV_INPUT_VERSION:
        raise ValueError("series config exact_ev_evaluator_version is unsupported")
    if config["boundary_abs_tolerance"] != BOUNDARY_ABS_TOLERANCE_WIRE:
        raise ValueError("series config boundary_abs_tolerance is not the approved value")
    if config["decimal_precision"] != DECIMAL_PRECISION:
        raise ValueError("series config decimal_precision is not 50")
    if config["decimal_rounding"] != DECIMAL_ROUNDING:
        raise ValueError("series config decimal_rounding is not ROUND_HALF_EVEN")
    horizons = config["horizon_set"]
    repetitions = config["repetition_set"]
    if (
        not isinstance(horizons, list)
        or not horizons
        or any(not _is_positive_int(item) for item in horizons)
        or horizons != sorted(set(horizons))
    ):
        raise ValueError("series horizon_set must be sorted unique positive integers")
    if (
        not isinstance(repetitions, list)
        or not repetitions
        or any(not isinstance(item, str) or not item for item in repetitions)
        or repetitions != sorted(set(repetitions))
    ):
        raise ValueError("series repetition_set must be sorted unique strings")


def _validate_opponents(payload: object) -> list[dict[str, Any]]:
    if not isinstance(payload, list) or not payload:
        raise ValueError("series opponents must be a non-empty list")
    opponents: list[dict[str, Any]] = []
    for item in payload:
        _require_fields(item, _OPPONENT_FIELDS, "series opponent")
        assert isinstance(item, dict)
        opponent_id = item["opponent_id"]
        if not isinstance(opponent_id, str) or not opponent_id:
            raise ValueError("opponent_id must be a non-empty string")
        if item["control_role"] not in ("evaluation", "gto_negative_control"):
            raise ValueError("opponent control_role is unsupported")
        _validate_sha256(item["strategy_artifact_sha256"], "opponent strategy SHA-256")
        equilibrium = item["equilibrium_artifact_sha256"]
        if item["control_role"] == "gto_negative_control":
            _validate_sha256(equilibrium, "GTO equilibrium SHA-256")
            if equilibrium != item["strategy_artifact_sha256"]:
                raise ValueError("GTO control strategy does not join its equilibrium artifact")
        elif equilibrium is not None:
            _validate_sha256(equilibrium, "opponent equilibrium SHA-256")
        opponents.append(item)
    ids = [item["opponent_id"] for item in opponents]
    if ids != sorted(set(ids)):
        raise ValueError("series opponents must be sorted and unique")
    if not any(item["control_role"] == "gto_negative_control" for item in opponents):
        raise ValueError("each series requires at least one GTO negative control")
    return opponents


def _validate_dimensions(
    payload: object,
    reason_rows: Mapping[str, Mapping[str, Any]],
    action_rows: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(payload, list) or not payload:
        raise ValueError("candidate_dimensions must be a non-empty list")
    dimensions: list[dict[str, Any]] = []
    for item in payload:
        _require_fields(item, _DIMENSION_FIELDS, "candidate dimension")
        assert isinstance(item, dict)
        rule_id = item["rule_id"]
        if rule_id not in reason_rows:
            raise ValueError("candidate dimension rule does not join P6-4 semantics")
        reason = reason_rows[rule_id]
        expected = {
            "semantic_id": reason["semantic_id"],
            "action_family_id": reason["action_family_id"],
            "opportunity_event_id": reason["opportunity_event_id"],
            "situation_key": reason["situation_id"],
        }
        if any(item[field] != value for field, value in expected.items()):
            raise ValueError("candidate dimension does not match P6-4 semantic key")
        action_row = action_rows.get(item["action_family_id"])
        if action_row is None or item["action_group"] != action_row["detector_encodings"]:
            raise ValueError("candidate dimension action group does not join action registry")
        _probability(item["baseline_rate"], "candidate dimension baseline_rate")
        dimensions.append(item)
    keys = [(item["rule_id"], item["situation_key"]) for item in dimensions]
    if keys != sorted(set(keys)):
        raise ValueError("candidate dimensions must be sorted and unique")
    return dimensions


def _validate_terminal_records(
    payload: object, descriptors: Mapping[str, dict[str, Any]]
) -> dict[CandidateKey, dict[str, Any]]:
    if not isinstance(payload, list):
        raise ValueError("terminal records must be a list")
    records: dict[CandidateKey, dict[str, Any]] = {}
    for record in payload:
        _require_fields(record, _TERMINAL_RECORD_FIELDS, "terminal record")
        assert isinstance(record, dict)
        key = _candidate_key(record)
        if key in records:
            raise ValueError("duplicate terminal candidate key")
        descriptor = descriptors.get(key[0])
        if descriptor is None:
            raise ValueError("terminal record series_id is unknown")
        _validate_terminal_record(record, descriptor)
        records[key] = record
    if [_candidate_key(record) for record in payload] != sorted(records):
        raise ValueError("terminal records must be in fixed candidate-key order")
    return records


def _validate_terminal_record(record: dict[str, Any], descriptor: dict[str, Any]) -> None:
    config = descriptor["config"]
    counts = record["action_counts"]
    if (
        not isinstance(counts, dict)
        or not counts
        or any(
            not isinstance(action, str)
            or not action
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
            for action, count in counts.items()
        )
    ):
        raise ValueError("terminal action_counts must be non-negative integer counts")
    n = record["n"]
    k = record["k"]
    if isinstance(n, bool) or not isinstance(n, int) or n < 0 or sum(counts.values()) != n:
        raise ValueError("terminal n does not match action_counts")
    if isinstance(k, bool) or not isinstance(k, int):
        raise ValueError("terminal k must be an integer")
    dimension = _dimension_for(record, descriptor)
    if record["action_group"] != dimension["action_group"]:
        raise ValueError("terminal action_group does not join candidate dimension")
    expected_k = sum(counts.get(action, 0) for action in record["action_group"])
    if k != expected_k or not 0 <= k <= n:
        raise ValueError("terminal k/n do not reconstruct from action_counts")
    if record["horizon"] not in config["horizon_set"] or n > record["horizon"]:
        raise ValueError("terminal horizon is invalid for its series")
    if record["repetition_id"] not in config["repetition_set"]:
        raise ValueError("terminal repetition_id is invalid for its series")
    if record["opponent_id"] not in {item["opponent_id"] for item in descriptor["opponents"]}:
        raise ValueError("terminal opponent_id is invalid for its series")
    baseline = _probability(record["baseline_rate"], "terminal baseline_rate")
    if record["baseline_rate"] != dimension["baseline_rate"]:
        raise ValueError("terminal baseline_rate does not join candidate dimension")
    tau = _decimal(record["tau"], "terminal tau")
    if record["tau"] != config["tau"]:
        raise ValueError("terminal tau does not join series config")
    q = _decimal(record["q"], "terminal q")
    confidence = _probability(record["posterior_confidence"], "posterior confidence")
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        if q != baseline + tau:
            raise ValueError("terminal q does not reconstruct as baseline_rate + tau")
        observed = Decimal(k) / Decimal(n) if n else Decimal(0)
        expected_eligibility = {
            "structurally_eligible": Decimal(0) < q < Decimal(1),
            "sample_gate": n >= config["sample_floor"],
            "deviation_gate": observed - baseline >= tau,
            "confidence_gate": confidence
            >= _decimal(config["detector_threshold"], "detector threshold"),
        }
        expected_eligibility["emitted"] = all(expected_eligibility.values())
    eligibility = record["candidate_eligibility"]
    _require_fields(eligibility, _ELIGIBILITY_FIELDS, "terminal candidate_eligibility")
    assert isinstance(eligibility, dict)
    if any(type(value) is not bool for value in eligibility.values()):
        raise ValueError("terminal eligibility fields must be JSON booleans")
    if eligibility != expected_eligibility:
        raise ValueError("terminal eligibility/gate/emit state cannot be reconstructed")


def _validate_ground_truth_records(
    payload: object, descriptors: Mapping[str, dict[str, Any]]
) -> dict[CandidateKey, dict[str, Any]]:
    if not isinstance(payload, list):
        raise ValueError("ground-truth records must be a list")
    records: dict[CandidateKey, dict[str, Any]] = {}
    for record in payload:
        _require_fields(record, _GROUND_TRUTH_RECORD_FIELDS, "ground-truth record")
        assert isinstance(record, dict)
        key = _candidate_key(record)
        if key in records:
            raise ValueError("duplicate ground-truth candidate key")
        descriptor = descriptors.get(key[0])
        if descriptor is None:
            raise ValueError("ground-truth series_id is unknown")
        dimension = _dimension_for(record, descriptor)
        opponent = next(
            (item for item in descriptor["opponents"] if item["opponent_id"] == key[1]), None
        )
        if opponent is None:
            raise ValueError("ground-truth opponent does not join series")
        for field in ("semantic_id", "action_family_id", "opportunity_event_id", "action_group"):
            if record[field] != dimension[field]:
                raise ValueError("ground truth does not join candidate semantics")
        if record["strategy_artifact_sha256"] != opponent["strategy_artifact_sha256"]:
            raise ValueError("ground truth does not join opponent strategy provenance")
        if (
            record["ground_truth_extractor_version"]
            != descriptor["config"]["ground_truth_extractor_version"]
        ):
            raise ValueError("ground truth extractor version does not join series config")
        _probability(record["true_rate"], "ground-truth true_rate")
        _probability(record["reach_weight"], "ground-truth reach_weight")
        records[key] = record
    if [_candidate_key(record) for record in payload] != sorted(records):
        raise ValueError("ground-truth records must be in fixed candidate-key order")
    invariant_truth: dict[tuple[str, str, str, str], tuple[object, ...]] = {}
    for key, record in records.items():
        invariant_key = key[:4]
        signature = (
            record["semantic_id"],
            record["action_family_id"],
            record["opportunity_event_id"],
            record["action_group"],
            record["true_rate"],
            record["reach_weight"],
            record["strategy_artifact_sha256"],
            record["ground_truth_extractor_version"],
        )
        if invariant_key in invariant_truth and invariant_truth[invariant_key] != signature:
            raise ValueError("ground truth varies across horizon or repetition")
        invariant_truth[invariant_key] = signature
    return records


def _validate_exact_ev_observations(
    observations: Sequence[ExactEvObservation], descriptors: Mapping[str, dict[str, Any]]
) -> dict[ExactEvKey, ExactEvObservation]:
    result: dict[ExactEvKey, ExactEvObservation] = {}
    for item in observations:
        if not isinstance(item, ExactEvObservation):
            raise TypeError("exact_ev_observations must contain ExactEvObservation values")
        key = (item.series_id, item.opponent_id, item.horizon, item.repetition_id)
        if key in result:
            raise ValueError("duplicate exact-EV session key")
        descriptor = descriptors.get(item.series_id)
        if descriptor is None:
            raise ValueError("exact-EV series_id is unknown")
        config = descriptor["config"]
        if item.cell.profiles.game_id != config["game_id"]:
            raise ValueError("exact-EV game identity does not join series config")
        if item.cell.profiles.opponent_id != item.opponent_id:
            raise ValueError("exact-EV opponent identity does not join session key")
        if (
            item.horizon not in config["horizon_set"]
            or item.repetition_id not in config["repetition_set"]
        ):
            raise ValueError("exact-EV session dimensions do not join series config")
        if item.opponent_id not in {
            opponent["opponent_id"] for opponent in descriptor["opponents"]
        }:
            raise ValueError("exact-EV opponent is outside the series closed world")
        for label, paths in (
            ("base", item.cell.base_ev),
            ("final", item.cell.final_ev),
            ("oracle BR", item.cell.oracle_br_ev),
        ):
            if not math.isclose(
                paths.production,
                paths.independent_leaves,
                rel_tol=0.0,
                abs_tol=EV_CONSISTENCY_ABS_TOLERANCE,
            ):
                raise ValueError(f"exact-EV {label} paths fail the P6-5 consistency gate")
        recalculated = calculate_efficiency(
            base_ev=item.cell.base_ev.production,
            final_ev=item.cell.final_ev.production,
            oracle_br_ev=item.cell.oracle_br_ev.production,
        )
        if (
            recalculated.gain != item.cell.gain
            or recalculated.opportunity != item.cell.opportunity
            or recalculated.efficiency != item.cell.efficiency
            or recalculated.efficiency_status != item.cell.efficiency_status
        ):
            raise ValueError("exact-EV derived values do not reconstruct through P6-5")
        _validate_sha256(item.sha256, "exact-EV observation SHA-256")
        expected_sha = exact_ev_observation_sha256(
            series_id=item.series_id,
            opponent_id=item.opponent_id,
            horizon=item.horizon,
            repetition_id=item.repetition_id,
            cell=item.cell,
        )
        if item.sha256 != expected_sha:
            raise ValueError("exact-EV observation SHA-256 mismatch")
        result[key] = item
    if list(result) != sorted(result):
        raise ValueError("exact-EV observations must be in fixed session-key order")
    return result


def _expected_keys(
    series_id: str, descriptor: dict[str, Any]
) -> tuple[set[CandidateKey], set[ExactEvKey]]:
    opponent_ids = [item["opponent_id"] for item in descriptor["opponents"]]
    dimensions = descriptor["candidate_dimensions"]
    config = descriptor["config"]
    candidate_keys = {
        (
            series_id,
            opponent_id,
            dimension["rule_id"],
            dimension["situation_key"],
            horizon,
            repetition,
        )
        for opponent_id in opponent_ids
        for dimension in dimensions
        for horizon in config["horizon_set"]
        for repetition in config["repetition_set"]
    }
    ev_keys = {
        (series_id, opponent_id, horizon, repetition)
        for opponent_id in opponent_ids
        for horizon in config["horizon_set"]
        for repetition in config["repetition_set"]
    }
    return candidate_keys, ev_keys


def _dimension_for(record: Mapping[str, Any], descriptor: dict[str, Any]) -> dict[str, Any]:
    matches = [
        item
        for item in descriptor["candidate_dimensions"]
        if item["rule_id"] == record["rule_id"] and item["situation_key"] == record["situation_key"]
    ]
    if len(matches) != 1:
        raise ValueError("record rule/situation does not join exactly one candidate dimension")
    return matches[0]


def _candidate_key(record: Mapping[str, Any]) -> CandidateKey:
    series_id = record.get("series_id")
    opponent_id = record.get("opponent_id")
    rule_id = record.get("rule_id")
    situation_key = record.get("situation_key")
    horizon = record.get("horizon")
    repetition_id = record.get("repetition_id")
    if any(
        not isinstance(item, str) or not item
        for item in (series_id, opponent_id, rule_id, situation_key, repetition_id)
    ):
        raise ValueError("candidate key string fields must be non-empty")
    if not _is_positive_int(horizon):
        raise ValueError("candidate key horizon must be a positive integer")
    return (series_id, opponent_id, rule_id, situation_key, horizon, repetition_id)


def _efficiency_metric(cells: Sequence[ExactEvCell]) -> MetricValue:
    values = [Decimal.from_float(cell.efficiency) for cell in cells if cell.efficiency is not None]
    return _mean_metric(values, METRIC_STATUS_NO_DEFINED_EFFICIENCY)


def _mean_defined_metrics(metrics: Sequence[MetricValue]) -> MetricValue:
    values = [item.value for item in metrics if item.value is not None]
    return _mean_metric(values, METRIC_STATUS_NO_DEFINED_GROUPS)


def _mean_metric(values: Sequence[Decimal], empty_status: str) -> MetricValue:
    if not values:
        return MetricValue(None, empty_status, 0)
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        total = Decimal(0)
        for value in values:
            total += value
        mean = total / Decimal(len(values))
    return MetricValue(mean, METRIC_STATUS_DEFINED, len(values))


def _ratio_metric(numerator: int, denominator: int, undefined_status: str) -> MetricValue:
    if denominator == 0:
        return MetricValue(None, undefined_status, 0)
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        value = Decimal(numerator) / Decimal(denominator)
    return MetricValue(value, METRIC_STATUS_DEFINED, denominator)


def _rate_fraction(numerator: int, denominator: int) -> RateFraction:
    if denominator == 0:
        return RateFraction(numerator, denominator, None, METRIC_STATUS_NO_ELIGIBLE_RECORDS)
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        value = Decimal(numerator) / Decimal(denominator)
    return RateFraction(numerator, denominator, value, METRIC_STATUS_DEFINED)


def _reliability(
    cells: Sequence[CalibrationCell],
) -> tuple[tuple[ReliabilityBin, ...], MetricValue]:
    bins: list[ReliabilityBin] = []
    total_count = len(cells)
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        for index in range(10):
            selected = [cell for cell in cells if cell.bin_index == index]
            lower = Decimal(ECE_BIN_EDGES_WIRE[index])
            upper = Decimal(ECE_BIN_EDGES_WIRE[index + 1])
            if not selected:
                bins.append(
                    ReliabilityBin(index, lower, upper, index == 9, 0, None, None, None, Decimal(0))
                )
                continue
            mean_confidence = _ordered_decimal_mean([cell.confidence for cell in selected])
            empirical_rate = _ordered_decimal_mean(
                [Decimal(cell.label) for cell in selected if cell.label is not None]
            )
            gap = abs(mean_confidence - empirical_rate)
            contribution = Decimal(len(selected)) / Decimal(total_count) * gap
            bins.append(
                ReliabilityBin(
                    index,
                    lower,
                    upper,
                    index == 9,
                    len(selected),
                    mean_confidence,
                    empirical_rate,
                    gap,
                    contribution,
                )
            )
        ece_value = (
            None
            if total_count == 0
            else sum((item.contribution for item in bins), start=Decimal(0))
        )
    ece = MetricValue(
        ece_value,
        METRIC_STATUS_DEFINED if ece_value is not None else METRIC_STATUS_NO_ELIGIBLE_RECORDS,
        total_count,
    )
    return tuple(bins), ece


def _ordered_decimal_mean(values: Sequence[Decimal]) -> Decimal:
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        total = Decimal(0)
        for value in values:
            total += value
        return total / Decimal(len(values))


def _exclusions(cells: Sequence[CalibrationCell]) -> ExclusionSummary:
    by_status = {
        status: [cell for cell in cells if cell.exclusion_status == status]
        for status in (
            EXCLUSION_ELIGIBLE,
            EXCLUSION_UNREACHED,
            EXCLUSION_STRUCTURAL,
            EXCLUSION_BOUNDARY,
        )
    }
    return ExclusionSummary(
        total=len(cells),
        eligible=len(by_status[EXCLUSION_ELIGIBLE]),
        unreached=len(by_status[EXCLUSION_UNREACHED]),
        structurally_ineligible=len(by_status[EXCLUSION_STRUCTURAL]),
        boundary_indifference=len(by_status[EXCLUSION_BOUNDARY]),
        eligible_weight=_weight_sum(by_status[EXCLUSION_ELIGIBLE]),
        unreached_weight=_weight_sum(by_status[EXCLUSION_UNREACHED]),
        structurally_ineligible_weight=_weight_sum(by_status[EXCLUSION_STRUCTURAL]),
        boundary_indifference_weight=_weight_sum(by_status[EXCLUSION_BOUNDARY]),
    )


def _weight_sum(cells: Sequence[CalibrationCell]) -> Decimal:
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        total = Decimal(0)
        for cell in cells:
            total += cell.reach_weight
        return total


def _bin_index(confidence: Decimal) -> int:
    for index, upper_wire in enumerate(ECE_BIN_EDGES_WIRE[1:-1]):
        if confidence < Decimal(upper_wire):
            return index
    return 9


def _decimal(value: object, label: str) -> Decimal:
    if not isinstance(value, str) or not _CANONICAL_DECIMAL.fullmatch(value):
        raise ValueError(f"{label} must be a canonical fixed-point decimal string")
    result = Decimal(value)
    if not result.is_finite():
        raise ValueError(f"{label} must be finite")
    return result


def _probability(value: object, label: str) -> Decimal:
    result = _decimal(value, label)
    if not Decimal(0) <= result <= Decimal(1):
        raise ValueError(f"{label} must be in [0, 1]")
    return result


def _float_decimal_wire(value: float) -> str:
    if not isinstance(value, float) or not math.isfinite(value):
        raise ValueError("exact-EV numeric provenance must be finite floats")
    decimal_value = Decimal.from_float(value)
    if decimal_value == 0:
        return "0"
    text = format(decimal_value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text


def _strategy_profile_payload(
    profile: Mapping[str, Mapping[str, float]], label: str
) -> list[dict[str, object]]:
    if not isinstance(profile, Mapping):
        raise TypeError(f"exact-EV {label} profile must be a mapping")
    payload: list[dict[str, object]] = []
    for infoset in sorted(profile):
        if not isinstance(infoset, str):
            raise TypeError(f"exact-EV {label} profile infoset IDs must be strings")
        distribution = profile[infoset]
        if not isinstance(distribution, Mapping):
            raise TypeError(f"exact-EV {label} profile action distributions must be mappings")
        actions: list[dict[str, str]] = []
        for action in sorted(distribution):
            if not isinstance(action, str):
                raise TypeError(f"exact-EV {label} profile action IDs must be strings")
            actions.append(
                {
                    "action": action,
                    "probability": _float_decimal_wire(distribution[action]),
                }
            )
        payload.append({"infoset": infoset, "actions": actions})
    return payload


def _ev_paths_payload(production: float, independent: float) -> dict[str, str]:
    return {
        "production": _float_decimal_wire(production),
        "independent_leaves": _float_decimal_wire(independent),
    }


def _validate_sha256(value: object, label: str) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{label} must be lowercase hexadecimal")


def _require_fields(payload: object, expected: set[str], label: str) -> None:
    if not isinstance(payload, dict) or set(payload) != expected:
        raise ValueError(f"{label} fields do not match the closed-world schema")


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


__all__ = [
    "BOUNDARY_ABS_TOLERANCE_WIRE",
    "CALIBRATION_EVALUATOR_VERSION",
    "DECIMAL_PRECISION",
    "DECIMAL_ROUNDING",
    "ECE_BIN_EDGES_WIRE",
    "EXCLUSION_BOUNDARY",
    "EXCLUSION_ELIGIBLE",
    "EXCLUSION_STRUCTURAL",
    "EXCLUSION_UNREACHED",
    "EXACT_EV_INPUT_VERSION",
    "GROUND_TRUTH_SCHEMA_VERSION",
    "METRIC_STATUS_DEFINED",
    "METRIC_STATUS_NO_ACTUAL_POSITIVES",
    "METRIC_STATUS_NO_DEFINED_EFFICIENCY",
    "METRIC_STATUS_NO_DEFINED_GROUPS",
    "METRIC_STATUS_NO_ELIGIBLE_RECORDS",
    "METRIC_STATUS_NO_PREDICTED_POSITIVES",
    "TERMINAL_SNAPSHOT_SCHEMA_VERSION",
    "AtomicGroupMetrics",
    "CalibrationCell",
    "CalibrationEvaluation",
    "CalibrationMetricSet",
    "CanonicalCalibrationArtifact",
    "ConfusionCounts",
    "ExactEvObservation",
    "ExclusionSummary",
    "GtoFprGroup",
    "GtoFprSummary",
    "MacroMetrics",
    "MetricValue",
    "MicroMetrics",
    "RateFraction",
    "ReliabilityBin",
    "SeriesCalibrationResult",
    "calibration_series_id",
    "evaluate_all_candidate_calibration",
    "exact_ev_observation_sha256",
]
