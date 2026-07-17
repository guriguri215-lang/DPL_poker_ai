"""Closed-world Phase 6 evaluation contracts for ADR-0020 and ADR-0021.

This module validates fixture-only contract bundles. It does not load an
opponent catalog, run a league, select a candidate, or create evaluation
results. The small reference artifacts model the joins that later runners must
honor without pre-empting their implementation.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import opponents.ground_truth as ground_truth_module
import opponents.synthesis as synthesis_module
from poker_ai.exploit import LEAK_NODELOCK_MAPPINGS
from poker_ai.leak import LeakDetectorConfig, default_action_baseline_table
from poker_core.reason_ontology import get_ontology

COVERAGE_CONTRACT_SCHEMA_VERSION = "coverage-semantics-v1"
SELECTION_CONTRACT_SCHEMA_VERSION = "selection-metrics-v1"
FULL_SELECTION_CONTRACT_SCHEMA_VERSION = "selection-metrics-v2"
SEMANTIC_SOURCE_SCHEMA_VERSION = "phase6-semantic-source-v1"
SEMANTIC_FIXTURE_SCHEMA_VERSION = "phase6-semantic-fixture-v1"
PREREGISTRATION_SCHEMA_VERSION = "phase6-evaluation-preregistration-v1"
FULL_SELECTION_PREREGISTRATION_SCHEMA_VERSION = "phase6-evaluation-preregistration-v2"
ROOT_MANIFEST_SCHEMA_VERSION = "phase6-evaluation-manifest-v1"
SERIES_REFERENCE_SCHEMA_VERSION = "phase6-evaluation-series-reference-v1"
VALIDATION_BATCH_REFERENCE_SCHEMA_VERSION = "phase6-validation-batch-reference-v1"
SELECTION_REPORT_REFERENCE_SCHEMA_VERSION = "phase6-selection-report-reference-v1"

GTO_FPR_METRIC_ID = "gto_negative_control_micro_fpr_v1"
R008_SEMANTIC_ID = "leak_r008_opponent_river_vs_check_bet_upper_v1"

COMPONENT_ROLES: tuple[str, ...] = (
    "reason_ontology",
    "baseline_detector",
    "ground_truth",
    "opponent_synthesis",
    "exploit_provider",
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SEMANTIC_KEY_FIELDS = {
    "semantic_id",
    "reason_id",
    "subject_actor",
    "street",
    "situation_id",
    "opportunity_event_id",
    "action_family_id",
    "statistical_direction",
    "deviation_expression_id",
    "provider_lock_subject",
    "provider_lock_situation_id",
    "provider_lock_action_family_id",
    "target_transform_id",
}
_SOURCE_REF_FIELDS = {"artifact_type", "schema_version", "path", "sha256"}

R008_SEMANTIC_KEY: dict[str, str] = {
    "semantic_id": R008_SEMANTIC_ID,
    "reason_id": "LEAK_R008",
    "subject_actor": "opponent",
    "street": "river",
    "situation_id": "river_vs_check",
    "opportunity_event_id": "opponent_river_decision_after_hero_check_v1",
    "action_family_id": "bet_when_checked_to_v1",
    "statistical_direction": "upper",
    "deviation_expression_id": "opponent_rate_minus_baseline_rate_ge_tau_v1",
    "provider_lock_subject": "opponent",
    "provider_lock_situation_id": "river_vs_check",
    "provider_lock_action_family_id": "bet_when_checked_to_v1",
    "target_transform_id": "identity_observed_rate_to_locked_probability_v1",
}

_COMPONENT_VERSIONS = {
    "reason_ontology": "reason-ontology-1.1.0",
    "baseline_detector": "action-baseline-detector-r008-v1",
    "ground_truth": "opponent-ground-truth-r008-v1",
    "opponent_synthesis": "nodelock-opponent-config-v1",
    "exploit_provider": "nodelock-provider-r008-v2",
}

_EXPECTED_R008_RAW: dict[str, dict[str, Any]] = {
    "reason_ontology": {
        "reason_id": "LEAK_R008",
        "label": "bet_too_often_when_checked_to",
    },
    "baseline_detector": {
        "reason_id": "LEAK_R008",
        "leak_type": "bet_too_often_when_checked_to",
        "subject_actor": "opponent",
        "street": "river",
        "situation_key": "river_vs_check",
        "action_group": ["BET", "BET_ALL_IN", "BET_33", "BET_75", "RAISE_ALL_IN"],
        "opportunity_source": "ActionStats.opportunities",
        "estimator_tail": "upper",
    },
    "ground_truth": {
        "reason_id": "LEAK_R008",
        "subject_actor": "opponent",
        "street": "river",
        "phase": "vs_check",
        "action": "BET",
        "opportunity_source": "reach_weighted_opponent_decision_after_hero_check",
        "statistical_direction": "upper",
    },
    "opponent_synthesis": {
        "reason_id": "LEAK_R008",
        "subject_actor": "opponent",
        "street": "river",
        "phase": "vs_check",
        "action": "BET",
    },
    "exploit_provider": {
        "reason_id": "LEAK_R008",
        "subject_actor": "opponent",
        "street": "river",
        "phase": "vs_check",
        "action": "BET",
        "target_source": "observed_rate",
        "hero_response_phase": "vs_bet",
    },
}

_R008_FIXTURE_SPECS: tuple[dict[str, Any], ...] = (
    {
        "fixture_id": "r008-ground-truth-positive-v1",
        "fixture_kind": "positive",
        "component_role": "ground_truth",
        "input_record": {
            "adapter_semantic_id": R008_SEMANTIC_ID,
            "raw": _EXPECTED_R008_RAW["ground_truth"],
        },
        "expected_result": {"matched": True, "mismatch_fields": []},
    },
    {
        "fixture_id": "r008-ground-truth-negative-action-v1",
        "fixture_kind": "negative",
        "component_role": "ground_truth",
        "input_record": {
            "adapter_semantic_id": R008_SEMANTIC_ID,
            "raw": {**_EXPECTED_R008_RAW["ground_truth"], "action": "FOLD"},
        },
        "expected_result": {"matched": False, "mismatch_fields": ["raw"]},
    },
)

_ACTION_FAMILY_REGISTRY = {
    "registry_version": "action-family-registry-v1",
    "rows": [
        {
            "action_family_id": "bet_when_checked_to_v1",
            "detector_encodings": [
                "BET",
                "BET_ALL_IN",
                "BET_33",
                "BET_75",
                "RAISE_ALL_IN",
            ],
            "solver_encodings": ["BET"],
        }
    ],
}

_SELECTION_CONTRACT: dict[str, Any] = {
    "schema_version": SELECTION_CONTRACT_SCHEMA_VERSION,
    "artifact_type": "selection_metric_contract",
    "gto_fpr": {
        "metric_id": GTO_FPR_METRIC_ID,
        "usage": "sort_key_only",
        "hard_constraint": None,
        "aggregation": "micro",
        "record_scope": "gto_negative_control_terminal_snapshots_v1",
        "numerator": "false_positive_count",
        "denominator": "false_positive_count_plus_true_negative_count",
        "comparison": "integer_cross_multiplication",
        "rate_tolerance": None,
    },
    "selection_keys": [{"position": 3, "metric_id": GTO_FPR_METRIC_ID, "direction": "ascending"}],
    "hard_constraints": [],
    "atomic_group": ["opponent_id", "horizon"],
    "undefined_policy": "fail_closed_no_partial_group_drop",
    "selection_order_status": "pending_human_approval_except_frozen_key_3",
    "worst_case_penalty_usage": "excluded",
}

_FULL_SELECTION_KEYS: tuple[tuple[str, str], ...] = (
    ("validation_macro_brier", "ascending"),
    ("validation_micro_brier", "ascending"),
    (GTO_FPR_METRIC_ID, "ascending"),
    ("validation_macro_exploitation_efficiency", "descending"),
    ("validation_macro_recall", "descending"),
    ("validation_macro_precision", "descending"),
    ("candidate_id", "lexicographic_ascending"),
)

_FULL_SELECTION_CONTRACT: dict[str, Any] = {
    "schema_version": FULL_SELECTION_CONTRACT_SCHEMA_VERSION,
    "artifact_type": "selection_metric_contract",
    "gto_fpr": copy.deepcopy(_SELECTION_CONTRACT["gto_fpr"]),
    "selection_keys": [
        {"position": position, "metric_id": metric_id, "direction": direction}
        for position, (metric_id, direction) in enumerate(_FULL_SELECTION_KEYS, start=1)
    ],
    "hard_constraints": [],
    "atomic_group": ["opponent_id", "horizon"],
    "undefined_policy": {
        "gto_fpr": "fail_closed_no_partial_group_drop",
        "selection_key_positions_4_through_6": "rank_undefined_as_worst",
    },
    "selection_order_status": "approved_adr_0021_0022",
    "worst_case_penalty_usage": "excluded",
}

_ARTIFACT_VERSIONS = {
    "coverage_semantics_contract": COVERAGE_CONTRACT_SCHEMA_VERSION,
    "selection_metric_contract": SELECTION_CONTRACT_SCHEMA_VERSION,
    "phase6_evaluation_preregistration": PREREGISTRATION_SCHEMA_VERSION,
    "phase6_evaluation_series_reference": SERIES_REFERENCE_SCHEMA_VERSION,
    "phase6_validation_batch_reference": VALIDATION_BATCH_REFERENCE_SCHEMA_VERSION,
    "phase6_selection_report_reference": SELECTION_REPORT_REFERENCE_SCHEMA_VERSION,
    "phase6_semantic_source": SEMANTIC_SOURCE_SCHEMA_VERSION,
    "phase6_semantic_fixture": SEMANTIC_FIXTURE_SCHEMA_VERSION,
}


@dataclass(frozen=True, slots=True)
class ComponentCoverageResult:
    """One component's independently reconstructed semantic match."""

    component_role: str
    source_sha256: str
    matched: bool
    mismatch_fields: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CoverageEvaluation:
    """Diagnostic result used by the strict loader's coverage hard gate."""

    component_results: tuple[ComponentCoverageResult, ...]
    matrix_matches_reconstruction: bool
    end_to_end_coverage: bool


@dataclass(frozen=True, slots=True)
class ValidatedPhase6ContractBundle:
    """Canonical fixture references returned after every hard gate passes."""

    root_manifest: dict[str, Any]
    preregistration: dict[str, Any]
    coverage_contract: dict[str, Any]
    selection_contract: dict[str, Any]
    series_reference: dict[str, Any]
    validation_batch_reference: dict[str, Any]
    selection_report_reference: dict[str, Any]
    coverage_evaluation: CoverageEvaluation


@dataclass(frozen=True, slots=True)
class ValidatedFullSelectionPreregistration:
    """Canonical additive v2 contract and its Validation preregistration."""

    preregistration: dict[str, Any]
    selection_contract: dict[str, Any]
    preregistration_sha256: str
    selection_contract_sha256: str


def canonical_json_bytes(payload: object) -> bytes:
    """Return the unique ADR-0020 JSON byte representation with one trailing LF."""
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    """Return a lowercase SHA-256 digest for exact stored bytes."""
    return hashlib.sha256(payload).hexdigest()


def artifact_ref(
    *, artifact_type: str, schema_version: str, path: str, payload: object
) -> dict[str, str]:
    """Build a version/hash/path reference for a canonical fixture artifact."""
    reference = {
        "artifact_type": artifact_type,
        "schema_version": schema_version,
        "path": path,
        "sha256": sha256_bytes(canonical_json_bytes(payload)),
    }
    _validate_artifact_ref(reference, artifact_type, schema_version)
    return reference


def build_r008_component_source_payloads() -> dict[str, dict[str, Any]]:
    """Extract fixture source facts from the five current R008 components.

    The declared semantic ID is recorded but never used to choose a crosswalk.
    The strict loader derives the semantic key from the raw record and the
    versioned crosswalk instead.
    """
    ontology = get_ontology()
    ontology_entry = ontology.get("LEAK_R008")
    baseline_matches = [
        rule for rule in default_action_baseline_table().rules if rule.reason_id == "LEAK_R008"
    ]
    if len(baseline_matches) != 1:
        raise ValueError("baseline detector must expose exactly one LEAK_R008 rule")
    baseline = baseline_matches[0]
    ground_phase, ground_action = ground_truth_module._GROUND_TRUTH_TARGETS["LEAK_R008"]
    synthesis = synthesis_module._LEAK_MAPPINGS["LEAK_R008"]
    provider = LEAK_NODELOCK_MAPPINGS["LEAK_R008"]

    raw_by_role: dict[str, dict[str, Any]] = {
        "reason_ontology": {
            "reason_id": ontology_entry.id,
            "label": ontology_entry.label,
        },
        "baseline_detector": {
            "reason_id": baseline.reason_id,
            "leak_type": baseline.leak_type,
            "subject_actor": "opponent",
            "street": "river",
            "situation_key": "river_vs_check",
            "action_group": list(baseline.action_group),
            "opportunity_source": "ActionStats.opportunities",
            "estimator_tail": LeakDetectorConfig().tail,
        },
        "ground_truth": {
            "reason_id": "LEAK_R008",
            "subject_actor": "opponent",
            "street": "river",
            "phase": ground_phase,
            "action": ground_action,
            "opportunity_source": "reach_weighted_opponent_decision_after_hero_check",
            "statistical_direction": "upper",
        },
        "opponent_synthesis": {
            "reason_id": "LEAK_R008",
            "subject_actor": "opponent",
            "street": "river",
            "phase": synthesis.phase,
            "action": synthesis.action,
        },
        "exploit_provider": {
            "reason_id": provider.reason_id,
            "subject_actor": provider.actor,
            "street": "river",
            "phase": provider.phase,
            "action": provider.action,
            "target_source": provider.target_source,
            "hero_response_phase": "vs_bet",
        },
    }
    payloads: dict[str, dict[str, Any]] = {}
    for role in COMPONENT_ROLES:
        component_version = _COMPONENT_VERSIONS[role]
        if role == "reason_ontology":
            component_version = f"reason-ontology-{ontology.ontology_version}"
        payloads[role] = {
            "schema_version": SEMANTIC_SOURCE_SCHEMA_VERSION,
            "artifact_type": "phase6_semantic_source",
            "component_role": role,
            "component_version": component_version,
            "records": [
                {
                    "adapter_semantic_id": R008_SEMANTIC_ID,
                    "raw": raw_by_role[role],
                }
            ],
        }
    return payloads


def build_r008_fixture_payloads() -> dict[str, dict[str, Any]]:
    """Build the frozen positive and negative R008 semantic fixture evidence."""
    payloads: dict[str, dict[str, Any]] = {}
    for spec in _R008_FIXTURE_SPECS:
        input_record = copy.deepcopy(spec["input_record"])
        expected_result = copy.deepcopy(spec["expected_result"])
        payloads[spec["fixture_id"]] = {
            "schema_version": SEMANTIC_FIXTURE_SCHEMA_VERSION,
            "artifact_type": "phase6_semantic_fixture",
            "fixture_id": spec["fixture_id"],
            "fixture_kind": spec["fixture_kind"],
            "component_role": spec["component_role"],
            "input_record": input_record,
            "input_sha256": sha256_bytes(canonical_json_bytes(input_record)),
            "expected_result": expected_result,
            "observed_result": copy.deepcopy(expected_result),
        }
    return payloads


def build_r008_coverage_contract(
    source_refs: Mapping[str, Mapping[str, object]],
    fixture_refs: Mapping[str, Mapping[str, object]],
) -> dict[str, Any]:
    """Build the closed-world R008 coverage contract around source references."""
    if set(source_refs) != set(COMPONENT_ROLES):
        raise ValueError("coverage source references must contain all five component roles")
    expected_fixture_ids = {spec["fixture_id"] for spec in _R008_FIXTURE_SPECS}
    if set(fixture_refs) != expected_fixture_ids:
        raise ValueError("coverage fixture references must contain both frozen R008 fixtures")
    for reference in fixture_refs.values():
        _validate_artifact_ref(
            reference,
            "phase6_semantic_fixture",
            SEMANTIC_FIXTURE_SCHEMA_VERSION,
        )
    components: list[dict[str, Any]] = []
    crosswalks: list[dict[str, Any]] = []
    matrix_results: list[dict[str, Any]] = []
    for role in COMPONENT_ROLES:
        reference = dict(source_refs[role])
        _validate_artifact_ref(
            reference,
            "phase6_semantic_source",
            SEMANTIC_SOURCE_SCHEMA_VERSION,
        )
        crosswalk_id = f"{role}-r008-v1"
        components.append(
            {
                "component_role": role,
                "component_version": _COMPONENT_VERSIONS[role],
                "source_artifact": reference,
                "source_locator": "/records/0",
                "normalization_crosswalk_id": crosswalk_id,
                "stored_semantic_key": copy.deepcopy(R008_SEMANTIC_KEY),
            }
        )
        crosswalks.append(
            {
                "crosswalk_id": crosswalk_id,
                "component_role": role,
                "reason_id": "LEAK_R008",
                "raw_sha256": sha256_bytes(canonical_json_bytes(_EXPECTED_R008_RAW[role])),
                "semantic_key": copy.deepcopy(R008_SEMANTIC_KEY),
            }
        )
        matrix_results.append(
            {
                "component_role": role,
                "source_sha256": reference["sha256"],
                "matched": True,
                "mismatch_fields": [],
            }
        )
    return {
        "schema_version": COVERAGE_CONTRACT_SCHEMA_VERSION,
        "artifact_type": "coverage_semantics_contract",
        "reason_rows": [copy.deepcopy(R008_SEMANTIC_KEY)],
        "action_family_registry": copy.deepcopy(_ACTION_FAMILY_REGISTRY),
        "crosswalk_registry": {
            "registry_version": "semantic-crosswalk-registry-v1",
            "rows": crosswalks,
        },
        "components": components,
        "coverage_matrix": {
            "semantic_id": R008_SEMANTIC_ID,
            "reason_id": "LEAK_R008",
            "component_results": matrix_results,
            "fixture_evidence": [
                {
                    "fixture_id": spec["fixture_id"],
                    "fixture_kind": spec["fixture_kind"],
                    "fixture_artifact": dict(fixture_refs[spec["fixture_id"]]),
                }
                for spec in _R008_FIXTURE_SPECS
            ],
            "positive_fixture_count": 1,
            "negative_fixture_count": 1,
            "provider_actionable": True,
            "provider_semantics_status": "match",
            "end_to_end_coverage": True,
        },
    }


def selection_metric_contract_payload() -> dict[str, Any]:
    """Return the frozen P6-4 selection-metric subset.

    Only the approved third key is frozen. The complete primary order remains
    explicitly pending human approval.
    """
    return copy.deepcopy(_SELECTION_CONTRACT)


def validate_selection_metric_contract(payload: object) -> dict[str, Any]:
    """Reject any selection metric substitution or Mode 2 penalty injection."""
    expected_fields = set(_SELECTION_CONTRACT)
    _require_fields(payload, expected_fields, "selection metric contract")
    assert isinstance(payload, dict)
    if payload["schema_version"] != SELECTION_CONTRACT_SCHEMA_VERSION:
        raise ValueError("unsupported selection metric contract schema_version")
    if payload["artifact_type"] != "selection_metric_contract":
        raise ValueError("unsupported selection metric contract artifact_type")
    gto_fields = set(_SELECTION_CONTRACT["gto_fpr"])
    _require_fields(payload["gto_fpr"], gto_fields, "GTO FPR metric contract")
    for item in (payload["selection_keys"], payload["hard_constraints"]):
        if "worst_case_penalty" in json.dumps(item, sort_keys=True):
            raise ValueError("worst_case_penalty is excluded from primary selection")
    if payload != _SELECTION_CONTRACT:
        raise ValueError("selection metric contract does not match the frozen v1 definition")
    return copy.deepcopy(payload)


def full_selection_metric_contract_v2_payload() -> dict[str, Any]:
    """Return the approved additive seven-key Validation selection contract."""
    return copy.deepcopy(_FULL_SELECTION_CONTRACT)


def validate_full_selection_metric_contract_v2(
    payload: object,
    *,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    """Reject any change to the approved seven-key v2 selection contract."""
    _require_fields(payload, set(_FULL_SELECTION_CONTRACT), "full selection metric contract")
    assert isinstance(payload, dict)
    if payload["schema_version"] != FULL_SELECTION_CONTRACT_SCHEMA_VERSION:
        raise ValueError("unsupported full selection metric contract schema_version")
    if payload["artifact_type"] != "selection_metric_contract":
        raise ValueError("unsupported full selection metric contract artifact_type")
    _require_fields(
        payload["gto_fpr"],
        set(_FULL_SELECTION_CONTRACT["gto_fpr"]),
        "full selection GTO FPR contract",
    )
    if "worst_case_penalty" in json.dumps(
        [payload["selection_keys"], payload["hard_constraints"]], sort_keys=True
    ):
        raise ValueError("worst_case_penalty is excluded from primary selection")
    if payload != _FULL_SELECTION_CONTRACT:
        raise ValueError("full selection metric contract does not match the approved v2 definition")
    if expected_sha256 is not None:
        if not isinstance(expected_sha256, str) or not _SHA256.fullmatch(expected_sha256):
            raise ValueError("full selection contract expected hash must be lowercase SHA-256")
        if sha256_bytes(canonical_json_bytes(payload)) != expected_sha256:
            raise ValueError("full selection metric contract hash mismatch")
    return copy.deepcopy(payload)


def full_selection_preregistration_v2_payload(
    *,
    selection_contract_sha256: str,
    sampling_contract_sha256: str,
) -> dict[str, Any]:
    """Build the Validation-only v2 preregistration hash joins."""
    for value, label in (
        (selection_contract_sha256, "selection contract hash"),
        (sampling_contract_sha256, "sampling contract hash"),
    ):
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise ValueError(f"{label} must be lowercase SHA-256")
    return {
        "schema_version": FULL_SELECTION_PREREGISTRATION_SCHEMA_VERSION,
        "artifact_type": "phase6_evaluation_preregistration",
        "split": "validation",
        "selection_metric_contract": {
            "artifact_type": "selection_metric_contract",
            "schema_version": FULL_SELECTION_CONTRACT_SCHEMA_VERSION,
            "sha256": selection_contract_sha256,
        },
        "sampling_contract": {
            "artifact_type": "seed_sampling_contract",
            "schema_version": "phase6-seed-sampling-contract-v2",
            "sha256": sampling_contract_sha256,
        },
    }


def validate_full_selection_preregistration_v2(
    payload: object,
    *,
    selection_contract: object,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate the v2 preregistration without accepting a v1 selection reference."""
    contract = validate_full_selection_metric_contract_v2(selection_contract)
    contract_sha256 = sha256_bytes(canonical_json_bytes(contract))
    _require_fields(
        payload,
        {
            "schema_version",
            "artifact_type",
            "split",
            "selection_metric_contract",
            "sampling_contract",
        },
        "full selection preregistration",
    )
    assert isinstance(payload, dict)
    if (
        payload["schema_version"] != FULL_SELECTION_PREREGISTRATION_SCHEMA_VERSION
        or payload["artifact_type"] != "phase6_evaluation_preregistration"
        or payload["split"] != "validation"
    ):
        raise ValueError("full selection preregistration identity is invalid")
    selection_reference = payload["selection_metric_contract"]
    _require_fields(
        selection_reference,
        {"artifact_type", "schema_version", "sha256"},
        "full selection preregistration selection reference",
    )
    assert isinstance(selection_reference, dict)
    if selection_reference != {
        "artifact_type": "selection_metric_contract",
        "schema_version": FULL_SELECTION_CONTRACT_SCHEMA_VERSION,
        "sha256": contract_sha256,
    }:
        raise ValueError("full selection preregistration selection version/hash mismatch")
    sampling_reference = payload["sampling_contract"]
    _require_fields(
        sampling_reference,
        {"artifact_type", "schema_version", "sha256"},
        "full selection preregistration sampling reference",
    )
    assert isinstance(sampling_reference, dict)
    sampling_hash = sampling_reference.get("sha256")
    if (
        sampling_reference.get("artifact_type") != "seed_sampling_contract"
        or sampling_reference.get("schema_version") != "phase6-seed-sampling-contract-v2"
        or not isinstance(sampling_hash, str)
        or not _SHA256.fullmatch(sampling_hash)
    ):
        raise ValueError("full selection preregistration sampling version/hash mismatch")
    if expected_sha256 is not None:
        if not isinstance(expected_sha256, str) or not _SHA256.fullmatch(expected_sha256):
            raise ValueError(
                "full selection preregistration expected hash must be lowercase SHA-256"
            )
        if sha256_bytes(canonical_json_bytes(payload)) != expected_sha256:
            raise ValueError("full selection preregistration hash mismatch")
    return copy.deepcopy(payload)


def load_full_selection_preregistration_v2(
    preregistration_path: Path | str,
    *,
    expected_sha256: str,
    selection_contract_path: Path | str,
    expected_selection_contract_sha256: str,
) -> ValidatedFullSelectionPreregistration:
    """Load canonical additive v2 files while leaving all v1 loaders unchanged."""
    selection_contract = _load_canonical_path(
        Path(selection_contract_path),
        expected_selection_contract_sha256,
        "full selection metric contract",
    )
    validated_contract = validate_full_selection_metric_contract_v2(
        selection_contract,
        expected_sha256=expected_selection_contract_sha256,
    )
    preregistration = _load_canonical_path(
        Path(preregistration_path),
        expected_sha256,
        "full selection preregistration",
    )
    validated_preregistration = validate_full_selection_preregistration_v2(
        preregistration,
        selection_contract=validated_contract,
        expected_sha256=expected_sha256,
    )
    return ValidatedFullSelectionPreregistration(
        preregistration=validated_preregistration,
        selection_contract=validated_contract,
        preregistration_sha256=expected_sha256,
        selection_contract_sha256=expected_selection_contract_sha256,
    )


def evaluate_coverage_semantics(
    payload: object,
    bundle_root: Path | str,
) -> CoverageEvaluation:
    """Reconstruct R008 semantics from raw source records without trusting adapters."""
    contract = _validate_coverage_shape(payload)
    reason_row = contract["reason_rows"][0]
    action_registry_matches = contract["action_family_registry"] == _ACTION_FAMILY_REGISTRY
    crosswalk_rows = contract["crosswalk_registry"]["rows"]
    matrix = contract["coverage_matrix"]
    results: list[ComponentCoverageResult] = []

    for component in contract["components"]:
        role = component["component_role"]
        mismatches: list[str] = []
        reference = component["source_artifact"]
        source_payload, actual_sha, source_issues = _read_source_for_evaluation(
            Path(bundle_root), reference
        )
        mismatches.extend(source_issues)
        if component["component_version"] != _COMPONENT_VERSIONS[role]:
            mismatches.append("component_version")
        if component["source_locator"] != "/records/0":
            mismatches.append("source_locator")
        crosswalk_matches = [
            row
            for row in crosswalk_rows
            if row["crosswalk_id"] == component["normalization_crosswalk_id"]
        ]
        crosswalk = crosswalk_matches[0] if len(crosswalk_matches) == 1 else None
        if crosswalk is None:
            mismatches.append("normalization_crosswalk_id")

        raw: object | None = None
        adapter_semantic_id: object | None = None
        if source_payload is not None:
            try:
                raw, adapter_semantic_id = _extract_source_record(source_payload, role)
            except ValueError:
                mismatches.append("source_artifact_contract")

        reconstructed_key: object | None = None
        if crosswalk is not None:
            if (
                crosswalk["component_role"] != role
                or crosswalk["reason_id"] != "LEAK_R008"
                or crosswalk["crosswalk_id"] != f"{role}-r008-v1"
            ):
                mismatches.append("normalization_crosswalk")
            if crosswalk["semantic_key"] != R008_SEMANTIC_KEY:
                mismatches.append("normalization_crosswalk.semantic_key")
            expected_raw_sha = sha256_bytes(canonical_json_bytes(_EXPECTED_R008_RAW[role]))
            if crosswalk["raw_sha256"] != expected_raw_sha:
                mismatches.append("normalization_crosswalk.raw_sha256")
            if raw is not None and crosswalk["raw_sha256"] != sha256_bytes(
                canonical_json_bytes(raw)
            ):
                mismatches.append("raw")
            reconstructed_key = crosswalk["semantic_key"]

        if raw is not None and raw != _EXPECTED_R008_RAW[role] and "raw" not in mismatches:
            mismatches.append("raw")
        if reconstructed_key is not None:
            if adapter_semantic_id != reconstructed_key["semantic_id"]:
                mismatches.append("adapter_semantic_id")
            if component["stored_semantic_key"] != reconstructed_key:
                mismatches.append("stored_semantic_key")
            if reason_row != reconstructed_key:
                mismatches.append("reason_row")
        if not action_registry_matches:
            mismatches.append("action_family_registry")

        results.append(
            ComponentCoverageResult(
                component_role=role,
                source_sha256=actual_sha,
                matched=not mismatches,
                mismatch_fields=tuple(dict.fromkeys(mismatches)),
            )
        )

    computed_matrix_results = [
        {
            "component_role": result.component_role,
            "source_sha256": result.source_sha256,
            "matched": result.matched,
            "mismatch_fields": list(result.mismatch_fields),
        }
        for result in results
    ]
    matrix_matches = matrix["component_results"] == computed_matrix_results
    fixture_counts = {"positive": 0, "negative": 0}
    fixtures_valid = True
    for evidence, spec in zip(matrix["fixture_evidence"], _R008_FIXTURE_SPECS, strict=True):
        fixture_payload = _read_fixture_for_evaluation(Path(bundle_root), evidence)
        if fixture_payload is None:
            fixtures_valid = False
            continue
        try:
            _validate_fixture_payload(fixture_payload, evidence, spec)
        except ValueError:
            fixtures_valid = False
            continue
        fixture_counts[evidence["fixture_kind"]] += 1
    counts_valid = (
        fixtures_valid
        and fixture_counts["positive"] > 0
        and fixture_counts["negative"] > 0
        and matrix["positive_fixture_count"] == fixture_counts["positive"]
        and matrix["negative_fixture_count"] == fixture_counts["negative"]
    )
    reconstructed_coverage = (
        all(result.matched for result in results)
        and matrix_matches
        and counts_valid
        and matrix["provider_actionable"] is True
        and matrix["provider_semantics_status"] == "match"
    )
    end_to_end = reconstructed_coverage and matrix["end_to_end_coverage"] is True
    return CoverageEvaluation(tuple(results), matrix_matches, end_to_end)


def load_phase6_contract_bundle(
    root_manifest_path: Path | str,
    *,
    expected_sha256: str,
) -> ValidatedPhase6ContractBundle:
    """Load a canonical fixture bundle and enforce every version/hash join."""
    if not isinstance(expected_sha256, str) or not _SHA256.fullmatch(expected_sha256):
        raise ValueError("expected root manifest SHA-256 must be lowercase hexadecimal")
    root_path = Path(root_manifest_path)
    root = _load_canonical_path(root_path, expected_sha256, "root manifest")
    _require_fields(
        root,
        {
            "schema_version",
            "artifact_type",
            "preregistration",
            "coverage_semantics_contract",
            "selection_metric_contract",
            "series_reference",
            "validation_batch_reference",
            "selection_report_reference",
        },
        "phase6 root manifest",
    )
    assert isinstance(root, dict)
    if root["schema_version"] != ROOT_MANIFEST_SCHEMA_VERSION:
        raise ValueError("unsupported phase6 root manifest schema_version")
    if root["artifact_type"] != "phase6_evaluation_manifest":
        raise ValueError("unsupported phase6 root manifest artifact_type")

    expected_refs = {
        "preregistration": (
            "phase6_evaluation_preregistration",
            PREREGISTRATION_SCHEMA_VERSION,
        ),
        "coverage_semantics_contract": (
            "coverage_semantics_contract",
            COVERAGE_CONTRACT_SCHEMA_VERSION,
        ),
        "selection_metric_contract": (
            "selection_metric_contract",
            SELECTION_CONTRACT_SCHEMA_VERSION,
        ),
        "series_reference": (
            "phase6_evaluation_series_reference",
            SERIES_REFERENCE_SCHEMA_VERSION,
        ),
        "validation_batch_reference": (
            "phase6_validation_batch_reference",
            VALIDATION_BATCH_REFERENCE_SCHEMA_VERSION,
        ),
        "selection_report_reference": (
            "phase6_selection_report_reference",
            SELECTION_REPORT_REFERENCE_SCHEMA_VERSION,
        ),
    }
    for name, (artifact_type, schema_version) in expected_refs.items():
        _validate_artifact_ref(root[name], artifact_type, schema_version)

    bundle_root = root_path.parent
    loaded = {name: _load_ref_payload(bundle_root, root[name], name) for name in expected_refs}
    preregistration = loaded["preregistration"]
    _validate_preregistration(preregistration, root)
    coverage_contract = loaded["coverage_semantics_contract"]
    selection_contract = validate_selection_metric_contract(loaded["selection_metric_contract"])
    coverage_evaluation = evaluate_coverage_semantics(coverage_contract, bundle_root)
    if not coverage_evaluation.end_to_end_coverage:
        raise ValueError("coverage semantics hard gate failed")

    series_reference = loaded["series_reference"]
    validation_batch_reference = loaded["validation_batch_reference"]
    selection_report_reference = loaded["selection_report_reference"]
    _validate_consumer_reference(
        series_reference,
        artifact_type="phase6_evaluation_series_reference",
        schema_version=SERIES_REFERENCE_SCHEMA_VERSION,
        root=root,
    )
    _validate_consumer_reference(
        validation_batch_reference,
        artifact_type="phase6_validation_batch_reference",
        schema_version=VALIDATION_BATCH_REFERENCE_SCHEMA_VERSION,
        root=root,
    )
    _validate_consumer_reference(
        selection_report_reference,
        artifact_type="phase6_selection_report_reference",
        schema_version=SELECTION_REPORT_REFERENCE_SCHEMA_VERSION,
        root=root,
        report=True,
    )
    return ValidatedPhase6ContractBundle(
        root_manifest=copy.deepcopy(root),
        preregistration=copy.deepcopy(preregistration),
        coverage_contract=copy.deepcopy(coverage_contract),
        selection_contract=selection_contract,
        series_reference=copy.deepcopy(series_reference),
        validation_batch_reference=copy.deepcopy(validation_batch_reference),
        selection_report_reference=copy.deepcopy(selection_report_reference),
        coverage_evaluation=coverage_evaluation,
    )


def _validate_coverage_shape(payload: object) -> dict[str, Any]:
    _require_fields(
        payload,
        {
            "schema_version",
            "artifact_type",
            "reason_rows",
            "action_family_registry",
            "crosswalk_registry",
            "components",
            "coverage_matrix",
        },
        "coverage semantics contract",
    )
    assert isinstance(payload, dict)
    if payload["schema_version"] != COVERAGE_CONTRACT_SCHEMA_VERSION:
        raise ValueError("unsupported coverage semantics contract schema_version")
    if payload["artifact_type"] != "coverage_semantics_contract":
        raise ValueError("unsupported coverage semantics contract artifact_type")
    reason_rows = payload["reason_rows"]
    if not isinstance(reason_rows, list) or len(reason_rows) != 1:
        raise ValueError("coverage contract requires exactly one R008 reason row")
    _validate_semantic_key(reason_rows[0], "coverage reason row")

    _require_fields(
        payload["action_family_registry"],
        {"registry_version", "rows"},
        "action family registry",
    )
    action_rows = payload["action_family_registry"]["rows"]
    if not isinstance(action_rows, list):
        raise ValueError("action family registry rows must be a list")
    for row in action_rows:
        _require_fields(
            row,
            {"action_family_id", "detector_encodings", "solver_encodings"},
            "action family registry row",
        )

    _require_fields(
        payload["crosswalk_registry"],
        {"registry_version", "rows"},
        "semantic crosswalk registry",
    )
    if payload["crosswalk_registry"]["registry_version"] != "semantic-crosswalk-registry-v1":
        raise ValueError("unsupported semantic crosswalk registry version")
    crosswalk_rows = payload["crosswalk_registry"]["rows"]
    if not isinstance(crosswalk_rows, list) or len(crosswalk_rows) != len(COMPONENT_ROLES):
        raise ValueError("semantic crosswalk registry requires exactly five rows")
    for row in crosswalk_rows:
        _require_fields(
            row,
            {"crosswalk_id", "component_role", "reason_id", "raw_sha256", "semantic_key"},
            "semantic crosswalk row",
        )
        if not isinstance(row["raw_sha256"], str) or not _SHA256.fullmatch(row["raw_sha256"]):
            raise ValueError("semantic crosswalk raw_sha256 must be lowercase hexadecimal")
        _validate_semantic_key(row["semantic_key"], "semantic crosswalk key")

    components = payload["components"]
    if not isinstance(components, list) or len(components) != len(COMPONENT_ROLES):
        raise ValueError("coverage contract requires exactly five components")
    roles: list[str] = []
    for component in components:
        _require_fields(
            component,
            {
                "component_role",
                "component_version",
                "source_artifact",
                "source_locator",
                "normalization_crosswalk_id",
                "stored_semantic_key",
            },
            "coverage component",
        )
        role = component["component_role"]
        if role not in COMPONENT_ROLES:
            raise ValueError(f"unknown coverage component role {role!r}")
        roles.append(role)
        if not isinstance(component["component_version"], str):
            raise ValueError("coverage component version must be a string")
        _validate_artifact_ref(
            component["source_artifact"],
            "phase6_semantic_source",
            SEMANTIC_SOURCE_SCHEMA_VERSION,
        )
        _validate_semantic_key(component["stored_semantic_key"], "stored semantic key")
    if tuple(roles) != COMPONENT_ROLES:
        raise ValueError("coverage components must appear exactly once in canonical role order")

    matrix = payload["coverage_matrix"]
    _require_fields(
        matrix,
        {
            "semantic_id",
            "reason_id",
            "component_results",
            "fixture_evidence",
            "positive_fixture_count",
            "negative_fixture_count",
            "provider_actionable",
            "provider_semantics_status",
            "end_to_end_coverage",
        },
        "coverage matrix",
    )
    if matrix["semantic_id"] != R008_SEMANTIC_ID or matrix["reason_id"] != "LEAK_R008":
        raise ValueError("coverage matrix must identify canonical R008 semantics")
    matrix_results = matrix["component_results"]
    if not isinstance(matrix_results, list) or len(matrix_results) != len(COMPONENT_ROLES):
        raise ValueError("coverage matrix requires exactly five component results")
    matrix_roles: list[str] = []
    for result in matrix_results:
        _require_fields(
            result,
            {"component_role", "source_sha256", "matched", "mismatch_fields"},
            "coverage matrix component result",
        )
        role = result["component_role"]
        if type(role) is not str or role not in COMPONENT_ROLES:
            raise ValueError("coverage matrix component_role must be a known string")
        matrix_roles.append(role)
        if type(result["source_sha256"]) is not str or not _SHA256.fullmatch(
            result["source_sha256"]
        ):
            raise ValueError("coverage matrix source_sha256 must be lowercase hexadecimal")
        if type(result["matched"]) is not bool:
            raise ValueError("coverage matrix matched must be a JSON boolean")
        if not isinstance(result["mismatch_fields"], list):
            raise ValueError("coverage mismatch_fields must be a list")
        if any(type(field) is not str or not field for field in result["mismatch_fields"]):
            raise ValueError("coverage mismatch_fields entries must be non-empty strings")
        if len(set(result["mismatch_fields"])) != len(result["mismatch_fields"]):
            raise ValueError("coverage mismatch_fields entries must be unique")
    if tuple(matrix_roles) != COMPONENT_ROLES:
        raise ValueError("coverage matrix components must be in canonical role order")

    fixture_evidence = matrix["fixture_evidence"]
    if not isinstance(fixture_evidence, list) or len(fixture_evidence) != len(_R008_FIXTURE_SPECS):
        raise ValueError("coverage matrix requires exactly two fixture evidence references")
    for evidence, spec in zip(fixture_evidence, _R008_FIXTURE_SPECS, strict=True):
        _require_fields(
            evidence,
            {"fixture_id", "fixture_kind", "fixture_artifact"},
            "coverage fixture evidence reference",
        )
        if type(evidence["fixture_id"]) is not str or evidence["fixture_id"] != spec["fixture_id"]:
            raise ValueError("coverage fixtures must appear exactly once in canonical order")
        if (
            type(evidence["fixture_kind"]) is not str
            or evidence["fixture_kind"] != spec["fixture_kind"]
        ):
            raise ValueError("coverage fixture kind mismatch")
        _validate_artifact_ref(
            evidence["fixture_artifact"],
            "phase6_semantic_fixture",
            SEMANTIC_FIXTURE_SCHEMA_VERSION,
        )
    if not _is_positive_int(matrix["positive_fixture_count"]) or not _is_positive_int(
        matrix["negative_fixture_count"]
    ):
        raise ValueError("coverage fixture counts must be positive JSON integers")
    if type(matrix["provider_actionable"]) is not bool:
        raise ValueError("coverage provider_actionable must be a JSON boolean")
    if type(matrix["provider_semantics_status"]) is not str:
        raise ValueError("coverage provider_semantics_status must be a string")
    if type(matrix["end_to_end_coverage"]) is not bool:
        raise ValueError("coverage end_to_end_coverage must be a JSON boolean")
    return payload


def _read_source_for_evaluation(
    root: Path,
    reference: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, str, list[str]]:
    issues: list[str] = []
    try:
        target = _resolve_bundle_path(root, reference["path"])
        raw = target.read_bytes()
    except (OSError, ValueError, KeyError, TypeError):
        return None, "", ["source_artifact"]
    actual_sha = sha256_bytes(raw)
    if actual_sha != reference["sha256"]:
        issues.append("source_sha256")
    try:
        payload = _strict_json_loads(raw)
    except (UnicodeDecodeError, ValueError):
        return None, actual_sha, [*issues, "source_json"]
    if canonical_json_bytes(payload) != raw:
        issues.append("source_canonical_bytes")
    if not isinstance(payload, dict):
        return None, actual_sha, [*issues, "source_artifact_contract"]
    return payload, actual_sha, issues


def _read_fixture_for_evaluation(
    root: Path,
    evidence: Mapping[str, Any],
) -> dict[str, Any] | None:
    try:
        reference = evidence["fixture_artifact"]
        target = _resolve_bundle_path(root, reference["path"])
        return _load_canonical_path(
            target,
            reference["sha256"],
            f"semantic fixture {evidence['fixture_id']}",
        )
    except (KeyError, TypeError, ValueError):
        return None


def _validate_fixture_payload(
    payload: object,
    evidence: Mapping[str, Any],
    spec: Mapping[str, Any],
) -> None:
    _require_fields(
        payload,
        {
            "schema_version",
            "artifact_type",
            "fixture_id",
            "fixture_kind",
            "component_role",
            "input_record",
            "input_sha256",
            "expected_result",
            "observed_result",
        },
        "semantic fixture artifact",
    )
    assert isinstance(payload, dict)
    if payload["schema_version"] != SEMANTIC_FIXTURE_SCHEMA_VERSION:
        raise ValueError("unsupported semantic fixture schema_version")
    if payload["artifact_type"] != "phase6_semantic_fixture":
        raise ValueError("unsupported semantic fixture artifact_type")
    for field in ("fixture_id", "fixture_kind", "component_role"):
        if type(payload[field]) is not str or payload[field] != spec[field]:
            raise ValueError(f"semantic fixture {field} mismatch")
    if (
        payload["fixture_id"] != evidence["fixture_id"]
        or payload["fixture_kind"] != evidence["fixture_kind"]
    ):
        raise ValueError("semantic fixture reference mismatch")

    input_record = payload["input_record"]
    _require_fields(input_record, {"adapter_semantic_id", "raw"}, "semantic fixture input")
    assert isinstance(input_record, dict)
    if type(input_record["adapter_semantic_id"]) is not str:
        raise ValueError("semantic fixture adapter_semantic_id must be a string")
    _require_fields(
        input_record["raw"],
        set(_EXPECTED_R008_RAW[spec["component_role"]]),
        "semantic fixture raw input",
    )
    if not _strict_json_equal(input_record, spec["input_record"]):
        raise ValueError("semantic fixture input does not match the frozen fixture")
    if type(payload["input_sha256"]) is not str or not _SHA256.fullmatch(payload["input_sha256"]):
        raise ValueError("semantic fixture input_sha256 must be lowercase hexadecimal")
    if payload["input_sha256"] != sha256_bytes(canonical_json_bytes(input_record)):
        raise ValueError("semantic fixture input hash mismatch")

    _validate_fixture_result(payload["expected_result"], "expected")
    _validate_fixture_result(payload["observed_result"], "observed")
    computed_result = _compute_fixture_result(input_record, spec["component_role"])
    if not _strict_json_equal(payload["expected_result"], spec["expected_result"]):
        raise ValueError("semantic fixture expected result mismatch")
    if not _strict_json_equal(payload["expected_result"], computed_result):
        raise ValueError("semantic fixture expectation does not match reconstructed result")
    if not _strict_json_equal(payload["observed_result"], computed_result):
        raise ValueError("semantic fixture observed result mismatch")


def _validate_fixture_result(payload: object, label: str) -> None:
    _require_fields(payload, {"matched", "mismatch_fields"}, f"semantic fixture {label} result")
    assert isinstance(payload, dict)
    if type(payload["matched"]) is not bool:
        raise ValueError(f"semantic fixture {label} matched must be a JSON boolean")
    mismatch_fields = payload["mismatch_fields"]
    if not isinstance(mismatch_fields, list):
        raise ValueError(f"semantic fixture {label} mismatch_fields must be a list")
    if any(type(field) is not str or not field for field in mismatch_fields):
        raise ValueError(
            f"semantic fixture {label} mismatch_fields entries must be non-empty strings"
        )
    if len(set(mismatch_fields)) != len(mismatch_fields):
        raise ValueError(f"semantic fixture {label} mismatch_fields entries must be unique")


def _compute_fixture_result(input_record: Mapping[str, Any], role: str) -> dict[str, Any]:
    mismatches: list[str] = []
    if input_record["adapter_semantic_id"] != R008_SEMANTIC_ID:
        mismatches.append("adapter_semantic_id")
    if not _strict_json_equal(input_record["raw"], _EXPECTED_R008_RAW[role]):
        mismatches.append("raw")
    return {"matched": not mismatches, "mismatch_fields": mismatches}


def _strict_json_equal(left: object, right: object) -> bool:
    return canonical_json_bytes(left) == canonical_json_bytes(right)


def _extract_source_record(
    payload: dict[str, Any],
    role: str,
) -> tuple[dict[str, Any], object]:
    _require_fields(
        payload,
        {"schema_version", "artifact_type", "component_role", "component_version", "records"},
        "semantic source artifact",
    )
    if payload["schema_version"] != SEMANTIC_SOURCE_SCHEMA_VERSION:
        raise ValueError("unsupported semantic source schema_version")
    if payload["artifact_type"] != "phase6_semantic_source":
        raise ValueError("unsupported semantic source artifact_type")
    if payload["component_role"] != role:
        raise ValueError("semantic source component role mismatch")
    if payload["component_version"] != _COMPONENT_VERSIONS[role]:
        raise ValueError("semantic source component version mismatch")
    records = payload["records"]
    if not isinstance(records, list) or len(records) != 1:
        raise ValueError("semantic source must contain exactly one record")
    record = records[0]
    _require_fields(record, {"adapter_semantic_id", "raw"}, "semantic source record")
    raw = record["raw"]
    _require_fields(raw, set(_EXPECTED_R008_RAW[role]), "semantic source raw record")
    return raw, record["adapter_semantic_id"]


def _validate_preregistration(payload: object, root: dict[str, Any]) -> None:
    _require_fields(
        payload,
        {
            "schema_version",
            "artifact_type",
            "coverage_semantics_contract",
            "selection_metric_contract",
        },
        "phase6 preregistration",
    )
    assert isinstance(payload, dict)
    if payload["schema_version"] != PREREGISTRATION_SCHEMA_VERSION:
        raise ValueError("unsupported phase6 preregistration schema_version")
    if payload["artifact_type"] != "phase6_evaluation_preregistration":
        raise ValueError("unsupported phase6 preregistration artifact_type")
    for name in ("coverage_semantics_contract", "selection_metric_contract"):
        if payload[name] != root[name]:
            raise ValueError(f"preregistration {name} version/hash reference mismatch")


def _validate_consumer_reference(
    payload: object,
    *,
    artifact_type: str,
    schema_version: str,
    root: dict[str, Any],
    report: bool = False,
) -> None:
    expected_fields = {
        "schema_version",
        "artifact_type",
        "preregistration",
        "coverage_semantics_contract",
        "selection_metric_contract",
    }
    if report:
        expected_fields.add("selection_metric_id")
    _require_fields(payload, expected_fields, f"{artifact_type} fixture reference")
    assert isinstance(payload, dict)
    if payload["schema_version"] != schema_version:
        raise ValueError(f"unsupported {artifact_type} schema_version")
    if payload["artifact_type"] != artifact_type:
        raise ValueError(f"unsupported {artifact_type} artifact_type")
    for name in (
        "preregistration",
        "coverage_semantics_contract",
        "selection_metric_contract",
    ):
        if payload[name] != root[name]:
            raise ValueError(f"{artifact_type} {name} version/hash reference mismatch")
    if report and payload["selection_metric_id"] != GTO_FPR_METRIC_ID:
        raise ValueError("selection report substituted the frozen GTO FPR metric")


def _validate_semantic_key(payload: object, label: str) -> None:
    _require_fields(payload, _SEMANTIC_KEY_FIELDS, label)
    assert isinstance(payload, dict)
    if any(not isinstance(value, str) or not value for value in payload.values()):
        raise ValueError(f"{label} fields must be non-empty strings")


def _validate_artifact_ref(
    payload: object,
    expected_type: str,
    expected_version: str,
) -> None:
    _require_fields(payload, _SOURCE_REF_FIELDS, f"{expected_type} reference")
    assert isinstance(payload, dict)
    if payload["artifact_type"] != expected_type:
        raise ValueError(f"artifact reference type must be {expected_type!r}")
    if payload["schema_version"] != expected_version:
        raise ValueError(f"unsupported {expected_type} reference schema_version")
    if _ARTIFACT_VERSIONS.get(expected_type) != expected_version:
        raise ValueError(f"unregistered artifact reference type {expected_type!r}")
    if not isinstance(payload["sha256"], str) or not _SHA256.fullmatch(payload["sha256"]):
        raise ValueError("artifact reference SHA-256 must be lowercase hexadecimal")
    _resolve_bundle_path(Path("."), payload["path"])


def _load_ref_payload(root: Path, reference: Mapping[str, Any], label: str) -> dict[str, Any]:
    target = _resolve_bundle_path(root, reference["path"])
    return _load_canonical_path(target, reference["sha256"], label)


def _load_canonical_path(path: Path, expected_sha: str, label: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"required {label} is unreadable") from exc
    if sha256_bytes(raw) != expected_sha:
        raise ValueError(f"{label} hash mismatch")
    try:
        payload = _strict_json_loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if canonical_json_bytes(payload) != raw:
        raise ValueError(f"{label} is not canonical JSON")
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return payload


def _strict_json_loads(raw: bytes) -> object:
    return json.loads(raw, parse_constant=_reject_nonfinite_json_constant)


def _reject_nonfinite_json_constant(token: str) -> object:
    raise ValueError(f"non-finite JSON token {token!r} is forbidden")


def _resolve_bundle_path(root: Path, relative_path: object) -> Path:
    if not isinstance(relative_path, str) or not relative_path:
        raise ValueError("bundle path must be a non-empty relative POSIX path")
    if "\\" in relative_path or ":" in relative_path:
        raise ValueError("bundle path must use a relative POSIX spelling")
    pure = PurePosixPath(relative_path)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
        raise ValueError("bundle path escapes or is not normalized")
    resolved_root = root.resolve()
    target = resolved_root.joinpath(*pure.parts).resolve()
    try:
        target.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError("bundle path escapes root") from exc
    return target


def _require_fields(payload: object, expected: set[str], label: str) -> None:
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    if set(payload) != expected:
        raise ValueError(
            f"{label} fields mismatch: missing={sorted(expected - set(payload))}, "
            f"extra={sorted(set(payload) - expected)}"
        )


def _is_positive_int(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value > 0
