"""Approved P6-7 settings, deterministic sampling, and fixture-only hard gates.

This module does not run Training or Validation and does not create batch,
result, report, or league artifacts.  It freezes the ADR-0022 configuration
surface and provides pure functions for unit fixtures and future runners.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from decimal import Decimal
from fractions import Fraction
from functools import cmp_to_key
from itertools import product
from typing import Literal

from opponents.ground_truth import extract_true_leaks
from opponents.model import OpponentModelConfig
from opponents.synthesis import synthesize_opponent

from .contracts import COMPONENT_ROLES, CoverageEvaluation

SEED_DERIVATION_VERSION = "phase6-domain-separated-sha256-v2"
DRAW_DERIVATION_VERSION = "phase6-digest-draw-v2"
EXECUTION_SAMPLER_VERSION = "epsilon-uniform-digest-v2"
LEGAL_ACTION_ORDER_VERSION = "phase6-legal-action-order-v1"
PROBABILITY_MAPPING_VERSION = "phase6-rational-icdf-256-v1"
SAMPLING_CONTRACT_SCHEMA_VERSION = "phase6-seed-sampling-contract-v2"
PRIMARY_GRID_VERSION = "phase6-primary-grid-v1"
PRIMARY_SELECTION_VERSION = "phase6-primary-selection-order-v1"
COMPARATOR_ID = "cmp_safety_alpha_050__v1"
RESERVED_ALPHA_ABLATION_ID = "abl_alpha_fixed__v1"
RESERVED_ALPHA_ABLATION_REASON = "primary_has_no_confidence_to_effective_alpha_mapping"
R008_COVERAGE_SEMANTIC_ID = "leak_r008_opponent_river_vs_check_bet_upper_v1"

STREAM_NAMES: tuple[str, ...] = (
    "observation",
    "hero_action",
    "epsilon_branch",
    "epsilon_action",
)
LEGAL_ACTION_ORDER: tuple[str, ...] = (
    "CHECK",
    "BET",
    "BET_33",
    "BET_75",
    "BET_ALL_IN",
    "FOLD",
    "CALL",
    "RAISE_ALL_IN",
)
REPETITION_SEEDS: tuple[tuple[str, int], ...] = tuple(
    (f"r{index:03d}", 620000 + index) for index in range(1, 31)
)
PRIMARY_SELECTION_KEYS: tuple[tuple[str, str], ...] = (
    ("validation_macro_brier", "ascending"),
    ("validation_micro_brier", "ascending"),
    ("gto_negative_control_micro_fpr_v1", "ascending"),
    ("validation_macro_exploitation_efficiency", "descending"),
    ("validation_macro_recall", "descending"),
    ("validation_macro_precision", "descending"),
    ("candidate_id", "lexicographic_ascending"),
)

_M = 1 << 256
_SHA256 = frozenset("0123456789abcdef")
_PRIMARY_REASONS = ("LEAK_R007", "LEAK_R008")
_EXPECTED_ADDITIONS = {
    ("training", "LEAK_R007", "0.32", 630732),
    ("training", "LEAK_R007", "0.4", 630740),
    ("training", "LEAK_R008", "0.32", 630832),
    ("training", "LEAK_R008", "0.4", 630840),
    ("validation", None, "0", 640000),
    ("validation", "LEAK_R007", "0.28", 640728),
    ("validation", "LEAK_R007", "0.36", 640736),
    ("validation", "LEAK_R008", "0.28", 640828),
    ("validation", "LEAK_R008", "0.36", 640836),
}


def _canonical_json_bytes(payload: object, *, trailing_lf: bool = True) -> bytes:
    text = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return (text + ("\n" if trailing_lf else "")).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _SHA256 for character in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def sampling_contract_payload(
    *, observation_registry_version: str, observation_registry_sha256: str
) -> dict[str, object]:
    """Return the complete approved digest-direct sampling contract."""
    if not observation_registry_version:
        raise ValueError("observation registry version must be non-empty")
    _validate_sha256(observation_registry_sha256, "observation registry hash")
    return {
        "schema_version": SAMPLING_CONTRACT_SCHEMA_VERSION,
        "seed_derivation_version": SEED_DERIVATION_VERSION,
        "draw_derivation_version": DRAW_DERIVATION_VERSION,
        "execution_sampler_version": EXECUTION_SAMPLER_VERSION,
        "legal_action_order_version": LEGAL_ACTION_ORDER_VERSION,
        "probability_mapping_version": PROBABILITY_MAPPING_VERSION,
        "stream_names": list(STREAM_NAMES),
        "root_domain_prefix": f"{SEED_DERIVATION_VERSION}\0",
        "draw_domain_prefix": f"{DRAW_DERIVATION_VERSION}\0",
        "root_payload_fields": [
            "derivation_version",
            "horizon",
            "master_seed",
            "opponent_id",
            "repetition_id",
            "split",
            "stream_name",
        ],
        "draw_coordinates": {
            "decision_index": "uint64_big_endian",
            "variate_index": "uint32_big_endian",
            "attempt_index": "uint32_big_endian",
        },
        "stream_variate_contract": {
            "observation": "encountered_stochastic_nodes_in_transition_order",
            "hero_action": 0,
            "epsilon_branch": 0,
            "epsilon_action": 0,
        },
        "legal_action_order": list(LEGAL_ACTION_ORDER),
        "probability_encoding": "finite_non_negative_binary64_as_exact_integer_ratio",
        "weighted_categorical": "left_closed_right_open_exact_rational_icdf",
        "uniform_mapping": "uint256_rejection_then_modulo",
        "unused_draw_policy": "derive_all_three_action_draws_and_never_reuse",
        "stateful_prng": None,
        "observation_registry_version": observation_registry_version,
        "observation_registry_sha256": observation_registry_sha256,
    }


def sampling_contract_sha256(payload: Mapping[str, object]) -> str:
    """Hash canonical stored bytes for a sampling contract."""
    validate_sampling_contract(payload)
    return _sha256_bytes(_canonical_json_bytes(payload))


def validate_sampling_contract(
    payload: Mapping[str, object], *, expected_sha256: str | None = None
) -> None:
    """Fail closed on unknown versions, fields, ordering, or a stale hash."""
    if not isinstance(payload, Mapping):
        raise ValueError("sampling contract must be an object")
    expected = sampling_contract_payload(
        observation_registry_version=payload.get("observation_registry_version", ""),
        observation_registry_sha256=payload.get("observation_registry_sha256", ""),
    )
    if dict(payload) != expected:
        raise ValueError("sampling contract does not match digest-direct v2")
    if expected_sha256 is not None:
        _validate_sha256(expected_sha256, "sampling contract expected hash")
        if _sha256_bytes(_canonical_json_bytes(payload)) != expected_sha256:
            raise ValueError("sampling contract hash mismatch")


@dataclass(frozen=True, slots=True)
class StreamRoot:
    payload: dict[str, object]
    digest: str


@dataclass(frozen=True, slots=True)
class ObservationNodeSpec:
    node_id: str
    outcome_registry_version: str
    ordered_outcomes: tuple[tuple[str, float], ...]

    def __post_init__(self) -> None:
        if not self.node_id or not self.outcome_registry_version:
            raise ValueError("observation node IDs and versions must be non-empty")
        outcome_ids = [outcome_id for outcome_id, _weight in self.ordered_outcomes]
        if not outcome_ids or len(set(outcome_ids)) != len(outcome_ids):
            raise ValueError("observation outcomes must be non-empty and unique")
        for outcome_id, weight in self.ordered_outcomes:
            if not outcome_id:
                raise ValueError("observation outcome IDs must be non-empty")
            if not isinstance(weight, float) or not math.isfinite(weight) or weight < 0:
                raise ValueError("observation weights must be finite non-negative binary64")
        if not any(weight > 0 for _outcome_id, weight in self.ordered_outcomes):
            raise ValueError("observation node must have positive total weight")

    def canonical_payload(self) -> dict[str, object]:
        return {
            "node_id": self.node_id,
            "outcome_registry_version": self.outcome_registry_version,
            "ordered_outcomes": [
                {"outcome_id": outcome_id, "weight_binary64_hex": weight.hex()}
                for outcome_id, weight in self.ordered_outcomes
            ],
        }


@dataclass(frozen=True, slots=True)
class ObservationRegistry:
    registry_version: str
    nodes: tuple[ObservationNodeSpec, ...]

    def __post_init__(self) -> None:
        if not self.registry_version or not self.nodes:
            raise ValueError("observation registry version and nodes must be non-empty")
        node_ids = [node.node_id for node in self.nodes]
        if node_ids != sorted(node_ids) or len(set(node_ids)) != len(node_ids):
            raise ValueError("observation nodes must be unique and sorted by node_id")

    def canonical_payload(self) -> dict[str, object]:
        return {
            "registry_version": self.registry_version,
            "nodes": [node.canonical_payload() for node in self.nodes],
        }

    @property
    def sha256(self) -> str:
        return _sha256_bytes(_canonical_json_bytes(self.canonical_payload()))


@dataclass(frozen=True, slots=True)
class ObservationDrawAudit:
    node_id: str
    outcome_registry_version: str
    variate_index: int
    draw_digest: str
    selected_outcome_id: str


def derive_stream_root(
    *,
    split: Literal["training", "validation"],
    opponent_id: str,
    horizon: int,
    repetition_id: str,
    stream_name: str,
) -> StreamRoot:
    """Derive one root digest without candidate fields or a stateful PRNG."""
    seed_map = dict(REPETITION_SEEDS)
    if split not in ("training", "validation"):
        raise ValueError("sampling split must be training or validation")
    if not opponent_id:
        raise ValueError("opponent_id must be non-empty")
    if isinstance(horizon, bool) or not isinstance(horizon, int) or horizon <= 0:
        raise ValueError("horizon must be a positive integer")
    if repetition_id not in seed_map:
        raise ValueError("repetition_id is outside r001..r030")
    if stream_name not in STREAM_NAMES:
        raise ValueError("unknown sampling stream")
    payload = {
        "derivation_version": SEED_DERIVATION_VERSION,
        "horizon": horizon,
        "master_seed": seed_map[repetition_id],
        "opponent_id": opponent_id,
        "repetition_id": repetition_id,
        "split": split,
        "stream_name": stream_name,
    }
    encoded = _canonical_json_bytes(payload, trailing_lf=False)
    digest = hashlib.sha256(SEED_DERIVATION_VERSION.encode() + b"\0" + encoded).hexdigest()
    return StreamRoot(payload, digest)


def _validate_stream_root(
    stream_root: StreamRoot, *, expected_stream_name: str | None = None
) -> None:
    if not isinstance(stream_root, StreamRoot):
        raise TypeError("draw derivation requires a StreamRoot")
    payload = stream_root.payload
    if not isinstance(payload, dict):
        raise ValueError("stream root payload must be an object")
    try:
        rebuilt = derive_stream_root(
            split=payload["split"],
            opponent_id=payload["opponent_id"],
            horizon=payload["horizon"],
            repetition_id=payload["repetition_id"],
            stream_name=payload["stream_name"],
        )
    except (KeyError, TypeError) as exc:
        raise ValueError("stream root payload is incomplete") from exc
    if stream_root != rebuilt:
        raise ValueError("stream root payload and digest do not match")
    if expected_stream_name is not None and payload["stream_name"] != expected_stream_name:
        raise ValueError(f"expected {expected_stream_name} stream root")


def derive_draw_digest(
    stream_root: StreamRoot,
    *,
    decision_index: int,
    variate_index: int = 0,
    attempt_index: int = 0,
) -> str:
    """Derive one scalar variate directly from its immutable coordinates."""
    _validate_stream_root(stream_root)
    bounds = (
        (decision_index, 8, "decision_index"),
        (variate_index, 4, "variate_index"),
        (attempt_index, 4, "attempt_index"),
    )
    encoded_parts: list[bytes] = []
    horizon = stream_root.payload["horizon"]
    if (
        isinstance(decision_index, bool)
        or not isinstance(decision_index, int)
        or decision_index < 0
        or decision_index >= horizon
    ):
        raise ValueError("decision_index is outside stream root horizon")
    for value, width, label in bounds:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or value >= 1 << (width * 8)
        ):
            raise ValueError(f"{label} is outside its unsigned integer width")
        encoded_parts.append(value.to_bytes(width, "big"))
    return hashlib.sha256(
        DRAW_DERIVATION_VERSION.encode()
        + b"\0"
        + bytes.fromhex(stream_root.digest)
        + b"".join(encoded_parts)
    ).hexdigest()


def sample_observation_node(
    registry: ObservationRegistry,
    *,
    node_id: str,
    stream_root: StreamRoot,
    decision_index: int,
    variate_index: int,
) -> ObservationDrawAudit:
    """Sample one encountered stochastic node using its transition-order coordinate."""
    matches = [node for node in registry.nodes if node.node_id == node_id]
    if len(matches) != 1:
        raise ValueError("unknown observation node")
    node = matches[0]
    _validate_stream_root(stream_root, expected_stream_name="observation")
    digest = derive_draw_digest(
        stream_root,
        decision_index=decision_index,
        variate_index=variate_index,
    )
    selected = weighted_categorical(
        [outcome_id for outcome_id, _weight in node.ordered_outcomes],
        [weight for _outcome_id, weight in node.ordered_outcomes],
        digest,
    )
    return ObservationDrawAudit(
        node.node_id,
        node.outcome_registry_version,
        variate_index,
        digest,
        selected,
    )


def canonical_legal_actions(actions: Sequence[str]) -> tuple[str, ...]:
    """Filter the frozen global action order over one valid legal set."""
    if not actions or any(not isinstance(action, str) for action in actions):
        raise ValueError("legal actions must be a non-empty string sequence")
    if len(set(actions)) != len(actions):
        raise ValueError("legal actions contain duplicates")
    unknown = set(actions) - set(LEGAL_ACTION_ORDER)
    if unknown:
        raise ValueError(f"unknown legal actions: {sorted(unknown)}")
    return tuple(action for action in LEGAL_ACTION_ORDER if action in set(actions))


def weighted_categorical(
    ordered_outcomes: Sequence[str], weights: Sequence[float], draw_digest: str
) -> str:
    """Map a digest through the approved exact rational inverse CDF."""
    if not ordered_outcomes or len(ordered_outcomes) != len(weights):
        raise ValueError("outcomes and weights must be non-empty and equally sized")
    if len(set(ordered_outcomes)) != len(ordered_outcomes):
        raise ValueError("outcomes must be unique")
    exact: list[Fraction] = []
    for weight in weights:
        if not isinstance(weight, float) or not math.isfinite(weight) or weight < 0:
            raise ValueError("weights must be finite non-negative binary64 values")
        exact.append(Fraction(*weight.as_integer_ratio()))
    total = sum(exact, start=Fraction(0))
    if total <= 0:
        raise ValueError("weight total must be positive")
    x = int(_validate_sha256(draw_digest, "draw digest"), 16)
    cumulative = Fraction(0)
    for outcome, weight in zip(ordered_outcomes, exact, strict=True):
        cumulative += weight
        if Fraction(x) * total < Fraction(_M) * cumulative:
            return outcome
    raise ValueError("weighted categorical failed without a permitted fallback")


def epsilon_branch_fires(draw_digest: str, epsilon: str) -> bool:
    """Apply the exact ADR-0022 epsilon inequality."""
    try:
        fraction = Fraction(Decimal(epsilon))
    except Exception as exc:
        raise ValueError("epsilon must be a canonical decimal string") from exc
    canonical = format(Decimal(epsilon), "f").rstrip("0").rstrip(".") or "0"
    if epsilon != canonical or not Fraction(0) <= fraction <= Fraction(1):
        raise ValueError("epsilon must be canonical and in [0, 1]")
    x = int(_validate_sha256(draw_digest, "epsilon branch digest"), 16)
    return x * fraction.denominator < fraction.numerator * _M


def uniform_action(
    legal_actions: Sequence[str], stream_root: StreamRoot, *, decision_index: int
) -> tuple[str, str, int]:
    """Select an exact discrete-uniform action with local rejection attempts."""
    _validate_stream_root(stream_root, expected_stream_name="epsilon_action")
    ordered = canonical_legal_actions(legal_actions)
    limit = _M - (_M % len(ordered))
    for attempt in range(1 << 32):
        digest = derive_draw_digest(
            stream_root,
            decision_index=decision_index,
            attempt_index=attempt,
        )
        x = int(digest, 16)
        if x < limit:
            return ordered[x % len(ordered)], digest, attempt
    raise ValueError("epsilon action rejection attempt limit reached")


@dataclass(frozen=True, slots=True)
class ActionDrawAudit:
    final_action: str
    branch_fired: bool
    hero_action: str
    epsilon_action: str
    hero_draw_digest: str
    epsilon_branch_draw_digest: str
    epsilon_action_draw_digest: str
    hero_draw_status: Literal["used", "unused"]
    epsilon_action_draw_status: Literal["used", "unused"]
    epsilon_action_attempt: int


def sample_execution_action(
    *,
    final_policy: Mapping[str, float],
    legal_actions: Sequence[str],
    epsilon: str,
    decision_index: int,
    hero_stream_root: StreamRoot,
    epsilon_branch_stream_root: StreamRoot,
    epsilon_action_stream_root: StreamRoot,
) -> ActionDrawAudit:
    """Derive all three reserved action draws and use exactly one action draw."""
    ordered = canonical_legal_actions(legal_actions)
    if set(final_policy) != set(ordered):
        raise ValueError("final policy must cover exactly the legal action set")
    _validate_stream_root(hero_stream_root, expected_stream_name="hero_action")
    _validate_stream_root(epsilon_branch_stream_root, expected_stream_name="epsilon_branch")
    _validate_stream_root(epsilon_action_stream_root, expected_stream_name="epsilon_action")
    coordinates = {
        (
            root.payload["split"],
            root.payload["opponent_id"],
            root.payload["horizon"],
            root.payload["repetition_id"],
        )
        for root in (hero_stream_root, epsilon_branch_stream_root, epsilon_action_stream_root)
    }
    if len(coordinates) != 1:
        raise ValueError("action stream roots do not share one sampling identity")
    hero_digest = derive_draw_digest(hero_stream_root, decision_index=decision_index)
    branch_digest = derive_draw_digest(epsilon_branch_stream_root, decision_index=decision_index)
    epsilon_action, epsilon_digest, attempt = uniform_action(
        ordered, epsilon_action_stream_root, decision_index=decision_index
    )
    hero_action = weighted_categorical(
        ordered, [final_policy[action] for action in ordered], hero_digest
    )
    fired = epsilon_branch_fires(branch_digest, epsilon)
    return ActionDrawAudit(
        final_action=epsilon_action if fired else hero_action,
        branch_fired=fired,
        hero_action=hero_action,
        epsilon_action=epsilon_action,
        hero_draw_digest=hero_digest,
        epsilon_branch_draw_digest=branch_digest,
        epsilon_action_draw_digest=epsilon_digest,
        hero_draw_status="unused" if fired else "used",
        epsilon_action_draw_status="used" if fired else "unused",
        epsilon_action_attempt=attempt,
    )


@dataclass(frozen=True, slots=True)
class PrimaryCandidate:
    candidate_id: str
    epsilon: str
    sample_floor: int
    detector_confidence: str
    provider_confidence: str
    safety_alpha: str
    sampling_contract_sha256: str

    def canonical_payload(self) -> dict[str, object]:
        return {
            "grid_version": PRIMARY_GRID_VERSION,
            "epsilon": self.epsilon,
            "sample_floor": self.sample_floor,
            "detector_confidence": self.detector_confidence,
            "provider_confidence": self.provider_confidence,
            "safety_alpha": self.safety_alpha,
            "sampling_contract_sha256": self.sampling_contract_sha256,
        }


def primary_candidate_grid(*, sampling_contract_sha256: str) -> tuple[PrimaryCandidate, ...]:
    """Build the approved canonical 2x2x2x2 selectable grid."""
    _validate_sha256(sampling_contract_sha256, "sampling contract hash")
    candidates: list[PrimaryCandidate] = []
    for epsilon, floor, confidence, alpha in product(
        ("0.05", "0.1"), (10, 25), ("0.9", "0.95"), ("0.25", "0.5")
    ):
        payload = {
            "grid_version": PRIMARY_GRID_VERSION,
            "epsilon": epsilon,
            "sample_floor": floor,
            "detector_confidence": confidence,
            "provider_confidence": confidence,
            "safety_alpha": alpha,
            "sampling_contract_sha256": sampling_contract_sha256,
        }
        candidate_id = f"primary_bb_v2__{_sha256_bytes(_canonical_json_bytes(payload))}"
        candidates.append(
            PrimaryCandidate(
                candidate_id,
                epsilon,
                floor,
                confidence,
                confidence,
                alpha,
                sampling_contract_sha256,
            )
        )
    return tuple(sorted(candidates, key=lambda item: item.candidate_id))


def validate_primary_candidate_grid(candidates: Sequence[PrimaryCandidate]) -> None:
    """Reject missing, duplicate, noncanonical, epsilon-zero, or stale candidates."""
    if len(candidates) != 16 or len({item.candidate_id for item in candidates}) != 16:
        raise ValueError("primary grid must contain exactly 16 unique candidates")
    hashes = {item.sampling_contract_sha256 for item in candidates}
    if len(hashes) != 1:
        raise ValueError("primary candidates must reference one sampling contract hash")
    expected = primary_candidate_grid(sampling_contract_sha256=next(iter(hashes)))
    if tuple(candidates) != expected:
        raise ValueError("primary grid is not the canonical approved complete product")


@dataclass(frozen=True, slots=True)
class CandidateSelectionMetrics:
    candidate_id: str
    validation_macro_brier: Decimal
    validation_micro_brier: Decimal
    gto_false_positives: int
    gto_total_negatives: int
    validation_macro_exploitation_efficiency: Decimal | None
    validation_macro_recall: Decimal | None
    validation_macro_precision: Decimal | None
    gto_groups: tuple[GtoSelectionGroup, ...]


@dataclass(frozen=True, slots=True)
class GtoSelectionGroup:
    opponent_id: str
    horizon: int
    false_positives: int
    total_negatives: int
    status: str
    eligible_keys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExpectedGtoSelectionGroup:
    opponent_id: str
    horizon: int
    eligible_keys: tuple[str, ...]


def _compare_optional_descending(left: Decimal | None, right: Decimal | None) -> int:
    if left is None or right is None:
        return 0 if left is right else (1 if left is None else -1)
    return -1 if left > right else (1 if left < right else 0)


def _compare_metrics(left: CandidateSelectionMetrics, right: CandidateSelectionMetrics) -> int:
    for first, second in (
        (left.validation_macro_brier, right.validation_macro_brier),
        (left.validation_micro_brier, right.validation_micro_brier),
    ):
        if first != second:
            return -1 if first < second else 1
    left_ratio = Fraction(left.gto_false_positives, left.gto_total_negatives)
    right_ratio = Fraction(right.gto_false_positives, right.gto_total_negatives)
    if left_ratio != right_ratio:
        return -1 if left_ratio < right_ratio else 1
    for first, second in (
        (
            left.validation_macro_exploitation_efficiency,
            right.validation_macro_exploitation_efficiency,
        ),
        (left.validation_macro_recall, right.validation_macro_recall),
        (left.validation_macro_precision, right.validation_macro_precision),
    ):
        comparison = _compare_optional_descending(first, second)
        if comparison:
            return comparison
    return (
        -1
        if left.candidate_id < right.candidate_id
        else (1 if left.candidate_id > right.candidate_id else 0)
    )


def rank_primary_candidates(
    candidates: Sequence[PrimaryCandidate],
    metrics: Sequence[CandidateSelectionMetrics],
    *,
    expected_gto_groups: Sequence[ExpectedGtoSelectionGroup],
) -> tuple[CandidateSelectionMetrics, ...]:
    """Apply the approved seven-key order, failing on undefined GTO FPR."""
    validate_primary_candidate_grid(candidates)
    candidate_ids = {item.candidate_id for item in candidates}
    if len(metrics) != 16 or {item.candidate_id for item in metrics} != candidate_ids:
        raise ValueError("selection metrics must cover every candidate exactly once")
    expected = {
        (group.opponent_id, group.horizon): group.eligible_keys for group in expected_gto_groups
    }
    if not expected or len(expected) != len(expected_gto_groups):
        raise ValueError("expected GTO group provenance must be non-empty and unique")
    if any(not keys or len(set(keys)) != len(keys) for keys in expected.values()):
        raise ValueError("expected GTO eligible key provenance is invalid")
    for item in metrics:
        if (
            isinstance(item.gto_false_positives, bool)
            or isinstance(item.gto_total_negatives, bool)
            or item.gto_false_positives < 0
            or item.gto_total_negatives <= 0
            or item.gto_false_positives > item.gto_total_negatives
        ):
            raise ValueError("GTO FPR is zero/partial-undefined or has invalid counts")
        groups = {(group.opponent_id, group.horizon): group for group in item.gto_groups}
        if len(groups) != len(item.gto_groups) or set(groups) != set(expected):
            raise ValueError("GTO group set does not match expected provenance")
        aggregate_fp = 0
        aggregate_denominator = 0
        for key, group in groups.items():
            if group.status != "defined" or group.total_negatives <= 0:
                raise ValueError("GTO FPR has a partial-undefined group")
            if (
                isinstance(group.false_positives, bool)
                or isinstance(group.total_negatives, bool)
                or group.false_positives < 0
                or group.false_positives > group.total_negatives
            ):
                raise ValueError("GTO group counts are invalid")
            if group.eligible_keys != expected[key]:
                raise ValueError("GTO eligible key set differs across candidates")
            if group.total_negatives != len(group.eligible_keys):
                raise ValueError("GTO group denominator does not match eligible key provenance")
            aggregate_fp += group.false_positives
            aggregate_denominator += group.total_negatives
        if (aggregate_fp, aggregate_denominator) != (
            item.gto_false_positives,
            item.gto_total_negatives,
        ):
            raise ValueError("GTO aggregate counts do not match verified groups")
    return tuple(sorted(metrics, key=cmp_to_key(_compare_metrics)))


@dataclass(frozen=True, slots=True)
class AlphaComparatorPlan:
    comparator_id: str
    primary_candidate_id: str
    comparator_candidate_id: str
    comparator_status: Literal["existing_grid_candidate", "degenerate_equal_to_primary"]
    exact_delta: str | None


def alpha_050_comparator_plan(
    selected: PrimaryCandidate, candidates: Sequence[PrimaryCandidate]
) -> AlphaComparatorPlan:
    """Reference the exact alpha-only peer or record a zero-delta degenerate case."""
    validate_primary_candidate_grid(candidates)
    if selected not in candidates:
        raise ValueError("selected primary is outside the canonical grid")
    if selected.safety_alpha == "0.5":
        return AlphaComparatorPlan(
            COMPARATOR_ID,
            selected.candidate_id,
            selected.candidate_id,
            "degenerate_equal_to_primary",
            "0",
        )
    matches = [
        item
        for item in candidates
        if item.epsilon == selected.epsilon
        and item.sample_floor == selected.sample_floor
        and item.detector_confidence == selected.detector_confidence
        and item.provider_confidence == selected.provider_confidence
        and item.safety_alpha == "0.5"
        and item.sampling_contract_sha256 == selected.sampling_contract_sha256
    ]
    if len(matches) != 1:
        raise ValueError("alpha comparator must join exactly one existing grid candidate")
    return AlphaComparatorPlan(
        COMPARATOR_ID,
        selected.candidate_id,
        matches[0].candidate_id,
        "existing_grid_candidate",
        None,
    )


def p6_7_preregistration_payload(*, sampling_contract_sha256: str) -> dict[str, object]:
    """Return approved settings only; this is not a run or result artifact."""
    candidates = primary_candidate_grid(sampling_contract_sha256=sampling_contract_sha256)
    return {
        "repetition_seed_mapping": [
            {"repetition_id": repetition, "master_seed": seed}
            for repetition, seed in REPETITION_SEEDS
        ],
        "primary_grid_version": PRIMARY_GRID_VERSION,
        "primary_candidate_ids": [item.candidate_id for item in candidates],
        "primary_selection_version": PRIMARY_SELECTION_VERSION,
        "primary_selection_keys": [
            {"metric_id": metric, "direction": direction}
            for metric, direction in PRIMARY_SELECTION_KEYS
        ],
        "gto_fpr_hard_constraint": None,
        "worst_case_penalty_usage": "excluded",
        "comparator_id": COMPARATOR_ID,
        "reserved_uninstantiated": {
            "id": RESERVED_ALPHA_ABLATION_ID,
            "reason": RESERVED_ALPHA_ABLATION_REASON,
        },
    }


@dataclass(frozen=True, slots=True)
class CatalogFixtureEvidence:
    config: OpponentModelConfig
    strategy_sha256: str
    primary_true_deltas: tuple[tuple[str, Decimal], ...]
    control_role: str | None
    end_to_end_coverage: bool
    r008_semantic_id: str | None


def _strategy_content_sha256(strategy: Mapping[str, Mapping[str, float]]) -> str:
    payload = [
        {
            "infoset": infoset,
            "actions": [
                {"action": action, "probability_binary64_hex": probability.hex()}
                for action, probability in sorted(strategy[infoset].items())
            ],
        }
        for infoset in sorted(strategy)
    ]
    return _sha256_bytes(_canonical_json_bytes(payload))


def _validate_coverage_evaluation(coverage_evaluation: CoverageEvaluation) -> None:
    if not isinstance(coverage_evaluation, CoverageEvaluation):
        raise TypeError("catalog evidence requires a P6-4 CoverageEvaluation")
    results = coverage_evaluation.component_results
    if (
        tuple(result.component_role for result in results) != COMPONENT_ROLES
        or any(not result.matched or result.mismatch_fields for result in results)
        or not coverage_evaluation.matrix_matches_reconstruction
        or not coverage_evaluation.end_to_end_coverage
    ):
        raise ValueError("P6-4 R008 coverage provenance is not fully verified")


def build_catalog_fixture_evidence(
    configs: Sequence[OpponentModelConfig],
    *,
    coverage_evaluation: CoverageEvaluation,
) -> tuple[CatalogFixtureEvidence, ...]:
    """Build static catalog evidence from synthesis, independent truth, and P6-4 coverage."""
    _validate_coverage_evaluation(coverage_evaluation)
    evidence: list[CatalogFixtureEvidence] = []
    for config in configs:
        generated = synthesize_opponent(config=config)
        measurement_config = replace(
            config,
            leak_vector=(("LEAK_R007", "0.1"), ("LEAK_R008", "0.1")),
        )
        measurements = extract_true_leaks(
            generated.game,
            generated.equilibrium_strategy,
            generated.strategy,
            measurement_config,
        )
        truth = tuple((item.reason_id, item.true_leak) for item in measurements)
        is_r008 = "LEAK_R008" in config.leak_amounts
        evidence.append(
            CatalogFixtureEvidence(
                config=config,
                strategy_sha256=_strategy_content_sha256(generated.strategy),
                primary_true_deltas=truth,
                control_role=(
                    "gto_negative_control"
                    if config.split == "validation" and not config.leak_vector
                    else None
                ),
                end_to_end_coverage=is_r008 and coverage_evaluation.end_to_end_coverage,
                r008_semantic_id=R008_COVERAGE_SEMANTIC_ID if is_r008 else None,
            )
        )
    return tuple(evidence)


def validate_catalog_fixture(
    evidence: Sequence[CatalogFixtureEvidence],
    *,
    coverage_evaluation: CoverageEvaluation,
) -> None:
    """Enforce the approved 9+9 catalog and its static coverage/identity gates."""
    _validate_coverage_evaluation(coverage_evaluation)
    if len(evidence) != 18:
        raise ValueError("P6-7 catalog fixture must contain 18 opponents")
    configs = [item.config for item in evidence]
    for attribute in ("opponent_id", "config_sha256", "model_identity", "seed"):
        values = [getattr(config, attribute) for config in configs]
        if len(set(values)) != len(values):
            raise ValueError(f"catalog {attribute} values must be globally unique")
    for item in evidence:
        rebuilt = build_catalog_fixture_evidence(
            (item.config,), coverage_evaluation=coverage_evaluation
        )[0]
        if item != rebuilt:
            raise ValueError("catalog evidence does not match reconstructed provenance")
        _validate_sha256(item.strategy_sha256, "catalog strategy hash")
        truth = dict(item.primary_true_deltas)
        if set(truth) != set(_PRIMARY_REASONS):
            raise ValueError("catalog evidence must measure both primary reasons")
        for value in truth.values():
            if not value.is_finite():
                raise ValueError("catalog true deltas must be finite")
        requested = item.config.leak_amounts
        for reason in _PRIMARY_REASONS:
            if reason in requested and abs(truth[reason] - requested[reason]) > Decimal("1e-12"):
                raise ValueError("catalog true delta does not match the requested delta")
    by_split = {
        split: [item for item in evidence if item.config.split == split]
        for split in ("training", "validation")
    }
    if {split: len(items) for split, items in by_split.items()} != {
        "training": 9,
        "validation": 9,
    }:
        raise ValueError("P6-7 catalog requires nine opponents in each development split")
    actual_additions: set[tuple[str, str | None, str, int]] = set()
    for item in evidence:
        config = item.config
        if config.seed < 1000:
            continue
        if not config.leak_vector:
            actual_additions.add((config.split, None, "0", config.seed))
        elif len(config.leak_vector) == 1:
            reason, amount = config.leak_vector[0]
            actual_additions.add((config.split, reason, str(Decimal(amount)), config.seed))
    if actual_additions != _EXPECTED_ADDITIONS:
        raise ValueError("catalog additions do not match the approved deltas and seeds")
    validation_controls = [
        item for item in by_split["validation"] if item.control_role == "gto_negative_control"
    ]
    if len(validation_controls) != 1 or validation_controls[0].config.leak_vector:
        raise ValueError("validation requires exactly one explicit GTO negative control")
    if any(
        dict(item.primary_true_deltas)[reason] != 0
        for item in validation_controls
        for reason in _PRIMARY_REASONS
    ):
        raise ValueError("validation GTO control must be negative for both primary reasons")
    gto_entries = [item for item in evidence if not item.config.leak_vector]
    if (
        len(gto_entries) != 2
        or len({item.config.equilibrium_artifact_sha256 for item in gto_entries}) != 1
        or len({item.strategy_sha256 for item in gto_entries}) != 1
    ):
        raise ValueError("split GTO controls must join one frozen equilibrium strategy")
    for split, items in by_split.items():
        for reason in _PRIMARY_REASONS:
            labels = {
                int(dict(item.primary_true_deltas)[reason] > Decimal("0.25")) for item in items
            }
            if labels != {0, 1}:
                raise ValueError(f"{split} {reason} lacks positive/negative fixture coverage")
        if not any(
            dict(item.primary_true_deltas)["LEAK_R008"] > Decimal("0.25")
            and item.end_to_end_coverage
            and item.r008_semantic_id == R008_COVERAGE_SEMANTIC_ID
            for item in items
        ):
            raise ValueError(f"{split} lacks R008 positive end-to-end coverage")
    nongto = [item for item in evidence if item.config.leak_vector]
    hashes = [item.strategy_sha256 for item in nongto]
    if len(set(hashes)) != len(hashes):
        raise ValueError("non-GTO strategy hashes must not repeat across splits")


__all__ = [
    "COMPARATOR_ID",
    "DRAW_DERIVATION_VERSION",
    "EXECUTION_SAMPLER_VERSION",
    "LEGAL_ACTION_ORDER",
    "LEGAL_ACTION_ORDER_VERSION",
    "PRIMARY_SELECTION_KEYS",
    "PROBABILITY_MAPPING_VERSION",
    "R008_COVERAGE_SEMANTIC_ID",
    "REPETITION_SEEDS",
    "RESERVED_ALPHA_ABLATION_ID",
    "RESERVED_ALPHA_ABLATION_REASON",
    "SAMPLING_CONTRACT_SCHEMA_VERSION",
    "SEED_DERIVATION_VERSION",
    "STREAM_NAMES",
    "ActionDrawAudit",
    "AlphaComparatorPlan",
    "CandidateSelectionMetrics",
    "CatalogFixtureEvidence",
    "ExpectedGtoSelectionGroup",
    "GtoSelectionGroup",
    "ObservationDrawAudit",
    "ObservationNodeSpec",
    "ObservationRegistry",
    "PrimaryCandidate",
    "StreamRoot",
    "alpha_050_comparator_plan",
    "build_catalog_fixture_evidence",
    "canonical_legal_actions",
    "derive_draw_digest",
    "derive_stream_root",
    "epsilon_branch_fires",
    "p6_7_preregistration_payload",
    "primary_candidate_grid",
    "rank_primary_candidates",
    "sample_execution_action",
    "sample_observation_node",
    "sampling_contract_payload",
    "sampling_contract_sha256",
    "uniform_action",
    "validate_catalog_fixture",
    "validate_primary_candidate_grid",
    "validate_sampling_contract",
    "weighted_categorical",
]
