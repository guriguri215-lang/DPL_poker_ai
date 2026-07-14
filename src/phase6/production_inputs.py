"""Production Training input contracts for the P6-7 execution boundary.

This module builds no batch or result files and runs no Training or Validation.
It freezes the deterministic observation registry for a frozen river game and
constructs the canonical in-memory inputs consumed by the existing P6-6
evaluator.  A separately approved backend may later supply terminal counts,
policies, and exact-EV cells through these strict boundaries.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal, localcontext

from opponents import load_training_catalog
from opponents.ground_truth import extract_independent_action_rates
from opponents.synthesis import SynthesizedOpponent, synthesize_opponent
from poker_ai.leak import beta_binomial_upper_tail
from poker_solver.game import Chance, Decision, Game, Node, Terminal

from .calibration import (
    BOUNDARY_ABS_TOLERANCE_WIRE,
    CALIBRATION_EVALUATOR_VERSION,
    DECIMAL_PRECISION,
    DECIMAL_ROUNDING,
    EXACT_EV_INPUT_VERSION,
    GROUND_TRUTH_SCHEMA_VERSION,
    TERMINAL_SNAPSHOT_SCHEMA_VERSION,
    CalibrationEvaluation,
    CanonicalCalibrationArtifact,
    ExactEvObservation,
    calibration_series_id,
    evaluate_all_candidate_calibration,
    exact_ev_observation_sha256,
)
from .contracts import (
    GTO_FPR_METRIC_ID,
    R008_SEMANTIC_ID,
    ValidatedPhase6ContractBundle,
    canonical_json_bytes,
    sha256_bytes,
)
from .exact_ev import ExactEvCell
from .p6_7 import (
    EXECUTION_SAMPLER_VERSION,
    REPETITION_SEEDS,
    ObservationNodeSpec,
    ObservationRegistry,
    PrimaryCandidate,
    primary_candidate_grid,
    sampling_contract_sha256,
    validate_sampling_contract,
)
from .training_runner import HORIZONS, TrainingSessionKey

PRODUCTION_OBSERVATION_REGISTRY_VERSION = "phase6-river-observation-registry-v1"
PRODUCTION_OUTCOME_REGISTRY_VERSION = "phase6-river-chance-outcomes-v1"
PRODUCTION_INPUT_BUILDER_VERSION = "p6-7-production-training-inputs-v1"
GROUND_TRUTH_EXTRACTOR_VERSION = "phase6-independent-ground-truth-v1"
EXPLOIT_PROVIDER_VERSION = "nodelock-provider-r008-v2"
R008_REASON_ID = "LEAK_R008"
R008_SITUATION_KEY = "river_vs_check"
TAU_WIRE = "0.25"


@dataclass(frozen=True, slots=True)
class TrainingTerminalInput:
    """Public terminal action counts for one approved Training session."""

    key: TrainingSessionKey
    action_counts: Mapping[str, int]


@dataclass(frozen=True, slots=True)
class TrainingExactEvInput:
    """One independently evaluated P6-5 cell for an approved session."""

    key: TrainingSessionKey
    cell: ExactEvCell


@dataclass(frozen=True, slots=True)
class ProductionCalibrationInputs:
    """Canonical P6-6 inputs for exactly one approved primary candidate."""

    builder_version: str
    candidate: PrimaryCandidate
    sampling_contract: dict[str, object]
    observation_registry: ObservationRegistry
    opponents: tuple[SynthesizedOpponent, ...]
    series_descriptor: dict[str, object]
    terminal_snapshots: CanonicalCalibrationArtifact
    ground_truth: CanonicalCalibrationArtifact
    exact_ev_observations: tuple[ExactEvObservation, ...]


def build_production_observation_registry(game: Game) -> ObservationRegistry:
    """Derive a closed-world chance registry from a frozen river game tree."""
    if not isinstance(game, Game) or game.name != "river":
        raise ValueError("production observation registry requires the frozen river game")
    nodes: list[ObservationNodeSpec] = []
    _collect_chance_nodes(game.root, game_id=game.name, path=(), result=nodes)
    if not nodes:
        raise ValueError("production river game must contain at least one chance node")
    return ObservationRegistry(
        PRODUCTION_OBSERVATION_REGISTRY_VERSION,
        tuple(sorted(nodes, key=lambda item: item.node_id)),
    )


def validate_production_observation_registry(game: Game, registry: ObservationRegistry) -> None:
    """Reconstruct the complete registry and reject any substituted mapping."""
    if not isinstance(registry, ObservationRegistry):
        raise TypeError("registry must be an ObservationRegistry")
    if registry != build_production_observation_registry(game):
        raise ValueError("production observation registry does not match the frozen game")


def build_production_calibration_inputs(
    *,
    contract_bundle: ValidatedPhase6ContractBundle,
    candidate: PrimaryCandidate,
    sampling_contract: Mapping[str, object],
    observation_registry: ObservationRegistry,
    opponents: Sequence[SynthesizedOpponent],
    terminal_inputs: Sequence[TrainingTerminalInput],
    exact_ev_inputs: Sequence[TrainingExactEvInput],
) -> ProductionCalibrationInputs:
    """Build and independently validate one candidate's complete P6-6 inputs."""
    _validate_contract_bundle(contract_bundle)
    validate_sampling_contract(sampling_contract)
    contract_sha = sampling_contract_sha256(sampling_contract)
    _validate_primary_candidate(candidate, contract_sha)
    if (
        sampling_contract["observation_registry_version"] != observation_registry.registry_version
        or sampling_contract["observation_registry_sha256"] != observation_registry.sha256
    ):
        raise ValueError("sampling contract does not join the production observation registry")

    ordered_opponents = _validate_training_opponents(opponents, observation_registry)
    descriptor, truth_by_opponent, strategy_hashes = _series_descriptor(
        candidate,
        sampling_contract,
        ordered_opponents,
        contract_bundle,
    )
    series_id = descriptor["series_id"]
    assert isinstance(series_id, str)
    expected_keys = _expected_session_keys(candidate, ordered_opponents)
    terminal_by_key = _closed_world_inputs(
        terminal_inputs, expected_keys, TrainingTerminalInput, "terminal inputs"
    )
    exact_by_key = _closed_world_inputs(
        exact_ev_inputs, expected_keys, TrainingExactEvInput, "exact-EV inputs"
    )

    dimension = descriptor["candidate_dimensions"][0]
    config = descriptor["config"]
    terminal_records = [
        _terminal_record(
            series_id,
            terminal_by_key[key],
            dimension=dimension,
            config=config,
        )
        for key in expected_keys
    ]
    terminal_records.sort(key=_record_key)
    ground_truth_records = [
        _ground_truth_record(
            series_id,
            key,
            dimension=dimension,
            truth=truth_by_opponent[key.opponent_id],
            strategy_sha256=strategy_hashes[key.opponent_id],
        )
        for key in expected_keys
    ]
    ground_truth_records.sort(key=_record_key)

    refs = _contract_refs(contract_bundle)
    terminal_artifact = _canonical_artifact(
        {
            "schema_version": TERMINAL_SNAPSHOT_SCHEMA_VERSION,
            "artifact_type": "terminal_candidate_snapshots",
            "contract_refs": refs,
            "series": [descriptor],
            "records": terminal_records,
        }
    )
    ground_truth_artifact = _canonical_artifact(
        {
            "schema_version": GROUND_TRUTH_SCHEMA_VERSION,
            "artifact_type": "calibration_ground_truth",
            "contract_refs": refs,
            "series_descriptor_sha256s": {
                series_id: sha256_bytes(canonical_json_bytes(descriptor))
            },
            "records": ground_truth_records,
        }
    )
    observations = tuple(
        _exact_ev_observation(series_id, exact_by_key[key], key) for key in expected_keys
    )
    observations = tuple(
        sorted(
            observations,
            key=lambda item: (
                item.series_id,
                item.opponent_id,
                item.horizon,
                item.repetition_id,
            ),
        )
    )
    result = ProductionCalibrationInputs(
        PRODUCTION_INPUT_BUILDER_VERSION,
        candidate,
        dict(sampling_contract),
        observation_registry,
        ordered_opponents,
        descriptor,
        terminal_artifact,
        ground_truth_artifact,
        observations,
    )
    verify_production_calibration_inputs(contract_bundle, result)
    return result


def verify_production_calibration_inputs(
    contract_bundle: ValidatedPhase6ContractBundle,
    inputs: ProductionCalibrationInputs,
) -> CalibrationEvaluation:
    """Reconstruct production-derived values before applying the P6-6 gates."""
    if not isinstance(inputs, ProductionCalibrationInputs):
        raise TypeError("inputs must be ProductionCalibrationInputs")
    if inputs.builder_version != PRODUCTION_INPUT_BUILDER_VERSION:
        raise ValueError("unsupported production input builder version")
    _validate_contract_bundle(contract_bundle)
    validate_sampling_contract(inputs.sampling_contract)
    contract_sha = sampling_contract_sha256(inputs.sampling_contract)
    _validate_primary_candidate(inputs.candidate, contract_sha)
    if (
        inputs.sampling_contract["observation_registry_version"]
        != inputs.observation_registry.registry_version
        or inputs.sampling_contract["observation_registry_sha256"]
        != inputs.observation_registry.sha256
    ):
        raise ValueError("sampling contract does not join the production observation registry")

    ordered_opponents = _validate_training_opponents(inputs.opponents, inputs.observation_registry)
    descriptor, truth_by_opponent, strategy_hashes = _series_descriptor(
        inputs.candidate,
        inputs.sampling_contract,
        ordered_opponents,
        contract_bundle,
    )
    if inputs.series_descriptor != descriptor:
        raise ValueError("production series descriptor does not reconstruct from provenance")
    series_id = descriptor["series_id"]
    assert isinstance(series_id, str)
    expected_keys = _expected_session_keys(inputs.candidate, ordered_opponents)

    terminal_payload = _load_production_payload(inputs.terminal_snapshots.raw, "terminal snapshots")
    terminal_records = terminal_payload.get("records")
    if not isinstance(terminal_records, list):
        raise ValueError("production terminal snapshots records must be a list")
    session_coordinates = [
        (record.get("opponent_id"), record.get("horizon"), record.get("repetition_id"))
        if isinstance(record, dict)
        else None
        for record in terminal_records
    ]
    expected_coordinates = [
        (key.opponent_id, key.horizon, key.repetition_id) for key in expected_keys
    ]
    if session_coordinates != expected_coordinates:
        raise ValueError("production terminal snapshots do not match approved session order")
    dimension = descriptor["candidate_dimensions"][0]
    config = descriptor["config"]
    rebuilt_terminal_records = [
        _terminal_record(
            series_id,
            TrainingTerminalInput(key, record.get("action_counts", {})),
            dimension=dimension,
            config=config,
        )
        for key, record in zip(expected_keys, terminal_records, strict=True)
    ]
    rebuilt_terminal_records.sort(key=_record_key)
    expected_terminal = _canonical_artifact(
        {
            "schema_version": TERMINAL_SNAPSHOT_SCHEMA_VERSION,
            "artifact_type": "terminal_candidate_snapshots",
            "contract_refs": _contract_refs(contract_bundle),
            "series": [descriptor],
            "records": rebuilt_terminal_records,
        }
    )
    if inputs.terminal_snapshots != expected_terminal:
        raise ValueError("production terminal snapshots do not reconstruct from action counts")

    rebuilt_truth_records = [
        _ground_truth_record(
            series_id,
            key,
            dimension=dimension,
            truth=truth_by_opponent[key.opponent_id],
            strategy_sha256=strategy_hashes[key.opponent_id],
        )
        for key in expected_keys
    ]
    rebuilt_truth_records.sort(key=_record_key)
    expected_ground_truth = _canonical_artifact(
        {
            "schema_version": GROUND_TRUTH_SCHEMA_VERSION,
            "artifact_type": "calibration_ground_truth",
            "contract_refs": _contract_refs(contract_bundle),
            "series_descriptor_sha256s": {
                series_id: sha256_bytes(canonical_json_bytes(descriptor))
            },
            "records": rebuilt_truth_records,
        }
    )
    if inputs.ground_truth != expected_ground_truth:
        raise ValueError("production ground truth does not reconstruct from frozen strategies")

    opponents_by_id = {item.config.opponent_id: item for item in ordered_opponents}
    rebuilt_observations: list[ExactEvObservation] = []
    if len(inputs.exact_ev_observations) != len(expected_keys):
        raise ValueError("production exact-EV observations do not match approved sessions")
    for key, observation in zip(expected_keys, inputs.exact_ev_observations, strict=True):
        if not isinstance(observation, ExactEvObservation):
            raise TypeError("production exact-EV inputs must contain ExactEvObservation values")
        if (
            observation.series_id,
            observation.opponent_id,
            observation.horizon,
            observation.repetition_id,
        ) != (series_id, key.opponent_id, key.horizon, key.repetition_id):
            raise ValueError("production exact-EV observations do not match approved session order")
        _validate_exact_ev_opponent_profile(observation.cell, opponents_by_id[key.opponent_id])
        rebuilt_observations.append(
            _exact_ev_observation(
                series_id,
                TrainingExactEvInput(key, observation.cell),
                key,
            )
        )
    if inputs.exact_ev_observations != tuple(rebuilt_observations):
        raise ValueError("production exact-EV observations do not reconstruct from provenance")
    return evaluate_all_candidate_calibration(
        contract_bundle,
        inputs.terminal_snapshots,
        inputs.ground_truth,
        inputs.exact_ev_observations,
    )


def _collect_chance_nodes(
    node: Node,
    *,
    game_id: str,
    path: tuple[dict[str, str], ...],
    result: list[ObservationNodeSpec],
) -> None:
    if isinstance(node, Terminal):
        return
    if isinstance(node, Chance):
        labels = [label for _probability, _child, label in node.branches]
        if any(not isinstance(label, str) or not label for label in labels):
            raise ValueError("production chance outcomes require non-empty labels")
        if len(set(labels)) != len(labels):
            raise ValueError("production chance outcome labels must be unique per node")
        identity = {"game_id": game_id, "path": list(path)}
        node_id = f"chance__{sha256_bytes(canonical_json_bytes(identity))}"
        result.append(
            ObservationNodeSpec(
                node_id,
                PRODUCTION_OUTCOME_REGISTRY_VERSION,
                tuple((label, float(probability)) for probability, _child, label in node.branches),
            )
        )
        for _probability, child, label in node.branches:
            _collect_chance_nodes(
                child,
                game_id=game_id,
                path=(*path, {"kind": "chance", "value": label}),
                result=result,
            )
        return
    assert isinstance(node, Decision)
    for action, child in zip(node.actions, node.children, strict=True):
        _collect_chance_nodes(
            child,
            game_id=game_id,
            path=(
                *path,
                {"kind": "infoset", "value": node.infoset},
                {"kind": "action", "value": action},
            ),
            result=result,
        )


def _validate_contract_bundle(bundle: ValidatedPhase6ContractBundle) -> None:
    if not isinstance(bundle, ValidatedPhase6ContractBundle):
        raise TypeError("contract_bundle must be a validated P6-4 bundle")
    if not bundle.coverage_evaluation.end_to_end_coverage:
        raise ValueError("P6-4 coverage hard gate is not satisfied")
    if bundle.selection_contract.get("gto_fpr", {}).get("metric_id") != GTO_FPR_METRIC_ID:
        raise ValueError("P6-4 selection metric provenance is invalid")
    reason_rows = bundle.coverage_contract.get("reason_rows")
    if not isinstance(reason_rows, list) or len(reason_rows) != 1:
        raise ValueError("production inputs require exactly one frozen R008 semantic row")
    row = reason_rows[0]
    if row.get("reason_id") != R008_REASON_ID or row.get("semantic_id") != R008_SEMANTIC_ID:
        raise ValueError("P6-4 semantic row is not the frozen R008 contract")


def _validate_training_opponents(
    opponents: Sequence[SynthesizedOpponent], registry: ObservationRegistry
) -> tuple[SynthesizedOpponent, ...]:
    if any(not isinstance(item, SynthesizedOpponent) for item in opponents):
        raise TypeError("opponents must contain SynthesizedOpponent values")
    ordered = tuple(sorted(opponents, key=lambda item: item.config.opponent_id))
    approved = tuple(sorted(load_training_catalog(), key=lambda item: item.opponent_id))
    if tuple(item.config for item in ordered) != approved:
        raise ValueError("production inputs require the complete approved Training catalog")
    if len({item.config.opponent_id for item in ordered}) != len(ordered):
        raise ValueError("production Training opponent IDs must be unique")
    for item in ordered:
        if item.config.split != "training":
            raise ValueError("production inputs reject non-Training opponents")
        if item.config_sha256 != item.config.config_sha256:
            raise ValueError("synthesized opponent config hash mismatch")
        if item.equilibrium_artifact_sha256 != item.config.equilibrium_artifact_sha256:
            raise ValueError("synthesized opponent equilibrium provenance mismatch")
        expected = synthesize_opponent(config=item.config)
        _validate_synthesized_opponent(item, expected)
        validate_production_observation_registry(item.game, registry)
    return ordered


def _validate_primary_candidate(candidate: PrimaryCandidate, contract_sha: str) -> None:
    if not isinstance(candidate, PrimaryCandidate):
        raise TypeError("candidate must be a PrimaryCandidate")
    matches = [
        approved
        for approved in primary_candidate_grid(sampling_contract_sha256=contract_sha)
        if approved == candidate
    ]
    if len(matches) != 1:
        raise ValueError("candidate does not join a canonical approved primary grid member")


def _validate_synthesized_opponent(
    actual: SynthesizedOpponent, expected: SynthesizedOpponent
) -> None:
    scalar_fields = (
        "config",
        "config_sha256",
        "equilibrium_version",
        "equilibrium_artifact_sha256",
        "node_lock_config",
        "leak_targets",
        "application",
    )
    if any(getattr(actual, field) != getattr(expected, field) for field in scalar_fields):
        raise ValueError("synthesized opponent does not match approved deterministic synthesis")
    if _game_sha256(actual.game) != _game_sha256(expected.game):
        raise ValueError("synthesized opponent game does not match the frozen equilibrium")
    if _strategy_sha256(actual.equilibrium_strategy) != _strategy_sha256(
        expected.equilibrium_strategy
    ):
        raise ValueError("synthesized opponent equilibrium profile does not match frozen content")
    if _strategy_sha256(actual.strategy) != _strategy_sha256(expected.strategy):
        raise ValueError(
            "synthesized opponent strategy does not match approved deterministic synthesis"
        )


def _expected_session_keys(
    candidate: PrimaryCandidate, opponents: Sequence[SynthesizedOpponent]
) -> tuple[TrainingSessionKey, ...]:
    return tuple(
        TrainingSessionKey(
            candidate.candidate_id,
            opponent.config.opponent_id,
            horizon,
            repetition_id,
        )
        for opponent in opponents
        for horizon in HORIZONS
        for repetition_id, _seed in REPETITION_SEEDS
    )


def _load_production_payload(raw: object, label: str) -> dict[str, object]:
    if not isinstance(raw, bytes):
        raise TypeError(f"production {label} raw value must be bytes")
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"production {label} must be JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"production {label} must be a JSON object")
    return payload


def _validate_exact_ev_opponent_profile(cell: ExactEvCell, opponent: SynthesizedOpponent) -> None:
    if not isinstance(cell, ExactEvCell):
        raise TypeError("production exact-EV observation cell must be an ExactEvCell")
    hero_player = 0 if opponent.config.opponent_position == "IP" else 1
    if (
        cell.profiles.game_id != opponent.game.name
        or cell.profiles.opponent_id != opponent.config.opponent_id
        or cell.profiles.hero_player != hero_player
    ):
        raise ValueError("exact-EV profile identity does not join frozen opponent provenance")
    opponent_infosets = opponent.game.infosets_of(1 - hero_player)
    expected = {infoset: opponent.strategy[infoset] for infoset in opponent_infosets}
    for label, profile in (
        ("base", cell.profiles.base),
        ("final", cell.profiles.final),
        ("oracle BR", cell.profiles.oracle_br),
    ):
        try:
            actual = {infoset: profile[infoset] for infoset in opponent_infosets}
        except KeyError as exc:
            raise ValueError(f"exact-EV {label} profile is missing opponent policy") from exc
        if actual != expected:
            raise ValueError(
                f"exact-EV {label} opponent profile does not join frozen strategy provenance"
            )


def _game_sha256(game: Game) -> str:
    return sha256_bytes(canonical_json_bytes({"name": game.name, "root": _node_payload(game.root)}))


def _node_payload(node: Node) -> dict[str, object]:
    if isinstance(node, Terminal):
        return {"kind": "terminal", "payoff_binary64_hex": float(node.payoff).hex()}
    if isinstance(node, Chance):
        return {
            "kind": "chance",
            "branches": [
                {
                    "probability_binary64_hex": probability.hex(),
                    "label": label,
                    "child": _node_payload(child),
                }
                for probability, child, label in node.branches
            ],
        }
    assert isinstance(node, Decision)
    return {
        "kind": "decision",
        "player": node.player,
        "infoset": node.infoset,
        "actions": list(node.actions),
        "children": [_node_payload(child) for child in node.children],
    }


def _series_descriptor(
    candidate: PrimaryCandidate,
    sampling_contract: Mapping[str, object],
    opponents: Sequence[SynthesizedOpponent],
    bundle: ValidatedPhase6ContractBundle,
) -> tuple[dict[str, object], dict[str, tuple[Decimal, Decimal]], dict[str, str]]:
    gto = [item for item in opponents if not item.config.leak_vector]
    if len(gto) != 1:
        raise ValueError("Training catalog must contain exactly one GTO negative control")
    baseline_truth = extract_independent_action_rates(
        gto[0].game,
        gto[0].equilibrium_strategy,
        gto[0].config,
        reason_ids=(R008_REASON_ID,),
    )[0]
    baseline_rate = _decimal_wire(baseline_truth.action_rate)
    semantic = bundle.coverage_contract["reason_rows"][0]
    action_rows = bundle.coverage_contract["action_family_registry"]["rows"]
    action_row = next(
        (item for item in action_rows if item["action_family_id"] == semantic["action_family_id"]),
        None,
    )
    if action_row is None:
        raise ValueError("P6-4 action family is missing")
    dimension = {
        "rule_id": R008_REASON_ID,
        "situation_key": semantic["situation_id"],
        "semantic_id": semantic["semantic_id"],
        "action_family_id": semantic["action_family_id"],
        "opportunity_event_id": semantic["opportunity_event_id"],
        "action_group": action_row["detector_encodings"],
        "baseline_rate": baseline_rate,
    }
    strategy_hashes: dict[str, str] = {}
    truth: dict[str, tuple[Decimal, Decimal]] = {}
    opponent_rows: list[dict[str, object]] = []
    for item in opponents:
        is_gto = not item.config.leak_vector
        strategy_hash = (
            item.equilibrium_artifact_sha256 if is_gto else _strategy_sha256(item.strategy)
        )
        strategy_hashes[item.config.opponent_id] = strategy_hash
        measurement = extract_independent_action_rates(
            item.game,
            item.strategy,
            item.config,
            reason_ids=(R008_REASON_ID,),
        )[0]
        truth[item.config.opponent_id] = (
            measurement.action_rate,
            measurement.opportunity_reach,
        )
        opponent_rows.append(
            {
                "opponent_id": item.config.opponent_id,
                "control_role": "gto_negative_control" if is_gto else "evaluation",
                "strategy_artifact_sha256": strategy_hash,
                "equilibrium_artifact_sha256": (
                    item.equilibrium_artifact_sha256 if is_gto else None
                ),
            }
        )
    config = {
        "split": "training",
        "opponent_catalog_sha256": sha256_bytes(
            canonical_json_bytes([item.config.canonical_payload() for item in opponents])
        ),
        "estimator_method_version": "beta-binomial-upper-tail-v1",
        "estimator_config_sha256": sha256_bytes(
            canonical_json_bytes(
                {
                    "method_version": "beta-binomial-upper-tail-v1",
                    "alpha0": "1",
                    "beta0": "1",
                    "tail": "upper",
                    "tau": TAU_WIRE,
                    "sample_floor": candidate.sample_floor,
                    "detector_threshold": candidate.detector_confidence,
                    "provider_threshold": candidate.provider_confidence,
                }
            )
        ),
        "baseline_table_sha256": sha256_bytes(
            canonical_json_bytes(
                {
                    "reason_id": R008_REASON_ID,
                    "situation_key": R008_SITUATION_KEY,
                    "baseline_rate": baseline_rate,
                    "action_group": dimension["action_group"],
                }
            )
        ),
        "tau": TAU_WIRE,
        "sample_floor": candidate.sample_floor,
        "detector_threshold": candidate.detector_confidence,
        "provider_threshold": candidate.provider_confidence,
        "exploit_provider": EXPLOIT_PROVIDER_VERSION,
        "safety_alpha": candidate.safety_alpha,
        "execution_sampler_version": EXECUTION_SAMPLER_VERSION,
        "epsilon": candidate.epsilon,
        "epsilon_distribution_sha256": sha256_bytes(
            canonical_json_bytes(
                {
                    "distribution": "legal_uniform",
                    "epsilon": candidate.epsilon,
                    "sampling_contract_sha256": sampling_contract_sha256(sampling_contract),
                }
            )
        ),
        "horizon_set": list(HORIZONS),
        "repetition_set": [item for item, _seed in REPETITION_SEEDS],
        "evaluator_version": CALIBRATION_EVALUATOR_VERSION,
        "boundary_abs_tolerance": BOUNDARY_ABS_TOLERANCE_WIRE,
        "decimal_precision": DECIMAL_PRECISION,
        "decimal_rounding": DECIMAL_ROUNDING,
        "game_id": opponents[0].game.name,
        "ground_truth_extractor_version": GROUND_TRUTH_EXTRACTOR_VERSION,
        "exact_ev_evaluator_version": EXACT_EV_INPUT_VERSION,
    }
    descriptor = {
        "series_id": calibration_series_id(config, opponent_rows, [dimension]),
        "config": config,
        "opponents": opponent_rows,
        "candidate_dimensions": [dimension],
    }
    return descriptor, truth, strategy_hashes


def _closed_world_inputs(
    values: Sequence[object],
    expected_keys: Sequence[TrainingSessionKey],
    expected_type: type,
    label: str,
) -> dict[TrainingSessionKey, object]:
    if any(not isinstance(item, expected_type) for item in values):
        raise TypeError(f"{label} contain an unsupported value")
    keys = [item.key for item in values]
    if keys != list(expected_keys) or len(set(keys)) != len(keys):
        raise ValueError(f"{label} do not exactly match the approved session order")
    return {item.key: item for item in values}


def _terminal_record(
    series_id: str,
    source: TrainingTerminalInput,
    *,
    dimension: Mapping[str, object],
    config: Mapping[str, object],
) -> dict[str, object]:
    counts = dict(sorted(source.action_counts.items()))
    if not counts or any(
        not isinstance(action, str)
        or not action
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
        for action, count in counts.items()
    ):
        raise ValueError("terminal action counts must be non-negative integers")
    n = sum(counts.values())
    if n > source.key.horizon:
        raise ValueError("terminal action counts exceed the session horizon")
    action_group = dimension["action_group"]
    assert isinstance(action_group, list)
    k = sum(counts.get(action, 0) for action in action_group)
    baseline = Decimal(str(dimension["baseline_rate"]))
    tau = Decimal(TAU_WIRE)
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        q = baseline + tau
        observed = Decimal(k) / Decimal(n) if n else Decimal(0)
    confidence = beta_binomial_upper_tail(
        k=k,
        n=n,
        baseline_rate=float(baseline),
        tau=float(tau),
    )
    confidence_wire = _decimal_wire(Decimal(str(confidence)))
    eligibility = {
        "structurally_eligible": Decimal(0) < q < Decimal(1),
        "sample_gate": n >= config["sample_floor"],
        "deviation_gate": observed - baseline >= tau,
        "confidence_gate": Decimal(confidence_wire) >= Decimal(str(config["detector_threshold"])),
    }
    eligibility["emitted"] = all(eligibility.values())
    return {
        "series_id": series_id,
        "opponent_id": source.key.opponent_id,
        "rule_id": dimension["rule_id"],
        "situation_key": dimension["situation_key"],
        "horizon": source.key.horizon,
        "repetition_id": source.key.repetition_id,
        "action_counts": counts,
        "action_group": action_group,
        "n": n,
        "k": k,
        "baseline_rate": dimension["baseline_rate"],
        "tau": TAU_WIRE,
        "q": _decimal_wire(q),
        "posterior_confidence": confidence_wire,
        "candidate_eligibility": eligibility,
    }


def _ground_truth_record(
    series_id: str,
    key: TrainingSessionKey,
    *,
    dimension: Mapping[str, object],
    truth: tuple[Decimal, Decimal],
    strategy_sha256: str,
) -> dict[str, object]:
    return {
        "series_id": series_id,
        "opponent_id": key.opponent_id,
        "rule_id": dimension["rule_id"],
        "situation_key": dimension["situation_key"],
        "horizon": key.horizon,
        "repetition_id": key.repetition_id,
        "semantic_id": dimension["semantic_id"],
        "action_family_id": dimension["action_family_id"],
        "opportunity_event_id": dimension["opportunity_event_id"],
        "action_group": dimension["action_group"],
        "true_rate": _decimal_wire(truth[0]),
        "reach_weight": _decimal_wire(truth[1]),
        "strategy_artifact_sha256": strategy_sha256,
        "ground_truth_extractor_version": GROUND_TRUTH_EXTRACTOR_VERSION,
    }


def _exact_ev_observation(
    series_id: str, source: TrainingExactEvInput, key: TrainingSessionKey
) -> ExactEvObservation:
    if source.cell.profiles.opponent_id != key.opponent_id:
        raise ValueError("exact-EV cell opponent identity does not join its session")
    fields = {
        "series_id": series_id,
        "opponent_id": key.opponent_id,
        "horizon": key.horizon,
        "repetition_id": key.repetition_id,
        "cell": source.cell,
    }
    return ExactEvObservation(**fields, sha256=exact_ev_observation_sha256(**fields))


def _strategy_sha256(strategy: Mapping[str, Mapping[str, float]]) -> str:
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
    return sha256_bytes(canonical_json_bytes(payload))


def _contract_refs(bundle: ValidatedPhase6ContractBundle) -> dict[str, object]:
    return {
        "preregistration": bundle.root_manifest["preregistration"],
        "coverage_semantics_contract": bundle.root_manifest["coverage_semantics_contract"],
        "selection_metric_contract": bundle.root_manifest["selection_metric_contract"],
        "series_reference": bundle.root_manifest["series_reference"],
    }


def _canonical_artifact(payload: dict[str, object]) -> CanonicalCalibrationArtifact:
    raw = canonical_json_bytes(payload)
    return CanonicalCalibrationArtifact(raw, sha256_bytes(raw))


def _record_key(record: Mapping[str, object]) -> tuple[object, ...]:
    return (
        record["series_id"],
        record["opponent_id"],
        record["rule_id"],
        record["situation_key"],
        record["horizon"],
        record["repetition_id"],
    )


def _decimal_wire(value: Decimal) -> str:
    if not value.is_finite():
        raise ValueError("production decimal values must be finite")
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        normalized = +value
    text = format(normalized, "f").rstrip("0").rstrip(".")
    result = text or "0"
    if result.startswith("-") or not math.isfinite(float(normalized)):
        raise ValueError("production probability values must be finite and non-negative")
    return result


__all__ = [
    "GROUND_TRUTH_EXTRACTOR_VERSION",
    "PRODUCTION_INPUT_BUILDER_VERSION",
    "PRODUCTION_OBSERVATION_REGISTRY_VERSION",
    "PRODUCTION_OUTCOME_REGISTRY_VERSION",
    "ProductionCalibrationInputs",
    "TrainingExactEvInput",
    "TrainingTerminalInput",
    "build_production_calibration_inputs",
    "build_production_observation_registry",
    "validate_production_observation_registry",
    "verify_production_calibration_inputs",
]
