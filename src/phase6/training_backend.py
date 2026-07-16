"""Concrete in-memory Training execution backend for approved P6-7 inputs.

The backend connects the frozen river game, public action-only session state,
approved digest sampling, solver-backed node locking, P6-5 exact EV, and the
production P6-6 input builder.  It neither writes artifacts nor opens any
Validation or Test catalog.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import fields, is_dataclass
from decimal import Decimal

from opponents import load_training_catalog
from opponents.ground_truth import extract_independent_action_rates
from opponents.synthesis import SynthesizedOpponent, synthesize_opponent
from poker_ai.exploit import nodelock_config_from_leaks
from poker_ai.leak import ActionBaselineTable, ActionLeakRule, LeakDetector, LeakDetectorConfig
from poker_ai.mixer import safety_mix
from poker_ai.observation import ActionStats, ObservationTracker
from poker_solver.best_response import best_response_strategy
from poker_solver.game import Chance, Decision
from poker_solver.nodelock import apply_node_locks, river_infoset_reach_weights
from poker_solver.strategy import StrategyProfile

from .calibration import CALIBRATION_EVALUATOR_VERSION, CalibrationEvaluation
from .contracts import ValidatedPhase6ContractBundle, canonical_json_bytes, sha256_bytes
from .exact_ev import ExactEvCell, PolicySlice, evaluate_exact_ev
from .p6_7 import (
    REPETITION_SEEDS,
    STREAM_NAMES,
    PrimaryCandidate,
    canonical_legal_actions,
    derive_draw_digest,
    derive_stream_root,
    primary_candidate_grid,
    sample_execution_action,
    sample_observation_node,
    sampling_contract_sha256,
    validate_sampling_contract,
    weighted_categorical,
)
from .production_inputs import (
    PRODUCTION_INPUT_BUILDER_VERSION,
    R008_REASON_ID,
    R008_SITUATION_KEY,
    ProductionCalibrationInputs,
    TrainingExactEvInput,
    TrainingTerminalInput,
    build_production_calibration_inputs,
    build_production_observation_registry,
    verify_production_calibration_inputs,
)
from .training_runner import (
    HORIZONS,
    TrainingCandidateRequest,
    TrainingCandidateResult,
    TrainingSessionKey,
    TrainingSessionRequest,
    TrainingSessionResult,
)

PRODUCTION_TRAINING_BACKEND_ID = "phase6-river-training"
PRODUCTION_TRAINING_BACKEND_VERSION = "p6-7-concrete-training-backend-v1"
TERMINAL_RESULT_SCHEMA_VERSION = "phase6-training-terminal-result-v1"
HERO_POLICY_RESULT_SCHEMA_VERSION = "phase6-training-hero-policy-result-v1"
EXACT_EV_RESULT_SCHEMA_VERSION = "phase6-training-exact-ev-result-v1"
CALIBRATION_RESULT_SCHEMA_VERSION = "phase6-training-calibration-result-v1"
AGGREGATE_RESULT_SCHEMA_VERSION = "phase6-training-aggregate-result-v1"

_R008_ACTIONS = ("BET", "BET_ALL_IN", "BET_33", "BET_75", "RAISE_ALL_IN")
_SHA256_CHARS = frozenset("0123456789abcdef")


class ProductionTrainingExecutionBackend:
    """Production implementation of the Training-only execution Protocol."""

    backend_id = PRODUCTION_TRAINING_BACKEND_ID
    backend_version = PRODUCTION_TRAINING_BACKEND_VERSION

    def __init__(
        self,
        *,
        contract_bundle: ValidatedPhase6ContractBundle,
        sampling_contract: Mapping[str, object],
    ) -> None:
        validate_sampling_contract(sampling_contract)
        self._contract_bundle = contract_bundle
        self._sampling_contract = dict(sampling_contract)
        self._sampling_sha256 = sampling_contract_sha256(self._sampling_contract)
        self._candidates = {
            item.candidate_id: item
            for item in primary_candidate_grid(sampling_contract_sha256=self._sampling_sha256)
        }
        configs = tuple(sorted(load_training_catalog(), key=lambda item: item.opponent_id))
        self._opponents = tuple(synthesize_opponent(config=config) for config in configs)
        self._opponents_by_id = {item.config.opponent_id: item for item in self._opponents}
        if len(self._opponents_by_id) != 9:
            raise ValueError("concrete Training backend requires nine unique opponents")
        first = self._opponents[0]
        self._registry = build_production_observation_registry(first.game)
        if (
            self._sampling_contract["observation_registry_version"]
            != self._registry.registry_version
            or self._sampling_contract["observation_registry_sha256"] != self._registry.sha256
        ):
            raise ValueError("sampling contract does not join the frozen river registry")
        for opponent in self._opponents[1:]:
            if build_production_observation_registry(opponent.game) != self._registry:
                raise ValueError("Training opponents do not share one frozen river registry")

        baseline = extract_independent_action_rates(
            first.game,
            first.equilibrium_strategy,
            first.config,
            reason_ids=(R008_REASON_ID,),
        )[0]
        self._baseline_rate = float(baseline.action_rate)
        self._baseline_table = ActionBaselineTable(
            table_version="phase6-frozen-r008-baseline-v1",
            rules=(
                ActionLeakRule(
                    reason_id=R008_REASON_ID,
                    leak_type="bet_too_often_when_checked_to",
                    action_group=_R008_ACTIONS,
                    baseline_rate=self._baseline_rate,
                    direction="decrease_bet_frequency_when_checked_to",
                    situation_overrides={R008_SITUATION_KEY: self._baseline_rate},
                ),
            ),
        )
        self._session_result_hashes: dict[TrainingSessionKey, tuple[str, str, str]] = {}
        self._hero_policy_cache: dict[
            tuple[str, str, int, int],
            tuple[StrategyProfile, StrategyProfile, StrategyProfile, list[dict[str, object]]],
        ] = {}

    def run_sessions(
        self, requests: Sequence[TrainingSessionRequest]
    ) -> Sequence[TrainingSessionResult]:
        """Run canonical approved sessions entirely in memory."""
        checked = self._validate_session_requests(requests)
        results = []
        for request in checked:
            result, _cell = self._run_session(request)
            hashes = _session_result_hashes(result)
            previous = self._session_result_hashes.get(request.key)
            if previous is not None and previous != hashes:
                raise ValueError("repeated session execution is not deterministic")
            self._session_result_hashes[request.key] = hashes
            results.append(result)
        return tuple(results)

    def evaluate_candidates(
        self, requests: Sequence[TrainingCandidateRequest]
    ) -> Sequence[TrainingCandidateResult]:
        """Build production inputs and apply the existing P6-6 evaluator."""
        checked = self._validate_candidate_requests(requests)
        results: list[TrainingCandidateResult] = []
        for request in checked:
            terminal_inputs: list[TrainingTerminalInput] = []
            exact_inputs: list[TrainingExactEvInput] = []
            for supplied in request.session_results:
                session_request = self._request_for_key(request.candidate, supplied.key)
                expected_hashes = self._session_result_hashes.get(supplied.key)
                if expected_hashes is None:
                    raise ValueError(
                        "candidate session result was not produced by this backend execution"
                    )
                if _session_result_hashes(supplied) != expected_hashes:
                    raise ValueError(
                        "candidate session result does not reconstruct from approved execution"
                    )
                terminal_payload, exact_cell = self._reconstruct_terminal_products(
                    session_request,
                    supplied,
                )
                terminal_inputs.append(
                    TrainingTerminalInput(
                        supplied.key,
                        terminal_payload["action_counts"],
                    )
                )
                exact_inputs.append(TrainingExactEvInput(supplied.key, exact_cell))

            inputs = build_production_calibration_inputs(
                contract_bundle=self._contract_bundle,
                candidate=request.candidate,
                sampling_contract=self._sampling_contract,
                observation_registry=self._registry,
                opponents=self._opponents,
                terminal_inputs=terminal_inputs,
                exact_ev_inputs=exact_inputs,
            )
            evaluation = verify_production_calibration_inputs(
                self._contract_bundle,
                inputs,
            )
            calibration, aggregate = _candidate_result_payloads(
                request,
                inputs,
                evaluation,
            )
            results.append(
                TrainingCandidateResult(
                    split="training",
                    candidate_id=request.candidate.candidate_id,
                    session_join_sha256=request.session_join_sha256,
                    calibration_cell=calibration,
                    aggregate_metrics=aggregate,
                )
            )
        return tuple(results)

    def _reconstruct_terminal_products(
        self,
        request: TrainingSessionRequest,
        supplied: TrainingSessionResult,
    ) -> tuple[dict[str, object], ExactEvCell]:
        if supplied.split != "training" or supplied.stream_roots != request.stream_roots:
            raise ValueError("candidate session result provenance is not Training canonical")
        terminal = supplied.terminal_candidate_snapshot
        if not isinstance(terminal, dict) or set(terminal) != {
            "schema_version",
            "backend_version",
            "session",
            "observation_registry_sha256",
            "action_counts",
            "opportunity_count",
            "transcript_sha256",
        }:
            raise ValueError("terminal result fields are not closed-world")
        counts = terminal["action_counts"]
        if (
            terminal["schema_version"] != TERMINAL_RESULT_SCHEMA_VERSION
            or terminal["backend_version"] != self.backend_version
            or terminal["session"] != request.key.canonical_payload()
            or terminal["observation_registry_sha256"] != self._registry.sha256
            or not isinstance(counts, dict)
            or set(counts) != {"BET", "CHECK"}
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in counts.values()
            )
            or terminal["opportunity_count"] != request.key.horizon
            or sum(counts.values()) != request.key.horizon
        ):
            raise ValueError("terminal result does not reconstruct from approved provenance")
        _validate_sha256(terminal["transcript_sha256"], "session transcript hash")

        opponent = self._opponents_by_id[request.key.opponent_id]
        stats = ActionStats(R008_SITUATION_KEY, request.key.horizon, counts)
        base, exploit, final, detected = self._hero_policies_from_stats(
            request.candidate,
            opponent,
            (stats,),
        )
        policy = supplied.hero_policy_snapshot
        if not isinstance(policy, dict) or set(policy) != {
            "schema_version",
            "backend_version",
            "session",
            "source_terminal_sha256",
            "base_hero_policy",
            "exploit_hero_policy",
            "final_hero_policy",
            "detected_leaks",
            "hero_response_action_counts",
            "exploration_fired_count",
        }:
            raise ValueError("Hero policy result fields are not closed-world")
        hero_counts = policy["hero_response_action_counts"]
        if (
            policy["schema_version"] != HERO_POLICY_RESULT_SCHEMA_VERSION
            or policy["backend_version"] != self.backend_version
            or policy["session"] != request.key.canonical_payload()
            or policy["source_terminal_sha256"] != sha256_bytes(canonical_json_bytes(terminal))
            or policy["base_hero_policy"] != _profile_payload(base)
            or policy["exploit_hero_policy"] != _profile_payload(exploit)
            or policy["final_hero_policy"] != _profile_payload(final)
            or policy["detected_leaks"] != detected
            or not isinstance(hero_counts, dict)
            or any(
                not isinstance(action, str)
                or not action
                or isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                for action, value in hero_counts.items()
            )
            or sum(hero_counts.values()) != counts["BET"]
            or isinstance(policy["exploration_fired_count"], bool)
            or not isinstance(policy["exploration_fired_count"], int)
            or not 0 <= policy["exploration_fired_count"] <= counts["BET"]
        ):
            raise ValueError("Hero policy result does not reconstruct from terminal counts")

        exact_cell = _evaluate_session_exact_ev(opponent, base, final)
        exact = supplied.exact_ev_cell
        expected_exact = {
            "schema_version": EXACT_EV_RESULT_SCHEMA_VERSION,
            "backend_version": self.backend_version,
            "session": request.key.canonical_payload(),
            "source_terminal_sha256": sha256_bytes(canonical_json_bytes(terminal)),
            "source_hero_policy_sha256": sha256_bytes(canonical_json_bytes(policy)),
            "cell": _exact_ev_payload(exact_cell),
        }
        if exact != expected_exact:
            raise ValueError("exact-EV result does not reconstruct from terminal Hero policy")
        return terminal, exact_cell

    def _validate_session_requests(
        self, requests: Sequence[TrainingSessionRequest]
    ) -> tuple[TrainingSessionRequest, ...]:
        values = tuple(requests)
        if not values:
            raise ValueError("concrete Training backend requires at least one session request")
        if any(not isinstance(item, TrainingSessionRequest) for item in values):
            raise TypeError("session requests must contain TrainingSessionRequest values")
        keys = [item.key for item in values]
        if keys != sorted(keys) or len(set(keys)) != len(keys):
            raise ValueError("session requests must be unique and in canonical order")
        for request in values:
            self._validate_session_request(request)
        return values

    def _validate_session_request(self, request: TrainingSessionRequest) -> None:
        candidate = self._candidates.get(request.key.candidate_id)
        if candidate is None or request.candidate != candidate:
            raise ValueError("session candidate is not an approved canonical primary candidate")
        opponent = self._opponents_by_id.get(request.key.opponent_id)
        if opponent is None or request.opponent != opponent.config:
            raise ValueError("session opponent is not an approved Training catalog member")
        if request.key.horizon not in HORIZONS or request.key.repetition_id not in dict(
            REPETITION_SEEDS
        ):
            raise ValueError("session key is outside the approved Training product")
        expected_roots = tuple(
            derive_stream_root(
                split="training",
                opponent_id=request.key.opponent_id,
                horizon=request.key.horizon,
                repetition_id=request.key.repetition_id,
                stream_name=stream_name,
            )
            for stream_name in STREAM_NAMES
        )
        if request.stream_roots != expected_roots:
            raise ValueError("session stream roots do not match the approved Training identity")

    def _validate_candidate_requests(
        self, requests: Sequence[TrainingCandidateRequest]
    ) -> tuple[TrainingCandidateRequest, ...]:
        values = tuple(requests)
        if not values:
            raise ValueError("concrete Training backend requires candidate requests")
        if any(not isinstance(item, TrainingCandidateRequest) for item in values):
            raise TypeError("candidate requests must contain TrainingCandidateRequest values")
        candidate_ids = [item.candidate.candidate_id for item in values]
        if candidate_ids != sorted(candidate_ids) or len(set(candidate_ids)) != len(candidate_ids):
            raise ValueError("candidate requests must be unique and in canonical order")
        for request in values:
            approved = self._candidates.get(request.candidate.candidate_id)
            if approved is None or request.candidate != approved:
                raise ValueError("candidate request is not an approved primary candidate")
            _validate_sha256(request.session_join_sha256, "candidate session join hash")
            if any(not isinstance(item, TrainingSessionResult) for item in request.session_results):
                raise TypeError(
                    "candidate session results must contain TrainingSessionResult values"
                )
            expected_keys = self._candidate_session_keys(request.candidate)
            actual = tuple(item.key for item in request.session_results)
            if actual != expected_keys or len(set(actual)) != len(actual):
                raise ValueError(
                    "candidate session results do not exactly match approved session order"
                )
            for item in request.session_results:
                if item.split != "training":
                    raise ValueError("candidate session result is not Training-only")
        return values

    def _candidate_session_keys(
        self, candidate: PrimaryCandidate
    ) -> tuple[TrainingSessionKey, ...]:
        return tuple(
            TrainingSessionKey(
                candidate.candidate_id,
                opponent.config.opponent_id,
                horizon,
                repetition_id,
            )
            for opponent in self._opponents
            for horizon in HORIZONS
            for repetition_id, _seed in REPETITION_SEEDS
        )

    def _request_for_key(
        self, candidate: PrimaryCandidate, key: TrainingSessionKey
    ) -> TrainingSessionRequest:
        request = TrainingSessionRequest(
            key=key,
            candidate=candidate,
            opponent=self._opponents_by_id[key.opponent_id].config,
            stream_roots=tuple(
                derive_stream_root(
                    split="training",
                    opponent_id=key.opponent_id,
                    horizon=key.horizon,
                    repetition_id=key.repetition_id,
                    stream_name=stream_name,
                )
                for stream_name in STREAM_NAMES
            ),
        )
        self._validate_session_request(request)
        return request

    def _run_session(
        self, request: TrainingSessionRequest
    ) -> tuple[TrainingSessionResult, ExactEvCell]:
        self._validate_session_request(request)
        opponent = self._opponents_by_id[request.key.opponent_id]
        game = opponent.game
        if not isinstance(game.root, Chance) or len(self._registry.nodes) != 1:
            raise ValueError("frozen Training river game must have one root chance node")
        roots = {root.payload["stream_name"]: root for root in request.stream_roots}
        tracker = ObservationTracker()
        hero_counts: Counter[str] = Counter()
        exploration_fired = 0
        transcript = hashlib.sha256()
        for decision_index in range(request.key.horizon):
            deal = sample_observation_node(
                self._registry,
                node_id=self._registry.nodes[0].node_id,
                stream_root=roots["observation"],
                decision_index=decision_index,
                variate_index=0,
            )
            start = _chance_child(game.root, deal.selected_outcome_id)
            if (
                not isinstance(start, Decision)
                or start.player != 0
                or not start.infoset.endswith(":start")
            ):
                raise ValueError("frozen river deal does not lead to the OOP start decision")
            try:
                opponent_node = start.child_of("CHECK")
            except KeyError as exc:
                raise ValueError("frozen river start decision lacks CHECK") from exc
            if (
                not isinstance(opponent_node, Decision)
                or opponent_node.player != 1
                or not opponent_node.infoset.endswith(":vs_check")
            ):
                raise ValueError("checked-to river path lacks the IP observation decision")

            opponent_digest = derive_draw_digest(
                roots["observation"],
                decision_index=decision_index,
                variate_index=1,
            )
            ordered_actions = canonical_legal_actions(opponent_node.actions)
            distribution = opponent.strategy[opponent_node.infoset]
            if set(distribution) != set(ordered_actions):
                raise ValueError("opponent policy does not cover the frozen legal action set")
            opponent_action = weighted_categorical(
                ordered_actions,
                [distribution[action] for action in ordered_actions],
                opponent_digest,
            )
            tracker.record_opponent_action(
                situation_key=R008_SITUATION_KEY,
                action=opponent_action,
            )
            event: dict[str, object] = {
                "decision_index": decision_index,
                "deal_draw_digest": deal.draw_digest,
                "deal_outcome_id": deal.selected_outcome_id,
                "opponent_action_draw_digest": opponent_digest,
                "opponent_action": opponent_action,
                "hero_action": None,
            }
            if opponent_action == "BET":
                response = opponent_node.child_of("BET")
                if not isinstance(response, Decision) or response.player != 0:
                    raise ValueError("opponent BET does not lead to a Hero response")
                stats = tracker.stats_for(R008_SITUATION_KEY)
                assert stats is not None
                policies = self._terminal_hero_policies(request.candidate, opponent, tracker)
                final_policy = policies[2][response.infoset]
                action = sample_execution_action(
                    final_policy=final_policy,
                    legal_actions=response.actions,
                    epsilon=request.candidate.epsilon,
                    decision_index=decision_index,
                    hero_stream_root=roots["hero_action"],
                    epsilon_branch_stream_root=roots["epsilon_branch"],
                    epsilon_action_stream_root=roots["epsilon_action"],
                )
                hero_counts[action.final_action] += 1
                exploration_fired += int(action.branch_fired)
                event["hero_action"] = _json_ready(action)
            elif opponent_action != "CHECK":
                raise ValueError("checked-to opponent action is outside CHECK/BET")
            transcript.update(canonical_json_bytes(event))

        base, exploit, final, detected = self._terminal_hero_policies(
            request.candidate,
            opponent,
            tracker,
        )
        stats = tracker.stats_for(R008_SITUATION_KEY)
        assert stats is not None
        action_counts = {
            "BET": stats.count("BET"),
            "CHECK": stats.count("CHECK"),
        }
        terminal = {
            "schema_version": TERMINAL_RESULT_SCHEMA_VERSION,
            "backend_version": self.backend_version,
            "session": request.key.canonical_payload(),
            "observation_registry_sha256": self._registry.sha256,
            "action_counts": action_counts,
            "opportunity_count": stats.opportunities,
            "transcript_sha256": transcript.hexdigest(),
        }
        policy = {
            "schema_version": HERO_POLICY_RESULT_SCHEMA_VERSION,
            "backend_version": self.backend_version,
            "session": request.key.canonical_payload(),
            "source_terminal_sha256": sha256_bytes(canonical_json_bytes(terminal)),
            "base_hero_policy": _profile_payload(base),
            "exploit_hero_policy": _profile_payload(exploit),
            "final_hero_policy": _profile_payload(final),
            "detected_leaks": detected,
            "hero_response_action_counts": dict(sorted(hero_counts.items())),
            "exploration_fired_count": exploration_fired,
        }
        exact_cell = _evaluate_session_exact_ev(opponent, base, final)
        exact = {
            "schema_version": EXACT_EV_RESULT_SCHEMA_VERSION,
            "backend_version": self.backend_version,
            "session": request.key.canonical_payload(),
            "source_terminal_sha256": sha256_bytes(canonical_json_bytes(terminal)),
            "source_hero_policy_sha256": sha256_bytes(canonical_json_bytes(policy)),
            "cell": _exact_ev_payload(exact_cell),
        }
        return (
            TrainingSessionResult(
                split="training",
                key=request.key,
                stream_roots=request.stream_roots,
                terminal_candidate_snapshot=terminal,
                hero_policy_snapshot=policy,
                exact_ev_cell=exact,
            ),
            exact_cell,
        )

    def _terminal_hero_policies(
        self,
        candidate: PrimaryCandidate,
        opponent: SynthesizedOpponent,
        tracker: ObservationTracker,
    ) -> tuple[StrategyProfile, StrategyProfile, StrategyProfile, list[dict[str, object]]]:
        stats = tracker.snapshot()
        item = tracker.stats_for(R008_SITUATION_KEY)
        if item is None:
            cache_key = (
                candidate.candidate_id,
                opponent.equilibrium_artifact_sha256,
                0,
                0,
            )
        else:
            cache_key = (
                candidate.candidate_id,
                opponent.equilibrium_artifact_sha256,
                item.count("CHECK"),
                item.count("BET"),
            )
        cached = self._hero_policy_cache.get(cache_key)
        if cached is not None:
            return cached
        result = self._hero_policies_from_stats(
            candidate,
            opponent,
            stats,
        )
        self._hero_policy_cache[cache_key] = result
        return result

    def _hero_policies_from_stats(
        self,
        candidate: PrimaryCandidate,
        opponent: SynthesizedOpponent,
        stats: Sequence[ActionStats],
    ) -> tuple[StrategyProfile, StrategyProfile, StrategyProfile, list[dict[str, object]]]:
        game = opponent.game
        hero_infosets = game.infosets_of(0)
        base = {infoset: dict(opponent.equilibrium_strategy[infoset]) for infoset in hero_infosets}
        config = LeakDetectorConfig(
            min_effective_sample_size=candidate.sample_floor,
            min_deviation=0.25,
            min_confidence=float(candidate.detector_confidence),
            rule_exploit_min_confidence=float(candidate.provider_confidence),
            nodelock_exploit_min_confidence=float(candidate.provider_confidence),
        )
        leaks = LeakDetector(self._baseline_table, config).detect_for_situation(
            stats,
            R008_SITUATION_KEY,
        )
        node_lock = nodelock_config_from_leaks(
            leaks,
            hero_position="OOP",
            min_confidence=float(candidate.provider_confidence),
        )
        exploit = {infoset: dict(policy) for infoset, policy in base.items()}
        if node_lock is not None:
            application = apply_node_locks(
                game,
                opponent.equilibrium_strategy,
                node_lock,
                reach_weights=river_infoset_reach_weights(
                    game,
                    opponent.equilibrium_strategy,
                ),
            )
            best_actions = best_response_strategy(game, 0, application.profile)
            for infoset in hero_infosets:
                if infoset.endswith(":vs_bet"):
                    exploit[infoset] = {
                        action: float(action == best_actions[infoset])
                        for action in game.actions_of(infoset)
                    }
        final = {
            infoset: safety_mix(
                base[infoset],
                exploit[infoset],
                float(candidate.safety_alpha),
            )
            for infoset in hero_infosets
        }
        return base, exploit, final, [_detected_leak_payload(item) for item in leaks]


def _chance_child(root: Chance, selected_label: str) -> Decision:
    matches = [child for _probability, child, label in root.branches if label == selected_label]
    if len(matches) != 1 or not isinstance(matches[0], Decision):
        raise ValueError("sampled river chance outcome does not resolve uniquely")
    return matches[0]


def _session_result_hashes(result: TrainingSessionResult) -> tuple[str, str, str]:
    try:
        return tuple(
            sha256_bytes(canonical_json_bytes(payload))
            for payload in (
                result.terminal_candidate_snapshot,
                result.hero_policy_snapshot,
                result.exact_ev_cell,
            )
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("session result payloads are not canonical-JSON compatible") from exc


def _evaluate_session_exact_ev(
    opponent: SynthesizedOpponent,
    base_hero_policy: StrategyProfile,
    final_hero_policy: StrategyProfile,
) -> ExactEvCell:
    game = opponent.game
    opponent_policy = {infoset: opponent.strategy[infoset] for infoset in game.infosets_of(1)}
    return evaluate_exact_ev(
        game,
        hero_player=0,
        opponent_policy=PolicySlice(
            game.name,
            opponent.config.opponent_id,
            opponent_policy,
        ),
        base_hero_policy=PolicySlice(
            game.name,
            opponent.config.opponent_id,
            base_hero_policy,
        ),
        final_hero_policy=PolicySlice(
            game.name,
            opponent.config.opponent_id,
            final_hero_policy,
        ),
    )


def _profile_payload(profile: Mapping[str, Mapping[str, float]]) -> dict[str, object]:
    return {
        infoset: {
            action: probability.hex() for action, probability in sorted(profile[infoset].items())
        }
        for infoset in sorted(profile)
    }


def _exact_ev_payload(cell: ExactEvCell) -> dict[str, object]:
    return {
        "game_id": cell.profiles.game_id,
        "opponent_id": cell.profiles.opponent_id,
        "hero_player": cell.profiles.hero_player,
        "profiles": {
            "base": _profile_payload(cell.profiles.base),
            "final": _profile_payload(cell.profiles.final),
            "oracle_br": _profile_payload(cell.profiles.oracle_br),
        },
        "base_ev": _ev_paths_payload(cell.base_ev.production, cell.base_ev.independent_leaves),
        "final_ev": _ev_paths_payload(
            cell.final_ev.production,
            cell.final_ev.independent_leaves,
        ),
        "oracle_br_ev": _ev_paths_payload(
            cell.oracle_br_ev.production,
            cell.oracle_br_ev.independent_leaves,
        ),
        "gain_binary64_hex": cell.gain.hex(),
        "opportunity_binary64_hex": cell.opportunity.hex(),
        "efficiency_binary64_hex": (None if cell.efficiency is None else cell.efficiency.hex()),
        "efficiency_status": cell.efficiency_status,
    }


def _ev_paths_payload(production: float, independent: float) -> dict[str, str]:
    return {
        "production_binary64_hex": production.hex(),
        "independent_leaves_binary64_hex": independent.hex(),
    }


def _detected_leak_payload(leak: object) -> dict[str, object]:
    return {
        "reason_id": leak.reason_id,
        "leak_type": leak.leak_type,
        "situation_key": leak.situation_key,
        "observed_rate_binary64_hex": leak.observed_rate.hex(),
        "baseline_rate_binary64_hex": leak.baseline_rate.hex(),
        "effective_sample_size": leak.effective_sample_size,
        "confidence_binary64_hex": leak.confidence.hex(),
        "direction": leak.direction,
    }


def _candidate_result_payloads(
    request: TrainingCandidateRequest,
    inputs: ProductionCalibrationInputs,
    evaluation: CalibrationEvaluation,
) -> tuple[dict[str, object], dict[str, object]]:
    if evaluation.evaluator_version != CALIBRATION_EVALUATOR_VERSION:
        raise ValueError("production evaluator returned an unsupported version")
    if len(evaluation.series) != 1:
        raise ValueError("one primary candidate must produce exactly one calibration series")
    series = evaluation.series[0]
    if series.series_id != inputs.series_descriptor["series_id"]:
        raise ValueError("production evaluation series does not join its descriptor")
    common = {
        "backend_version": PRODUCTION_TRAINING_BACKEND_VERSION,
        "candidate_id": request.candidate.candidate_id,
        "source_session_join_sha256": request.session_join_sha256,
        "production_input_builder_version": PRODUCTION_INPUT_BUILDER_VERSION,
        "evaluator_version": evaluation.evaluator_version,
        "series_id": series.series_id,
    }
    calibration = {
        "schema_version": CALIBRATION_RESULT_SCHEMA_VERSION,
        **common,
        "cells": _json_ready(series.cells),
    }
    aggregate = {
        "schema_version": AGGREGATE_RESULT_SCHEMA_VERSION,
        **common,
        "terminal_snapshot_sha256": series.terminal_snapshot_sha256,
        "ground_truth_sha256": series.ground_truth_sha256,
        "exact_ev_sha256s": list(series.exact_ev_sha256s),
        "atomic_groups": _json_ready(series.atomic_groups),
        "macro": _json_ready(series.macro),
        "micro": _json_ready(series.micro),
        "gto_fpr": _json_ready(series.gto_fpr),
    }
    return calibration, aggregate


def _json_ready(value: object) -> object:
    if isinstance(value, Decimal):
        return _decimal_wire(value)
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _json_ready(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_json_ready(item) for item in value]
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    raise TypeError(f"unsupported canonical result value {type(value).__name__}")


def _decimal_wire(value: Decimal) -> str:
    if not value.is_finite():
        raise ValueError("calibration result decimals must be finite")
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    if text in ("", "-0"):
        return "0"
    return text


def _validate_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _SHA256_CHARS for character in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


__all__ = [
    "AGGREGATE_RESULT_SCHEMA_VERSION",
    "CALIBRATION_RESULT_SCHEMA_VERSION",
    "EXACT_EV_RESULT_SCHEMA_VERSION",
    "HERO_POLICY_RESULT_SCHEMA_VERSION",
    "PRODUCTION_TRAINING_BACKEND_ID",
    "PRODUCTION_TRAINING_BACKEND_VERSION",
    "ProductionTrainingExecutionBackend",
    "TERMINAL_RESULT_SCHEMA_VERSION",
]
