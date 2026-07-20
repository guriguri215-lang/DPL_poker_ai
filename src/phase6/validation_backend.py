"""Concrete in-memory backend for the approved P6-9B Validation run.

The backend implements the P6-9A Validation-only Protocol without writing any
artifacts. It reconstructs the frozen Validation catalog and sampling product,
executes deterministic public-action sessions, and delegates only the approved
P6-5/P6-6 evaluator boundary to the existing P6-9A implementation.
"""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import fields, is_dataclass
from decimal import Decimal
from pathlib import Path

from opponents import load_validation_catalog
from opponents.synthesis import SynthesizedOpponent, synthesize_opponent
from poker_ai.exploit import (
    RuleExploitConfig,
    RuleExploitProvider,
    nodelock_config_from_leaks,
)
from poker_ai.leak import (
    ActionBaselineTable,
    ActionLeakRule,
    LeakDetector,
    LeakDetectorConfig,
)
from poker_ai.mixer import safety_mix
from poker_ai.observation import ActionStats
from poker_core.dpl_schema import DetectedLeak
from poker_solver.best_response import best_response_strategy
from poker_solver.game import Chance, Decision, Game, Node, Terminal
from poker_solver.nodelock import apply_node_locks, river_infoset_reach_weights
from poker_solver.strategy import StrategyProfile

from .calibration import CALIBRATION_EVALUATOR_VERSION, EXACT_EV_INPUT_VERSION
from .contracts import canonical_json_bytes, sha256_bytes
from .exact_ev import PolicySlice, evaluate_exact_ev
from .p6_7 import (
    REPETITION_SEEDS,
    STREAM_NAMES,
    PrimaryCandidate,
    canonical_legal_actions,
    derive_draw_digest,
    derive_stream_root,
    sample_execution_action,
    sample_observation_node,
    validate_sampling_contract,
    weighted_categorical,
)
from .production_inputs import build_production_observation_registry
from .training_runner import HORIZONS
from .validation_execution import (
    VALIDATION_EXACT_EV_RESULT_SCHEMA_VERSION,
    VALIDATION_HERO_POLICY_RESULT_SCHEMA_VERSION,
    VALIDATION_TERMINAL_RESULT_SCHEMA_VERSION,
    ValidationCandidateRequest,
    ValidationCandidateResult,
    ValidationSessionRequest,
    ValidationSessionResult,
    _candidate_products,
    _evaluation_context,
    _exact_ev_payload,
    _profile_payload,
)
from .validation_runner import (
    ValidationBatchPlan,
    ValidationSessionKey,
    verify_validation_batch_plan,
)

PRODUCTION_VALIDATION_BACKEND_ID = "phase6-validation-river-production"
PRODUCTION_VALIDATION_BACKEND_VERSION = "p6-9b-river-validation-backend-v1"
P6_10B_VALIDATION_BACKEND_ID = "phase6-validation-p6-10b-river"
P6_10B_VALIDATION_BACKEND_VERSION = "p6-10b-confidence-provider-validation-backend-v1"

_R008_REASON_ID = "LEAK_R008"
_R008_SITUATION_KEY = "river_vs_check"
_R008_LEAK_TYPE = "bet_too_often_when_checked_to"
_R008_DIRECTION = "decrease_bet_frequency_when_checked_to"
_TAU_WIRE = "0.25"


class ProductionValidationExecutionBackend:
    """Production implementation of the P6-9A Validation execution Protocol."""

    backend_id = PRODUCTION_VALIDATION_BACKEND_ID
    backend_version = PRODUCTION_VALIDATION_BACKEND_VERSION

    def __init__(
        self,
        plan: ValidationBatchPlan,
        *,
        repo_root: Path | str,
        additional_candidates: Sequence[PrimaryCandidate] = (),
    ) -> None:
        self._repo_root = Path(repo_root).resolve()
        verify_validation_batch_plan(plan, repo_root=self._repo_root)
        self._plan = plan
        self._context = _evaluation_context(plan, self._repo_root)
        self._candidates = {item.candidate_id: item for item in plan.candidates}
        additions = tuple(additional_candidates)
        if any(not isinstance(item, PrimaryCandidate) for item in additions):
            raise TypeError("additional Validation candidates must be PrimaryCandidate values")
        if len({item.candidate_id for item in additions}) != len(additions) or any(
            item.candidate_id in self._candidates for item in additions
        ):
            raise ValueError("additional Validation candidate IDs must be unique and new")
        sampling_hash = plan.manifest["sampling_contract"]["sha256"]
        if any(item.sampling_contract_sha256 != sampling_hash for item in additions):
            raise ValueError("additional Validation candidates must retain the sampling contract")
        self._additional_candidate_ids = frozenset(item.candidate_id for item in additions)
        self._candidates.update({item.candidate_id: item for item in additions})
        configs = tuple(sorted(load_validation_catalog(), key=lambda item: item.opponent_id))
        opponents = tuple(synthesize_opponent(config=config) for config in configs)
        self._opponents = {item.config.opponent_id: item for item in opponents}
        if len(self._opponents) != 9 or set(self._opponents) != set(self._context.opponents):
            raise ValueError("production Validation backend requires the verified nine opponents")
        for opponent_id, opponent in self._opponents.items():
            expected = self._context.opponents[opponent_id]
            if (
                opponent.config != expected.config
                or opponent.config_sha256 != expected.config_sha256
                or opponent.equilibrium_version != expected.equilibrium_version
                or opponent.equilibrium_artifact_sha256 != expected.equilibrium_artifact_sha256
                or opponent.equilibrium_strategy != expected.equilibrium_strategy
                or opponent.node_lock_config != expected.node_lock_config
                or opponent.strategy != expected.strategy
                or opponent.leak_targets != expected.leak_targets
                or opponent.application != expected.application
            ):
                raise ValueError("production Validation opponent provenance does not reconstruct")
        first = opponents[0]
        self._registry = build_production_observation_registry(first.game)
        for opponent in opponents[1:]:
            if build_production_observation_registry(opponent.game) != self._registry:
                raise ValueError("Validation opponents do not share one frozen river registry")
        sampling = plan.manifest.get("sampling_contract")
        if not isinstance(sampling, dict) or set(sampling) != {"payload", "sha256"}:
            raise ValueError("verified Validation plan lacks a closed-world sampling contract")
        sampling_payload = sampling["payload"]
        sampling_sha256 = sampling["sha256"]
        if not isinstance(sampling_payload, dict) or not isinstance(sampling_sha256, str):
            raise ValueError("verified Validation sampling contract is invalid")
        validate_sampling_contract(sampling_payload, expected_sha256=sampling_sha256)
        if (
            sampling_payload["observation_registry_version"] != self._registry.registry_version
            or sampling_payload["observation_registry_sha256"] != self._registry.sha256
        ):
            raise ValueError(
                "production Validation observation registry differs from the verified "
                "sampling contract"
            )
        self._session_hashes: dict[ValidationSessionKey, tuple[str, str, str]] = {}
        self._action_draw_audits: dict[ValidationSessionKey, tuple[dict[str, object], ...]] = {}
        self._execution_events: dict[ValidationSessionKey, tuple[dict[str, object], ...]] = {}
        self._policy_cache: dict[
            tuple[str, str, int, int], tuple[StrategyProfile, StrategyProfile]
        ] = {}

    def run_sessions(
        self, requests: Sequence[ValidationSessionRequest]
    ) -> Sequence[ValidationSessionResult]:
        checked = self._validate_session_requests(requests)
        results: list[ValidationSessionResult] = []
        for request in checked:
            result = self._run_session(request)
            hashes = _session_hashes(result)
            previous = self._session_hashes.get(request.key)
            if previous is not None and previous != hashes:
                raise ValueError("repeated Validation session execution is not deterministic")
            self._session_hashes[request.key] = hashes
            results.append(result)
        return tuple(results)

    def evaluate_candidates(
        self, requests: Sequence[ValidationCandidateRequest]
    ) -> Sequence[ValidationCandidateResult]:
        checked = self._validate_candidate_requests(requests)
        results: list[ValidationCandidateResult] = []
        for request in checked:
            calibration, aggregate, _series = _candidate_products(
                self._plan,
                request,
                self._context,
            )
            results.append(
                ValidationCandidateResult(
                    split="validation",
                    candidate_id=request.candidate.candidate_id,
                    session_join_sha256=request.session_join_sha256,
                    calibration_cell=calibration,
                    aggregate_metrics=aggregate,
                )
            )
        return tuple(results)

    def action_draw_audits(self, key: ValidationSessionKey) -> tuple[dict[str, object], ...]:
        """Return captured action-draw evidence for an additive candidate session."""
        if key.candidate_id not in self._additional_candidate_ids:
            raise ValueError("action-draw audits are limited to additional candidates")
        try:
            return self._action_draw_audits[key]
        except KeyError as exc:
            raise ValueError("additional candidate session has not been executed") from exc

    def execution_events(self, key: ValidationSessionKey) -> tuple[dict[str, object], ...]:
        """Return the exact transcript events captured for an additive candidate."""
        if key.candidate_id not in self._additional_candidate_ids:
            raise ValueError("execution events are limited to additional candidates")
        try:
            return self._execution_events[key]
        except KeyError as exc:
            raise ValueError("additional candidate session has not been executed") from exc

    def _validate_session_requests(
        self, requests: Sequence[ValidationSessionRequest]
    ) -> tuple[ValidationSessionRequest, ...]:
        values = tuple(requests)
        if not values:
            raise ValueError("production Validation backend requires session requests")
        if any(not isinstance(item, ValidationSessionRequest) for item in values):
            raise TypeError("session requests must contain ValidationSessionRequest values")
        keys = [item.key for item in values]
        if keys != sorted(keys) or len(set(keys)) != len(keys):
            raise ValueError("Validation session requests must be unique and canonical")
        for request in values:
            self._validate_session_request(request)
        return values

    def _validate_session_request(self, request: ValidationSessionRequest) -> None:
        candidate = self._candidates.get(request.key.candidate_id)
        if candidate is None or request.candidate != candidate:
            raise ValueError("Validation session candidate is not canonical")
        opponent = self._opponents.get(request.key.opponent_id)
        if opponent is None or request.opponent != opponent.config:
            raise ValueError("Validation session opponent is not in the frozen catalog")
        if request.key.horizon not in HORIZONS or request.key.repetition_id not in dict(
            REPETITION_SEEDS
        ):
            raise ValueError("Validation session key is outside the approved product")
        expected_roots = tuple(
            derive_stream_root(
                split="validation",
                opponent_id=request.key.opponent_id,
                horizon=request.key.horizon,
                repetition_id=request.key.repetition_id,
                stream_name=stream_name,
            )
            for stream_name in STREAM_NAMES
        )
        if request.stream_roots != expected_roots:
            raise ValueError("Validation stream roots do not reconstruct")

    def _validate_candidate_requests(
        self, requests: Sequence[ValidationCandidateRequest]
    ) -> tuple[ValidationCandidateRequest, ...]:
        values = tuple(requests)
        if not values:
            raise ValueError("production Validation backend requires candidate requests")
        if any(not isinstance(item, ValidationCandidateRequest) for item in values):
            raise TypeError("candidate requests must contain ValidationCandidateRequest values")
        candidate_ids = [item.candidate.candidate_id for item in values]
        if candidate_ids != sorted(candidate_ids) or len(set(candidate_ids)) != len(candidate_ids):
            raise ValueError("Validation candidate requests must be unique and canonical")
        for request in values:
            approved = self._candidates.get(request.candidate.candidate_id)
            if approved is None or request.candidate != approved:
                raise ValueError("Validation candidate request is not canonical")
            if request.candidate.candidate_id in self._additional_candidate_ids:
                coordinates = sorted(
                    {
                        (key.opponent_id, key.horizon, key.repetition_id)
                        for key in self._plan.sessions
                    }
                )
                expected_keys = tuple(
                    ValidationSessionKey(
                        request.candidate.candidate_id,
                        opponent_id,
                        horizon,
                        repetition_id,
                    )
                    for opponent_id, horizon, repetition_id in coordinates
                )
            else:
                expected_keys = tuple(
                    key
                    for key in self._plan.sessions
                    if key.candidate_id == request.candidate.candidate_id
                )
            actual_keys = tuple(item.key for item in request.session_results)
            if actual_keys != expected_keys or len(set(actual_keys)) != len(actual_keys):
                raise ValueError("Validation candidate sessions do not match the approved plan")
            for supplied in request.session_results:
                if supplied.split != "validation":
                    raise ValueError("candidate session result is not Validation-only")
                expected_hashes = self._session_hashes.get(supplied.key)
                if expected_hashes is None or _session_hashes(supplied) != expected_hashes:
                    raise ValueError("candidate session result was not produced by this execution")
        return values

    def _run_session(self, request: ValidationSessionRequest) -> ValidationSessionResult:
        opponent = self._opponents[request.key.opponent_id]
        game = opponent.game
        if not isinstance(game.root, Chance) or len(self._registry.nodes) != 1:
            raise ValueError("frozen Validation river game must have one root chance node")
        roots = {root.payload["stream_name"]: root for root in request.stream_roots}
        counts: Counter[str] = Counter()
        transcript = hashlib.sha256()
        action_draw_audits: list[dict[str, object]] = []
        execution_events: list[dict[str, object]] = []
        for decision_index in range(request.key.horizon):
            deal = sample_observation_node(
                self._registry,
                node_id=self._registry.nodes[0].node_id,
                stream_root=roots["observation"],
                decision_index=decision_index,
                variate_index=0,
            )
            start = _chance_child(game.root, deal.selected_outcome_id)
            try:
                opponent_node = start.child_of("CHECK")
            except KeyError as exc:
                raise ValueError("frozen Validation river start lacks CHECK") from exc
            if (
                not isinstance(opponent_node, Decision)
                or opponent_node.player != 1
                or not opponent_node.infoset.endswith(":vs_check")
            ):
                raise ValueError("Validation checked-to path lacks the opponent decision")
            opponent_digest = derive_draw_digest(
                roots["observation"],
                decision_index=decision_index,
                variate_index=1,
            )
            ordered_actions = canonical_legal_actions(opponent_node.actions)
            distribution = opponent.strategy[opponent_node.infoset]
            if set(distribution) != set(ordered_actions):
                raise ValueError("Validation opponent policy does not cover legal actions")
            opponent_action = weighted_categorical(
                ordered_actions,
                [distribution[action] for action in ordered_actions],
                opponent_digest,
            )
            if opponent_action not in {"BET", "CHECK"}:
                raise ValueError("Validation opponent action is outside CHECK/BET")
            counts[opponent_action] += 1
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
                    raise ValueError("Validation opponent BET lacks a Hero response")
                _base, final = self._hero_policies(
                    request.candidate,
                    opponent,
                    counts,
                    decision_index + 1,
                )
                action = sample_execution_action(
                    final_policy=final[response.infoset],
                    legal_actions=response.actions,
                    epsilon=request.candidate.epsilon,
                    decision_index=decision_index,
                    hero_stream_root=roots["hero_action"],
                    epsilon_branch_stream_root=roots["epsilon_branch"],
                    epsilon_action_stream_root=roots["epsilon_action"],
                )
                event["hero_action"] = _json_ready(action)
                if request.key.candidate_id in self._additional_candidate_ids:
                    action_draw_audits.append(
                        {
                            "decision_index": decision_index,
                            "legal_actions": list(canonical_legal_actions(response.actions)),
                            "audit": _json_ready(action),
                        }
                    )
            transcript.update(canonical_json_bytes(event))
            if request.key.candidate_id in self._additional_candidate_ids:
                execution_events.append(event)

        action_counts = {"BET": counts["BET"], "CHECK": counts["CHECK"]}
        terminal = {
            "schema_version": VALIDATION_TERMINAL_RESULT_SCHEMA_VERSION,
            "evaluator_version": CALIBRATION_EVALUATOR_VERSION,
            "session": request.key.canonical_payload(),
            "action_counts": action_counts,
            "opportunity_count": request.key.horizon,
            "transcript_sha256": transcript.hexdigest(),
        }
        base, final = self._hero_policies(
            request.candidate,
            opponent,
            counts,
            request.key.horizon,
        )
        policy = {
            "schema_version": VALIDATION_HERO_POLICY_RESULT_SCHEMA_VERSION,
            "exact_ev_evaluator_version": EXACT_EV_INPUT_VERSION,
            "session": request.key.canonical_payload(),
            "source_terminal_sha256": sha256_bytes(canonical_json_bytes(terminal)),
            "game_id": game.name,
            "opponent_id": request.key.opponent_id,
            "hero_player": 0,
            "base_hero_policy": _profile_payload(base),
            "final_hero_policy": _profile_payload(final),
        }
        opponent_policy = {infoset: opponent.strategy[infoset] for infoset in game.infosets_of(1)}
        cell = evaluate_exact_ev(
            game,
            hero_player=0,
            opponent_policy=PolicySlice(game.name, request.key.opponent_id, opponent_policy),
            base_hero_policy=PolicySlice(game.name, request.key.opponent_id, base),
            final_hero_policy=PolicySlice(game.name, request.key.opponent_id, final),
        )
        exact = {
            "schema_version": VALIDATION_EXACT_EV_RESULT_SCHEMA_VERSION,
            "exact_ev_evaluator_version": EXACT_EV_INPUT_VERSION,
            "session": request.key.canonical_payload(),
            "source_terminal_sha256": sha256_bytes(canonical_json_bytes(terminal)),
            "source_hero_policy_sha256": sha256_bytes(canonical_json_bytes(policy)),
            "cell": _exact_ev_payload(cell),
        }
        if request.key.candidate_id in self._additional_candidate_ids:
            self._action_draw_audits[request.key] = tuple(action_draw_audits)
            self._execution_events[request.key] = tuple(execution_events)
        return ValidationSessionResult(
            "validation",
            request.key,
            request.stream_roots,
            terminal,
            policy,
            exact,
        )

    def _hero_policies(
        self,
        candidate: PrimaryCandidate,
        opponent: SynthesizedOpponent,
        counts: Mapping[str, int],
        opportunities: int,
    ) -> tuple[StrategyProfile, StrategyProfile]:
        cache_key = (
            candidate.candidate_id,
            opponent.equilibrium_artifact_sha256,
            counts.get("CHECK", 0),
            counts.get("BET", 0),
        )
        cached = self._policy_cache.get(cache_key)
        if cached is not None:
            return cached
        dimension = self._context.dimension
        action_group = dimension["action_group"]
        baseline_wire = dimension["baseline_rate"]
        if not isinstance(action_group, list) or not isinstance(baseline_wire, str):
            raise ValueError("Validation R008 dimension is invalid")
        baseline_rate = float(Decimal(baseline_wire))
        baseline_table = ActionBaselineTable(
            table_version="phase6-frozen-r008-baseline-v1",
            rules=(
                ActionLeakRule(
                    reason_id=_R008_REASON_ID,
                    leak_type=_R008_LEAK_TYPE,
                    action_group=tuple(action_group),
                    baseline_rate=baseline_rate,
                    direction=_R008_DIRECTION,
                    situation_overrides={_R008_SITUATION_KEY: baseline_rate},
                ),
            ),
        )
        detector = LeakDetector(
            baseline_table,
            LeakDetectorConfig(
                min_effective_sample_size=candidate.sample_floor,
                min_deviation=float(Decimal(_TAU_WIRE)),
                min_confidence=float(Decimal(candidate.detector_confidence)),
                rule_exploit_min_confidence=float(Decimal(candidate.provider_confidence)),
                nodelock_exploit_min_confidence=float(Decimal(candidate.provider_confidence)),
            ),
        )
        stats = ActionStats(_R008_SITUATION_KEY, opportunities, counts)
        leaks = detector.detect_for_situation((stats,), _R008_SITUATION_KEY)
        node_lock = nodelock_config_from_leaks(
            leaks,
            hero_position="OOP",
            min_confidence=float(Decimal(candidate.provider_confidence)),
        )
        game = opponent.game
        hero_infosets = game.infosets_of(0)
        base = {infoset: dict(opponent.equilibrium_strategy[infoset]) for infoset in hero_infosets}
        exploit = {infoset: dict(distribution) for infoset, distribution in base.items()}
        if node_lock is not None:
            application = apply_node_locks(
                game,
                opponent.equilibrium_strategy,
                node_lock,
                reach_weights=river_infoset_reach_weights(game, opponent.equilibrium_strategy),
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
                float(Decimal(candidate.safety_alpha)),
            )
            for infoset in hero_infosets
        }
        result = (base, final)
        self._policy_cache[cache_key] = result
        return result


class P610BValidationExecutionBackend(ProductionValidationExecutionBackend):
    """Additive two-candidate backend without changing the P6-9 default path."""

    backend_id = P6_10B_VALIDATION_BACKEND_ID
    backend_version = P6_10B_VALIDATION_BACKEND_VERSION

    def __init__(
        self,
        plan: ValidationBatchPlan,
        *,
        repo_root: Path | str,
        confidence_candidate: PrimaryCandidate,
        provider_candidate: PrimaryCandidate,
    ) -> None:
        if confidence_candidate.candidate_id == provider_candidate.candidate_id:
            raise ValueError("P6-10B candidates must be distinct")
        super().__init__(
            plan,
            repo_root=repo_root,
            additional_candidates=(confidence_candidate, provider_candidate),
        )
        self._confidence_candidate_id = confidence_candidate.candidate_id
        self._provider_candidate_id = provider_candidate.candidate_id
        self._p6_10b_policy_cache: dict[
            tuple[str, str, int, int],
            tuple[StrategyProfile, StrategyProfile, dict[str, object]],
        ] = {}
        self._p6_10b_session_evidence: dict[ValidationSessionKey, dict[str, object]] = {}

    def ablation_evidence(self, key: ValidationSessionKey) -> dict[str, object]:
        """Return terminal estimator/provider evidence for an executed session."""
        try:
            return self._p6_10b_session_evidence[key]
        except KeyError as exc:
            raise ValueError("P6-10B session has not been executed") from exc

    def validate_p6_10b_saved_policy(
        self,
        candidate: PrimaryCandidate,
        terminal: object,
        policy: object,
        opponent: SynthesizedOpponent,
        dimension: Mapping[str, object],
    ) -> tuple[StrategyProfile, StrategyProfile]:
        """Reconstruct an additive ablation policy without changing P6-9 semantics."""
        if candidate.candidate_id not in {
            self._confidence_candidate_id,
            self._provider_candidate_id,
        }:
            raise ValueError("P6-10B policy verifier received a non-ablation candidate")
        if dimension != self._context.dimension:
            raise ValueError("P6-10B policy verifier received a different frozen dimension")
        if not isinstance(terminal, dict) or not isinstance(policy, dict):
            raise ValueError("P6-10B policy reconstruction requires canonical session results")
        counts = terminal.get("action_counts")
        opportunities = terminal.get("opportunity_count")
        if not isinstance(counts, dict) or not isinstance(opportunities, int):
            raise ValueError("P6-10B terminal counts are invalid")
        expected_base, expected_final = self._hero_policies(
            candidate, opponent, counts, opportunities
        )
        if policy.get("base_hero_policy") != _profile_payload(expected_base):
            raise ValueError("P6-10B base Hero policy differs from frozen equilibrium")
        if policy.get("final_hero_policy") != _profile_payload(expected_final):
            raise ValueError("P6-10B final Hero policy does not reconstruct")
        return expected_base, expected_final

    def evaluate_candidates(
        self, requests: Sequence[ValidationCandidateRequest]
    ) -> Sequence[ValidationCandidateResult]:
        """Evaluate additive candidates through their intervention-aware verifier."""
        checked = self._validate_candidate_requests(requests)
        results: list[ValidationCandidateResult] = []
        for request in checked:
            calibration, aggregate, _series = _candidate_products(
                self._plan,
                request,
                self._context,
                policy_validator=self.validate_p6_10b_saved_policy,
            )
            results.append(
                ValidationCandidateResult(
                    split="validation",
                    candidate_id=request.candidate.candidate_id,
                    session_join_sha256=request.session_join_sha256,
                    calibration_cell=calibration,
                    aggregate_metrics=aggregate,
                )
            )
        return tuple(results)

    def _run_session(self, request: ValidationSessionRequest) -> ValidationSessionResult:
        result = super()._run_session(request)
        counts = result.terminal_candidate_snapshot["action_counts"]
        opponent = self._opponents[request.key.opponent_id]
        cache_key = (
            request.candidate.candidate_id,
            opponent.equilibrium_artifact_sha256,
            counts["CHECK"],
            counts["BET"],
        )
        try:
            evidence = self._p6_10b_policy_cache[cache_key][2]
        except KeyError as exc:
            raise ValueError("P6-10B terminal policy evidence was not reconstructed") from exc
        self._p6_10b_session_evidence[request.key] = evidence
        return result

    def _hero_policies(
        self,
        candidate: PrimaryCandidate,
        opponent: SynthesizedOpponent,
        counts: Mapping[str, int],
        opportunities: int,
    ) -> tuple[StrategyProfile, StrategyProfile]:
        if candidate.candidate_id not in {
            self._confidence_candidate_id,
            self._provider_candidate_id,
        }:
            return super()._hero_policies(candidate, opponent, counts, opportunities)
        cache_key = (
            candidate.candidate_id,
            opponent.equilibrium_artifact_sha256,
            counts.get("CHECK", 0),
            counts.get("BET", 0),
        )
        cached = self._p6_10b_policy_cache.get(cache_key)
        if cached is not None:
            return cached[0], cached[1]
        if candidate.candidate_id == self._confidence_candidate_id:
            result = self._confidence_policies(candidate, opponent, counts, opportunities)
        else:
            result = self._provider_policies(candidate, opponent, counts, opportunities)
        self._p6_10b_policy_cache[cache_key] = result
        return result[0], result[1]

    def _r008_detector(
        self, candidate: PrimaryCandidate
    ) -> tuple[LeakDetector, float, tuple[str, ...]]:
        dimension = self._context.dimension
        action_group = dimension["action_group"]
        baseline_wire = dimension["baseline_rate"]
        if not isinstance(action_group, list) or not isinstance(baseline_wire, str):
            raise ValueError("Validation R008 dimension is invalid")
        baseline_rate = float(Decimal(baseline_wire))
        baseline_table = ActionBaselineTable(
            table_version="phase6-frozen-r008-baseline-v1",
            rules=(
                ActionLeakRule(
                    reason_id=_R008_REASON_ID,
                    leak_type=_R008_LEAK_TYPE,
                    action_group=tuple(action_group),
                    baseline_rate=baseline_rate,
                    direction=_R008_DIRECTION,
                    situation_overrides={_R008_SITUATION_KEY: baseline_rate},
                ),
            ),
        )
        detector = LeakDetector(
            baseline_table,
            LeakDetectorConfig(
                min_effective_sample_size=candidate.sample_floor,
                min_deviation=float(Decimal(_TAU_WIRE)),
                min_confidence=float(Decimal(candidate.detector_confidence)),
                rule_exploit_min_confidence=float(Decimal(candidate.provider_confidence)),
                nodelock_exploit_min_confidence=float(Decimal(candidate.provider_confidence)),
            ),
        )
        return detector, baseline_rate, tuple(action_group)

    def _confidence_policies(
        self,
        candidate: PrimaryCandidate,
        opponent: SynthesizedOpponent,
        counts: Mapping[str, int],
        opportunities: int,
    ) -> tuple[StrategyProfile, StrategyProfile, dict[str, object]]:
        _detector, baseline_rate, action_group = self._r008_detector(candidate)
        k = sum(counts.get(action, 0) for action in action_group)
        score = legacy_mvp_confidence(
            k=k,
            n=opportunities,
            baseline_rate=baseline_rate,
            sample_floor=candidate.sample_floor,
        )
        observed_rate = 0.0 if opportunities <= 0 else k / opportunities
        deviation = observed_rate - baseline_rate
        sample_gate = opportunities >= candidate.sample_floor
        deviation_gate = deviation >= float(Decimal(_TAU_WIRE))
        confidence_gate = score >= float(Decimal(candidate.detector_confidence))
        emitted = sample_gate and deviation_gate and confidence_gate
        leaks: tuple[DetectedLeak, ...] = ()
        if emitted:
            leaks = (
                DetectedLeak(
                    reason_id=_R008_REASON_ID,
                    leak_type=_R008_LEAK_TYPE,
                    situation_key=_R008_SITUATION_KEY,
                    observed_rate=observed_rate,
                    baseline_rate=baseline_rate,
                    effective_sample_size=opportunities,
                    confidence=score,
                    direction=_R008_DIRECTION,
                ),
            )
        base, exploit, final, node_lock_applied = self._nodelock_policies(
            candidate, opponent, leaks
        )
        score_evidence = _binary64_evidence(score)
        evidence = {
            "ablation_id": "abl_confidence_mvp__v1",
            "estimator_method_version": "mvp-confidence-heuristic-v1",
            "confidence_value_semantics": "bounded_legacy_score_not_probability",
            "dpl_semantic_version": "1.0.0",
            "source": {
                "k": k,
                "n": opportunities,
                "baseline_rate": _binary64_evidence(baseline_rate),
                "tau": _TAU_WIRE,
                "sample_floor": candidate.sample_floor,
                "detector_threshold": candidate.detector_confidence,
                "provider_threshold": candidate.provider_confidence,
            },
            "observed_rate": _binary64_evidence(observed_rate),
            "deviation": _binary64_evidence(deviation),
            "confidence_value": score_evidence["exact_decimal"],
            "score_binary64_hex": score_evidence["binary64_hex"],
            "score_exact_decimal": score_evidence["exact_decimal"],
            "candidate_eligibility": {
                "structurally_eligible": True,
                "sample_gate": sample_gate,
                "deviation_gate": deviation_gate,
                "confidence_gate": confidence_gate,
                "emitted": emitted,
            },
            "exploit_provider": "nodelock-provider-r008-v2",
            "safety_alpha": candidate.safety_alpha,
            "provider_result": {
                "node_lock_applied": node_lock_applied,
                "solver_result_id": None,
            },
            "pi_base": _json_ready(base),
            "pi_exploit": _json_ready(exploit),
            "pi_final": _json_ready(final),
        }
        return base, final, evidence

    def _nodelock_policies(
        self,
        candidate: PrimaryCandidate,
        opponent: SynthesizedOpponent,
        leaks: Sequence[DetectedLeak],
    ) -> tuple[StrategyProfile, StrategyProfile, StrategyProfile, bool]:
        node_lock = nodelock_config_from_leaks(
            tuple(leaks),
            hero_position="OOP",
            min_confidence=float(Decimal(candidate.provider_confidence)),
        )
        game = opponent.game
        hero_infosets = game.infosets_of(0)
        base = {infoset: dict(opponent.equilibrium_strategy[infoset]) for infoset in hero_infosets}
        exploit = {infoset: dict(distribution) for infoset, distribution in base.items()}
        if node_lock is not None:
            application = apply_node_locks(
                game,
                opponent.equilibrium_strategy,
                node_lock,
                reach_weights=river_infoset_reach_weights(game, opponent.equilibrium_strategy),
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
                base[infoset], exploit[infoset], float(Decimal(candidate.safety_alpha))
            )
            for infoset in hero_infosets
        }
        return base, exploit, final, node_lock is not None

    def _provider_policies(
        self,
        candidate: PrimaryCandidate,
        opponent: SynthesizedOpponent,
        counts: Mapping[str, int],
        opportunities: int,
    ) -> tuple[StrategyProfile, StrategyProfile, dict[str, object]]:
        detector, _baseline_rate, _action_group = self._r008_detector(candidate)
        stats = ActionStats(_R008_SITUATION_KEY, opportunities, counts)
        leaks = tuple(detector.detect_for_situation((stats,), _R008_SITUATION_KEY))
        provider = RuleExploitProvider(
            RuleExploitConfig(
                min_confidence=float(Decimal(candidate.provider_confidence)),
                min_ev_delta=0.0,
                max_call_probability_shift=0.5,
            )
        )
        game = opponent.game
        hero_infosets = game.infosets_of(0)
        base = {infoset: dict(opponent.equilibrium_strategy[infoset]) for infoset in hero_infosets}
        exploit = {infoset: dict(distribution) for infoset, distribution in base.items()}
        infoset_evidence: list[dict[str, object]] = []
        for infoset in hero_infosets:
            if not infoset.endswith(":vs_bet"):
                continue
            action_values, counterfactual_reach = _equilibrium_counterfactual_action_value_details(
                game, opponent.equilibrium_strategy, infoset
            )
            result = provider.build(
                base_policy=base[infoset],
                detected_leaks=leaks,
                legal_actions=game.actions_of(infoset),
                action_ev=action_values,
            )
            exploit[infoset] = result.policy
            infoset_evidence.append(
                {
                    "infoset": infoset,
                    "action_ev_contract": "equilibrium-counterfactual-action-value-v1",
                    "action_ev": {
                        action: {
                            "value_binary64_hex": action_values[action].hex(),
                            "value_exact_decimal": _binary64_evidence(action_values[action])[
                                "exact_decimal"
                            ],
                            "counterfactual_reach_binary64_hex": counterfactual_reach.hex(),
                            "counterfactual_reach_exact_decimal": _binary64_evidence(
                                counterfactual_reach
                            )["exact_decimal"],
                        }
                        for action in game.actions_of(infoset)
                    },
                    "base_policy": _json_ready(base[infoset]),
                    "provider_policy": _json_ready(result.policy),
                    "applied_leak_reason_ids": list(result.applied_leak_reason_ids),
                    "trigger_reasons": list(result.trigger_reasons),
                    "exploit_source": result.exploit_source,
                    "solver_result_id": result.solver_result_id,
                }
            )
        final = {
            infoset: safety_mix(
                base[infoset], exploit[infoset], float(Decimal(candidate.safety_alpha))
            )
            for infoset in hero_infosets
        }
        for item in infoset_evidence:
            item["final_policy"] = _json_ready(final[item["infoset"]])
        evidence = {
            "ablation_id": "abl_provider_rule__v1",
            "estimator_method_version": "beta-binomial-upper-tail-v1",
            "dpl_semantic_version": "2.0.0",
            "exploit_provider": "rule-exploit-provider-r008-v1",
            "provider_config": {
                "min_confidence": candidate.provider_confidence,
                "min_ev_delta": "0",
                "max_call_probability_shift": "0.5",
                "supported_reason": _R008_REASON_ID,
            },
            "detected_leaks": [
                {
                    "reason_id": leak.reason_id,
                    "observed_rate": _binary64_evidence(leak.observed_rate),
                    "baseline_rate": _binary64_evidence(leak.baseline_rate),
                    "effective_sample_size": leak.effective_sample_size,
                    "confidence": _binary64_evidence(leak.confidence),
                }
                for leak in leaks
            ],
            "infosets": infoset_evidence,
            "safety_alpha": candidate.safety_alpha,
            "pi_base": _json_ready(base),
            "pi_exploit": _json_ready(exploit),
            "pi_final": _json_ready(final),
        }
        return base, final, evidence


def legacy_mvp_confidence(*, k: int, n: int, baseline_rate: float, sample_floor: int) -> float:
    """Historical binary64 MVP confidence formula pinned by P6-10B D1/D2."""
    if not isinstance(k, int) or not isinstance(n, int) or k < 0 or n < 0 or k > n:
        raise ValueError("legacy confidence requires integer 0 <= k <= n")
    if not math.isfinite(baseline_rate) or not 0.0 <= baseline_rate <= 1.0:
        raise ValueError("baseline_rate must be finite and in [0, 1]")
    if not isinstance(sample_floor, int) or sample_floor <= 0:
        raise ValueError("sample_floor must be a positive integer")
    if n <= 0:
        return 0.0
    observed_rate = k / n
    deviation = observed_rate - baseline_rate
    sample_factor = min(1.0, n / sample_floor)
    scaled_deviation = deviation * 2.0
    raw_score = scaled_deviation * sample_factor
    return min(1.0, max(0.0, raw_score))


def equilibrium_counterfactual_action_values(
    game: Game,
    equilibrium_strategy: Mapping[str, Mapping[str, float]],
    infoset: str,
) -> dict[str, float]:
    """Compute frozen-equilibrium action values with Hero reach excluded."""
    values, _reach = _equilibrium_counterfactual_action_value_details(
        game, equilibrium_strategy, infoset
    )
    return values


def _equilibrium_counterfactual_action_value_details(
    game: Game,
    equilibrium_strategy: Mapping[str, Mapping[str, float]],
    infoset: str,
) -> tuple[dict[str, float], float]:
    if game.player_of(infoset) != 0:
        raise ValueError("counterfactual action values require a Hero infoset")
    actions = game.actions_of(infoset)
    weighted: dict[str, list[float]] = {action: [] for action in actions}
    reaches: list[float] = []

    def continuation(node: Node) -> float:
        if isinstance(node, Terminal):
            return float(node.payoff)
        if isinstance(node, Chance):
            return math.fsum(
                probability * continuation(child) for probability, child, _ in node.branches
            )
        distribution = equilibrium_strategy.get(node.infoset)
        if distribution is None or set(distribution) != set(node.actions):
            raise ValueError("equilibrium strategy does not cover a decision infoset")
        return math.fsum(
            distribution[action] * continuation(child)
            for action, child in zip(node.actions, node.children, strict=True)
        )

    def visit(node: Node, counterfactual_reach: float) -> None:
        if isinstance(node, Terminal):
            return
        if isinstance(node, Chance):
            for probability, child, _label in node.branches:
                visit(child, counterfactual_reach * probability)
            return
        if node.player == 0:
            if node.infoset == infoset:
                reaches.append(counterfactual_reach)
                for action, child in zip(node.actions, node.children, strict=True):
                    weighted[action].append(counterfactual_reach * continuation(child))
                return
            for child in node.children:
                visit(child, counterfactual_reach)
            return
        distribution = equilibrium_strategy.get(node.infoset)
        if distribution is None or set(distribution) != set(node.actions):
            raise ValueError("equilibrium strategy does not cover an opponent infoset")
        for action, child in zip(node.actions, node.children, strict=True):
            visit(child, counterfactual_reach * distribution[action])

    visit(game.root, 1.0)
    denominator = math.fsum(reaches)
    if not denominator > 0.0:
        raise ValueError("Hero infoset has zero counterfactual reach")
    return (
        {action: math.fsum(weighted[action]) / denominator for action in actions},
        denominator,
    )


def _binary64_evidence(value: float) -> dict[str, str]:
    if not math.isfinite(value):
        raise ValueError("binary64 evidence must be finite")
    decimal_value = Decimal.from_float(value)
    wire = format(decimal_value, "f")
    if "." in wire:
        wire = wire.rstrip("0").rstrip(".")
    if wire in {"-0", ""}:
        wire = "0"
    return {"binary64_hex": value.hex(), "exact_decimal": wire}


def _chance_child(root: Chance, selected_label: str) -> Decision:
    matches = [child for _probability, child, label in root.branches if label == selected_label]
    if len(matches) != 1:
        raise ValueError("frozen Validation deal is not in the game tree")
    child = matches[0]
    if not isinstance(child, Decision) or child.player != 0 or not child.infoset.endswith(":start"):
        raise ValueError("frozen Validation deal does not lead to the OOP start decision")
    return child


def _session_hashes(result: ValidationSessionResult) -> tuple[str, str, str]:
    return tuple(
        sha256_bytes(canonical_json_bytes(value))
        for value in (
            result.terminal_candidate_snapshot,
            result.hero_policy_snapshot,
            result.exact_ev_cell,
        )
    )


def _json_ready(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: _json_ready(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


__all__ = [
    "P6_10B_VALIDATION_BACKEND_ID",
    "P6_10B_VALIDATION_BACKEND_VERSION",
    "P610BValidationExecutionBackend",
    "PRODUCTION_VALIDATION_BACKEND_ID",
    "PRODUCTION_VALIDATION_BACKEND_VERSION",
    "ProductionValidationExecutionBackend",
    "equilibrium_counterfactual_action_values",
    "legacy_mvp_confidence",
]
