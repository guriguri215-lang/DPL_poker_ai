"""Vertical-slice session runner: scenarios -> decisions -> validated DPL + manifest.

Generates scenarios deterministically and solves each public river spot with CFR+.
The historical path observes the jam-all stub before Hero's finite-iteration
``vs_bet`` decision. Explicit R007, R001, R002, R003, and R004 fixtures instead give OOP Hero
the existing tree's bounded ``start`` decision and record an opponent response only
after Hero reaches the corresponding opportunity. Each decision is assembled into a current
:class:`~poker_core.dpl_schema.DecisionProvenanceLog`. Public action observations feed
the leak detector independently; its action baseline still matches the stub opponent,
so the normal CLI run remains leak-free. Optional rule or node-lock exploitation stays
behind the existing DPL SafetyMixer convex-combination contract, which is not a
strategy-safety proof. Frozen-model terminal/action EV is exact ``solver_exact``. A
:class:`~poker_core.run_manifest.RunManifest` pins the strategy and solver config; it
does not certify convergence, exact equilibrium, or GTO status.

The DPLs are written as JSONL (one decision per line); the manifest is written as a
sidecar JSON. Both live under a gitignored output directory.
"""

from __future__ import annotations

import hashlib
import json
import platform
import random
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from poker_core.dpl_schema import (
    DPL_SCHEMA_VERSION,
    DecisionProvenanceLog,
    DetectedLeak,
    EvEstimate,
)
from poker_core.range_model import Range
from poker_core.reason_ontology import get_ontology
from poker_core.run_manifest import (
    ArtifactRef,
    CodeProvenance,
    ComponentVersions,
    ConfigRef,
    OpponentRef,
    RunManifest,
)
from poker_core.state_cluster import CLUSTER_DEF_PATH, classify_board, cluster_def_version

from .base_policy import BasePolicyProvider
from .baseline_strategy import FACING_ALL_IN, build_situation_key
from .cfr_policy import (
    DEFAULT_CFR_RIVER_POLICY_CONFIG,
    CfrRiverNoFacingPolicyConfig,
    CfrRiverNoFacingPolicyProvider,
    CfrRiverPolicyConfig,
    CfrRiverPolicyProvider,
    CfrRiverR001NoFacingPolicyProvider,
)
from .decision import HeroAgent, Observation
from .exploit import ExploitProvider
from .hand_bucket import BUCKET_DEF_PATH, bucket_def_version, get_bucket_definition
from .leak import LeakDetector
from .mixer import EPSILON_SAMPLER_VERSION
from .observation import ActionStats, ObservationTracker
from .opponent import (
    CHECK_BACK_OPPONENT_ID,
    JAM_ALL_OPPONENT_ID,
    R001_FIXTURE_OPPONENT_ID,
    R002_FIXTURE_OPPONENT_ID,
    R003_FIXTURE_OPPONENT_ID,
    R003_FIXTURE_PROFILE_SEED,
    R003_FIXTURE_RESPONSE_SAMPLER_VERSION,
    R004_FIXTURE_OPPONENT_ID,
    R004_FIXTURE_RESPONSE_SAMPLER_VERSION,
    STUB_OPPONENT_VERSION,
    StubOpponent,
    load_r001_fixture_synthesis,
    load_r002_fixture_synthesis,
    r001_fixture_measurement,
    r002_fixture_measurement,
    r003_fixture_config_identity,
    r003_fixture_measurement,
    r004_fixture_config_identity,
    r004_fixture_measurement,
    sample_river_large_bet_fixture_response,
)
from .posterior_bundle import (
    PosteriorBundleParts,
    build_posterior_bundle_parts,
    validate_posterior_bundle,
    write_posterior_artifacts,
)
from .runtime_provenance import resolve_package_version
from .scenario import SCENARIO_SCHEMA_VERSION, Scenario, generate_scenarios

#: EV source for every task-3 DPL: exact frozen-model action evaluation (ADR-0008).
EV_SOURCE = "solver_exact"

#: Historical default stub identity (ADR-0007).
OPPONENT_ID = JAM_ALL_OPPONENT_ID
OPPONENT_VERSION = STUB_OPPONENT_VERSION

FACING_ALL_IN_SESSION_MODE = "facing_all_in"
R007_NO_FACING_SESSION_MODE = "r007_no_facing"
R001_NO_FACING_SESSION_MODE = "r001_no_facing"
R002_NO_FACING_SESSION_MODE = "r002_no_facing"
R003_NO_FACING_SESSION_MODE = "r003_no_facing"
R004_NO_FACING_SESSION_MODE = "r004_no_facing"
SessionMode = Literal[
    "facing_all_in",
    "r007_no_facing",
    "r001_no_facing",
    "r002_no_facing",
    "r003_no_facing",
    "r004_no_facing",
]


@dataclass(frozen=True)
class SessionResult:
    """The validated DPLs and the reproducibility manifest for one session."""

    session_id: str
    logs: list[DecisionProvenanceLog]
    manifest: RunManifest
    posterior_bundle: PosteriorBundleParts


def _session_id_for(seed: int) -> str:
    return f"S{seed:08d}"


def _build_dpl(
    scenario: Scenario,
    hand_id: str,
    session_id: str,
    *,
    tracker: ObservationTracker,
    leak_detector: LeakDetector,
    safety_alpha: float,
    exploration_epsilon: float,
    exploit_provider: ExploitProvider | None,
    base_policy_provider: BasePolicyProvider,
) -> DecisionProvenanceLog:
    """Run one decision and assemble its validated DPL."""
    opponent = StubOpponent(
        opponent_id=OPPONENT_ID,
        opponent_version=OPPONENT_VERSION,
        assumed_range=scenario.opponent_range_obj(),
    )
    # Environment-only: the opponent acts under its hidden strategy; Hero is handed
    # only the resulting facing bet, never the opponent object (AI Spec 6.3).
    opponent_action = opponent.act(effective_stack=scenario.effective_stack)

    observation = Observation(
        hand_id=hand_id,
        session_id=session_id,
        board=scenario.board_cards(),
        position=scenario.position,
        pot=scenario.pot,
        facing_bet=opponent_action.bet_size,
        effective_stack=scenario.effective_stack,
        hero_combo=scenario.hero_combo_obj(),
        hero_range=scenario.hero_range_obj(),
        opponent_assumed_range=Range(scenario.opponent_range),
    )
    situation_key = build_situation_key(
        classify_board(observation.board),
        observation.position,
        FACING_ALL_IN,
    )
    tracker.record_opponent_action(
        situation_key=situation_key,
        action=opponent_action.action,
    )
    detected_leaks = leak_detector.detect_for_situation(
        tracker.snapshot(),
        situation_key,
    )
    return _assemble_dpl(
        scenario,
        hand_id,
        session_id,
        observation=observation,
        detected_leaks=detected_leaks,
        leak_detector=leak_detector,
        safety_alpha=safety_alpha,
        exploration_epsilon=exploration_epsilon,
        exploit_provider=exploit_provider,
        base_policy_provider=base_policy_provider,
    )


def _build_r007_dpl(
    scenario: Scenario,
    hand_id: str,
    session_id: str,
    *,
    tracker: ObservationTracker,
    leak_detector: LeakDetector,
    safety_alpha: float,
    exploration_epsilon: float,
    exploit_provider: ExploitProvider | None,
    base_policy_provider: BasePolicyProvider,
) -> DecisionProvenanceLog:
    """Run one causal OOP no-facing decision for the R007 fixture."""
    scenario = _as_oop_scenario(scenario)
    opponent = StubOpponent(
        opponent_id=CHECK_BACK_OPPONENT_ID,
        opponent_version=OPPONENT_VERSION,
        assumed_range=scenario.opponent_range_obj(),
        _policy="check_back_all",
    )
    log, opponent_situation_key = _build_no_facing_decision(
        scenario,
        hand_id,
        session_id,
        opponent_phase="river_vs_check",
        tracker=tracker,
        leak_detector=leak_detector,
        safety_alpha=safety_alpha,
        exploration_epsilon=exploration_epsilon,
        exploit_provider=exploit_provider,
        base_policy_provider=base_policy_provider,
    )
    if log.selected_action == "CHECK":
        opponent_action = opponent.respond_to_check(
            effective_stack=scenario.effective_stack,
        )
        tracker.record_opponent_action(
            situation_key=opponent_situation_key,
            action=opponent_action.action,
        )
    return log


def _build_river_large_bet_dpl(
    scenario: Scenario,
    hand_id: str,
    session_id: str,
    *,
    tracker: ObservationTracker,
    leak_detector: LeakDetector,
    safety_alpha: float,
    exploration_epsilon: float,
    exploit_provider: ExploitProvider | None,
    base_policy_provider: BasePolicyProvider,
    bet_fraction: float,
    target_action: str,
    target_probability: float,
    response_rng: random.Random,
) -> DecisionProvenanceLog:
    """Run the shared causal OOP CHECK/BET_75 decision for R001 or R002."""

    scenario = _as_river_large_bet_scenario(scenario, bet_fraction=bet_fraction)
    log, opponent_situation_key = _build_no_facing_decision(
        scenario,
        hand_id,
        session_id,
        opponent_phase="river_vs_bet",
        tracker=tracker,
        leak_detector=leak_detector,
        safety_alpha=safety_alpha,
        exploration_epsilon=exploration_epsilon,
        exploit_provider=exploit_provider,
        base_policy_provider=base_policy_provider,
    )
    if log.selected_action == "BET_75":
        opponent_action = sample_river_large_bet_fixture_response(
            target_action=target_action,
            target_probability=target_probability,
            rng=response_rng,
        )
        tracker.record_opponent_action(
            situation_key=opponent_situation_key,
            action=opponent_action.action,
        )
    return log


def _build_r003_dpl(
    scenario: Scenario,
    hand_id: str,
    session_id: str,
    *,
    tracker: ObservationTracker,
    leak_detector: LeakDetector,
    safety_alpha: float,
    exploration_epsilon: float,
    exploit_provider: ExploitProvider | None,
    base_policy_provider: BasePolicyProvider,
    target_probability: float,
    response_rng: random.Random,
) -> DecisionProvenanceLog:
    """Run one causal OOP CHECK/BET_33 decision for the R003 fixture."""

    scenario = _as_oop_scenario(scenario)
    log, opponent_situation_key = _build_no_facing_decision(
        scenario,
        hand_id,
        session_id,
        opponent_phase="river_vs_bet",
        tracker=tracker,
        leak_detector=leak_detector,
        safety_alpha=safety_alpha,
        exploration_epsilon=exploration_epsilon,
        exploit_provider=exploit_provider,
        base_policy_provider=base_policy_provider,
    )
    if log.selected_action == "BET_33":
        opponent_action = sample_river_large_bet_fixture_response(
            target_action="FOLD",
            target_probability=target_probability,
            rng=response_rng,
        )
        tracker.record_opponent_action(
            situation_key=opponent_situation_key,
            action=opponent_action.action,
        )
    return log


def _build_r004_dpl(
    scenario: Scenario,
    hand_id: str,
    session_id: str,
    *,
    tracker: ObservationTracker,
    leak_detector: LeakDetector,
    safety_alpha: float,
    exploration_epsilon: float,
    exploit_provider: ExploitProvider | None,
    base_policy_provider: BasePolicyProvider,
    target_probability: float,
    response_rng: random.Random,
) -> DecisionProvenanceLog:
    """Run one causal OOP CHECK/BET_33 decision for the R004 fixture."""

    scenario = _as_oop_scenario(scenario)
    log, opponent_situation_key = _build_no_facing_decision(
        scenario,
        hand_id,
        session_id,
        opponent_phase="river_vs_bet",
        tracker=tracker,
        leak_detector=leak_detector,
        safety_alpha=safety_alpha,
        exploration_epsilon=exploration_epsilon,
        exploit_provider=exploit_provider,
        base_policy_provider=base_policy_provider,
    )
    if log.selected_action == "BET_33":
        opponent_action = sample_river_large_bet_fixture_response(
            target_action="CALL",
            target_probability=target_probability,
            rng=response_rng,
        )
        tracker.record_opponent_action(
            situation_key=opponent_situation_key,
            action=opponent_action.action,
        )
    return log


def _build_no_facing_decision(
    scenario: Scenario,
    hand_id: str,
    session_id: str,
    *,
    opponent_phase: str,
    tracker: ObservationTracker,
    leak_detector: LeakDetector,
    safety_alpha: float,
    exploration_epsilon: float,
    exploit_provider: ExploitProvider | None,
    base_policy_provider: BasePolicyProvider,
) -> tuple[DecisionProvenanceLog, str]:
    """Assemble a no-facing Hero decision before any causal opponent response."""

    observation = Observation(
        hand_id=hand_id,
        session_id=session_id,
        board=scenario.board_cards(),
        position="OOP",
        pot=scenario.pot,
        facing_bet=0.0,
        effective_stack=scenario.effective_stack,
        hero_combo=scenario.hero_combo_obj(),
        hero_range=scenario.hero_range_obj(),
        opponent_assumed_range=Range(scenario.opponent_range),
    )
    opponent_situation_key = f"{classify_board(observation.board)}:IP:{opponent_phase}"
    tracker.register_situation(opponent_situation_key)
    detected_leaks = leak_detector.detect_for_situation(
        tracker.snapshot(),
        opponent_situation_key,
    )
    log = _assemble_dpl(
        scenario,
        hand_id,
        session_id,
        observation=observation,
        detected_leaks=detected_leaks,
        leak_detector=leak_detector,
        safety_alpha=safety_alpha,
        exploration_epsilon=exploration_epsilon,
        exploit_provider=exploit_provider,
        base_policy_provider=base_policy_provider,
    )
    return log, opponent_situation_key


def _assemble_dpl(
    scenario: Scenario,
    hand_id: str,
    session_id: str,
    *,
    observation: Observation,
    detected_leaks: list[DetectedLeak],
    leak_detector: LeakDetector,
    safety_alpha: float,
    exploration_epsilon: float,
    exploit_provider: ExploitProvider | None,
    base_policy_provider: BasePolicyProvider,
) -> DecisionProvenanceLog:
    """Apply the shared Hero/mixer/DPL contract to one public observation."""
    agent = HeroAgent(
        base_policy_provider,
        get_bucket_definition(),
        safety_alpha=safety_alpha,
        exploration_epsilon=exploration_epsilon,
        exploit_provider=exploit_provider,
        confidence_config=leak_detector.config,
    )
    result = agent.decide(observation, detected_leaks=detected_leaks)
    leak_reason_ids = (
        result.applied_leak_reason_ids
        if result.mix_reasons
        else [leak.reason_id for leak in detected_leaks]
    )
    allowed_reason_ids = list(
        dict.fromkeys(
            [
                *leak_reason_ids,
                *result.trigger_reasons,
                *result.mix_reasons,
            ]
        )
    )

    ev = EvEstimate(
        base_ev=result.base_ev,
        exploit_ev=result.exploit_ev,
        final_ev=result.final_ev,
        worst_case_penalty=None,  # Mode-2 penalty is a solver product; not computed here.
        ev_source=EV_SOURCE,
        ev_unit=result.ev_unit,
        ev_definition=result.ev_definition,
    )
    return DecisionProvenanceLog(
        hand_id=hand_id,
        session_id=session_id,
        schema_version=DPL_SCHEMA_VERSION,
        state_cluster=result.state_cluster,
        cluster_def_version=result.cluster_def_version,
        hand_bucket=result.hand_bucket,
        hero_combo=scenario.hero_combo,
        base_policy=result.base_policy,
        detected_leaks=detected_leaks,
        trigger_reasons=result.trigger_reasons,
        mix_reasons=result.mix_reasons,
        exploit_policy=result.exploit_policy,
        exploit_source=result.exploit_source,
        solver_result_id=result.solver_result_id,
        safety_alpha=safety_alpha,
        final_policy=result.final_policy,
        selected_action=result.selected_action,
        sampling_seed=result.sampling_seed,
        execution_sampling=result.execution_sampling,
        ev_estimate=ev,
        allowed_reason_ids=allowed_reason_ids,
        baseline_table_version=leak_detector.baseline_table_version,
        base_strategy_provenance=result.base_strategy_provenance,
    )


def _as_oop_scenario(scenario: Scenario) -> Scenario:
    if scenario.position == "OOP":
        return scenario
    payload = scenario.model_dump(mode="python")
    payload["position"] = "OOP"
    return Scenario.model_validate(payload)


def _as_river_large_bet_scenario(scenario: Scenario, *, bet_fraction: float) -> Scenario:
    oop = _as_oop_scenario(scenario)
    minimum_stack = oop.pot * bet_fraction
    if oop.effective_stack >= minimum_stack:
        return oop
    payload = oop.model_dump(mode="python")
    payload["effective_stack"] = minimum_stack
    return Scenario.model_validate(payload)


def _river_large_bet_fixture_for(session_mode: SessionMode):
    """Return the one in-memory fixture used by a 0.75-pot session mode."""

    if session_mode == R001_NO_FACING_SESSION_MODE:
        fixture = load_r001_fixture_synthesis()
        return fixture, r001_fixture_measurement(fixture)
    if session_mode == R002_NO_FACING_SESSION_MODE:
        fixture = load_r002_fixture_synthesis()
        return fixture, r002_fixture_measurement(fixture)
    raise ValueError(f"session mode {session_mode!r} is not a river-large-bet fixture")


def _base_policy_provider_for(
    solver_config: CfrRiverPolicyConfig,
    session_mode: SessionMode,
) -> BasePolicyProvider:
    if session_mode == FACING_ALL_IN_SESSION_MODE:
        return CfrRiverPolicyProvider(solver_config)
    if session_mode in {
        R007_NO_FACING_SESSION_MODE,
        R003_NO_FACING_SESSION_MODE,
        R004_NO_FACING_SESSION_MODE,
    }:
        return CfrRiverNoFacingPolicyProvider(
            CfrRiverNoFacingPolicyConfig(
                iterations=solver_config.iterations,
                average_delay=solver_config.average_delay,
                checkpoints=solver_config.checkpoints,
            )
        )
    if session_mode in {R001_NO_FACING_SESSION_MODE, R002_NO_FACING_SESSION_MODE}:
        fixture, _measurement = _river_large_bet_fixture_for(session_mode)
        return CfrRiverR001NoFacingPolicyProvider(
            solver_config,
            bet_fraction=fixture.bet_fraction,
            equilibrium_version=fixture.equilibrium_version,
            equilibrium_artifact_sha256=fixture.equilibrium_artifact_sha256,
        )
    raise ValueError(f"unknown session_mode {session_mode!r}")


def _opponent_id_for(session_mode: SessionMode) -> str:
    if session_mode == FACING_ALL_IN_SESSION_MODE:
        return OPPONENT_ID
    if session_mode == R007_NO_FACING_SESSION_MODE:
        return CHECK_BACK_OPPONENT_ID
    if session_mode == R001_NO_FACING_SESSION_MODE:
        return R001_FIXTURE_OPPONENT_ID
    if session_mode == R002_NO_FACING_SESSION_MODE:
        return R002_FIXTURE_OPPONENT_ID
    if session_mode == R003_NO_FACING_SESSION_MODE:
        return R003_FIXTURE_OPPONENT_ID
    if session_mode == R004_NO_FACING_SESSION_MODE:
        return R004_FIXTURE_OPPONENT_ID
    raise ValueError(f"unknown session_mode {session_mode!r}")


def iter_session_logs(
    seed: int,
    num_hands: int,
    *,
    leak_detector: LeakDetector | None = None,
    safety_alpha: float = 0.0,
    exploration_epsilon: float = 0.0,
    exploit_provider: ExploitProvider | None = None,
    solver_config: CfrRiverPolicyConfig = DEFAULT_CFR_RIVER_POLICY_CONFIG,
    session_mode: SessionMode = FACING_ALL_IN_SESSION_MODE,
    _tracker: ObservationTracker | None = None,
    _base_policy_provider: BasePolicyProvider | None = None,
) -> Iterator[DecisionProvenanceLog]:
    """Yield one validated DPL per generated hand (deterministic for a seed)."""
    session_id = _session_id_for(seed)
    tracker = _tracker or ObservationTracker()
    detector = leak_detector or LeakDetector()
    base_policy_provider = _base_policy_provider or _base_policy_provider_for(
        solver_config,
        session_mode,
    )
    large_bet_fixture = None
    large_bet_measurement = None
    if session_mode in {R001_NO_FACING_SESSION_MODE, R002_NO_FACING_SESSION_MODE}:
        large_bet_fixture, large_bet_measurement = _river_large_bet_fixture_for(session_mode)
    r003_measurement = (
        r003_fixture_measurement() if session_mode == R003_NO_FACING_SESSION_MODE else None
    )
    r004_measurement = (
        r004_fixture_measurement() if session_mode == R004_NO_FACING_SESSION_MODE else None
    )
    response_rng = (
        random.Random(
            f"{session_id}:{large_bet_fixture.config.seed}:"
            f"{large_bet_measurement.reason_id.removeprefix('LEAK_').lower()}-opponent-response-v1"
        )
        if large_bet_fixture is not None and large_bet_measurement is not None
        else None
    )
    r003_response_rng = (
        random.Random(
            f"{session_id}:{R003_FIXTURE_PROFILE_SEED}:{R003_FIXTURE_RESPONSE_SAMPLER_VERSION}"
        )
        if r003_measurement is not None
        else None
    )
    r004_response_rng = (
        random.Random(
            f"{session_id}:{R003_FIXTURE_PROFILE_SEED}:{R004_FIXTURE_RESPONSE_SAMPLER_VERSION}"
        )
        if r004_measurement is not None
        else None
    )
    for index, scenario in enumerate(generate_scenarios(seed, num_hands)):
        hand_id = f"{session_id}-H{index:05d}"
        common = {
            "tracker": tracker,
            "leak_detector": detector,
            "safety_alpha": safety_alpha,
            "exploration_epsilon": exploration_epsilon,
            "exploit_provider": exploit_provider,
            "base_policy_provider": base_policy_provider,
        }
        if session_mode == R007_NO_FACING_SESSION_MODE:
            yield _build_r007_dpl(scenario, hand_id, session_id, **common)
        elif session_mode == R003_NO_FACING_SESSION_MODE:
            if r003_measurement is None or r003_response_rng is None:
                raise RuntimeError("R003 small-bet fixture environment was not initialized")
            yield _build_r003_dpl(
                scenario,
                hand_id,
                session_id,
                target_probability=float(r003_measurement.opponent_rate),
                response_rng=r003_response_rng,
                **common,
            )
        elif session_mode == R004_NO_FACING_SESSION_MODE:
            if r004_measurement is None or r004_response_rng is None:
                raise RuntimeError("R004 small-bet fixture environment was not initialized")
            yield _build_r004_dpl(
                scenario,
                hand_id,
                session_id,
                target_probability=float(r004_measurement.opponent_rate),
                response_rng=r004_response_rng,
                **common,
            )
        elif session_mode in {R001_NO_FACING_SESSION_MODE, R002_NO_FACING_SESSION_MODE}:
            if large_bet_fixture is None or large_bet_measurement is None or response_rng is None:
                raise RuntimeError("river-large-bet fixture environment was not initialized")
            yield _build_river_large_bet_dpl(
                scenario,
                hand_id,
                session_id,
                bet_fraction=large_bet_fixture.bet_fraction,
                target_action=large_bet_measurement.action,
                target_probability=float(large_bet_measurement.opponent_rate),
                response_rng=response_rng,
                **common,
            )
        else:
            yield _build_dpl(scenario, hand_id, session_id, **common)


def _config_ref(path: Path, *, name: str, role: str) -> ConfigRef:
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    return ConfigRef(name=name, role=role, path=path.name, sha256=sha)


def _opponent_ref_for(session_mode: SessionMode) -> OpponentRef:
    if session_mode == R001_NO_FACING_SESSION_MODE:
        from opponents.catalog import DEFAULT_CATALOG_ROOT

        fixture = load_r001_fixture_synthesis()
        config_path = (
            DEFAULT_CATALOG_ROOT
            / fixture.config.split
            / f"{fixture.config.opponent_id}.opponent.json"
        )
        return OpponentRef(
            opponent_id=fixture.config.opponent_id,
            opponent_version=fixture.config.opponent_version,
            split=fixture.config.split,
            config=_config_ref(config_path, name="r001_fixture_opponent", role="other"),
        )
    if session_mode == R002_NO_FACING_SESSION_MODE:
        fixture = load_r002_fixture_synthesis()
        config = fixture.config
        reason_id, delta = config.leak_vector[0]
        inline_path = (
            f"inline:noncatalog:{config.generator_version}:reason={reason_id}:delta={delta}:"
            f"equilibrium={config.equilibrium_version}:"
            f"artifact={config.equilibrium_artifact_sha256}:"
            f"position={config.opponent_position}:allocation={config.combo_allocation}:"
            f"lock_mode={config.lock_mode}:unlocked_policy_mode={config.unlocked_policy_mode}:"
            f"seed={config.seed}"
        )
        return OpponentRef(
            opponent_id=config.opponent_id,
            opponent_version=config.opponent_version,
            split=config.split,
            config=ConfigRef(
                name="r002_fixture_opponent",
                role="other",
                path=inline_path,
                sha256=config.config_sha256,
            ),
        )
    if session_mode == R003_NO_FACING_SESSION_MODE:
        inline_path, config_sha256 = r003_fixture_config_identity()
        return OpponentRef(
            opponent_id=R003_FIXTURE_OPPONENT_ID,
            opponent_version=OPPONENT_VERSION,
            split="training",
            config=ConfigRef(
                name="r003_fixture_opponent",
                role="other",
                path=inline_path,
                sha256=config_sha256,
            ),
        )
    if session_mode == R004_NO_FACING_SESSION_MODE:
        inline_path, config_sha256 = r004_fixture_config_identity()
        return OpponentRef(
            opponent_id=R004_FIXTURE_OPPONENT_ID,
            opponent_version=OPPONENT_VERSION,
            split="training",
            config=ConfigRef(
                name="r004_fixture_opponent",
                role="other",
                path=inline_path,
                sha256=config_sha256,
            ),
        )
    return OpponentRef(
        opponent_id=_opponent_id_for(session_mode),
        opponent_version=OPPONENT_VERSION,
        split="training",
    )


def _execution_sampler_config_ref(exploration_epsilon: float) -> ConfigRef:
    payload = {
        "sampler_version": EPSILON_SAMPLER_VERSION,
        "epsilon": exploration_epsilon,
        "epsilon_distribution": "legal_uniform",
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return ConfigRef(
        name="execution_sampler",
        role="other",
        path=f"inline:{EPSILON_SAMPLER_VERSION}:epsilon={exploration_epsilon:g}",
        sha256=hashlib.sha256(encoded).hexdigest(),
    )


def _artifact_ref(path: str) -> ArtifactRef:
    target = Path(path)
    sha = hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None
    return ArtifactRef(name=target.name, path=str(target), sha256=sha)


def build_manifest(
    seed: int,
    num_hands: int,
    *,
    git_commit: str = "unknown",
    git_dirty: bool | None = None,
    package_version: str | None = None,
    entrypoint: str = "poker_ai.session.run_session",
    argv: list[str] | None = None,
    output_paths: list[str] | None = None,
    leak_detector: LeakDetector | None = None,
    safety_alpha: float = 0.0,
    exploration_epsilon: float = 0.0,
    action_stats: tuple[ActionStats, ...] | list[ActionStats] = (),
    posterior_bundle: PosteriorBundleParts | None = None,
    solver_config: CfrRiverPolicyConfig = DEFAULT_CFR_RIVER_POLICY_CONFIG,
    session_mode: SessionMode = FACING_ALL_IN_SESSION_MODE,
    _base_policy_provider: BasePolicyProvider | None = None,
) -> RunManifest:
    """Build the RunManifest pinning versions, the seed and config hashes (M-7)."""
    detector = leak_detector or LeakDetector()
    bundle = posterior_bundle or build_posterior_bundle_parts(
        detector,
        action_stats,
        opponent_id=_opponent_id_for(session_mode),
        horizon=num_hands,
        seed=seed,
    )
    base_policy_provider = _base_policy_provider or _base_policy_provider_for(
        solver_config,
        session_mode,
    )
    versions = ComponentVersions(
        reason_ontology_version=get_ontology().ontology_version,
        cluster_def_version=cluster_def_version(),
        strategy_table_version=base_policy_provider.strategy_version,
        baseline_table_version=detector.baseline_table_version,
    )
    configs = [
        _config_ref(CLUSTER_DEF_PATH, name="state_cluster", role="cluster_def"),
        _config_ref(BUCKET_DEF_PATH, name="hand_bucket_def", role="other"),
        base_policy_provider.config_ref(),
        bundle.estimator_ref,
        bundle.baseline_ref,
        _execution_sampler_config_ref(exploration_epsilon),
    ]
    code = CodeProvenance(
        git_commit=git_commit,
        git_dirty=git_dirty,
        package_version=(resolve_package_version() if package_version is None else package_version),
        python_version=platform.python_version(),
        entrypoint=entrypoint,
        argv=list(argv or ()),
    )
    return RunManifest(
        run_id=_session_id_for(seed),
        description=(
            f"task-3 vertical slice; scenario_schema={SCENARIO_SCHEMA_VERSION}, "
            f"hand_bucket_def={bucket_def_version()}, hands={num_hands}, "
            f"base_strategy={base_policy_provider.strategy_version}, "
            f"base_strategy_source={base_policy_provider.source}, "
            f"safety_alpha={safety_alpha}, exploration_epsilon={exploration_epsilon}"
            + (
                f", session_mode={session_mode}"
                if session_mode != FACING_ALL_IN_SESSION_MODE
                else ""
            )
        ),
        code=code,
        versions=versions,
        seeds={"master": seed},
        configs=configs,
        opponents=[_opponent_ref_for(session_mode)],
        outputs=[bundle.snapshot_ref, *(_artifact_ref(path) for path in output_paths or [])],
    )


def run_session(
    seed: int,
    num_hands: int,
    *,
    git_commit: str = "unknown",
    git_dirty: bool | None = None,
    package_version: str | None = None,
    entrypoint: str = "poker_ai.session.run_session",
    argv: list[str] | None = None,
    leak_detector: LeakDetector | None = None,
    safety_alpha: float = 0.0,
    exploration_epsilon: float = 0.0,
    exploit_provider: ExploitProvider | None = None,
    solver_config: CfrRiverPolicyConfig = DEFAULT_CFR_RIVER_POLICY_CONFIG,
    session_mode: SessionMode = FACING_ALL_IN_SESSION_MODE,
    _base_policy_provider: BasePolicyProvider | None = None,
) -> SessionResult:
    """Run a full session in memory: validated DPLs plus the manifest."""
    detector = leak_detector or LeakDetector()
    tracker = ObservationTracker()
    base_policy_provider = _base_policy_provider or _base_policy_provider_for(
        solver_config,
        session_mode,
    )
    logs = list(
        iter_session_logs(
            seed,
            num_hands,
            leak_detector=detector,
            safety_alpha=safety_alpha,
            exploration_epsilon=exploration_epsilon,
            exploit_provider=exploit_provider,
            solver_config=solver_config,
            session_mode=session_mode,
            _tracker=tracker,
            _base_policy_provider=base_policy_provider,
        )
    )
    bundle = build_posterior_bundle_parts(
        detector,
        tracker.snapshot(),
        opponent_id=_opponent_id_for(session_mode),
        horizon=num_hands,
        seed=seed,
    )
    manifest = build_manifest(
        seed,
        num_hands,
        git_commit=git_commit,
        git_dirty=git_dirty,
        package_version=package_version,
        entrypoint=entrypoint,
        argv=argv,
        leak_detector=detector,
        safety_alpha=safety_alpha,
        exploration_epsilon=exploration_epsilon,
        action_stats=tracker.snapshot(),
        posterior_bundle=bundle,
        solver_config=solver_config,
        session_mode=session_mode,
        _base_policy_provider=base_policy_provider,
    )
    return SessionResult(_session_id_for(seed), logs, manifest, bundle)


def write_jsonl(
    logs: list[DecisionProvenanceLog],
    path: Path | str,
    *,
    manifest: RunManifest,
    bundle_root: Path | str,
) -> Path:
    """Write current posterior DPL JSONL after its contextual bundle hard gate passes."""
    validate_posterior_bundle(manifest, bundle_root)
    if any(log.schema_version != manifest.versions.dpl_schema_version for log in logs):
        raise ValueError("DPL log version does not match the posterior manifest")
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for log in logs:
            fh.write(json.dumps(log.model_dump(mode="json"), ensure_ascii=False) + "\n")
    return out


def write_manifest(manifest: RunManifest, path: Path | str) -> Path:
    """Write a posterior RunManifest after validating its sibling bundle."""
    out = Path(path)
    validate_posterior_bundle(manifest, out.parent)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(manifest.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return out


def write_session_bundle(
    result: SessionResult,
    out_dir: Path | str,
    *,
    dpl_filename: str | None = None,
    manifest_filename: str | None = None,
) -> tuple[Path, Path]:
    """Write canonical provenance, DPL JSONL, and manifest as one gated bundle."""
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    write_posterior_artifacts(result.posterior_bundle, root)
    validate_posterior_bundle(result.manifest, root)
    dpl_path = write_jsonl(
        result.logs,
        root / (dpl_filename or f"{result.session_id}.dpl.jsonl"),
        manifest=result.manifest,
        bundle_root=root,
    )
    manifest_path = write_manifest(
        result.manifest,
        root / (manifest_filename or f"{result.session_id}.manifest.json"),
    )
    return dpl_path, manifest_path
