"""Vertical-slice session runner: scenarios -> decisions -> validated DPL + manifest.

Ties task 3 together (ADR-0007): generate scenarios deterministically, have the stub
opponent act, let Hero decide on the *public* observation, and assemble each decision
into a frozen :class:`~poker_core.dpl_schema.DecisionProvenanceLog`. Phase 2 now also
records action-only public observations and runs a minimal leak detector. The default
stub baseline matches the stub opponent, so the normal CLI run remains leak-free, but
positive fixtures can inject a stricter baseline and produce DPL ``DetectedLeak``
records without reading hidden strategy. The Hero still runs at ``safety_alpha = 0``:
``exploit_policy == base_policy`` and every EV is exact ``solver_exact``. A
:class:`~poker_core.run_manifest.RunManifest` pins the versions, seed and config
hashes so the run is reproducible (M-7).

The DPLs are written as JSONL (one decision per line); the manifest is written as a
sidecar JSON. Both live under a gitignored output directory.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from poker_core.dpl_schema import DecisionProvenanceLog, EvEstimate
from poker_core.range_model import Range
from poker_core.reason_ontology import get_ontology
from poker_core.run_manifest import (
    CodeProvenance,
    ComponentVersions,
    ConfigRef,
    OpponentRef,
    RunManifest,
)
from poker_core.state_cluster import CLUSTER_DEF_PATH, cluster_def_version

from .baseline_strategy import (
    BASELINE_PATH,
    baseline_table_version,
    get_baseline_strategy,
)
from .decision import NO_EXPLOIT_SOURCE, HeroAgent, Observation
from .hand_bucket import BUCKET_DEF_PATH, bucket_def_version, get_bucket_definition
from .leak import LeakDetector
from .observation import ObservationTracker
from .opponent import StubOpponent
from .scenario import SCENARIO_SCHEMA_VERSION, Scenario, generate_scenarios

#: EV source for every task-3 DPL: exact showdown enumeration (ADR-0008).
EV_SOURCE = "solver_exact"

#: Fixed identity of the single stub opponent (ADR-0007).
OPPONENT_ID = "stub_jam_all"
OPPONENT_VERSION = "0.1.0"


@dataclass(frozen=True)
class SessionResult:
    """The validated DPLs and the reproducibility manifest for one session."""

    session_id: str
    logs: list[DecisionProvenanceLog]
    manifest: RunManifest


def _session_id_for(seed: int) -> str:
    return f"S{seed:08d}"


def _build_dpl(
    scenario: Scenario,
    hand_id: str,
    session_id: str,
    *,
    tracker: ObservationTracker,
    leak_detector: LeakDetector,
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
    agent = HeroAgent(get_baseline_strategy(), get_bucket_definition())
    result = agent.decide(observation)
    tracker.record_opponent_action(
        situation_key=result.situation_key,
        action=opponent_action.action,
    )
    detected_leaks = leak_detector.detect_for_situation(
        tracker.snapshot(),
        result.situation_key,
    )
    allowed_reason_ids = list(dict.fromkeys(leak.reason_id for leak in detected_leaks))

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
        state_cluster=result.state_cluster,
        cluster_def_version=result.cluster_def_version,
        hand_bucket=result.hand_bucket,
        hero_combo=scenario.hero_combo,
        base_policy=result.base_policy,
        detected_leaks=detected_leaks,
        trigger_reasons=[],
        mix_reasons=[],
        exploit_policy=result.exploit_policy,
        exploit_source=NO_EXPLOIT_SOURCE,
        solver_result_id=None,
        safety_alpha=0.0,
        final_policy=result.final_policy,
        selected_action=result.selected_action,
        sampling_seed=result.sampling_seed,
        ev_estimate=ev,
        allowed_reason_ids=allowed_reason_ids,
        baseline_table_version=leak_detector.baseline_table_version,
    )


def iter_session_logs(
    seed: int,
    num_hands: int,
    *,
    leak_detector: LeakDetector | None = None,
) -> Iterator[DecisionProvenanceLog]:
    """Yield one validated DPL per generated hand (deterministic for a seed)."""
    session_id = _session_id_for(seed)
    tracker = ObservationTracker()
    detector = leak_detector or LeakDetector()
    for index, scenario in enumerate(generate_scenarios(seed, num_hands)):
        hand_id = f"{session_id}-H{index:05d}"
        yield _build_dpl(
            scenario,
            hand_id,
            session_id,
            tracker=tracker,
            leak_detector=detector,
        )


def _config_ref(path: Path, *, name: str, role: str) -> ConfigRef:
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    return ConfigRef(name=name, role=role, path=path.name, sha256=sha)


def build_manifest(
    seed: int,
    num_hands: int,
    *,
    git_commit: str = "unknown",
    output_paths: list[str] | None = None,
    leak_detector: LeakDetector | None = None,
) -> RunManifest:
    """Build the RunManifest pinning versions, the seed and config hashes (M-7)."""
    detector = leak_detector or LeakDetector()
    versions = ComponentVersions(
        reason_ontology_version=get_ontology().ontology_version,
        cluster_def_version=cluster_def_version(),
        strategy_table_version=baseline_table_version(),
        baseline_table_version=detector.baseline_table_version,
    )
    configs = [
        _config_ref(CLUSTER_DEF_PATH, name="state_cluster", role="cluster_def"),
        _config_ref(BUCKET_DEF_PATH, name="hand_bucket_def", role="other"),
        _config_ref(BASELINE_PATH, name="baseline_strategy", role="baseline_table"),
    ]
    code = CodeProvenance(
        git_commit=git_commit,
        package_version="0.0.0",
        python_version=platform.python_version(),
        entrypoint="cli/run_session.py",
        argv=list(sys.argv[1:]),
    )
    return RunManifest(
        run_id=_session_id_for(seed),
        description=(
            f"task-3 vertical slice; scenario_schema={SCENARIO_SCHEMA_VERSION}, "
            f"hand_bucket_def={bucket_def_version()}, hands={num_hands}"
        ),
        code=code,
        versions=versions,
        seeds={"master": seed},
        configs=configs,
        opponents=[
            OpponentRef(
                opponent_id=OPPONENT_ID,
                opponent_version=OPPONENT_VERSION,
                split="training",
            )
        ],
    )


def run_session(
    seed: int,
    num_hands: int,
    *,
    git_commit: str = "unknown",
    leak_detector: LeakDetector | None = None,
) -> SessionResult:
    """Run a full session in memory: validated DPLs plus the manifest."""
    detector = leak_detector or LeakDetector()
    logs = list(iter_session_logs(seed, num_hands, leak_detector=detector))
    manifest = build_manifest(seed, num_hands, git_commit=git_commit, leak_detector=detector)
    return SessionResult(_session_id_for(seed), logs, manifest)


def write_jsonl(logs: list[DecisionProvenanceLog], path: Path | str) -> Path:
    """Write DPLs as JSONL (one decision per line) and return the path."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for log in logs:
            fh.write(json.dumps(log.model_dump(mode="json"), ensure_ascii=False) + "\n")
    return out


def write_manifest(manifest: RunManifest, path: Path | str) -> Path:
    """Write the RunManifest as JSON and return the path."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(manifest.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return out
