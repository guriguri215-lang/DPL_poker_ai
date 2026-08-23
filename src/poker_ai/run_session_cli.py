"""Distributed CLI for a normal simulated Hero session.

The command writes validated DPL v3 JSONL plus a RunManifest sidecar and can
opt in to verified template-explanation artifacts. The default river path is
limited to facing an all-in; explicit R007, R001, and R002 fixtures select bounded OOP
``CHECK``/fixed-bet slices. Solver iterations and average delay are explicit
inputs; the 40-iteration default is not a convergence guarantee.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path

from poker_ai.cfr_policy import DEFAULT_CFR_RIVER_POLICY_CONFIG, CfrRiverPolicyConfig
from poker_ai.explanation_artifacts import (
    NORMAL_HERO_EXPLANATION_ARTIFACT_ID,
    ExplanationBundleVerificationError,
    SavedExplanationBundleVerificationError,
    load_next_session_settings,
    write_verified_explanation_bundle,
)
from poker_ai.exploit import NodelockExploitConfig, NodelockExploitProvider, RuleExploitProvider
from poker_ai.leak import (
    R001_FIXTURE_MIN_DEVIATION,
    R002_FIXTURE_MIN_DEVIATION,
    LeakDetector,
    LeakDetectorConfig,
    leaky_fixture_action_baseline_table,
    leaky_r001_fixture_action_baseline_table,
    leaky_r002_fixture_action_baseline_table,
    leaky_r007_fixture_action_baseline_table,
)
from poker_ai.opponent import reveal_stub_opponent_answer_key
from poker_ai.runtime_provenance import collect_runtime_provenance, resolve_package_version
from poker_ai.session import (
    FACING_ALL_IN_SESSION_MODE,
    R001_NO_FACING_SESSION_MODE,
    R002_NO_FACING_SESSION_MODE,
    R007_NO_FACING_SESSION_MODE,
    run_session,
    write_session_bundle,
)

CONSOLE_ENTRYPOINT = "poker-xai-run-session"
LEGACY_ENTRYPOINT = "cli/run_session.py"
MODULE_ENTRYPOINT = "python -m poker_ai.run_session_cli"


def _parser(*, entrypoint: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version",
        action="version",
        version=f"{entrypoint} {resolve_package_version()}",
        help="show the executing poker-xai distribution version and exit",
    )
    parser.add_argument(
        "--seed", type=int, default=20260704, help="master seed (default: 20260704)"
    )
    parser.add_argument("--hands", type=int, default=200, help="number of hands (default: 200)")
    parser.add_argument(
        "--safety-alpha",
        type=float,
        default=None,
        help=(
            "SafetyMixer alpha in [0, 1] (default: restored setting, otherwise "
            "0.0 or 1.0 with --leaky-fixture)"
        ),
    )
    parser.add_argument(
        "--exploration-epsilon",
        type=float,
        default=None,
        help=(
            "post-SafetyMixer epsilon exploration rate in [0, 1] "
            "(default: restored setting, otherwise 0.0)"
        ),
    )
    parser.add_argument(
        "--previous-session-manifest",
        type=Path,
        help=(
            "explicit prior RunManifest whose verified post-session artifact "
            "supplies this session's default detector, alpha, and epsilon"
        ),
    )
    parser.add_argument(
        "--solver-iterations",
        type=int,
        default=DEFAULT_CFR_RIVER_POLICY_CONFIG.iterations,
        help=(
            "deterministic CFR+ iterations per river decision "
            f"(default: {DEFAULT_CFR_RIVER_POLICY_CONFIG.iterations})"
        ),
    )
    parser.add_argument(
        "--solver-average-delay",
        type=int,
        default=DEFAULT_CFR_RIVER_POLICY_CONFIG.average_delay,
        help=(
            f"CFR+ linear-average delay (default: {DEFAULT_CFR_RIVER_POLICY_CONFIG.average_delay})"
        ),
    )
    parser.add_argument(
        "--leaky-fixture",
        action="store_true",
        help="use a public fixture baseline that produces leak/exploit smoke output",
    )
    parser.add_argument(
        "--leaky-fixture-reason",
        choices=("LEAK_R001", "LEAK_R002", "LEAK_R007", "LEAK_R008"),
        default="LEAK_R008",
        help=(
            "fixture reason to simulate with --leaky-fixture; LEAK_R008 preserves "
            "the historical jam-all path (default), LEAK_R007 opts in to the OOP "
            "CHECK/BET_33 check-back slice, LEAK_R001 opts in to the OOP "
            "CHECK/BET_75 overfold slice, and LEAK_R002 uses that same node "
            "for an overcall slice"
        ),
    )
    parser.add_argument(
        "--explanations",
        action="store_true",
        help=(
            "generate template explanations and independently verify every item "
            "before writing the expanded bundle"
        ),
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("experiments_output/task3_vertical_slice"),
        help="output directory (gitignored; default: experiments_output/task3_vertical_slice)",
    )
    return parser


def main(argv: list[str] | None = None, *, entrypoint: str = CONSOLE_ENTRYPOINT) -> int:
    """Run a normal Hero session and record the exact invocation provenance."""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = _parser(entrypoint=entrypoint)
    args = parser.parse_args(raw_argv)
    if args.leaky_fixture_reason != "LEAK_R008" and not args.leaky_fixture:
        parser.error(f"--leaky-fixture-reason {args.leaky_fixture_reason} requires --leaky-fixture")

    previous_settings = None
    if args.previous_session_manifest is not None:
        try:
            previous_settings = load_next_session_settings(args.previous_session_manifest)
        except SavedExplanationBundleVerificationError as exc:
            print(f"previous-session settings verification failed: {exc}", file=sys.stderr)
            return 1

    safety_alpha = (
        args.safety_alpha
        if args.safety_alpha is not None
        else (
            previous_settings.safety_alpha
            if previous_settings is not None
            else (1.0 if args.leaky_fixture else 0.0)
        )
    )
    exploration_epsilon = (
        args.exploration_epsilon
        if args.exploration_epsilon is not None
        else (previous_settings.epsilon if previous_settings is not None else 0.0)
    )
    leak_detector = None
    exploit_provider = None
    if args.leaky_fixture:
        detector_config = (
            previous_settings.leak_detector_config
            if previous_settings is not None
            else LeakDetectorConfig(
                min_effective_sample_size=1,
                min_deviation=0.25,
                min_confidence=0.5,
            )
        )
        if args.leaky_fixture_reason == "LEAK_R001":
            detector_config = replace(
                detector_config,
                min_deviation=R001_FIXTURE_MIN_DEVIATION,
            )
            fixture_baseline = leaky_r001_fixture_action_baseline_table()
        elif args.leaky_fixture_reason == "LEAK_R002":
            detector_config = replace(
                detector_config,
                min_deviation=R002_FIXTURE_MIN_DEVIATION,
            )
            fixture_baseline = leaky_r002_fixture_action_baseline_table()
        elif args.leaky_fixture_reason == "LEAK_R007":
            fixture_baseline = leaky_r007_fixture_action_baseline_table()
        else:
            fixture_baseline = leaky_fixture_action_baseline_table()
        leak_detector = LeakDetector(fixture_baseline, detector_config)
        exploit_provider = NodelockExploitProvider(
            NodelockExploitConfig(
                min_confidence=leak_detector.config.nodelock_exploit_min_confidence,
                iterations=args.solver_iterations,
                average_delay=args.solver_average_delay,
            ),
            fallback_provider=RuleExploitProvider(confidence_config=leak_detector.config),
            confidence_config=leak_detector.config,
        )
    elif previous_settings is not None:
        leak_detector = LeakDetector(config=previous_settings.leak_detector_config)

    provenance = collect_runtime_provenance()
    if args.leaky_fixture and args.leaky_fixture_reason == "LEAK_R001":
        session_mode = R001_NO_FACING_SESSION_MODE
    elif args.leaky_fixture and args.leaky_fixture_reason == "LEAK_R002":
        session_mode = R002_NO_FACING_SESSION_MODE
    elif args.leaky_fixture and args.leaky_fixture_reason == "LEAK_R007":
        session_mode = R007_NO_FACING_SESSION_MODE
    else:
        session_mode = FACING_ALL_IN_SESSION_MODE
    result = run_session(
        args.seed,
        args.hands,
        git_commit=provenance.git_commit,
        git_dirty=provenance.git_dirty,
        package_version=provenance.package_version,
        entrypoint=entrypoint,
        argv=raw_argv,
        leak_detector=leak_detector,
        safety_alpha=safety_alpha,
        exploration_epsilon=exploration_epsilon,
        exploit_provider=exploit_provider,
        session_mode=session_mode,
        solver_config=CfrRiverPolicyConfig(
            iterations=args.solver_iterations,
            average_delay=args.solver_average_delay,
            checkpoints=(),
        ),
    )
    explanation_paths = None
    if args.explanations:
        # The environment reveals this only after run_session has completed every
        # Hero decision. It is passed to post-session evaluation, never to Hero.
        answer_key = reveal_stub_opponent_answer_key(
            opponent_model_id=result.manifest.opponents[0].opponent_id
        )
        try:
            explanation_paths = write_verified_explanation_bundle(
                result,
                args.out_dir,
                artifact_id=NORMAL_HERO_EXPLANATION_ARTIFACT_ID,
                safety_alpha=safety_alpha,
                leaky_fixture=args.leaky_fixture,
                answer_key=answer_key,
            )
        except ExplanationBundleVerificationError as exc:
            print(f"explanation verification failed: {exc}", file=sys.stderr)
            return 1
        jsonl_path = explanation_paths.dpl
        manifest_path = explanation_paths.manifest
    else:
        jsonl_path, manifest_path = write_session_bundle(result, args.out_dir)

    detected_leaks = sum(len(log.detected_leaks) for log in result.logs)
    mixed_decisions = sum(1 for log in result.logs if log.mix_reasons)
    print(f"session {result.session_id}: {len(result.logs)} decisions validated against DPL v3")
    print(f"detected_leaks={detected_leaks}")
    print(f"mixed_decisions={mixed_decisions}")
    print(f"wrote {jsonl_path}")
    if explanation_paths is not None:
        print(f"explanations_verified={len(result.logs)}")
        print(f"wrote {explanation_paths.explanations}")
        print(f"wrote {explanation_paths.verifier_summary}")
        print(f"wrote {explanation_paths.post_session_evaluation}")
    print(f"wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(entrypoint=MODULE_ENTRYPOINT))
