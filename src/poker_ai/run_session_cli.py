"""Distributed CLI for a normal simulated Hero session.

The command writes validated DPL v3 JSONL plus a RunManifest sidecar and can
opt in to verified template-explanation artifacts.  The river adapter remains
limited to facing an all-in.  Solver iterations and average delay are explicit
inputs; the 40-iteration default is not a convergence guarantee.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from poker_ai.cfr_policy import DEFAULT_CFR_RIVER_POLICY_CONFIG, CfrRiverPolicyConfig
from poker_ai.explanation_artifacts import (
    NORMAL_HERO_EXPLANATION_ARTIFACT_ID,
    ExplanationBundleVerificationError,
    write_verified_explanation_bundle,
)
from poker_ai.exploit import RuleExploitResult
from poker_ai.leak import (
    LeakDetector,
    LeakDetectorConfig,
    leaky_fixture_action_baseline_table,
)
from poker_ai.runtime_provenance import collect_runtime_provenance, resolve_package_version
from poker_ai.session import run_session, write_session_bundle

CONSOLE_ENTRYPOINT = "poker-xai-run-session"
LEGACY_ENTRYPOINT = "cli/run_session.py"
MODULE_ENTRYPOINT = "python -m poker_ai.run_session_cli"


class _LeakyFixtureExploitProvider:
    """CLI smoke helper: force a CALL exploit when the public fixture detects R008."""

    def build(self, **kwargs: object) -> RuleExploitResult:
        base_policy = kwargs["base_policy"]
        detected_leaks = kwargs["detected_leaks"]
        legal_actions = kwargs["legal_actions"]
        if (
            isinstance(base_policy, dict)
            and "CALL" in legal_actions
            and any(leak.reason_id == "LEAK_R008" for leak in detected_leaks)
        ):
            return RuleExploitResult(
                policy={"CALL": 1.0},
                applied_leak_reason_ids=("LEAK_R008",),
                trigger_reasons=("TRG_R001", "TRG_R002"),
            )
        return RuleExploitResult(policy=dict(base_policy))


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
        help="SafetyMixer alpha in [0, 1] (default: 0.0, or 1.0 with --leaky-fixture)",
    )
    parser.add_argument(
        "--exploration-epsilon",
        type=float,
        default=0.0,
        help="post-SafetyMixer epsilon exploration rate in [0, 1] (default: 0.0)",
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
    args = _parser(entrypoint=entrypoint).parse_args(raw_argv)

    safety_alpha = (
        args.safety_alpha if args.safety_alpha is not None else (1.0 if args.leaky_fixture else 0.0)
    )
    leak_detector = None
    exploit_provider = None
    if args.leaky_fixture:
        leak_detector = LeakDetector(
            leaky_fixture_action_baseline_table(),
            LeakDetectorConfig(
                min_effective_sample_size=1,
                min_deviation=0.25,
                min_confidence=0.5,
            ),
        )
        exploit_provider = _LeakyFixtureExploitProvider()

    provenance = collect_runtime_provenance()
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
        exploration_epsilon=args.exploration_epsilon,
        exploit_provider=exploit_provider,
        solver_config=CfrRiverPolicyConfig(
            iterations=args.solver_iterations,
            average_delay=args.solver_average_delay,
            checkpoints=(),
        ),
    )
    explanation_paths = None
    if args.explanations:
        try:
            explanation_paths = write_verified_explanation_bundle(
                result,
                args.out_dir,
                artifact_id=NORMAL_HERO_EXPLANATION_ARTIFACT_ID,
                safety_alpha=safety_alpha,
                leaky_fixture=args.leaky_fixture,
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
    print(f"wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(entrypoint=MODULE_ENTRYPOINT))
