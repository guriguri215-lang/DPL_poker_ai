"""Write P5-4 E2E leaky-fixture explanation verification artifacts.

Usage::

    python cli/p5_4_e2e_explanation_artifacts.py

The output is intentionally written under ``experiments_output/``. That tree is
gitignored, but it is kept in the workspace as the primary Phase 5 evidence that
the leaky-fixture session DPLs can be rendered as template explanations and pass
the independent verifier at 100%.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from poker_ai.cfr_policy import DEFAULT_CFR_RIVER_POLICY_CONFIG
from poker_ai.explanation_artifacts import (
    ExplanationBundleVerificationError,
    write_verified_explanation_bundle,
)
from poker_ai.exploit import (
    NodelockExploitConfig,
    NodelockExploitProvider,
    RuleExploitProvider,
)
from poker_ai.leak import (
    LeakDetector,
    LeakDetectorConfig,
    leaky_fixture_action_baseline_table,
)
from poker_ai.session import run_session

ARTIFACT_ID = "p5_4_e2e_explanation_artifacts"
ENTRYPOINT = "cli/p5_4_e2e_explanation_artifacts.py"
DEFAULT_SEED = 20260709
DEFAULT_HANDS = 5
DEFAULT_OUTPUT_DIR = Path("experiments_output/p5_4_e2e_explanation_artifacts")


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _leaky_fixture_detector() -> LeakDetector:
    return LeakDetector(
        leaky_fixture_action_baseline_table(),
        LeakDetectorConfig(
            min_effective_sample_size=1,
            min_deviation=0.25,
            min_confidence=0.5,
        ),
    )


def _current_git_commit(repo_root: Path) -> str:
    try:
        out = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={repo_root.as_posix()}",
                "rev-parse",
                "HEAD",
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return "unknown"
    commit = out.stdout.strip()
    return commit if commit else "unknown"


def _git_dirty(repo_root: Path) -> bool:
    try:
        out = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={repo_root.as_posix()}",
                "status",
                "--porcelain",
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return True
    return bool(out.stdout.strip())


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help=f"master seed (default: {DEFAULT_SEED})",
    )
    parser.add_argument(
        "--hands",
        type=_positive_int,
        default=DEFAULT_HANDS,
        help=f"number of fixture hands (default: {DEFAULT_HANDS})",
    )
    parser.add_argument(
        "--safety-alpha",
        type=float,
        default=1.0,
        help="SafetyMixer alpha in [0, 1] (default: 1.0)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=repo_root / DEFAULT_OUTPUT_DIR,
        help=f"output directory (default: {DEFAULT_OUTPUT_DIR.as_posix()})",
    )
    args = parser.parse_args(raw_argv)

    detector = _leaky_fixture_detector()
    exploit_provider = NodelockExploitProvider(
        NodelockExploitConfig(
            min_confidence=detector.config.nodelock_exploit_min_confidence,
            iterations=DEFAULT_CFR_RIVER_POLICY_CONFIG.iterations,
            average_delay=DEFAULT_CFR_RIVER_POLICY_CONFIG.average_delay,
        ),
        fallback_provider=RuleExploitProvider(confidence_config=detector.config),
        confidence_config=detector.config,
    )
    git_commit = _current_git_commit(repo_root)
    git_dirty = _git_dirty(repo_root)
    session = run_session(
        args.seed,
        args.hands,
        git_commit=git_commit,
        git_dirty=git_dirty,
        entrypoint=ENTRYPOINT,
        argv=raw_argv,
        leak_detector=detector,
        safety_alpha=args.safety_alpha,
        exploit_provider=exploit_provider,
        solver_config=DEFAULT_CFR_RIVER_POLICY_CONFIG,
    )

    try:
        args.out_dir.resolve().relative_to(repo_root.resolve())
        reference_root = repo_root
    except ValueError:
        reference_root = args.out_dir
    try:
        paths = write_verified_explanation_bundle(
            session,
            args.out_dir,
            artifact_id=ARTIFACT_ID,
            safety_alpha=args.safety_alpha,
            leaky_fixture=True,
            reference_root=reference_root,
        )
    except ExplanationBundleVerificationError as exc:
        print(f"explanation verification failed: {exc}", file=sys.stderr)
        return 1

    total = len(session.logs)
    print(f"session {session.session_id}: {total}/{total} explanations verified")
    print(f"pass_rate={1.0 if total else 0.0:.3f}")
    print(f"wrote {paths.dpl}")
    print(f"wrote {paths.explanations}")
    print(f"wrote {paths.verifier_summary}")
    print(f"wrote {paths.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
