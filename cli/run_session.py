"""CLI: run the Phase-2 river MVP session and write DPL JSONL + a manifest.

Usage::

    python cli/run_session.py --seed 20260704 --hands 200 --out-dir experiments_output/demo

Generates ``--hands`` river decisions deterministically from ``--seed``, validates
each against the frozen DPL schema, includes action-only public leak detection,
optional rule-based exploitation behind the SafetyMixer, writes them as JSONL, and
writes a RunManifest sidecar. Output goes under a gitignored directory
(``experiments_output/`` by default). Requires
``pip install -e .``.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from poker_ai.exploit import RuleExploitResult
from poker_ai.leak import (
    LeakDetector,
    LeakDetectorConfig,
    leaky_fixture_action_baseline_table,
)
from poker_ai.session import run_session, write_jsonl, write_manifest


def _current_git_commit() -> str:
    """The repo HEAD commit, or the ``"unknown"`` sentinel when unavailable."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return "unknown"
    commit = out.stdout.strip()
    return commit if commit else "unknown"


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
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
        "--leaky-fixture",
        action="store_true",
        help="use a public fixture baseline that produces leak/exploit smoke output",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("experiments_output/task3_vertical_slice"),
        help="output directory (gitignored; default: experiments_output/task3_vertical_slice)",
    )
    args = parser.parse_args(argv)

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

    result = run_session(
        args.seed,
        args.hands,
        git_commit=_current_git_commit(),
        leak_detector=leak_detector,
        safety_alpha=safety_alpha,
        exploration_epsilon=args.exploration_epsilon,
        exploit_provider=exploit_provider,
    )
    jsonl_path = write_jsonl(result.logs, args.out_dir / f"{result.session_id}.dpl.jsonl")
    manifest_path = write_manifest(
        result.manifest, args.out_dir / f"{result.session_id}.manifest.json"
    )

    detected_leaks = sum(len(log.detected_leaks) for log in result.logs)
    mixed_decisions = sum(1 for log in result.logs if log.mix_reasons)
    print(f"session {result.session_id}: {len(result.logs)} decisions validated against DPL v1")
    print(f"detected_leaks={detected_leaks}")
    print(f"mixed_decisions={mixed_decisions}")
    print(f"wrote {jsonl_path}")
    print(f"wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
