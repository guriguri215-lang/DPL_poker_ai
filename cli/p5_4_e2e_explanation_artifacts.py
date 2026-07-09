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
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from explanation import (
    EXPLANATION_SCHEMA_VERSION,
    TEMPLATE_GENERATOR,
    TEMPLATE_GENERATOR_VERSION,
    ExplanationDocument,
    generate_template_explanation,
    verify_explanation,
)
from poker_ai.decision import Observation
from poker_ai.exploit import RuleExploitResult
from poker_ai.leak import (
    LeakDetector,
    LeakDetectorConfig,
    leaky_fixture_action_baseline_table,
)
from poker_ai.session import build_manifest, run_session, write_jsonl, write_manifest
from poker_core.dpl_schema import DecisionProvenanceLog, DetectedLeak
from poker_core.run_manifest import ArtifactRef

ARTIFACT_ID = "p5_4_e2e_explanation_artifacts"
ENTRYPOINT = "cli/p5_4_e2e_explanation_artifacts.py"
DEFAULT_SEED = 20260709
DEFAULT_HANDS = 5
DEFAULT_OUTPUT_DIR = Path("experiments_output/p5_4_e2e_explanation_artifacts")


class _LeakyFixtureExploitProvider:
    """Force a CALL exploit when the public leaky fixture detects R008."""

    def build(
        self,
        *,
        base_policy: dict[str, float],
        detected_leaks: tuple[DetectedLeak, ...] | list[DetectedLeak],
        legal_actions: tuple[str, ...],
        action_ev: dict[str, float],
        observation: Observation | None = None,
    ) -> RuleExploitResult:
        del action_ev, observation
        if "CALL" in legal_actions and any(
            leak.reason_id == "LEAK_R008" for leak in detected_leaks
        ):
            return RuleExploitResult(
                policy={"CALL": 1.0},
                applied_leak_reason_ids=("LEAK_R008",),
                trigger_reasons=("TRG_R001", "TRG_R002"),
            )
        return RuleExploitResult(policy=dict(base_policy))


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


def _write_explanations_jsonl(explanations: list[ExplanationDocument], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for explanation in explanations:
            payload = explanation.model_dump(mode="json")
            fh.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    return path


def _verify_all(
    logs: list[DecisionProvenanceLog],
    explanations: list[ExplanationDocument],
) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    for log, explanation in zip(logs, explanations, strict=True):
        result = verify_explanation(explanation, log)
        if result.passed:
            continue
        failures.append(
            {
                "dpl_ref": f"{log.session_id}:{log.hand_id}",
                "issues": [
                    {
                        "code": issue.code,
                        "location": issue.location,
                        "message": issue.message,
                    }
                    for issue in result.issues
                ],
            }
        )
    return failures


def _relative_path(repo_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root).as_posix()
    except ValueError:
        return str(path)


def _artifact_ref(repo_root: Path, path: Path) -> ArtifactRef:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return ArtifactRef(
        name=path.name,
        path=_relative_path(repo_root, path),
        sha256=digest,
    )


def _summary_payload(
    *,
    repo_root: Path,
    logs: list[DecisionProvenanceLog],
    explanations: list[ExplanationDocument],
    failures: list[dict[str, Any]],
    seed: int,
    safety_alpha: float,
    git_commit: str,
    git_dirty: bool,
    dpl_path: Path,
    explanations_path: Path,
    summary_path: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    total = len(explanations)
    failed = len(failures)
    passed = total - failed
    return {
        "metadata": {
            "artifact_id": ARTIFACT_ID,
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "git_commit": git_commit,
            "git_dirty": git_dirty,
            "seed": seed,
            "hands": len(logs),
            "safety_alpha": safety_alpha,
            "leaky_fixture": True,
        },
        "versions": {
            "dpl_schema_version": logs[0].schema_version if logs else None,
            "explanation_schema_version": EXPLANATION_SCHEMA_VERSION,
            "generator": TEMPLATE_GENERATOR,
            "generator_version": TEMPLATE_GENERATOR_VERSION,
            "baseline_table_version": logs[0].baseline_table_version if logs else None,
        },
        "session": {
            "session_id": logs[0].session_id if logs else None,
            "dpl_count": len(logs),
            "explanation_count": total,
            "detected_leaks": sum(len(log.detected_leaks) for log in logs),
            "mixed_decisions": sum(1 for log in logs if log.mix_reasons),
        },
        "verification": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": passed / total if total else 0.0,
            "failures": failures,
        },
        "artifacts": {
            "dpl_jsonl": _relative_path(repo_root, dpl_path),
            "explanations_jsonl": _relative_path(repo_root, explanations_path),
            "verifier_summary_json": _relative_path(repo_root, summary_path),
            "manifest_json": _relative_path(repo_root, manifest_path),
        },
    }


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
    git_commit = _current_git_commit(repo_root)
    git_dirty = _git_dirty(repo_root)
    session = run_session(
        args.seed,
        args.hands,
        git_commit=git_commit,
        leak_detector=detector,
        safety_alpha=args.safety_alpha,
        exploit_provider=_LeakyFixtureExploitProvider(),
    )
    explanations = [generate_template_explanation(log) for log in session.logs]

    args.out_dir.mkdir(parents=True, exist_ok=True)
    dpl_path = args.out_dir / f"{session.session_id}.dpl.jsonl"
    explanations_path = args.out_dir / f"{session.session_id}.explanations.jsonl"
    summary_path = args.out_dir / f"{session.session_id}.verifier_summary.json"
    manifest_path = args.out_dir / f"{session.session_id}.manifest.json"

    write_jsonl(session.logs, dpl_path)
    _write_explanations_jsonl(explanations, explanations_path)

    failures = _verify_all(session.logs, explanations)
    summary = _summary_payload(
        repo_root=repo_root,
        logs=session.logs,
        explanations=explanations,
        failures=failures,
        seed=args.seed,
        safety_alpha=args.safety_alpha,
        git_commit=git_commit,
        git_dirty=git_dirty,
        dpl_path=dpl_path,
        explanations_path=explanations_path,
        summary_path=summary_path,
        manifest_path=manifest_path,
    )
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    manifest = build_manifest(
        args.seed,
        args.hands,
        git_commit=git_commit,
        git_dirty=git_dirty,
        entrypoint=ENTRYPOINT,
        argv=raw_argv,
        leak_detector=detector,
        safety_alpha=args.safety_alpha,
    )
    manifest.outputs = [
        _artifact_ref(repo_root, dpl_path),
        _artifact_ref(repo_root, explanations_path),
        _artifact_ref(repo_root, summary_path),
    ]
    write_manifest(manifest, manifest_path)

    verification = summary["verification"]
    print(
        f"session {session.session_id}: "
        f"{verification['passed']}/{verification['total']} explanations verified"
    )
    print(f"pass_rate={verification['pass_rate']:.3f}")
    print(f"wrote {dpl_path}")
    print(f"wrote {explanations_path}")
    print(f"wrote {summary_path}")
    print(f"wrote {manifest_path}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
