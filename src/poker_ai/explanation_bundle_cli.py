"""Read-only verification of a saved normal Hero explanation bundle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .explanation_artifacts import (
    SavedExplanationBundleVerificationError,
    _verify_saved_explanation_bundle_contents,
    verify_saved_explanation_bundle,
)
from .post_session_evaluation import PostSessionArtifact
from .runtime_provenance import resolve_package_version

CONSOLE_ENTRYPOINT = "poker-xai-verify-explanation-bundle"


def _parser(*, entrypoint: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version",
        action="version",
        version=f"{entrypoint} {resolve_package_version()}",
        help="show the executing poker-xai distribution version and exit",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="saved normal Hero RunManifest to verify without modifying its bundle",
    )
    parser.add_argument(
        "--show-evaluation",
        action="store_true",
        help="show verified post-session metrics and next-session settings",
    )
    return parser


def _json_value(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    )


def _post_session_lines(post_session: PostSessionArtifact) -> list[str]:
    evaluation = post_session.evaluation
    settings = post_session.next_session_settings
    detector = settings.leak_detector_config
    values = (
        ("evaluation.leak_detection_accuracy", evaluation.leak_detection_accuracy),
        ("evaluation.average_estimation_error", evaluation.average_estimation_error),
        ("evaluation.exploit_ev_gain_vs_base", evaluation.exploit_ev_gain_vs_base),
        ("evaluation.over_adjustment_count", evaluation.over_adjustment_count),
        ("evaluation.under_adjustment_count", evaluation.under_adjustment_count),
        ("evaluation.explanation_validity_score", evaluation.explanation_validity_score),
        ("next_session.leak_detector_config.method_version", detector.method_version),
        ("next_session.leak_detector_config.alpha0", detector.alpha0),
        ("next_session.leak_detector_config.beta0", detector.beta0),
        ("next_session.leak_detector_config.tail", detector.tail),
        (
            "next_session.leak_detector_config.min_effective_sample_size",
            detector.min_effective_sample_size,
        ),
        ("next_session.leak_detector_config.min_deviation", detector.min_deviation),
        ("next_session.leak_detector_config.min_confidence", detector.min_confidence),
        (
            "next_session.leak_detector_config.rule_exploit_min_confidence",
            detector.rule_exploit_min_confidence,
        ),
        (
            "next_session.leak_detector_config.nodelock_exploit_min_confidence",
            detector.nodelock_exploit_min_confidence,
        ),
        ("next_session.safety_alpha", settings.safety_alpha),
        ("next_session.epsilon", settings.epsilon),
    )
    return [f"{key}={_json_value(value)}" for key, value in values]


def main(argv: list[str] | None = None, *, entrypoint: str = CONSOLE_ENTRYPOINT) -> int:
    """Verify only the saved bundle identified by ``--manifest``."""

    args = _parser(entrypoint=entrypoint).parse_args(list(sys.argv[1:] if argv is None else argv))
    post_session = None
    try:
        if args.show_evaluation:
            result, post_session = _verify_saved_explanation_bundle_contents(
                args.manifest,
                require_post_session=True,
            )
        else:
            result = verify_saved_explanation_bundle(args.manifest)
    except SavedExplanationBundleVerificationError as exc:
        print(f"explanation bundle verification failed: {exc}", file=sys.stderr)
        return 1

    lines = [
        f"artifact_integrity=passed references={result.artifact_count}",
        f"explanation_checker=passed total={result.checker_total} summary=consistent",
    ]
    if post_session is not None:
        lines.extend(_post_session_lines(post_session))
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
