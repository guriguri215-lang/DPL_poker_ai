"""Deterministic post-session answer-key evaluation for normal Hero sessions.

The Poker AI Specification fixes the evaluation fields and the post-session
hidden-answer boundary, but it does not prescribe metric aggregation or numeric
update steps.  This initial MVP therefore records its conservative assumptions
in every artifact and uses only existing detector thresholds, SafetyMixer alpha,
and execution epsilon.  It never increases automatic exploitation.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from explanation import ExplanationDocument, VerificationResult
from poker_core.dpl_schema import EXPLANATION_SAFE_EV_SOURCE, DecisionProvenanceLog
from poker_core.run_manifest import RunManifest

from .leak import LeakDetectorConfig, classify_ground_truth_boundary
from .mixer import EPSILON_SAMPLER_VERSION
from .opponent import OpponentAnswerKey
from .posterior_bundle import (
    ESTIMATOR_CONFIG_NAME,
    ESTIMATOR_CONFIG_PATH,
    SNAPSHOT_ARTIFACT_NAME,
    SNAPSHOT_ARTIFACT_PATH,
    PosteriorBundleParts,
    canonical_json_bytes,
    sha256_bytes,
)

POST_SESSION_EVALUATION_SCHEMA_VERSION = "1.0.0"
POST_SESSION_EVALUATION_ARTIFACT_TYPE = "post_session_answer_key_evaluation"
POST_SESSION_EVALUATION_SUFFIX = ".post_session_evaluation.json"

_ASSUMPTION_NOTES = (
    "mvp_assumption:accuracy uses reached structurally eligible non-boundary candidates",
    (
        "mvp_assumption:average estimation error is the unweighted mean absolute "
        "action-rate error over reached candidates"
    ),
    ("mvp_assumption:exploit EV gain is the mean exact final-minus-base EV per decision"),
    (
        "mvp_assumption:over-adjustment means exact final EV below base EV; "
        "under-adjustment means exact exploit EV above final EV"
    ),
    (
        "mvp_assumption:explanation validity requires the existing verifier and "
        "truth-positive cited LEAK reasons"
    ),
    (
        "mvp_update_rule:false positives, negative mean EV gain, or over-adjustment "
        "set existing confidence gates to 1 and alpha/epsilon to 0; false negatives "
        "and under-adjustment hold settings"
    ),
)


@dataclass(frozen=True)
class PostSessionEvaluation:
    """The Phase 8 evaluation fields fixed by the Poker AI Specification."""

    session_id: str
    opponent_model_id: str
    leak_detection_accuracy: float
    average_estimation_error: float
    exploit_ev_gain_vs_base: float
    over_adjustment_count: int
    under_adjustment_count: int
    explanation_validity_score: float
    notes: tuple[str, ...]

    def to_payload(self) -> dict[str, object]:
        """Return the JSON representation with the specification's field names."""

        return {
            "session_id": self.session_id,
            "opponent_model_id": self.opponent_model_id,
            "leak_detection_accuracy": self.leak_detection_accuracy,
            "average_estimation_error": self.average_estimation_error,
            "exploit_ev_gain_vs_base": self.exploit_ev_gain_vs_base,
            "over_adjustment_count": self.over_adjustment_count,
            "under_adjustment_count": self.under_adjustment_count,
            "explanation_validity_score": self.explanation_validity_score,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class NextSessionSettings:
    """Existing settings proposed for the next session; no new tuning knob."""

    leak_detector_config: LeakDetectorConfig
    safety_alpha: float
    epsilon: float

    def to_payload(self) -> dict[str, object]:
        """Return fields that directly reconstruct the existing configuration."""

        config = self.leak_detector_config
        return {
            "leak_detector_config": {
                "method_version": config.method_version,
                "alpha0": config.alpha0,
                "beta0": config.beta0,
                "tail": config.tail,
                "min_effective_sample_size": config.min_effective_sample_size,
                "min_deviation": config.min_deviation,
                "min_confidence": config.min_confidence,
                "rule_exploit_min_confidence": config.rule_exploit_min_confidence,
                "nodelock_exploit_min_confidence": config.nodelock_exploit_min_confidence,
            },
            "safety_alpha": self.safety_alpha,
            "epsilon": self.epsilon,
        }


@dataclass(frozen=True)
class PostSessionArtifact:
    """One versioned evaluation plus its conservative next-session settings."""

    evaluation: PostSessionEvaluation
    next_session_settings: NextSessionSettings

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": POST_SESSION_EVALUATION_SCHEMA_VERSION,
            "artifact_type": POST_SESSION_EVALUATION_ARTIFACT_TYPE,
            "evaluation": self.evaluation.to_payload(),
            "next_session_settings": self.next_session_settings.to_payload(),
        }

    def canonical_bytes(self) -> bytes:
        """Return deterministic JSON bytes with no timestamp or local path."""

        return canonical_json_bytes(self.to_payload())


@dataclass(frozen=True)
class _CandidateMetrics:
    accuracy: float
    average_estimation_error: float
    false_positive_count: int
    false_negative_count: int
    truth_positive_by_reason_and_situation: Mapping[tuple[str, str], bool]


def post_session_evaluation_filename(session_id: str) -> str:
    """Return the single normal-Hero Phase 8 artifact filename."""

    if not session_id or any(separator in session_id for separator in ("/", "\\", ":")):
        raise ValueError("session_id must be a path-safe non-empty token")
    return f"{session_id}{POST_SESSION_EVALUATION_SUFFIX}"


def build_post_session_artifact(
    *,
    session_id: str,
    logs: Sequence[DecisionProvenanceLog],
    manifest: RunManifest,
    posterior_bundle: PosteriorBundleParts,
    answer_key: OpponentAnswerKey,
    explanations: Sequence[ExplanationDocument],
    checker_results: Sequence[VerificationResult],
) -> PostSessionArtifact:
    """Reconstruct all Phase 8 inputs from an already completed Hero session."""

    if manifest.run_id != session_id:
        raise ValueError("session_id does not match the RunManifest run_id")
    if len(manifest.opponents) != 1:
        raise ValueError("post-session evaluation requires exactly one opponent")
    opponent_model_id = manifest.opponents[0].opponent_id
    if answer_key.opponent_model_id != opponent_model_id:
        raise ValueError("answer key does not match the RunManifest opponent")

    detector_config = _detector_config(manifest, posterior_bundle)
    snapshot_records = _snapshot_records(manifest, posterior_bundle)
    safety_alpha = _unique_safety_alpha(logs)
    epsilon = _execution_epsilon(manifest)
    return evaluate_post_session(
        session_id=session_id,
        opponent_model_id=opponent_model_id,
        logs=logs,
        snapshot_records=snapshot_records,
        answer_key=answer_key,
        explanations=explanations,
        checker_results=checker_results,
        detector_config=detector_config,
        safety_alpha=safety_alpha,
        epsilon=epsilon,
    )


def evaluate_post_session(
    *,
    session_id: str,
    opponent_model_id: str,
    logs: Sequence[DecisionProvenanceLog],
    snapshot_records: Sequence[Mapping[str, Any]],
    answer_key: OpponentAnswerKey,
    explanations: Sequence[ExplanationDocument],
    checker_results: Sequence[VerificationResult],
    detector_config: LeakDetectorConfig,
    safety_alpha: float,
    epsilon: float,
) -> PostSessionArtifact:
    """Apply the documented deterministic MVP metric and update assumptions."""

    if not session_id or not opponent_model_id:
        raise ValueError("session and opponent identities must not be empty")
    if answer_key.opponent_model_id != opponent_model_id:
        raise ValueError("answer key opponent does not match the evaluation opponent")
    if not math.isfinite(safety_alpha) or not 0.0 <= safety_alpha <= 1.0:
        raise ValueError("safety_alpha must be finite and in [0, 1]")
    if not math.isfinite(epsilon) or not 0.0 <= epsilon <= 1.0:
        raise ValueError("epsilon must be finite and in [0, 1]")
    if not logs:
        raise ValueError("post-session evaluation requires at least one decision")
    if any(log.session_id != session_id for log in logs):
        raise ValueError("every DPL must match the evaluated session")
    if any(log.safety_alpha != safety_alpha for log in logs):
        raise ValueError("every DPL must match the evaluated safety_alpha")
    if len(explanations) != len(logs) or len(checker_results) != len(logs):
        raise ValueError("DPL, explanation, and checker counts must match")

    candidates = _candidate_metrics(
        snapshot_records,
        answer_key=answer_key,
        opponent_model_id=opponent_model_id,
    )
    gains: list[float] = []
    over_adjustment_count = 0
    under_adjustment_count = 0
    valid_explanations = 0
    for log, explanation, checker in zip(
        logs,
        explanations,
        checker_results,
        strict=True,
    ):
        if log.ev_estimate.ev_source != EXPLANATION_SAFE_EV_SOURCE:
            raise ValueError("post-session evaluation requires solver_exact DPL EV")
        if log.ev_for_explanation() is None:
            raise ValueError("post-session evaluation requires explanation-safe exact EV")
        gains.append(log.ev_estimate.gain_vs_base)
        over_adjustment_count += log.ev_estimate.final_ev < log.ev_estimate.base_ev
        under_adjustment_count += log.ev_estimate.exploit_ev > log.ev_estimate.final_ev

        expected_ref = f"{log.session_id}:{log.hand_id}"
        if explanation.dpl_ref != expected_ref:
            raise ValueError("explanation order or DPL identity does not match")
        truth_valid = _cited_leaks_are_truth_positive(
            log,
            explanation,
            candidates.truth_positive_by_reason_and_situation,
        )
        valid_explanations += checker.passed and truth_valid

    exploit_ev_gain_vs_base = math.fsum(gains) / len(gains)
    explanation_validity_score = valid_explanations / len(explanations)
    conservative = (
        candidates.false_positive_count > 0
        or exploit_ev_gain_vs_base < 0.0
        or over_adjustment_count > 0
    )
    next_detector_config = detector_config
    next_safety_alpha = safety_alpha
    next_epsilon = epsilon
    if conservative:
        next_detector_config = replace(
            detector_config,
            min_confidence=1.0,
            rule_exploit_min_confidence=1.0,
            nodelock_exploit_min_confidence=1.0,
        )
        next_safety_alpha = 0.0
        next_epsilon = 0.0

    notes = (
        *_ASSUMPTION_NOTES,
        f"outcome:false_positive_count={candidates.false_positive_count}",
        f"outcome:false_negative_count={candidates.false_negative_count}",
        f"outcome:next_settings={'conservative' if conservative else 'maintained'}",
    )
    evaluation = PostSessionEvaluation(
        session_id=session_id,
        opponent_model_id=opponent_model_id,
        leak_detection_accuracy=candidates.accuracy,
        average_estimation_error=candidates.average_estimation_error,
        exploit_ev_gain_vs_base=exploit_ev_gain_vs_base,
        over_adjustment_count=over_adjustment_count,
        under_adjustment_count=under_adjustment_count,
        explanation_validity_score=explanation_validity_score,
        notes=notes,
    )
    return PostSessionArtifact(
        evaluation=evaluation,
        next_session_settings=NextSessionSettings(
            leak_detector_config=next_detector_config,
            safety_alpha=next_safety_alpha,
            epsilon=next_epsilon,
        ),
    )


def _candidate_metrics(
    records: Sequence[Mapping[str, Any]],
    *,
    answer_key: OpponentAnswerKey,
    opponent_model_id: str,
) -> _CandidateMetrics:
    confusion = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    errors: list[float] = []
    truth_by_key: dict[tuple[str, str], bool] = {}
    ordered = sorted(
        records,
        key=lambda record: (
            str(record.get("opponent_id")),
            str(record.get("situation_key")),
            str(record.get("rule_id")),
        ),
    )
    for record in ordered:
        if record.get("opponent_id") != opponent_model_id:
            raise ValueError("terminal snapshot opponent does not match the answer key")
        reason_id = record.get("rule_id")
        situation_key = record.get("situation_key")
        if not isinstance(reason_id, str) or not reason_id:
            raise ValueError("terminal snapshot rule_id must be non-empty")
        if not isinstance(situation_key, str) or not situation_key:
            raise ValueError("terminal snapshot situation_key must be non-empty")
        key = (reason_id, situation_key)
        if key in truth_by_key:
            raise ValueError("terminal snapshot contains duplicate reason/situation truth")

        action_group = record.get("action_group")
        if not isinstance(action_group, list) or any(
            not isinstance(action, str) for action in action_group
        ):
            raise ValueError("terminal snapshot action_group must be a list of strings")
        n = record.get("n")
        k = record.get("k")
        if (
            isinstance(n, bool)
            or not isinstance(n, int)
            or n < 0
            or isinstance(k, bool)
            or not isinstance(k, int)
            or not 0 <= k <= n
        ):
            raise ValueError("terminal snapshot k/n must satisfy 0 <= k <= n")
        q = record.get("q")
        if isinstance(q, bool) or not isinstance(q, int | float) or not math.isfinite(q):
            raise ValueError("terminal snapshot q must be finite and numeric")
        eligibility = record.get("candidate_eligibility")
        if not isinstance(eligibility, dict):
            raise ValueError("terminal snapshot candidate_eligibility must be an object")
        structural = eligibility.get("structurally_eligible")
        predicted = eligibility.get("detected")
        if not isinstance(structural, bool) or not isinstance(predicted, bool):
            raise ValueError("terminal snapshot eligibility flags must be booleans")
        if structural != (0.0 < q < 1.0):
            raise ValueError("terminal snapshot structural eligibility does not match q")

        true_rate = answer_key.action_group_rate(action_group)
        if n > 0:
            errors.append(abs((k / n) - true_rate))

        boundary = None
        if structural:
            boundary = classify_ground_truth_boundary(p_true=str(true_rate), q=str(q))
        truth_positive = boundary == "positive"
        truth_by_key[key] = truth_positive
        if n == 0 or boundary in (None, "indifference"):
            continue
        if predicted and truth_positive:
            confusion["tp"] += 1
        elif predicted:
            confusion["fp"] += 1
        elif truth_positive:
            confusion["fn"] += 1
        else:
            confusion["tn"] += 1

    denominator = sum(confusion.values())
    accuracy = (confusion["tp"] + confusion["tn"]) / denominator if denominator else 0.0
    average_error = math.fsum(errors) / len(errors) if errors else 0.0
    return _CandidateMetrics(
        accuracy=accuracy,
        average_estimation_error=average_error,
        false_positive_count=confusion["fp"],
        false_negative_count=confusion["fn"],
        truth_positive_by_reason_and_situation=truth_by_key,
    )


def _cited_leaks_are_truth_positive(
    log: DecisionProvenanceLog,
    explanation: ExplanationDocument,
    truth_by_key: Mapping[tuple[str, str], bool],
) -> bool:
    for citation in explanation.policy_reasons.leak_reasons:
        matches = [leak for leak in log.detected_leaks if leak.reason_id == citation.reason_id]
        if len(matches) != 1:
            return False
        leak = matches[0]
        if not truth_by_key.get((leak.reason_id, leak.situation_key), False):
            return False
    return True


def _detector_config(
    manifest: RunManifest,
    posterior_bundle: PosteriorBundleParts,
) -> LeakDetectorConfig:
    matches = [config for config in manifest.configs if config.name == ESTIMATOR_CONFIG_NAME]
    if len(matches) != 1 or matches[0] != posterior_bundle.estimator_ref:
        raise ValueError("RunManifest estimator config does not match the posterior bundle")
    payload = _canonical_artifact_payload(
        posterior_bundle,
        ESTIMATOR_CONFIG_PATH,
        posterior_bundle.estimator_ref.sha256,
    )
    if not isinstance(payload, dict):
        raise ValueError("posterior estimator artifact must contain an object")
    try:
        return LeakDetectorConfig(
            method_version=payload["method_version"],
            alpha0=payload["alpha0"],
            beta0=payload["beta0"],
            tail=payload["tail"],
            min_effective_sample_size=payload["min_effective_sample_size"],
            min_deviation=payload["tau"],
            min_confidence=payload["detector_min_confidence"],
            rule_exploit_min_confidence=payload["rule_exploit_min_confidence"],
            nodelock_exploit_min_confidence=payload["nodelock_exploit_min_confidence"],
        )
    except (KeyError, TypeError) as exc:
        raise ValueError("posterior estimator artifact is incomplete") from exc


def _snapshot_records(
    manifest: RunManifest,
    posterior_bundle: PosteriorBundleParts,
) -> list[Mapping[str, Any]]:
    matches = [output for output in manifest.outputs if output.name == SNAPSHOT_ARTIFACT_NAME]
    if len(matches) != 1 or matches[0] != posterior_bundle.snapshot_ref:
        raise ValueError("RunManifest terminal snapshot does not match the posterior bundle")
    if posterior_bundle.snapshot_ref.sha256 is None:
        raise ValueError("terminal snapshot must carry a SHA-256 hash")
    payload = _canonical_artifact_payload(
        posterior_bundle,
        SNAPSHOT_ARTIFACT_PATH,
        posterior_bundle.snapshot_ref.sha256,
    )
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0.0":
        raise ValueError("unsupported terminal snapshot payload")
    records = payload.get("records")
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise ValueError("terminal snapshot records must be a list of objects")
    return records


def _canonical_artifact_payload(
    posterior_bundle: PosteriorBundleParts,
    relative_path: str,
    expected_sha256: str,
) -> object:
    try:
        raw = posterior_bundle.artifacts[relative_path]
    except KeyError as exc:
        raise ValueError(f"posterior bundle is missing {relative_path!r}") from exc
    if sha256_bytes(raw) != expected_sha256:
        raise ValueError(f"posterior bundle hash mismatch for {relative_path!r}")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"posterior bundle artifact is invalid JSON: {relative_path!r}") from exc
    if canonical_json_bytes(payload) != raw:
        raise ValueError(f"posterior bundle artifact is not canonical JSON: {relative_path!r}")
    return payload


def _unique_safety_alpha(logs: Sequence[DecisionProvenanceLog]) -> float:
    values = {log.safety_alpha for log in logs}
    if len(values) != 1:
        raise ValueError("post-session DPLs must have exactly one safety_alpha")
    return next(iter(values))


def _execution_epsilon(manifest: RunManifest) -> float:
    matches = [config for config in manifest.configs if config.name == "execution_sampler"]
    if len(matches) != 1 or matches[0].role != "other":
        raise ValueError("RunManifest must contain exactly one execution sampler config")
    reference = matches[0]
    prefix = f"inline:{EPSILON_SAMPLER_VERSION}:epsilon="
    if not reference.path.startswith(prefix):
        raise ValueError("execution sampler config path is not recognized")
    try:
        epsilon = float(reference.path.removeprefix(prefix))
    except ValueError as exc:
        raise ValueError("execution sampler epsilon is invalid") from exc
    if not math.isfinite(epsilon) or not 0.0 <= epsilon <= 1.0:
        raise ValueError("execution sampler epsilon must be in [0, 1]")
    payload = {
        "sampler_version": EPSILON_SAMPLER_VERSION,
        "epsilon": epsilon,
        "epsilon_distribution": "legal_uniform",
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if hashlib.sha256(encoded).hexdigest() != reference.sha256:
        raise ValueError("execution sampler config hash does not reconstruct")
    return epsilon


__all__ = [
    "POST_SESSION_EVALUATION_ARTIFACT_TYPE",
    "POST_SESSION_EVALUATION_SCHEMA_VERSION",
    "POST_SESSION_EVALUATION_SUFFIX",
    "NextSessionSettings",
    "PostSessionArtifact",
    "PostSessionEvaluation",
    "build_post_session_artifact",
    "evaluate_post_session",
    "post_session_evaluation_filename",
]
