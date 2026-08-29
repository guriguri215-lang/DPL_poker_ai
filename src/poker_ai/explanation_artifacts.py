"""In-repository-checked template artifacts for a completed Hero session.

This module is deliberately an orchestration boundary.  The deterministic
generator and verifier remain separate implementations in :mod:`explanation`;
this layer applies them one-for-one to an already validated session and writes
the existing P5-4 artifact formats after every explanation has passed. These
checks are not independent third-party validation.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from explanation import (
    EXPLANATION_SCHEMA_VERSION,
    TEMPLATE_GENERATOR,
    TEMPLATE_GENERATOR_VERSION,
    ExplanationDocument,
    VerificationResult,
    generate_template_explanation,
    verify_explanation,
)
from poker_core.dpl_schema import DecisionProvenanceLog, load_dpl_json
from poker_core.run_manifest import ArtifactRef, RunManifest

from .leak import LeakDetectorConfig
from .opponent import OpponentAnswerKey
from .post_session_evaluation import (
    POST_SESSION_EVALUATION_ARTIFACT_TYPE,
    POST_SESSION_EVALUATION_SCHEMA_VERSION,
    POST_SESSION_EVALUATION_SUFFIX,
    NextSessionSettings,
    PostSessionArtifact,
    PostSessionEvaluation,
    build_post_session_artifact,
    post_session_evaluation_filename,
)
from .posterior_bundle import (
    canonical_json_bytes,
    resolve_bundle_path,
    sha256_bytes,
    write_posterior_artifacts,
)
from .session import SessionResult, write_jsonl, write_manifest

NORMAL_HERO_EXPLANATION_ARTIFACT_ID = "hero_session_explanation_artifacts"


@dataclass(frozen=True)
class ExplanationBundlePaths:
    """Paths written for one successfully verified explanation bundle."""

    dpl: Path
    explanations: Path
    verifier_summary: Path
    manifest: Path
    post_session_evaluation: Path | None = None


class ExplanationBundleVerificationError(ValueError):
    """Raised before artifact writes when one or more explanations fail verification."""

    def __init__(self, failures: list[dict[str, Any]]) -> None:
        self.failures = failures
        super().__init__(f"{len(failures)} explanation(s) failed independent verification")


@dataclass(frozen=True)
class ExplanationPairingIssue:
    """One count, order, or identity failure in a DPL/explanation sequence."""

    code: str
    index: int | None = None


@dataclass(frozen=True)
class ExplanationSetVerification:
    """Shared pairing and checker result used by bundle writers and readers."""

    session_id: str | None
    dpl_count: int
    explanation_count: int
    detected_leaks: int
    mixed_decisions: int
    pairing_issues: tuple[ExplanationPairingIssue, ...]
    checker_results: tuple[VerificationResult, ...]
    checker_refs: tuple[str, ...]

    @property
    def checker_total(self) -> int:
        return len(self.checker_results)

    @property
    def checker_passed(self) -> int:
        return sum(result.passed for result in self.checker_results)

    @property
    def checker_failed(self) -> int:
        return self.checker_total - self.checker_passed

    @property
    def passed(self) -> bool:
        return (
            self.dpl_count == self.explanation_count
            and self.checker_total == self.explanation_count
            and not self.pairing_issues
            and self.checker_failed == 0
        )

    def failure_payloads(self) -> list[dict[str, Any]]:
        """Return the existing verifier-summary failure representation."""

        failures: list[dict[str, Any]] = []
        for issue in self.pairing_issues:
            failures.append(
                {
                    "dpl_ref": "bundle",
                    "issues": [
                        {
                            "code": issue.code,
                            "location": (
                                "bundle" if issue.index is None else f"bundle[{issue.index}]"
                            ),
                            "message": "DPL and explanation pairing is inconsistent",
                        }
                    ],
                }
            )
        for dpl_ref, result in zip(self.checker_refs, self.checker_results, strict=True):
            if result.passed:
                continue
            failures.append(
                {
                    "dpl_ref": dpl_ref,
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

    def session_summary(self) -> dict[str, Any]:
        """Return the shared session-count section of a verifier summary."""

        return {
            "session_id": self.session_id,
            "dpl_count": self.dpl_count,
            "explanation_count": self.explanation_count,
            "detected_leaks": self.detected_leaks,
            "mixed_decisions": self.mixed_decisions,
        }

    def verification_summary(self) -> dict[str, Any]:
        """Return the shared checker-result section of a verifier summary."""

        total = self.explanation_count
        passed = self.checker_passed
        failed = total - passed
        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": (passed / total) if total else 0.0,
            "failures": self.failure_payloads(),
        }


@dataclass(frozen=True)
class SavedExplanationBundleVerification:
    """Successful read-only verification counts for one saved normal Hero bundle."""

    artifact_count: int
    dpl_count: int
    explanation_count: int
    checker_total: int
    checker_passed: int
    summary_consistent: bool = True


class SavedExplanationBundleVerificationError(ValueError):
    """A saved bundle failed with a stable, non-content-bearing category."""

    def __init__(self, category: str, filename: str) -> None:
        self.category = category
        self.filename = filename
        super().__init__(f"saved explanation bundle issue: category={category} filename={filename}")


@dataclass(frozen=True)
class _SavedExplanationBundleSnapshot:
    """Manifest and artifact bytes captured by one integrity-checked read."""

    manifest: RunManifest
    manifest_filename: str
    artifacts: Mapping[str, tuple[ArtifactRef, bytes]]


def verify_explanation_pairs(
    logs: Sequence[DecisionProvenanceLog],
    explanations: Sequence[ExplanationDocument | Mapping[str, Any] | object],
    *,
    expected_session_id: str | None = None,
) -> ExplanationSetVerification:
    """Check one-to-one pairing and run the existing checker on every available pair."""

    pairing_issues: list[ExplanationPairingIssue] = []

    def add_issue(code: str, index: int | None = None) -> None:
        issue = ExplanationPairingIssue(code=code, index=index)
        if issue not in pairing_issues:
            pairing_issues.append(issue)

    if len(logs) != len(explanations):
        add_issue("pairing-count-mismatch")

    if expected_session_id is not None:
        for index, log in enumerate(logs):
            if log.session_id != expected_session_id:
                add_issue("pairing-session-id-mismatch", index)

    expected_refs = tuple(f"{log.session_id}:{log.hand_id}" for log in logs)
    actual_refs = tuple(_explanation_dpl_ref(item) for item in explanations)
    if len(expected_refs) == len(actual_refs) and actual_refs != expected_refs:
        if None not in actual_refs and Counter(actual_refs) == Counter(expected_refs):
            add_issue("pairing-order-mismatch")
        else:
            for index, (expected, actual) in enumerate(
                zip(expected_refs, actual_refs, strict=True)
            ):
                if actual == expected:
                    continue
                if actual is None or ":" not in actual:
                    add_issue("pairing-hand-id-mismatch", index)
                    continue
                actual_session, actual_hand = actual.split(":", 1)
                if actual_session != logs[index].session_id:
                    add_issue("pairing-session-id-mismatch", index)
                if actual_hand != logs[index].hand_id:
                    add_issue("pairing-hand-id-mismatch", index)

    log_identities = tuple((log.session_id, log.hand_id) for log in logs)
    if len(set(log_identities)) != len(log_identities):
        add_issue("pairing-hand-id-mismatch")
    non_null_refs = tuple(ref for ref in actual_refs if ref is not None)
    if len(set(non_null_refs)) != len(non_null_refs):
        add_issue("pairing-hand-id-mismatch")

    checker_results: list[VerificationResult] = []
    checker_refs: list[str] = []
    for log, explanation in zip(logs, explanations, strict=False):
        checker_refs.append(f"{log.session_id}:{log.hand_id}")
        checker_results.append(verify_explanation(explanation, log))  # type: ignore[arg-type]

    session_id = expected_session_id
    if session_id is None and logs:
        session_id = logs[0].session_id
    return ExplanationSetVerification(
        session_id=session_id,
        dpl_count=len(logs),
        explanation_count=len(explanations),
        detected_leaks=sum(len(log.detected_leaks) for log in logs),
        mixed_decisions=sum(1 for log in logs if log.mix_reasons),
        pairing_issues=tuple(pairing_issues),
        checker_results=tuple(checker_results),
        checker_refs=tuple(checker_refs),
    )


def generate_and_verify_explanations(
    logs: list[DecisionProvenanceLog],
) -> list[ExplanationDocument]:
    """Generate in DPL order and check every item with the separate verifier.

    All verifier results are collected before failure is reported.  The caller
    can therefore invoke this function before creating an output directory and
    be certain that a verification failure cannot leave a partial run bundle.
    """

    explanations, _ = _generate_and_verify_explanation_set(logs)
    return explanations


def write_verified_explanation_bundle(
    result: SessionResult,
    out_dir: Path | str,
    *,
    artifact_id: str,
    safety_alpha: float,
    leaky_fixture: bool,
    answer_key: OpponentAnswerKey | None = None,
    reference_root: Path | str | None = None,
    dpl_filename: str | None = None,
    explanations_filename: str | None = None,
    summary_filename: str | None = None,
    manifest_filename: str | None = None,
) -> ExplanationBundlePaths:
    """Verify all explanations, then write the expanded normal-Hero bundle.

    The DPL, explanation JSONL, verifier summary, and existing terminal posterior
    provenance output are all referenced with SHA-256 hashes through the current
    :class:`~poker_core.run_manifest.ArtifactRef` contract.  No DPL or
    RunManifest schema extension is involved.  When the completed normal Hero
    environment supplies its answer key, the same manifest also references one
    deterministic post-session evaluation and next-settings artifact. Historical
    P5-4 callers omit the answer key and retain their existing output set.
    """

    # This must remain the first operation with side effects deferred: generation
    # and every separate verifier check complete before the output tree exists.
    explanations, verification = _generate_and_verify_explanation_set(result.logs)
    post_session_artifact = None
    if answer_key is not None:
        post_session_artifact = build_post_session_artifact(
            session_id=result.session_id,
            logs=result.logs,
            manifest=result.manifest,
            posterior_bundle=result.posterior_bundle,
            answer_key=answer_key,
            explanations=explanations,
            checker_results=verification.checker_results,
        )

    root = Path(out_dir)
    refs_root = Path(reference_root) if reference_root is not None else root
    dpl_path = root / (dpl_filename or f"{result.session_id}.dpl.jsonl")
    explanations_path = root / (explanations_filename or f"{result.session_id}.explanations.jsonl")
    summary_path = root / (summary_filename or f"{result.session_id}.verifier_summary.json")
    manifest_path = root / (manifest_filename or f"{result.session_id}.manifest.json")
    post_session_path = (
        root / post_session_evaluation_filename(result.session_id)
        if post_session_artifact is not None
        else None
    )

    summary = _summary_payload(
        artifact_id=artifact_id,
        result=result,
        explanations=explanations,
        verification=verification,
        safety_alpha=safety_alpha,
        leaky_fixture=leaky_fixture,
        reference_root=refs_root,
        dpl_path=dpl_path,
        explanations_path=explanations_path,
        summary_path=summary_path,
        manifest_path=manifest_path,
    )

    root.mkdir(parents=True, exist_ok=True)
    write_posterior_artifacts(result.posterior_bundle, root)
    write_jsonl(
        result.logs,
        dpl_path,
        manifest=result.manifest,
        bundle_root=root,
    )
    _write_explanations_jsonl(explanations, explanations_path)
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if post_session_path is not None and post_session_artifact is not None:
        post_session_path.write_bytes(post_session_artifact.canonical_bytes())

    manifest = result.manifest.model_copy(deep=True)
    manifest.outputs = [
        *result.manifest.outputs,
        _artifact_ref(refs_root, dpl_path),
        _artifact_ref(refs_root, explanations_path),
        _artifact_ref(refs_root, summary_path),
        *([_artifact_ref(refs_root, post_session_path)] if post_session_path is not None else []),
    ]
    write_manifest(manifest, manifest_path)
    return ExplanationBundlePaths(
        dpl=dpl_path,
        explanations=explanations_path,
        verifier_summary=summary_path,
        manifest=manifest_path,
        post_session_evaluation=post_session_path,
    )


def verify_saved_explanation_bundle(
    manifest_path: Path | str,
) -> SavedExplanationBundleVerification:
    """Read and verify a saved normal Hero explanation bundle without changing it."""

    verification, _ = _verify_saved_explanation_bundle_contents(
        manifest_path,
        require_post_session=False,
    )
    return verification


def _verify_saved_explanation_bundle_contents(
    manifest_path: Path | str,
    *,
    require_post_session: bool,
) -> tuple[SavedExplanationBundleVerification, PostSessionArtifact | None]:
    """Verify and return displayable post-session data from one captured snapshot."""

    snapshot = _load_saved_explanation_bundle_snapshot(manifest_path)
    verification = _verify_saved_explanation_bundle_snapshot(snapshot)
    post_session = _validated_post_session_artifact(
        snapshot,
        required=require_post_session,
    )
    return verification, post_session


def load_next_session_settings(manifest_path: Path | str) -> NextSessionSettings:
    """Verify one prior Hero bundle and restore its explicit next-session settings.

    The manifest and every referenced artifact are captured once. The existing
    saved-explanation checks and the post-session semantic checks therefore use
    the same hash-verified bytes instead of verifying and then rereading mutable
    files. Only settings are returned; no baseline, posterior/action history, or
    answer key crosses the session boundary.
    """

    _, post_session = _verify_saved_explanation_bundle_contents(
        manifest_path,
        require_post_session=True,
    )
    assert post_session is not None
    return post_session.next_session_settings


def _validated_post_session_artifact(
    snapshot: _SavedExplanationBundleSnapshot,
    *,
    required: bool,
) -> PostSessionArtifact | None:
    """Validate and reconstruct one post-session artifact from captured bundle bytes."""

    has_reference = any(
        path.endswith(POST_SESSION_EVALUATION_SUFFIX) for path in snapshot.artifacts
    )
    if not has_reference and not required:
        return None
    evaluation_ref, raw = _required_artifact(
        snapshot.artifacts,
        POST_SESSION_EVALUATION_SUFFIX,
        snapshot.manifest_filename,
    )
    filename = _artifact_filename(evaluation_ref)
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SavedExplanationBundleVerificationError(
            "post-session-artifact-invalid", filename
        ) from exc
    try:
        canonical = canonical_json_bytes(payload)
    except (TypeError, ValueError) as exc:
        raise SavedExplanationBundleVerificationError(
            "post-session-artifact-invalid", filename
        ) from exc
    if canonical != raw:
        raise SavedExplanationBundleVerificationError(
            "post-session-artifact-noncanonical", filename
        )
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "artifact_type",
        "evaluation",
        "next_session_settings",
    }:
        raise SavedExplanationBundleVerificationError("post-session-artifact-invalid", filename)
    if payload["schema_version"] != POST_SESSION_EVALUATION_SCHEMA_VERSION:
        raise SavedExplanationBundleVerificationError("post-session-schema-unsupported", filename)
    if payload["artifact_type"] != POST_SESSION_EVALUATION_ARTIFACT_TYPE:
        raise SavedExplanationBundleVerificationError("post-session-type-unsupported", filename)

    evaluation_payload = payload["evaluation"]
    try:
        evaluation = _validate_post_session_evaluation(evaluation_payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise SavedExplanationBundleVerificationError(
            "post-session-artifact-invalid", filename
        ) from exc
    if evaluation.session_id != snapshot.manifest.run_id:
        raise SavedExplanationBundleVerificationError("post-session-session-mismatch", filename)
    if (
        len(snapshot.manifest.opponents) != 1
        or evaluation.opponent_model_id != snapshot.manifest.opponents[0].opponent_id
    ):
        raise SavedExplanationBundleVerificationError("post-session-opponent-mismatch", filename)

    try:
        settings = _parse_next_session_settings(payload["next_session_settings"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SavedExplanationBundleVerificationError(
            "post-session-settings-invalid", filename
        ) from exc
    return PostSessionArtifact(
        evaluation=evaluation,
        next_session_settings=settings,
    )


def _validate_post_session_evaluation(payload: object) -> PostSessionEvaluation:
    """Fail closed on the complete versioned PR #19 evaluation shape."""

    fields = {
        "session_id",
        "opponent_model_id",
        "leak_detection_accuracy",
        "average_estimation_error",
        "exploit_ev_gain_vs_base",
        "over_adjustment_count",
        "under_adjustment_count",
        "explanation_validity_score",
        "notes",
    }
    if not isinstance(payload, dict) or set(payload) != fields:
        raise ValueError("evaluation fields do not match the strict contract")
    if not isinstance(payload["session_id"], str) or not isinstance(
        payload["opponent_model_id"], str
    ):
        raise TypeError("evaluation identities must be strings")

    bounded_metrics = (
        "leak_detection_accuracy",
        "average_estimation_error",
        "explanation_validity_score",
    )
    normalized_metrics: dict[str, float] = {}
    for field in bounded_metrics:
        value = _strict_finite_float(payload[field], field)
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"{field} must be finite and in [0, 1]")
        normalized_metrics[field] = value
    exploit_ev_gain = _strict_finite_float(
        payload["exploit_ev_gain_vs_base"],
        "exploit_ev_gain_vs_base",
    )

    for field in ("over_adjustment_count", "under_adjustment_count"):
        value = payload[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise TypeError(f"{field} must be a nonnegative integer")

    notes = payload["notes"]
    if not isinstance(notes, list) or any(not isinstance(note, str) for note in notes):
        raise TypeError("evaluation notes must be a list of strings")

    return PostSessionEvaluation(
        session_id=payload["session_id"],
        opponent_model_id=payload["opponent_model_id"],
        leak_detection_accuracy=normalized_metrics["leak_detection_accuracy"],
        average_estimation_error=normalized_metrics["average_estimation_error"],
        exploit_ev_gain_vs_base=exploit_ev_gain,
        over_adjustment_count=payload["over_adjustment_count"],
        under_adjustment_count=payload["under_adjustment_count"],
        explanation_validity_score=normalized_metrics["explanation_validity_score"],
        notes=tuple(notes),
    )


def _load_saved_explanation_bundle_snapshot(
    manifest_path: Path | str,
) -> _SavedExplanationBundleSnapshot:
    """Capture a manifest and all of its path- and hash-verified outputs once."""

    path = Path(manifest_path)
    manifest_filename = path.name or "manifest.json"
    try:
        manifest_bytes = path.read_bytes()
    except OSError as exc:
        raise SavedExplanationBundleVerificationError(
            "manifest-missing", manifest_filename
        ) from exc
    try:
        manifest = RunManifest.model_validate_json(manifest_bytes)
    except (ValueError, TypeError) as exc:
        raise SavedExplanationBundleVerificationError(
            "manifest-invalid", manifest_filename
        ) from exc

    root = path.parent
    artifacts: dict[str, tuple[ArtifactRef, bytes]] = {}
    seen_names: set[str] = set()
    for ref in manifest.outputs:
        ref_filename = _artifact_filename(ref)
        if ref.name in seen_names or ref.path in artifacts:
            raise SavedExplanationBundleVerificationError(
                "artifact-reference-duplicate", ref_filename
            )
        seen_names.add(ref.name)
        if ref.sha256 is None:
            raise SavedExplanationBundleVerificationError("artifact-hash-missing", ref_filename)
        try:
            target = resolve_bundle_path(root, ref.path)
        except ValueError as exc:
            raise SavedExplanationBundleVerificationError(
                "artifact-path-invalid", ref_filename
            ) from exc
        if not target.is_file():
            raise SavedExplanationBundleVerificationError("artifact-missing", ref_filename)
        try:
            payload = target.read_bytes()
        except OSError as exc:
            raise SavedExplanationBundleVerificationError(
                "artifact-unreadable", ref_filename
            ) from exc
        if sha256_bytes(payload) != ref.sha256:
            raise SavedExplanationBundleVerificationError("artifact-hash-mismatch", ref_filename)
        artifacts[ref.path] = (ref, payload)

    return _SavedExplanationBundleSnapshot(
        manifest=manifest,
        manifest_filename=manifest_filename,
        artifacts=artifacts,
    )


def _verify_saved_explanation_bundle_snapshot(
    snapshot: _SavedExplanationBundleSnapshot,
) -> SavedExplanationBundleVerification:
    """Apply the existing explanation verifier to one captured bundle snapshot."""

    manifest = snapshot.manifest
    manifest_filename = snapshot.manifest_filename
    artifacts = snapshot.artifacts

    dpl_ref, dpl_bytes = _required_artifact(artifacts, ".dpl.jsonl", manifest_filename)
    explanation_ref, explanation_bytes = _required_artifact(
        artifacts, ".explanations.jsonl", manifest_filename
    )
    summary_ref, summary_bytes = _required_artifact(
        artifacts, ".verifier_summary.json", manifest_filename
    )

    logs: list[DecisionProvenanceLog] = []
    for raw_line in _jsonl_lines(dpl_bytes, dpl_ref, "dpl-jsonl-invalid"):
        try:
            loaded = load_dpl_json(raw_line)
        except (ValueError, TypeError) as exc:
            raise SavedExplanationBundleVerificationError(
                "dpl-jsonl-invalid", _artifact_filename(dpl_ref)
            ) from exc
        if not isinstance(loaded, DecisionProvenanceLog):
            raise SavedExplanationBundleVerificationError(
                "dpl-version-unsupported", _artifact_filename(dpl_ref)
            )
        logs.append(loaded)

    explanations: list[object] = []
    for raw_line in _jsonl_lines(explanation_bytes, explanation_ref, "explanations-jsonl-invalid"):
        try:
            explanations.append(json.loads(raw_line))
        except json.JSONDecodeError as exc:
            raise SavedExplanationBundleVerificationError(
                "explanations-jsonl-invalid", _artifact_filename(explanation_ref)
            ) from exc

    try:
        summary = json.loads(summary_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SavedExplanationBundleVerificationError(
            "verifier-summary-invalid", _artifact_filename(summary_ref)
        ) from exc
    if not isinstance(summary, dict):
        raise SavedExplanationBundleVerificationError(
            "verifier-summary-invalid", _artifact_filename(summary_ref)
        )

    metadata = summary.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("artifact_id") != (
        NORMAL_HERO_EXPLANATION_ARTIFACT_ID
    ):
        raise SavedExplanationBundleVerificationError(
            "bundle-kind-mismatch", _artifact_filename(summary_ref)
        )

    verification = verify_explanation_pairs(
        logs,
        explanations,
        expected_session_id=manifest.run_id,
    )
    if verification.pairing_issues:
        raise SavedExplanationBundleVerificationError(
            verification.pairing_issues[0].code,
            _artifact_filename(explanation_ref),
        )
    if verification.checker_failed or verification.checker_total != len(explanations):
        raise SavedExplanationBundleVerificationError(
            "explanation-checker-failed", _artifact_filename(explanation_ref)
        )

    expected_artifacts = {
        "dpl_jsonl": dpl_ref.path,
        "explanations_jsonl": explanation_ref.path,
        "verifier_summary_json": summary_ref.path,
        "manifest_json": manifest_filename,
    }
    if (
        metadata.get("hands") != len(logs)
        or summary.get("session") != verification.session_summary()
        or summary.get("verification") != verification.verification_summary()
        or summary.get("artifacts") != expected_artifacts
    ):
        raise SavedExplanationBundleVerificationError(
            "verifier-summary-mismatch", _artifact_filename(summary_ref)
        )

    return SavedExplanationBundleVerification(
        artifact_count=len(artifacts),
        dpl_count=len(logs),
        explanation_count=len(explanations),
        checker_total=verification.checker_total,
        checker_passed=verification.checker_passed,
    )


def _parse_next_session_settings(payload: object) -> NextSessionSettings:
    """Strictly reconstruct only the existing detector, alpha, and epsilon knobs."""

    if not isinstance(payload, dict) or set(payload) != {
        "leak_detector_config",
        "safety_alpha",
        "epsilon",
    }:
        raise ValueError("next_session_settings fields do not match the strict contract")
    config_payload = payload["leak_detector_config"]
    config_fields = {
        "method_version",
        "alpha0",
        "beta0",
        "tail",
        "min_effective_sample_size",
        "min_deviation",
        "min_confidence",
        "rule_exploit_min_confidence",
        "nodelock_exploit_min_confidence",
    }
    if not isinstance(config_payload, dict) or set(config_payload) != config_fields:
        raise ValueError("leak_detector_config fields do not match the strict contract")

    numeric_fields = (
        "alpha0",
        "beta0",
        "min_deviation",
        "min_confidence",
        "rule_exploit_min_confidence",
        "nodelock_exploit_min_confidence",
    )
    numeric_values = {
        field: _strict_finite_float(config_payload[field], field) for field in numeric_fields
    }
    sample_floor = config_payload["min_effective_sample_size"]
    if isinstance(sample_floor, bool) or not isinstance(sample_floor, int):
        raise TypeError("min_effective_sample_size must be an integer")
    if not isinstance(config_payload["method_version"], str) or not isinstance(
        config_payload["tail"], str
    ):
        raise TypeError("leak detector method_version and tail must be strings")

    restored_values = {
        "safety_alpha": _strict_finite_float(payload["safety_alpha"], "safety_alpha"),
        "epsilon": _strict_finite_float(payload["epsilon"], "epsilon"),
    }
    for name, value in restored_values.items():
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"{name} must be finite and in [0, 1]")

    return NextSessionSettings(
        leak_detector_config=LeakDetectorConfig(
            method_version=config_payload["method_version"],
            alpha0=numeric_values["alpha0"],
            beta0=numeric_values["beta0"],
            tail=config_payload["tail"],
            min_effective_sample_size=sample_floor,
            min_deviation=numeric_values["min_deviation"],
            min_confidence=numeric_values["min_confidence"],
            rule_exploit_min_confidence=numeric_values["rule_exploit_min_confidence"],
            nodelock_exploit_min_confidence=numeric_values["nodelock_exploit_min_confidence"],
        ),
        safety_alpha=restored_values["safety_alpha"],
        epsilon=restored_values["epsilon"],
    )


def _strict_finite_float(value: object, field_name: str) -> float:
    """Reject JSON booleans, non-numbers, infinities, NaN, and float overflow."""

    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TypeError(f"{field_name} must be numeric")
    try:
        converted = float(value)
    except OverflowError as exc:
        raise ValueError(f"{field_name} must be finite") from exc
    if not math.isfinite(converted):
        raise ValueError(f"{field_name} must be finite")
    return converted


def _verification_failures(
    logs: list[DecisionProvenanceLog],
    explanations: list[ExplanationDocument],
) -> list[dict[str, Any]]:
    return verify_explanation_pairs(logs, explanations).failure_payloads()


def _generate_and_verify_explanation_set(
    logs: list[DecisionProvenanceLog],
) -> tuple[list[ExplanationDocument], ExplanationSetVerification]:
    explanations = [generate_template_explanation(log) for log in logs]
    verification = verify_explanation_pairs(logs, explanations)
    if not verification.passed:
        raise ExplanationBundleVerificationError(verification.failure_payloads())
    return explanations, verification


def _explanation_dpl_ref(value: object) -> str | None:
    if isinstance(value, ExplanationDocument):
        return value.dpl_ref
    if isinstance(value, Mapping):
        dpl_ref = value.get("dpl_ref")
        return dpl_ref if isinstance(dpl_ref, str) else None
    return None


def _artifact_filename(ref: ArtifactRef) -> str:
    normalized = ref.path.replace("\\", "/")
    return PurePosixPath(normalized).name or ref.name


def _required_artifact(
    artifacts: Mapping[str, tuple[ArtifactRef, bytes]],
    suffix: str,
    manifest_filename: str,
) -> tuple[ArtifactRef, bytes]:
    matches = [value for path, value in artifacts.items() if path.endswith(suffix)]
    if len(matches) != 1:
        raise SavedExplanationBundleVerificationError(
            "required-artifact-reference", manifest_filename
        )
    return matches[0]


def _jsonl_lines(payload: bytes, ref: ArtifactRef, category: str) -> list[str]:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise SavedExplanationBundleVerificationError(category, _artifact_filename(ref)) from exc
    if any(not line.strip() for line in lines):
        raise SavedExplanationBundleVerificationError(category, _artifact_filename(ref))
    return lines


def _write_explanations_jsonl(
    explanations: list[ExplanationDocument],
    path: Path,
) -> Path:
    with path.open("w", encoding="utf-8") as fh:
        for explanation in explanations:
            payload = explanation.model_dump(mode="json")
            fh.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    return path


def _relative_path(reference_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(reference_root.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError("artifact path must be inside its reference root") from exc


def _artifact_ref(reference_root: Path, path: Path) -> ArtifactRef:
    return ArtifactRef(
        name=path.name,
        path=_relative_path(reference_root, path),
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
    )


def _summary_payload(
    *,
    artifact_id: str,
    result: SessionResult,
    explanations: list[ExplanationDocument],
    verification: ExplanationSetVerification,
    safety_alpha: float,
    leaky_fixture: bool,
    reference_root: Path,
    dpl_path: Path,
    explanations_path: Path,
    summary_path: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    return {
        "metadata": {
            "artifact_id": artifact_id,
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "git_commit": result.manifest.code.git_commit,
            "git_dirty": result.manifest.code.git_dirty,
            "seed": result.manifest.seeds["master"],
            "hands": len(result.logs),
            "safety_alpha": safety_alpha,
            "leaky_fixture": leaky_fixture,
        },
        "versions": {
            "dpl_schema_version": result.logs[0].schema_version if result.logs else None,
            "explanation_schema_version": EXPLANATION_SCHEMA_VERSION,
            "generator": TEMPLATE_GENERATOR,
            "generator_version": TEMPLATE_GENERATOR_VERSION,
            "baseline_table_version": (
                result.logs[0].baseline_table_version if result.logs else None
            ),
        },
        "session": verification.session_summary(),
        "verification": verification.verification_summary(),
        "artifacts": {
            "dpl_jsonl": _relative_path(reference_root, dpl_path),
            "explanations_jsonl": _relative_path(reference_root, explanations_path),
            "verifier_summary_json": _relative_path(reference_root, summary_path),
            "manifest_json": _relative_path(reference_root, manifest_path),
        },
    }


__all__ = [
    "NORMAL_HERO_EXPLANATION_ARTIFACT_ID",
    "ExplanationBundlePaths",
    "ExplanationBundleVerificationError",
    "ExplanationPairingIssue",
    "ExplanationSetVerification",
    "SavedExplanationBundleVerification",
    "SavedExplanationBundleVerificationError",
    "generate_and_verify_explanations",
    "load_next_session_settings",
    "verify_explanation_pairs",
    "verify_saved_explanation_bundle",
    "write_verified_explanation_bundle",
]
