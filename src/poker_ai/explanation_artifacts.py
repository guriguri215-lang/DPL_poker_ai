"""Verified template-explanation artifacts for a completed Hero session.

This module is deliberately an orchestration boundary.  The deterministic
generator and the independent verifier remain separate in :mod:`explanation`;
this layer only applies them one-for-one to an already validated session and
writes the existing P5-4 artifact formats after every explanation has passed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
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
from poker_core.dpl_schema import DecisionProvenanceLog
from poker_core.run_manifest import ArtifactRef

from .posterior_bundle import write_posterior_artifacts
from .session import SessionResult, write_jsonl, write_manifest


@dataclass(frozen=True)
class ExplanationBundlePaths:
    """Paths written for one successfully verified explanation bundle."""

    dpl: Path
    explanations: Path
    verifier_summary: Path
    manifest: Path


class ExplanationBundleVerificationError(ValueError):
    """Raised before artifact writes when one or more explanations fail verification."""

    def __init__(self, failures: list[dict[str, Any]]) -> None:
        self.failures = failures
        super().__init__(f"{len(failures)} explanation(s) failed independent verification")


def generate_and_verify_explanations(
    logs: list[DecisionProvenanceLog],
) -> list[ExplanationDocument]:
    """Generate explanations in DPL order and independently verify every item.

    All verifier results are collected before failure is reported.  The caller
    can therefore invoke this function before creating an output directory and
    be certain that a verification failure cannot leave a partial run bundle.
    """

    explanations = [generate_template_explanation(log) for log in logs]
    failures = _verification_failures(logs, explanations)
    if failures:
        raise ExplanationBundleVerificationError(failures)
    return explanations


def write_verified_explanation_bundle(
    result: SessionResult,
    out_dir: Path | str,
    *,
    artifact_id: str,
    safety_alpha: float,
    leaky_fixture: bool,
    reference_root: Path | str | None = None,
    dpl_filename: str | None = None,
    explanations_filename: str | None = None,
    summary_filename: str | None = None,
    manifest_filename: str | None = None,
) -> ExplanationBundlePaths:
    """Verify all explanations, then write the existing four-output bundle.

    The DPL, explanation JSONL, verifier summary, and existing terminal posterior
    provenance output are all referenced with SHA-256 hashes through the current
    :class:`~poker_core.run_manifest.ArtifactRef` contract.  No DPL or
    RunManifest schema extension is involved.
    """

    # This must remain the first operation with side effects deferred: generation
    # and every independent verification complete before the output tree exists.
    explanations = generate_and_verify_explanations(result.logs)

    root = Path(out_dir)
    refs_root = Path(reference_root) if reference_root is not None else root
    dpl_path = root / (dpl_filename or f"{result.session_id}.dpl.jsonl")
    explanations_path = root / (explanations_filename or f"{result.session_id}.explanations.jsonl")
    summary_path = root / (summary_filename or f"{result.session_id}.verifier_summary.json")
    manifest_path = root / (manifest_filename or f"{result.session_id}.manifest.json")

    summary = _summary_payload(
        artifact_id=artifact_id,
        result=result,
        explanations=explanations,
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

    manifest = result.manifest.model_copy(deep=True)
    manifest.outputs = [
        *result.manifest.outputs,
        _artifact_ref(refs_root, dpl_path),
        _artifact_ref(refs_root, explanations_path),
        _artifact_ref(refs_root, summary_path),
    ]
    write_manifest(manifest, manifest_path)
    return ExplanationBundlePaths(
        dpl=dpl_path,
        explanations=explanations_path,
        verifier_summary=summary_path,
        manifest=manifest_path,
    )


def _verification_failures(
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
    safety_alpha: float,
    leaky_fixture: bool,
    reference_root: Path,
    dpl_path: Path,
    explanations_path: Path,
    summary_path: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    total = len(explanations)
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
        "session": {
            "session_id": result.session_id,
            "dpl_count": len(result.logs),
            "explanation_count": total,
            "detected_leaks": sum(len(log.detected_leaks) for log in result.logs),
            "mixed_decisions": sum(1 for log in result.logs if log.mix_reasons),
        },
        "verification": {
            "total": total,
            "passed": total,
            "failed": 0,
            "pass_rate": 1.0 if total else 0.0,
            "failures": [],
        },
        "artifacts": {
            "dpl_jsonl": _relative_path(reference_root, dpl_path),
            "explanations_jsonl": _relative_path(reference_root, explanations_path),
            "verifier_summary_json": _relative_path(reference_root, summary_path),
            "manifest_json": _relative_path(reference_root, manifest_path),
        },
    }


__all__ = [
    "ExplanationBundlePaths",
    "ExplanationBundleVerificationError",
    "generate_and_verify_explanations",
    "write_verified_explanation_bundle",
]
