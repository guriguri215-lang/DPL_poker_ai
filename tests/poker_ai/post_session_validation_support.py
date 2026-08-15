from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from poker_ai.posterior_bundle import canonical_json_bytes


@dataclass(frozen=True)
class PostSessionValidationCase:
    name: str
    category: str
    filename_kind: Literal["evaluation", "manifest"] = "evaluation"


POST_SESSION_VALIDATION_CASES = (
    PostSessionValidationCase("evaluation-file-missing", "artifact-missing"),
    PostSessionValidationCase(
        "evaluation-reference-multiple", "required-artifact-reference", "manifest"
    ),
    PostSessionValidationCase("artifact-changed", "artifact-hash-mismatch"),
    PostSessionValidationCase("artifact-noncanonical", "post-session-artifact-noncanonical"),
    PostSessionValidationCase("schema-unsupported", "post-session-schema-unsupported"),
    PostSessionValidationCase("type-unsupported", "post-session-type-unsupported"),
    PostSessionValidationCase("evaluation-field-missing", "post-session-artifact-invalid"),
    PostSessionValidationCase("evaluation-field-extra", "post-session-artifact-invalid"),
    PostSessionValidationCase("evaluation-metric-nonfinite", "post-session-artifact-invalid"),
    PostSessionValidationCase("evaluation-metric-out-of-range", "post-session-artifact-invalid"),
    PostSessionValidationCase("evaluation-count-invalid", "post-session-artifact-invalid"),
    PostSessionValidationCase("evaluation-notes-invalid", "post-session-artifact-invalid"),
    PostSessionValidationCase("session-mismatch", "post-session-session-mismatch"),
    PostSessionValidationCase("opponent-mismatch", "post-session-opponent-mismatch"),
    PostSessionValidationCase("manifest-opponent-multiple", "post-session-opponent-mismatch"),
    PostSessionValidationCase("alpha-out-of-range", "post-session-settings-invalid"),
    PostSessionValidationCase("alpha-boolean", "post-session-settings-invalid"),
    PostSessionValidationCase("epsilon-out-of-range", "post-session-settings-invalid"),
    PostSessionValidationCase("detector-config-out-of-range", "post-session-settings-invalid"),
    PostSessionValidationCase("detector-confidence-out-of-range", "post-session-settings-invalid"),
    PostSessionValidationCase("detector-sample-floor-invalid", "post-session-settings-invalid"),
    PostSessionValidationCase("detector-sample-floor-boolean", "post-session-settings-invalid"),
    PostSessionValidationCase("detector-method-unsupported", "post-session-settings-invalid"),
)


def snapshot_bundle(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def remove_post_session_artifact(
    manifest_path: Path,
    *,
    package_version: str | None = None,
) -> None:
    manifest = _load_object(manifest_path)
    ref = _evaluation_ref(manifest)
    artifact_path = manifest_path.parent / str(ref["path"])
    artifact_path.unlink()
    outputs = manifest["outputs"]
    assert isinstance(outputs, list)
    outputs.remove(ref)
    if package_version is not None:
        code = manifest["code"]
        assert isinstance(code, dict)
        code["package_version"] = package_version
    _write_manifest(manifest_path, manifest)


def apply_post_session_validation_case(
    manifest_path: Path,
    case: PostSessionValidationCase,
) -> str:
    manifest = _load_object(manifest_path)
    ref = _evaluation_ref(manifest)
    artifact_path = manifest_path.parent / str(ref["path"])

    if case.name == "evaluation-file-missing":
        artifact_path.unlink()
    elif case.name == "evaluation-reference-multiple":
        duplicate = manifest_path.parent / "copy.post_session_evaluation.json"
        duplicate.write_bytes(artifact_path.read_bytes())
        outputs = manifest["outputs"]
        assert isinstance(outputs, list)
        outputs.append(
            {
                "name": duplicate.name,
                "path": duplicate.name,
                "sha256": hashlib.sha256(duplicate.read_bytes()).hexdigest(),
            }
        )
        _write_manifest(manifest_path, manifest)
    elif case.name == "artifact-changed":
        artifact_path.write_bytes(artifact_path.read_bytes() + b" ")
    elif case.name == "manifest-opponent-multiple":
        opponents = manifest["opponents"]
        assert isinstance(opponents, list)
        assert isinstance(opponents[0], dict)
        opponents.append(dict(opponents[0]))
        _write_manifest(manifest_path, manifest)
    else:
        payload = _load_object(artifact_path)
        _mutate_payload(payload, case.name)
        raw = (
            (json.dumps(payload, ensure_ascii=True, indent=2) + "\n").encode("utf-8")
            if case.name == "artifact-noncanonical"
            else canonical_json_bytes(payload)
        )
        artifact_path.write_bytes(raw)
        ref["sha256"] = hashlib.sha256(raw).hexdigest()
        _write_manifest(manifest_path, manifest)

    return manifest_path.name if case.filename_kind == "manifest" else artifact_path.name


def _mutate_payload(payload: dict[str, object], case_name: str) -> None:
    evaluation = payload["evaluation"]
    settings = payload["next_session_settings"]
    assert isinstance(evaluation, dict)
    assert isinstance(settings, dict)
    detector = settings["leak_detector_config"]
    assert isinstance(detector, dict)

    if case_name == "artifact-noncanonical":
        return
    if case_name == "schema-unsupported":
        payload["schema_version"] = "999.0.0"
    elif case_name == "type-unsupported":
        payload["artifact_type"] = "other"
    elif case_name == "evaluation-field-missing":
        evaluation.pop("notes")
    elif case_name == "evaluation-field-extra":
        evaluation["unexpected"] = "value"
    elif case_name == "evaluation-metric-nonfinite":
        evaluation["exploit_ev_gain_vs_base"] = float("nan")
    elif case_name == "evaluation-metric-out-of-range":
        evaluation["leak_detection_accuracy"] = 1.1
    elif case_name == "evaluation-count-invalid":
        evaluation["over_adjustment_count"] = True
    elif case_name == "evaluation-notes-invalid":
        evaluation["notes"] = ["valid", 1]
    elif case_name == "session-mismatch":
        evaluation["session_id"] = "S99999999"
    elif case_name == "opponent-mismatch":
        evaluation["opponent_model_id"] = "other-opponent"
    elif case_name == "alpha-out-of-range":
        settings["safety_alpha"] = -0.1
    elif case_name == "alpha-boolean":
        settings["safety_alpha"] = True
    elif case_name == "epsilon-out-of-range":
        settings["epsilon"] = 1.1
    elif case_name == "detector-config-out-of-range":
        detector["min_deviation"] = 0.0
    elif case_name == "detector-confidence-out-of-range":
        detector["rule_exploit_min_confidence"] = 1.1
    elif case_name == "detector-sample-floor-invalid":
        detector["min_effective_sample_size"] = 0
    elif case_name == "detector-sample-floor-boolean":
        detector["min_effective_sample_size"] = True
    elif case_name == "detector-method-unsupported":
        detector["method_version"] = "other-method"
    else:  # pragma: no cover - keeps the shared case table exhaustive
        raise AssertionError(case_name)


def _load_object(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_bytes())
    assert isinstance(payload, dict)
    return payload


def _evaluation_ref(manifest: dict[str, object]) -> dict[str, object]:
    outputs = manifest["outputs"]
    assert isinstance(outputs, list)
    matches = [
        item
        for item in outputs
        if isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and item["path"].endswith(".post_session_evaluation.json")
    ]
    assert len(matches) == 1
    return matches[0]


def _write_manifest(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
