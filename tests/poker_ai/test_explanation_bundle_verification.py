from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from poker_ai import explanation_bundle_cli, run_session_cli
from poker_ai.explanation_artifacts import (
    SavedExplanationBundleVerificationError,
    verify_saved_explanation_bundle,
)


def _write_bundle(root: Path, *, leaky: bool = False) -> Path:
    argv = [
        "--seed",
        "20260704",
        "--hands",
        "3",
        "--solver-iterations",
        "1",
        "--explanations",
        "--out-dir",
        str(root),
    ]
    if leaky:
        argv.insert(-2, "--leaky-fixture")
    assert run_session_cli.main(argv) == 0
    return root / "S20260704.manifest.json"


def _payload(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_payload(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _artifact_path(manifest_path: Path, suffix: str) -> Path:
    manifest = _payload(manifest_path)
    matches = [item for item in manifest["outputs"] if item["path"].endswith(suffix)]
    assert len(matches) == 1
    return manifest_path.parent / matches[0]["path"]


def _refresh_hash(manifest_path: Path, suffix: str) -> None:
    manifest = _payload(manifest_path)
    matches = [item for item in manifest["outputs"] if item["path"].endswith(suffix)]
    assert len(matches) == 1
    target = manifest_path.parent / matches[0]["path"]
    matches[0]["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
    _write_payload(manifest_path, manifest)


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.write_text(
        "".join(
            json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records
        ),
        encoding="utf-8",
    )


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _assert_failure_is_read_only(
    root: Path,
    manifest_path: Path,
    category: str,
) -> None:
    before = _snapshot(root)
    with pytest.raises(SavedExplanationBundleVerificationError) as raised:
        verify_saved_explanation_bundle(manifest_path)
    assert raised.value.category == category
    assert _snapshot(root) == before


@pytest.mark.parametrize("leaky", [False, True])
def test_saved_normal_and_leaky_bundles_pass_read_only_verification(tmp_path, leaky):
    root = tmp_path / ("leaky" if leaky else "normal")
    manifest_path = _write_bundle(root, leaky=leaky)
    before = _snapshot(root)

    result = verify_saved_explanation_bundle(manifest_path)

    assert result.artifact_count == 5
    assert result.dpl_count == result.explanation_count == 3
    assert result.checker_total == result.checker_passed == 3
    assert result.summary_consistent
    assert _snapshot(root) == before


def test_hash_mismatch_fails_without_changing_bundle(tmp_path):
    root = tmp_path / "bundle"
    manifest_path = _write_bundle(root)
    explanations = _artifact_path(manifest_path, ".explanations.jsonl")
    explanations.write_bytes(explanations.read_bytes() + b" ")

    _assert_failure_is_read_only(root, manifest_path, "artifact-hash-mismatch")


def test_post_session_evaluation_tamper_is_rejected_by_artifact_hash(tmp_path):
    root = tmp_path / "bundle"
    manifest_path = _write_bundle(root)
    evaluation = _artifact_path(manifest_path, ".post_session_evaluation.json")
    evaluation.write_bytes(evaluation.read_bytes() + b" ")

    _assert_failure_is_read_only(root, manifest_path, "artifact-hash-mismatch")


def test_missing_required_file_fails_without_creating_output(tmp_path):
    root = tmp_path / "bundle"
    manifest_path = _write_bundle(root)
    _artifact_path(manifest_path, ".verifier_summary.json").unlink()

    _assert_failure_is_read_only(root, manifest_path, "artifact-missing")


def test_count_mismatch_is_detected_after_artifact_integrity(tmp_path):
    root = tmp_path / "bundle"
    manifest_path = _write_bundle(root)
    explanations_path = _artifact_path(manifest_path, ".explanations.jsonl")
    explanations = _jsonl(explanations_path)
    _write_jsonl(explanations_path, explanations[:-1])
    _refresh_hash(manifest_path, ".explanations.jsonl")

    _assert_failure_is_read_only(root, manifest_path, "pairing-count-mismatch")


def test_order_mismatch_is_detected_after_checking_all_pairs(tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    manifest_path = _write_bundle(root)
    explanations_path = _artifact_path(manifest_path, ".explanations.jsonl")
    explanations = _jsonl(explanations_path)
    _write_jsonl(explanations_path, list(reversed(explanations)))
    _refresh_hash(manifest_path, ".explanations.jsonl")

    from poker_ai import explanation_artifacts

    original = explanation_artifacts.verify_explanation
    checked: list[str] = []

    def recording_checker(explanation, dpl):
        checked.append(dpl.hand_id)
        return original(explanation, dpl)

    monkeypatch.setattr(explanation_artifacts, "verify_explanation", recording_checker)
    _assert_failure_is_read_only(root, manifest_path, "pairing-order-mismatch")
    assert len(checked) == 3


def test_session_id_mismatch_is_rejected(tmp_path):
    root = tmp_path / "bundle"
    manifest_path = _write_bundle(root)
    dpl_path = _artifact_path(manifest_path, ".dpl.jsonl")
    dpls = _jsonl(dpl_path)
    dpls[0]["session_id"] = "S99999999"
    _write_jsonl(dpl_path, dpls)
    _refresh_hash(manifest_path, ".dpl.jsonl")

    _assert_failure_is_read_only(root, manifest_path, "pairing-session-id-mismatch")


def test_hand_id_mismatch_is_rejected(tmp_path):
    root = tmp_path / "bundle"
    manifest_path = _write_bundle(root)
    explanations_path = _artifact_path(manifest_path, ".explanations.jsonl")
    explanations = _jsonl(explanations_path)
    explanations[0]["dpl_ref"] = "S20260704:S20260704-H99999"
    _write_jsonl(explanations_path, explanations)
    _refresh_hash(manifest_path, ".explanations.jsonl")

    _assert_failure_is_read_only(root, manifest_path, "pairing-hand-id-mismatch")


def test_modified_explanation_reaches_existing_checker_and_fails(tmp_path):
    root = tmp_path / "bundle"
    manifest_path = _write_bundle(root)
    explanations_path = _artifact_path(manifest_path, ".explanations.jsonl")
    explanations = _jsonl(explanations_path)
    explanations[0]["rendered_text"] += " altered"
    _write_jsonl(explanations_path, explanations)
    _refresh_hash(manifest_path, ".explanations.jsonl")

    _assert_failure_is_read_only(root, manifest_path, "explanation-checker-failed")


def test_verifier_summary_result_mismatch_is_rejected(tmp_path):
    root = tmp_path / "bundle"
    manifest_path = _write_bundle(root)
    summary_path = _artifact_path(manifest_path, ".verifier_summary.json")
    summary = _payload(summary_path)
    summary["verification"]["total"] += 1
    _write_payload(summary_path, summary)
    _refresh_hash(manifest_path, ".verifier_summary.json")

    _assert_failure_is_read_only(root, manifest_path, "verifier-summary-mismatch")


def test_artifact_reference_cannot_escape_bundle_root(tmp_path):
    root = tmp_path / "bundle"
    manifest_path = _write_bundle(root)
    dpl_path = _artifact_path(manifest_path, ".dpl.jsonl")
    outside = tmp_path / "outside.dpl.jsonl"
    outside.write_bytes(dpl_path.read_bytes())
    manifest = _payload(manifest_path)
    dpl_ref = next(item for item in manifest["outputs"] if item["path"].endswith(".dpl.jsonl"))
    dpl_ref["path"] = "../outside.dpl.jsonl"
    dpl_ref["sha256"] = hashlib.sha256(outside.read_bytes()).hexdigest()
    _write_payload(manifest_path, manifest)

    _assert_failure_is_read_only(tmp_path, manifest_path, "artifact-path-invalid")


def test_a8_normal_bundle_format_remains_loadable(tmp_path):
    root = tmp_path / "bundle"
    manifest_path = _write_bundle(root)
    manifest = _payload(manifest_path)
    manifest["code"]["package_version"] = "0.1.0a8"
    evaluation_refs = [
        item
        for item in manifest["outputs"]
        if item["path"].endswith(".post_session_evaluation.json")
    ]
    assert len(evaluation_refs) == 1
    (root / evaluation_refs[0]["path"]).unlink()
    manifest["outputs"] = [
        item
        for item in manifest["outputs"]
        if not item["path"].endswith(".post_session_evaluation.json")
    ]
    _write_payload(manifest_path, manifest)

    result = verify_saved_explanation_bundle(manifest_path)

    assert result.checker_passed == 3


def test_distribution_cli_reports_only_bundle_and_checker_results(tmp_path, capsys):
    root = tmp_path / "bundle"
    manifest_path = _write_bundle(root)
    capsys.readouterr()
    before = _snapshot(root)

    assert explanation_bundle_cli.main(["--manifest", str(manifest_path)]) == 0

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.splitlines() == [
        "artifact_integrity=passed references=5",
        "explanation_checker=passed total=3 summary=consistent",
    ]
    assert _snapshot(root) == before


def test_distribution_cli_failure_has_no_partial_success_output(tmp_path, capsys):
    root = tmp_path / "bundle"
    manifest_path = _write_bundle(root)
    explanations = _artifact_path(manifest_path, ".explanations.jsonl")
    explanations.write_bytes(explanations.read_bytes() + b" ")
    capsys.readouterr()
    before = _snapshot(root)

    assert explanation_bundle_cli.main(["--manifest", str(manifest_path)]) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "category=artifact-hash-mismatch" in captured.err
    assert _snapshot(root) == before


def test_distribution_cli_version_writes_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit) as stopped:
        explanation_bundle_cli.main(["--version"])

    assert stopped.value.code == 0
    assert capsys.readouterr().out == "poker-xai-verify-explanation-bundle 0.1.0a9\n"
    assert tuple(tmp_path.iterdir()) == ()
