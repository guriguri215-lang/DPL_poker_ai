"""Explicit, fail-closed handoff of PR #19 next-session settings."""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from poker_ai import run_session_cli
from poker_ai.explanation_artifacts import load_next_session_settings
from poker_ai.opponent import OpponentAnswerKey
from poker_ai.posterior_bundle import canonical_json_bytes
from poker_core.dpl_schema import DecisionProvenanceLog
from poker_core.run_manifest import RunManifest


def _run_explanation_bundle(
    root: Path,
    *,
    seed: int,
    hands: int = 3,
    leaky: bool = False,
    safety_alpha: float | None = None,
    epsilon: float | None = None,
) -> Path:
    argv = [
        "--seed",
        str(seed),
        "--hands",
        str(hands),
        "--solver-iterations",
        "1",
        "--explanations",
        "--out-dir",
        str(root),
    ]
    if leaky:
        argv.insert(-2, "--leaky-fixture")
    if safety_alpha is not None:
        argv[0:0] = ["--safety-alpha", str(safety_alpha)]
    if epsilon is not None:
        argv[0:0] = ["--exploration-epsilon", str(epsilon)]
    assert run_session_cli.main(argv) == 0
    return root / f"S{seed:08d}.manifest.json"


@pytest.fixture(scope="module")
def normal_source_manifest(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("normal-previous-session")
    return _run_explanation_bundle(root, seed=101)


@pytest.fixture(scope="module")
def maintained_source_manifest(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("maintained-previous-session")
    return _run_explanation_bundle(
        root,
        seed=102,
        leaky=True,
        safety_alpha=0.25,
        epsilon=0.2,
    )


def _manifest(path: Path) -> RunManifest:
    return RunManifest.model_validate_json(path.read_bytes())


def _dpls(root: Path, seed: int) -> list[DecisionProvenanceLog]:
    path = root / f"S{seed:08d}.dpl.jsonl"
    return [
        DecisionProvenanceLog.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def _estimator(root: Path) -> dict[str, object]:
    path = root / "provenance/leak_confidence_estimator.json"
    return json.loads(path.read_bytes())


def _execution_sampler(manifest: RunManifest):
    matches = [config for config in manifest.configs if config.name == "execution_sampler"]
    assert len(matches) == 1
    return matches[0]


def _evaluation_ref(manifest_payload: dict[str, object]) -> dict[str, object]:
    outputs = manifest_payload["outputs"]
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


def _write_manifest_payload(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _rewrite_evaluation(
    manifest_path: Path,
    mutate: Callable[[dict[str, object]], None],
    *,
    canonical: bool = True,
) -> None:
    manifest = json.loads(manifest_path.read_bytes())
    ref = _evaluation_ref(manifest)
    artifact_path = manifest_path.parent / str(ref["path"])
    payload = json.loads(artifact_path.read_bytes())
    mutate(payload)
    raw = (
        canonical_json_bytes(payload)
        if canonical
        else (json.dumps(payload, ensure_ascii=True, indent=2) + "\n").encode("utf-8")
    )
    artifact_path.write_bytes(raw)
    ref["sha256"] = hashlib.sha256(raw).hexdigest()
    _write_manifest_payload(manifest_path, manifest)


def test_maintained_settings_are_consumed_by_the_next_normal_session(
    tmp_path,
    maintained_source_manifest,
):
    restored = load_next_session_settings(maintained_source_manifest)
    out_dir = tmp_path / "successor"
    seed = 202

    assert (
        run_session_cli.main(
            [
                "--seed",
                str(seed),
                "--hands",
                "2",
                "--solver-iterations",
                "1",
                "--previous-session-manifest",
                str(maintained_source_manifest),
                "--out-dir",
                str(out_dir),
            ]
        )
        == 0
    )

    logs = _dpls(out_dir, seed)
    manifest = _manifest(out_dir / f"S{seed:08d}.manifest.json")
    estimator = _estimator(out_dir)
    assert all(log.safety_alpha == restored.safety_alpha == 0.25 for log in logs)
    assert estimator == {
        "method_version": restored.leak_detector_config.method_version,
        "alpha0": restored.leak_detector_config.alpha0,
        "beta0": restored.leak_detector_config.beta0,
        "tail": restored.leak_detector_config.tail,
        "tau": restored.leak_detector_config.min_deviation,
        "min_effective_sample_size": restored.leak_detector_config.min_effective_sample_size,
        "detector_min_confidence": restored.leak_detector_config.min_confidence,
        "rule_exploit_min_confidence": (restored.leak_detector_config.rule_exploit_min_confidence),
        "nodelock_exploit_min_confidence": (
            restored.leak_detector_config.nodelock_exploit_min_confidence
        ),
        "run_identity": estimator["run_identity"],
        "baseline_table": estimator["baseline_table"],
    }
    sampler = _execution_sampler(manifest)
    assert sampler.path == "inline:epsilon-uniform-v1:epsilon=0.2"


def test_real_rule_provider_is_used_across_two_consecutive_leaky_sessions(
    tmp_path,
    maintained_source_manifest,
):
    out_dir = tmp_path / "leaky-successor"
    seed = 203
    assert (
        run_session_cli.main(
            [
                "--seed",
                str(seed),
                "--hands",
                "12",
                "--solver-iterations",
                "1",
                "--leaky-fixture",
                "--explanations",
                "--previous-session-manifest",
                str(maintained_source_manifest),
                "--out-dir",
                str(out_dir),
            ]
        )
        == 0
    )

    logs = _dpls(out_dir, seed)
    manifest = _manifest(out_dir / f"S{seed:08d}.manifest.json")
    restored = load_next_session_settings(maintained_source_manifest)
    assert all(log.baseline_table_version == "fixture-action-baseline" for log in logs)
    assert all(log.detected_leaks for log in logs)
    mixed = [log for log in logs if log.mix_reasons and "MIX_R001" in log.mix_reasons]
    assert mixed
    assert all(log.exploit_source == "rule_based" for log in mixed)
    assert _estimator(out_dir)["detector_min_confidence"] == (
        restored.leak_detector_config.min_confidence
    )
    assert _execution_sampler(manifest).path == "inline:epsilon-uniform-v1:epsilon=0.2"


def test_conservative_settings_are_consumed_by_the_next_session(tmp_path, monkeypatch):
    source_root = tmp_path / "conservative-source"

    def false_positive_answer_key(*, opponent_model_id: str) -> OpponentAnswerKey:
        return OpponentAnswerKey(
            opponent_model_id=opponent_model_id,
            action_probabilities=(("CHECK", 1.0),),
        )

    monkeypatch.setattr(
        run_session_cli,
        "reveal_stub_opponent_answer_key",
        false_positive_answer_key,
    )
    source = _run_explanation_bundle(
        source_root,
        seed=104,
        leaky=True,
        safety_alpha=0.5,
        epsilon=0.4,
    )
    restored = load_next_session_settings(source)
    assert restored.safety_alpha == restored.epsilon == 0.0
    assert restored.leak_detector_config.min_confidence == 1.0
    assert restored.leak_detector_config.rule_exploit_min_confidence == 1.0
    assert restored.leak_detector_config.nodelock_exploit_min_confidence == 1.0

    successor = tmp_path / "conservative-successor"
    seed = 204
    assert (
        run_session_cli.main(
            [
                "--seed",
                str(seed),
                "--hands",
                "2",
                "--solver-iterations",
                "1",
                "--previous-session-manifest",
                str(source),
                "--out-dir",
                str(successor),
            ]
        )
        == 0
    )
    logs = _dpls(successor, seed)
    estimator = _estimator(successor)
    manifest = _manifest(successor / f"S{seed:08d}.manifest.json")
    assert all(log.safety_alpha == 0.0 for log in logs)
    assert estimator["detector_min_confidence"] == 1.0
    assert estimator["rule_exploit_min_confidence"] == 1.0
    assert estimator["nodelock_exploit_min_confidence"] == 1.0
    assert _execution_sampler(manifest).path == "inline:epsilon-uniform-v1:epsilon=0"


@pytest.mark.parametrize(
    ("alpha", "epsilon"),
    [(0.0, 0.0), (0.75, 0.6)],
)
def test_explicit_alpha_and_epsilon_override_restored_defaults(
    tmp_path,
    maintained_source_manifest,
    alpha,
    epsilon,
):
    out_dir = tmp_path / f"override-{alpha}-{epsilon}"
    seed = 205 if alpha == 0.0 else 206
    assert (
        run_session_cli.main(
            [
                "--seed",
                str(seed),
                "--hands",
                "1",
                "--solver-iterations",
                "1",
                "--previous-session-manifest",
                str(maintained_source_manifest),
                "--safety-alpha",
                str(alpha),
                "--exploration-epsilon",
                str(epsilon),
                "--out-dir",
                str(out_dir),
            ]
        )
        == 0
    )
    logs = _dpls(out_dir, seed)
    manifest = _manifest(out_dir / f"S{seed:08d}.manifest.json")
    assert all(log.safety_alpha == alpha for log in logs)
    assert _execution_sampler(manifest).path == (f"inline:epsilon-uniform-v1:epsilon={epsilon:g}")


def test_omitting_the_source_preserves_normal_and_leaky_defaults(tmp_path):
    cases = (
        ("normal", False, 207, 0.0, 10, 0.95, "0.0.1-stub"),
        ("leaky", True, 208, 1.0, 1, 0.5, "fixture-action-baseline"),
    )
    for name, leaky, seed, alpha, sample_floor, confidence, baseline_version in cases:
        root = tmp_path / name
        argv = [
            "--seed",
            str(seed),
            "--hands",
            "1",
            "--solver-iterations",
            "1",
            "--out-dir",
            str(root),
        ]
        if leaky:
            argv.insert(-2, "--leaky-fixture")
        assert run_session_cli.main(argv) == 0
        logs = _dpls(root, seed)
        manifest = _manifest(root / f"S{seed:08d}.manifest.json")
        estimator = _estimator(root)
        assert logs[0].safety_alpha == alpha
        assert logs[0].baseline_table_version == baseline_version
        assert estimator["min_effective_sample_size"] == sample_floor
        assert estimator["detector_min_confidence"] == confidence
        assert _execution_sampler(manifest).path == "inline:epsilon-uniform-v1:epsilon=0"


@pytest.mark.parametrize(
    "case",
    [
        "evaluation-reference-missing",
        "evaluation-file-missing",
        "evaluation-reference-multiple",
        "artifact-changed",
        "artifact-noncanonical",
        "schema-unsupported",
        "type-unsupported",
        "evaluation-field-missing",
        "evaluation-field-extra",
        "evaluation-metric-nonfinite",
        "evaluation-metric-out-of-range",
        "evaluation-count-invalid",
        "evaluation-notes-invalid",
        "session-mismatch",
        "opponent-mismatch",
        "manifest-opponent-multiple",
        "alpha-out-of-range",
        "alpha-boolean",
        "epsilon-out-of-range",
        "detector-config-out-of-range",
        "detector-confidence-out-of-range",
        "detector-sample-floor-invalid",
        "detector-sample-floor-boolean",
        "detector-method-unsupported",
    ],
)
def test_invalid_previous_bundle_is_rejected_before_session_or_output(
    tmp_path,
    monkeypatch,
    normal_source_manifest,
    case,
):
    source_root = tmp_path / "source"
    shutil.copytree(normal_source_manifest.parent, source_root)
    manifest_path = source_root / normal_source_manifest.name
    manifest = json.loads(manifest_path.read_bytes())
    ref = _evaluation_ref(manifest)
    artifact_path = source_root / str(ref["path"])

    if case == "evaluation-reference-missing":
        manifest["outputs"].remove(ref)
        _write_manifest_payload(manifest_path, manifest)
    elif case == "evaluation-file-missing":
        artifact_path.unlink()
    elif case == "evaluation-reference-multiple":
        duplicate = source_root / "copy.post_session_evaluation.json"
        duplicate.write_bytes(artifact_path.read_bytes())
        manifest["outputs"].append(
            {
                "name": duplicate.name,
                "path": duplicate.name,
                "sha256": hashlib.sha256(duplicate.read_bytes()).hexdigest(),
            }
        )
        _write_manifest_payload(manifest_path, manifest)
    elif case == "artifact-changed":
        artifact_path.write_bytes(artifact_path.read_bytes() + b" ")
    elif case == "artifact-noncanonical":
        _rewrite_evaluation(manifest_path, lambda _payload: None, canonical=False)
    elif case == "schema-unsupported":
        _rewrite_evaluation(
            manifest_path,
            lambda payload: payload.__setitem__("schema_version", "999.0.0"),
        )
    elif case == "type-unsupported":
        _rewrite_evaluation(
            manifest_path,
            lambda payload: payload.__setitem__("artifact_type", "other"),
        )
    elif case == "evaluation-field-missing":
        _rewrite_evaluation(
            manifest_path,
            lambda payload: payload["evaluation"].pop("notes"),
        )
    elif case == "evaluation-field-extra":
        _rewrite_evaluation(
            manifest_path,
            lambda payload: payload["evaluation"].__setitem__("unexpected", "value"),
        )
    elif case == "evaluation-metric-nonfinite":
        _rewrite_evaluation(
            manifest_path,
            lambda payload: payload["evaluation"].__setitem__(
                "exploit_ev_gain_vs_base", float("nan")
            ),
        )
    elif case == "evaluation-metric-out-of-range":
        _rewrite_evaluation(
            manifest_path,
            lambda payload: payload["evaluation"].__setitem__("leak_detection_accuracy", 1.1),
        )
    elif case == "evaluation-count-invalid":
        _rewrite_evaluation(
            manifest_path,
            lambda payload: payload["evaluation"].__setitem__("over_adjustment_count", True),
        )
    elif case == "evaluation-notes-invalid":
        _rewrite_evaluation(
            manifest_path,
            lambda payload: payload["evaluation"].__setitem__("notes", ["valid", 1]),
        )
    elif case == "session-mismatch":
        _rewrite_evaluation(
            manifest_path,
            lambda payload: payload["evaluation"].__setitem__("session_id", "S99999999"),
        )
    elif case == "opponent-mismatch":
        _rewrite_evaluation(
            manifest_path,
            lambda payload: payload["evaluation"].__setitem__(
                "opponent_model_id", "other-opponent"
            ),
        )
    elif case == "manifest-opponent-multiple":
        manifest["opponents"].append(dict(manifest["opponents"][0]))
        _write_manifest_payload(manifest_path, manifest)
    elif case == "alpha-out-of-range":
        _rewrite_evaluation(
            manifest_path,
            lambda payload: payload["next_session_settings"].__setitem__("safety_alpha", -0.1),
        )
    elif case == "alpha-boolean":
        _rewrite_evaluation(
            manifest_path,
            lambda payload: payload["next_session_settings"].__setitem__("safety_alpha", True),
        )
    elif case == "epsilon-out-of-range":
        _rewrite_evaluation(
            manifest_path,
            lambda payload: payload["next_session_settings"].__setitem__("epsilon", 1.1),
        )
    elif case == "detector-config-out-of-range":
        _rewrite_evaluation(
            manifest_path,
            lambda payload: payload["next_session_settings"]["leak_detector_config"].__setitem__(
                "min_deviation", 0.0
            ),
        )
    elif case == "detector-confidence-out-of-range":
        _rewrite_evaluation(
            manifest_path,
            lambda payload: payload["next_session_settings"]["leak_detector_config"].__setitem__(
                "rule_exploit_min_confidence", 1.1
            ),
        )
    elif case == "detector-sample-floor-invalid":
        _rewrite_evaluation(
            manifest_path,
            lambda payload: payload["next_session_settings"]["leak_detector_config"].__setitem__(
                "min_effective_sample_size", 0
            ),
        )
    elif case == "detector-sample-floor-boolean":
        _rewrite_evaluation(
            manifest_path,
            lambda payload: payload["next_session_settings"]["leak_detector_config"].__setitem__(
                "min_effective_sample_size", True
            ),
        )
    elif case == "detector-method-unsupported":
        _rewrite_evaluation(
            manifest_path,
            lambda payload: payload["next_session_settings"]["leak_detector_config"].__setitem__(
                "method_version", "other-method"
            ),
        )
    else:  # pragma: no cover - keeps the mutation table exhaustive
        raise AssertionError(case)

    def unexpected_session(*_args, **_kwargs):
        raise AssertionError("invalid previous bundle must fail before Hero session start")

    monkeypatch.setattr(run_session_cli, "run_session", unexpected_session)
    out_dir = tmp_path / "must-not-exist"
    assert (
        run_session_cli.main(
            [
                "--previous-session-manifest",
                str(manifest_path),
                "--safety-alpha",
                "0.0",
                "--exploration-epsilon",
                "0.0",
                "--out-dir",
                str(out_dir),
            ]
        )
        == 1
    )
    assert not out_dir.exists()


def test_same_previous_manifest_reproduces_dpl_settings_and_artifact_bytes(
    tmp_path,
    maintained_source_manifest,
):
    seed = 209
    roots = [tmp_path / "first", tmp_path / "second"]
    for root in roots:
        assert (
            run_session_cli.main(
                [
                    "--seed",
                    str(seed),
                    "--hands",
                    "3",
                    "--solver-iterations",
                    "1",
                    "--explanations",
                    "--previous-session-manifest",
                    str(maintained_source_manifest),
                    "--out-dir",
                    str(root),
                ]
            )
            == 0
        )

    assert load_next_session_settings(maintained_source_manifest) == load_next_session_settings(
        maintained_source_manifest
    )
    assert (roots[0] / f"S{seed:08d}.dpl.jsonl").read_bytes() == (
        roots[1] / f"S{seed:08d}.dpl.jsonl"
    ).read_bytes()
    assert (roots[0] / "provenance/leak_confidence_estimator.json").read_bytes() == (
        roots[1] / "provenance/leak_confidence_estimator.json"
    ).read_bytes()
    assert (roots[0] / f"S{seed:08d}.post_session_evaluation.json").read_bytes() == (
        roots[1] / f"S{seed:08d}.post_session_evaluation.json"
    ).read_bytes()
    first_manifest = _manifest(roots[0] / f"S{seed:08d}.manifest.json")
    second_manifest = _manifest(roots[1] / f"S{seed:08d}.manifest.json")
    assert _execution_sampler(first_manifest) == _execution_sampler(second_manifest)
