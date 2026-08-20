"""Explicit, fail-closed handoff of PR #19 next-session settings."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from post_session_validation_support import (
    POST_SESSION_VALIDATION_CASES,
    apply_post_session_validation_case,
    remove_post_session_artifact,
    snapshot_bundle,
)

from poker_ai import run_session_cli
from poker_ai.explanation_artifacts import (
    SavedExplanationBundleVerificationError,
    load_next_session_settings,
    verify_saved_explanation_bundle,
)
from poker_ai.exploit import NodelockExploitProvider, RuleExploitProvider
from poker_ai.opponent import OpponentAnswerKey
from poker_core.dpl_schema import DecisionProvenanceLog
from poker_core.run_manifest import RunManifest


def _run_explanation_bundle(
    root: Path,
    *,
    seed: int,
    hands: int = 3,
    leaky: bool = False,
    leaky_reason: str = "LEAK_R008",
    solver_iterations: int = 1,
    safety_alpha: float | None = None,
    epsilon: float | None = None,
) -> Path:
    argv = [
        "--seed",
        str(seed),
        "--hands",
        str(hands),
        "--solver-iterations",
        str(solver_iterations),
        "--explanations",
        "--out-dir",
        str(root),
    ]
    if leaky:
        argv.insert(-2, "--leaky-fixture")
        if leaky_reason != "LEAK_R008":
            argv[-2:-2] = ["--leaky-fixture-reason", leaky_reason]
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


def test_real_nodelock_provider_is_used_across_two_consecutive_leaky_sessions(
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
    solver_mixed = [log for log in mixed if log.exploit_source == "nodelock_solver"]
    fallback_mixed = [log for log in mixed if log.exploit_source == "rule_based"]
    assert solver_mixed
    assert all(log.solver_result_id for log in solver_mixed)
    assert all(log.solver_result_id is None for log in fallback_mixed)
    assert _estimator(out_dir)["detector_min_confidence"] == (
        restored.leak_detector_config.min_confidence
    )
    assert _execution_sampler(manifest).path == "inline:epsilon-uniform-v1:epsilon=0.2"


def test_r007_two_session_handoff_restores_settings_and_solver_provenance(tmp_path):
    source_root = tmp_path / "r007-source"
    source = _run_explanation_bundle(
        source_root,
        seed=20260704,
        hands=5,
        leaky=True,
        leaky_reason="LEAK_R007",
        solver_iterations=5,
        epsilon=1.0,
    )
    restored = load_next_session_settings(source)
    successor_root = tmp_path / "r007-successor"
    raw_argv = [
        "--seed",
        "20260708",
        "--hands",
        "5",
        "--solver-iterations",
        "5",
        "--leaky-fixture",
        "--leaky-fixture-reason",
        "LEAK_R007",
        "--explanations",
        "--previous-session-manifest",
        str(source),
        "--out-dir",
        str(successor_root),
    ]

    assert run_session_cli.main(raw_argv) == 0

    logs = _dpls(successor_root, 20260708)
    manifest_path = successor_root / "S20260708.manifest.json"
    manifest = _manifest(manifest_path)
    solver_logs = [log for log in logs if log.exploit_source == "nodelock_solver"]
    assert restored.safety_alpha == 1.0
    assert restored.epsilon == 1.0
    assert all(log.safety_alpha == restored.safety_alpha for log in logs)
    assert _execution_sampler(manifest).path == "inline:epsilon-uniform-v1:epsilon=1"
    assert manifest.opponents[0].opponent_id == "stub_check_back_all"
    assert logs[0].detected_leaks == []
    assert solver_logs
    assert all(log.detected_leaks[0].reason_id == "LEAK_R007" for log in solver_logs)
    assert all(log.solver_result_id for log in solver_logs)
    assert verify_saved_explanation_bundle(manifest_path).checker_total == len(logs)


def test_r007_cross_mode_handoff_restores_only_settings(
    tmp_path,
    maintained_source_manifest,
):
    restored = load_next_session_settings(maintained_source_manifest)
    successor_root = tmp_path / "r007-cross-mode-successor"
    raw_argv = [
        "--seed",
        "203",
        "--hands",
        "1",
        "--solver-iterations",
        "1",
        "--leaky-fixture",
        "--leaky-fixture-reason",
        "LEAK_R007",
        "--explanations",
        "--previous-session-manifest",
        str(maintained_source_manifest),
        "--out-dir",
        str(successor_root),
    ]

    assert run_session_cli.main(raw_argv) == 0

    logs = _dpls(successor_root, 203)
    manifest_path = successor_root / "S00000203.manifest.json"
    manifest = _manifest(manifest_path)
    assert logs[0].detected_leaks == []
    assert all(log.safety_alpha == restored.safety_alpha == 0.25 for log in logs)
    assert _execution_sampler(manifest).path == "inline:epsilon-uniform-v1:epsilon=0.2"
    assert _estimator(successor_root)["detector_min_confidence"] == (
        restored.leak_detector_config.min_confidence
    )
    assert manifest.versions.baseline_table_version == "fixture-r007-action-baseline"
    assert manifest.opponents[0].opponent_id == "stub_check_back_all"
    assert "session_mode=r007_no_facing" in manifest.description
    assert verify_saved_explanation_bundle(manifest_path).checker_total == 1


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

    constructed_providers = []

    def record_nodelock_provider(config, *, fallback_provider, confidence_config):
        provider = NodelockExploitProvider(
            config,
            fallback_provider=fallback_provider,
            confidence_config=confidence_config,
        )
        constructed_providers.append(provider)
        return provider

    monkeypatch.setattr(run_session_cli, "NodelockExploitProvider", record_nodelock_provider)

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
                "2",
                "--solver-average-delay",
                "1",
                "--leaky-fixture",
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
    assert len(constructed_providers) == 1
    provider = constructed_providers[0]
    assert provider.config.min_confidence == 1.0
    assert provider.config.iterations == 2
    assert provider.config.average_delay == 1
    assert isinstance(provider.fallback_provider, RuleExploitProvider)
    assert provider.fallback_provider.config.min_confidence == 1.0


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
    POST_SESSION_VALIDATION_CASES,
    ids=lambda case: case.name,
)
def test_current_post_session_validation_is_identical_and_read_only(
    tmp_path,
    monkeypatch,
    normal_source_manifest,
    case,
):
    source_root = tmp_path / "source"
    shutil.copytree(normal_source_manifest.parent, source_root)
    manifest_path = source_root / normal_source_manifest.name
    expected_filename = apply_post_session_validation_case(manifest_path, case)
    before = snapshot_bundle(source_root)

    observed = []
    for validator in (verify_saved_explanation_bundle, load_next_session_settings):
        with pytest.raises(SavedExplanationBundleVerificationError) as raised:
            validator(manifest_path)
        observed.append((raised.value.category, raised.value.filename))
        assert snapshot_bundle(source_root) == before

    assert observed == [(case.category, expected_filename)] * 2

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
    assert snapshot_bundle(source_root) == before


def test_consumer_requires_post_session_reference_before_session_or_output(
    tmp_path,
    monkeypatch,
    normal_source_manifest,
):
    source_root = tmp_path / "source"
    shutil.copytree(normal_source_manifest.parent, source_root)
    manifest_path = source_root / normal_source_manifest.name
    remove_post_session_artifact(manifest_path)
    before = snapshot_bundle(source_root)

    with pytest.raises(SavedExplanationBundleVerificationError) as raised:
        load_next_session_settings(manifest_path)
    assert (raised.value.category, raised.value.filename) == (
        "required-artifact-reference",
        manifest_path.name,
    )
    assert snapshot_bundle(source_root) == before

    def unexpected_session(*_args, **_kwargs):
        raise AssertionError("invalid previous bundle must fail before Hero session start")

    monkeypatch.setattr(run_session_cli, "run_session", unexpected_session)
    out_dir = tmp_path / "must-not-exist"
    assert (
        run_session_cli.main(
            [
                "--previous-session-manifest",
                str(manifest_path),
                "--out-dir",
                str(out_dir),
            ]
        )
        == 1
    )
    assert not out_dir.exists()
    assert snapshot_bundle(source_root) == before


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
                    "13",
                    "--solver-iterations",
                    "1",
                    "--leaky-fixture",
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
    assert any(log.exploit_source == "nodelock_solver" for log in _dpls(roots[0], seed))
    first_manifest = _manifest(roots[0] / f"S{seed:08d}.manifest.json")
    second_manifest = _manifest(roots[1] / f"S{seed:08d}.manifest.json")
    assert _execution_sampler(first_manifest) == _execution_sampler(second_manifest)
