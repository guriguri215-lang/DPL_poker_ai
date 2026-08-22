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


def test_r001_two_session_handoff_is_verified_causal_and_pinned(tmp_path, monkeypatch):
    action_keys = frozenset({"CHECK", "BET_75"})
    opponent_id = "nl-train-r001-d016-s102"
    baseline_version = "river-large-bet-equilibrium-v1-r001-action-baseline"
    observed_action_contracts: list[dict[str, object]] = []
    revealed_opponent_ids: list[str] = []

    class RecordingNodelockExploitProvider(NodelockExploitProvider):
        def build(
            self,
            *,
            base_policy,
            detected_leaks,
            legal_actions,
            action_ev,
            observation=None,
        ):
            result = super().build(
                base_policy=base_policy,
                detected_leaks=detected_leaks,
                legal_actions=legal_actions,
                action_ev=action_ev,
                observation=observation,
            )
            assert observation is not None
            observed_action_contracts.append(
                {
                    "session_id": observation.session_id,
                    "legal_actions": frozenset(legal_actions),
                    "base_policy": frozenset(base_policy),
                    "action_ev": frozenset(action_ev),
                    "exploit_policy": frozenset(result.policy),
                    "nodelock_action_ev": (
                        None
                        if result.decision_action_ev is None
                        else frozenset(result.decision_action_ev)
                    ),
                }
            )
            return result

    real_reveal_answer_key = run_session_cli.reveal_stub_opponent_answer_key

    def record_revealed_answer_key(*, opponent_model_id: str):
        revealed_opponent_ids.append(opponent_model_id)
        return real_reveal_answer_key(opponent_model_id=opponent_model_id)

    monkeypatch.setattr(
        run_session_cli,
        "NodelockExploitProvider",
        RecordingNodelockExploitProvider,
    )
    monkeypatch.setattr(
        run_session_cli,
        "reveal_stub_opponent_answer_key",
        record_revealed_answer_key,
    )

    source_seed = 20260000
    source_root = tmp_path / "r001-source"
    source_manifest_path = _run_explanation_bundle(
        source_root,
        seed=source_seed,
        hands=20,
        leaky=True,
        leaky_reason="LEAK_R001",
        solver_iterations=5,
        epsilon=1.0,
    )
    source_logs = _dpls(source_root, source_seed)
    source_manifest = _manifest(source_manifest_path)
    source_estimator = _estimator(source_root)
    source_baseline = json.loads(
        (source_root / "provenance/action_baseline_table.json").read_bytes()
    )
    source_snapshot = json.loads(
        (source_root / "provenance/action_stats_terminal_snapshots.json").read_bytes()
    )
    source_evaluation = json.loads(
        (source_root / f"S{source_seed:08d}.post_session_evaluation.json").read_bytes()
    )
    source_bundle_before_handoff = snapshot_bundle(source_root)
    source_saved = verify_saved_explanation_bundle(source_manifest_path)
    restored = load_next_session_settings(source_manifest_path)
    restored_payload = restored.to_payload()

    assert source_saved.dpl_count == source_saved.explanation_count == len(source_logs)
    assert source_saved.checker_total == source_saved.checker_passed == len(source_logs)
    assert set(restored_payload) == {"leak_detector_config", "safety_alpha", "epsilon"}
    assert source_evaluation["next_session_settings"] == restored_payload
    assert restored.leak_detector_config.min_deviation == pytest.approx(0.08)
    assert restored.leak_detector_config.min_confidence == pytest.approx(0.5)
    assert restored.leak_detector_config.rule_exploit_min_confidence == pytest.approx(0.95)
    assert restored.leak_detector_config.nodelock_exploit_min_confidence == pytest.approx(0.95)
    assert restored.safety_alpha == restored.epsilon == 1.0

    successor_seed = 20260012
    successor_root = tmp_path / "r001-successor"
    raw_argv = [
        "--seed",
        str(successor_seed),
        "--hands",
        "20",
        "--solver-iterations",
        "5",
        "--leaky-fixture",
        "--leaky-fixture-reason",
        "LEAK_R001",
        "--explanations",
        "--previous-session-manifest",
        str(source_manifest_path),
        "--out-dir",
        str(successor_root),
    ]

    assert run_session_cli.main(raw_argv) == 0
    assert snapshot_bundle(source_root) == source_bundle_before_handoff

    successor_logs = _dpls(successor_root, successor_seed)
    successor_manifest_path = successor_root / f"S{successor_seed:08d}.manifest.json"
    successor_manifest = _manifest(successor_manifest_path)
    successor_estimator = _estimator(successor_root)
    successor_baseline = json.loads(
        (successor_root / "provenance/action_baseline_table.json").read_bytes()
    )
    successor_snapshot = json.loads(
        (successor_root / "provenance/action_stats_terminal_snapshots.json").read_bytes()
    )
    successor_evaluation = json.loads(
        (successor_root / f"S{successor_seed:08d}.post_session_evaluation.json").read_bytes()
    )

    assert source_manifest.run_id == f"S{source_seed:08d}"
    assert successor_manifest.run_id == f"S{successor_seed:08d}"
    assert successor_manifest.run_id != source_manifest.run_id
    assert successor_manifest.code.argv == raw_argv
    assert "session_mode=r001_no_facing" in source_manifest.description
    assert "session_mode=r001_no_facing" in successor_manifest.description
    assert successor_logs[0].detected_leaks == []
    assert source_estimator["run_identity"]["seeds"] == [source_seed]
    assert successor_estimator["run_identity"]["seeds"] == [successor_seed]
    assert successor_estimator["run_identity"]["horizon"] == len(successor_logs)
    assert successor_estimator["run_identity"]["opponent_ids"] == [opponent_id]

    prior_bets: dict[str, int] = {}
    for log in successor_logs:
        for leak in log.detected_leaks:
            assert leak.reason_id == "LEAK_R001"
            assert leak.situation_key.endswith(":IP:river_vs_bet")
            assert leak.effective_sample_size == prior_bets.get(leak.situation_key, 0)
        if log.selected_action == "BET_75":
            situation_key = f"{log.state_cluster}:IP:river_vs_bet"
            prior_bets[situation_key] = prior_bets.get(situation_key, 0) + 1

    source_observations = sum(record["n"] for record in source_snapshot["records"])
    successor_observations = sum(record["n"] for record in successor_snapshot["records"])
    successor_bets = sum(log.selected_action == "BET_75" for log in successor_logs)
    successor_checks = sum(log.selected_action == "CHECK" for log in successor_logs)
    assert source_observations > 0
    assert successor_observations == successor_bets == sum(prior_bets.values())
    assert successor_observations < source_observations + successor_bets
    assert successor_bets > 0
    assert successor_checks > 0
    assert all(record["seed"] == successor_seed for record in successor_snapshot["records"])
    assert all(record["opponent_id"] == opponent_id for record in successor_snapshot["records"])
    assert all(record["rule_id"] == "LEAK_R001" for record in successor_snapshot["records"])
    assert all(record["action_group"] == ["FOLD"] for record in successor_snapshot["records"])
    assert all(
        set(record["action_counts"]) <= {"FOLD", "CALL"}
        and sum(record["action_counts"].values()) == record["n"]
        for record in successor_snapshot["records"]
    )

    assert source_baseline == successor_baseline
    assert successor_baseline["table_version"] == baseline_version
    assert successor_baseline["rules"][0]["reason_id"] == "LEAK_R001"
    assert successor_baseline["rules"][0]["action_group"] == ["FOLD"]
    assert source_manifest.versions.baseline_table_version == baseline_version
    assert successor_manifest.versions.baseline_table_version == baseline_version
    assert successor_estimator["tau"] == restored.leak_detector_config.min_deviation == 0.08
    assert successor_estimator["method_version"] == restored.leak_detector_config.method_version
    assert successor_estimator["alpha0"] == restored.leak_detector_config.alpha0
    assert successor_estimator["beta0"] == restored.leak_detector_config.beta0
    assert successor_estimator["tail"] == restored.leak_detector_config.tail
    assert successor_estimator["min_effective_sample_size"] == (
        restored.leak_detector_config.min_effective_sample_size
    )
    assert successor_estimator["detector_min_confidence"] == (
        restored.leak_detector_config.min_confidence
    )
    assert successor_estimator["rule_exploit_min_confidence"] == (
        restored.leak_detector_config.rule_exploit_min_confidence
    )
    assert successor_estimator["nodelock_exploit_min_confidence"] == (
        restored.leak_detector_config.nodelock_exploit_min_confidence
    )
    assert all(log.safety_alpha == restored.safety_alpha for log in successor_logs)
    assert _execution_sampler(successor_manifest).path == "inline:epsilon-uniform-v1:epsilon=1"

    assert source_manifest.opponents == successor_manifest.opponents
    opponent = successor_manifest.opponents[0]
    assert opponent.opponent_id == opponent_id
    assert opponent.split == "training"
    assert opponent.config is not None
    assert opponent.config.path == "nl-train-r001-d016-s102.opponent.json"

    all_logs = [*source_logs, *successor_logs]
    assert len(observed_action_contracts) == len(all_logs)
    for log in all_logs:
        assert set(log.base_policy) == action_keys
        assert set(log.exploit_policy) == action_keys
        assert set(log.final_policy) == action_keys
        assert log.execution_sampling is not None
        assert set(log.execution_sampling.epsilon_distribution) == action_keys
        assert set(log.execution_sampling.execution_policy) == action_keys
        assert log.selected_action in action_keys
        assert log.ev_estimate.ev_source == "solver_exact"
        assert log.ev_estimate.ev_definition == "incremental_ev_from_current_node"
    for contract in observed_action_contracts:
        assert contract["legal_actions"] == action_keys
        assert contract["base_policy"] == action_keys
        assert contract["action_ev"] == action_keys
        assert contract["exploit_policy"] == action_keys
        if contract["nodelock_action_ev"] is not None:
            assert contract["nodelock_action_ev"] == action_keys

    exact_nodelock_sessions = {
        contract["session_id"]
        for contract in observed_action_contracts
        if contract["nodelock_action_ev"] is not None
    }
    assert exact_nodelock_sessions == {source_manifest.run_id, successor_manifest.run_id}
    source_solver_ref = next(
        config for config in source_manifest.configs if config.role == "solver"
    )
    successor_solver_ref = next(
        config for config in successor_manifest.configs if config.role == "solver"
    )
    assert source_solver_ref == successor_solver_ref
    assert "public_bet=BET_75" in successor_solver_ref.path
    assert "bet_fraction=0.75" in successor_solver_ref.path
    assert "equilibrium=river-large-bet-equilibrium-v1" in successor_solver_ref.path
    assert (
        "artifact=e463a8651412b9569334f27c5fe23d95be7e68f6c6d32d377857bfbf3105aa74"
        in successor_solver_ref.path
    )
    assert all(
        log.base_strategy_provenance.solver_config_sha256 == successor_solver_ref.sha256
        for log in successor_logs
    )

    solver_logs = [
        (index, log)
        for index, log in enumerate(successor_logs)
        if log.exploit_source == "nodelock_solver"
    ]
    assert solver_logs
    for index, log in solver_logs:
        assert index > 0
        leak = log.detected_leaks[0]
        assert leak.reason_id == "LEAK_R001"
        assert leak.effective_sample_size > 0
        assert leak.confidence >= restored.leak_detector_config.nodelock_exploit_min_confidence
        assert leak.observed_rate - leak.baseline_rate >= 0.08
        assert log.solver_result_id is not None
        assert "allocation=baseline_scaled" in log.solver_result_id
        assert "lock_mode=HARD" in log.solver_result_id
        assert "unlocked_policy_mode=fix_to_baseline" in log.solver_result_id
        assert log.ev_estimate.exploit_ev > log.ev_estimate.base_ev

    for manifest_path, evaluation, logs in (
        (source_manifest_path, source_evaluation, source_logs),
        (successor_manifest_path, successor_evaluation, successor_logs),
    ):
        manifest = _manifest(manifest_path)
        assert evaluation["evaluation"]["session_id"] == manifest.run_id
        assert evaluation["evaluation"]["opponent_model_id"] == opponent_id
        assert evaluation["evaluation"]["explanation_validity_score"] == 1.0
        assert set(evaluation["next_session_settings"]) == {
            "leak_detector_config",
            "safety_alpha",
            "epsilon",
        }
        saved = verify_saved_explanation_bundle(manifest_path)
        assert saved.dpl_count == saved.explanation_count == len(logs)
        assert saved.checker_total == saved.checker_passed == len(logs)

    assert (
        load_next_session_settings(successor_manifest_path).to_payload()
        == (successor_evaluation["next_session_settings"])
    )
    assert revealed_opponent_ids == [opponent_id, opponent_id]


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
