"""End-to-end tests for the vertical-slice session (task-3 acceptance criteria)."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
from pathlib import Path

import pytest

from explanation import (
    ExplanationDocument,
    VerificationIssue,
    VerificationResult,
    verify_explanation,
)
from poker_ai.base_policy import StubBasePolicyProvider
from poker_ai.cfr_policy import (
    CFR_RIVER_POLICY_SOURCE,
    DEFAULT_CFR_RIVER_POLICY_CONFIG,
    CfrRiverPolicyConfig,
    CfrRiverPolicyProvider,
)
from poker_ai.exploit import RuleExploitResult
from poker_ai.leak import (
    BET_ACTIONS,
    ActionBaselineTable,
    ActionLeakRule,
    LeakDetector,
    LeakDetectorConfig,
    leaky_fixture_action_baseline_table,
)
from poker_ai.posterior_bundle import load_posterior_run_bundle
from poker_ai.session import (
    EV_SOURCE,
    build_manifest,
    iter_session_logs,
    run_session,
    write_session_bundle,
)
from poker_core.dpl_schema import DecisionProvenanceLog
from poker_core.run_manifest import RunManifest
from poker_core.state_cluster import cluster_def_version

HANDS = 120  # exceeds the 100-hand acceptance floor
STUB_PROVIDER = StubBasePolicyProvider()


def _iter_stub(*args, **kwargs):
    kwargs["_base_policy_provider"] = STUB_PROVIDER
    return iter_session_logs(*args, **kwargs)


def _run_stub(*args, **kwargs):
    kwargs["_base_policy_provider"] = STUB_PROVIDER
    return run_session(*args, **kwargs)


def test_runs_over_100_hands_all_dpl_valid():
    logs = list(_iter_stub(20260704, HANDS))
    assert len(logs) == HANDS
    for log in logs:
        assert isinstance(log, DecisionProvenanceLog)
        # Re-validate the serialised form against the frozen schema (round-trip).
        DecisionProvenanceLog.model_validate(log.model_dump(mode="json"))


def test_normal_session_uses_cfr_policy_and_consistent_provenance():
    config = CfrRiverPolicyConfig(iterations=5, average_delay=0, checkpoints=())

    first = run_session(20260704, 1, solver_config=config)
    second = run_session(20260704, 1, solver_config=config)
    first_log = first.logs[0]
    second_log = second.logs[0]
    solver_refs = [config for config in first.manifest.configs if config.role == "solver"]

    assert first_log == second_log
    assert first_log.base_strategy_provenance.source == CFR_RIVER_POLICY_SOURCE
    assert (
        first_log.base_strategy_provenance.table_version
        == first.manifest.versions.strategy_table_version
    )
    assert len(solver_refs) == 1
    assert first_log.base_strategy_provenance.solver_config_sha256 == solver_refs[0].sha256
    assert set(first_log.base_policy) == {"FOLD", "CALL"}
    assert math.fsum(first_log.base_policy.values()) == pytest.approx(1.0)


def test_cfr_base_policy_composes_with_existing_safety_mix():
    result = run_session(
        20260704,
        1,
        leak_detector=_positive_fixture_detector(),
        safety_alpha=0.25,
        exploit_provider=_StaticExploitProvider(),
        solver_config=CfrRiverPolicyConfig(iterations=1, average_delay=0, checkpoints=()),
    )
    log = result.logs[0]

    assert log.base_strategy_provenance.source == CFR_RIVER_POLICY_SOURCE
    for action in set(log.base_policy) | set(log.exploit_policy):
        expected = 0.75 * log.base_policy.get(action, 0.0) + 0.25 * log.exploit_policy.get(
            action, 0.0
        )
        assert log.final_policy.get(action, 0.0) == pytest.approx(expected)
    assert log.mix_reasons == ["MIX_R001"]


def test_ev_source_is_solver_exact_only():
    for log in _iter_stub(20260704, HANDS):
        assert log.ev_estimate.ev_source == EV_SOURCE == "solver_exact"
        assert log.ev_estimate.ev_definition == "incremental_ev_from_current_node"
        assert math.isfinite(log.ev_estimate.final_ev)
        # Only solver_exact EVs are cleared for explanations (ADR-0008).
        assert log.ev_for_explanation() is not None


def test_alpha_zero_and_closed_world_reason_fields():
    for log in _iter_stub(20260704, HANDS):
        assert log.safety_alpha == 0.0
        assert log.final_policy == log.base_policy
        assert log.exploit_policy == log.base_policy
        assert log.detected_leaks == []
        assert log.trigger_reasons == []
        assert log.mix_reasons == []
        assert log.allowed_reason_ids == []  # nothing to cite when nothing is adjusted
        assert log.exploit_source == "rule_based"
        assert log.solver_result_id is None
        assert log.selected_action in log.final_policy


def test_positive_leak_fixture_is_written_to_dpl_closed_world():
    leak_detector = _positive_fixture_detector()

    logs = list(_iter_stub(20260704, 3, leak_detector=leak_detector))
    assert len(logs) == 3
    for log in logs:
        assert log.detected_leaks
        assert log.allowed_reason_ids == ["LEAK_R008"]
        assert log.trigger_reasons == []
        assert log.mix_reasons == []
        assert log.safety_alpha == 0.0
        assert log.exploit_policy == log.base_policy
        DecisionProvenanceLog.model_validate(log.model_dump(mode="json"))


def test_positive_alpha_writes_rule_exploit_reasons_closed_world():
    result = _run_stub(
        20260704,
        1,
        leak_detector=_positive_fixture_detector(),
        safety_alpha=1.0,
        exploit_provider=_StaticExploitProvider(),
    )
    log = result.logs[0]

    assert log.detected_leaks
    assert log.safety_alpha == 1.0
    assert log.exploit_policy == {"CALL": 1.0}
    assert log.final_policy["CALL"] == 1.0
    assert all(prob == 0.0 for action, prob in log.final_policy.items() if action != "CALL")
    assert log.trigger_reasons == ["TRG_R001", "TRG_R002"]
    assert log.mix_reasons == ["MIX_R001"]
    assert log.allowed_reason_ids == ["LEAK_R008", "TRG_R001", "TRG_R002", "MIX_R001"]
    assert log.ev_estimate.final_ev == log.ev_estimate.exploit_ev
    assert "safety_alpha=1.0" in result.manifest.description
    DecisionProvenanceLog.model_validate(log.model_dump(mode="json"))


def test_epsilon_one_writes_epsilon_reason_and_manifest_config():
    result = _run_stub(20260704, 5, exploration_epsilon=1.0)

    assert "exploration_epsilon=1.0" in result.manifest.description
    sampler_configs = [c for c in result.manifest.configs if c.name == "execution_sampler"]
    assert len(sampler_configs) == 1
    assert sampler_configs[0].path == "inline:epsilon-uniform-v1:epsilon=1"

    for log in result.logs:
        assert log.final_policy == log.base_policy
        assert log.mix_reasons == ["MIX_EPSILON"]
        assert log.allowed_reason_ids == ["MIX_EPSILON"]
        assert log.execution_sampling is not None
        assert log.execution_sampling.epsilon == 1.0
        assert set(log.execution_sampling.epsilon_distribution) == {"FOLD", "CALL"}
        assert log.selected_action in log.execution_sampling.epsilon_distribution
        DecisionProvenanceLog.model_validate(log.model_dump(mode="json"))


def test_epsilon_only_does_not_allow_policy_reasons_from_exploit_provider():
    result = _run_stub(
        20260704,
        1,
        leak_detector=_positive_fixture_detector(),
        safety_alpha=0.0,
        exploration_epsilon=1.0,
        exploit_provider=_StaticExploitProvider(),
    )
    log = result.logs[0]

    assert log.detected_leaks
    assert log.final_policy == log.base_policy
    assert log.exploit_policy == {"CALL": 1.0}
    assert log.trigger_reasons == []
    assert log.mix_reasons == ["MIX_EPSILON"]
    assert log.allowed_reason_ids == ["MIX_EPSILON"]
    assert log.execution_sampling is not None
    DecisionProvenanceLog.model_validate(log.model_dump(mode="json"))


def test_positive_alpha_writes_nodelock_solver_provenance_to_dpl():
    result = _run_stub(
        20260704,
        1,
        leak_detector=_positive_fixture_detector(),
        safety_alpha=1.0,
        exploit_provider=_StaticNodelockProvider(),
    )
    log = result.logs[0]

    assert log.detected_leaks
    assert log.exploit_source == "nodelock_solver"
    assert log.solver_result_id is not None
    assert "allocation=baseline_scaled" in log.solver_result_id
    assert "lock_mode=HARD" in log.solver_result_id
    assert "unlocked_policy_mode=fix_to_baseline" in log.solver_result_id
    assert log.allowed_reason_ids == ["LEAK_R008", "TRG_R001", "TRG_R002", "MIX_R001"]
    DecisionProvenanceLog.model_validate(log.model_dump(mode="json"))


def test_custom_leak_baseline_version_is_stamped_on_manifest_and_logs():
    leak_detector = _positive_fixture_detector()
    result = _run_stub(20260704, 1, leak_detector=leak_detector)

    assert result.logs[0].baseline_table_version == "fixture-action-baseline"
    assert result.manifest.versions.baseline_table_version == "fixture-action-baseline"
    baseline_configs = [c for c in result.manifest.configs if c.name == "action_baseline_table"]
    assert len(baseline_configs) == 1
    assert baseline_configs[0].path == "provenance/action_baseline_table.json"
    assert len(baseline_configs[0].sha256) == 64


def _positive_fixture_detector() -> LeakDetector:
    return LeakDetector(
        ActionBaselineTable(
            "fixture-action-baseline",
            (
                ActionLeakRule(
                    reason_id="LEAK_R008",
                    leak_type="bet_too_often_when_checked_to",
                    action_group=BET_ACTIONS,
                    baseline_rate=0.0,
                    direction="decrease_bet_frequency_when_checked_to",
                ),
            ),
        ),
        LeakDetectorConfig(
            min_effective_sample_size=1,
            min_deviation=0.25,
            min_confidence=0.5,
        ),
    )


class _StaticExploitProvider:
    def build(self, **_kwargs) -> RuleExploitResult:
        return RuleExploitResult(
            policy={"CALL": 1.0},
            applied_leak_reason_ids=("LEAK_R008",),
            trigger_reasons=("TRG_R001", "TRG_R002"),
        )


class _StaticNodelockProvider:
    def build(self, **_kwargs) -> RuleExploitResult:
        return RuleExploitResult(
            policy={"CALL": 1.0},
            applied_leak_reason_ids=("LEAK_R008",),
            trigger_reasons=("TRG_R001", "TRG_R002"),
            exploit_source="nodelock_solver",
            solver_result_id=(
                "nodelock_solver:v1:allocation=baseline_scaled:lock_mode=HARD:"
                "unlocked_policy_mode=fix_to_baseline:digest=test"
            ),
        )


def test_versions_are_stamped_on_every_log():
    default_detector = LeakDetector()
    for log in _iter_stub(20260704, HANDS):
        assert log.cluster_def_version == cluster_def_version()
        assert log.cluster_def_version == "0.1.0"
        assert log.baseline_table_version == default_detector.baseline_table_version
        assert log.baseline_table_version.endswith("-stub")
        assert log.base_strategy_provenance.table_version.endswith("-stub")
        assert log.base_strategy_provenance.source == "task3_stub_baseline"


def test_hand_buckets_and_actions_have_variety():
    logs = list(_iter_stub(20260704, HANDS))
    buckets = {log.hand_bucket for log in logs}
    actions = {log.selected_action for log in logs}
    # The generated session should exercise more than one bucket and both actions.
    assert len(buckets) >= 3
    assert actions == {"FOLD", "CALL"}


def test_seed_reproducible_jsonl(tmp_path):
    first = _run_stub(42, HANDS)
    second = _run_stub(42, HANDS)
    a, _ = write_session_bundle(first, tmp_path / "a")
    b, _ = write_session_bundle(second, tmp_path / "b")
    assert a.read_bytes() == b.read_bytes()


def test_different_seed_changes_output():
    a = [log.model_dump(mode="json") for log in _iter_stub(1, HANDS)]
    b = [log.model_dump(mode="json") for log in _iter_stub(2, HANDS)]
    assert a != b


def test_manifest_is_valid_and_pins_versions_and_configs():
    manifest = build_manifest(20260704, HANDS, git_commit="unknown")
    assert isinstance(manifest, RunManifest)
    assert manifest.code.package_version == "0.1.0a9"
    assert manifest.code.git_dirty is None
    assert manifest.code.entrypoint == "poker_ai.session.run_session"
    assert manifest.code.argv == []
    assert manifest.seeds["master"] == 20260704
    assert manifest.versions.cluster_def_version == cluster_def_version()
    assert (
        manifest.versions.strategy_table_version
        == CfrRiverPolicyProvider(DEFAULT_CFR_RIVER_POLICY_CONFIG).strategy_version
    )
    assert manifest.versions.baseline_table_version == LeakDetector().baseline_table_version
    # Every referenced config carries a content hash (auditable provenance).
    roles = {c.role for c in manifest.configs}
    assert {"cluster_def", "solver", "baseline_table", "other"} <= roles
    for config in manifest.configs:
        assert len(config.sha256) == 64
    assert manifest.opponents[0].opponent_id == "stub_jam_all"


def test_manifest_config_hashes_are_reproducible():
    first = build_manifest(1, HANDS)
    second = build_manifest(1, HANDS)
    assert [c.sha256 for c in first.configs] == [c.sha256 for c in second.configs]


def test_posterior_1000_hand_session_regression():
    result = _run_stub(20260710, 1000)

    assert len(result.logs) == 1000
    assert all(log.schema_version == "3.0.0" for log in result.logs)
    snapshot = json.loads(
        result.posterior_bundle.artifacts["provenance/action_stats_terminal_snapshots.json"]
    )
    r007_records = [record for record in snapshot["records"] if record["rule_id"] == "LEAK_R007"]
    assert sum(record["n"] for record in r007_records) == 1000


def test_run_session_writes_and_reloads(tmp_path):
    result = _run_stub(7, HANDS, git_commit="unknown")
    jsonl_path, manifest_path = write_session_bundle(result, tmp_path)

    lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == HANDS
    for line in lines:
        DecisionProvenanceLog.model_validate(json.loads(line))

    reloaded = RunManifest.model_validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    assert reloaded.run_id == result.session_id
    validated = load_posterior_run_bundle(manifest_path)
    assert validated.manifest.run_id == result.session_id


def test_leaky_fixture_cli_smoke_writes_detected_leaks_and_mix(tmp_path, capsys):
    cli = _load_cli_module()
    raw_argv = [
        "--seed",
        "20260704",
        "--hands",
        "12",
        "--solver-iterations",
        "1",
        "--safety-alpha",
        "0.25",
        "--leaky-fixture",
        "--out-dir",
        str(tmp_path),
    ]

    rc = cli.main(raw_argv)

    assert rc == 0
    out = capsys.readouterr().out
    assert "detected_leaks=12" in out
    assert "mixed_decisions=" in out
    jsonl_path = tmp_path / "S20260704.dpl.jsonl"
    manifest_path = tmp_path / "S20260704.manifest.json"
    logs = [
        DecisionProvenanceLog.model_validate(json.loads(line))
        for line in jsonl_path.read_text(encoding="utf-8").splitlines()
    ]
    manifest = RunManifest.model_validate(json.loads(manifest_path.read_text(encoding="utf-8")))

    assert len(logs) == 12
    assert all(log.detected_leaks for log in logs)
    assert all(
        log.baseline_table_version == leaky_fixture_action_baseline_table().table_version
        for log in logs
    )
    improved = [log for log in logs if log.ev_estimate.exploit_ev > log.ev_estimate.base_ev]
    unchanged = [log for log in logs if log.ev_estimate.exploit_ev == log.ev_estimate.base_ev]
    non_improving = [
        log
        for log in unchanged
        if any(leak.confidence >= 0.95 for leak in log.detected_leaks)
        and log.base_policy.get("FOLD", 0.0) > 0.0
        and log.ev_estimate.base_ev < 0.0
    ]
    assert improved
    assert non_improving
    for log in improved:
        assert log.exploit_source == "rule_based"
        assert log.trigger_reasons == ["TRG_R001", "TRG_R002"]
        assert log.mix_reasons == ["MIX_R001"]
        assert all(
            log.final_policy[action]
            == pytest.approx(
                (1.0 - log.safety_alpha) * log.base_policy.get(action, 0.0)
                + log.safety_alpha * log.exploit_policy.get(action, 0.0)
            )
            for action in set(log.base_policy) | set(log.exploit_policy)
        )
    for log in unchanged:
        assert log.exploit_policy == log.base_policy
        assert log.final_policy == log.base_policy
        assert log.trigger_reasons == []
        assert log.mix_reasons == []
    estimator = json.loads(
        (tmp_path / "provenance/leak_confidence_estimator.json").read_text(encoding="utf-8")
    )
    assert estimator["detector_min_confidence"] == 0.5
    assert estimator["rule_exploit_min_confidence"] == 0.95
    assert manifest.versions.baseline_table_version == "fixture-action-baseline"
    assert manifest.code.package_version == "0.1.0a9"
    assert manifest.code.entrypoint == "cli/run_session.py"
    assert manifest.code.argv == raw_argv
    assert {
        path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*") if path.is_file()
    } == {
        "S20260704.dpl.jsonl",
        "S20260704.manifest.json",
        "provenance/action_baseline_table.json",
        "provenance/action_stats_terminal_snapshots.json",
        "provenance/leak_confidence_estimator.json",
    }


@pytest.mark.parametrize("leaky_fixture", [False, True])
def test_explanations_flag_writes_verified_one_to_one_bundle(
    tmp_path,
    capsys,
    leaky_fixture,
):
    from poker_ai import run_session_cli

    hands = 12 if leaky_fixture else 3
    raw_argv = [
        "--seed",
        "20260704",
        "--hands",
        str(hands),
        "--solver-iterations",
        "1",
        "--explanations",
        "--out-dir",
        str(tmp_path),
    ]
    if leaky_fixture:
        raw_argv.insert(-2, "--leaky-fixture")

    assert run_session_cli.main(raw_argv) == 0
    assert f"explanations_verified={hands}" in capsys.readouterr().out

    dpl_path = tmp_path / "S20260704.dpl.jsonl"
    explanations_path = tmp_path / "S20260704.explanations.jsonl"
    summary_path = tmp_path / "S20260704.verifier_summary.json"
    evaluation_path = tmp_path / "S20260704.post_session_evaluation.json"
    manifest_path = tmp_path / "S20260704.manifest.json"
    dpls = [
        DecisionProvenanceLog.model_validate(json.loads(line))
        for line in dpl_path.read_text(encoding="utf-8").splitlines()
    ]
    explanations = [
        ExplanationDocument.model_validate(json.loads(line))
        for line in explanations_path.read_text(encoding="utf-8").splitlines()
    ]

    assert len(dpls) == len(explanations) == hands
    assert [item.dpl_ref for item in explanations] == [
        f"{dpl.session_id}:{dpl.hand_id}" for dpl in dpls
    ]
    for dpl, explanation in zip(dpls, explanations, strict=True):
        verified = verify_explanation(explanation, dpl)
        assert verified.passed, verified.issues
    if leaky_fixture:
        assert all(dpl.detected_leaks for dpl in dpls)
        assert any(dpl.mix_reasons for dpl in dpls)
    else:
        assert all(not dpl.detected_leaks for dpl in dpls)

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["metadata"]["artifact_id"] == "hero_session_explanation_artifacts"
    assert summary["metadata"]["leaky_fixture"] is leaky_fixture
    assert summary["session"]["session_id"] == "S20260704"
    assert summary["session"]["dpl_count"] == summary["session"]["explanation_count"] == hands
    assert summary["verification"] == {
        "total": hands,
        "passed": hands,
        "failed": 0,
        "pass_rate": 1.0,
        "failures": [],
    }

    evaluation_bytes = evaluation_path.read_bytes()
    evaluation = json.loads(evaluation_bytes)
    assert evaluation_bytes == (
        json.dumps(evaluation, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")
    assert evaluation["schema_version"] == "1.0.0"
    assert evaluation["artifact_type"] == "post_session_answer_key_evaluation"
    metrics = evaluation["evaluation"]
    assert metrics["session_id"] == "S20260704"
    assert metrics["opponent_model_id"] == "stub_jam_all"
    assert metrics["leak_detection_accuracy"] == 1.0
    assert metrics["average_estimation_error"] == 0.0
    assert metrics["over_adjustment_count"] == 0
    assert metrics["under_adjustment_count"] == 0
    assert metrics["explanation_validity_score"] == 1.0
    next_settings = evaluation["next_session_settings"]
    if leaky_fixture:
        assert metrics["exploit_ev_gain_vs_base"] > 0.0
        assert next_settings["safety_alpha"] == 1.0
        assert next_settings["leak_detector_config"]["min_confidence"] == 0.5
    else:
        assert metrics["exploit_ev_gain_vs_base"] == 0.0
        assert next_settings["safety_alpha"] == 0.0
        assert next_settings["leak_detector_config"]["min_confidence"] == 0.95
    assert next_settings["epsilon"] == 0.0

    manifest = RunManifest.model_validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    assert manifest.code.argv == raw_argv
    assert [output.name for output in manifest.outputs] == [
        "action_stats_terminal_snapshots",
        "S20260704.dpl.jsonl",
        "S20260704.explanations.jsonl",
        "S20260704.verifier_summary.json",
        "S20260704.post_session_evaluation.json",
    ]
    for output in manifest.outputs:
        assert not Path(output.path).is_absolute()
        target = tmp_path / output.path
        assert target.is_file()
        assert output.sha256 == hashlib.sha256(target.read_bytes()).hexdigest()


def test_explanation_verification_failure_checks_all_and_writes_nothing(
    tmp_path,
    monkeypatch,
    capsys,
):
    from poker_ai import explanation_artifacts, run_session_cli

    out_dir = tmp_path / "fresh"
    verified_refs = []

    def reject(_explanation, dpl):
        verified_refs.append(f"{dpl.session_id}:{dpl.hand_id}")
        return VerificationResult(
            (
                VerificationIssue(
                    code="injected_failure",
                    location="test",
                    message="injected verification failure",
                ),
            )
        )

    monkeypatch.setattr(explanation_artifacts, "verify_explanation", reject)
    rc = run_session_cli.main(
        [
            "--seed",
            "20260704",
            "--hands",
            "3",
            "--solver-iterations",
            "1",
            "--explanations",
            "--out-dir",
            str(out_dir),
        ]
    )

    assert rc == 1
    assert len(verified_refs) == 3
    assert len(set(verified_refs)) == 3
    assert "explanation verification failed" in capsys.readouterr().err
    assert not out_dir.exists()


def test_explanation_generation_failure_writes_nothing(tmp_path, monkeypatch):
    from poker_ai import explanation_artifacts, run_session_cli

    out_dir = tmp_path / "fresh"

    def reject(_dpl):
        raise RuntimeError("injected explanation generation failure")

    monkeypatch.setattr(explanation_artifacts, "generate_template_explanation", reject)
    with pytest.raises(RuntimeError, match="injected explanation generation failure"):
        run_session_cli.main(
            [
                "--seed",
                "20260704",
                "--hands",
                "1",
                "--solver-iterations",
                "1",
                "--explanations",
                "--out-dir",
                str(out_dir),
            ]
        )
    assert not out_dir.exists()


def test_answer_key_reveal_occurs_after_all_decisions_without_hidden_strategy_read(
    tmp_path,
    monkeypatch,
):
    from poker_ai import run_session_cli
    from poker_ai.decision import HeroAgent
    from poker_ai.opponent import StubOpponent

    source_root = tmp_path / "source"
    assert (
        run_session_cli.main(
            [
                "--seed",
                "6",
                "--hands",
                "1",
                "--solver-iterations",
                "1",
                "--explanations",
                "--out-dir",
                str(source_root),
            ]
        )
        == 0
    )
    previous_manifest = source_root / "S00000006.manifest.json"

    events: list[str] = []
    hidden_reads: list[str] = []
    original_decide = HeroAgent.decide
    original_reveal = run_session_cli.reveal_stub_opponent_answer_key

    def recording_decide(self, *args, **kwargs):
        result = original_decide(self, *args, **kwargs)
        events.append("decision-complete")
        return result

    def recording_reveal(*, opponent_model_id):
        events.append("answer-key-revealed")
        return original_reveal(opponent_model_id=opponent_model_id)

    def forbidden_hidden_strategy_read(_self):
        hidden_reads.append("read")
        raise AssertionError("normal Hero must not read hidden_strategy")

    monkeypatch.setattr(HeroAgent, "decide", recording_decide)
    monkeypatch.setattr(run_session_cli, "reveal_stub_opponent_answer_key", recording_reveal)
    monkeypatch.setattr(
        StubOpponent,
        "hidden_strategy",
        property(forbidden_hidden_strategy_read),
    )

    assert (
        run_session_cli.main(
            [
                "--seed",
                "7",
                "--hands",
                "3",
                "--solver-iterations",
                "1",
                "--explanations",
                "--previous-session-manifest",
                str(previous_manifest),
                "--out-dir",
                str(tmp_path / "successor"),
            ]
        )
        == 0
    )
    assert events == ["decision-complete"] * 3 + ["answer-key-revealed"]
    assert hidden_reads == []


def test_distributed_session_entrypoint_and_help_are_available(capsys):
    import tomllib

    from poker_ai import run_session_cli

    root = Path(__file__).resolve().parents[2]
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["scripts"]["poker-xai-run-session"] == (
        "poker_ai.run_session_cli:main"
    )
    with pytest.raises(SystemExit) as stopped:
        run_session_cli.main(["--help"])
    assert stopped.value.code == 0
    help_text = capsys.readouterr().out
    assert "--version" in help_text
    assert "--solver-iterations" in help_text
    assert "--explanations" in help_text
    assert "--previous-session-manifest" in help_text
    previous_actions = [
        action
        for action in run_session_cli._parser(entrypoint="test")._actions
        if "--previous-session-manifest" in action.option_strings
    ]
    assert len(previous_actions) == 1
    assert "--out-dir" in help_text


def test_session_version_commands_exit_without_starting_or_writing(tmp_path, monkeypatch, capsys):
    from poker_ai import run_session_cli

    def unexpected(*_args, **_kwargs):
        raise AssertionError("--version must not start or write a session")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_session_cli, "run_session", unexpected)
    monkeypatch.setattr(run_session_cli, "write_session_bundle", unexpected)

    with pytest.raises(SystemExit) as console_stopped:
        run_session_cli.main(["--version"])
    assert console_stopped.value.code == 0
    assert capsys.readouterr().out == "poker-xai-run-session 0.1.0a9\n"
    assert tuple(tmp_path.iterdir()) == ()

    compatibility_cli = _load_cli_module()
    with pytest.raises(SystemExit) as wrapper_stopped:
        compatibility_cli.main(["--version"])
    assert wrapper_stopped.value.code == 0
    assert capsys.readouterr().out == "cli/run_session.py 0.1.0a9\n"
    assert tuple(tmp_path.iterdir()) == ()


def test_session_version_uses_explicit_unknown_fallback(monkeypatch, capsys):
    from poker_ai import run_session_cli

    monkeypatch.setattr(run_session_cli, "resolve_package_version", lambda: "unknown")

    with pytest.raises(SystemExit) as stopped:
        run_session_cli.main(["--version"])
    assert stopped.value.code == 0
    assert capsys.readouterr().out == "poker-xai-run-session unknown\n"


def _load_cli_module():
    path = Path(__file__).resolve().parents[2] / "cli" / "run_session.py"
    spec = importlib.util.spec_from_file_location("run_session_cli", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
