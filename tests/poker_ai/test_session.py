"""End-to-end tests for the vertical-slice session (task-3 acceptance criteria)."""

from __future__ import annotations

import importlib.util
import json
import math
from pathlib import Path

from poker_ai.baseline_strategy import baseline_table_version
from poker_ai.exploit import RuleExploitResult
from poker_ai.leak import (
    BET_ACTIONS,
    ActionBaselineTable,
    ActionLeakRule,
    LeakDetector,
    LeakDetectorConfig,
    leaky_fixture_action_baseline_table,
)
from poker_ai.session import (
    EV_SOURCE,
    build_manifest,
    iter_session_logs,
    run_session,
    write_jsonl,
    write_manifest,
)
from poker_core.dpl_schema import DecisionProvenanceLog
from poker_core.run_manifest import RunManifest
from poker_core.state_cluster import cluster_def_version

HANDS = 120  # exceeds the 100-hand acceptance floor


def test_runs_over_100_hands_all_dpl_valid():
    logs = list(iter_session_logs(20260704, HANDS))
    assert len(logs) == HANDS
    for log in logs:
        assert isinstance(log, DecisionProvenanceLog)
        # Re-validate the serialised form against the frozen schema (round-trip).
        DecisionProvenanceLog.model_validate(log.model_dump(mode="json"))


def test_ev_source_is_solver_exact_only():
    for log in iter_session_logs(20260704, HANDS):
        assert log.ev_estimate.ev_source == EV_SOURCE == "solver_exact"
        assert log.ev_estimate.ev_definition == "incremental_ev_from_current_node"
        assert math.isfinite(log.ev_estimate.final_ev)
        # Only solver_exact EVs are cleared for explanations (ADR-0008).
        assert log.ev_for_explanation() is not None


def test_alpha_zero_and_closed_world_reason_fields():
    for log in iter_session_logs(20260704, HANDS):
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

    logs = list(iter_session_logs(20260704, 3, leak_detector=leak_detector))
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
    result = run_session(
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


def test_custom_leak_baseline_version_is_stamped_on_manifest_and_logs():
    leak_detector = _positive_fixture_detector()
    result = run_session(20260704, 1, leak_detector=leak_detector)

    assert result.logs[0].baseline_table_version == "fixture-action-baseline"
    assert result.manifest.versions.baseline_table_version == "fixture-action-baseline"
    baseline_configs = [c for c in result.manifest.configs if c.name == "action_baseline_table"]
    assert len(baseline_configs) == 1
    assert baseline_configs[0].path == "inline:fixture-action-baseline"
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


def test_versions_are_stamped_on_every_log():
    default_detector = LeakDetector()
    for log in iter_session_logs(20260704, HANDS):
        assert log.cluster_def_version == cluster_def_version()
        assert log.cluster_def_version == "0.1.0"
        assert log.baseline_table_version == default_detector.baseline_table_version
        assert log.baseline_table_version.endswith("-stub")


def test_hand_buckets_and_actions_have_variety():
    logs = list(iter_session_logs(20260704, HANDS))
    buckets = {log.hand_bucket for log in logs}
    actions = {log.selected_action for log in logs}
    # The generated session should exercise more than one bucket and both actions.
    assert len(buckets) >= 3
    assert actions == {"FOLD", "CALL"}


def test_seed_reproducible_jsonl(tmp_path):
    a = write_jsonl(list(iter_session_logs(42, HANDS)), tmp_path / "a.jsonl")
    b = write_jsonl(list(iter_session_logs(42, HANDS)), tmp_path / "b.jsonl")
    assert a.read_bytes() == b.read_bytes()


def test_different_seed_changes_output():
    a = [log.model_dump(mode="json") for log in iter_session_logs(1, HANDS)]
    b = [log.model_dump(mode="json") for log in iter_session_logs(2, HANDS)]
    assert a != b


def test_manifest_is_valid_and_pins_versions_and_configs():
    manifest = build_manifest(20260704, HANDS, git_commit="unknown")
    assert isinstance(manifest, RunManifest)
    assert manifest.seeds["master"] == 20260704
    assert manifest.versions.cluster_def_version == cluster_def_version()
    assert manifest.versions.strategy_table_version == baseline_table_version()
    assert manifest.versions.baseline_table_version == LeakDetector().baseline_table_version
    # Every referenced config carries a content hash (auditable provenance).
    roles = {c.role for c in manifest.configs}
    assert {"cluster_def", "strategy_table", "baseline_table", "other"} <= roles
    for config in manifest.configs:
        assert len(config.sha256) == 64
    assert manifest.opponents[0].opponent_id == "stub_jam_all"


def test_manifest_config_hashes_are_reproducible():
    first = build_manifest(1, HANDS)
    second = build_manifest(1, HANDS)
    assert [c.sha256 for c in first.configs] == [c.sha256 for c in second.configs]


def test_run_session_writes_and_reloads(tmp_path):
    result = run_session(7, HANDS, git_commit="unknown")
    jsonl_path = write_jsonl(result.logs, tmp_path / f"{result.session_id}.jsonl")
    manifest_path = write_manifest(result.manifest, tmp_path / f"{result.session_id}.manifest.json")

    lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == HANDS
    for line in lines:
        DecisionProvenanceLog.model_validate(json.loads(line))

    reloaded = RunManifest.model_validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    assert reloaded.run_id == result.session_id


def test_leaky_fixture_cli_smoke_writes_detected_leaks_and_mix(tmp_path, capsys):
    cli = _load_cli_module()

    rc = cli.main(
        [
            "--seed",
            "20260704",
            "--hands",
            "3",
            "--leaky-fixture",
            "--out-dir",
            str(tmp_path),
        ]
    )

    assert rc == 0
    out = capsys.readouterr().out
    assert "detected_leaks=3" in out
    assert "mixed_decisions=" in out
    jsonl_path = tmp_path / "S20260704.dpl.jsonl"
    manifest_path = tmp_path / "S20260704.manifest.json"
    logs = [
        DecisionProvenanceLog.model_validate(json.loads(line))
        for line in jsonl_path.read_text(encoding="utf-8").splitlines()
    ]
    manifest = RunManifest.model_validate(json.loads(manifest_path.read_text(encoding="utf-8")))

    assert len(logs) == 3
    assert all(log.detected_leaks for log in logs)
    assert all(
        log.baseline_table_version == leaky_fixture_action_baseline_table().table_version
        for log in logs
    )
    assert any(log.safety_alpha > 0.0 and log.mix_reasons for log in logs)
    assert any(log.exploit_policy == {"CALL": 1.0} for log in logs)
    assert manifest.versions.baseline_table_version == "fixture-action-baseline"


def _load_cli_module():
    path = Path(__file__).resolve().parents[2] / "cli" / "run_session.py"
    spec = importlib.util.spec_from_file_location("run_session_cli", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
