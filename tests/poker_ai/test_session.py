"""End-to-end tests for the vertical-slice session (task-3 acceptance criteria)."""

from __future__ import annotations

import json
import math

from poker_ai.baseline_strategy import baseline_table_version
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


def test_versions_are_stamped_on_every_log():
    for log in iter_session_logs(20260704, HANDS):
        assert log.cluster_def_version == cluster_def_version()
        assert log.cluster_def_version.endswith("-draft")
        assert log.baseline_table_version == baseline_table_version()
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
    assert manifest.versions.baseline_table_version == baseline_table_version()
    # Every referenced config carries a content hash (auditable provenance).
    roles = {c.role for c in manifest.configs}
    assert {"cluster_def", "baseline_table", "other"} <= roles
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
