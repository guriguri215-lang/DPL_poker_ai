"""Regression coverage for the bounded LEAK_R003 Hero CLI slice."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from explanation import ExplanationDocument, verify_explanation
from opponents.model import OpponentModelConfig, leak_action_mapping
from poker_ai import run_session_cli
from poker_ai.explanation_artifacts import (
    load_next_session_settings,
    verify_saved_explanation_bundle,
)
from poker_ai.opponent import (
    R003_FIXTURE_OPPONENT_ID,
    R003_FIXTURE_PROFILE_VERSION,
    r003_fixture_config_identity,
    r003_fixture_measurement,
    reveal_stub_opponent_answer_key,
)
from poker_core.dpl_schema import DecisionProvenanceLog
from poker_core.reason_ontology import get_ontology
from poker_core.run_manifest import RunManifest


def _logs(root: Path, seed: int) -> list[DecisionProvenanceLog]:
    path = root / f"S{seed:08d}.dpl.jsonl"
    return [
        DecisionProvenanceLog.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def _manifest(root: Path, seed: int) -> RunManifest:
    return RunManifest.model_validate_json((root / f"S{seed:08d}.manifest.json").read_bytes())


def test_r003_is_canonical_and_requires_the_explicit_fixture_flag(tmp_path, capsys):
    assert get_ontology().get("LEAK_R003").label == "river_small_bet_overfold"
    with pytest.raises(ValueError, match="unsupported synthetic leak reason 'LEAK_R003'"):
        leak_action_mapping("LEAK_R003")

    with pytest.raises(ValueError, match="unsupported synthetic leak reason 'LEAK_R003'"):
        OpponentModelConfig(
            opponent_id="must-remain-rejected-r003",
            opponent_version="0.1.0",
            split="training",
            equilibrium_version="fixture-equilibrium-v1",
            equilibrium_artifact_sha256="0" * 64,
            opponent_position="IP",
            leak_vector=(("LEAK_R003", "0.16"),),
            seed=1,
        )

    output_root = tmp_path / "must-not-exist"
    with pytest.raises(SystemExit) as stopped:
        run_session_cli.main(
            [
                "--leaky-fixture-reason",
                "LEAK_R003",
                "--out-dir",
                str(output_root),
            ]
        )

    captured = capsys.readouterr()
    assert stopped.value.code == 2
    assert "requires --leaky-fixture" in captured.err
    assert not output_root.exists()

    with pytest.raises(SystemExit) as unsupported:
        run_session_cli.main(
            [
                "--leaky-fixture",
                "--leaky-fixture-reason",
                "LEAK_R005",
                "--out-dir",
                str(output_root),
            ]
        )

    captured = capsys.readouterr()
    assert unsupported.value.code == 2
    assert "invalid choice: 'LEAK_R005'" in captured.err
    assert not output_root.exists()


def test_r003_fixed_profile_supplies_response_and_inline_provenance():
    first = r003_fixture_measurement()
    second = r003_fixture_measurement()
    assert first == second
    assert (first.reason_id, first.phase, first.action) == (
        "LEAK_R003",
        "vs_bet",
        "FOLD",
    )
    assert float(first.true_leak) == pytest.approx(0.16, abs=1e-12)
    assert 0.0 < float(first.baseline_rate) < float(first.opponent_rate) < 1.0

    answer_key = reveal_stub_opponent_answer_key(opponent_model_id=R003_FIXTURE_OPPONENT_ID)
    probabilities = dict(answer_key.action_probabilities)
    assert set(probabilities) == {"CALL", "FOLD"}
    assert probabilities["FOLD"] == pytest.approx(float(first.opponent_rate), abs=1e-12)

    path, sha256 = r003_fixture_config_identity()
    assert path.startswith(f"inline:noncatalog:{R003_FIXTURE_PROFILE_VERSION}:")
    assert "reason=LEAK_R003" in path
    assert "profile=finite_iteration_cfr" in path
    assert "source=poker_solver.solve_frozen_river_scenario" in path
    assert "seed=20260704" in path
    assert "scenario_index=0" in path
    assert "public_bet=BET_33" in path
    assert "bet_fraction=0.33" in path
    assert "iterations=40" in path
    assert "average_delay=0" in path
    assert "solve_config=" in path
    assert "allocation=baseline_scaled" in path
    assert "lock_mode=HARD" in path
    assert "unlocked_policy_mode=fix_to_baseline" in path
    assert "response_sampler=r003-opponent-response-v1" in path
    assert "equilibrium" not in path.lower()
    assert len(re.findall(r"(?:baseline|locked)_profile=([0-9a-f]{64})", path)) == 2
    assert re.fullmatch(r"[0-9a-f]{64}", sha256)


def test_r003_inline_provenance_names_action_phase_and_solver():
    path, _sha256 = r003_fixture_config_identity()

    for token in (
        "reason=LEAK_R003",
        "action=FOLD",
        "phase=vs_bet",
        "solver=cfr_plus",
        "seed=20260704",
    ):
        assert token in path


def test_r003_cli_is_causal_solver_backed_explained_and_handoff_ready(tmp_path, capsys):
    source_seed = 20260004
    source_root = tmp_path / "source"
    source_argv = [
        "--seed",
        str(source_seed),
        "--hands",
        "20",
        "--solver-iterations",
        "5",
        "--leaky-fixture",
        "--leaky-fixture-reason",
        "LEAK_R003",
        "--exploration-epsilon",
        "1.0",
        "--explanations",
        "--out-dir",
        str(source_root),
    ]
    assert run_session_cli.main(source_argv) == 0
    assert "explanations_verified=20" in capsys.readouterr().out

    logs = _logs(source_root, source_seed)
    manifest = _manifest(source_root, source_seed)
    explanations = [
        ExplanationDocument.model_validate_json(line)
        for line in (source_root / f"S{source_seed:08d}.explanations.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    measurement = r003_fixture_measurement()

    assert len(logs) == len(explanations) == 20
    assert logs[0].detected_leaks == []
    assert all(set(log.base_policy) == {"CHECK", "BET_33"} for log in logs)
    assert all(set(log.exploit_policy) == {"CHECK", "BET_33"} for log in logs)
    assert all(set(log.final_policy) == {"CHECK", "BET_33"} for log in logs)
    assert all(
        log.ev_estimate.ev_source == "solver_exact"
        and log.ev_estimate.ev_definition == "incremental_ev_from_current_node"
        for log in logs
    )

    prior_bets: dict[str, int] = {}
    for log in logs:
        for leak in log.detected_leaks:
            assert leak.reason_id == "LEAK_R003"
            assert leak.leak_type == "river_small_bet_overfold"
            assert leak.baseline_rate == pytest.approx(float(measurement.baseline_rate), abs=1e-12)
            assert leak.effective_sample_size == prior_bets.get(leak.situation_key, 0)
        if log.selected_action == "BET_33":
            situation_key = f"{log.state_cluster}:IP:river_vs_bet"
            prior_bets[situation_key] = prior_bets.get(situation_key, 0) + 1

    snapshot = json.loads(
        (source_root / "provenance/action_stats_terminal_snapshots.json").read_bytes()
    )
    bet_count = sum(log.selected_action == "BET_33" for log in logs)
    check_count = sum(log.selected_action == "CHECK" for log in logs)
    assert bet_count > 0
    assert check_count > 0
    assert sum(record["n"] for record in snapshot["records"]) == bet_count
    assert all(record["rule_id"] == "LEAK_R003" for record in snapshot["records"])
    assert all(record["action_group"] == ["FOLD"] for record in snapshot["records"])
    assert all(set(record["action_counts"]) <= {"FOLD", "CALL"} for record in snapshot["records"])

    solver_logs = [log for log in logs if log.exploit_source == "nodelock_solver"]
    assert solver_logs
    for log in solver_logs:
        assert [leak.reason_id for leak in log.detected_leaks] == ["LEAK_R003"]
        assert log.solver_result_id is not None
        assert "allocation=baseline_scaled" in log.solver_result_id
        assert "lock_mode=HARD" in log.solver_result_id
        assert "unlocked_policy_mode=fix_to_baseline" in log.solver_result_id
        assert log.ev_estimate.exploit_ev > log.ev_estimate.base_ev

    solver_ref = next(config for config in manifest.configs if config.role == "solver")
    opponent_ref = manifest.opponents[0]
    baseline = json.loads((source_root / "provenance/action_baseline_table.json").read_bytes())
    assert opponent_ref.opponent_id == R003_FIXTURE_OPPONENT_ID
    assert opponent_ref.config is not None
    assert opponent_ref.config.path.startswith("inline:noncatalog:")
    assert opponent_ref.config.sha256 == r003_fixture_config_identity()[1]
    assert "reason=LEAK_R003" in opponent_ref.config.path
    assert "session_mode=r003_no_facing" in manifest.description
    assert "public_bet=BET_33" in solver_ref.path
    assert "bet_fraction=0.33" in solver_ref.path
    assert all(
        log.base_strategy_provenance.solver_config_sha256 == solver_ref.sha256 for log in logs
    )
    assert baseline["table_version"] == manifest.versions.baseline_table_version
    assert baseline["rules"][0]["reason_id"] == "LEAK_R003"
    assert baseline["rules"][0]["action_group"] == ["FOLD"]

    for log, explanation in zip(logs, explanations, strict=True):
        assert explanation.generator == "template"
        verified = verify_explanation(explanation, log)
        assert verified.passed, verified.issues
    source_manifest_path = source_root / f"S{source_seed:08d}.manifest.json"
    saved = verify_saved_explanation_bundle(source_manifest_path)
    assert saved.checker_total == saved.checker_passed == 20

    evaluation = json.loads(
        (source_root / f"S{source_seed:08d}.post_session_evaluation.json").read_bytes()
    )
    assert evaluation["evaluation"]["opponent_model_id"] == R003_FIXTURE_OPPONENT_ID
    assert evaluation["evaluation"]["explanation_validity_score"] == 1.0
    assert evaluation["next_session_settings"]["leak_detector_config"]["min_deviation"] == 0.08

    restored = load_next_session_settings(source_manifest_path)
    successor_seed = 20260012
    successor_root = tmp_path / "successor"
    successor_argv = [
        "--seed",
        str(successor_seed),
        "--hands",
        "1",
        "--solver-iterations",
        "5",
        "--leaky-fixture",
        "--leaky-fixture-reason",
        "LEAK_R003",
        "--explanations",
        "--previous-session-manifest",
        str(source_manifest_path),
        "--out-dir",
        str(successor_root),
    ]
    assert run_session_cli.main(successor_argv) == 0

    successor_manifest = _manifest(successor_root, successor_seed)
    successor_logs = _logs(successor_root, successor_seed)
    execution_sampler = next(
        config for config in successor_manifest.configs if config.name == "execution_sampler"
    )
    assert successor_manifest.code.argv == successor_argv
    assert successor_manifest.opponents == manifest.opponents
    assert successor_manifest.versions == manifest.versions
    assert successor_logs[0].detected_leaks == []
    assert all(log.safety_alpha == restored.safety_alpha for log in successor_logs)
    assert execution_sampler.path == f"inline:epsilon-uniform-v1:epsilon={restored.epsilon:g}"
    successor_estimator = json.loads(
        (successor_root / "provenance/leak_confidence_estimator.json").read_bytes()
    )
    restored_detector = restored.leak_detector_config
    assert successor_estimator == {
        "method_version": restored_detector.method_version,
        "alpha0": restored_detector.alpha0,
        "beta0": restored_detector.beta0,
        "tail": restored_detector.tail,
        "tau": restored_detector.min_deviation,
        "min_effective_sample_size": restored_detector.min_effective_sample_size,
        "detector_min_confidence": restored_detector.min_confidence,
        "rule_exploit_min_confidence": restored_detector.rule_exploit_min_confidence,
        "nodelock_exploit_min_confidence": restored_detector.nodelock_exploit_min_confidence,
        "run_identity": successor_estimator["run_identity"],
        "baseline_table": successor_estimator["baseline_table"],
    }
    successor_manifest_path = successor_root / f"S{successor_seed:08d}.manifest.json"
    assert verify_saved_explanation_bundle(successor_manifest_path).checker_total == 1
