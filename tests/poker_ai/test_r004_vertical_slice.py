"""Regression coverage for the bounded LEAK_R004 Hero CLI slice."""

from __future__ import annotations

import hashlib
import json
import math
import re
from decimal import Decimal

import pytest

from explanation import ExplanationDocument, verify_explanation
from opponents.catalog import load_training_catalog, load_validation_catalog
from opponents.model import OpponentModelConfig, leak_action_mapping
from poker_ai import run_session_cli
from poker_ai.decision import Observation
from poker_ai.explanation_artifacts import (
    load_next_session_settings,
    verify_saved_explanation_bundle,
)
from poker_ai.exploit import (
    NodelockExploitConfig,
    NodelockExploitProvider,
    nodelock_config_from_leaks,
    nodelock_mapping_for_reason,
)
from poker_ai.opponent import (
    R003_FIXTURE_BET_FRACTION,
    R003_FIXTURE_DELTA,
    R003_FIXTURE_PROFILE_AVERAGE_DELAY,
    R003_FIXTURE_PROFILE_ITERATIONS,
    R003_FIXTURE_PROFILE_SEED,
    R004_FIXTURE_OPPONENT_ID,
    R004_FIXTURE_PROFILE_VERSION,
    r003_fixture_config_identity,
    r003_fixture_measurement,
    r004_fixture_config_identity,
    r004_fixture_measurement,
    reveal_stub_opponent_answer_key,
)
from poker_ai.scenario import Scenario, generate_scenarios
from poker_core.dpl_schema import DecisionProvenanceLog, DetectedLeak
from poker_core.reason_ontology import get_ontology
from poker_core.run_manifest import RunManifest
from poker_solver.nodelock import (
    NodeLockConfig,
    NodeLockRule,
    apply_node_locks,
    river_infoset_reach_weights,
)
from poker_solver.river_solve import solve_frozen_river_scenario
from poker_solver.river_tree import RiverBettingConfig, build_river_game


def _profile_sha256(profile: dict[str, dict[str, float]]) -> str:
    payload = {
        infoset: {action: distribution[action] for action in sorted(distribution)}
        for infoset, distribution in sorted(profile.items())
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _logs(root, seed: int) -> list[DecisionProvenanceLog]:
    path = root / f"S{seed:08d}.dpl.jsonl"
    return [
        DecisionProvenanceLog.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def _manifest(root, seed: int) -> RunManifest:
    return RunManifest.model_validate_json((root / f"S{seed:08d}.manifest.json").read_bytes())


def test_r004_is_canonical_explicit_only_and_noncatalog(tmp_path, capsys):
    assert get_ontology().get("LEAK_R004").label == "river_small_bet_overcall"

    with pytest.raises(ValueError, match="unsupported synthetic leak reason 'LEAK_R004'"):
        leak_action_mapping("LEAK_R004")

    with pytest.raises(ValueError, match="unsupported synthetic leak reason 'LEAK_R004'"):
        OpponentModelConfig(
            opponent_id="must-remain-rejected-r004",
            opponent_version="0.1.0",
            split="training",
            equilibrium_version="fixture-equilibrium-v1",
            equilibrium_artifact_sha256="0" * 64,
            opponent_position="IP",
            leak_vector=(("LEAK_R004", "0.16"),),
            seed=1,
        )

    for catalog in (load_training_catalog(), load_validation_catalog()):
        assert all("LEAK_R004" not in dict(config.leak_vector) for config in catalog)

    output_root = tmp_path / "must-not-exist"
    with pytest.raises(SystemExit) as stopped:
        run_session_cli.main(
            [
                "--leaky-fixture-reason",
                "LEAK_R004",
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


def test_r003_profile_can_supply_r004_call_nodelock_and_stable_provenance():
    generated = next(generate_scenarios(R003_FIXTURE_PROFILE_SEED, 1))
    scenario_payload = generated.model_dump(mode="python")
    scenario_payload["position"] = "OOP"
    scenario_payload["effective_stack"] = max(
        generated.effective_stack,
        generated.pot * R003_FIXTURE_BET_FRACTION,
    )
    scenario = Scenario.model_validate(scenario_payload)
    result = solve_frozen_river_scenario(
        scenario,
        bet_fraction=R003_FIXTURE_BET_FRACTION,
        iterations=R003_FIXTURE_PROFILE_ITERATIONS,
        checkpoints=(),
        average_delay=R003_FIXTURE_PROFILE_AVERAGE_DELAY,
    )
    game = build_river_game(
        RiverBettingConfig(
            pot=scenario.pot,
            bet_fraction=R003_FIXTURE_BET_FRACTION,
        ),
        scenario.hero_range_obj(),
        scenario.opponent_range_obj(),
        scenario.board_cards(),
    )
    mapping = leak_action_mapping("LEAK_R002")
    assert (mapping.phase, mapping.action) == ("vs_bet", "CALL")

    target_infosets = tuple(
        infoset
        for infoset in game.infosets
        if infoset.startswith("IP:")
        and infoset.endswith(f":{mapping.phase}")
        and mapping.action in game.actions_of(infoset)
    )
    reach_weights = river_infoset_reach_weights(game, result.strategy)
    denominator = math.fsum(reach_weights[infoset] for infoset in target_infosets)
    assert target_infosets
    assert denominator > 0.0
    baseline_rate = (
        math.fsum(
            reach_weights[infoset] * result.strategy[infoset][mapping.action]
            for infoset in target_infosets
        )
        / denominator
    )
    target_rate = baseline_rate + float(Decimal(R003_FIXTURE_DELTA))
    assert 0.0 < baseline_rate < target_rate < 1.0

    application = apply_node_locks(
        game,
        result.strategy,
        NodeLockConfig(
            rules=(
                NodeLockRule(
                    actor="IP",
                    phase=mapping.phase,
                    action=mapping.action,
                    target_frequency=target_rate,
                    combo_allocation="baseline_scaled",
                    rule_id="LEAK_R004_synthetic_opponent",
                ),
            ),
            lock_mode="HARD",
            unlocked_policy_mode="fix_to_baseline",
        ),
        reach_weights=reach_weights,
    )
    assert len(application.applied_locks) == 1
    assert application.applied_locks[0].achieved_frequency == pytest.approx(
        target_rate,
        rel=0.0,
        abs=1e-12,
    )

    baseline_profile_sha256 = _profile_sha256(result.strategy)
    locked_profile_sha256 = _profile_sha256(application.profile)
    provenance_payload = {
        "fixture_version": "finite-cfr-r004-profile-v1",
        "profile_kind": "finite_iteration_cfr",
        "profile_source": "poker_solver.solve_frozen_river_scenario",
        "reason_id": "LEAK_R004",
        "action": mapping.action,
        "phase": mapping.phase,
        "solver": "cfr_plus",
        "bet_fraction": R003_FIXTURE_BET_FRACTION,
        "iterations": R003_FIXTURE_PROFILE_ITERATIONS,
        "average_delay": R003_FIXTURE_PROFILE_AVERAGE_DELAY,
        "solve_config_digest": result.solve_config_digest,
        "baseline_profile_sha256": baseline_profile_sha256,
        "locked_profile_sha256": locked_profile_sha256,
        "combo_allocation": "baseline_scaled",
        "lock_mode": application.lock_mode,
        "unlocked_policy_mode": application.unlocked_policy_mode,
    }
    encoded = json.dumps(
        provenance_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    first_hash = hashlib.sha256(encoded).hexdigest()
    second_hash = hashlib.sha256(encoded).hexdigest()
    inline_path = (
        "inline:noncatalog:finite-cfr-r004-profile-v1:reason=LEAK_R004:"
        f"action={mapping.action}:phase={mapping.phase}:"
        "source=poker_solver.solve_frozen_river_scenario:solver=cfr_plus:"
        f"bet_fraction={R003_FIXTURE_BET_FRACTION:g}:"
        f"iterations={R003_FIXTURE_PROFILE_ITERATIONS}:"
        f"average_delay={R003_FIXTURE_PROFILE_AVERAGE_DELAY}:"
        f"solve_config={result.solve_config_digest}:"
        f"baseline_profile={baseline_profile_sha256}:"
        f"locked_profile={locked_profile_sha256}:"
        f"lock_mode={application.lock_mode}:"
        f"unlocked_policy_mode={application.unlocked_policy_mode}"
    )

    assert first_hash == second_hash
    assert re.fullmatch(r"[0-9a-f]{64}", first_hash)
    assert "reason=LEAK_R004" in inline_path
    assert "action=CALL" in inline_path
    assert "solver=cfr_plus" in inline_path
    assert "iterations=40" in inline_path
    assert len(re.findall(r"(?:baseline|locked)_profile=([0-9a-f]{64})", inline_path)) == 2


def test_r004_fixed_profile_supplies_call_response_and_inline_provenance():
    first = r004_fixture_measurement()
    second = r004_fixture_measurement()
    assert first == second
    assert (first.reason_id, first.phase, first.action) == (
        "LEAK_R004",
        "vs_bet",
        "CALL",
    )
    assert float(first.true_leak) == pytest.approx(0.16, abs=1e-12)
    assert 0.0 < float(first.baseline_rate) < float(first.opponent_rate) < 1.0
    assert float(first.baseline_rate) + float(r003_fixture_measurement().baseline_rate) == (
        pytest.approx(1.0, abs=1e-12)
    )

    answer_key = reveal_stub_opponent_answer_key(opponent_model_id=R004_FIXTURE_OPPONENT_ID)
    probabilities = dict(answer_key.action_probabilities)
    assert set(probabilities) == {"CALL", "FOLD"}
    assert probabilities["CALL"] == pytest.approx(float(first.opponent_rate), abs=1e-12)

    r003_path, _r003_sha256 = r003_fixture_config_identity()
    path, sha256 = r004_fixture_config_identity()
    assert path.startswith(f"inline:noncatalog:{R004_FIXTURE_PROFILE_VERSION}:")
    for token in (
        "reason=LEAK_R004",
        "action=CALL",
        "phase=vs_bet",
        "profile=finite_iteration_cfr",
        "source=poker_solver.solve_frozen_river_scenario",
        "solver=cfr_plus",
        "seed=20260704",
        "scenario_index=0",
        "public_bet=BET_33",
        "bet_fraction=0.33",
        "iterations=40",
        "average_delay=0",
        "solve_config=",
        "allocation=baseline_scaled",
        "lock_mode=HARD",
        "unlocked_policy_mode=fix_to_baseline",
        "response_sampler=r004-opponent-response-v1",
    ):
        assert token in path
    assert "equilibrium" not in path.lower()
    r003_baseline_profile = re.search(r"baseline_profile=([0-9a-f]{64})", r003_path)
    r004_baseline_profile = re.search(r"baseline_profile=([0-9a-f]{64})", path)
    assert r003_baseline_profile is not None
    assert r004_baseline_profile is not None
    assert r004_baseline_profile.group(1) == r003_baseline_profile.group(1)
    assert len(re.findall(r"(?:baseline|locked)_profile=([0-9a-f]{64})", path)) == 2
    assert re.fullmatch(r"[0-9a-f]{64}", sha256)


def test_r004_provider_uses_call_lock_and_falls_back_outside_bet_33_scope():
    measurement = r004_fixture_measurement()
    leak = DetectedLeak(
        reason_id="LEAK_R004",
        leak_type="river_small_bet_overcall",
        situation_key="dry:IP:river_vs_bet",
        observed_rate=float(measurement.opponent_rate),
        baseline_rate=float(measurement.baseline_rate),
        effective_sample_size=20,
        confidence=1.0,
        direction="adjust_small_bet_frequency_for_overcall",
    )
    mapping = nodelock_mapping_for_reason("LEAK_R004")
    config = nodelock_config_from_leaks(
        (leak,),
        hero_position="OOP",
        min_confidence=0.95,
        combo_allocation="baseline_scaled",
        lock_mode="HARD",
        unlocked_policy_mode="fix_to_baseline",
    )
    assert (mapping.phase, mapping.action) == ("vs_bet", "CALL")
    assert config is not None
    assert config.lock_mode == "HARD"
    assert config.unlocked_policy_mode == "fix_to_baseline"
    assert config.rules[0].actor == "IP"
    assert config.rules[0].rule_id == "LEAK_R004_opponent_CALL_vs_bet"
    assert config.rules[0].target_frequency == pytest.approx(float(measurement.opponent_rate))

    generated = next(generate_scenarios(20260004, 1))
    scenario_payload = generated.model_dump(mode="python")
    scenario_payload["position"] = "OOP"
    scenario = Scenario.model_validate(scenario_payload)
    observation = Observation(
        hand_id="R004-H0",
        session_id="R004",
        board=scenario.board_cards(),
        position="OOP",
        pot=scenario.pot,
        facing_bet=0.0,
        effective_stack=scenario.effective_stack,
        hero_combo=scenario.hero_combo_obj(),
        hero_range=scenario.hero_range_obj(),
        opponent_assumed_range=scenario.opponent_range_obj(),
    )
    base_policy = {"CHECK": 0.5, "BET_75": 0.5}
    result = NodelockExploitProvider(NodelockExploitConfig(iterations=1)).build(
        base_policy=base_policy,
        detected_leaks=(leak,),
        legal_actions=("CHECK", "BET_75"),
        action_ev={"CHECK": 0.0, "BET_75": 1.0},
        observation=observation,
    )
    assert result.policy == base_policy
    assert result.exploit_source == "rule_based"
    assert result.solver_result_id is None


def test_r004_cli_is_causal_solver_backed_explained_and_handoff_ready(tmp_path, capsys):
    source_seed = 20260004
    source_root = tmp_path / "source"
    source_argv = [
        "--seed",
        str(source_seed),
        "--hands",
        "160",
        "--solver-iterations",
        "5",
        "--leaky-fixture",
        "--leaky-fixture-reason",
        "LEAK_R004",
        "--exploration-epsilon",
        "1.0",
        "--explanations",
        "--out-dir",
        str(source_root),
    ]
    assert run_session_cli.main(source_argv) == 0
    assert "explanations_verified=160" in capsys.readouterr().out

    logs = _logs(source_root, source_seed)
    manifest = _manifest(source_root, source_seed)
    explanations = [
        ExplanationDocument.model_validate_json(line)
        for line in (source_root / f"S{source_seed:08d}.explanations.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    measurement = r004_fixture_measurement()

    assert len(logs) == len(explanations) == 160
    assert logs[0].detected_leaks == []
    assert all(set(log.base_policy) == {"CHECK", "BET_33"} for log in logs)
    assert all(set(log.exploit_policy) == {"CHECK", "BET_33"} for log in logs)
    assert all(set(log.final_policy) == {"CHECK", "BET_33"} for log in logs)
    assert all(log.safety_alpha == 1.0 for log in logs)
    assert all(
        log.ev_estimate.ev_source == "solver_exact"
        and log.ev_estimate.ev_definition == "incremental_ev_from_current_node"
        for log in logs
    )

    prior_bets: dict[str, int] = {}
    for log in logs:
        for leak in log.detected_leaks:
            assert leak.reason_id == "LEAK_R004"
            assert leak.leak_type == "river_small_bet_overcall"
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
    assert all(record["rule_id"] == "LEAK_R004" for record in snapshot["records"])
    assert all(record["action_group"] == ["CALL"] for record in snapshot["records"])
    assert all(set(record["action_counts"]) <= {"FOLD", "CALL"} for record in snapshot["records"])

    solver_logs = [log for log in logs if log.exploit_source == "nodelock_solver"]
    assert solver_logs
    for log in solver_logs:
        assert [leak.reason_id for leak in log.detected_leaks] == ["LEAK_R004"]
        assert log.solver_result_id is not None
        assert "allocation=baseline_scaled" in log.solver_result_id
        assert "lock_mode=HARD" in log.solver_result_id
        assert "unlocked_policy_mode=fix_to_baseline" in log.solver_result_id
        assert log.ev_estimate.exploit_ev > log.ev_estimate.base_ev + 1e-12
        assert log.final_policy == pytest.approx(log.exploit_policy)

    solver_ref = next(config for config in manifest.configs if config.role == "solver")
    opponent_ref = manifest.opponents[0]
    baseline = json.loads((source_root / "provenance/action_baseline_table.json").read_bytes())
    assert opponent_ref.opponent_id == R004_FIXTURE_OPPONENT_ID
    assert opponent_ref.config is not None
    assert opponent_ref.config.path == r004_fixture_config_identity()[0]
    assert opponent_ref.config.sha256 == r004_fixture_config_identity()[1]
    assert opponent_ref.config.path.startswith("inline:noncatalog:")
    assert "reason=LEAK_R004" in opponent_ref.config.path
    assert "session_mode=r004_no_facing" in manifest.description
    assert "public_bet=BET_33" in solver_ref.path
    assert "bet_fraction=0.33" in solver_ref.path
    assert all(
        log.base_strategy_provenance.solver_config_sha256 == solver_ref.sha256 for log in logs
    )
    assert baseline["table_version"] == manifest.versions.baseline_table_version
    assert baseline["rules"][0]["reason_id"] == "LEAK_R004"
    assert baseline["rules"][0]["action_group"] == ["CALL"]

    for log, explanation in zip(logs, explanations, strict=True):
        assert explanation.generator == "template"
        verified = verify_explanation(explanation, log)
        assert verified.passed, verified.issues
    source_manifest_path = source_root / f"S{source_seed:08d}.manifest.json"
    saved = verify_saved_explanation_bundle(source_manifest_path)
    assert saved.checker_total == saved.checker_passed == 160

    evaluation = json.loads(
        (source_root / f"S{source_seed:08d}.post_session_evaluation.json").read_bytes()
    )
    assert evaluation["evaluation"]["opponent_model_id"] == R004_FIXTURE_OPPONENT_ID
    assert evaluation["evaluation"]["explanation_validity_score"] == 1.0
    settings = evaluation["next_session_settings"]
    assert set(settings) == {"leak_detector_config", "safety_alpha", "epsilon"}
    assert settings["leak_detector_config"]["min_deviation"] == 0.08

    restored = load_next_session_settings(source_manifest_path)
    source_before_handoff = {
        path.relative_to(source_root): path.read_bytes()
        for path in source_root.rglob("*")
        if path.is_file()
    }
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
        "LEAK_R004",
        "--explanations",
        "--previous-session-manifest",
        str(source_manifest_path),
        "--out-dir",
        str(successor_root),
    ]
    assert run_session_cli.main(successor_argv) == 0
    assert source_before_handoff == {
        path.relative_to(source_root): path.read_bytes()
        for path in source_root.rglob("*")
        if path.is_file()
    }

    successor_manifest = _manifest(successor_root, successor_seed)
    successor_logs = _logs(successor_root, successor_seed)
    execution_sampler = next(
        config for config in successor_manifest.configs if config.name == "execution_sampler"
    )
    assert successor_manifest.code.argv == successor_argv
    assert successor_manifest.opponents == manifest.opponents
    assert successor_manifest.versions == manifest.versions
    assert successor_logs[0].detected_leaks == []
    assert all(set(log.final_policy) == {"CHECK", "BET_33"} for log in successor_logs)
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
