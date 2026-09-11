"""R005 semantic, causal, fixed-tree, and public saved-evidence regressions."""

from __future__ import annotations

import copy
import json
from dataclasses import replace

import pytest

from poker_ai import opponent, run_session_cli
from poker_ai._r005 import (
    _BOARD,
    _HERO,
    _HERO_RANGE,
    _MODE,
    _OPPONENT_RANGE,
    _action_evs,
    _bluff_share,
    _classify_revealed,
    _R005Detector,
    _R005ExploitProvider,
    _scenario,
    _ShowdownStats,
    _solve,
)
from poker_ai._r005_bundle import _EVIDENCE_PATH, _validate_r005
from poker_ai.cfr_policy import DEFAULT_CFR_RIVER_POLICY_CONFIG as CONFIG
from poker_ai.decision import Observation
from poker_ai.explanation_artifacts import (
    SavedExplanationBundleVerificationError,
    load_next_session_settings,
    verify_saved_explanation_bundle,
)
from poker_ai.posterior_bundle import canonical_json_bytes, sha256_bytes
from poker_ai.session import run_session
from poker_core.card import parse_cards
from poker_core.dpl_schema import DecisionProvenanceLog
from poker_core.range_model import Range
from poker_core.run_manifest import RunManifest
from poker_solver.game import Terminal
from poker_solver.river_tree import RiverBettingConfig, build_river_game


def _run(seed=20260704, hands=100, alpha=1.0, epsilon=0.0, config=None):
    detector = _R005Detector(CONFIG, config)
    provider = _R005ExploitProvider(CONFIG, detector.config)
    return run_session(
        seed,
        hands,
        session_mode=_MODE,
        solver_config=CONFIG,
        leak_detector=detector,
        exploit_provider=provider,
        safety_alpha=alpha,
        exploration_epsilon=epsilon,
    )


def _observation():
    scenario = _scenario("H")
    return Observation(
        hand_id="H",
        session_id="S",
        board=scenario.board_cards(),
        position="OOP",
        pot=16.6,
        facing_bet=6.7,
        effective_stack=6.7,
        hero_combo=scenario.hero_combo_obj(),
        hero_range=scenario.hero_range_obj(),
        opponent_assumed_range=scenario.opponent_range_obj(),
    )


def test_fixed_tree_keeps_original_game_and_correct_raise_terminals():
    original = build_river_game(
        RiverBettingConfig(10, 0.33),
        Range(_HERO_RANGE),
        Range(_OPPONENT_RANGE),
        parse_cards(_BOARD),
    )
    assert all("RAISE_ALL_IN" not in original.actions_of(key) for key in original.infosets)
    game, profile = _solve(40, 0)
    assert sum(p for p, _, _ in game.root.branches) == pytest.approx(1)
    for _, response, label in game.root.branches:
        assert response.actions == ("CALL", "FOLD", "RAISE_ALL_IN")
        raised = response.child_of("RAISE_ALL_IN")
        assert raised.actions == ("CALL", "FOLD")
        assert raised.child_of("FOLD") == Terminal(-8.3)
        expected = 15 if _classify_revealed(label.split("|")[1]) == "bluff" else -15
        assert raised.child_of("CALL") == Terminal(expected)
    baseline = _bluff_share(game, profile)
    assert 0 < baseline < 1
    assert _action_evs(game, profile) == pytest.approx(
        {
            "CALL": 30 * baseline - 6.7,
            "FOLD": 0,
        }
    )
    assert all(set(profile[key]) == {"CALL", "FOLD"} for key in profile if key.startswith("OOP:"))


def test_bluff_is_structurally_polarized_not_raise_frequency_or_showdown_loss():
    assert [_classify_revealed(combo) for combo in _OPPONENT_RANGE] == [
        "value",
        "value",
        "bluff",
        "bluff",
    ]
    with pytest.raises(ValueError, match="support"):
        _classify_revealed(_HERO)
    detector = _R005Detector(CONFIG)
    # Same 100 public raises, radically different revealed compositions.
    assert detector._detect_public(_ShowdownStats(100, 100, 0))
    assert detector._detect_public(_ShowdownStats(100, 100, 50)) == []
    assert detector._detect_public(_ShowdownStats(100, 100, 23)) == []
    # Arbitrarily many uncalled raises cannot manufacture evidence.
    unknown = _ShowdownStats(10000, 0, 0)
    assert detector._detect_public(unknown) == []
    assert detector._score(unknown)["observed_bluff_rate"] is None
    assert detector._detect_public(_ShowdownStats(10000, 1, 0)) == []


@pytest.mark.parametrize("counts", [(1, 2, 0), (2, 1, 2), (-1, 0, 0), (True, 0, 0)])
def test_invalid_showdown_counts_rejected(counts):
    with pytest.raises(ValueError):
        _ShowdownStats(*counts)


def test_fold_never_reveals_and_call_requires_public_showdown():
    stats = _ShowdownStats()
    with pytest.raises(ValueError):
        stats.after(selected_action="FOLD", revealed_combo="AsAd")
    with pytest.raises(ValueError):
        stats.after(selected_action="CALL", revealed_combo=None)
    assert stats.after(selected_action="FOLD", revealed_combo=None) == _ShowdownStats(1, 0, 0)


def test_provider_uses_observed_composition_and_exact_solver_evs(monkeypatch):
    import poker_ai._r005 as r005

    detector = _R005Detector(CONFIG)
    provider = _R005ExploitProvider(CONFIG, detector.config)
    game, profile = _solve(40, 0)
    base = profile[f"OOP:{_HERO}:vs_raise"]
    seen = []
    original_apply = r005.apply_node_locks

    def record_lock(*args, **kwargs):
        result = original_apply(*args, **kwargs)
        seen.append(result)
        return result

    monkeypatch.setattr(r005, "apply_node_locks", record_lock)
    candidate = provider.build(
        base_policy=base,
        detected_leaks=detector._detect_public(_ShowdownStats(100, 100, 4)),
        legal_actions=("FOLD", "CALL"),
        action_ev=_action_evs(game, profile),
        observation=_observation(),
    )
    assert _bluff_share(game, seen[0].profile) == pytest.approx(0.04)
    assert candidate.policy == {"CALL": 0.0, "FOLD": 1.0}
    assert candidate.decision_action_ev == pytest.approx({"CALL": -5.5, "FOLD": 0})
    assert candidate.exploit_source == "nodelock_solver"
    assert "lock_mode=HARD" in candidate.solver_result_id
    assert all(lock.action == "RAISE_ALL_IN" for lock in seen[0].applied_locks)
    for key in profile:
        if key.startswith("IP:") and _classify_revealed(key.split(":")[1]) == "value":
            assert seen[0].profile[key] == profile[key]
    with pytest.raises(ValueError, match="exact fixed"):
        provider.build(
            base_policy=base,
            detected_leaks=[],
            legal_actions=("FOLD", "CALL"),
            action_ev=_action_evs(game, profile),
            observation=replace(_observation(), pot=17),
        )


def test_current_private_cards_cannot_change_current_decision(monkeypatch):
    def forbidden_answer():
        raise AssertionError("answer key entered a Hero session")

    monkeypatch.setattr(opponent, "_reveal_r005_answer_key", forbidden_answer)
    monkeypatch.setattr(opponent, "_sample_r005_raised_combo", lambda rng: "AsAd")
    value = _run(hands=100)
    monkeypatch.setattr(opponent, "_sample_r005_raised_combo", lambda rng: "6c5c")
    bluff = _run(hands=100)
    assert value.logs[0] == bluff.logs[0]
    assert value.logs[0].detected_leaks == []
    assert any(log.detected_leaks for log in value.logs)
    assert all(not log.detected_leaks for log in bluff.logs)


@pytest.mark.parametrize("alpha,epsilon", [(0.0, 0.0), (0.5, 0.2), (1.0, 0.0)])
def test_session_mixer_and_reveal_prefix(alpha, epsilon):
    result = _run(alpha=alpha, epsilon=epsilon)
    evidence = json.loads(result.posterior_bundle.artifacts[_EVIDENCE_PATH])
    stats = _ShowdownStats()
    detector = _R005Detector(CONFIG)
    for log, event in zip(result.logs, evidence["events"], strict=True):
        assert log.detected_leaks == detector._detect_public(stats)
        assert set(log.final_policy) == {"CALL", "FOLD"}
        for action in log.final_policy:
            assert log.final_policy[action] == pytest.approx(
                (1 - alpha) * log.base_policy[action] + alpha * log.exploit_policy[action]
            )
        if log.selected_action == "FOLD":
            assert event["revealed_combo"] is None and event["classification"] == "unknown"
        stats = stats.after(
            selected_action=log.selected_action, revealed_combo=event["revealed_combo"]
        )
    assert evidence["terminal"] == detector._score(stats)
    assert stats.raises == len(result.logs)
    if alpha == 0:
        assert all(log.exploit_source == "rule_based" for log in result.logs)
    else:
        assert any(log.exploit_source == "nodelock_solver" for log in result.logs)
    assert result.logs == _run(alpha=alpha, epsilon=epsilon).logs


@pytest.fixture
def completed():
    return _run()


def _replace_artifact(result, path, payload):
    raw = canonical_json_bytes(payload)
    artifacts = dict(result.posterior_bundle.artifacts)
    artifacts[path] = raw
    manifest = result.manifest.model_copy(deep=True)
    for ref in [*manifest.outputs, *manifest.configs]:
        if ref.path == path:
            ref.sha256 = sha256_bytes(raw)
    return manifest, artifacts


@pytest.mark.parametrize("mutation", ["hidden_fold", "classification", "time", "history", "count"])
def test_rehashed_public_evidence_tampering_fails(completed, mutation):
    payload = json.loads(completed.posterior_bundle.artifacts[_EVIDENCE_PATH])
    if mutation == "hidden_fold":
        event = next(e for e in payload["events"] if e["selected_action"] == "FOLD")
        event.update(revealed_combo="AsAd", classification="value")
    elif mutation == "classification":
        event = next(e for e in payload["events"] if e["revealed_combo"] is not None)
        event["classification"] = "unknown"
    elif mutation == "time":
        payload["events"][0]["available_after"] = payload["events"][1]["hand_id"]
    elif mutation == "history":
        payload["events"][0]["history"][0]["amount"] = 7.5
    else:
        payload["terminal"]["bluffs"] += 1
    manifest, artifacts = _replace_artifact(completed, _EVIDENCE_PATH, payload)
    with pytest.raises(ValueError):
        _validate_r005(manifest, artifacts, logs=completed.logs)


def test_no_future_leak_or_wrong_solver_identity_in_saved_dpl(completed):
    logs = copy.deepcopy(completed.logs)
    logs[0].base_strategy_provenance = logs[0].base_strategy_provenance.model_copy(
        update={"source": "wrong-solver"}
    )
    with pytest.raises(ValueError, match="earlier public"):
        _validate_r005(completed.manifest, completed.posterior_bundle.artifacts, logs=logs)
    manifest = completed.manifest.model_copy(deep=True)
    manifest.versions.strategy_table_version = "wrong"
    with pytest.raises(ValueError, match="solver identity"):
        _validate_r005(manifest, completed.posterior_bundle.artifacts)


def test_cli_saved_bundle_and_successor_handoff(tmp_path, capsys):
    root = tmp_path / "source"
    assert (
        run_session_cli.main(
            [
                "--leaky-fixture",
                "--leaky-fixture-reason",
                "LEAK_R005",
                "--hands",
                "100",
                "--explanations",
                "--out-dir",
                str(root),
            ]
        )
        == 0
    )
    path = root / "S20260704.manifest.json"
    assert verify_saved_explanation_bundle(path).dpl_count == 100
    settings = load_next_session_settings(path)
    before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    successor = tmp_path / "successor"
    assert (
        run_session_cli.main(
            [
                "--seed",
                "20260705",
                "--hands",
                "1",
                "--leaky-fixture",
                "--leaky-fixture-reason",
                "LEAK_R005",
                "--explanations",
                "--previous-session-manifest",
                str(path),
                "--out-dir",
                str(successor),
            ]
        )
        == 0
    )
    log = DecisionProvenanceLog.model_validate_json(
        (successor / "S20260705.dpl.jsonl").read_text().strip()
    )
    assert log.detected_leaks == []
    assert log.safety_alpha == settings.safety_alpha
    assert verify_saved_explanation_bundle(successor / "S20260705.manifest.json").dpl_count == 1
    assert before == {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    # A rehashed, structurally valid but false evaluation must also fail.
    manifest = RunManifest.model_validate_json(path.read_bytes())
    ref = next(
        ref for ref in manifest.outputs if ref.path.endswith(".post_session_evaluation.json")
    )
    evaluation_path = root / ref.path
    payload = json.loads(evaluation_path.read_bytes())
    payload["evaluation"]["average_estimation_error"] = 0.99
    raw = canonical_json_bytes(payload)
    evaluation_path.write_bytes(raw)
    ref.sha256 = sha256_bytes(raw)
    path.write_text(manifest.model_dump_json(), encoding="utf-8")
    with pytest.raises(SavedExplanationBundleVerificationError, match="r005-post-session"):
        load_next_session_settings(path)
    rejected = tmp_path / "rejected-successor"
    assert (
        run_session_cli.main(
            [
                "--previous-session-manifest",
                str(path),
                "--out-dir",
                str(rejected),
            ]
        )
        == 1
    )
    assert not rejected.exists()


def test_r005_requires_opt_in_and_r006_stays_unimplemented(tmp_path, capsys):
    for args in (
        ["--leaky-fixture-reason", "LEAK_R005"],
        ["--leaky-fixture", "--leaky-fixture-reason", "LEAK_R006"],
    ):
        with pytest.raises(SystemExit) as error:
            run_session_cli.main([*args, "--out-dir", str(tmp_path / "absent")])
        assert error.value.code == 2
        assert not (tmp_path / "absent").exists()
    from opponents.model import leak_action_mapping

    with pytest.raises(ValueError, match="unsupported"):
        leak_action_mapping("LEAK_R005")


def test_r005_evidence_cannot_be_routed_to_generic_verification(tmp_path, completed):
    from poker_ai._r005_bundle import _is_r005
    from poker_ai.explanation_artifacts import (
        NORMAL_HERO_EXPLANATION_ARTIFACT_ID,
        write_verified_explanation_bundle,
    )

    paths = write_verified_explanation_bundle(
        completed,
        tmp_path,
        artifact_id=NORMAL_HERO_EXPLANATION_ARTIFACT_ID,
        safety_alpha=1.0,
        leaky_fixture=True,
        answer_key=opponent._reveal_r005_answer_key(),
    )
    manifest = RunManifest.model_validate_json(paths.manifest.read_bytes())
    manifest.opponents[0].opponent_id = "stub_jam_all"
    manifest.versions.baseline_table_version = "0.0.1-stub"
    for ref in manifest.outputs:
        if ref.name == "r005_public_showdowns":
            ref.name = "other-observations"
            path = tmp_path / ref.path
            payload = json.loads(path.read_bytes())
            payload["terminal"]["bluffs"] = 9999
        elif ref.path.endswith(".post_session_evaluation.json"):
            path = tmp_path / ref.path
            payload = json.loads(path.read_bytes())
            payload["evaluation"]["opponent_model_id"] = "stub_jam_all"
            payload["next_session_settings"]["safety_alpha"] = 0.123
        else:
            continue
        raw = canonical_json_bytes(payload)
        path.write_bytes(raw)
        ref.sha256 = sha256_bytes(raw)
    paths.manifest.write_text(manifest.model_dump_json(), encoding="utf-8")
    with pytest.raises(SavedExplanationBundleVerificationError, match="r005-public-evidence"):
        load_next_session_settings(paths.manifest)
    # Even removing every manifest marker cannot hide the DPL's R005 provenance.
    stripped = manifest.model_copy(deep=True)
    stripped.configs = []
    stripped.outputs = []
    assert not _is_r005(stripped)
    assert _is_r005(stripped, logs=completed.logs)
