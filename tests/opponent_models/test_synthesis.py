"""Deterministic synthesis and independent true-leak regression checks."""

from __future__ import annotations

import json
from decimal import Decimal

import pytest

from opponents import (
    DEFAULT_EQUILIBRIUM_ROOT,
    OpponentModelConfig,
    equilibrium_artifact_sha256,
    extract_true_leaks,
    load_frozen_equilibrium,
    load_training_catalog,
    load_validation_catalog,
    synthesize_opponent,
)
from poker_solver.cfr_plus import solve_cfr_plus

EQUILIBRIUM_VERSION = "river-large-bet-equilibrium-v1"
TRUE_LEAK_TOLERANCE = Decimal("1e-12")


def test_frozen_strategy_exactly_replays_declared_solver_provenance():
    config = load_training_catalog()[0]
    frozen = load_frozen_equilibrium(
        config.equilibrium_version,
        expected_sha256=config.equilibrium_artifact_sha256,
    )

    assert frozen.solver_provenance == {
        "algorithm": "cfr-plus",
        "implementation": "poker_solver.cfr_plus.solve_cfr_plus",
        "iterations": 10000,
        "average_delay": 100,
    }
    replayed = solve_cfr_plus(frozen.game, 10000, average_delay=100)

    assert replayed == frozen.strategy


def test_every_development_catalog_leak_matches_frozen_artifact_ground_truth():
    catalog = (*load_training_catalog(), *load_validation_catalog())

    for config in catalog:
        generated = synthesize_opponent(config=config)
        measured = extract_true_leaks(
            generated.game,
            generated.equilibrium_strategy,
            generated.strategy,
            config,
        )
        assert generated.equilibrium_version == config.equilibrium_version
        assert generated.equilibrium_artifact_sha256 == config.equilibrium_artifact_sha256
        assert {item.reason_id for item in measured} == set(config.leak_amounts)
        for item in measured:
            assert abs(item.true_leak - config.leak_amounts[item.reason_id]) <= TRUE_LEAK_TOLERANCE


def test_gto_negative_control_is_an_exact_profile_copy():
    config = next(config for config in load_training_catalog() if not config.leak_vector)

    generated = synthesize_opponent(config=config)

    assert generated.strategy == generated.equilibrium_strategy
    assert generated.strategy is not generated.equilibrium_strategy
    assert generated.application.applied_locks == ()
    assert (
        extract_true_leaks(
            generated.game,
            generated.equilibrium_strategy,
            generated.strategy,
            config,
        )
        == ()
    )


def test_same_generation_config_reproduces_identity_targets_and_strategy():
    config = load_validation_catalog()[-1]

    first = synthesize_opponent(config=config)
    second = synthesize_opponent(
        config=OpponentModelConfig.from_payload(config.canonical_payload())
    )

    assert first.config.model_identity == second.config.model_identity
    assert first.config_sha256 == second.config_sha256
    assert first.equilibrium_artifact_sha256 == second.equilibrium_artifact_sha256
    assert first.node_lock_config == second.node_lock_config
    assert first.leak_targets == second.leak_targets
    assert first.strategy == second.strategy


def test_multiple_nonoverlapping_leaks_are_composed_deterministically():
    base = load_training_catalog()[0].canonical_payload()
    base.update(
        {
            "opponent_id": "nl-fixture-compound-s777",
            "seed": 777,
            "leak_vector": {"LEAK_R001": "0.08", "LEAK_R007": "0.12"},
        }
    )
    config = OpponentModelConfig.from_payload(base)

    generated = synthesize_opponent(config=config)
    measured = extract_true_leaks(
        generated.game,
        generated.equilibrium_strategy,
        generated.strategy,
        config,
    )

    assert len(generated.application.applied_locks) == 2
    assert {item.reason_id for item in measured} == {"LEAK_R001", "LEAK_R007"}
    for item in measured:
        assert abs(item.true_leak - config.leak_amounts[item.reason_id]) <= TRUE_LEAK_TOLERANCE


def test_same_version_with_different_self_consistent_profile_is_rejected(tmp_path):
    config = load_training_catalog()[1]
    source = DEFAULT_EQUILIBRIUM_ROOT / f"{EQUILIBRIUM_VERSION}.equilibrium.json"
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["strategy"]["IP:6h6c:vs_bet"] = {
        "CALL": "0.5",
        "FOLD": "0.5",
    }
    payload["artifact_sha256"] = equilibrium_artifact_sha256(payload)
    (tmp_path / source.name).write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="opponent config SHA-256"):
        synthesize_opponent(config=config, equilibrium_root=tmp_path)
