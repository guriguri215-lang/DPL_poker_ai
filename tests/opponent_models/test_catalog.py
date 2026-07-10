"""Catalog identity and physical split isolation checks (P6-3)."""

from __future__ import annotations

import json

import pytest

from opponents.catalog import (
    TestPoolAccessError as PoolAccessDenied,
)
from opponents.catalog import (
    load_development_catalog,
    load_training_catalog,
    load_validation_catalog,
)
from opponents.model import OpponentModelConfig


def test_catalog_has_nine_reproducible_training_and_validation_models():
    training = load_training_catalog()
    validation = load_validation_catalog()
    catalog = (*training, *validation)

    assert len(training) == 5
    assert len(validation) == 4
    assert len(catalog) == 9
    assert {config.split for config in training} == {"training"}
    assert {config.split for config in validation} == {"validation"}
    assert len({config.opponent_id for config in catalog}) == len(catalog)
    assert len({config.config_sha256 for config in catalog}) == len(catalog)
    assert {config.seed for config in training} == {100, 101, 102, 103, 104}
    assert {config.seed for config in validation} == {201, 202, 203, 204}
    for config in catalog:
        rebuilt = OpponentModelConfig.from_payload(config.canonical_payload())
        assert rebuilt == config
        assert rebuilt.model_identity == config.model_identity
        assert rebuilt.config_sha256 == config.config_sha256


def test_catalog_uses_preregistered_training_and_validation_delta_sets():
    training = load_training_catalog()
    validation = load_validation_catalog()

    assert {str(amount) for config in training for amount in config.leak_amounts.values()} == {
        "0.08",
        "0.16",
    }
    assert {str(amount) for config in validation for amount in config.leak_amounts.values()} == {
        "0.12",
        "0.24",
    }
    assert {reason for config in training for reason in config.leak_amounts} == {
        "LEAK_R001",
        "LEAK_R007",
    }
    assert {reason for config in validation for reason in config.leak_amounts} == {
        "LEAK_R001",
        "LEAK_R007",
    }
    assert sum(not config.leak_vector for config in training) == 1
    assert all(config.leak_vector for config in validation)


def test_normal_loader_rejects_test_before_touching_catalog_root():
    class ExplodingPath:
        def __fspath__(self):
            raise AssertionError("Test rejection must happen before filesystem access")

    with pytest.raises(PoolAccessDenied, match="unavailable"):
        load_development_catalog("test", catalog_root=ExplodingPath())


def test_loader_rejects_config_stored_in_the_wrong_physical_split(tmp_path):
    training_dir = tmp_path / "training"
    training_dir.mkdir()
    source = load_validation_catalog()[0].canonical_payload()
    (training_dir / "wrong.opponent.json").write_text(json.dumps(source), encoding="utf-8")

    with pytest.raises(ValueError, match="declares split 'validation'"):
        load_training_catalog(catalog_root=tmp_path)


def test_config_parser_rejects_untracked_generation_fields():
    payload = load_training_catalog()[0].canonical_payload()
    payload["selected_from_test"] = True

    with pytest.raises(ValueError, match="fields mismatch"):
        OpponentModelConfig.from_payload(payload)


@pytest.mark.parametrize("amount", ["0.080", "0.0800", "8e-2", "00.08", ".08", "+0.08"])
def test_config_parser_rejects_noncanonical_decimal_spellings(amount):
    payload = load_training_catalog()[1].canonical_payload()
    payload["leak_vector"] = {"LEAK_R001": amount}

    with pytest.raises(ValueError, match="canonical fixed-point spelling"):
        OpponentModelConfig.from_payload(payload)


def test_loader_cannot_bypass_duplicate_identity_with_decimal_spelling(tmp_path):
    training_dir = tmp_path / "training"
    training_dir.mkdir()
    first = load_training_catalog()[1].canonical_payload()
    second = dict(first)
    second["opponent_id"] = "nl-train-r001-d008-alias-s101"
    second["leak_vector"] = {"LEAK_R001": "0.080"}
    (training_dir / "first.opponent.json").write_text(json.dumps(first), encoding="utf-8")
    (training_dir / "second.opponent.json").write_text(json.dumps(second), encoding="utf-8")

    with pytest.raises(ValueError, match="canonical fixed-point spelling"):
        load_training_catalog(catalog_root=tmp_path)
