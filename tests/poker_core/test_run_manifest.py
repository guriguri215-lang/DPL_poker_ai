"""Tests for the RunManifest reproducibility contract (REV-20260702 M-7)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from poker_core.run_manifest import MANIFEST_SCHEMA_VERSION, RunManifest


def test_valid_manifest_round_trips(valid_manifest):
    manifest = RunManifest.model_validate(valid_manifest)
    assert manifest.schema_version == MANIFEST_SCHEMA_VERSION
    assert manifest.created_at is not None  # default-stamped
    assert manifest.opponents[0].split == "training"
    again = RunManifest.model_validate_json(manifest.model_dump_json())
    assert again == manifest


def test_ontology_version_mismatch_rejected(valid_manifest):
    valid_manifest["versions"]["reason_ontology_version"] = "9.9.9"
    with pytest.raises(ValidationError, match="does not match the loaded"):
        RunManifest.model_validate(valid_manifest)


def test_bad_sha256_rejected(valid_manifest):
    valid_manifest["configs"][0]["sha256"] = "not-a-hash"
    with pytest.raises(ValidationError):
        RunManifest.model_validate(valid_manifest)


def test_missing_code_field_rejected(valid_manifest):
    del valid_manifest["code"]["git_commit"]
    with pytest.raises(ValidationError):
        RunManifest.model_validate(valid_manifest)


def test_unsupported_schema_version_rejected(valid_manifest):
    valid_manifest["schema_version"] = "0.1.0"
    with pytest.raises(ValidationError, match="unsupported manifest schema_version"):
        RunManifest.model_validate(valid_manifest)


def test_invalid_split_rejected(valid_manifest):
    valid_manifest["opponents"][0]["split"] = "holdout"
    with pytest.raises(ValidationError):
        RunManifest.model_validate(valid_manifest)


def test_empty_seed_name_rejected(valid_manifest):
    valid_manifest["seeds"] = {"": 1}
    with pytest.raises(ValidationError, match="seed names must be non-empty"):
        RunManifest.model_validate(valid_manifest)


def test_extra_field_forbidden(valid_manifest):
    valid_manifest["oops"] = True
    with pytest.raises(ValidationError):
        RunManifest.model_validate(valid_manifest)


def test_minimal_manifest_without_optional_lists():
    manifest = RunManifest.model_validate(
        {
            "run_id": "R2",
            "code": {
                "git_commit": "abc",
                "package_version": "0.0.0",
                "python_version": "3.12.0",
            },
            "versions": {
                "reason_ontology_version": "1.0.0",
                "cluster_def_version": "1.0.0",
                "strategy_table_version": "1.0.0",
                "baseline_table_version": "1.0.0",
            },
        }
    )
    assert manifest.configs == []
    assert manifest.opponents == []
    assert manifest.seeds == {}
