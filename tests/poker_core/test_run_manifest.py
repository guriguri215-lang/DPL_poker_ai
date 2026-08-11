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
    assert manifest.code.entrypoint == "cli/run_session.py"
    assert manifest.configs[0].role == "scenario"
    again = RunManifest.model_validate_json(manifest.model_dump_json())
    assert again == manifest


# --- code / invocation provenance -----------------------------------------


def test_bad_git_commit_rejected(valid_manifest):
    valid_manifest["code"]["git_commit"] = "xyz"
    with pytest.raises(ValidationError, match="git_commit must be"):
        RunManifest.model_validate(valid_manifest)


def test_unknown_git_commit_sentinel_allowed(valid_manifest):
    valid_manifest["code"]["git_commit"] = "unknown"
    manifest = RunManifest.model_validate(valid_manifest)
    assert manifest.code.git_commit == "unknown"


def test_unknown_dirty_state_round_trips_as_null(valid_manifest):
    valid_manifest["code"]["git_dirty"] = None
    manifest = RunManifest.model_validate(valid_manifest)
    assert manifest.code.git_dirty is None
    assert RunManifest.model_validate_json(manifest.model_dump_json()) == manifest


def test_omitted_dirty_state_keeps_legacy_false_default(valid_manifest):
    del valid_manifest["code"]["git_dirty"]
    assert RunManifest.model_validate(valid_manifest).code.git_dirty is False


def test_entrypoint_required(valid_manifest):
    del valid_manifest["code"]["entrypoint"]
    with pytest.raises(ValidationError):
        RunManifest.model_validate(valid_manifest)


def test_missing_code_field_rejected(valid_manifest):
    del valid_manifest["code"]["git_commit"]
    with pytest.raises(ValidationError):
        RunManifest.model_validate(valid_manifest)


# --- seeds / configs / outputs --------------------------------------------


def test_master_seed_required(valid_manifest):
    valid_manifest["seeds"] = {"sampling": 1}
    with pytest.raises(ValidationError, match="required seed"):
        RunManifest.model_validate(valid_manifest)


def test_empty_seed_name_rejected(valid_manifest):
    valid_manifest["seeds"] = {"": 1}
    with pytest.raises(ValidationError, match="seed names must be non-empty"):
        RunManifest.model_validate(valid_manifest)


def test_config_role_required(valid_manifest):
    del valid_manifest["configs"][0]["role"]
    with pytest.raises(ValidationError):
        RunManifest.model_validate(valid_manifest)


def test_invalid_config_role_rejected(valid_manifest):
    valid_manifest["configs"][0]["role"] = "bogus"
    with pytest.raises(ValidationError):
        RunManifest.model_validate(valid_manifest)


def test_bad_sha256_rejected(valid_manifest):
    valid_manifest["configs"][0]["sha256"] = "not-a-hash"
    with pytest.raises(ValidationError):
        RunManifest.model_validate(valid_manifest)


def test_output_artifact_sha_optional(valid_manifest):
    valid_manifest["outputs"] = [
        {"name": "decisions", "path": "out/decisions.jsonl"},
        {"name": "summary", "path": "out/summary.json", "sha256": "b" * 64},
    ]
    manifest = RunManifest.model_validate(valid_manifest)
    assert manifest.outputs[0].sha256 is None
    assert manifest.outputs[1].sha256 == "b" * 64


def test_output_artifact_bad_sha_rejected(valid_manifest):
    valid_manifest["outputs"] = [{"name": "x", "path": "out/x", "sha256": "nope"}]
    with pytest.raises(ValidationError):
        RunManifest.model_validate(valid_manifest)


# --- ontology compatibility is separate from structural validation --------


def test_old_ontology_version_loads_but_flagged(valid_manifest):
    valid_manifest["versions"]["reason_ontology_version"] = "9.9.9"
    manifest = RunManifest.model_validate(valid_manifest)  # structural load OK
    assert manifest.ontology_matches_current() is False


def test_current_ontology_version_matches(valid_manifest):
    manifest = RunManifest.model_validate(valid_manifest)
    assert manifest.ontology_matches_current() is True


# --- misc ------------------------------------------------------------------


def test_unsupported_schema_version_rejected(valid_manifest):
    valid_manifest["schema_version"] = "0.1.0"
    with pytest.raises(ValidationError, match="unsupported manifest schema_version"):
        RunManifest.model_validate(valid_manifest)


def test_invalid_split_rejected(valid_manifest):
    valid_manifest["opponents"][0]["split"] = "holdout"
    with pytest.raises(ValidationError):
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
                "git_commit": "unknown",
                "package_version": "0.0.0",
                "python_version": "3.12.0",
                "entrypoint": "cli/evaluate.py",
            },
            "versions": {
                "reason_ontology_version": "1.0.0",
                "cluster_def_version": "1.0.0",
                "strategy_table_version": "1.0.0",
                "baseline_table_version": "1.0.0",
            },
            "seeds": {"master": 7},
        }
    )
    assert manifest.configs == []
    assert manifest.opponents == []
    assert manifest.outputs == []
    assert manifest.code.argv == []
