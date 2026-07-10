"""Contextual hard-gate tests for ADR-0019 posterior provenance bundles."""

from __future__ import annotations

import json

import pytest

from poker_ai.posterior_bundle import (
    BASELINE_CONFIG_NAME,
    ESTIMATOR_CONFIG_NAME,
    SNAPSHOT_ARTIFACT_NAME,
    canonical_json_bytes,
    load_posterior_run_bundle,
    sha256_bytes,
    validate_posterior_bundle,
    write_posterior_artifacts,
)
from poker_ai.session import run_session, write_session_bundle


def test_session_bundle_has_exactly_one_reconstructible_posterior_artifact_set(tmp_path):
    result = run_session(20260710, 10)
    _dpl_path, manifest_path = write_session_bundle(result, tmp_path)

    validated = load_posterior_run_bundle(manifest_path)
    estimator_refs = [
        item for item in validated.manifest.configs if item.name == "leak_confidence_estimator"
    ]
    baseline_refs = [
        item for item in validated.manifest.configs if item.name == BASELINE_CONFIG_NAME
    ]
    snapshot_refs = [
        item for item in validated.manifest.outputs if item.name == SNAPSHOT_ARTIFACT_NAME
    ]
    assert len(estimator_refs) == len(baseline_refs) == len(snapshot_refs) == 1
    assert validated.estimator["method_version"] == "beta-binomial-upper-tail-v1"
    assert validated.estimator["detector_min_confidence"] == 0.95
    records = validated.terminal_snapshots["records"]
    situations = {record["situation_key"] for record in records}
    assert len(records) == 2 * len(situations)
    assert sum(record["n"] for record in records if record["rule_id"] == "LEAK_R007") == 10
    for record in records:
        assert record["k"] == sum(
            record["action_counts"].get(action, 0) for action in record["action_group"]
        )


def test_bundle_fails_closed_on_duplicate_required_config(tmp_path):
    result = run_session(1, 2)
    write_posterior_artifacts(result.posterior_bundle, tmp_path)
    baseline_ref = next(
        item for item in result.manifest.configs if item.name == BASELINE_CONFIG_NAME
    )
    manifest = result.manifest.model_copy(deep=True)
    manifest.configs.append(baseline_ref)

    with pytest.raises(ValueError, match="exactly one config"):
        validate_posterior_bundle(manifest, tmp_path)


def test_bundle_fails_closed_on_hash_mismatch(tmp_path):
    result = run_session(1, 2)
    write_posterior_artifacts(result.posterior_bundle, tmp_path)
    baseline_ref = next(
        item for item in result.manifest.configs if item.name == BASELINE_CONFIG_NAME
    )
    target = tmp_path / baseline_ref.path
    target.write_bytes(target.read_bytes() + b" ")

    with pytest.raises(ValueError, match="hash mismatch"):
        validate_posterior_bundle(result.manifest, tmp_path)


@pytest.mark.parametrize("bad_path", ["inline:payload", "../escape.json", "/absolute.json"])
def test_bundle_rejects_non_relative_or_escaping_required_paths(tmp_path, bad_path):
    result = run_session(1, 2)
    write_posterior_artifacts(result.posterior_bundle, tmp_path)
    manifest = result.manifest.model_copy(deep=True)
    baseline_ref = next(item for item in manifest.configs if item.name == BASELINE_CONFIG_NAME)
    baseline_ref.path = bad_path

    with pytest.raises(ValueError, match="bundle path"):
        validate_posterior_bundle(manifest, tmp_path)


def test_bundle_rehash_cannot_hide_snapshot_baseline_join_tampering(tmp_path):
    result = run_session(1, 2)
    write_posterior_artifacts(result.posterior_bundle, tmp_path)
    manifest = result.manifest.model_copy(deep=True)
    snapshot_ref = next(item for item in manifest.outputs if item.name == SNAPSHOT_ARTIFACT_NAME)
    target = tmp_path / snapshot_ref.path
    payload = json.loads(target.read_bytes())
    payload["records"][0]["k"] += 1
    raw = canonical_json_bytes(payload)
    target.write_bytes(raw)
    snapshot_ref.sha256 = sha256_bytes(raw)

    with pytest.raises(ValueError, match="k/n"):
        validate_posterior_bundle(manifest, tmp_path)


def test_bundle_rehash_cannot_hide_posterior_score_tampering(tmp_path):
    result = run_session(1, 2)
    write_posterior_artifacts(result.posterior_bundle, tmp_path)
    manifest = result.manifest.model_copy(deep=True)
    snapshot_ref = next(item for item in manifest.outputs if item.name == SNAPSHOT_ARTIFACT_NAME)
    target = tmp_path / snapshot_ref.path
    payload = json.loads(target.read_bytes())
    payload["records"][0]["posterior_confidence"] = 0.5
    raw = canonical_json_bytes(payload)
    target.write_bytes(raw)
    snapshot_ref.sha256 = sha256_bytes(raw)

    with pytest.raises(ValueError, match="cannot be reconstructed"):
        validate_posterior_bundle(manifest, tmp_path)


@pytest.mark.parametrize(
    ("field", "bad_value", "message"),
    [
        ("seed", 999999, "seed does not match"),
        ("opponent_id", "contradicts-manifest", "opponent does not match"),
        ("horizon", 999999, "horizon does not match"),
    ],
)
def test_bundle_rehash_cannot_hide_snapshot_run_identity_tampering(
    tmp_path, field, bad_value, message
):
    result = run_session(123, 10)
    write_posterior_artifacts(result.posterior_bundle, tmp_path)
    manifest = result.manifest.model_copy(deep=True)
    snapshot_ref = next(item for item in manifest.outputs if item.name == SNAPSHOT_ARTIFACT_NAME)
    target = tmp_path / snapshot_ref.path
    payload = json.loads(target.read_bytes())
    for record in payload["records"]:
        record[field] = bad_value
    raw = canonical_json_bytes(payload)
    target.write_bytes(raw)
    snapshot_ref.sha256 = sha256_bytes(raw)

    with pytest.raises(ValueError, match=message):
        validate_posterior_bundle(manifest, tmp_path)


def test_bundle_rejects_rehashed_empty_terminal_snapshot(tmp_path):
    result = run_session(123, 10)
    write_posterior_artifacts(result.posterior_bundle, tmp_path)
    manifest = result.manifest.model_copy(deep=True)
    snapshot_ref = next(item for item in manifest.outputs if item.name == SNAPSHOT_ARTIFACT_NAME)
    target = tmp_path / snapshot_ref.path
    payload = json.loads(target.read_bytes())
    payload["records"] = []
    raw = canonical_json_bytes(payload)
    target.write_bytes(raw)
    snapshot_ref.sha256 = sha256_bytes(raw)

    with pytest.raises(ValueError, match="missing a canonical run candidate group"):
        validate_posterior_bundle(manifest, tmp_path)


def test_bundle_rejects_rehashed_missing_situation_group(tmp_path):
    result = run_session(123, 10)
    write_posterior_artifacts(result.posterior_bundle, tmp_path)
    manifest = result.manifest.model_copy(deep=True)
    snapshot_ref = next(item for item in manifest.outputs if item.name == SNAPSHOT_ARTIFACT_NAME)
    target = tmp_path / snapshot_ref.path
    payload = json.loads(target.read_bytes())
    missing_situation = payload["records"][0]["situation_key"]
    payload["records"] = [
        record for record in payload["records"] if record["situation_key"] != missing_situation
    ]
    raw = canonical_json_bytes(payload)
    target.write_bytes(raw)
    snapshot_ref.sha256 = sha256_bytes(raw)

    with pytest.raises(ValueError, match="missing a canonical run candidate group"):
        validate_posterior_bundle(manifest, tmp_path)


@pytest.mark.parametrize(
    ("field", "bad_value", "message"),
    [
        ("leak_type", "ontology-invalid-tamper", "does not match ontology label"),
        ("baseline_rate", 1.5, "must be finite and in"),
        ("direction", "", "direction must not be empty"),
        ("unexpected", "tamper", "strict contract"),
    ],
)
def test_bundle_rehash_cannot_hide_invalid_baseline_contract(tmp_path, field, bad_value, message):
    result = run_session(123, 10)
    write_posterior_artifacts(result.posterior_bundle, tmp_path)
    manifest = result.manifest.model_copy(deep=True)
    baseline_ref = next(item for item in manifest.configs if item.name == BASELINE_CONFIG_NAME)
    estimator_ref = next(item for item in manifest.configs if item.name == ESTIMATOR_CONFIG_NAME)
    baseline_target = tmp_path / baseline_ref.path
    baseline_payload = json.loads(baseline_target.read_bytes())
    baseline_payload["rules"][0][field] = bad_value
    baseline_raw = canonical_json_bytes(baseline_payload)
    baseline_target.write_bytes(baseline_raw)
    baseline_ref.sha256 = sha256_bytes(baseline_raw)

    estimator_target = tmp_path / estimator_ref.path
    estimator_payload = json.loads(estimator_target.read_bytes())
    estimator_payload["baseline_table"]["sha256"] = baseline_ref.sha256
    estimator_raw = canonical_json_bytes(estimator_payload)
    estimator_target.write_bytes(estimator_raw)
    estimator_ref.sha256 = sha256_bytes(estimator_raw)

    with pytest.raises(ValueError, match=message):
        validate_posterior_bundle(manifest, tmp_path)


def test_bundle_rejects_noncanonical_json_even_with_matching_hash(tmp_path):
    result = run_session(1, 2)
    write_posterior_artifacts(result.posterior_bundle, tmp_path)
    manifest = result.manifest.model_copy(deep=True)
    snapshot_ref = next(item for item in manifest.outputs if item.name == SNAPSHOT_ARTIFACT_NAME)
    target = tmp_path / snapshot_ref.path
    payload = json.loads(target.read_bytes())
    raw = json.dumps(payload, indent=2).encode("utf-8")
    target.write_bytes(raw)
    snapshot_ref.sha256 = sha256_bytes(raw)

    with pytest.raises(ValueError, match="not canonical JSON"):
        validate_posterior_bundle(manifest, tmp_path)
