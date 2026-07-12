from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from opponents import load_training_catalog
from phase6 import (
    ObservationNodeSpec,
    ObservationRegistry,
    TrainingCandidateResult,
    TrainingSessionResult,
    build_training_batch_plan,
    canonical_json_bytes,
    derive_stream_root,
    run_training_execution_adapter,
    sampling_contract_payload,
    verify_training_artifact_bundle,
    verify_training_execution_records,
    write_training_artifact_bundle,
)


def _contract():
    registry = ObservationRegistry(
        "fixture-observation-v1",
        (ObservationNodeSpec("deal", "deal-outcomes-v1", (("left", 0.5), ("right", 0.5))),),
    )
    return sampling_contract_payload(
        observation_registry_version=registry.registry_version,
        observation_registry_sha256=registry.sha256,
    )


@pytest.fixture(scope="module")
def plan():
    return build_training_batch_plan(_contract())


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _payload_hash(payload: object) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _rewrite_artifact(bundle, name, payload):
    raw = canonical_json_bytes(payload)
    (bundle.root / bundle.references[name]["path"]).write_bytes(raw)
    bundle.references[name]["sha256"] = hashlib.sha256(raw).hexdigest()


class _FakeTrainingBackend:
    backend_id = "fixture-in-memory"
    backend_version = "v1"

    def __init__(self, mode="ok"):
        self.mode = mode
        self.session_request_count = 0
        self.candidate_request_count = 0

    def run_sessions(self, requests):
        self.session_request_count = len(requests)
        results = tuple(
            TrainingSessionResult(
                split="training",
                key=request.key,
                stream_roots=request.stream_roots,
                terminal_candidate_snapshot={
                    "kind": "terminal_candidate_snapshot",
                    "session": request.key.canonical_payload(),
                },
                hero_policy_snapshot={
                    "kind": "hero_policy_snapshot",
                    "candidate_id": request.key.candidate_id,
                    "stream_digests": [root.digest for root in request.stream_roots],
                },
                exact_ev_cell={
                    "kind": "exact_ev_cell",
                    "opponent_id": request.key.opponent_id,
                    "horizon": request.key.horizon,
                    "repetition_id": request.key.repetition_id,
                },
            )
            for request in requests
        )
        if self.mode == "missing":
            return results[:-1]
        if self.mode == "duplicate":
            return (*results[:-1], results[0])
        if self.mode == "out_of_order":
            return (results[1], results[0], *results[2:])
        if self.mode == "validation":
            return (replace(results[0], split="validation"), *results[1:])
        return results

    def evaluate_candidates(self, requests):
        self.candidate_request_count = len(requests)
        results = tuple(
            TrainingCandidateResult(
                split="training",
                candidate_id=request.candidate.candidate_id,
                session_join_sha256=request.session_join_sha256,
                calibration_cell={
                    "kind": "calibration_cell",
                    "session_count": len(request.session_results),
                },
                aggregate_metrics={
                    "kind": "aggregate_metrics",
                    "source_session_join_sha256": request.session_join_sha256,
                },
            )
            for request in requests
        )
        if self.mode == "candidate_out_of_order":
            return (results[1], results[0], *results[2:])
        return results


@pytest.fixture(scope="module")
def execution_records(plan):
    return run_training_execution_adapter(plan, _FakeTrainingBackend())


def test_training_plan_is_complete_reproducible_and_training_only(plan):
    rebuilt = build_training_batch_plan(_contract())

    assert plan.manifest_bytes == rebuilt.manifest_bytes
    assert plan.manifest_sha256 == rebuilt.manifest_sha256
    assert len(plan.candidates) == 16
    assert len(plan.sessions) == 16 * 9 * 3 * 30 == 12960
    assert len(set(plan.sessions)) == 12960
    assert plan.manifest["split"] == "training"
    assert {item["payload"]["split"] for item in plan.manifest["stream_roots"]} == {"training"}
    assert plan.manifest["expected_cardinality"] == {
        "candidate_count": 16,
        "opponent_count": 9,
        "horizon_count": 3,
        "repetition_count": 30,
        "session_count": 12960,
        "stream_root_count": 3240,
    }
    assert plan.manifest["artifact_bundle"] == {
        "bundle_kind": "training_execution",
        "artifacts": [
            {
                "artifact_type": artifact_type,
                "schema_version": "phase6-training-execution-artifact-v1",
            }
            for artifact_type in (
                "terminal_candidate_snapshots",
                "hero_policy_snapshots",
                "exact_ev_cells",
                "calibration_cells",
                "aggregate_metrics",
            )
        ],
    }


def test_writer_emits_canonical_hash_bound_fixture_bundle(plan, execution_records, tmp_path):
    records = execution_records
    bundle = write_training_artifact_bundle(plan, records, tmp_path)
    verify_training_artifact_bundle(bundle)

    assert set(bundle.references) == {
        "training_batch_manifest",
        "terminal_candidate_snapshots",
        "hero_policy_snapshots",
        "exact_ev_cells",
        "calibration_cells",
        "aggregate_metrics",
        "training_selection_report",
    }
    selection = json.loads((tmp_path / "training_selection_report.json").read_bytes())
    assert selection["performance_based_top_n"] is None
    assert selection["input_candidate_ids"] == selection["retained_candidate_ids"]
    assert selection["p6_8_candidate_count"] == 16
    for reference in bundle.references.values():
        raw = (tmp_path / reference["path"]).read_bytes()
        assert raw == canonical_json_bytes(json.loads(raw))
        assert hashlib.sha256(raw).hexdigest() == reference["sha256"]

    reversed_records = {
        artifact_type: tuple(reversed(items)) for artifact_type, items in records.items()
    }
    second = write_training_artifact_bundle(plan, reversed_records, tmp_path / "reordered")
    for name in bundle.references:
        assert (tmp_path / bundle.references[name]["path"]).read_bytes() == (
            second.root / second.references[name]["path"]
        ).read_bytes()


@pytest.mark.parametrize(
    "artifact_type", ["terminal_candidate_snapshots", "hero_policy_snapshots", "exact_ev_cells"]
)
def test_writer_rejects_incomplete_or_duplicate_session_joins(
    plan, execution_records, tmp_path, artifact_type
):
    records = dict(execution_records)
    records[artifact_type] = records[artifact_type][1:]
    with pytest.raises(ValueError, match="exactly join the Training session set"):
        write_training_artifact_bundle(plan, records, tmp_path)


def test_writer_rejects_candidate_loss_extra_types_and_noncanonical_hash(
    plan, execution_records, tmp_path
):
    records = dict(execution_records)
    records["aggregate_metrics"] = records["aggregate_metrics"][:-1]
    with pytest.raises(ValueError, match="exactly join the candidate set"):
        write_training_artifact_bundle(plan, records, tmp_path / "missing")

    records = dict(execution_records)
    records["validation_metrics"] = ()
    with pytest.raises(ValueError, match="exactly the five approved"):
        write_training_artifact_bundle(plan, records, tmp_path / "extra")

    records = dict(execution_records)
    first = records["calibration_cells"][0]
    records["calibration_cells"] = (
        replace(first, payload_sha256="A" * 64),
        *records["calibration_cells"][1:],
    )
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        write_training_artifact_bundle(plan, records, tmp_path / "hash")


def test_verifier_rejects_tampering_and_writer_is_immutable(plan, execution_records, tmp_path):
    records = execution_records
    bundle = write_training_artifact_bundle(plan, records, tmp_path)
    target = tmp_path / "aggregate_metrics.json"
    target.write_bytes(target.read_bytes().replace(b"aggregate_metrics", b"calibration_cells", 1))
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_training_artifact_bundle(bundle)

    bundle.references["aggregate_metrics"]["sha256"] = hashlib.sha256(
        target.read_bytes()
    ).hexdigest()
    with pytest.raises(ValueError, match="provenance mismatch"):
        verify_training_artifact_bundle(bundle)

    with pytest.raises(ValueError, match="immutable artifact"):
        write_training_artifact_bundle(plan, records, tmp_path)


def test_verifier_rehashes_record_payload_after_outer_reference_rehash(
    plan, execution_records, tmp_path
):
    bundle = write_training_artifact_bundle(plan, execution_records, tmp_path)
    name = "aggregate_metrics"
    payload = json.loads((tmp_path / bundle.references[name]["path"]).read_bytes())
    payload["records"][0]["payload_sha256"] = _hash("substituted-record-hash")
    _rewrite_artifact(bundle, name, payload)

    with pytest.raises(ValueError, match="does not match its canonical payload"):
        verify_training_artifact_bundle(bundle)


@pytest.mark.parametrize("substitution", ["validation_split", "opponent", "horizon"])
def test_verifier_rejects_valid_but_unapproved_stream_root(
    plan, execution_records, tmp_path, substitution
):
    bundle = write_training_artifact_bundle(plan, execution_records, tmp_path)
    name = "training_batch_manifest"
    manifest = json.loads((tmp_path / bundle.references[name]["path"]).read_bytes())
    stream_payload = dict(manifest["stream_roots"][0]["payload"])
    if substitution == "validation_split":
        stream_payload["split"] = "validation"
    elif substitution == "opponent":
        stream_payload["opponent_id"] = "unapproved-training-opponent"
    else:
        stream_payload["horizon"] = 51
    root = derive_stream_root(
        split=stream_payload["split"],
        opponent_id=stream_payload["opponent_id"],
        horizon=stream_payload["horizon"],
        repetition_id=stream_payload["repetition_id"],
        stream_name=stream_payload["stream_name"],
    )
    manifest["stream_roots"][0] = {"digest": root.digest, "payload": root.payload}
    _rewrite_artifact(bundle, name, manifest)

    with pytest.raises(ValueError, match="do not exactly match the approved product"):
        verify_training_artifact_bundle(bundle)


def test_verifier_rejects_coherently_reidentified_candidate(plan, execution_records, tmp_path):
    bundle = write_training_artifact_bundle(plan, execution_records, tmp_path)
    name = "training_batch_manifest"
    manifest = json.loads((tmp_path / bundle.references[name]["path"]).read_bytes())
    config = dict(manifest["candidates"][0]["config"])
    config["epsilon"] = "0.06"
    replacement_id = hashlib.sha256(canonical_json_bytes(config)).hexdigest()
    manifest["candidates"][0] = {
        "candidate_id": f"primary_bb_v2__{replacement_id}",
        "config": config,
    }
    _rewrite_artifact(bundle, name, manifest)

    with pytest.raises(ValueError, match="not the approved canonical grid"):
        verify_training_artifact_bundle(bundle)


def test_builder_rejects_arbitrary_nine_item_training_catalog(tmp_path):
    training_root = tmp_path / "training"
    training_root.mkdir()
    for index, opponent in enumerate(load_training_catalog()):
        payload = opponent.canonical_payload()
        payload["opponent_id"] = f"alternate-train-{index:02d}"
        (training_root / f"alternate-{index:02d}.opponent.json").write_bytes(
            canonical_json_bytes(payload)
        )

    with pytest.raises(ValueError, match="differs from the approved repository catalog"):
        build_training_batch_plan(_contract(), catalog_root=tmp_path)


def test_execution_adapter_is_deterministic_and_completely_joined(
    plan, execution_records, tmp_path
):
    verify_training_execution_records(plan, execution_records)
    assert {name: len(records) for name, records in execution_records.items()} == {
        "terminal_candidate_snapshots": 12960,
        "hero_policy_snapshots": 12960,
        "exact_ev_cells": 12960,
        "calibration_cells": 16,
        "aggregate_metrics": 16,
    }
    first = execution_records["terminal_candidate_snapshots"][0].payload
    assert first["split"] == "training"
    assert [root["payload"]["stream_name"] for root in first["stream_roots"]] == [
        "observation",
        "hero_action",
        "epsilon_branch",
        "epsilon_action",
    ]
    joins = {
        record.candidate_id: record.payload["source_session_join_sha256"]
        for record in execution_records["calibration_cells"]
    }
    assert joins == {
        record.candidate_id: record.payload["source_session_join_sha256"]
        for record in execution_records["aggregate_metrics"]
    }

    rebuilt = run_training_execution_adapter(plan, _FakeTrainingBackend())
    assert {
        name: [record.payload_sha256 for record in records]
        for name, records in execution_records.items()
    } == {name: [record.payload_sha256 for record in records] for name, records in rebuilt.items()}

    bundle = write_training_artifact_bundle(plan, execution_records, tmp_path)
    assert {
        json.loads((tmp_path / bundle.references[name]["path"]).read_bytes())["schema_version"]
        for name in execution_records
    } == {"phase6-training-execution-artifact-v1"}
    verify_training_artifact_bundle(bundle)


def test_saved_execution_bundle_rejects_chained_session_result_rehash(
    plan, execution_records, tmp_path
):
    bundle = write_training_artifact_bundle(plan, execution_records, tmp_path)
    name = "exact_ev_cells"
    payload = json.loads((tmp_path / bundle.references[name]["path"]).read_bytes())
    record = payload["records"][0]
    record["payload"]["result"] = {"kind": "forged_exact_ev_cell"}
    record["payload_sha256"] = _payload_hash(record["payload"])
    _rewrite_artifact(bundle, name, payload)

    with pytest.raises(ValueError, match="not bound to its complete session join"):
        verify_training_artifact_bundle(bundle)


def test_saved_execution_bundle_rejects_schema_downgrade_and_chained_rehash(
    plan, execution_records, tmp_path
):
    bundle = write_training_artifact_bundle(plan, execution_records, tmp_path)
    for name in (
        "terminal_candidate_snapshots",
        "hero_policy_snapshots",
        "exact_ev_cells",
        "calibration_cells",
        "aggregate_metrics",
    ):
        payload = json.loads((tmp_path / bundle.references[name]["path"]).read_bytes())
        for record in payload["records"]:
            record["payload"]["schema_version"] = "phase6-generic-record-v1"
            record["payload_sha256"] = _payload_hash(record["payload"])
        if name == "exact_ev_cells":
            record = payload["records"][0]
            record["payload"]["result"] = {"kind": "forged_exact_ev_cell"}
            record["payload_sha256"] = _payload_hash(record["payload"])
        _rewrite_artifact(bundle, name, payload)

    with pytest.raises(ValueError, match="payload provenance mismatch"):
        verify_training_artifact_bundle(bundle)


def test_saved_execution_bundle_rejects_all_markers_removed_and_chained_rehash(
    plan, execution_records, tmp_path
):
    bundle = write_training_artifact_bundle(plan, execution_records, tmp_path)
    for name in (
        "terminal_candidate_snapshots",
        "hero_policy_snapshots",
        "exact_ev_cells",
        "calibration_cells",
        "aggregate_metrics",
    ):
        payload = json.loads((tmp_path / bundle.references[name]["path"]).read_bytes())
        for record in payload["records"]:
            record["payload"] = {"fixture_payload": f"forged:{name}"}
            record["payload_sha256"] = _payload_hash(record["payload"])
        _rewrite_artifact(bundle, name, payload)

    with pytest.raises(ValueError, match="execution payload fields are not closed-world"):
        verify_training_artifact_bundle(bundle)


def test_saved_execution_bundle_rejects_outer_schema_downgrade_and_all_markers_removed(
    plan, execution_records, tmp_path
):
    bundle = write_training_artifact_bundle(plan, execution_records, tmp_path)
    for name in (
        "terminal_candidate_snapshots",
        "hero_policy_snapshots",
        "exact_ev_cells",
        "calibration_cells",
        "aggregate_metrics",
    ):
        payload = json.loads((tmp_path / bundle.references[name]["path"]).read_bytes())
        payload["schema_version"] = "phase6-training-artifact-v1"
        for record in payload["records"]:
            record["payload"] = {"fixture_payload": f"forged:{name}"}
            record["payload_sha256"] = _payload_hash(record["payload"])
        _rewrite_artifact(bundle, name, payload)

    with pytest.raises(ValueError, match="result artifact provenance mismatch"):
        verify_training_artifact_bundle(bundle)


def test_execution_adapter_invokes_the_complete_products(plan):
    backend = _FakeTrainingBackend()
    run_training_execution_adapter(plan, backend)
    assert backend.session_request_count == 12960
    assert backend.candidate_request_count == 16


@pytest.mark.parametrize("mutation", ["reversed", "adjacent_swap"])
def test_execution_adapter_rejects_plan_session_order_mismatch(plan, mutation):
    sessions = list(plan.sessions)
    if mutation == "reversed":
        sessions.reverse()
    else:
        sessions[0], sessions[1] = sessions[1], sessions[0]

    with pytest.raises(ValueError, match="manifest session order differs from the plan"):
        run_training_execution_adapter(
            replace(plan, sessions=tuple(sessions)), _FakeTrainingBackend()
        )


@pytest.mark.parametrize("mode", ["missing", "duplicate", "out_of_order", "candidate_out_of_order"])
def test_execution_adapter_rejects_missing_duplicate_or_out_of_order_backend_results(plan, mode):
    with pytest.raises(ValueError, match="missing, duplicate, or out of order"):
        run_training_execution_adapter(plan, _FakeTrainingBackend(mode))


def test_execution_adapter_rejects_validation_split_from_backend(plan):
    with pytest.raises(ValueError, match="non-Training split"):
        run_training_execution_adapter(plan, _FakeTrainingBackend("validation"))


def test_execution_record_verifier_rejects_hash_and_split_tampering(plan, execution_records):
    records = dict(execution_records)
    first = records["exact_ev_cells"][0]
    records["exact_ev_cells"] = (
        replace(first, payload_sha256="0" * 64),
        *records["exact_ev_cells"][1:],
    )
    with pytest.raises(ValueError, match="does not match its canonical payload"):
        verify_training_execution_records(plan, records)

    records = dict(execution_records)
    first = records["terminal_candidate_snapshots"][0]
    payload = dict(first.payload)
    payload["split"] = "validation"
    records["terminal_candidate_snapshots"] = (
        replace(first, payload=payload, payload_sha256=_payload_hash(payload)),
        *records["terminal_candidate_snapshots"][1:],
    )
    with pytest.raises(ValueError, match="payload provenance mismatch"):
        verify_training_execution_records(plan, records)
