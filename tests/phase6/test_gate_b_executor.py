"""Synthetic-only tests for the concrete Gate B executor."""

from __future__ import annotations

import ast
import copy
import dataclasses
import hashlib
import inspect
import json
import sys
import textwrap
from decimal import Decimal
from functools import lru_cache
from types import MappingProxyType, SimpleNamespace

import pytest

import phase6.gate_b_executor as executor_module
from opponents import OpponentModelConfig, load_training_catalog
from phase6.contracts import (
    COMPONENT_ROLES,
    COVERAGE_CONTRACT_SCHEMA_VERSION,
    GTO_FPR_METRIC_ID,
    PREREGISTRATION_SCHEMA_VERSION,
    ROOT_MANIFEST_SCHEMA_VERSION,
    SELECTION_CONTRACT_SCHEMA_VERSION,
    SELECTION_REPORT_REFERENCE_SCHEMA_VERSION,
    SEMANTIC_FIXTURE_SCHEMA_VERSION,
    SEMANTIC_SOURCE_SCHEMA_VERSION,
    SERIES_REFERENCE_SCHEMA_VERSION,
    VALIDATION_BATCH_REFERENCE_SCHEMA_VERSION,
    CanonicalPhase6ContractArtifact,
    ValidatedPhase6ContractBundleEvidence,
    artifact_ref,
    build_r008_component_source_payloads,
    build_r008_coverage_contract,
    build_r008_fixture_payloads,
    canonical_json_bytes,
    load_phase6_contract_bundle_evidence_from_canonical_artifacts,
    selection_metric_contract_payload,
    sha256_bytes,
    validate_phase6_contract_bundle_evidence,
)
from phase6.exact_ev import CompiledStrategyProfiles, ExactEvCell, ExactEvPaths
from phase6.gate_b_executor import (
    DRAW_DERIVATION_VERSION,
    EXECUTION_SAMPLER_VERSION,
    LEGAL_ACTION_ORDER_VERSION,
    MAX_AGGREGATE_OUTPUT_BYTES,
    MAX_CHUNK_BYTES,
    OUTPUT_LIMITS,
    PROBABILITY_MAPPING_VERSION,
    SEED_DERIVATION_VERSION,
    GateBDeadlineExceeded,
    GateBFrameError,
    GateBOutputError,
    GateBProductionExecutor,
    GateBStreamRoot,
    derive_gate_b_draw_digest,
    gate_b_uniform_action,
)


def _build_genuine_evidence() -> ValidatedPhase6ContractBundleEvidence:
    artifacts: dict[str, CanonicalPhase6ContractArtifact] = {}

    def add(
        relative_path: str,
        payload: dict[str, object],
        *,
        artifact_type: str,
        schema_version: str,
    ) -> dict[str, str]:
        raw = canonical_json_bytes(payload)
        artifacts[relative_path] = CanonicalPhase6ContractArtifact(
            relative_path,
            raw,
            sha256_bytes(raw),
        )
        return artifact_ref(
            artifact_type=artifact_type,
            schema_version=schema_version,
            path=relative_path,
            payload=payload,
        )

    source_payloads = build_r008_component_source_payloads()
    source_refs = {
        role: add(
            f"sources/{role}.json",
            source_payloads[role],
            artifact_type="phase6_semantic_source",
            schema_version=SEMANTIC_SOURCE_SCHEMA_VERSION,
        )
        for role in COMPONENT_ROLES
    }
    fixture_payloads = build_r008_fixture_payloads()
    fixture_refs = {
        fixture_id: add(
            f"fixtures/{fixture_id}.json",
            payload,
            artifact_type="phase6_semantic_fixture",
            schema_version=SEMANTIC_FIXTURE_SCHEMA_VERSION,
        )
        for fixture_id, payload in fixture_payloads.items()
    }
    coverage = build_r008_coverage_contract(source_refs, fixture_refs)
    coverage_ref = add(
        "contracts/coverage.json",
        coverage,
        artifact_type="coverage_semantics_contract",
        schema_version=COVERAGE_CONTRACT_SCHEMA_VERSION,
    )
    selection = selection_metric_contract_payload()
    selection_ref = add(
        "contracts/selection.json",
        selection,
        artifact_type="selection_metric_contract",
        schema_version=SELECTION_CONTRACT_SCHEMA_VERSION,
    )
    preregistration = {
        "schema_version": PREREGISTRATION_SCHEMA_VERSION,
        "artifact_type": "phase6_evaluation_preregistration",
        "coverage_semantics_contract": coverage_ref,
        "selection_metric_contract": selection_ref,
    }
    preregistration_ref = add(
        "references/preregistration.json",
        preregistration,
        artifact_type="phase6_evaluation_preregistration",
        schema_version=PREREGISTRATION_SCHEMA_VERSION,
    )
    common_refs = {
        "preregistration": preregistration_ref,
        "coverage_semantics_contract": coverage_ref,
        "selection_metric_contract": selection_ref,
    }
    series_ref = add(
        "references/series.json",
        {
            "schema_version": SERIES_REFERENCE_SCHEMA_VERSION,
            "artifact_type": "phase6_evaluation_series_reference",
            **copy.deepcopy(common_refs),
        },
        artifact_type="phase6_evaluation_series_reference",
        schema_version=SERIES_REFERENCE_SCHEMA_VERSION,
    )
    validation_batch_ref = add(
        "references/validation-batch.json",
        {
            "schema_version": VALIDATION_BATCH_REFERENCE_SCHEMA_VERSION,
            "artifact_type": "phase6_validation_batch_reference",
            **copy.deepcopy(common_refs),
        },
        artifact_type="phase6_validation_batch_reference",
        schema_version=VALIDATION_BATCH_REFERENCE_SCHEMA_VERSION,
    )
    selection_report_ref = add(
        "references/selection-report.json",
        {
            "schema_version": SELECTION_REPORT_REFERENCE_SCHEMA_VERSION,
            "artifact_type": "phase6_selection_report_reference",
            **copy.deepcopy(common_refs),
            "selection_metric_id": GTO_FPR_METRIC_ID,
        },
        artifact_type="phase6_selection_report_reference",
        schema_version=SELECTION_REPORT_REFERENCE_SCHEMA_VERSION,
    )
    root = {
        "schema_version": ROOT_MANIFEST_SCHEMA_VERSION,
        "artifact_type": "phase6_evaluation_manifest",
        "preregistration": preregistration_ref,
        "coverage_semantics_contract": coverage_ref,
        "selection_metric_contract": selection_ref,
        "series_reference": series_ref,
        "validation_batch_reference": validation_batch_ref,
        "selection_report_reference": selection_report_ref,
    }
    root_raw = canonical_json_bytes(root)
    return load_phase6_contract_bundle_evidence_from_canonical_artifacts(
        root_raw,
        expected_sha256=sha256_bytes(root_raw),
        artifacts=tuple(artifacts.values()),
    )


@lru_cache(maxsize=1)
def _genuine_evidence() -> ValidatedPhase6ContractBundleEvidence:
    return _build_genuine_evidence()


def _opponent_payload(index: int) -> dict[str, object]:
    source = load_training_catalog()[index]
    payload = source.canonical_payload()
    payload.update(
        {
            "opponent_id": f"fixture-test-opponent-{index:03d}",
            "opponent_version": "fixture-opponent-v1",
            "split": "test",
            "leak_vector": {} if index == 0 else {"LEAK_R008": "0.2"},
            "seed": 9000 + index,
        }
    )
    return payload


@lru_cache(maxsize=9)
def _opponent_strategy_sha256(index: int) -> str:
    config = OpponentModelConfig.from_payload(_opponent_payload(index))
    generated = executor_module.synthesize_opponent(config=config)
    return executor_module._strategy_sha256(generated.strategy)


def _selected_config() -> dict[str, object]:
    return {
        "detector_confidence": "0.9",
        "epsilon": "0.1",
        "grid_version": "phase6-primary-grid-v1",
        "provider_confidence": "0.9",
        "safety_alpha": "0.25",
        "sample_floor": 10,
        "sampling_contract_sha256": "f" * 64,
        "tau": "0.25",
    }


def _coordinates() -> dict[str, object]:
    opponents = [f"fixture-test-opponent-{index:03d}" for index in range(9)]
    horizons = [50, 200, 1000]
    repetitions = [f"r{index:03d}" for index in range(1, 31)]
    rows = []
    for opponent_index, opponent_id in enumerate(opponents):
        for horizon in horizons:
            for repetition_index, repetition_id in enumerate(repetitions, start=1):
                rows.append(
                    {
                        "opponent_id": opponent_id,
                        "horizon": horizon,
                        "repetition_id": repetition_id,
                        "seed": 700_000 + opponent_index * 1000 + repetition_index,
                    }
                )
    return {
        "opponent_ids": opponents,
        "horizons": horizons,
        "repetition_ids": repetitions,
        "seed_mapping": rows,
    }


def _component_payloads() -> dict[str, dict[str, object]]:
    payloads = {
        name: {
            "schema_version": f"fixture-{name}-v1",
            "artifact_type": f"fixture_{name}",
        }
        for name in executor_module._COMPONENT_ORDER
    }
    selected = _selected_config()
    primary_raw = canonical_json_bytes(selected)
    gto_config = OpponentModelConfig.from_payload(_opponent_payload(0))
    gto = executor_module.synthesize_opponent(config=gto_config)
    baseline_rate = executor_module.extract_independent_action_rates(
        gto.game,
        gto.equilibrium_strategy,
        gto.config,
        reason_ids=(executor_module.R008_REASON_ID,),
    )[0].action_rate
    payloads["baseline_table"] = {
        "schema_version": "fixture-baseline-table-v1",
        "artifact_type": "fixture_baseline_table",
        "table_version": "fixture-baseline-table-v1",
        "reason_id": executor_module.R008_REASON_ID,
        "situation_key": executor_module.R008_SITUATION_KEY,
        "action_group": list(executor_module.R008_ACTION_GROUP),
        "baseline_rate": executor_module._decimal_wire(baseline_rate),
    }
    payloads["estimator_config"] = {
        "schema_version": "fixture-estimator-config-v1",
        "artifact_type": "fixture_estimator_config",
        "method_version": executor_module.ESTIMATOR_METHOD_VERSION,
        "alpha0": "1",
        "beta0": "1",
        "tail": "upper",
        "tau": selected["tau"],
        "sample_floor": selected["sample_floor"],
        "detector_threshold": selected["detector_confidence"],
        "provider_threshold": selected["provider_confidence"],
    }
    payloads["evaluator"] = {
        "schema_version": "fixture-evaluator-component-v1",
        "artifact_type": "fixture_evaluator",
        "evaluator_version": executor_module.CALIBRATION_EVALUATOR_VERSION,
        "exact_ev_evaluator_version": executor_module.EXACT_EV_INPUT_VERSION,
    }
    payloads["ground_truth_extractor"] = {
        "schema_version": "fixture-ground-truth-component-v1",
        "artifact_type": "fixture_ground_truth_extractor",
        "ground_truth_extractor_version": executor_module.GROUND_TRUTH_EXTRACTOR_VERSION,
        "reason_ids": [executor_module.R008_REASON_ID],
    }
    payloads["selected_config_lock"] = {
        "schema_version": "fixture-selected-config-lock-v1",
        "artifact_type": "fixture_selected_config_lock",
        "selected_config": selected,
    }
    payloads["execution_sampler"] = {
        "schema_version": "fixture-gate-b-sampler-v1",
        "artifact_type": "fixture_execution_sampler",
        "execution_sampler_version": EXECUTION_SAMPLER_VERSION,
        "draw_derivation_version": DRAW_DERIVATION_VERSION,
        "seed_derivation_version": SEED_DERIVATION_VERSION,
        "legal_action_order_version": LEGAL_ACTION_ORDER_VERSION,
        "probability_mapping_version": PROBABILITY_MAPPING_VERSION,
        "common_random_numbers": True,
    }
    payloads["execution_config_index"] = {
        "schema_version": "fixture-execution-config-index-v1",
        "artifact_type": "fixture_execution_config_index",
        "estimator_config_sha256": sha256_bytes(canonical_json_bytes(payloads["estimator_config"])),
        "selected_config_lock_sha256": sha256_bytes(
            canonical_json_bytes(payloads["selected_config_lock"])
        ),
        "primary": {
            "config_id": "fixture-primary-001",
            "derivation": "canonical_json_bytes(selected_config_lock#/selected_config)",
            "name": "primary",
            "sha256": sha256_bytes(primary_raw),
            "size_bytes": len(primary_raw),
            "source_component_sha256": sha256_bytes(
                canonical_json_bytes(payloads["selected_config_lock"])
            ),
        },
        "comparators": [],
        "ablations": [],
    }
    opponent_payloads = [_opponent_payload(index) for index in range(9)]
    payloads["opponent_catalog"] = {
        "schema_version": "fixture-opponent-catalog-v1",
        "artifact_type": "fixture_opponent_catalog",
        "opponents": [
            {
                "opponent_id": payload["opponent_id"],
                "config_sha256": OpponentModelConfig.from_payload(payload).config_sha256,
                "seed": payload["seed"],
                "equilibrium_version": payload["equilibrium_version"],
                "equilibrium_artifact_sha256": payload["equilibrium_artifact_sha256"],
                "strategy_sha256": _opponent_strategy_sha256(index),
                "control_role": (
                    "gto_negative_control" if not payload["leak_vector"] else "evaluation"
                ),
            }
            for index, payload in enumerate(opponent_payloads)
        ],
    }
    payloads["opponent_payload_index"] = {
        "schema_version": "fixture-opponent-payload-index-v1",
        "artifact_type": "fixture_opponent_payload_index",
        "opponents": [
            {
                "opponent_id": payload["opponent_id"],
                "relative_path": f"opponents/{index:03d}.json",
                "sha256": sha256_bytes(canonical_json_bytes(payload)),
                "size_bytes": len(canonical_json_bytes(payload)),
            }
            for index, payload in enumerate(opponent_payloads)
        ],
    }
    return payloads


def _manifest_and_stream() -> tuple[dict[str, object], bytes]:
    payloads = _component_payloads()
    component_refs = {}
    for name in executor_module._COMPONENT_ORDER:
        raw = canonical_json_bytes(payloads[name])
        component_refs[name] = {
            "name": name,
            "schema_version": payloads[name]["schema_version"],
            "sha256": sha256_bytes(raw),
            "size_bytes": len(raw),
        }
    execution_index = payloads["execution_config_index"]
    execution_index["estimator_config_sha256"] = component_refs["estimator_config"]["sha256"]
    execution_index["selected_config_lock_sha256"] = component_refs["selected_config_lock"][
        "sha256"
    ]
    execution_index["primary"]["source_component_sha256"] = component_refs["selected_config_lock"][
        "sha256"
    ]
    execution_index_raw = canonical_json_bytes(execution_index)
    component_refs["execution_config_index"]["sha256"] = sha256_bytes(execution_index_raw)
    component_refs["execution_config_index"]["size_bytes"] = len(execution_index_raw)
    selected = _selected_config()
    primary_raw = canonical_json_bytes(selected)
    manifest = {
        "components": component_refs,
        "selection": {
            "primary_config_id": "fixture-primary-001",
            "primary_config_sha256": sha256_bytes(primary_raw),
            "comparators": [],
            "ablations": [],
        },
        "test_input": {
            "format_id": "fixture-framed-input-v1",
            "physical_split_id": "fixture-test-only",
            "split_id": "fixture-test",
        },
        "coordinates": _coordinates(),
    }
    context = {
        "coordinates": manifest["coordinates"],
        "selection": manifest["selection"],
        "test_input": manifest["test_input"],
    }
    frames = [
        _frame(
            "batch_context",
            "test_batch_context",
            "test_batch_context",
            canonical_json_bytes(context),
        )
    ]
    for name in executor_module._COMPONENT_ORDER:
        frames.append(_frame("component", name, name, canonical_json_bytes(payloads[name])))
    frames.append(_frame("config", "fixture-primary-001", "primary", primary_raw))
    for payload in [_opponent_payload(index) for index in range(9)]:
        frames.append(
            _frame(
                "opponent_payload",
                payload["opponent_id"],
                payload["opponent_id"],
                canonical_json_bytes(payload),
            )
        )
    return manifest, b"".join(frames)


def _frame(frame_type: str, frame_id: str, name: str, payload: bytes) -> bytes:
    header = canonical_json_bytes(
        {
            "frame_type": frame_type,
            "id": frame_id,
            "name": name,
            "sha256": sha256_bytes(payload),
            "size_bytes": len(payload),
        }
    )
    return len(header).to_bytes(8, "big") + header + len(payload).to_bytes(8, "big") + payload


class _Input:
    def __init__(self, raw: bytes, chunk_size: int) -> None:
        self.raw = raw
        self.chunk_size = chunk_size
        self.offset = 0
        self.eof_count = 0
        self.bounds = []

    def read_chunk(self, maximum: int) -> bytes:
        self.bounds.append(maximum)
        assert maximum == MAX_CHUNK_BYTES
        if self.offset == len(self.raw):
            self.eof_count += 1
            assert self.eof_count == 1
            return b""
        end = min(len(self.raw), self.offset + min(self.chunk_size, maximum))
        result = self.raw[self.offset : end]
        self.offset = end
        return result


class _Output:
    def __init__(self) -> None:
        self.values: dict[str, bytearray] = {}
        self.calls: list[tuple[str, int]] = []

    def write_chunk(self, name: str, raw: bytes) -> None:
        assert 1 <= len(raw) <= MAX_CHUNK_BYTES
        self.calls.append((name, len(raw)))
        self.values.setdefault(name, bytearray()).extend(raw)


def _request(manifest: dict[str, object]) -> SimpleNamespace:
    return SimpleNamespace(
        batch=SimpleNamespace(
            payload=executor_module._freeze(manifest),
            test_batch_hash="a" * 64,
        ),
        execution_context=SimpleNamespace(sha256="b" * 64),
    )


@pytest.mark.parametrize("chunk_size", [1, 2, 7, 8, 17, 4095, 4096, 1_048_576])
def test_forward_decoder_accepts_every_boundary_split(chunk_size: int) -> None:
    manifest, raw = _manifest_and_stream()
    source = _Input(raw, chunk_size)

    decoded = executor_module._decode_frames(source, executor_module._freeze(manifest))

    assert len(decoded.opponent_configs) == 9
    assert decoded.configs[0] == _selected_config()
    assert source.eof_count == 1
    assert set(source.bounds) == {MAX_CHUNK_BYTES}


@pytest.mark.parametrize("mutation", ["truncated", "extra", "hash", "order"])
def test_forward_decoder_rejects_truncation_extra_hash_and_order(mutation: str) -> None:
    manifest, raw = _manifest_and_stream()
    if mutation == "truncated":
        raw = raw[:-1]
    elif mutation == "extra":
        raw += b"x"
    elif mutation == "hash":
        raw = raw[:-10] + bytes([raw[-10] ^ 1]) + raw[-9:]
    else:
        first_header_size = int.from_bytes(raw[:8], "big")
        first_end = 8 + first_header_size
        context_size = int.from_bytes(raw[first_end : first_end + 8], "big")
        frame_end = first_end + 8 + context_size
        raw = raw[frame_end:] + raw[:frame_end]

    with pytest.raises(GateBFrameError):
        executor_module._decode_frames(_Input(raw, 31), executor_module._freeze(manifest))


def test_decoder_rejects_noncanonical_header_duplicate_id_and_bad_sampler() -> None:
    manifest, raw = _manifest_and_stream()
    header_size = int.from_bytes(raw[:8], "big")
    header = json.loads(raw[8 : 8 + header_size])
    noncanonical = json.dumps(header, ensure_ascii=True).encode("ascii") + b"\n"
    raw = len(noncanonical).to_bytes(8, "big") + noncanonical + raw[8 + header_size :]
    with pytest.raises(GateBFrameError):
        executor_module._decode_frames(_Input(raw, 103), executor_module._freeze(manifest))

    payloads = _component_payloads()
    payloads["execution_sampler"]["common_random_numbers"] = False
    sampler_raw = canonical_json_bytes(payloads["execution_sampler"])
    sampler_ref = manifest["components"]["execution_sampler"]
    sampler_ref["sha256"] = sha256_bytes(sampler_raw)
    sampler_ref["size_bytes"] = len(sampler_raw)
    with pytest.raises(GateBFrameError):
        executor_module._decode_frames(
            _Input(_stream_from_payloads(manifest, payloads), 97),
            executor_module._freeze(manifest),
        )

    duplicate = _frame("fixture", "duplicate", "first", b"") + _frame(
        "fixture",
        "duplicate",
        "second",
        b"",
    )
    reader = executor_module._ForwardReader(_Input(duplicate, 19))
    seen: set[str] = set()
    executor_module._read_frame(reader, seen)
    with pytest.raises(ValueError, match="duplicate"):
        executor_module._read_frame(reader, seen)


@pytest.mark.parametrize("header_size", [0, 4097])
def test_decoder_rejects_header_length_bounds(header_size: int) -> None:
    manifest, raw = _manifest_and_stream()
    forged = header_size.to_bytes(8, "big") + raw[8:]
    with pytest.raises(GateBFrameError):
        executor_module._decode_frames(
            _Input(forged, 211),
            executor_module._freeze(manifest),
        )


@pytest.mark.parametrize(
    ("component", "mutation"),
    [
        (
            "execution_config_index",
            lambda value: value["primary"].update({"source_component_sha256": "0" * 64}),
        ),
        (
            "execution_config_index",
            lambda value: value.update({"estimator_config_sha256": "0" * 64}),
        ),
        (
            "opponent_catalog",
            lambda value: value["opponents"][0].pop("seed"),
        ),
        (
            "opponent_catalog",
            lambda value: value["opponents"][1].update({"config_sha256": "0" * 64}),
        ),
    ],
)
def test_decoder_rejects_primary_index_and_catalog_provenance_drift(
    component: str,
    mutation: object,
) -> None:
    manifest, _raw = _manifest_and_stream()
    payloads = _component_payloads()
    mutation(payloads[component])
    raw = canonical_json_bytes(payloads[component])
    manifest["components"][component]["sha256"] = sha256_bytes(raw)
    manifest["components"][component]["size_bytes"] = len(raw)

    with pytest.raises(GateBFrameError):
        executor_module._decode_frames(
            _Input(_stream_from_payloads(manifest, payloads), 113),
            executor_module._freeze(manifest),
        )


def test_decoder_rejects_payload_length_overflow_early_eof_and_capability_errors() -> None:
    manifest, raw = _manifest_and_stream()
    header_size = int.from_bytes(raw[:8], "big")
    payload_length_offset = 8 + header_size
    oversized = (
        raw[:payload_length_offset]
        + (executor_module.MAX_FRAME_PAYLOAD_BYTES + 1).to_bytes(8, "big")
        + raw[payload_length_offset + 8 :]
    )
    with pytest.raises(GateBFrameError):
        executor_module._decode_frames(
            _Input(oversized, 512),
            executor_module._freeze(manifest),
        )

    class EarlyEof:
        def read_chunk(self, maximum: int) -> bytes:
            assert maximum == MAX_CHUNK_BYTES
            return b""

    class NonBytes:
        def read_chunk(self, maximum: int) -> str:
            assert maximum == MAX_CHUNK_BYTES
            return "synthetic-payload-sentinel"

    class Raised:
        def read_chunk(self, maximum: int) -> bytes:
            assert maximum == MAX_CHUNK_BYTES
            raise ValueError("synthetic-root-sentinel")

    for capability in (EarlyEof(), NonBytes(), Raised()):
        with pytest.raises(GateBFrameError) as caught:
            executor_module._decode_frames(
                capability,
                executor_module._freeze(manifest),
            )
        assert "sentinel" not in str(caught.value)
        assert "sentinel" not in repr(caught.value)


def test_forward_reader_enforces_aggregate_cap_and_single_eof() -> None:
    source = _Input(b"x", 1)
    reader = executor_module._ForwardReader(source)
    reader._consumed = executor_module.MAX_AGGREGATE_INPUT_BYTES
    with pytest.raises(ValueError, match="aggregate"):
        reader.exact(1)

    empty = _Input(b"", 1)
    finished = executor_module._ForwardReader(empty)
    finished.finish()
    assert empty.eof_count == 1
    with pytest.raises(ValueError, match="after EOF"):
        finished.finish()


def _stream_from_payloads(
    manifest: dict[str, object], payloads: dict[str, dict[str, object]]
) -> bytes:
    context = {
        "coordinates": manifest["coordinates"],
        "selection": manifest["selection"],
        "test_input": manifest["test_input"],
    }
    frames = [
        _frame(
            "batch_context",
            "test_batch_context",
            "test_batch_context",
            canonical_json_bytes(context),
        )
    ]
    for name in executor_module._COMPONENT_ORDER:
        frames.append(_frame("component", name, name, canonical_json_bytes(payloads[name])))
    frames.append(
        _frame(
            "config",
            "fixture-primary-001",
            "primary",
            canonical_json_bytes(_selected_config()),
        )
    )
    for payload in [_opponent_payload(index) for index in range(9)]:
        frames.append(
            _frame(
                "opponent_payload",
                payload["opponent_id"],
                payload["opponent_id"],
                canonical_json_bytes(payload),
            )
        )
    return b"".join(frames)


def test_test_stream_root_and_draw_match_independent_fixed_vector() -> None:
    root = GateBStreamRoot.derive(
        opponent_id="fixture-opponent",
        horizon=50,
        repetition_id="r001",
        master_seed=777001,
        stream_name="observation",
    )
    payload = {
        "derivation_version": SEED_DERIVATION_VERSION,
        "horizon": 50,
        "master_seed": 777001,
        "opponent_id": "fixture-opponent",
        "repetition_id": "r001",
        "split": "test",
        "stream_name": "observation",
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    expected_root = hashlib.sha256(SEED_DERIVATION_VERSION.encode() + b"\0" + encoded).hexdigest()
    expected_draw = hashlib.sha256(
        DRAW_DERIVATION_VERSION.encode()
        + b"\0"
        + bytes.fromhex(expected_root)
        + (3).to_bytes(8, "big")
        + (2).to_bytes(4, "big")
        + (1).to_bytes(4, "big")
    ).hexdigest()

    assert root.digest == expected_root
    assert (
        derive_gate_b_draw_digest(
            root,
            decision_index=3,
            variate_index=2,
            attempt_index=1,
        )
        == expected_draw
    )


def test_uniform_action_is_exact_and_requires_epsilon_stream() -> None:
    root = GateBStreamRoot.derive(
        opponent_id="fixture-opponent",
        horizon=10,
        repetition_id="r001",
        master_seed=5,
        stream_name="epsilon_action",
    )
    action, digest, attempt = gate_b_uniform_action(
        ("CALL", "FOLD"),
        root,
        decision_index=0,
    )
    ordered = ("FOLD", "CALL")
    assert action == ordered[int(digest, 16) % 2]
    assert attempt == 0
    wrong = dataclasses.replace(
        root,
        payload=MappingProxyType({**dict(root.payload), "stream_name": "hero_action"}),
    )
    with pytest.raises(ValueError, match="epsilon_action"):
        gate_b_uniform_action(("CALL", "FOLD"), wrong, decision_index=0)


def test_exact_icdf_legal_order_common_random_numbers_and_uniform_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = GateBStreamRoot.derive(
        opponent_id="fixture-opponent",
        horizon=50,
        repetition_id="r001",
        master_seed=9182,
        stream_name="observation",
    )
    first = derive_gate_b_draw_digest(root, decision_index=9, variate_index=3)
    second = derive_gate_b_draw_digest(root, decision_index=9, variate_index=3)
    assert first == second
    assert executor_module.weighted_categorical(
        ("CHECK", "BET"),
        (0.25, 0.75),
        first,
    ) == executor_module.weighted_categorical(
        ("CHECK", "BET"),
        (0.25, 0.75),
        second,
    )
    assert executor_module.canonical_legal_actions(("BET", "CHECK")) == ("CHECK", "BET")

    epsilon_root = GateBStreamRoot.derive(
        opponent_id="fixture-opponent",
        horizon=50,
        repetition_id="r001",
        master_seed=9182,
        stream_name="epsilon_action",
    )
    digests = iter(("f" * 64, "0" * 64))
    monkeypatch.setattr(
        executor_module,
        "derive_gate_b_draw_digest",
        lambda *_args, **_kwargs: next(digests),
    )
    action, digest, attempt = gate_b_uniform_action(
        ("CHECK", "BET", "CALL"),
        epsilon_root,
        decision_index=4,
    )
    assert (action, digest, attempt) == (
        executor_module.canonical_legal_actions(("CHECK", "BET", "CALL"))[0],
        "0" * 64,
        1,
    )


def test_manifest_coordinates_are_exact_810_order_and_once() -> None:
    values = executor_module._coordinates(executor_module._freeze({"coordinates": _coordinates()}))
    assert len(values) == 9 * 3 * 30
    assert len(set(values)) == len(values)
    assert values[0].opponent_id == "fixture-test-opponent-000"
    assert values[0].horizon == 50
    assert values[-1].opponent_id == "fixture-test-opponent-008"
    assert values[-1].horizon == 1000
    assert values[-1].repetition_id == "r030"


def test_executor_identity_is_request_bound_and_immutable() -> None:
    manifest, _raw = _manifest_and_stream()
    request = _request(manifest)
    executor = GateBProductionExecutor.from_request(
        request,
        phase6_contract_bundle_evidence=_genuine_evidence(),
        execution_context_sha256="b" * 64,
    )

    assert executor.executor_id == manifest["components"]["execution_sampler"]["schema_version"]
    assert executor.executor_sha256 == manifest["components"]["execution_sampler"]["sha256"]
    with pytest.raises(AttributeError):
        executor._executor_id = "changed"
    with pytest.raises(TypeError):
        GateBProductionExecutor(
            object(),
            executor_id="x",
            executor_sha256="c" * 64,
            batch_hash="d" * 64,
            execution_context_sha256="e" * 64,
            manifest={},
            operation_timeout_seconds=1,
            phase6_contract_bundle_evidence=_genuine_evidence(),
        )


def test_executor_factory_requires_genuine_keyword_only_evidence() -> None:
    manifest, _raw = _manifest_and_stream()
    request = _request(manifest)
    evidence = _genuine_evidence()

    with pytest.raises(TypeError):
        GateBProductionExecutor.from_request(
            request,
            execution_context_sha256="b" * 64,
        )
    with pytest.raises(TypeError):
        GateBProductionExecutor.from_request(
            request,
            evidence,
            execution_context_sha256="b" * 64,
        )
    with pytest.raises(ValueError):
        GateBProductionExecutor.from_request(
            request,
            phase6_contract_bundle_evidence=object(),
            execution_context_sha256="b" * 64,
        )
    forged = object.__new__(ValidatedPhase6ContractBundleEvidence)
    with pytest.raises((AttributeError, ValueError)):
        GateBProductionExecutor.from_request(
            request,
            phase6_contract_bundle_evidence=forged,
            execution_context_sha256="b" * 64,
        )
    mutated = _build_genuine_evidence()
    object.__setattr__(mutated, "_provenance_sha256", "f" * 64)
    with pytest.raises(ValueError):
        GateBProductionExecutor.from_request(
            request,
            phase6_contract_bundle_evidence=mutated,
            execution_context_sha256="b" * 64,
        )


def test_executor_retains_exact_evidence_only_and_validation_is_fresh() -> None:
    manifest, _raw = _manifest_and_stream()
    evidence = _genuine_evidence()
    executor = GateBProductionExecutor.from_request(
        _request(manifest),
        phase6_contract_bundle_evidence=evidence,
        execution_context_sha256="b" * 64,
    )

    assert executor._phase6_contract_bundle_evidence is evidence
    assert GateBProductionExecutor.__slots__ == (
        "_batch_hash",
        "_executor_id",
        "_executor_sha256",
        "_execution_context_sha256",
        "_locked",
        "_manifest",
        "_operation_timeout_seconds",
        "_phase6_contract_bundle_evidence",
    )
    first = validate_phase6_contract_bundle_evidence(evidence)
    second = validate_phase6_contract_bundle_evidence(evidence)
    assert first == second
    assert first is not second
    assert first.root_manifest is not second.root_manifest
    assert first.coverage_contract is not second.coverage_contract


def test_calibration_method_has_exact_fresh_bundle_adjacency_and_import_boundary() -> None:
    method = ast.parse(
        textwrap.dedent(inspect.getsource(GateBProductionExecutor._evaluate_test_calibration))
    )
    function = method.body[0]
    assert isinstance(function, ast.FunctionDef)
    assignments = [
        index
        for index, statement in enumerate(function.body)
        if isinstance(statement, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "fresh_bundle"
            for target in statement.targets
        )
    ]
    assert len(assignments) == 1
    index = assignments[0]
    assignment = function.body[index]
    evaluation = function.body[index + 1]
    deletion = function.body[index + 2]
    assert isinstance(assignment.value, ast.Call)
    assert isinstance(assignment.value.func, ast.Name)
    assert assignment.value.func.id == "validate_phase6_contract_bundle_evidence"
    assert isinstance(assignment.value.args[0], ast.Attribute)
    assert assignment.value.args[0].attr == "_phase6_contract_bundle_evidence"
    assert isinstance(evaluation, ast.Assign)
    assert isinstance(evaluation.value, ast.Call)
    assert isinstance(evaluation.value.func, ast.Name)
    assert evaluation.value.func.id == "evaluate_all_candidate_calibration"
    assert isinstance(evaluation.value.args[0], ast.Name)
    assert evaluation.value.args[0].id == "fresh_bundle"
    assert isinstance(deletion, ast.Delete)
    assert isinstance(deletion.targets[0], ast.Name)
    assert deletion.targets[0].id == "fresh_bundle"

    module = ast.parse(inspect.getsource(executor_module))
    imported = {
        (node.module, alias.name)
        for node in module.body
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    assert {
        ("phase6.calibration", "CanonicalCalibrationArtifact"),
        ("phase6.calibration", "ExactEvObservation"),
        ("phase6.calibration", "exact_ev_observation_sha256"),
        ("phase6.contracts", "ValidatedPhase6ContractBundleEvidence"),
        ("phase6.contracts", "validate_phase6_contract_bundle_evidence"),
        ("phase6.gate_b_loader", "GateBLoaderRequest"),
    } <= imported
    forbidden_calls = {
        node.func.id
        for node in ast.walk(module)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id
        in {
            "getattr",
            "hasattr",
            "globals",
            "locals",
            "__import__",
            "load_phase6_contract_bundle_evidence",
        }
    }
    assert forbidden_calls == set()
    assert "ValidatedPhase6ContractBundle" not in {
        alias.name
        for node in module.body
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }


@pytest.mark.parametrize(
    ("component", "field", "value"),
    [
        ("baseline_table", "baseline_rate", "0.1"),
        ("estimator_config", "method_version", "foreign-estimator"),
        ("estimator_config", "tau", "0.2"),
        ("evaluator", "evaluator_version", "foreign-evaluator"),
        (
            "ground_truth_extractor",
            "ground_truth_extractor_version",
            "foreign-ground-truth",
        ),
    ],
)
def test_scientific_component_drift_fails_closed(
    component: str,
    field: str,
    value: object,
) -> None:
    manifest, _raw = _manifest_and_stream()
    payloads = _component_payloads()
    payloads[component][field] = value
    changed = canonical_json_bytes(payloads[component])
    manifest["components"][component]["sha256"] = sha256_bytes(changed)
    manifest["components"][component]["size_bytes"] = len(changed)
    if component == "estimator_config":
        payloads["execution_config_index"]["estimator_config_sha256"] = sha256_bytes(changed)
        index_raw = canonical_json_bytes(payloads["execution_config_index"])
        manifest["components"]["execution_config_index"]["sha256"] = sha256_bytes(index_raw)
        manifest["components"]["execution_config_index"]["size_bytes"] = len(index_raw)
    decoded = executor_module._decode_frames(
        _Input(_stream_from_payloads(manifest, payloads), 503),
        executor_module._freeze(manifest),
    )
    with pytest.raises(ValueError):
        executor_module._scientific_contract(decoded, decoded.configs[0])


@dataclasses.dataclass(frozen=True)
class _WireValue:
    decimal: Decimal
    count: int


def test_wire_conversion_is_exact_and_rejects_float_and_development_result() -> None:
    assert executor_module._wire(_WireValue(Decimal("-0.000"), 3)) == {
        "decimal": "0",
        "count": 3,
    }
    with pytest.raises(ValueError, match="float"):
        executor_module._wire(0.5)

    fake_type = dataclasses.make_dataclass("ValidationResult", [("value", int)])
    fake_type.__module__ = "phase6.validation_execution"
    with pytest.raises(ValueError, match="development"):
        executor_module._wire(fake_type(1))


def test_bounded_outputs_enforces_chunk_per_sink_and_aggregate_caps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability = _Output()
    bounded = executor_module._BoundedOutputs(capability)
    raw = b"x" * (MAX_CHUNK_BYTES + 1)
    bounded.write("result", raw)
    assert capability.calls == [("result", MAX_CHUNK_BYTES), ("result", 1)]

    bounded._sizes["metrics"] = OUTPUT_LIMITS["metrics"] - 1
    bounded.write("metrics", b"x")
    with pytest.raises(GateBOutputError):
        bounded.write("metrics", b"x")
    bounded._sizes["metrics"] = 0
    bounded._total = MAX_AGGREGATE_OUTPUT_BYTES - 1
    bounded.write("log", b"x")
    with pytest.raises(GateBOutputError):
        bounded.write("log", b"x")
    with pytest.raises(GateBOutputError):
        bounded.write("stdout", b"x")
    with pytest.raises(GateBOutputError):
        bounded.write("result", b"")

    exact = {"fixture": ["value", 1, True, None]}
    second = executor_module._BoundedOutputs(_Output())
    assert second.json("metrics", exact) == canonical_json_bytes(exact)

    consumed = []

    def oversized(_payload: object):
        consumed.append("first")
        yield b"x" * OUTPUT_LIMITS["metrics"]
        consumed.append("forbidden")
        yield b"y"

    monkeypatch.setattr(executor_module, "_canonical_json_ascii_chunks", oversized)
    third_capability = _Output()
    third = executor_module._BoundedOutputs(third_capability)
    with pytest.raises(GateBOutputError):
        third.json("metrics", {})
    assert consumed == ["first"]
    assert third_capability.calls == []


def _fake_coordinate(
    _decoded: object,
    _selected: object,
    _config: object,
    coordinate: executor_module._Coordinate,
    _scientific: object,
) -> executor_module._CoordinateResult:
    session = coordinate.session()
    terminal = {
        "schema_version": executor_module.TERMINAL_SCHEMA,
        "evaluator_version": "fixture-evaluator-v1",
        "session": session,
        "action_counts": {"BET": 0, "CHECK": coordinate.horizon},
        "opportunity_count": coordinate.horizon,
        "transcript_sha256": "1" * 64,
    }
    policy = {
        "schema_version": executor_module.HERO_POLICY_SCHEMA,
        "exact_ev_evaluator_version": "fixture-evaluator-v1",
        "session": session,
        "source_terminal_sha256": sha256_bytes(canonical_json_bytes(terminal)),
        "game_id": "fixture-game",
        "opponent_id": coordinate.opponent_id,
        "hero_player": 0,
        "base_hero_policy": {},
        "final_hero_policy": {},
    }
    exact = {
        "schema_version": executor_module.EXACT_EV_SCHEMA,
        "exact_ev_evaluator_version": "fixture-evaluator-v1",
        "session": session,
        "source_terminal_sha256": sha256_bytes(canonical_json_bytes(terminal)),
        "source_hero_policy_sha256": sha256_bytes(canonical_json_bytes(policy)),
        "cell": {
            "game_id": "fixture-game",
            "opponent_id": coordinate.opponent_id,
            "hero_player": 0,
            "profiles": {"base": {}, "final": {}, "oracle_br": {}},
            "base_ev": {
                "production_binary64_hex": "0x0.0p+0",
                "independent_leaves_binary64_hex": "0x0.0p+0",
            },
            "final_ev": {
                "production_binary64_hex": "0x0.0p+0",
                "independent_leaves_binary64_hex": "0x0.0p+0",
            },
            "oracle_br_ev": {
                "production_binary64_hex": "0x0.0p+0",
                "independent_leaves_binary64_hex": "0x0.0p+0",
            },
            "gain_binary64_hex": "0x0.0p+0",
            "opportunity_binary64_hex": "0x0.0p+0",
            "efficiency_binary64_hex": None,
            "efficiency_status": "zero_or_near_zero_opportunity",
        },
    }
    profiles = CompiledStrategyProfiles(
        game_id="fixture-game",
        opponent_id=coordinate.opponent_id,
        hero_player=0,
        base={},
        final={},
        oracle_br={},
    )
    paths = ExactEvPaths(0.0, 0.0)
    cell = ExactEvCell(
        profiles=profiles,
        base_ev=paths,
        final_ev=paths,
        oracle_br_ev=paths,
        gain=0.0,
        opportunity=0.0,
        efficiency=None,
        efficiency_status="zero_or_near_zero_opportunity",
    )
    is_gto = coordinate.opponent_id.endswith("000")
    measurement = SimpleNamespace(
        reason_id=executor_module.R008_REASON_ID,
        action_rate=Decimal("0") if is_gto else Decimal("0.2"),
        opportunity_reach=Decimal("1"),
    )
    return executor_module._CoordinateResult(
        coordinate,
        executor_module._freeze(terminal),
        executor_module._freeze(policy),
        executor_module._freeze(exact),
        cell,
        ((), (measurement,)),
    )


def test_fake_kernel_executes_exact_810_once_and_writes_strict_terminal_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, raw = _manifest_and_stream()
    request = _request(manifest)
    executor = GateBProductionExecutor.from_request(
        request,
        phase6_contract_bundle_evidence=_genuine_evidence(),
        execution_context_sha256="b" * 64,
    )
    calls = []

    def run(*args):
        result = _fake_coordinate(*args)
        calls.append(result.coordinate)
        return result

    monkeypatch.setattr(executor_module, "_run_coordinate", run)
    output = _Output()
    source = _Input(raw, 127)
    calibration_bundles = []
    previous_profile = sys.getprofile()

    def capture_calibration_bundle(frame, event, _argument):
        if (
            event == "call"
            and frame.f_code is executor_module.evaluate_all_candidate_calibration.__code__
        ):
            calibration_bundles.append(frame.f_locals["contract_bundle"])

    sys.setprofile(capture_calibration_bundle)
    try:
        assert executor.execute(source, output) is None
    finally:
        sys.setprofile(previous_profile)
    assert len(calibration_bundles) == 2
    assert calibration_bundles[0] == calibration_bundles[1]
    assert calibration_bundles[0] is not calibration_bundles[1]
    assert calibration_bundles[0].root_manifest is not calibration_bundles[1].root_manifest
    assert calibration_bundles[0].coverage_contract is not calibration_bundles[1].coverage_contract
    assert source.eof_count == 1
    assert len(calls) == 810
    assert len(set(calls)) == 810
    assert set(output.values) == {"progress", "log", "result", "metrics"}
    assert "stdout" not in output.values and "stderr" not in output.values
    result_raw = bytes(output.values["result"])
    metrics_raw = bytes(output.values["metrics"])
    result = json.loads(result_raw)
    metrics = json.loads(metrics_raw)
    progress = [
        json.loads(line) for line in bytes(output.values["progress"]).decode("ascii").splitlines()
    ]
    log = [json.loads(line) for line in bytes(output.values["log"]).decode("ascii").splitlines()]
    assert canonical_json_bytes(result) == result_raw
    assert canonical_json_bytes(metrics) == metrics_raw
    assert all(
        canonical_json_bytes(item) == line.encode("ascii") + b"\n"
        for item, line in zip(
            progress,
            bytes(output.values["progress"]).decode("ascii").splitlines(),
            strict=True,
        )
    )
    expected_write_order = ["progress", "log"]
    for _coordinate in range(810):
        expected_write_order.extend(("progress", "log", "progress", "log"))
    expected_write_order.extend(("result", "metrics", "progress", "log"))
    actual_write_order = []
    for name, _size in output.calls:
        if not actual_write_order or actual_write_order[-1] != name:
            actual_write_order.append(name)
    assert actual_write_order == expected_write_order
    assert set(result) == {
        "schema_version",
        "artifact_type",
        "test_batch_hash",
        "execution_context_sha256",
        "executor_id",
        "executor_sha256",
        "selected_config_sha256",
        "coordinate_order_sha256",
        "coordinate_count",
        "session_results",
        "calibration",
        "aggregate",
        "status",
    }
    assert set(metrics) == {
        "schema_version",
        "artifact_type",
        "test_batch_hash",
        "executor_id",
        "executor_sha256",
        "coordinate_count",
        "primary_metric",
        "diagnostic_metrics",
        "gto_fpr",
        "result_sha256",
        "status",
    }
    assert result["coordinate_count"] == 810
    assert [item["coordinate_index"] for item in result["session_results"]] == list(range(1, 811))
    assert metrics["result_sha256"] == sha256_bytes(result_raw)
    first = result["session_results"][0]
    assert set(first) == {
        "coordinate_index",
        "opponent_id",
        "horizon",
        "repetition_id",
        "seed",
        "terminal_candidate_snapshot",
        "hero_policy_snapshot",
        "exact_ev_cell",
    }
    assert first["hero_policy_snapshot"]["source_terminal_sha256"] == sha256_bytes(
        canonical_json_bytes(first["terminal_candidate_snapshot"])
    )
    assert first["exact_ev_cell"]["source_hero_policy_sha256"] == sha256_bytes(
        canonical_json_bytes(first["hero_policy_snapshot"])
    )
    series = result["calibration"]["series"][0]
    assert result["aggregate"] == {
        key: series[key]
        for key in (
            "series_id",
            "terminal_snapshot_sha256",
            "ground_truth_sha256",
            "exact_ev_sha256s",
            "atomic_groups",
            "macro",
            "micro",
            "gto_fpr",
        )
    }
    assert progress[0]["event_type"] == "executor_started"
    assert progress[-1]["event_type"] == "executor_completed"
    assert progress[-1]["metrics_sha256"] == sha256_bytes(metrics_raw)
    assert log[-1]["event_type"] == "executor_completed"


def test_cooperative_deadline_fails_before_result_and_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, raw = _manifest_and_stream()
    executor = GateBProductionExecutor.from_request(
        _request(manifest),
        phase6_contract_bundle_evidence=_genuine_evidence(),
        execution_context_sha256="b" * 64,
        operation_timeout_seconds=1,
    )
    times = iter((0.0, 2.0))
    monkeypatch.setattr(executor_module.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(executor_module, "_run_coordinate", _fake_coordinate)
    output = _Output()

    with pytest.raises(GateBDeadlineExceeded) as caught:
        executor.execute(_Input(raw, 1024), output)
    assert str(caught.value) == "Gate B executor failed closed"
    assert "result" not in output.values


def test_small_real_public_primitives_session_and_evaluator_smoke() -> None:
    manifest, raw = _manifest_and_stream()
    decoded = executor_module._decode_frames(
        _Input(raw, 101),
        executor_module._freeze(manifest),
    )
    selected = decoded.configs[0]
    configs = decoded.opponent_configs[:2]
    coordinate_payload = {
        "opponent_ids": [item.opponent_id for item in configs],
        "horizons": [2],
        "repetition_ids": ["r001"],
        "seed_mapping": [
            {
                "opponent_id": item.opponent_id,
                "horizon": 2,
                "repetition_id": "r001",
                "seed": 12345 + index,
            }
            for index, item in enumerate(configs)
        ],
    }
    small = dataclasses.replace(
        decoded,
        batch_context=executor_module._freeze(
            {
                **executor_module._plain(decoded.batch_context),
                "coordinates": coordinate_payload,
            }
        ),
        opponent_configs=configs,
        opponent_catalog_rows=decoded.opponent_catalog_rows[:2],
    )
    scientific = executor_module._scientific_contract(small, selected)
    coordinates = tuple(
        executor_module._Coordinate(
            index,
            config.opponent_id,
            2,
            "r001",
            12344 + index,
        )
        for index, config in enumerate(configs, start=1)
    )

    results = tuple(
        executor_module._run_coordinate(
            small,
            selected,
            config,
            coordinate,
            scientific,
        )
        for config, coordinate in zip(configs, coordinates, strict=True)
    )
    executor = GateBProductionExecutor.from_request(
        _request(manifest),
        phase6_contract_bundle_evidence=_genuine_evidence(),
        execution_context_sha256="b" * 64,
    )
    evaluation = executor._evaluate_test_calibration(
        small,
        selected,
        results,
        scientific,
    )

    assert tuple(item.coordinate for item in results) == coordinates
    assert all(item.terminal["opportunity_count"] == 2 for item in results)
    assert evaluation.evaluator_version == executor_module.CALIBRATION_EVALUATOR_VERSION
    assert len(evaluation.series) == 1
    assert len(evaluation.series[0].exact_ev_sha256s) == 2
    calibration = executor_module._wire(evaluation)
    aggregate = executor_module._aggregate_from_calibration(evaluation)
    assert aggregate == {
        key: calibration["series"][0][key]
        for key in (
            "series_id",
            "terminal_snapshot_sha256",
            "ground_truth_sha256",
            "exact_ev_sha256s",
            "atomic_groups",
            "macro",
            "micro",
            "gto_fpr",
        )
    }
    catalog_rows = [executor_module._plain(item) for item in small.opponent_catalog_rows]
    catalog_rows[1]["strategy_sha256"] = "0" * 64
    drifted = dataclasses.replace(
        small,
        opponent_catalog_rows=executor_module._freeze(catalog_rows),
    )
    with pytest.raises(ValueError, match="strategy"):
        executor_module._test_series_descriptor(
            drifted,
            selected,
            scientific,
            results,
        )


def test_real_public_primitives_leak_branch_uses_nodelock_br_and_safety_mixer() -> None:
    manifest, raw = _manifest_and_stream()
    decoded = executor_module._decode_frames(
        _Input(raw, 137),
        executor_module._freeze(manifest),
    )
    selected = decoded.configs[0]
    scientific = executor_module._scientific_contract(decoded, selected)
    config = decoded.opponent_configs[1]
    synthesized = executor_module.synthesize_opponent(config=config)
    opportunities = 1000
    counts = {"BET": opportunities, "CHECK": 0}

    base, final = executor_module._hero_policies(
        synthesized.game,
        synthesized,
        selected,
        scientific,
        counts,
        opportunities,
    )

    leaks = tuple(
        executor_module.LeakDetector(
            scientific.baseline_table,
            scientific.detector_config,
        ).detect_for_situation(
            (
                executor_module.ActionStats(
                    executor_module.R008_SITUATION_KEY,
                    opportunities,
                    counts,
                ),
            ),
            executor_module.R008_SITUATION_KEY,
        )
    )
    node_lock = executor_module.nodelock_config_from_leaks(
        leaks,
        hero_position="OOP",
        min_confidence=float(Decimal(selected["provider_confidence"])),
    )
    assert node_lock is not None
    application = executor_module.apply_node_locks(
        synthesized.game,
        synthesized.equilibrium_strategy,
        node_lock,
        reach_weights=executor_module.river_infoset_reach_weights(
            synthesized.game,
            synthesized.equilibrium_strategy,
        ),
    )
    best_actions = executor_module.best_response_strategy(
        synthesized.game,
        0,
        application.profile,
    )
    alpha = float(Decimal(selected["safety_alpha"]))
    changed = []
    for infoset in synthesized.game.infosets_of(0):
        expected_exploit = dict(base[infoset])
        if infoset.endswith(":vs_bet"):
            expected_exploit = {
                action: float(action == best_actions[infoset])
                for action in synthesized.game.actions_of(infoset)
            }
        assert final[infoset] == executor_module.safety_mix(
            base[infoset],
            expected_exploit,
            alpha,
        )
        if final[infoset] != base[infoset]:
            changed.append(infoset)
    assert changed


def test_executor_has_no_learning_selection_release_or_retry_surface() -> None:
    public = {name for name in dir(GateBProductionExecutor) if not name.startswith("_")}
    assert public == {"execute", "executor_id", "executor_sha256", "from_request"}
