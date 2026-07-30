"""Concrete non-disclosing Gate B Test executor.

The module owns the Test-only sampling domain, the forward-only input decoder,
the scientific session adapter, and every byte written through the quarantine
capabilities. It deliberately has no filesystem path or release surface.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass
from decimal import ROUND_HALF_EVEN, Decimal, localcontext
from types import MappingProxyType
from typing import Any

from opponents.ground_truth import extract_independent_action_rates, extract_true_leaks
from opponents.model import OpponentModelConfig
from opponents.synthesis import synthesize_opponent
from phase6.calibration import (
    CanonicalCalibrationArtifact,
    ExactEvObservation,
    calibration_series_id,
    evaluate_all_candidate_calibration,
    exact_ev_observation_sha256,
)
from phase6.contracts import (
    ValidatedPhase6ContractBundleEvidence,
    canonical_json_bytes,
    sha256_bytes,
    validate_phase6_contract_bundle_evidence,
)
from phase6.exact_ev import PolicySlice, evaluate_exact_ev
from phase6.gate_b_loader import GateBLoaderRequest
from phase6.p6_7 import canonical_legal_actions, epsilon_branch_fires, weighted_categorical
from phase6.production_inputs import build_production_observation_registry
from poker_ai.exploit import nodelock_config_from_leaks
from poker_ai.leak import ActionBaselineTable, ActionLeakRule, LeakDetector, LeakDetectorConfig
from poker_ai.mixer import safety_mix
from poker_ai.observation import ActionStats
from poker_solver.best_response import best_response_strategy
from poker_solver.game import Chance, Decision, Game
from poker_solver.nodelock import apply_node_locks, river_infoset_reach_weights
from poker_solver.strategy import StrategyProfile

EXECUTOR_PROGRESS_SCHEMA = "phase6-gate-b-executor-progress-entry-v1"
EXECUTOR_LOG_SCHEMA = "phase6-gate-b-executor-log-entry-v1"
METRICS_SCHEMA = "phase6-gate-b-metrics-v1"
RESULT_SCHEMA = "phase6-gate-b-result-v1"
TERMINAL_SCHEMA = "phase6-gate-b-terminal-candidate-snapshot-v1"
HERO_POLICY_SCHEMA = "phase6-gate-b-hero-policy-snapshot-v1"
EXACT_EV_SCHEMA = "phase6-gate-b-exact-ev-cell-v1"

SEED_DERIVATION_VERSION = "phase6-domain-separated-sha256-v2"
DRAW_DERIVATION_VERSION = "phase6-digest-draw-v2"
EXECUTION_SAMPLER_VERSION = "epsilon-uniform-digest-v2"
LEGAL_ACTION_ORDER_VERSION = "phase6-legal-action-order-v1"
PROBABILITY_MAPPING_VERSION = "phase6-rational-icdf-256-v1"
STREAM_NAMES = ("observation", "hero_action", "epsilon_branch", "epsilon_action")

CALIBRATION_EVALUATOR_VERSION = "all-candidate-calibration-v1"
EXACT_EV_INPUT_VERSION = "p6-5-exact-ev-cell-v2"
TERMINAL_CALIBRATION_SCHEMA = "phase6-terminal-candidate-snapshots-v1"
GROUND_TRUTH_CALIBRATION_SCHEMA = "phase6-calibration-ground-truth-v1"
GROUND_TRUTH_EXTRACTOR_VERSION = "phase6-independent-ground-truth-v1"
ESTIMATOR_METHOD_VERSION = "beta-binomial-upper-tail-v1"
EXPLOIT_PROVIDER_VERSION = "nodelock-provider-r008-v2"
BOUNDARY_ABS_TOLERANCE_WIRE = "0.000000000001"
DECIMAL_PRECISION = 50
DECIMAL_ROUNDING = "ROUND_HALF_EVEN"
GTO_FPR_METRIC_ID = "gto_negative_control_micro_fpr_v1"
R008_REASON_ID = "LEAK_R008"
R008_SITUATION_KEY = "river_vs_check"
R008_SEMANTIC_ID = "leak_r008_opponent_river_vs_check_bet_upper_v1"
R008_ACTION_FAMILY_ID = "bet_when_checked_to_v1"
R008_OPPORTUNITY_EVENT_ID = "opponent_river_decision_after_hero_check_v1"
R008_ACTION_GROUP = ("BET", "BET_ALL_IN", "BET_33", "BET_75", "RAISE_ALL_IN")

MAX_CHUNK_BYTES = 1_048_576
MAX_HEADER_BYTES = 4_096
MAX_FRAME_PAYLOAD_BYTES = 1_048_576
MAX_AGGREGATE_INPUT_BYTES = 16_777_216
OUTPUT_LIMITS = MappingProxyType(
    {
        "stdout": 0,
        "stderr": 0,
        "progress": 4_194_304,
        "metrics": 1_048_576,
        "log": 4_194_304,
        "result": 33_554_432,
    }
)
MAX_AGGREGATE_OUTPUT_BYTES = 42_991_616

_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMPONENT_ORDER = (
    "baseline_table",
    "estimator_config",
    "evaluator",
    "execution_config_index",
    "execution_sampler",
    "ground_truth_extractor",
    "opponent_catalog",
    "opponent_payload_index",
    "selected_config_lock",
    "validation_selection_report",
)
_CONSTRUCTION_TOKEN = object()
_UINT256 = 1 << 256


class GateBExecutorError(RuntimeError):
    """Path-free failure visible across the loader callback boundary."""

    error_code = "gate_b_executor_failure"

    def __init__(self) -> None:
        super().__init__("Gate B executor failed closed")


class GateBFrameError(GateBExecutorError):
    error_code = "gate_b_frame_failure"


class GateBScientificError(GateBExecutorError):
    error_code = "gate_b_scientific_failure"


class GateBOutputError(GateBExecutorError):
    error_code = "gate_b_output_failure"


class GateBDeadlineExceeded(GateBExecutorError):
    error_code = "gate_b_operation_timeout"


def _raise_sanitized(error_type: type[GateBExecutorError]) -> None:
    error = error_type()
    error.__cause__ = None
    error.__context__ = None
    error.__traceback__ = None
    raise error


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate field")
        value[key] = item
    return value


def _strict_canonical_object(raw: bytes) -> dict[str, Any]:
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise ValueError("canonical JSON requires one LF")
    value = json.loads(
        raw.decode("ascii"),
        object_pairs_hook=_duplicate_rejecting_object,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite JSON")),
    )
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise ValueError("non-canonical JSON object")
    return value


def _require_fields(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} fields mismatch")
    return value


def _sha(value: object) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise ValueError("invalid SHA-256")
    return value


def _positive_int(value: object, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError("invalid integer")
    return value


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class GateBStreamRoot:
    """One immutable Test-domain stream root."""

    payload: Mapping[str, object]
    digest: str

    @classmethod
    def derive(
        cls,
        *,
        opponent_id: str,
        horizon: int,
        repetition_id: str,
        master_seed: int,
        stream_name: str,
    ) -> GateBStreamRoot:
        if not isinstance(opponent_id, str) or not opponent_id:
            raise ValueError("opponent_id must be non-empty")
        _positive_int(horizon)
        if not isinstance(repetition_id, str) or not repetition_id:
            raise ValueError("repetition_id must be non-empty")
        if isinstance(master_seed, bool) or not isinstance(master_seed, int) or master_seed < 0:
            raise ValueError("master_seed must be a non-negative integer")
        if stream_name not in STREAM_NAMES:
            raise ValueError("unknown Test stream")
        payload = {
            "derivation_version": SEED_DERIVATION_VERSION,
            "horizon": horizon,
            "master_seed": master_seed,
            "opponent_id": opponent_id,
            "repetition_id": repetition_id,
            "split": "test",
            "stream_name": stream_name,
        }
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        digest = hashlib.sha256(
            SEED_DERIVATION_VERSION.encode("ascii") + b"\0" + encoded
        ).hexdigest()
        return cls(_freeze(payload), digest)


def derive_gate_b_draw_digest(
    stream_root: GateBStreamRoot,
    *,
    decision_index: int,
    variate_index: int = 0,
    attempt_index: int = 0,
) -> str:
    """Derive one immutable Test scalar draw."""
    if not isinstance(stream_root, GateBStreamRoot):
        raise TypeError("draw derivation requires GateBStreamRoot")
    payload = stream_root.payload
    rebuilt = GateBStreamRoot.derive(
        opponent_id=payload["opponent_id"],
        horizon=payload["horizon"],
        repetition_id=payload["repetition_id"],
        master_seed=payload["master_seed"],
        stream_name=payload["stream_name"],
    )
    if stream_root != rebuilt:
        raise ValueError("stream root does not reconstruct")
    horizon = payload["horizon"]
    bounds = (
        (decision_index, 8),
        (variate_index, 4),
        (attempt_index, 4),
    )
    if (
        isinstance(decision_index, bool)
        or not isinstance(decision_index, int)
        or not 0 <= decision_index < horizon
    ):
        raise ValueError("decision index outside Test horizon")
    encoded = []
    for value, width in bounds:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value < 1 << (8 * width)
        ):
            raise ValueError("draw coordinate outside unsigned width")
        encoded.append(value.to_bytes(width, "big"))
    return hashlib.sha256(
        DRAW_DERIVATION_VERSION.encode("ascii")
        + b"\0"
        + bytes.fromhex(stream_root.digest)
        + b"".join(encoded)
    ).hexdigest()


def gate_b_uniform_action(
    legal_actions: Sequence[str],
    stream_root: GateBStreamRoot,
    *,
    decision_index: int,
) -> tuple[str, str, int]:
    """Apply the exact uint256 local-rejection mapping."""
    if stream_root.payload["stream_name"] != "epsilon_action":
        raise ValueError("uniform action requires epsilon_action stream")
    ordered = canonical_legal_actions(legal_actions)
    limit = _UINT256 - (_UINT256 % len(ordered))
    for attempt in range(1 << 32):
        digest = derive_gate_b_draw_digest(
            stream_root,
            decision_index=decision_index,
            attempt_index=attempt,
        )
        value = int(digest, 16)
        if value < limit:
            return ordered[value % len(ordered)], digest, attempt
    raise ValueError("uniform rejection limit reached")


@dataclass(frozen=True, slots=True)
class _DecodedFrame:
    frame_type: str
    frame_id: str
    name: str
    sha256: str
    payload: bytes


class _ForwardReader:
    __slots__ = ("_buffer", "_capability", "_consumed", "_eof")

    def __init__(self, capability: Any) -> None:
        self._capability = capability
        self._buffer = bytearray()
        self._consumed = 0
        self._eof = False

    def _read_once(self) -> bytes:
        if self._eof:
            raise ValueError("read after EOF")
        chunk = self._capability.read_chunk(MAX_CHUNK_BYTES)
        if not isinstance(chunk, bytes):
            raise TypeError("input capability returned non-bytes")
        if len(chunk) > MAX_CHUNK_BYTES:
            raise ValueError("input capability exceeded chunk bound")
        if not chunk:
            self._eof = True
        return chunk

    def exact(self, size: int) -> bytes:
        _positive_int(size, allow_zero=True)
        while len(self._buffer) < size:
            chunk = self._read_once()
            if not chunk:
                raise EOFError("early EOF")
            self._buffer.extend(chunk)
        result = bytes(self._buffer[:size])
        del self._buffer[:size]
        self._consumed += size
        if self._consumed > MAX_AGGREGATE_INPUT_BYTES:
            raise ValueError("aggregate frame cap exceeded")
        return result

    def finish(self) -> None:
        if self._buffer:
            raise ValueError("trailing framed bytes")
        if self._read_once() != b"":
            raise ValueError("trailing framed bytes")


def _read_frame(reader: _ForwardReader, seen_ids: set[str]) -> _DecodedFrame:
    header_size = int.from_bytes(reader.exact(8), "big")
    if not 1 <= header_size <= MAX_HEADER_BYTES:
        raise ValueError("header size outside bound")
    header = _strict_canonical_object(reader.exact(header_size))
    _require_fields(header, {"frame_type", "id", "name", "sha256", "size_bytes"}, "frame")
    if any(
        not isinstance(header[name], str) or not header[name]
        for name in ("frame_type", "id", "name")
    ):
        raise ValueError("frame text field invalid")
    if header["id"] in seen_ids:
        raise ValueError("duplicate frame ID")
    seen_ids.add(header["id"])
    payload_size = int.from_bytes(reader.exact(8), "big")
    declared_size = _positive_int(header["size_bytes"], allow_zero=True)
    if payload_size != declared_size or payload_size > MAX_FRAME_PAYLOAD_BYTES:
        raise ValueError("frame payload size mismatch")
    payload = reader.exact(payload_size)
    digest = _sha(header["sha256"])
    if sha256_bytes(payload) != digest:
        raise ValueError("frame payload hash mismatch")
    return _DecodedFrame(
        header["frame_type"],
        header["id"],
        header["name"],
        digest,
        payload,
    )


@dataclass(frozen=True, slots=True)
class _DecodedInput:
    batch_context: Mapping[str, Any]
    components: Mapping[str, Mapping[str, Any]]
    component_refs: Mapping[str, Mapping[str, Any]]
    configs: tuple[Mapping[str, Any], ...]
    opponent_configs: tuple[OpponentModelConfig, ...]
    opponent_catalog_rows: tuple[Mapping[str, Any], ...]


def _expect_frame(
    frame: _DecodedFrame,
    *,
    frame_type: str,
    frame_id: str,
    name: str,
    sha256: str,
    size_bytes: int,
) -> None:
    if (
        frame.frame_type != frame_type
        or frame.frame_id != frame_id
        or frame.name != name
        or frame.sha256 != sha256
        or len(frame.payload) != size_bytes
    ):
        raise ValueError("frame identity or order mismatch")


def _find_values(value: object, key: str) -> list[object]:
    found: list[object] = []
    if isinstance(value, Mapping):
        for candidate, item in value.items():
            if candidate == key:
                found.append(item)
            found.extend(_find_values(item, key))
    elif isinstance(value, tuple | list):
        for item in value:
            found.extend(_find_values(item, key))
    return found


def _require_embedded_contract(value: Mapping[str, Any], key: str, expected: object) -> None:
    matches = _find_values(value, key)
    if not matches or any(item != expected for item in matches):
        raise ValueError("execution sampler contract mismatch")


def _catalog_rows(payload: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    rows = payload.get("opponents")
    if not isinstance(rows, tuple | list) or not rows:
        raise ValueError("opponent catalog rows missing")
    result = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("opponent catalog row invalid")
        result.append(row)
    return tuple(result)


def _config_from_catalog_row(row: Mapping[str, Any], raw: bytes) -> OpponentModelConfig:
    payload = _strict_canonical_object(raw)
    config = OpponentModelConfig.from_payload(payload)
    if config.split != "test":
        raise ValueError("opponent payload is not Test split")
    if row.get("opponent_id") != config.opponent_id:
        raise ValueError("opponent catalog ID mismatch")
    required_joins = {
        "config_sha256": config.config_sha256,
        "seed": config.seed,
        "equilibrium_version": config.equilibrium_version,
        "equilibrium_artifact_sha256": config.equilibrium_artifact_sha256,
    }
    for key, expected in required_joins.items():
        if key not in row or row[key] != expected:
            raise ValueError("opponent catalog provenance mismatch")
    _sha(row.get("strategy_sha256"))
    expected_role = "gto_negative_control" if not config.leak_vector else "evaluation"
    if row.get("control_role") != expected_role:
        raise ValueError("opponent catalog control-role mismatch")
    return config


def _decode_frames(input_capability: Any, manifest: Mapping[str, Any]) -> _DecodedInput:
    reader = _ForwardReader(input_capability)
    seen_ids: set[str] = set()
    try:
        context_frame = _read_frame(reader, seen_ids)
        expected_context = {
            "coordinates": _plain(manifest["coordinates"]),
            "selection": _plain(manifest["selection"]),
            "test_input": _plain(manifest["test_input"]),
        }
        context_raw = canonical_json_bytes(expected_context)
        _expect_frame(
            context_frame,
            frame_type="batch_context",
            frame_id="test_batch_context",
            name="test_batch_context",
            sha256=sha256_bytes(context_raw),
            size_bytes=len(context_raw),
        )
        if context_frame.payload != context_raw:
            raise ValueError("batch context mismatch")

        component_payloads: dict[str, Mapping[str, Any]] = {}
        for component_name in _COMPONENT_ORDER:
            frame = _read_frame(reader, seen_ids)
            ref = manifest["components"][component_name]
            _expect_frame(
                frame,
                frame_type="component",
                frame_id=component_name,
                name=component_name,
                sha256=ref["sha256"],
                size_bytes=ref["size_bytes"],
            )
            payload = _strict_canonical_object(frame.payload)
            if payload.get("schema_version") != ref["schema_version"]:
                raise ValueError("component schema mismatch")
            component_payloads[component_name] = _freeze(payload)

        sampler = component_payloads["execution_sampler"]
        for key, expected in (
            ("execution_sampler_version", EXECUTION_SAMPLER_VERSION),
            ("draw_derivation_version", DRAW_DERIVATION_VERSION),
            ("seed_derivation_version", SEED_DERIVATION_VERSION),
            ("legal_action_order_version", LEGAL_ACTION_ORDER_VERSION),
            ("probability_mapping_version", PROBABILITY_MAPPING_VERSION),
            ("common_random_numbers", True),
        ):
            _require_embedded_contract(sampler, key, expected)

        selected_lock = component_payloads["selected_config_lock"]
        selected = selected_lock.get("selected_config")
        if not isinstance(selected, Mapping):
            raise ValueError("selected configuration missing")
        primary_raw = canonical_json_bytes(_plain(selected))
        selection = manifest["selection"]
        if sha256_bytes(primary_raw) != selection["primary_config_sha256"]:
            raise ValueError("primary configuration hash mismatch")

        execution_index = component_payloads["execution_config_index"]
        if (
            set(execution_index)
            != {
                "schema_version",
                "artifact_type",
                "estimator_config_sha256",
                "selected_config_lock_sha256",
                "primary",
                "comparators",
                "ablations",
            }
            or execution_index["estimator_config_sha256"]
            != manifest["components"]["estimator_config"]["sha256"]
            or execution_index["selected_config_lock_sha256"]
            != manifest["components"]["selected_config_lock"]["sha256"]
        ):
            raise ValueError("execution configuration index identity mismatch")
        primary_ref = execution_index.get("primary")
        if (
            not isinstance(primary_ref, Mapping)
            or set(primary_ref)
            != {
                "config_id",
                "derivation",
                "name",
                "sha256",
                "size_bytes",
                "source_component_sha256",
            }
            or primary_ref["config_id"] != selection["primary_config_id"]
            or primary_ref["derivation"]
            != "canonical_json_bytes(selected_config_lock#/selected_config)"
            or primary_ref["name"] != "primary"
            or primary_ref["sha256"] != selection["primary_config_sha256"]
            or primary_ref["size_bytes"] != len(primary_raw)
            or primary_ref["source_component_sha256"]
            != manifest["components"]["selected_config_lock"]["sha256"]
        ):
            raise ValueError("primary execution index missing")
        primary_frame = _read_frame(reader, seen_ids)
        _expect_frame(
            primary_frame,
            frame_type="config",
            frame_id=selection["primary_config_id"],
            name="primary",
            sha256=selection["primary_config_sha256"],
            size_bytes=len(primary_raw),
        )
        if primary_frame.payload != primary_raw:
            raise ValueError("derived primary bytes mismatch")
        configs: list[Mapping[str, Any]] = [
            _freeze(_strict_canonical_object(primary_frame.payload))
        ]

        for group_name in ("comparators", "ablations"):
            indexed = execution_index.get(group_name)
            selected_group = selection[group_name]
            if not isinstance(indexed, tuple | list) or len(indexed) != len(selected_group):
                raise ValueError("execution configuration cardinality mismatch")
            for ref, selected_ref in zip(indexed, selected_group, strict=True):
                if not isinstance(ref, Mapping) or not isinstance(selected_ref, Mapping):
                    raise ValueError("execution configuration ref invalid")
                frame = _read_frame(reader, seen_ids)
                _expect_frame(
                    frame,
                    frame_type="config",
                    frame_id=ref["config_id"],
                    name=ref["name"],
                    sha256=ref["sha256"],
                    size_bytes=ref["size_bytes"],
                )
                if any(ref[key] != selected_ref[key] for key in ("config_id", "name", "sha256")):
                    raise ValueError("selection and execution index mismatch")
                config_payload = _strict_canonical_object(frame.payload)
                if config_payload.get("schema_version") != ref["schema_version"]:
                    raise ValueError("indexed configuration schema mismatch")
                configs.append(_freeze(config_payload))

        opponent_index = component_payloads["opponent_payload_index"]
        opponent_refs = opponent_index.get("opponents")
        opponent_ids = manifest["coordinates"]["opponent_ids"]
        catalog_rows = _catalog_rows(component_payloads["opponent_catalog"])
        if (
            not isinstance(opponent_refs, tuple | list)
            or len(opponent_refs) != len(opponent_ids)
            or len(catalog_rows) != len(opponent_ids)
        ):
            raise ValueError("opponent cardinality mismatch")
        opponent_configs = []
        for ref, row, opponent_id in zip(opponent_refs, catalog_rows, opponent_ids, strict=True):
            if not isinstance(ref, Mapping) or ref.get("opponent_id") != opponent_id:
                raise ValueError("opponent index order mismatch")
            if row.get("opponent_id") != opponent_id:
                raise ValueError("opponent catalog order mismatch")
            frame = _read_frame(reader, seen_ids)
            _expect_frame(
                frame,
                frame_type="opponent_payload",
                frame_id=opponent_id,
                name=opponent_id,
                sha256=ref["sha256"],
                size_bytes=ref["size_bytes"],
            )
            opponent_configs.append(_config_from_catalog_row(row, frame.payload))

        reader.finish()
        return _DecodedInput(
            _freeze(expected_context),
            MappingProxyType(component_payloads),
            _freeze(manifest["components"]),
            tuple(configs),
            tuple(opponent_configs),
            tuple(catalog_rows),
        )
    except GateBExecutorError:
        raise
    except Exception:
        _raise_sanitized(GateBFrameError)


@dataclass(frozen=True, slots=True)
class _ScientificContract:
    baseline_table: ActionBaselineTable
    detector_config: LeakDetectorConfig
    baseline_rate: Decimal
    tau: Decimal
    action_group: tuple[str, ...]
    evaluator_version: str
    exact_ev_evaluator_version: str
    ground_truth_extractor_version: str
    component_sha256s: Mapping[str, str]


def _component_value(
    payload: Mapping[str, Any],
    key: str,
    *,
    expected: object | None = None,
) -> object:
    values = _find_values(payload, key)
    if not values:
        raise ValueError("required scientific component field is absent")
    if expected is not None:
        if any(value != expected for value in values):
            raise ValueError("scientific component field mismatch")
        return expected
    first = values[0]
    if any(value != first for value in values[1:]):
        raise ValueError("scientific component field is ambiguous")
    return first


def _component_version(
    payload: Mapping[str, Any],
    field: str | tuple[str, ...],
    expected: str,
) -> str:
    names = (field,) if isinstance(field, str) else field
    values = [value for name in names for value in _find_values(payload, name)]
    if values:
        if any(value != expected for value in values):
            raise ValueError("scientific component version mismatch")
    elif payload.get("schema_version") != expected:
        raise ValueError("scientific component version is absent")
    return expected


def _decimal_probability(value: object, label: str) -> Decimal:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a canonical decimal string")
    parsed = Decimal(value)
    if not parsed.is_finite() or not Decimal(0) <= parsed <= Decimal(1):
        raise ValueError(f"{label} must be in [0, 1]")
    if _decimal_wire(parsed) != value:
        raise ValueError(f"{label} is not canonical")
    return parsed


def _scientific_contract(
    decoded: _DecodedInput,
    selected: Mapping[str, Any],
) -> _ScientificContract:
    baseline = decoded.components["baseline_table"]
    estimator = decoded.components["estimator_config"]
    evaluator = decoded.components["evaluator"]
    ground_truth = decoded.components["ground_truth_extractor"]

    _component_value(baseline, "reason_id", expected=R008_REASON_ID)
    _component_value(baseline, "situation_key", expected=R008_SITUATION_KEY)
    action_group_value = _component_value(baseline, "action_group")
    if not isinstance(action_group_value, tuple | list):
        raise ValueError("baseline action group is invalid")
    action_group = tuple(action_group_value)
    if action_group != R008_ACTION_GROUP:
        raise ValueError("baseline action group is not the frozen R008 group")
    baseline_rate = _decimal_probability(
        _component_value(baseline, "baseline_rate"),
        "baseline rate",
    )
    gto_configs = [config for config in decoded.opponent_configs if not config.leak_vector]
    if len(gto_configs) != 1:
        raise ValueError("Test catalog must contain exactly one GTO control")
    gto = synthesize_opponent(config=gto_configs[0])
    independent_baseline = extract_independent_action_rates(
        gto.game,
        gto.equilibrium_strategy,
        gto.config,
        reason_ids=(R008_REASON_ID,),
    )
    if len(independent_baseline) != 1 or independent_baseline[0].action_rate != baseline_rate:
        raise ValueError("baseline component does not join independent GTO truth")

    _component_value(estimator, "method_version", expected=ESTIMATOR_METHOD_VERSION)
    _component_value(estimator, "alpha0", expected="1")
    _component_value(estimator, "beta0", expected="1")
    _component_value(estimator, "tail", expected="upper")
    tau = _decimal_probability(_component_value(estimator, "tau"), "tau")
    if tau <= 0:
        raise ValueError("tau must be positive")
    for estimator_field, selected_field in (
        ("sample_floor", "sample_floor"),
        ("detector_threshold", "detector_confidence"),
        ("provider_threshold", "provider_confidence"),
    ):
        _component_value(
            estimator,
            estimator_field,
            expected=selected[selected_field],
        )
    detector_threshold = _decimal_probability(
        selected["detector_confidence"],
        "detector threshold",
    )
    provider_threshold = _decimal_probability(
        selected["provider_confidence"],
        "provider threshold",
    )
    sample_floor = selected["sample_floor"]
    if isinstance(sample_floor, bool) or not isinstance(sample_floor, int) or sample_floor <= 0:
        raise ValueError("sample floor is invalid")
    if "tau" in selected and _decimal_probability(selected["tau"], "selected tau") != tau:
        raise ValueError("selected tau does not join estimator")

    evaluator_version = _component_version(
        evaluator,
        ("evaluator_version", "calibration_evaluator_version"),
        CALIBRATION_EVALUATOR_VERSION,
    )
    exact_ev_version = _component_version(
        evaluator,
        "exact_ev_evaluator_version",
        EXACT_EV_INPUT_VERSION,
    )
    ground_truth_version = _component_version(
        ground_truth,
        "ground_truth_extractor_version",
        GROUND_TRUTH_EXTRACTOR_VERSION,
    )

    baseline_table = ActionBaselineTable(
        table_version=str(baseline.get("table_version", baseline["schema_version"])),
        rules=(
            ActionLeakRule(
                reason_id=R008_REASON_ID,
                leak_type="bet_too_often_when_checked_to",
                action_group=action_group,
                baseline_rate=float(baseline_rate),
                direction="decrease_bet_frequency_when_checked_to",
                situation_overrides={R008_SITUATION_KEY: float(baseline_rate)},
            ),
        ),
    )
    detector_config = LeakDetectorConfig(
        method_version=ESTIMATOR_METHOD_VERSION,
        alpha0=1.0,
        beta0=1.0,
        tail="upper",
        min_effective_sample_size=sample_floor,
        min_deviation=float(tau),
        min_confidence=float(detector_threshold),
        rule_exploit_min_confidence=float(provider_threshold),
        nodelock_exploit_min_confidence=float(provider_threshold),
    )
    component_sha256s = {
        name: _sha(decoded.component_refs[name]["sha256"])
        for name in (
            "baseline_table",
            "estimator_config",
            "evaluator",
            "execution_sampler",
            "ground_truth_extractor",
            "opponent_catalog",
            "selected_config_lock",
            "validation_selection_report",
        )
    }
    return _ScientificContract(
        baseline_table,
        detector_config,
        baseline_rate,
        tau,
        action_group,
        evaluator_version,
        exact_ev_version,
        ground_truth_version,
        MappingProxyType(component_sha256s),
    )


def _decimal_wire(value: Decimal) -> str:
    if not value.is_finite():
        raise ValueError("non-finite Decimal")
    if value.is_zero():
        return "0"
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    if rendered == "-0":
        return "0"
    return rendered


def _reject_development_result(value: object) -> None:
    module = type(value).__module__
    name = type(value).__name__.lower()
    if (
        module.startswith("phase6.training")
        or module.startswith("phase6.validation")
        or "training" in name
        or "validation" in name
    ):
        raise ValueError("development result is not a Test result")


def _wire(value: object) -> object:
    _reject_development_result(value)
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _wire(object.__getattribute__(value, field.name)) for field in fields(value)
        }
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("wire mapping keys must be strings")
        return {key: _wire(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_wire(item) for item in value]
    if isinstance(value, Decimal):
        return _decimal_wire(value)
    if isinstance(value, float):
        raise ValueError("raw float forbidden at wire boundary")
    if value is None or isinstance(value, bool | int | str):
        return value
    raise TypeError("unsupported wire value")


def _policy_wire(profile: Mapping[str, Mapping[str, float]]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for infoset in sorted(profile):
        distribution = profile[infoset]
        if not distribution or any(
            not isinstance(probability, float)
            or not math.isfinite(probability)
            or probability < 0.0
            for probability in distribution.values()
        ):
            raise ValueError("invalid policy distribution")
        if abs(sum(distribution.values()) - 1.0) > 1e-12:
            raise ValueError("policy distribution is not normalized")
        result[infoset] = {action: distribution[action].hex() for action in sorted(distribution)}
    return result


def _ev_paths_wire(value: object) -> dict[str, str]:
    production = value.production
    independent = value.independent_leaves
    if any(
        not isinstance(item, float) or not math.isfinite(item) for item in (production, independent)
    ):
        raise ValueError("invalid exact EV path")
    return {
        "production_binary64_hex": production.hex(),
        "independent_leaves_binary64_hex": independent.hex(),
    }


def _exact_ev_cell_wire(cell: object) -> dict[str, object]:
    profiles = cell.profiles
    efficiency = cell.efficiency
    floats = (cell.gain, cell.opportunity)
    if any(not isinstance(item, float) or not math.isfinite(item) for item in floats):
        raise ValueError("invalid exact EV scalar")
    if efficiency is not None and (
        not isinstance(efficiency, float) or not math.isfinite(efficiency)
    ):
        raise ValueError("invalid exact EV efficiency")
    return {
        "game_id": profiles.game_id,
        "opponent_id": profiles.opponent_id,
        "hero_player": profiles.hero_player,
        "profiles": {
            "base": _policy_wire(profiles.base),
            "final": _policy_wire(profiles.final),
            "oracle_br": _policy_wire(profiles.oracle_br),
        },
        "base_ev": _ev_paths_wire(cell.base_ev),
        "final_ev": _ev_paths_wire(cell.final_ev),
        "oracle_br_ev": _ev_paths_wire(cell.oracle_br_ev),
        "gain_binary64_hex": cell.gain.hex(),
        "opportunity_binary64_hex": cell.opportunity.hex(),
        "efficiency_binary64_hex": None if efficiency is None else efficiency.hex(),
        "efficiency_status": cell.efficiency_status,
    }


@dataclass(frozen=True, slots=True)
class _Coordinate:
    index: int
    opponent_id: str
    horizon: int
    repetition_id: str
    seed: int

    def session(self) -> dict[str, object]:
        return {
            "opponent_id": self.opponent_id,
            "horizon": self.horizon,
            "repetition_id": self.repetition_id,
            "seed": self.seed,
        }


@dataclass(frozen=True, slots=True)
class _CoordinateResult:
    coordinate: _Coordinate
    terminal: Mapping[str, object]
    hero_policy: Mapping[str, object]
    exact_ev: Mapping[str, object]
    exact_ev_cell: object
    ground_truth: tuple[object, ...]

    def wire(self) -> dict[str, object]:
        return {
            "coordinate_index": self.coordinate.index,
            **self.coordinate.session(),
            "terminal_candidate_snapshot": _plain(self.terminal),
            "hero_policy_snapshot": _plain(self.hero_policy),
            "exact_ev_cell": _plain(self.exact_ev),
        }


def _chance_child(root: Chance, selected_label: str) -> Decision:
    matches = [child for _probability, child, label in root.branches if label == selected_label]
    if len(matches) != 1 or not isinstance(matches[0], Decision):
        raise ValueError("observation outcome does not identify one decision")
    return matches[0]


def _hero_policies(
    game: Game,
    synthesized: object,
    selected: Mapping[str, Any],
    scientific: _ScientificContract,
    counts: Mapping[str, int],
    opportunities: int,
) -> tuple[StrategyProfile, StrategyProfile]:
    leaks = tuple(
        LeakDetector(scientific.baseline_table, scientific.detector_config).detect_for_situation(
            (ActionStats(R008_SITUATION_KEY, opportunities, counts),),
            R008_SITUATION_KEY,
        )
    )
    node_lock = nodelock_config_from_leaks(
        leaks,
        hero_position="OOP",
        min_confidence=float(Decimal(selected["provider_confidence"])),
    )
    hero_infosets = game.infosets_of(0)
    base = {infoset: dict(synthesized.equilibrium_strategy[infoset]) for infoset in hero_infosets}
    exploit = {infoset: dict(distribution) for infoset, distribution in base.items()}
    if node_lock is not None:
        application = apply_node_locks(
            game,
            synthesized.equilibrium_strategy,
            node_lock,
            reach_weights=river_infoset_reach_weights(game, synthesized.equilibrium_strategy),
        )
        best_actions = best_response_strategy(game, 0, application.profile)
        for infoset in hero_infosets:
            if infoset.endswith(":vs_bet"):
                exploit[infoset] = {
                    action: float(action == best_actions[infoset])
                    for action in game.actions_of(infoset)
                }
    alpha = float(Decimal(selected["safety_alpha"]))
    final = {
        infoset: safety_mix(base[infoset], exploit[infoset], alpha) for infoset in hero_infosets
    }
    return base, final


def _run_coordinate(
    decoded: _DecodedInput,
    selected: Mapping[str, Any],
    config: OpponentModelConfig,
    coordinate: _Coordinate,
    scientific: _ScientificContract,
) -> _CoordinateResult:
    synthesized = synthesize_opponent(config=config)
    game = synthesized.game
    registry = build_production_observation_registry(game)
    if not isinstance(game.root, Chance) or len(registry.nodes) != 1:
        raise ValueError("Test river game shape mismatch")
    roots = {
        name: GateBStreamRoot.derive(
            opponent_id=coordinate.opponent_id,
            horizon=coordinate.horizon,
            repetition_id=coordinate.repetition_id,
            master_seed=coordinate.seed,
            stream_name=name,
        )
        for name in STREAM_NAMES
    }
    counts: Counter[str] = Counter()
    transcript = hashlib.sha256()
    for decision_index in range(coordinate.horizon):
        node = registry.nodes[0]
        observation_digest = derive_gate_b_draw_digest(
            roots["observation"],
            decision_index=decision_index,
            variate_index=0,
        )
        outcome = weighted_categorical(
            [item[0] for item in node.ordered_outcomes],
            [item[1] for item in node.ordered_outcomes],
            observation_digest,
        )
        start = _chance_child(game.root, outcome)
        opponent_node = start.child_of("CHECK")
        if not isinstance(opponent_node, Decision) or opponent_node.player != 1:
            raise ValueError("Test checked-to opponent decision missing")
        opponent_digest = derive_gate_b_draw_digest(
            roots["observation"],
            decision_index=decision_index,
            variate_index=1,
        )
        ordered_actions = canonical_legal_actions(opponent_node.actions)
        distribution = synthesized.strategy[opponent_node.infoset]
        opponent_action = weighted_categorical(
            ordered_actions,
            [distribution[action] for action in ordered_actions],
            opponent_digest,
        )
        counts[opponent_action] += 1
        event: dict[str, object] = {
            "decision_index": decision_index,
            "observation_draw_sha256": observation_digest,
            "opponent_draw_sha256": opponent_digest,
            "opponent_action": opponent_action,
            "hero_action": None,
        }
        if opponent_action == "BET":
            response = opponent_node.child_of("BET")
            if not isinstance(response, Decision) or response.player != 0:
                raise ValueError("Test Hero response missing")
            _base, final = _hero_policies(
                game,
                synthesized,
                selected,
                scientific,
                counts,
                decision_index + 1,
            )
            legal = canonical_legal_actions(response.actions)
            hero_digest = derive_gate_b_draw_digest(
                roots["hero_action"],
                decision_index=decision_index,
            )
            epsilon_digest = derive_gate_b_draw_digest(
                roots["epsilon_branch"],
                decision_index=decision_index,
            )
            hero_action = weighted_categorical(
                legal,
                [final[response.infoset][action] for action in legal],
                hero_digest,
            )
            epsilon_action, _uniform_digest, _attempt = gate_b_uniform_action(
                legal,
                roots["epsilon_action"],
                decision_index=decision_index,
            )
            event["hero_action"] = (
                epsilon_action
                if epsilon_branch_fires(epsilon_digest, selected["epsilon"])
                else hero_action
            )
        transcript.update(canonical_json_bytes(event))

    action_counts = {"BET": counts["BET"], "CHECK": counts["CHECK"]}
    terminal = {
        "schema_version": TERMINAL_SCHEMA,
        "evaluator_version": scientific.evaluator_version,
        "session": coordinate.session(),
        "action_counts": action_counts,
        "opportunity_count": coordinate.horizon,
        "transcript_sha256": transcript.hexdigest(),
    }
    base, final = _hero_policies(
        game,
        synthesized,
        selected,
        scientific,
        counts,
        coordinate.horizon,
    )
    terminal_hash = sha256_bytes(canonical_json_bytes(terminal))
    policy = {
        "schema_version": HERO_POLICY_SCHEMA,
        "exact_ev_evaluator_version": scientific.exact_ev_evaluator_version,
        "session": coordinate.session(),
        "source_terminal_sha256": terminal_hash,
        "game_id": game.name,
        "opponent_id": coordinate.opponent_id,
        "hero_player": 0,
        "base_hero_policy": _policy_wire(base),
        "final_hero_policy": _policy_wire(final),
    }
    opponent_policy = {infoset: synthesized.strategy[infoset] for infoset in game.infosets_of(1)}
    cell = evaluate_exact_ev(
        game,
        hero_player=0,
        opponent_policy=PolicySlice(game.name, coordinate.opponent_id, opponent_policy),
        base_hero_policy=PolicySlice(game.name, coordinate.opponent_id, base),
        final_hero_policy=PolicySlice(game.name, coordinate.opponent_id, final),
    )
    exact = {
        "schema_version": EXACT_EV_SCHEMA,
        "exact_ev_evaluator_version": scientific.exact_ev_evaluator_version,
        "session": coordinate.session(),
        "source_terminal_sha256": terminal_hash,
        "source_hero_policy_sha256": sha256_bytes(canonical_json_bytes(policy)),
        "cell": _exact_ev_cell_wire(cell),
    }
    truth = (
        extract_true_leaks(
            game,
            synthesized.equilibrium_strategy,
            synthesized.strategy,
            config,
        ),
        extract_independent_action_rates(
            game,
            synthesized.strategy,
            config,
            reason_ids=(R008_REASON_ID,),
        ),
    )
    return _CoordinateResult(
        coordinate,
        _freeze(terminal),
        _freeze(policy),
        _freeze(exact),
        cell,
        truth,
    )


def _coordinates(batch_context: Mapping[str, Any]) -> tuple[_Coordinate, ...]:
    coordinates = batch_context["coordinates"]
    opponent_ids = tuple(coordinates["opponent_ids"])
    horizons = tuple(coordinates["horizons"])
    repetition_ids = tuple(coordinates["repetition_ids"])
    expected = [
        (opponent_id, horizon, repetition_id)
        for opponent_id in opponent_ids
        for horizon in horizons
        for repetition_id in repetition_ids
    ]
    if len(expected) != 810:
        raise ValueError("Gate B coordinate cardinality must be exactly 810")
    seed_mapping = tuple(coordinates["seed_mapping"])
    if len(seed_mapping) != len(expected):
        raise ValueError("seed mapping cardinality mismatch")
    result = []
    for index, (row, expected_key) in enumerate(zip(seed_mapping, expected, strict=True), start=1):
        key = (row["opponent_id"], row["horizon"], row["repetition_id"])
        if key != expected_key:
            raise ValueError("seed mapping order mismatch")
        seed = row["seed"]
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError("seed mapping seed invalid")
        result.append(_Coordinate(index, *key, seed))
    if len(result) != len(
        set((item.opponent_id, item.horizon, item.repetition_id) for item in result)
    ):
        raise ValueError("duplicate coordinate")
    return tuple(result)


def _strategy_sha256(profile: Mapping[str, Mapping[str, float]]) -> str:
    payload = [
        {
            "infoset": infoset,
            "actions": [
                {
                    "action": action,
                    "probability_binary64_hex": profile[infoset][action].hex(),
                }
                for action in sorted(profile[infoset])
            ],
        }
        for infoset in sorted(profile)
    ]
    return sha256_bytes(canonical_json_bytes(payload))


def _posterior_confidence(*, k: int, n: int, baseline: float, tau: float) -> float:
    if not 0 <= k <= n or not 0.0 <= baseline <= 1.0 or not 0.0 < tau < 1.0:
        raise ValueError("posterior input is invalid")
    q = baseline + tau
    if q >= 1.0:
        return 0.0
    trials = n + 1
    log_q = math.log(q)
    log_one_minus_q = math.log1p(-q)
    terms = [
        math.lgamma(trials + 1)
        - math.lgamma(index + 1)
        - math.lgamma(trials - index + 1)
        + index * log_q
        + (trials - index) * log_one_minus_q
        for index in range(k + 1)
    ]
    maximum = max(terms)
    probability = math.exp(maximum) * math.fsum(math.exp(term - maximum) for term in terms)
    return min(1.0, max(0.0, probability))


def _component_ref(decoded: _DecodedInput, name: str) -> dict[str, object]:
    ref = decoded.component_refs[name]
    return {
        "name": name,
        "schema_version": ref["schema_version"],
        "sha256": _sha(ref["sha256"]),
        "size_bytes": ref["size_bytes"],
    }


def _test_series_descriptor(
    decoded: _DecodedInput,
    selected: Mapping[str, Any],
    scientific: _ScientificContract,
    results: Sequence[_CoordinateResult],
) -> tuple[dict[str, object], dict[str, str]]:
    synthesized = [synthesize_opponent(config=config) for config in decoded.opponent_configs]
    gto_ids = [item.config.opponent_id for item in synthesized if not item.config.leak_vector]
    if len(gto_ids) != 1:
        raise ValueError("Test series requires exactly one GTO negative control")
    strategy_hashes: dict[str, str] = {}
    opponent_rows = []
    if len(synthesized) != len(decoded.opponent_catalog_rows):
        raise ValueError("Test catalog synthesis cardinality mismatch")
    for item, catalog_row in zip(
        synthesized,
        decoded.opponent_catalog_rows,
        strict=True,
    ):
        is_gto = not item.config.leak_vector
        generated_strategy_hash = _strategy_sha256(item.strategy)
        if catalog_row["strategy_sha256"] != generated_strategy_hash:
            raise ValueError("synthesized strategy does not join opponent catalog")
        strategy_hash = (
            item.config.equilibrium_artifact_sha256 if is_gto else catalog_row["strategy_sha256"]
        )
        strategy_hashes[item.config.opponent_id] = strategy_hash
        opponent_rows.append(
            {
                "opponent_id": item.config.opponent_id,
                "control_role": "gto_negative_control" if is_gto else "evaluation",
                "strategy_artifact_sha256": strategy_hash,
                "equilibrium_artifact_sha256": strategy_hash if is_gto else None,
            }
        )
    opponent_rows.sort(key=lambda item: item["opponent_id"])
    coordinate_contract = decoded.batch_context["coordinates"]
    horizons = list(coordinate_contract["horizons"])
    repetitions = list(coordinate_contract["repetition_ids"])
    if horizons != sorted(set(horizons)) or repetitions != sorted(set(repetitions)):
        raise ValueError("Test calibration dimensions are not canonical")
    if not results:
        raise ValueError("Test calibration has no coordinate results")
    epsilon = _decimal_probability(selected["epsilon"], "epsilon")
    safety_alpha = _decimal_probability(selected["safety_alpha"], "safety alpha")
    config = {
        "split": "test",
        "opponent_catalog_sha256": scientific.component_sha256s["opponent_catalog"],
        "estimator_method_version": ESTIMATOR_METHOD_VERSION,
        "estimator_config_sha256": scientific.component_sha256s["estimator_config"],
        "baseline_table_sha256": scientific.component_sha256s["baseline_table"],
        "tau": _decimal_wire(scientific.tau),
        "sample_floor": scientific.detector_config.min_effective_sample_size,
        "detector_threshold": _decimal_wire(
            Decimal(str(scientific.detector_config.min_confidence))
        ),
        "provider_threshold": _decimal_wire(
            Decimal(str(scientific.detector_config.rule_exploit_min_confidence))
        ),
        "exploit_provider": EXPLOIT_PROVIDER_VERSION,
        "safety_alpha": _decimal_wire(safety_alpha),
        "execution_sampler_version": EXECUTION_SAMPLER_VERSION,
        "epsilon": _decimal_wire(epsilon),
        "epsilon_distribution_sha256": sha256_bytes(
            canonical_json_bytes(
                {
                    "distribution": "legal_uniform",
                    "epsilon": _decimal_wire(epsilon),
                    "execution_sampler_sha256": scientific.component_sha256s["execution_sampler"],
                }
            )
        ),
        "horizon_set": horizons,
        "repetition_set": repetitions,
        "evaluator_version": scientific.evaluator_version,
        "boundary_abs_tolerance": BOUNDARY_ABS_TOLERANCE_WIRE,
        "decimal_precision": DECIMAL_PRECISION,
        "decimal_rounding": DECIMAL_ROUNDING,
        "game_id": results[0].exact_ev_cell.profiles.game_id,
        "ground_truth_extractor_version": scientific.ground_truth_extractor_version,
        "exact_ev_evaluator_version": scientific.exact_ev_evaluator_version,
    }
    dimension = {
        "rule_id": R008_REASON_ID,
        "situation_key": R008_SITUATION_KEY,
        "semantic_id": R008_SEMANTIC_ID,
        "action_family_id": R008_ACTION_FAMILY_ID,
        "opportunity_event_id": R008_OPPORTUNITY_EVENT_ID,
        "action_group": list(scientific.action_group),
        "baseline_rate": _decimal_wire(scientific.baseline_rate),
    }
    descriptor = {
        "config": config,
        "opponents": opponent_rows,
        "candidate_dimensions": [dimension],
    }
    descriptor["series_id"] = calibration_series_id(
        config,
        opponent_rows,
        [dimension],
    )
    return descriptor, strategy_hashes


def _terminal_calibration_record(
    series_id: str,
    result: _CoordinateResult,
    scientific: _ScientificContract,
) -> dict[str, object]:
    coordinate = result.coordinate
    counts = dict(result.terminal["action_counts"])
    if set(counts) != {"BET", "CHECK"}:
        raise ValueError("terminal action-count surface changed")
    n = sum(counts.values())
    if n != coordinate.horizon:
        raise ValueError("terminal count does not join coordinate horizon")
    k = sum(counts.get(action, 0) for action in scientific.action_group)
    confidence = _posterior_confidence(
        k=k,
        n=n,
        baseline=float(scientific.baseline_rate),
        tau=float(scientific.tau),
    )
    confidence_wire = _decimal_wire(Decimal(str(confidence)))
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        q = scientific.baseline_rate + scientific.tau
        observed = Decimal(k) / Decimal(n)
    eligibility = {
        "structurally_eligible": Decimal(0) < q < Decimal(1),
        "sample_gate": n >= scientific.detector_config.min_effective_sample_size,
        "deviation_gate": observed - scientific.baseline_rate >= scientific.tau,
        "confidence_gate": Decimal(confidence_wire)
        >= Decimal(str(scientific.detector_config.min_confidence)),
    }
    eligibility["emitted"] = all(eligibility.values())
    return {
        "series_id": series_id,
        "opponent_id": coordinate.opponent_id,
        "rule_id": R008_REASON_ID,
        "situation_key": R008_SITUATION_KEY,
        "horizon": coordinate.horizon,
        "repetition_id": coordinate.repetition_id,
        "action_counts": counts,
        "action_group": list(scientific.action_group),
        "n": n,
        "k": k,
        "baseline_rate": _decimal_wire(scientific.baseline_rate),
        "tau": _decimal_wire(scientific.tau),
        "q": _decimal_wire(q),
        "posterior_confidence": confidence_wire,
        "candidate_eligibility": eligibility,
    }


def _ground_truth_calibration_record(
    series_id: str,
    result: _CoordinateResult,
    scientific: _ScientificContract,
    strategy_hash: str,
) -> dict[str, object]:
    rates = result.ground_truth[1]
    measurements = [item for item in rates if item.reason_id == R008_REASON_ID]
    if len(measurements) != 1:
        raise ValueError("independent R008 ground truth is not unique")
    measurement = measurements[0]
    coordinate = result.coordinate
    return {
        "series_id": series_id,
        "opponent_id": coordinate.opponent_id,
        "rule_id": R008_REASON_ID,
        "situation_key": R008_SITUATION_KEY,
        "horizon": coordinate.horizon,
        "repetition_id": coordinate.repetition_id,
        "semantic_id": R008_SEMANTIC_ID,
        "action_family_id": R008_ACTION_FAMILY_ID,
        "opportunity_event_id": R008_OPPORTUNITY_EVENT_ID,
        "action_group": list(scientific.action_group),
        "true_rate": _decimal_wire(measurement.action_rate),
        "reach_weight": _decimal_wire(measurement.opportunity_reach),
        "strategy_artifact_sha256": strategy_hash,
        "ground_truth_extractor_version": scientific.ground_truth_extractor_version,
    }


def _aggregate_from_calibration(evaluation: object) -> dict[str, object]:
    series = evaluation.series
    if not isinstance(series, tuple | list) or len(series) != 1:
        raise ValueError("Test calibration must contain exactly one series")
    item = series[0]
    return {
        "series_id": item.series_id,
        "terminal_snapshot_sha256": item.terminal_snapshot_sha256,
        "ground_truth_sha256": item.ground_truth_sha256,
        "exact_ev_sha256s": list(item.exact_ev_sha256s),
        "atomic_groups": _wire(item.atomic_groups),
        "macro": _wire(item.macro),
        "micro": _wire(item.micro),
        "gto_fpr": _wire(item.gto_fpr),
    }


class _BoundedOutputs:
    __slots__ = ("_capability", "_sizes", "_total")

    def __init__(self, capability: Any) -> None:
        self._capability = capability
        self._sizes = {name: 0 for name in OUTPUT_LIMITS}
        self._total = 0

    def write(self, name: str, raw: bytes) -> None:
        if name not in OUTPUT_LIMITS or not isinstance(raw, bytes) or not raw:
            _raise_sanitized(GateBOutputError)
        new_size = self._sizes[name] + len(raw)
        new_total = self._total + len(raw)
        if new_size > OUTPUT_LIMITS[name] or new_total > MAX_AGGREGATE_OUTPUT_BYTES:
            _raise_sanitized(GateBOutputError)
        self._sizes[name] = new_size
        self._total = new_total
        for offset in range(0, len(raw), MAX_CHUNK_BYTES):
            self._capability.write_chunk(name, raw[offset : offset + MAX_CHUNK_BYTES])

    def json(self, name: str, payload: object) -> bytes:
        if name not in OUTPUT_LIMITS:
            _raise_sanitized(GateBOutputError)
        remaining = min(
            OUTPUT_LIMITS[name] - self._sizes[name],
            MAX_AGGREGATE_OUTPUT_BYTES - self._total,
        )
        if remaining <= 0:
            _raise_sanitized(GateBOutputError)
        raw = _bounded_canonical_json_bytes(payload, remaining)
        self.write(name, raw)
        return raw


def _canonical_json_ascii_chunks(payload: object) -> Any:
    encoder = json.JSONEncoder(
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    for chunk in encoder.iterencode(payload):
        yield chunk.encode("ascii")


def _bounded_canonical_json_bytes(payload: object, maximum: int) -> bytes:
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0:
        _raise_sanitized(GateBOutputError)
    chunks: list[bytes] = []
    size = 0
    try:
        for chunk in _canonical_json_ascii_chunks(payload):
            if not chunk:
                continue
            if size + len(chunk) + 1 > maximum:
                _raise_sanitized(GateBOutputError)
            chunks.append(chunk)
            size += len(chunk)
    except GateBExecutorError:
        raise
    except Exception:
        _raise_sanitized(GateBOutputError)
    if size + 1 > maximum:
        _raise_sanitized(GateBOutputError)
    chunks.append(b"\n")
    return b"".join(chunks)


def _progress_entry(
    *,
    sequence: int,
    event_type: str,
    coordinate: _Coordinate | None,
    coordinate_count: int,
    status: str,
    result_sha256: str | None = None,
    metrics_sha256: str | None = None,
) -> dict[str, object]:
    return {
        "schema_version": EXECUTOR_PROGRESS_SCHEMA,
        "artifact_type": "gate_b_test_progress",
        "event_sequence": sequence,
        "event_type": event_type,
        "coordinate_index": None if coordinate is None else coordinate.index,
        "coordinate_count": coordinate_count,
        "opponent_id": None if coordinate is None else coordinate.opponent_id,
        "horizon": None if coordinate is None else coordinate.horizon,
        "repetition_id": None if coordinate is None else coordinate.repetition_id,
        "status": status,
        "result_sha256": result_sha256,
        "metrics_sha256": metrics_sha256,
    }


def _log_entry(
    *,
    sequence: int,
    event_type: str,
    coordinate: _Coordinate | None,
    detail_code: str,
) -> dict[str, object]:
    return {
        "schema_version": EXECUTOR_LOG_SCHEMA,
        "artifact_type": "gate_b_test_log",
        "event_sequence": sequence,
        "event_type": event_type,
        "coordinate_index": None if coordinate is None else coordinate.index,
        "component": "gate_b_executor",
        "detail_code": detail_code,
    }


def _metric_projection(aggregate: Mapping[str, object]) -> tuple[object, object, object]:
    micro = aggregate["micro"]
    gto_fpr = aggregate["gto_fpr"]
    if not isinstance(micro, Mapping):
        raise ValueError("calibration micro projection is invalid")
    calibration = micro.get("calibration")
    if (
        not isinstance(calibration, Mapping)
        or set(("brier", "ece")) - set(calibration)
        or not isinstance(gto_fpr, Mapping)
    ):
        raise ValueError("calibration metric projection is incomplete")
    return calibration["brier"], calibration["ece"], gto_fpr


class GateBProductionExecutor:
    """Immutable concrete implementation of the accepted executor protocol."""

    __slots__ = (
        "_batch_hash",
        "_executor_id",
        "_executor_sha256",
        "_execution_context_sha256",
        "_locked",
        "_manifest",
        "_operation_timeout_seconds",
        "_phase6_contract_bundle_evidence",
    )

    def __init__(
        self,
        token: object,
        *,
        executor_id: str,
        executor_sha256: str,
        batch_hash: str,
        execution_context_sha256: str,
        manifest: Mapping[str, Any],
        operation_timeout_seconds: int,
        phase6_contract_bundle_evidence: ValidatedPhase6ContractBundleEvidence,
    ) -> None:
        if token is not _CONSTRUCTION_TOKEN:
            raise TypeError("GateBProductionExecutor construction requires from_request")
        object.__setattr__(self, "_executor_id", executor_id)
        object.__setattr__(self, "_executor_sha256", executor_sha256)
        object.__setattr__(self, "_batch_hash", batch_hash)
        object.__setattr__(self, "_execution_context_sha256", execution_context_sha256)
        object.__setattr__(self, "_manifest", manifest)
        object.__setattr__(self, "_operation_timeout_seconds", operation_timeout_seconds)
        object.__setattr__(
            self,
            "_phase6_contract_bundle_evidence",
            phase6_contract_bundle_evidence,
        )
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("GateBProductionExecutor is immutable")

    @property
    def executor_id(self) -> str:
        return self._executor_id

    @property
    def executor_sha256(self) -> str:
        return self._executor_sha256

    @classmethod
    def from_request(
        cls,
        request: GateBLoaderRequest,
        *,
        phase6_contract_bundle_evidence: ValidatedPhase6ContractBundleEvidence,
        execution_context_sha256: str,
        operation_timeout_seconds: int = 7200,
    ) -> GateBProductionExecutor:
        validate_phase6_contract_bundle_evidence(phase6_contract_bundle_evidence)
        if (
            isinstance(operation_timeout_seconds, bool)
            or not isinstance(operation_timeout_seconds, int)
            or operation_timeout_seconds <= 0
        ):
            raise ValueError("operation timeout must be a positive integer")
        context_hash = _sha(execution_context_sha256)
        if request.execution_context.sha256 != context_hash:
            raise ValueError("execution context trust anchor mismatch")
        manifest = request.batch.payload
        sampler = manifest["components"]["execution_sampler"]
        executor_id = sampler["schema_version"]
        executor_sha256 = _sha(sampler["sha256"])
        if not isinstance(executor_id, str) or not executor_id:
            raise ValueError("execution sampler schema identity invalid")
        return cls(
            _CONSTRUCTION_TOKEN,
            executor_id=executor_id,
            executor_sha256=executor_sha256,
            batch_hash=_sha(request.batch.test_batch_hash),
            execution_context_sha256=context_hash,
            manifest=manifest,
            operation_timeout_seconds=operation_timeout_seconds,
            phase6_contract_bundle_evidence=phase6_contract_bundle_evidence,
        )

    def _evaluate_test_calibration(
        self,
        decoded: _DecodedInput,
        selected: Mapping[str, Any],
        results: Sequence[_CoordinateResult],
        scientific: _ScientificContract,
    ) -> object:
        """Build one independent calibration input and use one fresh bundle."""
        evidence_root = _strict_canonical_object(
            self._phase6_contract_bundle_evidence.root_manifest_raw
        )
        refs = {
            "preregistration": evidence_root["preregistration"],
            "coverage_semantics_contract": evidence_root["coverage_semantics_contract"],
            "selection_metric_contract": evidence_root["selection_metric_contract"],
            "series_reference": evidence_root["series_reference"],
        }
        descriptor, strategy_hashes = _test_series_descriptor(
            decoded,
            selected,
            scientific,
            results,
        )
        series_id = descriptor["series_id"]
        terminal_records = [
            _terminal_calibration_record(series_id, result, scientific) for result in results
        ]
        terminal_records.sort(
            key=lambda item: (
                item["series_id"],
                item["opponent_id"],
                item["rule_id"],
                item["situation_key"],
                item["horizon"],
                item["repetition_id"],
            )
        )
        truth_records = [
            _ground_truth_calibration_record(
                series_id,
                result,
                scientific,
                strategy_hashes[result.coordinate.opponent_id],
            )
            for result in results
        ]
        truth_records.sort(
            key=lambda item: (
                item["series_id"],
                item["opponent_id"],
                item["rule_id"],
                item["situation_key"],
                item["horizon"],
                item["repetition_id"],
            )
        )
        terminal_payload = {
            "schema_version": TERMINAL_CALIBRATION_SCHEMA,
            "artifact_type": "terminal_candidate_snapshots",
            "contract_refs": refs,
            "series": [descriptor],
            "records": terminal_records,
        }
        descriptor_hash = sha256_bytes(canonical_json_bytes(descriptor))
        truth_payload = {
            "schema_version": GROUND_TRUTH_CALIBRATION_SCHEMA,
            "artifact_type": "calibration_ground_truth",
            "contract_refs": refs,
            "series_descriptor_sha256s": {series_id: descriptor_hash},
            "records": truth_records,
        }
        terminal_raw = canonical_json_bytes(terminal_payload)
        truth_raw = canonical_json_bytes(truth_payload)
        terminal_artifact = CanonicalCalibrationArtifact(
            terminal_raw,
            sha256_bytes(terminal_raw),
        )
        truth_artifact = CanonicalCalibrationArtifact(
            truth_raw,
            sha256_bytes(truth_raw),
        )
        observations = tuple(
            ExactEvObservation(
                series_id=series_id,
                opponent_id=result.coordinate.opponent_id,
                horizon=result.coordinate.horizon,
                repetition_id=result.coordinate.repetition_id,
                cell=result.exact_ev_cell,
                sha256=exact_ev_observation_sha256(
                    series_id=series_id,
                    opponent_id=result.coordinate.opponent_id,
                    horizon=result.coordinate.horizon,
                    repetition_id=result.coordinate.repetition_id,
                    cell=result.exact_ev_cell,
                ),
            )
            for result in sorted(
                results,
                key=lambda item: (
                    item.coordinate.opponent_id,
                    item.coordinate.horizon,
                    item.coordinate.repetition_id,
                ),
            )
        )
        fresh_bundle = validate_phase6_contract_bundle_evidence(
            self._phase6_contract_bundle_evidence
        )
        evaluation = evaluate_all_candidate_calibration(
            fresh_bundle,
            terminal_artifact,
            truth_artifact,
            observations,
        )
        del fresh_bundle
        if evaluation.evaluator_version != scientific.evaluator_version:
            raise ValueError("accepted calibration evaluator identity mismatch")
        if not isinstance(evaluation.series, tuple) or len(evaluation.series) != 1:
            raise ValueError("accepted calibration evaluator returned wrong series cardinality")
        return evaluation

    def execute(self, input_capability: Any, quarantine_outputs: Any) -> None:
        started = time.monotonic()

        def check_deadline() -> None:
            if time.monotonic() - started >= self._operation_timeout_seconds:
                _raise_sanitized(GateBDeadlineExceeded)

        try:
            decoded = _decode_frames(input_capability, self._manifest)
            coordinates = _coordinates(decoded.batch_context)
            opponent_by_id = {item.opponent_id: item for item in decoded.opponent_configs}
            if tuple(opponent_by_id) != tuple(decoded.batch_context["coordinates"]["opponent_ids"]):
                raise ValueError("decoded opponent order mismatch")
            selected = decoded.configs[0]
            scientific = _scientific_contract(decoded, selected)
            output = _BoundedOutputs(quarantine_outputs)
            progress_sequence = 1
            log_sequence = 1
            coordinate_count = len(coordinates)
            output.json(
                "progress",
                _progress_entry(
                    sequence=progress_sequence,
                    event_type="executor_started",
                    coordinate=None,
                    coordinate_count=coordinate_count,
                    status="running",
                ),
            )
            output.json(
                "log",
                _log_entry(
                    sequence=log_sequence,
                    event_type="executor_started",
                    coordinate=None,
                    detail_code="executor_started",
                ),
            )
            results = []
            for coordinate in coordinates:
                check_deadline()
                progress_sequence += 1
                log_sequence += 1
                output.json(
                    "progress",
                    _progress_entry(
                        sequence=progress_sequence,
                        event_type="coordinate_started",
                        coordinate=coordinate,
                        coordinate_count=coordinate_count,
                        status="running",
                    ),
                )
                output.json(
                    "log",
                    _log_entry(
                        sequence=log_sequence,
                        event_type="coordinate_started",
                        coordinate=coordinate,
                        detail_code="coordinate_started",
                    ),
                )
                result = _run_coordinate(
                    decoded,
                    selected,
                    opponent_by_id[coordinate.opponent_id],
                    coordinate,
                    scientific,
                )
                if result.coordinate != coordinate:
                    raise ValueError("coordinate kernel reordered result")
                results.append(result)
                progress_sequence += 1
                log_sequence += 1
                output.json(
                    "progress",
                    _progress_entry(
                        sequence=progress_sequence,
                        event_type="coordinate_completed",
                        coordinate=coordinate,
                        coordinate_count=coordinate_count,
                        status="complete",
                    ),
                )
                output.json(
                    "log",
                    _log_entry(
                        sequence=log_sequence,
                        event_type="coordinate_completed",
                        coordinate=coordinate,
                        detail_code="coordinate_completed",
                    ),
                )
                check_deadline()
            if tuple(item.coordinate for item in results) != coordinates:
                raise ValueError("coordinate results are incomplete or reordered")
            evaluation = self._evaluate_test_calibration(
                decoded,
                selected,
                results,
                scientific,
            )
            calibration = _wire(evaluation)
            aggregate = _aggregate_from_calibration(evaluation)
            reconstructed_evaluation = self._evaluate_test_calibration(
                decoded,
                selected,
                tuple(results),
                scientific,
            )
            reconstructed_calibration = _wire(reconstructed_evaluation)
            reconstructed_aggregate = _aggregate_from_calibration(reconstructed_evaluation)
            if canonical_json_bytes(calibration) != canonical_json_bytes(
                reconstructed_calibration
            ) or canonical_json_bytes(aggregate) != canonical_json_bytes(reconstructed_aggregate):
                raise ValueError("independent calibration reconstruction mismatch")
            del reconstructed_evaluation
            coordinate_order_sha256 = sha256_bytes(
                canonical_json_bytes(
                    [
                        {
                            "opponent_id": item.opponent_id,
                            "horizon": item.horizon,
                            "repetition_id": item.repetition_id,
                            "seed": item.seed,
                        }
                        for item in coordinates
                    ]
                )
            )
            result_payload = {
                "schema_version": RESULT_SCHEMA,
                "artifact_type": "gate_b_test_result",
                "test_batch_hash": self._batch_hash,
                "execution_context_sha256": self._execution_context_sha256,
                "executor_id": self._executor_id,
                "executor_sha256": self._executor_sha256,
                "selected_config_sha256": self._manifest["selection"]["primary_config_sha256"],
                "coordinate_order_sha256": coordinate_order_sha256,
                "coordinate_count": coordinate_count,
                "session_results": [item.wire() for item in results],
                "calibration": calibration,
                "aggregate": aggregate,
                "status": "complete",
            }
            check_deadline()
            result_raw = output.json("result", result_payload)
            result_hash = sha256_bytes(result_raw)
            primary, diagnostic, gto_fpr = _metric_projection(aggregate)
            metrics_payload = {
                "schema_version": METRICS_SCHEMA,
                "artifact_type": "gate_b_test_metrics",
                "test_batch_hash": self._batch_hash,
                "executor_id": self._executor_id,
                "executor_sha256": self._executor_sha256,
                "coordinate_count": coordinate_count,
                "primary_metric": {"name": "brier", "value": primary},
                "diagnostic_metrics": {"ece": diagnostic},
                "gto_fpr": gto_fpr,
                "result_sha256": result_hash,
                "status": "complete",
            }
            check_deadline()
            metrics_raw = output.json("metrics", metrics_payload)
            metrics_hash = sha256_bytes(metrics_raw)
            check_deadline()
            progress_sequence += 1
            output.json(
                "progress",
                _progress_entry(
                    sequence=progress_sequence,
                    event_type="executor_completed",
                    coordinate=None,
                    coordinate_count=coordinate_count,
                    status="complete",
                    result_sha256=result_hash,
                    metrics_sha256=metrics_hash,
                ),
            )
            check_deadline()
            log_sequence += 1
            output.json(
                "log",
                _log_entry(
                    sequence=log_sequence,
                    event_type="executor_completed",
                    coordinate=None,
                    detail_code="executor_completed",
                ),
            )
            return None
        except GateBExecutorError:
            raise
        except Exception:
            _raise_sanitized(GateBScientificError)
