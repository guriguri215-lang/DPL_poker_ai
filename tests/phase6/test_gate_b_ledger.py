from __future__ import annotations

import gc
import json
import multiprocessing
import os
import weakref
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest

import phase6.gate_b_ledger as ledger_module
from phase6.contracts import canonical_json_bytes, sha256_bytes
from phase6.gate_b_contracts import (
    ACCESS_LOG_ENTRY_SCHEMA_VERSION,
    QUARANTINE_OUTPUT_NAMES,
    RELEASE_AUTHORIZATION_SCHEMA_VERSION,
    RETRY_AUTHORIZATION_SCHEMA_VERSION,
    GateBV2CompatibilityObject,
    _root_identity_payload,
)
from phase6.gate_b_ledger import (
    GateBLedgerError,
    GateBLedgerStore,
    GateBPinnedArtifact,
    GateBPinnedDirectory,
    GateBQuarantine,
    _append_started,
    _capability_result,
    _durable_descriptor_write,
    _load_quarantine,
    _new_record,
    _pinned_child_name,
    _platform_contract,
    _posix_flock_adapter,
    _posix_openat_adapter,
    _reserve_attempt,
    _validate_access_log_bytes,
    _validate_record_payload,
    _windows_create_file_descriptor,
    _windows_final_path_from_descriptor,
    _windows_lock_adapter,
    _windows_reject_network_volume,
    _windows_stream_names,
    _windows_unlock_adapter,
    _windows_v2_identity_from_descriptor,
    _write_exclusive,
    _write_exclusive_at,
    authorize_gate_b_release,
    authorize_gate_b_retry,
    mark_gate_b_failed_closed,
    open_gate_b_v2_pinned_directory,
    seal_gate_b_attempt,
    verify_gate_b_v2_pinned_directory,
    verify_gate_b_v2_retained_root_topology,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
APPROVAL_HASH = "d" * 64
SIGNATURE_HASH = "e" * 64
RETRY_CATALOG = {
    "fixture-environment": ("RESERVED",),
    "fixture-prestart": ("RESERVED",),
    "fixture-started-append": ("RESERVED",),
    "fixture-poststart": ("STARTED",),
    "fixture-executor": ("STARTED",),
}


class _Batch:
    test_batch_hash = HASH_A
    sha256 = HASH_A
    payload = {
        "git": {"commit_oid": "a" * 40},
        "selection": {"primary_config_id": "fixture-primary"},
        "coordinates": {"horizons": [50]},
        "governance": {
            "technical_retry_reasons": [
                {
                    "reason_id": reason_id,
                    "eligible_from_states": list(states),
                }
                for reason_id, states in RETRY_CATALOG.items()
            ],
        },
    }
    roots_independent_digests = (HASH_A, HASH_B)

    @staticmethod
    def reason_for(failure_class: str, from_state: str) -> str:
        reasons = {
            ("execution_environment_failure", "RESERVED"): "fixture-environment",
            ("test_input_prestart_failure", "RESERVED"): "fixture-prestart",
            ("started_append_failure", "RESERVED"): "fixture-started-append",
            ("test_input_poststart_failure", "STARTED"): "fixture-poststart",
            ("executor_callback_failure", "STARTED"): "fixture-executor",
        }
        return reasons[(failure_class, from_state)]


def _root_ref(path: Path, role: str, anchor_hash: str) -> dict[str, object]:
    identity = _root_identity_payload(path)
    return {
        **identity,
        "anchor_relative_path": ".gate-b-root-anchor.json",
        "anchor_sha256": anchor_hash,
        "root_role": role,
    }


def _fixture_roots(tmp_path: Path) -> tuple[Path, Path, Path]:
    base = tmp_path / "gate-b-fixture"
    test_root = base / "test-root"
    ledger_root = base / "ledger-root"
    quarantine_root = base / "quarantine-root"
    return test_root, ledger_root, quarantine_root


def _existing_request(tmp_path: Path) -> SimpleNamespace:
    _test_root, ledger, quarantine = _fixture_roots(tmp_path)
    anchor_hashes = {
        role: sha256_bytes((path / ".gate-b-root-anchor.json").read_bytes())
        for path, role in (
            (ledger, "ledger_base"),
            (quarantine, "quarantine_base"),
        )
    }
    readiness_payload = {
        "authorized_ledger_manager_actor_id": "fixture-ledger-manager",
        "authorized_ledger_manager_role": "ledger_manager",
        "designated_release_approver_id": "fixture-release-approver",
        "designated_release_approver_role": "release_approver",
        "designated_retry_approver_id": "fixture-retry-approver",
        "designated_retry_approver_role": "retry_approver",
    }
    return SimpleNamespace(
        batch=_Batch(),
        readiness=SimpleNamespace(sha256=HASH_B, payload=readiness_payload),
        execution_context=SimpleNamespace(sha256=HASH_B),
        roots={
            "ledger_base": _root_ref(ledger.resolve(), "ledger_base", anchor_hashes["ledger_base"]),
            "quarantine_base": _root_ref(
                quarantine.resolve(),
                "quarantine_base",
                anchor_hashes["quarantine_base"],
            ),
        },
        actor_id="fixture-runner",
        attempt_ordinal=1,
    )


def _request(tmp_path: Path) -> SimpleNamespace:
    test_root, ledger, quarantine = _fixture_roots(tmp_path)
    test_root.mkdir(parents=True, exist_ok=True)
    ledger.mkdir(parents=True, exist_ok=True)
    quarantine.mkdir(parents=True, exist_ok=True)
    for path, role in (
        (ledger, "ledger_base"),
        (quarantine, "quarantine_base"),
    ):
        raw = canonical_json_bytes(
            {
                "schema_version": "phase6-gate-b-root-anchor-v1",
                "artifact_type": "gate_b_root_anchor",
                "root_role": role,
                "anchor_id": f"fixture-{role}-anchor",
                "created_at_utc": "2026-07-24T00:00:00Z",
                "approval_record_sha256": APPROVAL_HASH,
            }
        )
        (path / ".gate-b-root-anchor.json").write_bytes(raw)
    return _existing_request(tmp_path)


def _reservation_worker(base: str, start_event, results) -> None:
    request = _existing_request(Path(base))
    start_event.wait()
    try:
        reservation = _reserve_attempt(request, expected_latest_record_sha256=None)
        results.put(("winner", reservation.reserved_record_sha256))
    except GateBLedgerError:
        results.put(("rejected", None))


def _write_authorization(
    store: GateBLedgerStore,
    kind: str,
    payload: dict[str, object],
    ordinal: int,
) -> tuple[Path, str]:
    raw = canonical_json_bytes(payload)
    digest = sha256_bytes(raw)
    path = store.authorization_directory / f"{kind}-attempt-{ordinal:06d}-{digest}.json"
    _write_exclusive(path, raw)
    return path, digest


def _access_log(
    request: SimpleNamespace,
    events: list[dict[str, object]],
    *,
    verified_environment: bool = True,
) -> bytes:
    previous = "0" * 64
    lines = []
    for sequence, event in enumerate(events, start=1):
        payload = {
            "schema_version": ACCESS_LOG_ENTRY_SCHEMA_VERSION,
            "artifact_type": "gate_b_test_access_log_entry",
            "event_sequence": sequence,
            "previous_entry_sha256": previous,
            "test_batch_hash": request.batch.test_batch_hash,
            "attempt_ordinal": request.attempt_ordinal,
            "actor_id": request.actor_id,
            "timestamp_utc": "2026-07-24T00:00:00Z",
            "event_type": event["event_type"],
            "execution_context_sha256": request.execution_context.sha256,
            "execution_evidence_sha256": HASH_A if verified_environment else None,
            "failure_class": event.get("failure_class"),
            "byte_count": event.get("byte_count"),
            "output_name": event.get("output_name"),
            "cumulative_input_sha256": event.get("cumulative_input_sha256"),
            "reason_id": event.get("reason_id"),
        }
        raw = canonical_json_bytes(payload)
        lines.append(raw)
        previous = sha256_bytes(raw)
    return b"".join(lines)


def _success_events() -> list[dict[str, object]]:
    return [
        {"event_type": "environment_verified"},
        {"event_type": "started_appended"},
        {"event_type": "test_input_verified"},
        {
            "event_type": "input_read",
            "byte_count": 3,
            "cumulative_input_sha256": HASH_A,
        },
        {
            "event_type": "input_eof",
            "byte_count": 0,
            "cumulative_input_sha256": HASH_B,
        },
        {"event_type": "output_write", "byte_count": 2, "output_name": "result"},
        {"event_type": "capabilities_closed"},
        {"event_type": "executor_returned"},
        {"event_type": "seal_started"},
    ]


def test_reservation_and_started_are_hash_chained_and_single_writer(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    reservation = _reserve_attempt(request, expected_latest_record_sha256=None)

    with pytest.raises(GateBLedgerError, match="trust anchor"):
        _reserve_attempt(request, expected_latest_record_sha256=None)

    store = GateBLedgerStore(request)
    with store.lock():
        started = _append_started(request, reservation, store=store)
    chain = store.load_chain()
    assert [record.to_state for record in chain] == ["RESERVED", "STARTED"]
    assert started.payload["previous_record_sha256"] == reservation.reserved_record_sha256


def test_concurrent_initial_reservation_has_exactly_one_winner(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)

    def reserve() -> str:
        try:
            return _reserve_attempt(
                request, expected_latest_record_sha256=None
            ).reserved_record_sha256
        except GateBLedgerError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _item: reserve(), range(2)))

    assert outcomes.count("rejected") == 1
    assert len([value for value in outcomes if value != "rejected"]) == 1


def test_multiprocess_reservation_barrier_has_one_winner(tmp_path: Path) -> None:
    _request(tmp_path)
    context = multiprocessing.get_context("spawn")
    start_event = context.Event()
    results = context.Queue()
    processes = [
        context.Process(
            target=_reservation_worker,
            args=(str(tmp_path), start_event, results),
        )
        for _index in range(2)
    ]
    for process in processes:
        process.start()
    start_event.set()
    outcomes = [results.get(timeout=20)[0] for _index in range(2)]
    for process in processes:
        process.join(timeout=20)
        assert process.exitcode == 0

    assert outcomes.count("winner") == 1
    assert outcomes.count("rejected") == 1


def test_chain_reopen_rehash_rejects_record_tamper(tmp_path: Path) -> None:
    request = _request(tmp_path)
    reservation = _reserve_attempt(request, expected_latest_record_sha256=None)
    store = GateBLedgerStore(request)
    with store.lock():
        _append_started(request, reservation, store=store)
    record_path = store.directory / "record-000001.json"
    raw = record_path.read_bytes()
    record_path.write_bytes(raw.replace(b"fixture-ledger-manager", b"fixture-ledger-tamper"))

    with pytest.raises(GateBLedgerError):
        store.load_chain()


def test_append_revalidates_completed_chain_before_reporting_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    reservation = _reserve_attempt(request, expected_latest_record_sha256=None)
    store = GateBLedgerStore(request)
    original_write = ledger_module._write_exclusive_at

    def write_then_tamper_previous(directory_descriptor, directory_path, name, raw):
        path = original_write(directory_descriptor, directory_path, name, raw)
        previous_path = directory_path / "record-000001.json"
        previous_raw = previous_path.read_bytes()
        tampered = previous_raw.replace(
            b"fixture-ledger-manager",
            b"fixture-ledger-managex",
        )
        assert len(tampered) == len(previous_raw)
        with previous_path.open("r+b") as handle:
            handle.seek(0)
            assert handle.write(tampered) == len(tampered)
            handle.flush()
            os.fsync(handle.fileno())
        return path

    monkeypatch.setattr(ledger_module, "_write_exclusive_at", write_then_tamper_previous)
    with store.lock(), pytest.raises(GateBLedgerError):
        _append_started(request, reservation, store=store)

    assert (store.directory / "record-000002.json").is_file()
    with pytest.raises(GateBLedgerError):
        store.load_chain()


def test_every_noncontract_ledger_transition_is_rejected(tmp_path: Path) -> None:
    request = _request(tmp_path)
    reservation = _reserve_attempt(request, expected_latest_record_sha256=None)
    previous = reservation.record
    states = {
        "UNSEEN",
        "RESERVED",
        "STARTED",
        "SEALED",
        "RELEASED",
        "FAILED_CLOSED",
        "RETRY_AUTHORIZED",
    }
    allowed = {
        ("UNSEEN", "RESERVED"),
        ("RESERVED", "STARTED"),
        ("STARTED", "SEALED"),
        ("SEALED", "RELEASED"),
        ("RESERVED", "FAILED_CLOSED"),
        ("STARTED", "FAILED_CLOSED"),
        ("FAILED_CLOSED", "RETRY_AUTHORIZED"),
        ("RETRY_AUTHORIZED", "RESERVED"),
    }
    rejected = 0
    for from_state in states:
        for to_state in states:
            if (from_state, to_state) in allowed:
                continue
            payload = dict(previous.payload)
            payload.update(
                {
                    "record_sequence": 2,
                    "previous_record_sha256": previous.record_sha256,
                    "from_state": from_state,
                    "to_state": to_state,
                }
            )
            with pytest.raises(GateBLedgerError):
                _validate_record_payload(
                    payload,
                    previous=previous,
                    expected_sequence=2,
                    expected_initial_authorization_sha256=HASH_B,
                    retry_catalog=RETRY_CATALOG,
                )
            rejected += 1
    assert rejected == len(states) ** 2 - len(allowed)


def test_ledger_cross_record_bindings_reject_hash_consistent_tamper(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    reservation = _reserve_attempt(request, expected_latest_record_sha256=None)
    store = GateBLedgerStore(request)
    with store.lock():
        started = _append_started(request, reservation, store=store)

    started_tamper = dict(started.payload)
    started_tamper["attempt_ordinal"] = 2
    with pytest.raises(GateBLedgerError, match="attempt ordinal"):
        _validate_record_payload(
            started_tamper,
            previous=reservation.record,
            expected_sequence=2,
            expected_initial_authorization_sha256=HASH_B,
            retry_catalog=RETRY_CATALOG,
        )

    sealed_payload = _new_record(
        request,
        started,
        attempt_ordinal=1,
        from_state="STARTED",
        to_state="SEALED",
        actor_id=request.actor_id,
        actor_role="test_runner",
        quarantine_manifest_sha256=HASH_A,
    )
    sealed = SimpleNamespace(
        record_sha256=sha256_bytes(canonical_json_bytes(sealed_payload)),
        record_sequence=3,
        attempt_ordinal=1,
        from_state="STARTED",
        to_state="SEALED",
        payload=sealed_payload,
    )
    released_tamper = _new_record(
        request,
        sealed,
        attempt_ordinal=1,
        from_state="SEALED",
        to_state="RELEASED",
        actor_id="fixture-release-approver",
        actor_role="release_approver",
        quarantine_manifest_sha256=HASH_B,
        authorization_record_sha256=HASH_A,
    )
    with pytest.raises(GateBLedgerError, match="sealed quarantine"):
        _validate_record_payload(
            released_tamper,
            previous=sealed,
            expected_sequence=4,
            expected_initial_authorization_sha256=HASH_B,
            retry_catalog=RETRY_CATALOG,
        )

    failed_payload = _new_record(
        request,
        reservation.record,
        attempt_ordinal=1,
        from_state="RESERVED",
        to_state="FAILED_CLOSED",
        actor_id=request.actor_id,
        actor_role="test_runner",
        reason_id="fixture-prestart",
        reason_detail_sha256=sha256_bytes(canonical_json_bytes({"reason_id": "fixture-prestart"})),
        quarantine_manifest_sha256=HASH_A,
    )
    failed = SimpleNamespace(
        record_sha256=sha256_bytes(canonical_json_bytes(failed_payload)),
        record_sequence=2,
        attempt_ordinal=1,
        from_state="RESERVED",
        to_state="FAILED_CLOSED",
        payload=failed_payload,
    )
    retry_tamper = _new_record(
        request,
        failed,
        attempt_ordinal=1,
        from_state="FAILED_CLOSED",
        to_state="RETRY_AUTHORIZED",
        actor_id="fixture-retry-approver",
        actor_role="retry_approver",
        reason_id="fixture-executor",
        quarantine_manifest_sha256=HASH_B,
        authorization_record_sha256=HASH_A,
        next_attempt_ordinal=2,
    )
    with pytest.raises(GateBLedgerError, match="failed evidence"):
        _validate_record_payload(
            retry_tamper,
            previous=failed,
            expected_sequence=3,
            expected_initial_authorization_sha256=HASH_B,
            retry_catalog=RETRY_CATALOG,
        )

    initial_tamper = dict(reservation.record.payload)
    with pytest.raises(GateBLedgerError, match="initial"):
        _validate_record_payload(
            initial_tamper,
            previous=None,
            expected_sequence=1,
            expected_initial_authorization_sha256=HASH_A,
            retry_catalog=RETRY_CATALOG,
        )


@pytest.mark.parametrize(
    "reason_id",
    ["fixture-unknown", "fixture-executor"],
)
def test_ledger_reload_rejects_unknown_or_ineligible_failure_reason(
    tmp_path: Path,
    reason_id: str,
) -> None:
    request = _request(tmp_path)
    reservation = _reserve_attempt(request, expected_latest_record_sha256=None)
    payload = _new_record(
        request,
        reservation.record,
        attempt_ordinal=1,
        from_state="RESERVED",
        to_state="FAILED_CLOSED",
        actor_id=request.actor_id,
        actor_role="test_runner",
        reason_id=reason_id,
        reason_detail_sha256=sha256_bytes(canonical_json_bytes({"reason_id": reason_id})),
        quarantine_manifest_sha256=HASH_A,
    )
    (GateBLedgerStore(request).directory / "record-000002.json").write_bytes(
        canonical_json_bytes(payload)
    )
    with pytest.raises(GateBLedgerError, match="unknown or ineligible"):
        GateBLedgerStore(request).load_chain()


def test_ledger_record_namespace_is_six_digit_bounded(tmp_path: Path) -> None:
    request = _request(tmp_path)
    reservation = _reserve_attempt(request, expected_latest_record_sha256=None)
    oversized_sequence = dict(reservation.record.payload)
    oversized_sequence["record_sequence"] = 1000000
    with pytest.raises(GateBLedgerError, match="six-digit"):
        _validate_record_payload(
            oversized_sequence,
            previous=None,
            expected_sequence=1000000,
            expected_initial_authorization_sha256=HASH_B,
            retry_catalog=RETRY_CATALOG,
        )

    oversized_request = SimpleNamespace(**vars(request))
    oversized_request.attempt_ordinal = 1000000
    with pytest.raises(GateBLedgerError, match="six-digit"):
        GateBLedgerStore(oversized_request)


def test_ledger_records_use_pinned_direct_child_io(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    reservation = _reserve_attempt(request, expected_latest_record_sha256=None)
    store = GateBLedgerStore(request)
    original_read = ledger_module._read_pinned

    def forbid_path_record_read(path: Path, label: str) -> bytes:
        if label == "Gate B ledger record":
            raise AssertionError("path-only ledger record read")
        return original_read(path, label)

    monkeypatch.setattr(ledger_module, "_read_pinned", forbid_path_record_read)
    monkeypatch.setattr(
        ledger_module,
        "_write_exclusive",
        lambda *_args: (_ for _ in ()).throw(AssertionError("path-only ledger record write")),
    )
    with store.lock():
        started = _append_started(request, reservation, store=store)
    assert started.to_state == "STARTED"
    assert GateBLedgerStore(request).load_chain()[-1].record_sha256 == started.record_sha256


def test_ledger_pinned_directory_rejects_wrong_opened_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    store = GateBLedgerStore(request)
    other = tmp_path / "gate-b-fixture" / "other-ledger"
    other.mkdir()
    other_descriptor = ledger_module._open_directory_descriptor(other)
    try:
        monkeypatch.setattr(
            ledger_module,
            "_open_directory_descriptor",
            lambda _path: os.dup(other_descriptor),
        )
        with pytest.raises(GateBLedgerError, match="pinned identity"):
            store.load_chain()
    finally:
        os.close(other_descriptor)


def test_ledger_namespace_rename_and_replacement_fail_closed(tmp_path: Path) -> None:
    request = _request(tmp_path)
    store = GateBLedgerStore(request)
    moved = store.directory.with_name("moved-ledger-namespace")
    store.directory.rename(moved)
    store.directory.mkdir()
    (store.directory / "authorizations").mkdir()
    (store.directory / ".gate-b.lock").write_bytes(b"")
    with pytest.raises(GateBLedgerError, match="identity changed"):
        store.load_chain()


def test_fresh_store_rejects_renamed_or_missing_claimed_ledger_namespace(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    store = GateBLedgerStore(request)
    moved = store.directory.with_name("moved-ledger-namespace")
    store.directory.rename(moved)

    with pytest.raises(GateBLedgerError, match="claimed Gate B namespace"):
        GateBLedgerStore(request)

    assert not store.directory.exists()
    assert moved.is_dir()


def test_fresh_store_never_recreates_missing_claimed_lock(tmp_path: Path) -> None:
    request = _request(tmp_path)
    store = GateBLedgerStore(request)
    store.lock_path.unlink()

    with pytest.raises(GateBLedgerError, match="claimed Gate B namespace lock"):
        GateBLedgerStore(request)

    assert not store.lock_path.exists()


def test_locked_descriptor_rejects_current_lock_path_identity_substitution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    store = GateBLedgerStore(request)
    original_verify = ledger_module._verify_regular
    with store.lock() as lock:

        def substituted(path: Path, label: str, *, expected_size=None):
            metadata = original_verify(path, label, expected_size=expected_size)
            if path != store.lock_path:
                return metadata
            return SimpleNamespace(
                st_mode=metadata.st_mode,
                st_nlink=metadata.st_nlink,
                st_dev=metadata.st_dev + 1,
                st_ino=metadata.st_ino + 1,
                st_size=metadata.st_size,
                st_file_attributes=getattr(metadata, "st_file_attributes", 0),
            )

        monkeypatch.setattr(ledger_module, "_verify_regular", substituted)
        with pytest.raises(GateBLedgerError, match="descriptor/path identity mismatch"):
            lock.verify_identity()


@pytest.mark.parametrize(
    "authorization_function", [authorize_gate_b_release, authorize_gate_b_retry]
)
def test_unsafe_authorization_hash_rejects_before_namespace_or_file_io(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    authorization_function,
) -> None:
    request = _request(tmp_path)
    store_constructed = False

    class ForbiddenStore:
        def __init__(self, _request):
            nonlocal store_constructed
            store_constructed = True

    monkeypatch.setattr(ledger_module, "GateBLedgerStore", ForbiddenStore)
    with pytest.raises(GateBLedgerError, match="hash") as caught:
        authorization_function(
            request,
            None,
            authorization_path=tmp_path / "must-not-open",
            expected_authorization_sha256="../outside",
            expected_approval_record_sha256=APPROVAL_HASH,
            expected_signature_record_sha256=SIGNATURE_HASH,
        )
    assert store_constructed is False
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_ledger_namespace_is_closed_world(tmp_path: Path) -> None:
    request = _request(tmp_path)
    _reserve_attempt(request, expected_latest_record_sha256=None)
    store = GateBLedgerStore(request)
    (store.directory / "unexpected.txt").write_bytes(b"x")

    with pytest.raises(GateBLedgerError, match="unexpected"):
        store.load_chain()


def test_existing_store_rereads_writable_root_anchor_before_every_operation(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    store = GateBLedgerStore(request)
    _reserve_attempt(request, expected_latest_record_sha256=None)
    ledger_root = Path(request.roots["ledger_base"]["absolute_path"])
    (ledger_root / ".gate-b-root-anchor.json").write_bytes(
        canonical_json_bytes(
            {
                "schema_version": "phase6-gate-b-root-anchor-v1",
                "artifact_type": "gate_b_root_anchor",
                "root_role": "ledger_base",
                "anchor_id": "fixture-replaced-anchor",
                "created_at_utc": "2026-07-24T00:00:00Z",
                "approval_record_sha256": APPROVAL_HASH,
            }
        )
    )
    with pytest.raises(GateBLedgerError, match="anchor"):
        store.load_chain()


def test_access_log_validates_hash_chain_lifecycle_and_post_eof_output(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    raw = _access_log(request, _success_events())
    entries = _validate_access_log_bytes(
        raw,
        test_batch_hash=request.batch.test_batch_hash,
        attempt_ordinal=1,
        actor_id=request.actor_id,
        execution_context_sha256=request.execution_context.sha256,
    )
    assert entries[-1]["event_type"] == "seal_started"
    assert entries[5]["event_type"] == "output_write"

    lines = raw.splitlines(keepends=True)
    lines[4] = lines[4].replace(b'"event_sequence":5', b'"event_sequence":6')
    with pytest.raises(GateBLedgerError):
        _validate_access_log_bytes(
            b"".join(lines),
            test_batch_hash=request.batch.test_batch_hash,
            attempt_ordinal=1,
            actor_id=request.actor_id,
            execution_context_sha256=request.execution_context.sha256,
        )


@pytest.mark.parametrize(
    ("line_index", "field", "bad_value"),
    [
        (0, "event_sequence", True),
        (3, "byte_count", True),
        (3, "output_name", "result"),
        (4, "byte_count", False),
        (4, "output_name", "result"),
    ],
)
def test_access_log_rejects_boolean_integers_and_input_output_name(
    tmp_path: Path,
    line_index: int,
    field: str,
    bad_value: object,
) -> None:
    request = _request(tmp_path)
    lines = _access_log(request, _success_events()).splitlines(keepends=True)
    payload = json.loads(lines[line_index])
    payload[field] = bad_value
    lines[line_index] = canonical_json_bytes(payload)
    with pytest.raises(GateBLedgerError):
        _validate_access_log_bytes(
            b"".join(lines),
            test_batch_hash=request.batch.test_batch_hash,
            attempt_ordinal=1,
            actor_id=request.actor_id,
            execution_context_sha256=request.execution_context.sha256,
        )


def test_quarantine_seals_manifest_last_then_ledger_seals(tmp_path: Path) -> None:
    request = _request(tmp_path)
    reservation = _reserve_attempt(request, expected_latest_record_sha256=None)
    store = GateBLedgerStore(request)
    with store.lock():
        started = _append_started(request, reservation, store=store)
    quarantine = GateBQuarantine.create(request)
    quarantine.writable_handle("result").write(b"ok")
    quarantine.access_log_handle().write(_access_log(request, _success_events()))

    manifest_path, manifest_hash = quarantine.seal(
        request, status="sealed", started_record_sha256=started.record_sha256
    )
    sealed = seal_gate_b_attempt(
        request,
        started,
        quarantine_manifest_path=manifest_path,
        expected_quarantine_manifest_sha256=manifest_hash,
    )

    assert sealed.to_state == "SEALED"
    assert manifest_path.name == "quarantine-manifest.json"
    assert {path.name for path in manifest_path.parent.iterdir()} == {
        "quarantine-manifest.json",
        "stdout.txt",
        "stderr.txt",
        "progress.jsonl",
        "metrics.json",
        "log.jsonl",
        "result.json",
        "access-log.jsonl",
    }
    assert tuple(QUARANTINE_OUTPUT_NAMES)[-1] == "access_log"


def test_quarantine_reopen_rehash_rejects_post_seal_child_swap(tmp_path: Path) -> None:
    request = _request(tmp_path)
    reservation = _reserve_attempt(request, expected_latest_record_sha256=None)
    store = GateBLedgerStore(request)
    with store.lock():
        started = _append_started(request, reservation, store=store)
    quarantine = GateBQuarantine.create(request)
    quarantine.writable_handle("result").write(b"ok")
    quarantine.access_log_handle().write(_access_log(request, _success_events()))
    manifest_path, manifest_hash = quarantine.seal(
        request,
        status="sealed",
        started_record_sha256=started.record_sha256,
    )
    (manifest_path.parent / "result.json").write_bytes(b"post-seal-swap")
    with pytest.raises(GateBLedgerError, match="changed"):
        _load_quarantine(request, manifest_path, manifest_hash)


@pytest.mark.parametrize(
    ("target_name", "read_label"),
    [
        ("result", "quarantine result"),
        ("access_log", "quarantine access log"),
    ],
)
def test_quarantine_seal_reopen_rejects_swap_after_named_identity_check(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    target_name: str,
    read_label: str,
) -> None:
    request = _request(tmp_path)
    quarantine = GateBQuarantine.create(request)
    access_raw = _access_log(request, _success_events())
    quarantine.writable_handle("result").write(b"ok")
    quarantine.access_log_handle().write(access_raw)
    replacement = tmp_path / f"replacement-{target_name}.bin"
    replacement.write_bytes(b"NO" if target_name == "result" else access_raw)
    original_read = ledger_module._read_pinned_at
    swapped = False

    def swap_before_reopen(
        directory_descriptor,
        directory_path,
        name,
        label,
        *,
        expected_identity=None,
    ):
        nonlocal swapped
        if label == read_label and not swapped:
            replacement.replace(directory_path / name)
            swapped = True
        return original_read(
            directory_descriptor,
            directory_path,
            name,
            label,
            expected_identity=expected_identity,
        )

    monkeypatch.setattr(ledger_module, "_read_pinned_at", swap_before_reopen)
    try:
        with pytest.raises(GateBLedgerError, match="identity changed"):
            quarantine.seal(
                request,
                status="sealed",
                started_record_sha256=HASH_A,
            )
    finally:
        quarantine.invalidate_partial()
    assert swapped is True
    assert not (quarantine._directory / "quarantine-manifest.json").exists()


def test_post_seal_root_replacement_cannot_append_sealed_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    reservation = _reserve_attempt(request, expected_latest_record_sha256=None)
    store = GateBLedgerStore(request)
    with store.lock():
        started = _append_started(request, reservation, store=store)
    quarantine = GateBQuarantine.create(request)
    quarantine.writable_handle("result").write(b"ok")
    quarantine.access_log_handle().write(_access_log(request, _success_events()))
    manifest_path, manifest_hash = quarantine.seal(
        request,
        status="sealed",
        started_record_sha256=started.record_sha256,
    )
    quarantine_base = Path(request.roots["quarantine_base"]["absolute_path"])
    moved = quarantine_base.with_name("quarantine-root-post-seal-moved")
    anchor_raw = (quarantine_base / ".gate-b-root-anchor.json").read_bytes()
    original_verify = ledger_module._verify_pinned_root_descriptor
    race_result = []

    def replace_after_initial_pin(ref, expected_role, descriptor):
        result = original_verify(ref, expected_role, descriptor)
        if expected_role == "quarantine_base" and not race_result:
            try:
                quarantine_base.rename(moved)
            except OSError:
                race_result.append("rename_blocked_by_pinned_handle")
                raise GateBLedgerError("fixture post-seal replacement was blocked") from None
            quarantine_base.mkdir()
            (quarantine_base / ".gate-b-root-anchor.json").write_bytes(anchor_raw)
            race_result.append("replacement_installed")
        return result

    monkeypatch.setattr(
        ledger_module,
        "_verify_pinned_root_descriptor",
        replace_after_initial_pin,
    )
    with pytest.raises(GateBLedgerError):
        seal_gate_b_attempt(
            request,
            started,
            quarantine_manifest_path=manifest_path,
            expected_quarantine_manifest_sha256=manifest_hash,
        )
    assert race_result in [
        ["rename_blocked_by_pinned_handle"],
        ["replacement_installed"],
    ]
    assert [record.to_state for record in store.load_chain()] == ["RESERVED", "STARTED"]


@pytest.mark.parametrize(
    "mutation",
    ["manifest", "result", "access_log", "extra_entry"],
)
def test_post_load_artifact_mutation_cannot_append_sealed_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: str,
) -> None:
    request = _request(tmp_path)
    reservation = _reserve_attempt(request, expected_latest_record_sha256=None)
    store = GateBLedgerStore(request)
    with store.lock():
        started = _append_started(request, reservation, store=store)
    quarantine = GateBQuarantine.create(request)
    quarantine.writable_handle("result").write(b"ok")
    quarantine.access_log_handle().write(_access_log(request, _success_events()))
    manifest_path, manifest_hash = quarantine.seal(
        request,
        status="sealed",
        started_record_sha256=started.record_sha256,
    )
    original_verify = ledger_module._PinnedQuarantineLoad.verify_identity
    verify_calls = 0

    def mutate_after_initial_load(self, loaded_request):
        nonlocal verify_calls
        verify_calls += 1
        original_verify(self, loaded_request)
        if verify_calls != 1:
            return
        if mutation == "extra_entry":
            (manifest_path.parent / "unexpected.bin").write_bytes(b"x")
            return
        target = {
            "manifest": manifest_path,
            "result": manifest_path.parent / "result.json",
            "access_log": manifest_path.parent / "access-log.jsonl",
        }[mutation]
        raw = bytearray(target.read_bytes())
        raw[len(raw) // 2] ^= 1
        target.write_bytes(raw)

    monkeypatch.setattr(
        ledger_module._PinnedQuarantineLoad,
        "verify_identity",
        mutate_after_initial_load,
    )
    with pytest.raises(GateBLedgerError, match="pinned quarantine"):
        seal_gate_b_attempt(
            request,
            started,
            quarantine_manifest_path=manifest_path,
            expected_quarantine_manifest_sha256=manifest_hash,
        )
    assert verify_calls == 2
    assert [record.to_state for record in store.load_chain()] == ["RESERVED", "STARTED"]


@pytest.mark.parametrize("next_ordinal", [1, 2])
def test_fresh_quarantine_rejects_renamed_claimed_batch_namespace_across_ordinals(
    tmp_path: Path,
    next_ordinal: int,
) -> None:
    request = _request(tmp_path)
    quarantine = GateBQuarantine.create(request)
    quarantine.invalidate_partial()
    batch_directory = quarantine._directory.parent
    moved = batch_directory.with_name("moved-quarantine-batch")
    batch_directory.rename(moved)
    next_request = SimpleNamespace(**vars(request))
    next_request.attempt_ordinal = next_ordinal

    with pytest.raises(GateBLedgerError, match="claimed Gate B namespace"):
        GateBQuarantine.create(next_request)

    assert not batch_directory.exists()
    assert moved.is_dir()


@pytest.mark.parametrize("bad_ordinal", [True, "1", 1.0, 0, -1, 1000000])
def test_quarantine_manifest_attempt_ordinal_is_exact_bounded_integer(
    tmp_path: Path,
    bad_ordinal: object,
) -> None:
    request = _request(tmp_path)
    quarantine = GateBQuarantine.create(request)
    quarantine.writable_handle("result").write(b"ok")
    quarantine.access_log_handle().write(_access_log(request, _success_events()))
    manifest_path, _manifest_hash = quarantine.seal(
        request,
        status="sealed",
        started_record_sha256=HASH_A,
    )
    manifest = json.loads(manifest_path.read_bytes())
    manifest["attempt_ordinal"] = bad_ordinal
    raw = canonical_json_bytes(manifest)
    manifest_path.write_bytes(raw)

    with pytest.raises(GateBLedgerError, match="attempt ordinal"):
        _load_quarantine(request, manifest_path, sha256_bytes(raw))


def test_prestart_failure_remains_reserved_and_binds_reason(tmp_path: Path) -> None:
    request = _request(tmp_path)
    reservation = _reserve_attempt(request, expected_latest_record_sha256=None)
    quarantine = GateBQuarantine.create(request)
    events = [
        {"event_type": "environment_verified"},
        {
            "event_type": "test_input_prestart_failed",
            "failure_class": "test_input_prestart_failure",
            "reason_id": "fixture-prestart",
        },
        {"event_type": "failure_seal_started"},
    ]
    quarantine.access_log_handle().write(_access_log(request, events))
    manifest_path, manifest_hash = quarantine.seal(
        request, status="failed_closed", started_record_sha256=None
    )
    failed = mark_gate_b_failed_closed(
        request,
        reservation,
        failure_class="test_input_prestart_failure",
        quarantine_manifest_path=manifest_path,
        expected_quarantine_manifest_sha256=manifest_hash,
    )

    assert failed.from_state == "RESERVED"
    assert failed.to_state == "FAILED_CLOSED"
    assert failed.payload["reason_id"] == "fixture-prestart"


def test_release_auth(tmp_path: Path) -> None:
    request = _request(tmp_path)
    reservation = _reserve_attempt(request, expected_latest_record_sha256=None)
    store = GateBLedgerStore(request)
    with store.lock():
        started = _append_started(request, reservation, store=store)
    quarantine = GateBQuarantine.create(request)
    quarantine.writable_handle("result").write(b"ok")
    quarantine.access_log_handle().write(_access_log(request, _success_events()))
    manifest_path, manifest_hash = quarantine.seal(
        request, status="sealed", started_record_sha256=started.record_sha256
    )
    sealed = seal_gate_b_attempt(
        request,
        started,
        quarantine_manifest_path=manifest_path,
        expected_quarantine_manifest_sha256=manifest_hash,
    )
    access_raw = (manifest_path.parent / "access-log.jsonl").read_bytes()
    authorization_path, authorization_hash = _write_authorization(
        store,
        "release",
        {
            "schema_version": RELEASE_AUTHORIZATION_SCHEMA_VERSION,
            "artifact_type": "gate_b_release_authorization",
            "authorization_id": "fixture-release-001",
            "authorized_at_utc": "2026-07-24T00:00:00Z",
            "approval_record_id": "fixture-approval-001",
            "approval_record_sha256": APPROVAL_HASH,
            "signature_record_sha256": SIGNATURE_HASH,
            "test_batch_hash": request.batch.test_batch_hash,
            "attempt_ordinal": 1,
            "sealed_record_sha256": sealed.record_sha256,
            "quarantine_manifest_sha256": manifest_hash,
            "access_log_sha256": sha256_bytes(access_raw),
            "approver_id": "fixture-release-approver",
            "approver_role": "release_approver",
            "non_disclosure_attested": True,
        },
        1,
    )
    released = authorize_gate_b_release(
        request,
        sealed,
        authorization_path=authorization_path,
        expected_authorization_sha256=authorization_hash,
        expected_approval_record_sha256=APPROVAL_HASH,
        expected_signature_record_sha256=SIGNATURE_HASH,
    )
    repeated = authorize_gate_b_release(
        request,
        sealed,
        authorization_path=authorization_path,
        expected_authorization_sha256=authorization_hash,
        expected_approval_record_sha256=APPROVAL_HASH,
        expected_signature_record_sha256=SIGNATURE_HASH,
    )

    assert released.to_state == "RELEASED"
    assert repeated.record_sha256 == released.record_sha256
    (manifest_path.parent / "stdout.txt").write_bytes(b"post-release-tamper")
    with pytest.raises(GateBLedgerError, match="changed"):
        authorize_gate_b_release(
            request,
            sealed,
            authorization_path=authorization_path,
            expected_authorization_sha256=authorization_hash,
            expected_approval_record_sha256=APPROVAL_HASH,
            expected_signature_record_sha256=SIGNATURE_HASH,
        )


def test_retry_auth(tmp_path: Path) -> None:
    request = _request(tmp_path)
    reservation = _reserve_attempt(request, expected_latest_record_sha256=None)
    quarantine = GateBQuarantine.create(request)
    events = [
        {"event_type": "environment_verified"},
        {
            "event_type": "test_input_prestart_failed",
            "failure_class": "test_input_prestart_failure",
            "reason_id": "fixture-prestart",
        },
        {"event_type": "failure_seal_started"},
    ]
    quarantine.access_log_handle().write(_access_log(request, events))
    manifest_path, manifest_hash = quarantine.seal(
        request, status="failed_closed", started_record_sha256=None
    )
    failed = mark_gate_b_failed_closed(
        request,
        reservation,
        failure_class="test_input_prestart_failure",
        quarantine_manifest_path=manifest_path,
        expected_quarantine_manifest_sha256=manifest_hash,
    )
    store = GateBLedgerStore(request)
    access_raw = (manifest_path.parent / "access-log.jsonl").read_bytes()
    authorization_path, authorization_hash = _write_authorization(
        store,
        "retry",
        {
            "schema_version": RETRY_AUTHORIZATION_SCHEMA_VERSION,
            "artifact_type": "gate_b_retry_authorization",
            "authorization_id": "fixture-retry-001",
            "authorized_at_utc": "2026-07-24T00:00:00Z",
            "approval_record_id": "fixture-approval-001",
            "approval_record_sha256": APPROVAL_HASH,
            "signature_record_sha256": SIGNATURE_HASH,
            "test_batch_hash": request.batch.test_batch_hash,
            "failed_record_sha256": failed.record_sha256,
            "failed_attempt_ordinal": 1,
            "quarantine_manifest_sha256": manifest_hash,
            "access_log_sha256": sha256_bytes(access_raw),
            "non_disclosure_attested": True,
            "disclosure_event_detected": False,
            "technical_reason_id": "fixture-prestart",
            "approver_id": "fixture-retry-approver",
            "approver_role": "retry_approver",
            "failed_runner_actor_id": request.actor_id,
            "next_attempt_ordinal": 2,
            "unchanged_implementation_commit": "a" * 40,
            "unchanged_batch_manifest_sha256": request.batch.sha256,
            "unchanged_selection_sha256": HASH_A,
            "unchanged_coordinates_sha256": HASH_B,
        },
        1,
    )
    retry = authorize_gate_b_retry(
        request,
        failed,
        authorization_path=authorization_path,
        expected_authorization_sha256=authorization_hash,
        expected_approval_record_sha256=APPROVAL_HASH,
        expected_signature_record_sha256=SIGNATURE_HASH,
    )
    repeated = authorize_gate_b_retry(
        request,
        failed,
        authorization_path=authorization_path,
        expected_authorization_sha256=authorization_hash,
        expected_approval_record_sha256=APPROVAL_HASH,
        expected_signature_record_sha256=SIGNATURE_HASH,
    )
    (manifest_path.parent / "stderr.txt").write_bytes(b"post-retry-tamper")
    with pytest.raises(GateBLedgerError, match="changed"):
        authorize_gate_b_retry(
            request,
            failed,
            authorization_path=authorization_path,
            expected_authorization_sha256=authorization_hash,
            expected_approval_record_sha256=APPROVAL_HASH,
            expected_signature_record_sha256=SIGNATURE_HASH,
        )
    next_request = SimpleNamespace(**vars(request))
    next_request.attempt_ordinal = 2
    next_reservation = _reserve_attempt(
        next_request, expected_latest_record_sha256=retry.record_sha256
    )

    assert retry.to_state == "RETRY_AUTHORIZED"
    assert repeated.record_sha256 == retry.record_sha256
    assert next_reservation.attempt_ordinal == 2


def _release_authorization_case(tmp_path: Path):
    request = _request(tmp_path)
    reservation = _reserve_attempt(request, expected_latest_record_sha256=None)
    store = GateBLedgerStore(request)
    with store.lock():
        started = _append_started(request, reservation, store=store)
    quarantine = GateBQuarantine.create(request)
    quarantine.writable_handle("result").write(b"ok")
    quarantine.access_log_handle().write(_access_log(request, _success_events()))
    manifest_path, manifest_hash = quarantine.seal(
        request,
        status="sealed",
        started_record_sha256=started.record_sha256,
    )
    sealed = seal_gate_b_attempt(
        request,
        started,
        quarantine_manifest_path=manifest_path,
        expected_quarantine_manifest_sha256=manifest_hash,
    )
    access_raw = (manifest_path.parent / "access-log.jsonl").read_bytes()
    payload = {
        "schema_version": RELEASE_AUTHORIZATION_SCHEMA_VERSION,
        "artifact_type": "gate_b_release_authorization",
        "authorization_id": "fixture-release-matrix",
        "authorized_at_utc": "2026-07-24T00:00:00Z",
        "approval_record_id": "fixture-approval-001",
        "approval_record_sha256": APPROVAL_HASH,
        "signature_record_sha256": SIGNATURE_HASH,
        "test_batch_hash": request.batch.test_batch_hash,
        "attempt_ordinal": 1,
        "sealed_record_sha256": sealed.record_sha256,
        "quarantine_manifest_sha256": manifest_hash,
        "access_log_sha256": sha256_bytes(access_raw),
        "approver_id": "fixture-release-approver",
        "approver_role": "release_approver",
        "non_disclosure_attested": True,
    }
    return request, sealed, store, payload


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("test_batch_hash", HASH_B),
        ("attempt_ordinal", 2),
        ("sealed_record_sha256", HASH_B),
        ("quarantine_manifest_sha256", HASH_B),
        ("access_log_sha256", HASH_B),
        ("approver_id", "fixture-other-approver"),
        ("approver_role", "retry_approver"),
        ("non_disclosure_attested", False),
    ],
)
def test_release_authorization_wrong_binding_matrix(
    tmp_path: Path,
    field: str,
    bad_value: object,
) -> None:
    request, sealed, store, payload = _release_authorization_case(tmp_path)
    payload[field] = bad_value
    path, digest = _write_authorization(store, "release", payload, 1)
    with pytest.raises(GateBLedgerError):
        authorize_gate_b_release(
            request,
            sealed,
            authorization_path=path,
            expected_authorization_sha256=digest,
            expected_approval_record_sha256=APPROVAL_HASH,
            expected_signature_record_sha256=SIGNATURE_HASH,
        )


def _retry_authorization_case(tmp_path: Path):
    request = _request(tmp_path)
    reservation = _reserve_attempt(request, expected_latest_record_sha256=None)
    quarantine = GateBQuarantine.create(request)
    events = [
        {"event_type": "environment_verified"},
        {
            "event_type": "test_input_prestart_failed",
            "failure_class": "test_input_prestart_failure",
            "reason_id": "fixture-prestart",
        },
        {"event_type": "failure_seal_started"},
    ]
    quarantine.access_log_handle().write(_access_log(request, events))
    manifest_path, manifest_hash = quarantine.seal(
        request,
        status="failed_closed",
        started_record_sha256=None,
    )
    failed = mark_gate_b_failed_closed(
        request,
        reservation,
        failure_class="test_input_prestart_failure",
        quarantine_manifest_path=manifest_path,
        expected_quarantine_manifest_sha256=manifest_hash,
    )
    store = GateBLedgerStore(request)
    access_raw = (manifest_path.parent / "access-log.jsonl").read_bytes()
    payload = {
        "schema_version": RETRY_AUTHORIZATION_SCHEMA_VERSION,
        "artifact_type": "gate_b_retry_authorization",
        "authorization_id": "fixture-retry-matrix",
        "authorized_at_utc": "2026-07-24T00:00:00Z",
        "approval_record_id": "fixture-approval-001",
        "approval_record_sha256": APPROVAL_HASH,
        "signature_record_sha256": SIGNATURE_HASH,
        "test_batch_hash": request.batch.test_batch_hash,
        "failed_record_sha256": failed.record_sha256,
        "failed_attempt_ordinal": 1,
        "quarantine_manifest_sha256": manifest_hash,
        "access_log_sha256": sha256_bytes(access_raw),
        "non_disclosure_attested": True,
        "disclosure_event_detected": False,
        "technical_reason_id": "fixture-prestart",
        "approver_id": "fixture-retry-approver",
        "approver_role": "retry_approver",
        "failed_runner_actor_id": request.actor_id,
        "next_attempt_ordinal": 2,
        "unchanged_implementation_commit": "a" * 40,
        "unchanged_batch_manifest_sha256": request.batch.sha256,
        "unchanged_selection_sha256": HASH_A,
        "unchanged_coordinates_sha256": HASH_B,
    }
    return request, failed, store, payload


def test_retry_rejoins_hash_consistent_failed_reason_to_access_log(
    tmp_path: Path,
) -> None:
    request, failed, store, payload = _retry_authorization_case(tmp_path)
    record_payload = json.loads(failed._raw.decode("utf-8"))
    record_payload["reason_id"] = "fixture-environment"
    record_payload["reason_detail_sha256"] = sha256_bytes(
        canonical_json_bytes({"reason_id": "fixture-environment"})
    )
    failed._path.write_bytes(canonical_json_bytes(record_payload))
    tampered_failed = store.load_chain()[-1]
    payload["failed_record_sha256"] = tampered_failed.record_sha256
    payload["technical_reason_id"] = "fixture-environment"
    path, digest = _write_authorization(store, "retry", payload, 1)

    with pytest.raises(GateBLedgerError, match="access-log failure evidence disagree"):
        authorize_gate_b_retry(
            request,
            tampered_failed,
            authorization_path=path,
            expected_authorization_sha256=digest,
            expected_approval_record_sha256=APPROVAL_HASH,
            expected_signature_record_sha256=SIGNATURE_HASH,
        )


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("test_batch_hash", HASH_B),
        ("failed_record_sha256", HASH_B),
        ("failed_attempt_ordinal", 2),
        ("quarantine_manifest_sha256", HASH_B),
        ("access_log_sha256", HASH_B),
        ("disclosure_event_detected", True),
        ("technical_reason_id", "fixture-executor"),
        ("approver_id", "fixture-other-approver"),
        ("approver_role", "release_approver"),
        ("failed_runner_actor_id", "fixture-other-runner"),
        ("next_attempt_ordinal", 3),
        ("unchanged_implementation_commit", "b" * 40),
        ("unchanged_batch_manifest_sha256", HASH_B),
        ("unchanged_selection_sha256", HASH_B),
        ("unchanged_coordinates_sha256", HASH_A),
    ],
)
def test_retry_authorization_wrong_binding_matrix(
    tmp_path: Path,
    field: str,
    bad_value: object,
) -> None:
    request, failed, store, payload = _retry_authorization_case(tmp_path)
    payload[field] = bad_value
    path, digest = _write_authorization(store, "retry", payload, 1)
    with pytest.raises(GateBLedgerError):
        authorize_gate_b_retry(
            request,
            failed,
            authorization_path=path,
            expected_authorization_sha256=digest,
            expected_approval_record_sha256=APPROVAL_HASH,
            expected_signature_record_sha256=SIGNATURE_HASH,
        )


def test_different_retry_authorization_is_not_idempotent(tmp_path: Path) -> None:
    request, failed, store, payload = _retry_authorization_case(tmp_path)
    first_path, first_hash = _write_authorization(store, "retry", payload, 1)
    authorize_gate_b_retry(
        request,
        failed,
        authorization_path=first_path,
        expected_authorization_sha256=first_hash,
        expected_approval_record_sha256=APPROVAL_HASH,
        expected_signature_record_sha256=SIGNATURE_HASH,
    )
    payload["authorization_id"] = "fixture-retry-different"
    second_path, second_hash = _write_authorization(store, "retry", payload, 1)
    with pytest.raises(GateBLedgerError, match="stale or already transitioned"):
        authorize_gate_b_retry(
            request,
            failed,
            authorization_path=second_path,
            expected_authorization_sha256=second_hash,
            expected_approval_record_sha256=APPROVAL_HASH,
            expected_signature_record_sha256=SIGNATURE_HASH,
        )


@pytest.mark.parametrize(
    ("platform_name", "regular", "lock", "parent"),
    [
        (
            "posix",
            "openat+O_NOFOLLOW",
            "flock(LOCK_EX)",
            "fsync(parent-directory)",
        ),
        (
            "nt",
            "CreateFileW(FILE_FLAG_OPEN_REPARSE_POINT)",
            "LockFileEx(LOCKFILE_EXCLUSIVE_LOCK)",
            "pinned-parent-name-identity-verification",
        ),
    ],
)
def test_posix_and_windows_adapter_contracts_are_nonoptional(
    platform_name: str, regular: str, lock: str, parent: str
) -> None:
    contract = _platform_contract(platform_name)
    assert contract.regular_open_primitive == regular
    assert contract.lock_primitive == lock
    assert contract.parent_durability_primitive == parent
    assert contract.file_flush_primitive in {"fsync(file)", "FlushFileBuffers"}
    assert (
        _capability_result(applicable=False, supported=True, privileged=True)
        == "platform_not_applicable"
    )
    assert (
        _capability_result(applicable=True, supported=False, privileged=True)
        == "unsupported_by_host_fs"
    )
    assert (
        _capability_result(applicable=True, supported=True, privileged=False)
        == "insufficient_privilege"
    )
    with pytest.raises(GateBLedgerError, match="unsupported platform"):
        _platform_contract("unknown")


def test_host_lock_and_durability_primitives_fail_closed_or_are_present(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request = _request(tmp_path)
    if os.name == "nt":
        assert hasattr(__import__("ctypes"), "WinDLL")
    else:
        assert getattr(os, "O_NOFOLLOW", None) is not None
        assert getattr(os, "O_DIRECTORY", None) is not None
        import fcntl

        assert fcntl.LOCK_EX

    monkeypatch.setattr(os, "fsync", lambda _descriptor: (_ for _ in ()).throw(OSError()))
    with pytest.raises((GateBLedgerError, OSError)):
        _reserve_attempt(request, expected_latest_record_sha256=None)


def test_fake_posix_adapters_enforce_flags_lock_and_flush_order() -> None:
    calls = []

    def fake_open(name, flags, mode, *, dir_fd):
        calls.append(("openat", name, flags, mode, dir_fd))
        return 41

    descriptor = _posix_openat_adapter(
        fake_open,
        "fixture.json",
        os.O_RDONLY,
        0o600,
        17,
        nofollow_flag=0x20000,
    )
    assert descriptor == 41
    assert calls == [("openat", "fixture.json", os.O_RDONLY | 0x20000, 0o600, 17)]
    for unavailable in (-1, 0, False):
        with pytest.raises(GateBLedgerError, match="O_NOFOLLOW"):
            _posix_openat_adapter(
                fake_open,
                "fixture.json",
                os.O_RDONLY,
                0o600,
                17,
                nofollow_flag=unavailable,
            )

    _posix_flock_adapter(
        lambda fd, operation: calls.append(("flock", fd, operation)),
        17,
        0x02,
    )
    assert calls[-1] == ("flock", 17, 0x02)

    durable = []
    _durable_descriptor_write(
        23,
        b"fixture",
        write_all_function=lambda fd, raw: durable.append(("write_all", fd, raw)),
        flush_function=lambda fd: durable.append(("flush", fd)),
    )
    assert durable == [("write_all", 23, b"fixture"), ("flush", 23)]


@pytest.mark.parametrize("unavailable", [-1, 0, False])
def test_ledger_operational_pinned_read_rejects_unavailable_nofollow(
    monkeypatch: pytest.MonkeyPatch,
    unavailable: object,
) -> None:
    class FakePosixOs:
        name = "posix"
        O_NOFOLLOW = unavailable
        O_RDONLY = 0

        def __init__(self) -> None:
            self.open_calls = []
            self.stat_calls = []
            self.supports_dir_fd = {self.open, self.stat}

        def open(self, *args, **kwargs):
            self.open_calls.append((args, kwargs))
            raise AssertionError("open must not run without O_NOFOLLOW")

        def stat(self, *args, **kwargs):
            self.stat_calls.append((args, kwargs))
            raise AssertionError("stat must not run without O_NOFOLLOW")

    fake_os = FakePosixOs()
    monkeypatch.setattr(ledger_module, "os", fake_os)
    with pytest.raises(GateBLedgerError, match="O_NOFOLLOW"):
        ledger_module._read_pinned_at(17, Path("/fixture"), "artifact.json", "artifact")
    assert fake_os.open_calls == []
    assert fake_os.stat_calls == []


@pytest.mark.parametrize(
    ("directory_flag", "nofollow_flag", "expected"),
    [
        (-1, 0x20000, "O_DIRECTORY"),
        (0, 0x20000, "O_DIRECTORY"),
        (False, 0x20000, "O_DIRECTORY"),
        (0x10000, -1, "O_NOFOLLOW"),
        (0x10000, 0, "O_NOFOLLOW"),
        (0x10000, False, "O_NOFOLLOW"),
    ],
)
def test_ledger_operational_directory_open_rejects_unavailable_required_flags(
    monkeypatch: pytest.MonkeyPatch,
    directory_flag: object,
    nofollow_flag: object,
    expected: str,
) -> None:
    class FakePosixOs:
        name = "posix"
        O_DIRECTORY = directory_flag
        O_NOFOLLOW = nofollow_flag
        O_RDONLY = 0

        def __init__(self) -> None:
            self.open_calls = []
            self.supports_dir_fd = {self.open}

        def open(self, *args, **kwargs):
            self.open_calls.append((args, kwargs))
            raise AssertionError("open must not run without required POSIX flags")

    fake_os = FakePosixOs()
    monkeypatch.setattr(ledger_module, "os", fake_os)
    with pytest.raises(GateBLedgerError, match=expected):
        ledger_module._posix_open_directory(Path("/fixture"))
    assert fake_os.open_calls == []


def test_posix_pinned_child_rechecks_single_link_topology_after_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = SimpleNamespace(
        st_mode=0o100000,
        st_nlink=1,
        st_dev=7,
        st_ino=11,
        st_size=2,
        st_file_attributes=0,
    )
    after = SimpleNamespace(
        st_mode=0o100000,
        st_nlink=2,
        st_dev=7,
        st_ino=11,
        st_size=2,
        st_file_attributes=0,
    )

    class FakePosixOs:
        name = "posix"
        O_NOFOLLOW = 0x20000
        O_RDONLY = 0

        def __init__(self) -> None:
            self.stat_calls = 0
            self.read_calls = 0
            self.closed = []
            self.supports_dir_fd = {self.open, self.stat}

        def stat(self, *_args, **_kwargs):
            self.stat_calls += 1
            return before if self.stat_calls == 1 else after

        def open(self, *_args, **_kwargs):
            return 31

        def fstat(self, _descriptor):
            return before

        def read(self, _descriptor, _size):
            self.read_calls += 1
            return b"ok" if self.read_calls == 1 else b""

        def close(self, descriptor):
            self.closed.append(descriptor)

    fake_os = FakePosixOs()
    monkeypatch.setattr(ledger_module, "os", fake_os)
    with pytest.raises(GateBLedgerError, match="topology changed"):
        ledger_module._read_pinned_at(17, Path("/fixture"), "artifact.json", "artifact")
    assert fake_os.closed == [31]


@pytest.mark.parametrize("platform_name", ["posix", "nt"])
def test_exclusive_write_fake_orders_file_flush_close_and_parent_durability(
    monkeypatch: pytest.MonkeyPatch,
    platform_name: str,
) -> None:
    events = []
    fake_os = SimpleNamespace(
        name=platform_name,
        close=lambda descriptor: events.append(("close", descriptor)),
        fsync=lambda descriptor: events.append(("parent_fsync", descriptor)),
    )
    monkeypatch.setattr(ledger_module, "os", fake_os)
    monkeypatch.setattr(
        ledger_module,
        "_open_new_at",
        lambda *_args: events.append("open") or 31,
    )
    monkeypatch.setattr(
        ledger_module,
        "_durable_descriptor_write",
        lambda descriptor, raw: events.append(("write_flush", descriptor, raw)),
    )
    monkeypatch.setattr(
        ledger_module,
        "_read_pinned_at",
        lambda *_args: events.append("reopen_rehash") or b"fixture",
    )
    if platform_name == "nt":
        identity = SimpleNamespace(st_dev=7, st_ino=11)
        monkeypatch.setattr(
            ledger_module,
            "_verify_directory",
            lambda *_args: events.append("parent_verify") or identity,
        )
        fake_os.fstat = lambda _descriptor: identity
    _write_exclusive_at(17, Path("C:/fixture"), "artifact.json", b"fixture")
    assert events[:3] == ["open", ("write_flush", 31, b"fixture"), ("close", 31)]
    if platform_name == "posix":
        assert events[3:] == [("parent_fsync", 17), "reopen_rehash"]
    else:
        assert events[3:] == ["parent_verify", "reopen_rehash"]


def test_fake_windows_adapters_enforce_create_lock_stream_and_identity_flags() -> None:
    calls = []

    class FakeFunction:
        def __init__(self, callback):
            self.callback = callback
            self.argtypes = None
            self.restype = None

        def __call__(self, *args):
            return self.callback(*args)

    class FakeKernel:
        def __init__(self):
            self.CreateFileW = FakeFunction(self._create)
            self.CloseHandle = FakeFunction(lambda handle: calls.append(("close", handle.value)))
            self.FindFirstStreamW = FakeFunction(self._find_first)
            self.FindNextStreamW = FakeFunction(lambda _handle, _data: 0)
            self.FindClose = FakeFunction(lambda handle: calls.append(("find_close", handle)))

        @staticmethod
        def _create(path, access, share, _security, creation, attributes, _template):
            calls.append(("create", path, access, share, creation, attributes))
            return 1234

        @staticmethod
        def _find_first(path, _level, data_pointer, _flags):
            calls.append(("find_first", path))
            data_pointer._obj.cStreamName = "::$DATA"
            return 99

    kernel = FakeKernel()
    converted = []
    descriptor = _windows_create_file_descriptor(
        Path("C:/fixture/directory"),
        access=0x80000000,
        creation=3,
        share=3,
        directory=True,
        _kernel32=kernel,
        _open_osfhandle=lambda handle, flags: converted.append((handle, flags)) or 51,
    )
    assert descriptor == 51
    create = next(call for call in calls if call[0] == "create")
    assert create[2:5] == (0x80000000, 3, 3)
    assert create[5] & 0x00200000
    assert create[5] & 0x02000000
    assert converted[0][0] == 1234

    lock_calls = []
    assert _windows_lock_adapter(
        lambda *args: lock_calls.append(args) or 1,
        71,
        "overlapped",
    )
    assert lock_calls[0][0].value == 71
    assert lock_calls[0][1:5] == (0x00000002, 0, 1, 0)
    assert _windows_unlock_adapter(
        lambda *args: lock_calls.append(args) or 1,
        71,
        "overlapped",
    )
    assert lock_calls[1][0].value == 71
    assert lock_calls[1][1:4] == (0, 1, 0)

    assert _windows_stream_names(
        Path("C:/fixture/file.json"),
        _kernel32=kernel,
        _get_last_error=lambda: 38,
    ) == ("::$DATA",)
    assert any(call[0] == "find_first" for call in calls)
    assert any(call[0] == "find_close" for call in calls)


def test_fake_platform_negative_paths_fail_closed_and_sanitize(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class FakeFunction:
        def __init__(self, callback):
            self.callback = callback
            self.argtypes = None
            self.restype = None

        def __call__(self, *args):
            return self.callback(*args)

    closed = []
    invalid_kernel = SimpleNamespace(
        CreateFileW=FakeFunction(lambda *_args: None),
        CloseHandle=FakeFunction(lambda handle: closed.append(handle)),
    )
    monkeypatch.setattr(ledger_module.ctypes, "get_last_error", lambda: 5, raising=False)
    with pytest.raises(OSError):
        _windows_create_file_descriptor(
            Path("C:/fixture/file.json"),
            access=0x80000000,
            creation=3,
            share=1,
            _kernel32=invalid_kernel,
            _open_osfhandle=lambda *_args: 1,
        )

    close_kernel = SimpleNamespace(
        CreateFileW=FakeFunction(lambda *_args: 123),
        CloseHandle=FakeFunction(lambda handle: closed.append(handle.value)),
    )
    with pytest.raises(RuntimeError, match="conversion"):
        _windows_create_file_descriptor(
            Path("C:/fixture/file.json"),
            access=0x80000000,
            creation=3,
            share=1,
            _kernel32=close_kernel,
            _open_osfhandle=lambda *_args: (_ for _ in ()).throw(RuntimeError("conversion")),
        )
    assert 123 in closed
    assert not _windows_lock_adapter(lambda *_args: 0, 71, "overlapped")
    assert not _windows_unlock_adapter(lambda *_args: 0, 71, "overlapped")

    stream_closed = []
    stream_kernel = SimpleNamespace(
        FindFirstStreamW=FakeFunction(lambda *_args: None),
        FindNextStreamW=FakeFunction(lambda *_args: 0),
        FindClose=FakeFunction(lambda handle: stream_closed.append(handle)),
    )
    with pytest.raises(GateBLedgerError, match="stream enumeration"):
        _windows_stream_names(
            Path("C:/fixture/file.json"),
            _kernel32=stream_kernel,
            _get_last_error=lambda: 5,
        )

    events = []
    fake_os = SimpleNamespace(
        name="nt",
        close=lambda descriptor: events.append(("close", descriptor)),
        fstat=lambda _descriptor: SimpleNamespace(st_dev=1, st_ino=1),
    )
    monkeypatch.setattr(ledger_module, "os", fake_os)
    monkeypatch.setattr(ledger_module, "_open_new_at", lambda *_args: 31)
    monkeypatch.setattr(ledger_module, "_durable_descriptor_write", lambda *_args: None)
    monkeypatch.setattr(
        ledger_module,
        "_verify_directory",
        lambda *_args: SimpleNamespace(st_dev=2, st_ino=2),
    )
    with pytest.raises(GateBLedgerError, match="parent identity"):
        _write_exclusive_at(17, Path("C:/fixture"), "artifact.json", b"fixture")

    request = _request(tmp_path)
    monkeypatch.setattr(
        ledger_module,
        "GateBLedgerStore",
        lambda _request: (_ for _ in ()).throw(OSError("fixture-secret-platform-path")),
    )
    with pytest.raises(GateBLedgerError) as caught:
        authorize_gate_b_retry(
            request,
            SimpleNamespace(attempt_ordinal=1),
            authorization_path=Path("C:/fixture/retry.json"),
            expected_authorization_sha256=HASH_A,
            expected_approval_record_sha256=APPROVAL_HASH,
            expected_signature_record_sha256=SIGNATURE_HASH,
        )
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "fixture-secret-platform-path" not in str(caught.value)


def _directory_identity(path: Path) -> tuple[str, str]:
    metadata = path.stat()
    return format(metadata.st_dev, "x"), format(metadata.st_ino, "x")


def test_host_pinned_directory_create_read_list_and_close(tmp_path: Path) -> None:
    parent = tmp_path / "pinned-host-integration"
    parent.mkdir()
    volume_id, file_id = _directory_identity(parent)
    raw = b'{"fixture":"pinned"}\n'

    pinned = GateBPinnedDirectory.open(
        parent,
        expected_volume_id_hex=volume_id,
        expected_file_id_hex=file_id,
    )
    with pinned:
        created = pinned.create_regular("approval.json", raw)
        assert created.raw == raw
        assert created.sha256 == sha256_bytes(raw)
        assert created.size_bytes == len(raw)
        assert created.physical_identity == (
            created.volume_id_hex,
            created.file_id_hex,
        )
        loaded = pinned.read_regular(
            "approval.json",
            expected_sha256=sha256_bytes(raw),
            expected_size_bytes=len(raw),
        )
        assert loaded == created
        assert pinned.direct_child_names() == ("approval.json",)
        pinned.verify_identity()
        with pytest.raises(GateBLedgerError):
            pinned.create_regular("approval.json", raw)
    pinned.close()
    for operation in (
        lambda: pinned.verify_identity(),
        lambda: pinned.direct_child_names(),
        lambda: pinned.read_regular(
            "approval.json",
            expected_sha256=sha256_bytes(raw),
            expected_size_bytes=len(raw),
        ),
        lambda: pinned.create_regular("other.json", raw),
    ):
        with pytest.raises(GateBLedgerError, match="closed"):
            operation()
    with pytest.raises(TypeError):
        GateBPinnedArtifact()
    forged = object.__new__(GateBPinnedArtifact)
    for name in (
        "_raw",
        "_sha256",
        "_size_bytes",
        "_volume_id_hex",
        "_file_id_hex",
        "_loader_token",
    ):
        object.__setattr__(forged, name, getattr(created, name))
    with pytest.raises(GateBLedgerError, match="provenance"):
        _ = forged.raw
    with pytest.raises(GateBLedgerError, match="provenance"):
        _ = forged == created
    object.__setattr__(created, "_raw", b"retained-mutation")
    with pytest.raises(GateBLedgerError, match="provenance"):
        _ = created.sha256


def test_pinned_artifact_rejects_coordinated_raw_hash_and_size_mutation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "coordinated-artifact.json"
    raw = b'{"fixture":"original"}\n'
    path.write_bytes(raw)
    artifact = ledger_module._new_pinned_artifact(raw, path.stat())
    replacement = b'{"fixture":"replacement"}\n'
    object.__setattr__(artifact, "_raw", replacement)
    object.__setattr__(artifact, "_sha256", sha256_bytes(replacement))
    object.__setattr__(artifact, "_size_bytes", len(replacement))

    with pytest.raises(GateBLedgerError, match="provenance"):
        _ = artifact.raw


@pytest.mark.parametrize("field", ["_volume_id_hex", "_file_id_hex"])
def test_pinned_artifact_rejects_physical_identity_mutation(
    tmp_path: Path,
    field: str,
) -> None:
    path = tmp_path / "identity-artifact.json"
    raw = b'{"fixture":"identity"}\n'
    path.write_bytes(raw)
    artifact = ledger_module._new_pinned_artifact(raw, path.stat())
    original = object.__getattribute__(artifact, field)
    object.__setattr__(artifact, field, "1" if original != "1" else "2")

    with pytest.raises(GateBLedgerError, match="provenance"):
        _ = artifact.physical_identity


def test_pinned_artifact_registry_is_weak_and_retains_no_raw_bytes(tmp_path: Path) -> None:
    path = tmp_path / "weak-artifact.json"
    raw = b'{"fixture":"weak"}\n'
    path.write_bytes(raw)
    artifact = ledger_module._new_pinned_artifact(raw, path.stat())
    artifact_id = id(artifact)
    retained = weakref.ref(artifact)
    registration = ledger_module._PINNED_ARTIFACT_REGISTRY[artifact_id]
    assert registration[0]() is artifact
    assert registration[1] == (
        raw,
        sha256_bytes(raw),
        len(raw),
        *artifact.physical_identity,
    )
    del artifact
    gc.collect()
    assert retained() is None
    assert artifact_id not in ledger_module._PINNED_ARTIFACT_REGISTRY


@pytest.mark.parametrize(
    "name",
    [
        "",
        ".",
        "..",
        "a/b",
        "a\\b",
        "a:b",
        "a*",
        "a?",
        "a<",
        "a>",
        'a"',
        "a|",
        "a.",
        "a ",
        "CON",
        "con.json",
        "PRN.txt",
        "AUX",
        "NUL.bin",
        "COM1",
        "com9.txt",
        "LPT1",
        "lpt9.txt",
        "\x1f",
        "\x7f",
        "non-ascii-\u00e9",
        "a" * 256,
    ],
)
def test_pinned_child_name_rejects_aliases_and_devices(name: str) -> None:
    with pytest.raises(GateBLedgerError):
        _pinned_child_name(name)


def test_pinned_directory_rejects_wrong_target_identity(tmp_path: Path) -> None:
    parent = tmp_path / "wrong-identity"
    parent.mkdir()
    volume_id, file_id = _directory_identity(parent)
    wrong_volume = "1" if volume_id != "1" else "2"
    wrong_file = "1" if file_id != "1" else "2"
    with pytest.raises(GateBLedgerError, match="identity"):
        GateBPinnedDirectory.open(
            parent,
            expected_volume_id_hex=wrong_volume,
            expected_file_id_hex=file_id,
        )
    with pytest.raises(GateBLedgerError, match="identity"):
        GateBPinnedDirectory.open(
            parent,
            expected_volume_id_hex=volume_id,
            expected_file_id_hex=wrong_file,
        )
    with pytest.raises(GateBLedgerError):
        GateBPinnedDirectory.open(parent)  # type: ignore[call-arg]


def test_pinned_directory_parent_swap_is_blocked_or_stays_on_pinned_parent(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "pinned-parent"
    moved = tmp_path / "moved-parent"
    replacement = tmp_path / "replacement-parent"
    parent.mkdir()
    replacement.mkdir()
    volume_id, file_id = _directory_identity(parent)
    pinned = GateBPinnedDirectory.open(
        parent,
        expected_volume_id_hex=volume_id,
        expected_file_id_hex=file_id,
    )
    try:
        renamed = False
        try:
            os.rename(parent, moved)
            renamed = True
        except OSError:
            pass
        if renamed:
            os.rename(replacement, parent)
            try:
                artifact = pinned.create_regular("pinned.json", b"pinned\n")
            except GateBLedgerError:
                artifact = None
            assert not (parent / "pinned.json").exists()
            if artifact is not None:
                assert artifact.raw == b"pinned\n"
                assert (moved / "pinned.json").read_bytes() == b"pinned\n"
        else:
            artifact = pinned.create_regular("pinned.json", b"pinned\n")
            assert artifact.raw == b"pinned\n"
            assert (parent / "pinned.json").read_bytes() == b"pinned\n"
    finally:
        pinned.close()


def test_pinned_directory_rejects_hardlink_or_alternate_stream(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "pinned-alias"
    parent.mkdir()
    target = parent / "record.json"
    raw = b"fixture\n"
    target.write_bytes(raw)
    if os.name == "nt":
        (parent / "record.json:fixture-stream").write_bytes(b"alias")
    else:
        os.link(target, parent / "record-alias.json")
    volume_id, file_id = _directory_identity(parent)
    with (
        GateBPinnedDirectory.open(
            parent,
            expected_volume_id_hex=volume_id,
            expected_file_id_hex=file_id,
        ) as pinned,
        pytest.raises(GateBLedgerError),
    ):
        pinned.read_regular(
            "record.json",
            expected_sha256=sha256_bytes(raw),
            expected_size_bytes=len(raw),
        )


def test_pinned_directory_rejects_injected_reparse_or_replacement_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    reparse_metadata = SimpleNamespace(
        st_mode=0o100600,
        st_nlink=1,
        st_file_attributes=0x400,
    )
    with pytest.raises(GateBLedgerError, match="physical regular file"):
        ledger_module._regular_pinned_metadata(reparse_metadata, "fixture reparse")

    parent = tmp_path / "replacement-metadata"
    parent.mkdir()
    raw = b"fixture\n"
    (parent / "record.json").write_bytes(raw)
    volume_id, file_id = _directory_identity(parent)
    with GateBPinnedDirectory.open(
        parent,
        expected_volume_id_hex=volume_id,
        expected_file_id_hex=file_id,
    ) as pinned:
        original = ledger_module._regular_pinned_metadata
        calls = 0

        def replacement_on_reopen(metadata, label):
            nonlocal calls
            validated = original(metadata, label)
            calls += 1
            if calls == 3:
                values = list(validated)
                values[1] = validated.st_ino + 1
                return os.stat_result(values)
            return validated

        monkeypatch.setattr(
            ledger_module,
            "_regular_pinned_metadata",
            replacement_on_reopen,
        )
        with pytest.raises(GateBLedgerError, match="changed during reopen"):
            pinned.read_regular(
                "record.json",
                expected_sha256=sha256_bytes(raw),
                expected_size_bytes=len(raw),
            )


def test_pinned_directory_partial_write_failure_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent = tmp_path / "pinned-partial"
    parent.mkdir()
    volume_id, file_id = _directory_identity(parent)
    with GateBPinnedDirectory.open(
        parent,
        expected_volume_id_hex=volume_id,
        expected_file_id_hex=file_id,
    ) as pinned:
        monkeypatch.setattr(
            ledger_module,
            "_write_all",
            lambda *_args: (_ for _ in ()).throw(OSError("fixture-partial")),
        )
        with pytest.raises(GateBLedgerError):
            pinned.create_regular("partial.json", b"fixture\n")


def test_windows_volume_guid_helpers_are_injectable_and_reject_network() -> None:
    final_path = "\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\fixture"

    class FakeFunction:
        def __init__(self, callback):
            self.callback = callback

        def __call__(self, *args):
            return self.callback(*args)

    def get_final(_handle, buffer, _size, flags):
        assert flags == 1
        if buffer is None:
            return len(final_path)
        buffer.value = final_path
        return len(final_path)

    kernel = SimpleNamespace(GetFinalPathNameByHandleW=FakeFunction(get_final))
    assert (
        _windows_final_path_from_descriptor(
            17,
            _kernel32=kernel,
            _get_osfhandle=lambda descriptor: descriptor + 1,
        )
        == final_path
    )
    network_kernel = SimpleNamespace(GetDriveTypeW=FakeFunction(lambda _root: 4))
    with pytest.raises(GateBLedgerError, match="network"):
        _windows_reject_network_volume(
            "\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\",
            _kernel32=network_kernel,
        )


@pytest.mark.parametrize(
    "invalid_path",
    [
        PureWindowsPath(r"\\server\share\fixture"),
        PureWindowsPath(r"\\.\C:\fixture"),
        PureWindowsPath(r"\\?\C:\fixture"),
    ],
)
def test_windows_chain_rejects_unc_and_device_namespaces(
    invalid_path: PureWindowsPath,
) -> None:
    with pytest.raises(GateBLedgerError, match="canonical local DOS-drive"):
        ledger_module._open_windows_pinned_chain(invalid_path, (1, 1))


@pytest.mark.parametrize(
    "final_path",
    [
        r"\\?\C:\fixture",
        r"\\?\UNC\server\share\fixture",
        r"\\.\C:\fixture",
        r"\\?\GLOBALROOT\Device\fixture",
    ],
)
def test_windows_final_path_rejects_unavailable_guid_or_device_namespace(
    final_path: str,
) -> None:
    class FakeFunction:
        def __init__(self, callback):
            self.callback = callback

        def __call__(self, *args):
            return self.callback(*args)

    def get_final(_handle, buffer, _size, _flags):
        if buffer is None:
            return len(final_path)
        buffer.value = final_path
        return len(final_path)

    kernel = SimpleNamespace(GetFinalPathNameByHandleW=FakeFunction(get_final))
    with pytest.raises(GateBLedgerError, match="Volume-GUID"):
        _windows_final_path_from_descriptor(
            17,
            _kernel32=kernel,
            _get_osfhandle=lambda descriptor: descriptor,
        )


def test_windows_cumulative_chain_uses_no_delete_share_and_guid_reopen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    volume_root = "\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\"
    initial_paths: list[tuple[str, int, bool]] = []
    initial_descriptors = iter((101, 102, 103))
    identities = {101: (9, 1), 102: (9, 2), 103: (9, 3)}
    final_paths = {
        101: volume_root,
        102: volume_root + "fixture",
        103: volume_root + "fixture\\target",
    }
    closed: list[int] = []

    def initial_open(path, *, share, directory=False, **_kwargs):
        descriptor = next(initial_descriptors)
        initial_paths.append((str(path), share, directory))
        return descriptor

    monkeypatch.setattr(ledger_module, "_windows_create_file_descriptor", initial_open)
    monkeypatch.setattr(
        ledger_module.os,
        "fstat",
        lambda descriptor: SimpleNamespace(
            st_mode=0o040700,
            st_dev=identities[descriptor][0],
            st_ino=identities[descriptor][1],
            st_file_attributes=0,
        ),
    )
    monkeypatch.setattr(
        ledger_module,
        "_windows_final_path_from_descriptor",
        lambda descriptor: final_paths[descriptor],
    )
    monkeypatch.setattr(ledger_module, "_windows_reject_network_volume", lambda _root: None)
    monkeypatch.setattr(ledger_module.os, "close", closed.append)

    chain = ledger_module._open_windows_pinned_chain(
        PureWindowsPath("C:/fixture/target"),
        (9, 3),
    )
    assert [share for _path, share, _directory in initial_paths] == [3, 3, 3]
    assert all(directory for _path, _share, directory in initial_paths)

    reopened_paths: list[str] = []
    reopen_descriptors = iter((201, 202, 203))
    reopen_identities = {201: (9, 1), 202: (9, 2), 203: (9, 3)}
    reopen_final_paths = {
        201: volume_root,
        202: volume_root + "fixture",
        203: volume_root + "fixture\\target",
    }

    def reopen(path, **_kwargs):
        reopened_paths.append(str(path))
        return next(reopen_descriptors)

    monkeypatch.setattr(ledger_module, "_windows_create_file_descriptor", reopen)
    monkeypatch.setattr(
        ledger_module.os,
        "fstat",
        lambda descriptor: SimpleNamespace(
            st_mode=0o040700,
            st_dev=(identities | reopen_identities)[descriptor][0],
            st_ino=(identities | reopen_identities)[descriptor][1],
            st_file_attributes=0,
        ),
    )
    monkeypatch.setattr(
        ledger_module,
        "_windows_final_path_from_descriptor",
        lambda descriptor: (final_paths | reopen_final_paths)[descriptor],
    )
    ledger_module._verify_windows_pinned_chain(chain)
    assert all(path.startswith(volume_root) for path in reopened_paths)
    assert not any(path.startswith("C:") for path in reopened_paths)
    assert closed == [201, 202, 203]


@pytest.mark.parametrize(
    ("stage", "bad_descriptor"),
    [
        ("volume-root", 101),
        ("intermediate", 102),
        ("target", 103),
    ],
)
def test_windows_chain_rejects_each_ancestor_substitution_during_open(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    bad_descriptor: int,
) -> None:
    volume_root = "\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\"
    descriptors = iter((101, 102, 103))
    opened_stages: list[str] = []
    identities = {101: (9, 1), 102: (9, 2), 103: (9, 3)}
    paths = {
        101: volume_root,
        102: volume_root + "fixture",
        103: volume_root + "fixture\\target",
    }
    paths[bad_descriptor] = "\\\\?\\Volume{22222222-2222-2222-2222-222222222222}\\substituted"
    child_opened = False

    def open_component(_path, **_kwargs):
        nonlocal child_opened
        child_opened = True
        descriptor = next(descriptors)
        opened_stages.append({101: "volume-root", 102: "intermediate", 103: "target"}[descriptor])
        return descriptor

    monkeypatch.setattr(ledger_module, "_windows_create_file_descriptor", open_component)
    monkeypatch.setattr(
        ledger_module.os,
        "fstat",
        lambda descriptor: SimpleNamespace(
            st_mode=0o040700,
            st_dev=identities[descriptor][0],
            st_ino=identities[descriptor][1],
            st_file_attributes=0,
        ),
    )
    monkeypatch.setattr(
        ledger_module,
        "_windows_final_path_from_descriptor",
        lambda descriptor: paths[descriptor],
    )
    monkeypatch.setattr(ledger_module, "_windows_reject_network_volume", lambda _root: None)
    monkeypatch.setattr(ledger_module.os, "close", lambda _descriptor: None)
    with pytest.raises(GateBLedgerError):
        ledger_module._open_windows_pinned_chain(
            PureWindowsPath("C:/fixture/target"),
            (9, 3),
        )
    assert child_opened is True
    assert stage in opened_stages


@pytest.mark.parametrize(
    ("stage", "substitution_index"),
    [("volume-root", 0), ("intermediate", 1), ("target", 2)],
)
def test_windows_chain_swap_before_each_component_open_closes_retained_ancestors(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    substitution_index: int,
) -> None:
    volume_root = "\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\"
    alternate_root = "\\\\?\\Volume{22222222-2222-2222-2222-222222222222}\\"
    opened: list[int] = []
    closed: list[int] = []
    identities = {401: (9, 1), 402: (9, 2), 403: (9, 3)}
    final_paths = {
        401: volume_root,
        402: volume_root + "fixture",
        403: volume_root + "fixture\\target",
    }

    def injected_open(_path, **_kwargs):
        descriptor = 401 + len(opened)
        if len(opened) == substitution_index:
            final_paths[descriptor] = alternate_root + stage
            identities[descriptor] = (10, descriptor)
        opened.append(descriptor)
        return descriptor

    monkeypatch.setattr(
        ledger_module,
        "_windows_create_file_descriptor",
        injected_open,
    )
    monkeypatch.setattr(
        ledger_module.os,
        "fstat",
        lambda descriptor: SimpleNamespace(
            st_mode=0o040700,
            st_dev=identities[descriptor][0],
            st_ino=identities[descriptor][1],
            st_file_attributes=0,
        ),
    )
    monkeypatch.setattr(
        ledger_module,
        "_windows_final_path_from_descriptor",
        lambda descriptor: final_paths[descriptor],
    )
    monkeypatch.setattr(ledger_module, "_windows_reject_network_volume", lambda _root: None)
    monkeypatch.setattr(ledger_module.os, "close", closed.append)
    with pytest.raises(GateBLedgerError):
        GateBPinnedDirectory.open(
            Path("C:/fixture/target"),
            expected_volume_id_hex="9",
            expected_file_id_hex="3",
        )
    assert closed == list(reversed(opened))


def test_windows_dos_alias_remap_before_target_open_is_rejected_by_pinned_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ledger_module, "Path", PureWindowsPath)
    monkeypatch.setattr(ledger_module.os, "name", "nt")
    alternate_root = "\\\\?\\Volume{22222222-2222-2222-2222-222222222222}\\"
    descriptors = iter((501, 502, 503))
    identities = {501: (10, 1), 502: (10, 2), 503: (10, 99)}
    final_paths = {
        501: alternate_root,
        502: alternate_root + "fixture",
        503: alternate_root + "fixture\\target",
    }

    def open_remapped(_path, **_kwargs):
        return next(descriptors)

    monkeypatch.setattr(ledger_module, "_windows_create_file_descriptor", open_remapped)
    monkeypatch.setattr(
        ledger_module.os,
        "fstat",
        lambda descriptor: SimpleNamespace(
            st_mode=0o040700,
            st_dev=identities[descriptor][0],
            st_ino=identities[descriptor][1],
            st_file_attributes=0,
        ),
    )
    monkeypatch.setattr(
        ledger_module,
        "_windows_final_path_from_descriptor",
        lambda descriptor: final_paths[descriptor],
    )
    monkeypatch.setattr(ledger_module, "_windows_reject_network_volume", lambda _root: None)
    monkeypatch.setattr(ledger_module.os, "close", lambda _descriptor: None)
    with pytest.raises(GateBLedgerError, match="identity"):
        GateBPinnedDirectory.open(
            Path("C:/fixture/target"),
            expected_volume_id_hex="9",
            expected_file_id_hex="3",
        )


def test_pinned_open_closes_every_retained_handle_when_final_verify_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ledger_module, "Path", PureWindowsPath)
    monkeypatch.setattr(ledger_module.os, "name", "nt")
    final_path = "\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\fixture"
    chain = (
        ledger_module._PinnedWindowsDirectoryHandle(301, (9, 1), final_path.rsplit("\\", 1)[0]),
        ledger_module._PinnedWindowsDirectoryHandle(302, (9, 2), final_path),
    )
    closed: list[int] = []
    monkeypatch.setattr(
        ledger_module,
        "_open_windows_pinned_chain",
        lambda _path, _identity: chain,
    )
    monkeypatch.setattr(
        GateBPinnedDirectory,
        "verify_identity",
        lambda _self: (_ for _ in ()).throw(GateBLedgerError("fixture-verify")),
    )
    monkeypatch.setattr(ledger_module.os, "close", closed.append)
    with pytest.raises(GateBLedgerError):
        GateBPinnedDirectory.open(
            Path("C:/fixture"),
            expected_volume_id_hex="9",
            expected_file_id_hex="2",
        )
    assert closed == [302, 301]


@pytest.mark.parametrize("ancestor_index", [0, 1, 2])
@pytest.mark.parametrize("timing", ["before-child-create", "after-child-open"])
def test_each_synthetic_ancestor_swap_around_child_create_is_blocked_or_stays_pinned(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    ancestor_index: int,
    timing: str,
) -> None:
    base = tmp_path / f"ancestor-race-{ancestor_index}-{timing}"
    ancestor_a = base / "ancestor-a"
    ancestor_b = ancestor_a / "ancestor-b"
    target = ancestor_b / "target"
    target.mkdir(parents=True)
    ancestors = (ancestor_a, ancestor_b, target)
    selected = ancestors[ancestor_index]
    moved = base / f"moved-{ancestor_index}"
    relative_target = target.relative_to(selected)
    original_pinned_target = moved / relative_target
    replacement_target = selected / relative_target
    replacement_installed = False

    def inject_swap() -> None:
        nonlocal replacement_installed
        try:
            os.rename(selected, moved)
        except OSError:
            return
        replacement_target.mkdir(parents=True)
        replacement_installed = True

    volume_id, file_id = _directory_identity(target)
    with GateBPinnedDirectory.open(
        target,
        expected_volume_id_hex=volume_id,
        expected_file_id_hex=file_id,
    ) as pinned:
        if timing == "before-child-create":
            inject_swap()
        else:
            original_open = GateBPinnedDirectory._open_new_child

            def open_then_swap(instance, name):
                descriptor = original_open(instance, name)
                inject_swap()
                return descriptor

            monkeypatch.setattr(
                GateBPinnedDirectory,
                "_open_new_child",
                open_then_swap,
            )
        try:
            artifact = pinned.create_regular("pinned-only.json", b"pinned\n")
        except GateBLedgerError:
            artifact = None

    if replacement_installed:
        assert not (replacement_target / "pinned-only.json").exists()
        if artifact is not None:
            assert (original_pinned_target / "pinned-only.json").read_bytes() == b"pinned\n"
    else:
        assert artifact is not None
        assert (target / "pinned-only.json").read_bytes() == b"pinned\n"


def test_windows_dos_alias_remap_after_initial_open_uses_only_retained_guid_namespace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    del tmp_path
    monkeypatch.setattr(ledger_module, "Path", PureWindowsPath)
    monkeypatch.setattr(ledger_module.os, "name", "nt")
    final_path = "\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\fixture"
    chain = (ledger_module._PinnedWindowsDirectoryHandle(700, (9, 2), final_path),)
    opened_paths: list[str] = []
    stored_raw = b""
    descriptors = iter((701, 702))
    closed: list[int] = []

    def observed_open(path, **_kwargs):
        opened_paths.append(str(path))
        return next(descriptors)

    def modeled_write(_descriptor: int, raw: bytes) -> None:
        nonlocal stored_raw
        stored_raw = bytes(raw)

    def modeled_fstat(_descriptor: int) -> SimpleNamespace:
        return SimpleNamespace(
            st_mode=0o100600,
            st_dev=9,
            st_ino=3,
            st_size=len(stored_raw),
            st_nlink=1,
            st_file_attributes=0,
        )

    monkeypatch.setattr(
        ledger_module,
        "_open_windows_pinned_chain",
        lambda _path, _identity: chain,
    )
    monkeypatch.setattr(ledger_module, "_verify_windows_pinned_chain", lambda _chain: None)
    monkeypatch.setattr(ledger_module, "_windows_create_file_descriptor", observed_open)
    monkeypatch.setattr(
        ledger_module,
        "_windows_stream_names",
        lambda _path: ("::$DATA",),
    )
    monkeypatch.setattr(ledger_module, "_write_all", modeled_write)
    monkeypatch.setattr(ledger_module, "_read_all_descriptor", lambda _descriptor: stored_raw)
    monkeypatch.setattr(ledger_module.os, "fstat", modeled_fstat)
    monkeypatch.setattr(ledger_module.os, "fsync", lambda _descriptor: None)
    monkeypatch.setattr(ledger_module.os, "close", closed.append)

    with GateBPinnedDirectory.open(
        PureWindowsPath("C:/fixture"),
        expected_volume_id_hex="9",
        expected_file_id_hex="2",
    ) as pinned:
        object.__setattr__(
            pinned,
            "_path",
            PureWindowsPath("Z:/synthetic-remapped-target"),
        )
        artifact = pinned.create_regular("guid-only.json", b"fixture\n")

    assert artifact.raw == b"fixture\n"
    assert opened_paths
    assert all(path.startswith("\\\\?\\Volume{") for path in opened_paths)
    assert stored_raw == b"fixture\n"
    assert closed == [701, 702, 700]


@pytest.mark.parametrize(
    ("operation", "failure_call"),
    [
        ("read", 1),
        ("read", 2),
        ("create", 1),
        ("create", 2),
        ("list", 1),
        ("list", 2),
    ],
)
def test_pinned_directory_identity_change_before_or_after_every_operation_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    operation: str,
    failure_call: int,
) -> None:
    parent = tmp_path / f"identity-{operation}-{failure_call}"
    parent.mkdir()
    existing = parent / "existing.json"
    existing.write_bytes(b"fixture\n")
    volume_id, file_id = _directory_identity(parent)
    with GateBPinnedDirectory.open(
        parent,
        expected_volume_id_hex=volume_id,
        expected_file_id_hex=file_id,
    ) as pinned:
        original = GateBPinnedDirectory._verify_identity_unwrapped
        calls = 0

        def injected(instance):
            nonlocal calls
            calls += 1
            if calls == failure_call:
                raise GateBLedgerError("fixture identity substitution")
            return original(instance)

        monkeypatch.setattr(GateBPinnedDirectory, "_verify_identity_unwrapped", injected)
        with pytest.raises(GateBLedgerError, match="identity"):
            if operation == "read":
                pinned.read_regular(
                    "existing.json",
                    expected_sha256=sha256_bytes(b"fixture\n"),
                    expected_size_bytes=len(b"fixture\n"),
                )
            elif operation == "create":
                pinned.create_regular("created.json", b"created\n")
            else:
                pinned.direct_child_names()


@pytest.mark.parametrize("failure", ["flush", "reopen"])
def test_pinned_create_flush_or_reopen_failure_returns_no_artifact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: str,
) -> None:
    parent = tmp_path / f"durability-{failure}"
    parent.mkdir()
    volume_id, file_id = _directory_identity(parent)
    with GateBPinnedDirectory.open(
        parent,
        expected_volume_id_hex=volume_id,
        expected_file_id_hex=file_id,
    ) as pinned:
        if failure == "flush":
            monkeypatch.setattr(
                ledger_module.os,
                "fsync",
                lambda _descriptor: (_ for _ in ()).throw(OSError("fixture flush")),
            )
        else:
            monkeypatch.setattr(
                GateBPinnedDirectory,
                "_open_existing_child",
                lambda _self, _name: (_ for _ in ()).throw(OSError("fixture reopen")),
            )
        with pytest.raises(GateBLedgerError):
            pinned.create_regular("artifact.json", b"fixture\n")


def test_pinned_human_record_files_reject_physical_alias(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "human-record-alias"
    parent.mkdir()
    approval_path = parent / "approval.json"
    signature_path = parent / "signature.json"
    raw = b"fixture\n"
    approval_path.write_bytes(raw)
    os.link(approval_path, signature_path)
    volume_id, file_id = _directory_identity(parent)
    with GateBPinnedDirectory.open(
        parent,
        expected_volume_id_hex=volume_id,
        expected_file_id_hex=file_id,
    ) as pinned:
        for name in ("approval.json", "signature.json"):
            with pytest.raises(GateBLedgerError, match="single-link"):
                pinned.read_regular(
                    name,
                    expected_sha256=sha256_bytes(raw),
                    expected_size_bytes=len(raw),
                )


def test_windows_v2_native_identity_uses_exact_volume_serial_and_file_index() -> None:
    class Function:
        argtypes = None
        restype = None

        def __call__(self, handle, output) -> int:
            assert handle.value == 1234
            information = output._obj
            information.volume_serial_number = 0x00355357
            information.file_index_high = 0x0EDB0000
            information.file_index_low = 0x0002971B
            return 1

    kernel32 = SimpleNamespace(GetFileInformationByHandle=Function())
    assert _windows_v2_identity_from_descriptor(
        9,
        _kernel32=kernel32,
        _get_osfhandle=lambda descriptor: 1234 if descriptor == 9 else 0,
    ) == (0x00355357, 0x0EDB00000002971B)


@pytest.mark.skipif(os.name != "nt", reason="v2 profile is Windows-only")
def test_v2_pinned_directory_exact_text_numeric_and_same_profile_round_trip(
    tmp_path: Path,
) -> None:
    root = tmp_path / "v2-native-root"
    root.mkdir()
    descriptor = ledger_module._open_directory_descriptor(root)
    try:
        volume, file_id = _windows_v2_identity_from_descriptor(descriptor)
    finally:
        os.close(descriptor)
    volume_text = format(volume, "08x")
    file_text = format(file_id, "016x")
    with open_gate_b_v2_pinned_directory(
        root,
        serialization_profile="windows-volume8-file16-lowerhex-v1",
        expected_volume_id_hex=volume_text,
        expected_file_id_hex=file_text,
    ) as pinned:
        assert (
            verify_gate_b_v2_pinned_directory(
                pinned,
                serialization_profile="windows-volume8-file16-lowerhex-v1",
                expected_volume_id_hex=volume_text,
                expected_file_id_hex=file_text,
            )
            is None
        )


@pytest.mark.parametrize(
    ("volume", "file_id"),
    [
        ("355357", "0edb00000002971b"),
        ("00355357", "edb00000002971b"),
        ("0035535A", "0edb00000002971b"),
        ("00355357", "0EDB00000002971B"),
        ("00000000", "0edb00000002971b"),
        ("00355357", "0000000000000000"),
    ],
)
def test_v2_pinned_directory_rejects_text_before_any_native_identity_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    volume: str,
    file_id: str,
) -> None:
    native_reads = []

    def forbidden(*_args, **_kwargs):
        native_reads.append("called")
        raise AssertionError("invalid text reached native identity parsing")

    monkeypatch.setattr(ledger_module, "_windows_v2_identity_from_descriptor", forbidden)
    with pytest.raises(GateBLedgerError):
        open_gate_b_v2_pinned_directory(
            tmp_path,
            serialization_profile="windows-volume8-file16-lowerhex-v1",
            expected_volume_id_hex=volume,
            expected_file_id_hex=file_id,
        )
    assert native_reads == []


def test_v2_retained_root_topology_rejects_native_alias_nesting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    volume_root = r"\\?\Volume{11111111-1111-1111-1111-111111111111}"
    final_paths = {
        81: volume_root + r"\physical-parent",
        82: volume_root + r"\physical-parent\aliased-child",
        83: volume_root + r"\independent-root",
    }
    native_identities = {81: (9, 1), 82: (9, 2), 83: (9, 3)}
    directories = {}
    for role, descriptor in zip(
        ("ledger_base", "quarantine_base", "test_root"),
        (81, 82, 83),
        strict=True,
    ):
        directory = object.__new__(GateBPinnedDirectory)
        object.__setattr__(directory, "_descriptor", descriptor)
        object.__setattr__(directory, "_stable_path", PureWindowsPath(final_paths[descriptor]))
        directories[role] = directory

    monkeypatch.setattr(ledger_module.os, "name", "nt")
    monkeypatch.setattr(GateBPinnedDirectory, "verify_identity", lambda _self: None)
    monkeypatch.setattr(
        ledger_module,
        "_windows_final_path_from_descriptor",
        lambda descriptor: final_paths[descriptor],
    )
    monkeypatch.setattr(
        ledger_module,
        "_windows_v2_identity_from_descriptor",
        lambda descriptor: native_identities[descriptor],
    )
    with pytest.raises(GateBLedgerError, match="physically nested"):
        verify_gate_b_v2_retained_root_topology(directories)


def test_every_ledger_request_consumer_nominally_rejects_v2_before_create(
    tmp_path: Path,
) -> None:
    class SyntheticV2(GateBV2CompatibilityObject):
        pass

    request = SyntheticV2()
    calls = (
        lambda: GateBLedgerStore(request),
        lambda: GateBLedgerStore.reserve_attempt(request, expected_latest_record_sha256=None),
        lambda: GateBQuarantine.create(request),
        lambda: _new_record(
            request,
            None,
            attempt_ordinal=1,
            from_state="UNSEEN",
            to_state="RESERVED",
            actor_id="fixture",
            actor_role="fixture",
        ),
        lambda: _reserve_attempt(request, expected_latest_record_sha256=None),
        lambda: _append_started(request, request, store=request),
        lambda: mark_gate_b_failed_closed(request, request),
        lambda: seal_gate_b_attempt(request, request),
        lambda: authorize_gate_b_release(request, request),
        lambda: authorize_gate_b_retry(request, request),
    )
    before = tuple(tmp_path.iterdir())
    for call in calls:
        with pytest.raises(GateBLedgerError):
            call()
    assert tuple(tmp_path.iterdir()) == before == ()
