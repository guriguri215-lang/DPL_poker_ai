from __future__ import annotations

import json
import multiprocessing
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

import phase6.gate_b_ledger as ledger_module
from phase6.contracts import canonical_json_bytes, sha256_bytes
from phase6.gate_b_contracts import (
    ACCESS_LOG_ENTRY_SCHEMA_VERSION,
    QUARANTINE_OUTPUT_NAMES,
    RELEASE_AUTHORIZATION_SCHEMA_VERSION,
    RETRY_AUTHORIZATION_SCHEMA_VERSION,
    _root_identity_payload,
)
from phase6.gate_b_ledger import (
    GateBLedgerError,
    GateBLedgerStore,
    GateBQuarantine,
    _append_started,
    _capability_result,
    _durable_descriptor_write,
    _load_quarantine,
    _new_record,
    _platform_contract,
    _posix_flock_adapter,
    _posix_openat_adapter,
    _reserve_attempt,
    _validate_access_log_bytes,
    _validate_record_payload,
    _windows_create_file_descriptor,
    _windows_lock_adapter,
    _windows_stream_names,
    _windows_unlock_adapter,
    _write_exclusive,
    _write_exclusive_at,
    authorize_gate_b_release,
    authorize_gate_b_retry,
    mark_gate_b_failed_closed,
    seal_gate_b_attempt,
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
