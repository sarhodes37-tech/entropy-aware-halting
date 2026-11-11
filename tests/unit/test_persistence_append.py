"""
Unit, Boundedness, and Crash-Consistency Tests for Persistence Append Subsystem.
Baseline: EpistemicOS Persistence Architecture Specification v5.1.1 (Phase 2 Remediation).
"""

import hashlib
import json
import math
import multiprocessing
import os
import sqlite3
import tempfile
import threading
import pytest

from epistemicos.persistence.schema import initialize_database, open_database, transaction
from epistemicos.persistence.append import (
    append_event,
    verify_append_state,
    reconcile_active_segment,
    canonical_json_serialize,
    acquire_writer_lock,
    AppendResult,
    DuplicateEventError,
    InvalidPayloadError,
    SegmentNotActiveError,
    UnresolvedGapError,
    FatalCommittedDataCorruptionError,
    PersistenceAppendError,
    MissingLockConfigurationError,
)


@pytest.fixture
def persistence_env():
    """Provides temporary DB path, open DB conn, segment file, and segment FD."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "metadata.db")
    segment_path = os.path.join(temp_dir, "segment_00000000.log")
    lock_path = os.path.join(temp_dir, "active_writer.lock")

    conn = initialize_database(db_path)
    fd = os.open(segment_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o640)

    yield {
        "dir": temp_dir,
        "db_path": db_path,
        "conn": conn,
        "segment_path": segment_path,
        "segment_fd": fd,
        "lock_path": lock_path,
    }

    os.close(fd)
    conn.close()
    for fname in os.listdir(temp_dir):
        try:
            os.unlink(os.path.join(temp_dir, fname))
        except OSError:
            pass
    try:
        os.rmdir(temp_dir)
    except OSError:
        pass


def test_canonical_json_serialization():
    """Verify deterministic JSON serialization, sorted keys, no whitespace, and float validation."""
    data = {"z": 1, "a": 2, "m": [3, 2, 1]}
    serialized = canonical_json_serialize(data)
    assert serialized == b'{"a":2,"m":[3,2,1],"z":1}'

    with pytest.raises(InvalidPayloadError, match="Non-finite float"):
        canonical_json_serialize({"val": float("nan")})

    with pytest.raises(InvalidPayloadError, match="Non-finite float"):
        canonical_json_serialize({"val": float("inf")})

    with pytest.raises(InvalidPayloadError, match="Record payload must be a dict"):
        canonical_json_serialize(["not", "a", "dict"])


def test_mandatory_writer_locking_enforced(persistence_env):
    """Verify that omitting or passing invalid lock_file_path is strictly rejected before writing bytes."""
    conn = persistence_env["conn"]
    fd = persistence_env["segment_fd"]
    db_path = persistence_env["db_path"]

    # None lock_file_path
    with pytest.raises(MissingLockConfigurationError, match="Mandatory lock_file_path"):
        append_event(
            ledger_id="audit_ledger",
            segment_sequence=0,
            event_id="ev_no_lock",
            payload={"action": "FAIL"},
            segment_fd=fd,
            db_conn=conn,
            lock_file_path=None,  # type: ignore
            db_path=db_path,
        )

    # Empty string lock_file_path
    with pytest.raises(MissingLockConfigurationError, match="Mandatory lock_file_path"):
        append_event(
            ledger_id="audit_ledger",
            segment_sequence=0,
            event_id="ev_empty_lock",
            payload={"action": "FAIL"},
            segment_fd=fd,
            db_conn=conn,
            lock_file_path="   ",
            db_path=db_path,
        )

    assert os.fstat(fd).st_size == 0


def test_first_and_sequential_appends(persistence_env):
    """Verify first append and sequential append offsets, lengths, hashes, and watermark progression."""
    conn = persistence_env["conn"]
    fd = persistence_env["segment_fd"]
    db_path = persistence_env["db_path"]
    lock_path = persistence_env["lock_path"]

    res1 = append_event(
        ledger_id="audit_ledger",
        segment_sequence=0,
        event_id="ev_001",
        payload={"action": "INIT", "user": "alice"},
        segment_fd=fd,
        db_conn=conn,
        lock_file_path=lock_path,
        db_path=db_path,
    )
    assert res1.byte_offset == 0
    assert res1.prev_event_hash == "0" * 64
    assert res1.new_contiguous_watermark == res1.record_length
    assert os.fstat(fd).st_size == res1.new_contiguous_watermark

    res2 = append_event(
        ledger_id="audit_ledger",
        segment_sequence=0,
        event_id="ev_002",
        payload={"action": "PROCESS", "user": "bob"},
        segment_fd=fd,
        db_conn=conn,
        lock_file_path=lock_path,
        db_path=db_path,
    )
    assert res2.byte_offset == res1.new_contiguous_watermark
    assert res2.prev_event_hash == res1.entry_hash
    assert res2.new_contiguous_watermark == res1.new_contiguous_watermark + res2.record_length
    assert os.fstat(fd).st_size == res2.new_contiguous_watermark


def test_duplicate_event_rejection(persistence_env):
    """Verify duplicate event IDs are rejected with DuplicateEventError and do not advance file size."""
    conn = persistence_env["conn"]
    fd = persistence_env["segment_fd"]
    db_path = persistence_env["db_path"]
    lock_path = persistence_env["lock_path"]

    append_event(
        ledger_id="audit_ledger",
        segment_sequence=0,
        event_id="ev_duplicate",
        payload={"key": "val1"},
        segment_fd=fd,
        db_conn=conn,
        lock_file_path=lock_path,
        db_path=db_path,
    )
    size_before = os.fstat(fd).st_size

    with pytest.raises(DuplicateEventError, match="already exists"):
        append_event(
            ledger_id="audit_ledger",
            segment_sequence=0,
            event_id="ev_duplicate",
            payload={"key": "val2"},
            segment_fd=fd,
            db_conn=conn,
            lock_file_path=lock_path,
            db_path=db_path,
        )

    assert os.fstat(fd).st_size == size_before


def test_concurrent_writer_serialization_threads(persistence_env):
    """Verify concurrent appenders across threads serialize cleanly without offset collisions."""
    db_path = persistence_env["db_path"]
    segment_path = persistence_env["segment_path"]
    lock_path = persistence_env["lock_path"]

    num_threads = 4
    events_per_thread = 5
    results = []
    errors = []

    def worker(worker_id):
        worker_conn = open_database(db_path)
        worker_fd = os.open(segment_path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
        try:
            for i in range(events_per_thread):
                eid = f"ev_w{worker_id}_{i}"
                res = append_event(
                    ledger_id="concurrent_ledger",
                    segment_sequence=0,
                    event_id=eid,
                    payload={"worker": worker_id, "idx": i},
                    segment_fd=worker_fd,
                    db_conn=worker_conn,
                    lock_file_path=lock_path,
                    db_path=db_path,
                )
                results.append(res)
        except Exception as exc:
            errors.append(exc)
        finally:
            os.close(worker_fd)
            worker_conn.close()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(results) == num_threads * events_per_thread

    sorted_res = sorted(results, key=lambda r: r.byte_offset)
    current_off = 0
    for r in sorted_res:
        assert r.byte_offset == current_off
        current_off += r.record_length
    assert os.path.getsize(segment_path) == current_off


def _mp_worker(worker_id, num_events, db_path, segment_path, lock_path, queue):
    """Multiprocessing worker function."""
    conn = open_database(db_path)
    fd = os.open(segment_path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
    worker_results = []
    try:
        for i in range(num_events):
            eid = f"ev_mp_{worker_id}_{i}"
            res = append_event(
                ledger_id="mp_ledger",
                segment_sequence=0,
                event_id=eid,
                payload={"proc": worker_id, "idx": i},
                segment_fd=fd,
                db_conn=conn,
                lock_file_path=lock_path,
                db_path=db_path,
            )
            worker_results.append((res.byte_offset, res.record_length, res.event_id))
        queue.put(("OK", worker_results))
    except Exception as exc:
        queue.put(("ERR", str(exc)))
    finally:
        os.close(fd)
        conn.close()


def test_concurrent_writer_serialization_processes(persistence_env):
    """Verify independent OS processes attempting concurrent appends serialize correctly via fcntl.flock."""
    db_path = persistence_env["db_path"]
    segment_path = persistence_env["segment_path"]
    lock_path = persistence_env["lock_path"]

    num_processes = 3
    events_per_proc = 5
    queue = multiprocessing.Queue()

    procs = [
        multiprocessing.Process(
            target=_mp_worker,
            args=(p_id, events_per_proc, db_path, segment_path, lock_path, queue),
        )
        for p_id in range(num_processes)
    ]

    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=10.0)
        assert not p.is_alive()

    all_records = []
    for _ in range(num_processes):
        status, data = queue.get(timeout=2.0)
        assert status == "OK", f"Process worker error: {data}"
        all_records.extend(data)

    assert len(all_records) == num_processes * events_per_proc

    # Verify no overlapping byte ranges across processes
    sorted_records = sorted(all_records, key=lambda r: r[0])
    curr_off = 0
    for off, length, eid in sorted_records:
        assert off == curr_off
        curr_off += length

    assert os.path.getsize(segment_path) == curr_off


def test_full_reconciliation_truncates_trailing_unindexed_bytes(persistence_env):
    """Verify explicit full reconciliation truncates unindexed trailing bytes back to committed watermark."""
    conn = persistence_env["conn"]
    fd = persistence_env["segment_fd"]
    db_path = persistence_env["db_path"]
    lock_path = persistence_env["lock_path"]

    res = append_event(
        ledger_id="audit_ledger",
        segment_sequence=0,
        event_id="ev_001",
        payload={"action": "VALID"},
        segment_fd=fd,
        db_conn=conn,
        lock_file_path=lock_path,
        db_path=db_path,
    )
    valid_size = res.new_contiguous_watermark

    # Append uncommitted trailing bytes
    os.lseek(fd, valid_size, os.SEEK_SET)
    os.write(fd, b'{"action":"UNCOMMITTED_CRASH_DATA"}\n')
    os.fdatasync(fd)
    assert os.fstat(fd).st_size > valid_size

    # Verify bounded append-time verification detects physical EOF != watermark
    with pytest.raises(UnresolvedGapError, match="does not match committed watermark"):
        append_event(
            ledger_id="audit_ledger",
            segment_sequence=0,
            event_id="ev_002",
            payload={"action": "AFTER_CRASH"},
            segment_fd=fd,
            db_conn=conn,
            lock_file_path=lock_path,
            db_path=db_path,
        )

    # Now execute explicit full reconciliation
    reconciled_wm = reconcile_active_segment(
        ledger_id="audit_ledger",
        segment_sequence=0,
        segment_fd=fd,
        db_conn=conn,
    )
    assert reconciled_wm == valid_size
    assert os.fstat(fd).st_size == valid_size

    # Subsequent append succeeds cleanly
    res2 = append_event(
        ledger_id="audit_ledger",
        segment_sequence=0,
        event_id="ev_002",
        payload={"action": "AFTER_RECOVERY"},
        segment_fd=fd,
        db_conn=conn,
        lock_file_path=lock_path,
        db_path=db_path,
    )
    assert res2.byte_offset == valid_size
    assert os.fstat(fd).st_size == valid_size + res2.record_length


def test_tail_record_corruption_fails_closed(persistence_env):
    """Verify modifying tail record bytes on disk triggers FatalCommittedDataCorruptionError during bounded verification."""
    conn = persistence_env["conn"]
    fd = persistence_env["segment_fd"]
    db_path = persistence_env["db_path"]
    lock_path = persistence_env["lock_path"]

    res = append_event(
        ledger_id="audit_ledger",
        segment_sequence=0,
        event_id="ev_tail_tamper",
        payload={"sensitive": "tail_original_value"},
        segment_fd=fd,
        db_conn=conn,
        lock_file_path=lock_path,
        db_path=db_path,
    )

    # Tamper with the committed tail record on disk
    os.lseek(fd, res.byte_offset + 2, os.SEEK_SET)
    os.write(fd, b"X")
    os.fdatasync(fd)

    with pytest.raises(FatalCommittedDataCorruptionError, match="hash mismatch"):
        append_event(
            ledger_id="audit_ledger",
            segment_sequence=0,
            event_id="ev_next",
            payload={"action": "BLOCKED"},
            segment_fd=fd,
            db_conn=conn,
            lock_file_path=lock_path,
            db_path=db_path,
        )


def test_full_reconciliation_detects_historical_tampering(persistence_env):
    """
    Verify that explicit full reconciliation detects tampering in an old historical record
    (which bounded tail verification does not inspect).
    """
    conn = persistence_env["conn"]
    fd = persistence_env["segment_fd"]
    db_path = persistence_env["db_path"]
    lock_path = persistence_env["lock_path"]

    append_event("audit_ledger", 0, "ev_0", {"idx": 0}, fd, conn, lock_path, db_path)
    append_event("audit_ledger", 0, "ev_1", {"idx": 1}, fd, conn, lock_path, db_path)
    append_event("audit_ledger", 0, "ev_2", {"idx": 2}, fd, conn, lock_path, db_path)

    # Tamper with record 0 (offset 2)
    os.lseek(fd, 2, os.SEEK_SET)
    os.write(fd, b"Z")
    os.fdatasync(fd)

    # Bounded tail verification on record 2 does NOT inspect record 0, so bounded verify passes:
    state = verify_append_state("audit_ledger", 0, fd, conn)
    assert state.watermark_offset == os.fstat(fd).st_size

    # BUT explicit full reconciliation MUST detect the historical tamper in record 0:
    with pytest.raises(FatalCommittedDataCorruptionError, match="hash mismatch"):
        reconcile_active_segment("audit_ledger", 0, fd, conn)


def test_append_event_does_not_call_reconcile_active_segment(persistence_env, monkeypatch):
    """Regression test: verify append_event strictly does NOT call full reconcile_active_segment."""
    conn = persistence_env["conn"]
    fd = persistence_env["segment_fd"]
    db_path = persistence_env["db_path"]
    lock_path = persistence_env["lock_path"]

    def forbid_full_reconcile(*args, **kwargs):
        raise AssertionError("reconcile_active_segment was unexpectedly called during normal append!")

    import epistemicos.persistence.append as append_mod
    monkeypatch.setattr(append_mod, "reconcile_active_segment", forbid_full_reconcile)

    res = append_event(
        ledger_id="audit_ledger",
        segment_sequence=0,
        event_id="ev_no_reconcile",
        payload={"action": "FAST_APPEND"},
        segment_fd=fd,
        db_conn=conn,
        lock_file_path=lock_path,
        db_path=db_path,
    )
    assert res.event_id == "ev_no_reconcile"


class CountingConnectionWrapper:
    """Wraps an sqlite3.Connection to count historical rows retrieved."""
    def __init__(self, real_conn):
        self._real_conn = real_conn
        self.historical_rows_retrieved = 0

    def __getattr__(self, name):
        return getattr(self._real_conn, name)

    def execute(self, sql, *args, **kwargs):
        cur = self._real_conn.execute(sql, *args, **kwargs)
        # Count historical reads (SELECT queries on seen_events)
        if "seen_events" in sql and "SELECT" in sql:
            rows = cur.fetchall()
            self.historical_rows_retrieved += len(rows)
            return self._real_conn.execute(sql, *args, **kwargs)
        return cur


def test_complete_append_path_performance_instrumentation(persistence_env, monkeypatch):
    """
    Correction B Requirement:
    Extend deterministic performance instrumentation to cover the COMPLETE append_event() execution path
    at N = 10, 100, 1,000.
    Demonstrates that the complete append operation performs:
      - O(1) historical SQLite rows retrieved (exactly 1 or 2 rows: tail record check & duplicate check)
      - O(1) historical physical record ranges read (exactly 1 range: tail record)
      - O(1) historical SHA-256 computations (exactly 1 computation: tail record verification)
      - Historical verification bytes read bounded strictly by tail record size.
    """
    conn = persistence_env["conn"]
    fd = persistence_env["segment_fd"]
    db_path = persistence_env["db_path"]
    lock_path = persistence_env["lock_path"]

    for n in (10, 100, 1000, 5000):
        # Reset database and file for clean measurement
        conn.close()
        os.ftruncate(fd, 0)
        os.unlink(db_path)
        for ext in ("-wal", "-shm"):
            if os.path.exists(db_path + ext):
                os.unlink(db_path + ext)
        conn = initialize_database(db_path)

        for i in range(n):
            append_event(
                ledger_id="benchmark_ledger",
                segment_sequence=0,
                event_id=f"ev_{n}_{i}",
                payload={"index": i, "padding": "x" * 50},
                segment_fd=fd,
                db_conn=conn,
                lock_file_path=lock_path,
                db_path=db_path,
            )

        counting_conn = CountingConnectionWrapper(conn)

        ranges_read = 0
        bytes_read = 0
        orig_read = os.read

        def counting_read(target_fd, length):
            nonlocal ranges_read, bytes_read
            data = orig_read(target_fd, length)
            if target_fd == fd:
                ranges_read += 1
                bytes_read += len(data)
            return data

        monkeypatch.setattr(os, "read", counting_read)

        hashes_computed = 0
        orig_sha256 = hashlib.sha256

        # Exclude the hash of the new record itself from historical verification counts
        new_payload_bytes = canonical_json_serialize({"action": "NEW_APPEND_MEASURED", "data": "abc"})

        def counting_sha256(data=b""):
            nonlocal hashes_computed
            if data != new_payload_bytes:
                hashes_computed += 1
            return orig_sha256(data)

        monkeypatch.setattr(hashlib, "sha256", counting_sha256)

        # Execute COMPLETE append_event execution path
        res = append_event(
            ledger_id="benchmark_ledger",
            segment_sequence=0,
            event_id=f"ev_{n}_new_record",
            payload={"action": "NEW_APPEND_MEASURED", "data": "abc"},
            segment_fd=fd,
            db_conn=counting_conn,
            lock_file_path=lock_path,
            db_path=db_path,
        )

        assert res.new_contiguous_watermark == os.fstat(fd).st_size

        # Verify O(1) bounds across the entire append_event call:
        # Rows retrieved: 1 from tail check + 0 from duplicate check (none returned) = 1
        assert counting_conn.historical_rows_retrieved == 1, (
            f"Expected 1 historical row retrieved, got {counting_conn.historical_rows_retrieved} at N={n}"
        )
        assert ranges_read == 1, f"Expected 1 physical range read, got {ranges_read} at N={n}"
        assert hashes_computed == 1, f"Expected 1 historical hash computed, got {hashes_computed} at N={n}"
        assert bytes_read < 256, f"Expected <256 verification bytes read, got {bytes_read} at N={n}"

        monkeypatch.undo()


class MockFailingConnection:
    """Wraps an sqlite3.Connection to inject selective execution failures for testing."""
    def __init__(self, real_conn, fail_after_commit=False, fail_on_insert=False):
        self._real_conn = real_conn
        self.fail_after_commit = fail_after_commit
        self.fail_on_insert = fail_on_insert
        self.seen_first_commit = False

    def __getattr__(self, name):
        return getattr(self._real_conn, name)

    def execute(self, sql, *args, **kwargs):
        if self.fail_on_insert and "INSERT INTO seen_events" in sql:
            raise sqlite3.OperationalError("Simulated disk I/O failure during insert")
        if self.fail_after_commit and sql == "COMMIT;":
            if self.seen_first_commit:
                self._real_conn.execute("COMMIT;")
                raise sqlite3.OperationalError("Simulated commit timeout/network interrupt")
            else:
                self.seen_first_commit = True
        return self._real_conn.execute(sql, *args, **kwargs)


def test_indeterminate_commit_recovery_success(persistence_env):
    """Verify recovery when commit error occurs but transaction actually committed (Case A)."""
    conn = persistence_env["conn"]
    fd = persistence_env["segment_fd"]
    db_path = persistence_env["db_path"]
    lock_path = persistence_env["lock_path"]

    mock_conn = MockFailingConnection(conn, fail_after_commit=True)

    res = append_event(
        ledger_id="indet_ledger",
        segment_sequence=0,
        event_id="ev_indet_ok",
        payload={"status": "committed_despite_error"},
        segment_fd=fd,
        db_conn=mock_conn,
        lock_file_path=lock_path,
        db_path=db_path,
    )

    assert res.event_id == "ev_indet_ok"
    assert res.byte_offset == 0
    assert res.new_contiguous_watermark == res.record_length


def test_indeterminate_commit_recovery_rollback(persistence_env):
    """Verify recovery when commit fails and was rolled back (Case B)."""
    conn = persistence_env["conn"]
    fd = persistence_env["segment_fd"]
    db_path = persistence_env["db_path"]
    lock_path = persistence_env["lock_path"]

    mock_conn = MockFailingConnection(conn, fail_on_insert=True)

    with pytest.raises(PersistenceAppendError, match="SQLite transaction failed"):
        append_event(
            ledger_id="rollback_ledger",
            segment_sequence=0,
            event_id="ev_fail",
            payload={"status": "should_rollback"},
            segment_fd=fd,
            db_conn=mock_conn,
            lock_file_path=lock_path,
            db_path=db_path,
        )

    assert os.fstat(fd).st_size == 0
