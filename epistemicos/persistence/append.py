"""
Durable JSONL Append, Indexing, and Atomic Watermark Advancement Subsystem.

Baseline: EpistemicOS Persistence Architecture Specification v5.1.1 (Phase 2 Remediation).
Enforces:
  - Deterministic Canonical JSON record serialization
  - Mandatory exclusive single-writer file locking per ledger (fcntl.flock with O_CLOEXEC)
  - Bounded O(1) append-time verification (tail validation only)
  - Full O(N) integrity reconciliation available for explicit recovery and audit
  - Physical media durability (fdatasync) prior to SQLite commit
  - Atomic SQLite indexing and segment-scoped watermark advancement
  - Deterministic recovery from indeterminate SQLite commits via fresh connection verification
  - Fail-closed handling on committed data corruption or unresolved gaps
"""

import contextlib
import dataclasses
import fcntl
import hashlib
import json
import math
import os
import sqlite3
from typing import Any, Dict, Generator, Optional, Tuple, Union

from epistemicos.persistence.schema import (
    configure_pragmas,
    open_database,
    transaction,
)

# Exception Hierarchy for Append Subsystem
class PersistenceAppendError(Exception):
    """Base exception for persistence append errors."""


class DuplicateEventError(PersistenceAppendError):
    """Raised when an event ID has already been committed in the ledger."""


class InvalidPayloadError(PersistenceAppendError):
    """Raised when the record payload is malformed or contains non-serializable elements."""


class SegmentNotActiveError(PersistenceAppendError):
    """Raised when an append is attempted on a non-active or sealed segment."""


class UnresolvedGapError(PersistenceAppendError):
    """Raised when the physical write offset does not match the committed watermark."""


class PhysicalRecordCorruptionError(PersistenceAppendError):
    """Raised when physical bytes on disk do not match committed index records."""


class ReconciliationError(PersistenceAppendError):
    """Raised when pre-append or startup reconciliation fails."""


class FatalCommittedDataCorruptionError(PersistenceAppendError):
    """Raised when committed index entries reference missing or corrupted physical file bytes."""


class IndeterminateCommitError(PersistenceAppendError):
    """Raised when SQLite commit durability cannot be determined."""


class MissingLockConfigurationError(PersistenceAppendError):
    """Raised when lock_file_path is missing, empty, or invalid."""


@dataclasses.dataclass(frozen=True)
class AppendResult:
    """Structured result returned upon successful, durable event append."""
    ledger_id: str
    segment_sequence: int
    event_id: str
    byte_offset: int
    record_length: int
    entry_hash: str
    prev_event_hash: str
    new_contiguous_watermark: int


@dataclasses.dataclass(frozen=True)
class VerifiedAppendState:
    """Bounded metadata returned by verify_append_state."""
    watermark_offset: int
    prev_event_hash: str


def canonical_json_serialize(record_payload: Dict[str, Any]) -> bytes:
    """
    Serializes a dictionary payload into deterministic canonical JSON bytes.
    Enforces sorted keys, no whitespace outside strings (separators=(',', ':')),
    UTF-8 encoding, and rejection of non-finite floating point numbers (NaN, Inf).

    Args:
        record_payload: JSON-serializable dictionary.

    Returns:
        Canonical UTF-8 encoded bytes.

    Raises:
        InvalidPayloadError: If the payload cannot be canonically serialized.
    """
    if not isinstance(record_payload, dict):
        raise InvalidPayloadError(f"Record payload must be a dict, got {type(record_payload).__name__}")

    def _validate_finite(val: Any) -> None:
        if isinstance(val, float) and not math.isfinite(val):
            raise InvalidPayloadError(f"Non-finite float value {val} is prohibited in canonical JSON.")
        if isinstance(val, dict):
            for k, v in val.items():
                if not isinstance(k, str):
                    raise InvalidPayloadError(f"Dictionary keys must be strings, got {type(k).__name__}")
                _validate_finite(v)
        elif isinstance(val, (list, tuple)):
            for item in val:
                _validate_finite(item)

    _validate_finite(record_payload)

    try:
        serialized = json.dumps(
            record_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return serialized.encode("utf-8")
    except Exception as exc:
        raise InvalidPayloadError(f"Failed to canonicalize payload: {exc}") from exc


@contextlib.contextmanager
def acquire_writer_lock(lock_file_path: str) -> Generator[int, None, None]:
    """
    Acquires an exclusive OS-level advisory lock (fcntl.flock) for single-writer coordination.
    File descriptor is opened with O_CLOEXEC. Lock is guaranteed released on context exit.

    Args:
        lock_file_path: Filepath to the dedicated lock file. Must be non-empty string.

    Yields:
        Open file descriptor for the lock file.

    Raises:
        MissingLockConfigurationError: If lock_file_path is missing, empty, or invalid.
    """
    if not isinstance(lock_file_path, str) or not lock_file_path.strip():
        raise MissingLockConfigurationError(
            f"lock_file_path must be a non-empty string, got {lock_file_path!r}"
        )

    parent_dir = os.path.dirname(os.path.abspath(lock_file_path))
    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)

    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(lock_file_path, flags, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield fd
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def verify_append_state(
    ledger_id: str,
    segment_sequence: int,
    segment_fd: int,
    db_conn: sqlite3.Connection,
) -> VerifiedAppendState:
    """
    Performs bounded O(1) append-time verification of the active segment tail.
    Does not scan, read, or hash historical records preceding the tail record.

    Steps:
      1. Retrieve committed watermark and sealed status from segment_watermarks.
      2. Verify segment is active in ledger_metadata and not sealed.
      3. Verify physical file size equals committed watermark.
      4. Query only the most recent committed index entry (tail entry) via index.
      5. If no records exist, verify watermark is 0 and prev_event_hash is all-zeroes.
      6. If tail record exists, verify tail offset + length terminates exactly at watermark.
      7. Read only the tail record's physical bytes from disk.
      8. Verify tail newline termination and SHA-256 digest against indexed entry_hash.
      9. Return VerifiedAppendState with watermark and tail's entry_hash as prev_event_hash.

    Args:
        ledger_id: Target ledger identifier.
        segment_sequence: Target segment sequence.
        segment_fd: Open writable file descriptor for the segment log file.
        db_conn: Active SQLite connection.

    Returns:
        VerifiedAppendState with verified watermark_offset and prev_event_hash.

    Raises:
        SegmentNotActiveError: If segment is sealed or not the active segment.
        UnresolvedGapError: If physical file EOF does not equal the committed watermark.
        FatalCommittedDataCorruptionError: If tail record bytes are corrupt or inconsistent.
    """
    cursor = db_conn.execute(
        """SELECT contiguous_watermark_offset, is_sealed
           FROM segment_watermarks
           WHERE ledger_id = ? AND segment_sequence = ?;""",
        (ledger_id, segment_sequence),
    )
    row = cursor.fetchone()
    if not row:
        watermark_offset = 0
        is_sealed = 0
    else:
        watermark_offset, is_sealed = row

    if is_sealed:
        raise SegmentNotActiveError(f"Segment {segment_sequence} of ledger {ledger_id} is sealed.")

    cursor = db_conn.execute(
        "SELECT active_segment_sequence FROM ledger_metadata WHERE ledger_id = ?;",
        (ledger_id,),
    )
    meta_row = cursor.fetchone()
    if meta_row and meta_row[0] != segment_sequence:
        raise SegmentNotActiveError(
            f"Segment {segment_sequence} is not the active segment (active is {meta_row[0]})."
        )

    file_size = os.fstat(segment_fd).st_size
    if file_size != watermark_offset:
        raise UnresolvedGapError(
            f"Physical file size {file_size} does not match committed watermark {watermark_offset}."
        )

    # Query ONLY the single most recent committed index entry (tail record)
    cursor = db_conn.execute(
        """SELECT byte_offset, record_length, entry_hash, event_id
           FROM seen_events
           WHERE ledger_id = ? AND segment_sequence = ?
           ORDER BY byte_offset DESC LIMIT 1;""",
        (ledger_id, segment_sequence),
    )
    tail_row = cursor.fetchone()

    if tail_row is None:
        if watermark_offset != 0:
            raise FatalCommittedDataCorruptionError(
                f"No records indexed for segment {segment_sequence}, but watermark is {watermark_offset}."
            )
        return VerifiedAppendState(watermark_offset=0, prev_event_hash="0" * 64)

    tail_offset, tail_length, tail_expected_hash, tail_event_id = tail_row

    if tail_offset + tail_length != watermark_offset:
        raise FatalCommittedDataCorruptionError(
            f"Tail record {tail_event_id} terminates at {tail_offset + tail_length}, "
            f"which does not match committed watermark {watermark_offset}."
        )

    os.lseek(segment_fd, tail_offset, os.SEEK_SET)
    tail_bytes = os.read(segment_fd, tail_length)

    if len(tail_bytes) != tail_length or not tail_bytes.endswith(b"\n"):
        raise FatalCommittedDataCorruptionError(
            f"Tail record {tail_event_id} at offset {tail_offset} is truncated or lacks trailing newline."
        )

    computed_hash = hashlib.sha256(tail_bytes[:-1]).hexdigest()
    if computed_hash != tail_expected_hash:
        raise FatalCommittedDataCorruptionError(
            f"Tail record {tail_event_id} at offset {tail_offset} has hash mismatch: "
            f"DB {tail_expected_hash} vs Disk {computed_hash}."
        )

    return VerifiedAppendState(
        watermark_offset=watermark_offset,
        prev_event_hash=tail_expected_hash,
    )


def reconcile_active_segment(
    ledger_id: str,
    segment_sequence: int,
    segment_fd: int,
    db_conn: sqlite3.Connection,
) -> int:
    """
    Performs full O(N) integrity reconciliation over every committed record in the active segment.
    Used for startup recovery, disaster repair, and explicit integrity auditing.

    Steps:
      1. Retrieve all committed index entries for the specified segment in ascending byte offset order.
      2. Verify that each indexed byte range exists in the physical segment.
      3. Verify record boundaries, contiguous offsets, and newline termination.
      4. Recompute and compare each record's SHA-256 digest against its stored entry_hash.
      5. Verify the final committed watermark equals the end offset of the last record.
      6. If physical EOF exceeds committed watermark, truncate trailing uncommitted bytes and fdatasync().
      7. Fail closed (FatalCommittedDataCorruptionError) if committed records are missing, corrupted, or gapped.

    Args:
        ledger_id: Target ledger identifier.
        segment_sequence: Target segment sequence.
        segment_fd: Open writable file descriptor to the segment file.
        db_conn: SQLite connection to the persistence database.

    Returns:
        Current verified contiguous watermark byte offset.

    Raises:
        FatalCommittedDataCorruptionError: If committed records are missing or corrupted on disk.
        ReconciliationError: If metadata state is inconsistent.
    """
    cursor = db_conn.execute(
        """SELECT contiguous_watermark_offset, is_sealed
           FROM segment_watermarks
           WHERE ledger_id = ? AND segment_sequence = ?;""",
        (ledger_id, segment_sequence),
    )
    row = cursor.fetchone()
    if not row:
        watermark_offset = 0
        is_sealed = 0
    else:
        watermark_offset, is_sealed = row

    if is_sealed:
        raise SegmentNotActiveError(f"Segment {segment_sequence} of ledger {ledger_id} is sealed.")

    file_size = os.fstat(segment_fd).st_size
    if watermark_offset > file_size:
        raise FatalCommittedDataCorruptionError(
            f"Committed watermark {watermark_offset} exceeds physical file size {file_size}."
        )

    # Retrieve ALL committed records for full verification
    cursor = db_conn.execute(
        """SELECT byte_offset, record_length, entry_hash, event_id
           FROM seen_events
           WHERE ledger_id = ? AND segment_sequence = ?
           ORDER BY byte_offset ASC;""",
        (ledger_id, segment_sequence),
    )
    indexed_records = cursor.fetchall()

    expected_offset = 0
    for offset, length, expected_hash, event_id in indexed_records:
        if offset != expected_offset:
            raise FatalCommittedDataCorruptionError(
                f"Unresolved gap in committed index: expected offset {expected_offset}, found {offset}."
            )
        if offset + length > file_size:
            raise FatalCommittedDataCorruptionError(
                f"Record {event_id} at offset {offset} extends beyond physical file size {file_size}."
            )

        os.lseek(segment_fd, offset, os.SEEK_SET)
        record_bytes = os.read(segment_fd, length)
        if len(record_bytes) != length or not record_bytes.endswith(b"\n"):
            raise FatalCommittedDataCorruptionError(
                f"Record {event_id} at offset {offset} is truncated or lacks trailing newline."
            )

        computed_hash = hashlib.sha256(record_bytes[:-1]).hexdigest()
        if computed_hash != expected_hash:
            raise FatalCommittedDataCorruptionError(
                f"Record {event_id} at offset {offset} has hash mismatch: "
                f"DB {expected_hash} vs Disk {computed_hash}."
            )

        expected_offset += length

    if expected_offset != watermark_offset:
        raise FatalCommittedDataCorruptionError(
            f"End of verified records {expected_offset} does not equal committed watermark {watermark_offset}."
        )

    # Handle trailing bytes past watermark_offset
    if file_size > watermark_offset:
        os.ftruncate(segment_fd, watermark_offset)
        os.fdatasync(segment_fd)

    return watermark_offset


def _write_all(fd: int, data: bytes) -> None:
    """Writes all bytes to fd, handling partial writes."""
    total_written = 0
    total_len = len(data)
    while total_written < total_len:
        written = os.write(fd, data[total_written:])
        if written <= 0:
            raise OSError("Zero bytes written; disk full or stream closed.")
        total_written += written


def _recover_indeterminate_commit(
    db_path: str,
    ledger_id: str,
    segment_sequence: int,
    event_id: str,
    byte_offset: int,
    record_length: int,
    entry_hash: str,
    segment_fd: int,
    original_watermark: int,
) -> Optional[AppendResult]:
    """
    Inspects database state using a fresh SQLite connection after an indeterminate commit.
    Returns AppendResult if the transaction succeeded, or rolls back/truncates if not.
    """
    fresh_conn = open_database(db_path)
    try:
        cursor = fresh_conn.execute(
            """SELECT segment_sequence, byte_offset, record_length, entry_hash, prev_event_hash
               FROM seen_events
               WHERE ledger_id = ? AND event_id = ?;""",
            (ledger_id, event_id),
        )
        rec = cursor.fetchone()

        cursor = fresh_conn.execute(
            """SELECT contiguous_watermark_offset
               FROM segment_watermarks
               WHERE ledger_id = ? AND segment_sequence = ?;""",
            (ledger_id, segment_sequence),
        )
        wm_row = cursor.fetchone()
        wm_offset = wm_row[0] if wm_row else None

        if rec is not None:
            r_seq, r_off, r_len, r_hash, r_prev = rec
            if (
                r_seq == segment_sequence
                and r_off == byte_offset
                and r_len == record_length
                and r_hash == entry_hash
                and wm_offset == byte_offset + record_length
            ):
                return AppendResult(
                    ledger_id=ledger_id,
                    segment_sequence=segment_sequence,
                    event_id=event_id,
                    byte_offset=byte_offset,
                    record_length=record_length,
                    entry_hash=entry_hash,
                    prev_event_hash=r_prev,
                    new_contiguous_watermark=wm_offset,
                )
            else:
                raise FatalCommittedDataCorruptionError(
                    f"Indeterminate commit resulted in inconsistent database state for event {event_id}."
                )

        if wm_offset == original_watermark:
            os.ftruncate(segment_fd, original_watermark)
            os.fdatasync(segment_fd)
            return None
        else:
            raise FatalCommittedDataCorruptionError(
                f"Transaction aborted but watermark advanced to {wm_offset} (expected {original_watermark})."
            )
    finally:
        fresh_conn.close()


def append_event(
    ledger_id: str,
    segment_sequence: int,
    event_id: str,
    payload: Dict[str, Any],
    segment_fd: int,
    db_conn: sqlite3.Connection,
    lock_file_path: str,
    db_path: Optional[str] = None,
) -> AppendResult:
    """
    Appends an event record durably to the active segment and indexes it in SQLite.
    Requires mandatory exclusive writer locking (lock_file_path).
    Executes bounded O(1) tail verification instead of full historical reconciliation.

    Ordering:
      1. Acquire mandatory exclusive single-writer lock.
      2. Ensure ledger_metadata and segment_watermarks records exist.
      3. Execute bounded append-state verification (tail record only).
      4. Verify event_id is not already committed.
      5. Compute canonical JSON and entry hash.
      6. Append physical bytes to segment file at watermark.
      7. Execute fdatasync(segment_fd).
      8. Begin SQLite IMMEDIATE transaction.
      9. Insert seen_events row.
      10. Advance segment_watermarks row.
      11. Commit SQLite transaction.
      12. Return AppendResult to caller.

    Args:
        ledger_id: Ledger identifier.
        segment_sequence: Active segment sequence number.
        event_id: Unique event identifier.
        payload: Event payload dictionary.
        segment_fd: Open writable file descriptor for the segment log file.
        db_conn: Active SQLite connection.
        lock_file_path: Mandatory filepath to dedicated lockfile. Cannot be None or empty.
        db_path: Optional path to SQLite DB file (auto-discovered from db_conn via PRAGMA database_list if omitted).

    Returns:
        AppendResult confirming durable persistence and commitment.

    Raises:
        MissingLockConfigurationError: If lock_file_path is missing, None, or empty string.
        DuplicateEventError: If event_id has already been committed in this ledger.
        InvalidPayloadError: If payload or event_id is malformed.
        SegmentNotActiveError: If segment is sealed or non-active.
        UnresolvedGapError: If physical EOF does not match committed watermark.
        FatalCommittedDataCorruptionError: If committed data is corrupted.
        PersistenceAppendError: On physical I/O or SQLite execution failure.
    """
    # Mandatory writer lock path validation before any action
    if not isinstance(lock_file_path, str) or not lock_file_path.strip():
        raise MissingLockConfigurationError(
            f"Mandatory lock_file_path must be a non-empty string, got {lock_file_path!r}"
        )

    if not isinstance(event_id, str) or not event_id.strip():
        raise InvalidPayloadError(f"event_id must be a non-empty string, got {event_id!r}")

    canonical_payload_bytes = canonical_json_serialize(payload)
    entry_hash = hashlib.sha256(canonical_payload_bytes).hexdigest()

    line_bytes = canonical_payload_bytes + b"\n"
    record_length = len(line_bytes)

    with acquire_writer_lock(lock_file_path):
        # Step 1: Ensure ledger_metadata and segment_watermarks exist if uninitialized
        with transaction(db_conn):
            db_conn.execute(
                """INSERT INTO ledger_metadata (ledger_id, active_segment_sequence, created_at_utc, updated_at_utc)
                   VALUES (?, ?, datetime('now', 'utc'), datetime('now', 'utc'))
                   ON CONFLICT(ledger_id) DO UPDATE SET updated_at_utc = datetime('now', 'utc');""",
                (ledger_id, segment_sequence),
            )
            db_conn.execute(
                """INSERT INTO segment_watermarks
                   (ledger_id, segment_sequence, contiguous_watermark_offset, is_sealed, updated_at_utc)
                   VALUES (?, ?, 0, 0, datetime('now', 'utc'))
                   ON CONFLICT(ledger_id, segment_sequence) DO NOTHING;""",
                (ledger_id, segment_sequence),
            )

        # Step 2: Bounded O(1) append state verification (inspects only tail record)
        state = verify_append_state(
            ledger_id=ledger_id,
            segment_sequence=segment_sequence,
            segment_fd=segment_fd,
            db_conn=db_conn,
        )
        watermark_offset = state.watermark_offset
        prev_event_hash = state.prev_event_hash

        # Step 3: Check for duplicate event_id
        cursor = db_conn.execute(
            "SELECT segment_sequence, byte_offset, entry_hash FROM seen_events WHERE ledger_id = ? AND event_id = ?;",
            (ledger_id, event_id),
        )
        existing = cursor.fetchone()
        if existing:
            raise DuplicateEventError(
                f"Event {event_id} already exists in ledger {ledger_id} at segment {existing[0]} offset {existing[1]}."
            )

        # Step 4: Write physical record to segment file at watermark_offset
        os.lseek(segment_fd, watermark_offset, os.SEEK_SET)
        try:
            _write_all(segment_fd, line_bytes)
        except Exception as exc:
            os.ftruncate(segment_fd, watermark_offset)
            os.fdatasync(segment_fd)
            raise PersistenceAppendError(f"Failed writing record to segment: {exc}") from exc

        # Step 5: Force physical durability
        os.fdatasync(segment_fd)

        # Step 6: Commit to SQLite atomically (seen_events + segment_watermarks)
        new_watermark = watermark_offset + record_length

        try:
            with transaction(db_conn):
                db_conn.execute(
                    """INSERT INTO seen_events
                       (ledger_id, event_id, segment_sequence, byte_offset, record_length, entry_hash, prev_event_hash, appended_at_utc)
                       VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', 'utc'));""",
                    (
                        ledger_id,
                        event_id,
                        segment_sequence,
                        watermark_offset,
                        record_length,
                        entry_hash,
                        prev_event_hash,
                    ),
                )
                db_conn.execute(
                    """UPDATE segment_watermarks
                       SET contiguous_watermark_offset = ?, updated_at_utc = datetime('now', 'utc')
                       WHERE ledger_id = ? AND segment_sequence = ?;""",
                    (new_watermark, ledger_id, segment_sequence),
                )
        except Exception as commit_exc:
            # Check transaction state of original connection before attempting any destructive recovery
            try:
                orig_in_transaction = bool(db_conn.in_transaction)
            except Exception as check_exc:
                # If transaction state cannot be established, fail closed immediately
                raise IndeterminateCommitError(
                    f"Failed establishing transaction state on original connection: {check_exc}. Primary error: {commit_exc}"
                ) from commit_exc

            # If original connection remains inside an unresolved transaction, do NOT truncate
            if orig_in_transaction:
                raise IndeterminateCommitError(
                    f"Original SQLite connection remains inside an unresolved transaction after error. "
                    f"Physical ledger truncation blocked to prevent corruption: {commit_exc}"
                ) from commit_exc

            # Auto-resolve db_path from db_conn if not explicitly passed
            effective_db_path = db_path
            if not effective_db_path:
                try:
                    rows = db_conn.execute("PRAGMA database_list;").fetchall()
                    for _, name, file_path in rows:
                        if name == "main" and file_path:
                            effective_db_path = file_path
                            break
                except Exception:
                    effective_db_path = None

            if effective_db_path:
                recovered = _recover_indeterminate_commit(
                    db_path=effective_db_path,
                    ledger_id=ledger_id,
                    segment_sequence=segment_sequence,
                    event_id=event_id,
                    byte_offset=watermark_offset,
                    record_length=record_length,
                    entry_hash=entry_hash,
                    segment_fd=segment_fd,
                    original_watermark=watermark_offset,
                )
                if recovered is not None:
                    return recovered

            # If commit durability cannot be verified via fresh connection, do not assume rollback
            if not effective_db_path:
                raise IndeterminateCommitError(
                    f"SQLite transaction outcome indeterminate and db_path unresolvable: {commit_exc}"
                ) from commit_exc

            # Truncation is safe ONLY when transaction is confirmed resolved and uncommitted
            os.ftruncate(segment_fd, watermark_offset)
            os.fdatasync(segment_fd)
            raise PersistenceAppendError(f"SQLite transaction failed: {commit_exc}") from commit_exc

        return AppendResult(
            ledger_id=ledger_id,
            segment_sequence=segment_sequence,
            event_id=event_id,
            byte_offset=watermark_offset,
            record_length=record_length,
            entry_hash=entry_hash,
            prev_event_hash=prev_event_hash,
            new_contiguous_watermark=new_watermark,
        )
