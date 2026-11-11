"""
SQLite Persistence Schema and Initialization Layer for EpistemicOS.

Baseline: Persistence Architecture Specification v5.1.1 (Phase 1)
Enforces:
  - SQLite WAL mode (PRAGMA journal_mode = WAL)
  - Synchronous durability (PRAGMA synchronous = FULL)
  - Foreign key constraints (PRAGMA foreign_keys = ON)
  - Busy timeout handling (PRAGMA busy_timeout = 5000)
  - Explicit BEGIN IMMEDIATE transactions with safe rollback
  - Unambiguous segment-scoped watermark representation via `segment_watermarks` table
  - Non-destructive idempotent initialization
"""

import contextlib
import os
import sqlite3
from typing import Generator, Optional

SCHEMA_VERSION = 1

# Database DDL statements
SCHEMA_MIGRATIONS_DDL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at_utc TEXT NOT NULL,
    description TEXT NOT NULL
);
"""

LEDGER_METADATA_DDL = """
CREATE TABLE IF NOT EXISTS ledger_metadata (
    ledger_id TEXT PRIMARY KEY,
    active_segment_sequence INTEGER NOT NULL DEFAULT 0,
    manifest_generation INTEGER NOT NULL DEFAULT 0,
    checkpoint_sequence INTEGER NOT NULL DEFAULT 0,
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    CONSTRAINT chk_seq_nonneg CHECK (active_segment_sequence >= 0),
    CONSTRAINT chk_gen_nonneg CHECK (manifest_generation >= 0),
    CONSTRAINT chk_chkseq_nonneg CHECK (checkpoint_sequence >= 0)
) WITHOUT ROWID;
"""

# Segment-scoped watermark representation:
# Resolves the v5.1.1 ambiguity between per-segment watermarks and global queries.
# Each segment sequence within a ledger maintains its own exact byte watermark offset.
SEGMENT_WATERMARKS_DDL = """
CREATE TABLE IF NOT EXISTS segment_watermarks (
    ledger_id TEXT NOT NULL,
    segment_sequence INTEGER NOT NULL,
    contiguous_watermark_offset INTEGER NOT NULL DEFAULT 0,
    is_sealed INTEGER NOT NULL DEFAULT 0,
    sealed_at_utc TEXT,
    updated_at_utc TEXT NOT NULL,
    PRIMARY KEY (ledger_id, segment_sequence),
    FOREIGN KEY (ledger_id) REFERENCES ledger_metadata (ledger_id) ON DELETE RESTRICT,
    CONSTRAINT chk_offset_nonneg CHECK (contiguous_watermark_offset >= 0),
    CONSTRAINT chk_sealed_bool CHECK (is_sealed IN (0, 1))
) WITHOUT ROWID;
"""

SEEN_EVENTS_DDL = """
CREATE TABLE IF NOT EXISTS seen_events (
    ledger_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    segment_sequence INTEGER NOT NULL,
    byte_offset INTEGER NOT NULL,
    record_length INTEGER NOT NULL,
    entry_hash TEXT NOT NULL,
    prev_event_hash TEXT NOT NULL DEFAULT '',
    appended_at_utc TEXT NOT NULL,
    PRIMARY KEY (ledger_id, event_id),
    CONSTRAINT uq_segment_offset UNIQUE (ledger_id, segment_sequence, byte_offset),
    FOREIGN KEY (ledger_id, segment_sequence)
        REFERENCES segment_watermarks (ledger_id, segment_sequence) ON DELETE RESTRICT,
    CONSTRAINT chk_byte_offset_nonneg CHECK (byte_offset >= 0),
    CONSTRAINT chk_record_length_pos CHECK (record_length > 0),
    CONSTRAINT chk_entry_hash_format CHECK (length(entry_hash) == 64)
) WITHOUT ROWID;
"""

INDEXES_DDL = """
CREATE INDEX IF NOT EXISTS idx_seen_events_segment_offset
ON seen_events (ledger_id, segment_sequence, byte_offset);
"""


class PersistenceDatabaseError(Exception):
    """Base exception for persistence database errors."""


class SchemaVersionError(PersistenceDatabaseError):
    """Raised when an unsupported or newer schema version is detected."""


class TransactionError(PersistenceDatabaseError):
    """Raised when a transaction error occurs."""


class RollbackFailedError(TransactionError):
    """Raised when rolling back a transaction fails after an execution error."""
    def __init__(self, message: str, original_exception: Exception, rollback_exception: Exception):
        super().__init__(message)
        self.original_exception = original_exception
        self.rollback_exception = rollback_exception


def configure_pragmas(conn: sqlite3.Connection) -> None:
    """
    Applies mandatory SQLite PRAGMAs for durability, concurrency, and integrity.

    Args:
        conn: Open sqlite3.Connection.
    """
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = FULL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA busy_timeout = 5000;")


def open_database(database_path: str) -> sqlite3.Connection:
    """
    Opens an SQLite connection with autocommit disabled (isolation_level=None)
    so transactions are controlled explicitly with BEGIN IMMEDIATE.

    Args:
        database_path: Path to the SQLite database file, or ':memory:'.

    Returns:
        Configured sqlite3.Connection.
    """
    if database_path != ":memory:":
        parent_dir = os.path.dirname(os.path.abspath(database_path))
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)

    # isolation_level=None puts sqlite3 in manual transaction mode
    conn = sqlite3.connect(
        database_path,
        isolation_level=None,
        timeout=5.0,
        check_same_thread=True,
    )
    configure_pragmas(conn)
    return conn


def get_schema_version(conn: sqlite3.Connection) -> int:
    """
    Reads the highest recorded schema version from schema_migrations.

    Returns:
        Integer schema version, or 0 if uninitialized.
    """
    # Check if schema_migrations table exists
    cursor = conn.execute(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations';"
    )
    if cursor.fetchone()[0] == 0:
        return 0

    cursor = conn.execute(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations;"
    )
    row = cursor.fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def initialize_database(
    database_path: str,
    target_version: int = SCHEMA_VERSION,
) -> sqlite3.Connection:
    """
    Idempotently initializes the SQLite database schema up to target_version.
    Does not drop or recreate existing data. Fails closed if a newer version exists.

    Args:
        database_path: Filepath or ':memory:'.
        target_version: Desired schema version (defaults to current SCHEMA_VERSION).

    Returns:
        sqlite3.Connection connected to initialized database.

    Raises:
        SchemaVersionError: If database has a version higher than target_version.
    """
    conn = open_database(database_path)

    current_ver = get_schema_version(conn)
    if current_ver > target_version:
        conn.close()
        raise SchemaVersionError(
            f"Database schema version {current_ver} is newer than supported {target_version}."
        )

    if current_ver == target_version:
        # Already fully initialized and idempotent
        return conn

    # Apply schema version 1 inside an explicit IMMEDIATE transaction
    with transaction(conn):
        conn.execute(SCHEMA_MIGRATIONS_DDL)
        conn.execute(LEDGER_METADATA_DDL)
        conn.execute(SEGMENT_WATERMARKS_DDL)
        conn.execute(SEEN_EVENTS_DDL)
        conn.execute(INDEXES_DDL)

        conn.execute(
            """INSERT INTO schema_migrations (version, applied_at_utc, description)
               VALUES (?, datetime('now', 'utc'), ?);""",
            (1, "EpistemicOS persistence schema v1: ledger metadata, segment watermarks, and seen events"),
        )

    return conn


@contextlib.contextmanager
def transaction(conn: sqlite3.Connection) -> Generator[sqlite3.Connection, None, None]:
    """
    Explicit transaction context manager issuing 'BEGIN IMMEDIATE',
    committing on success and rolling back on exceptions without nested transaction ambiguity.

    Usage:
        with transaction(conn):
            conn.execute(...)

    Raises:
        TransactionError: If a transaction is already active on this connection.
    """
    if conn.in_transaction:
        raise TransactionError(
            "Nested transactions are not supported. A transaction is already active on this connection."
        )

    conn.execute("BEGIN IMMEDIATE;")
    try:
        yield conn
        conn.execute("COMMIT;")
    except Exception as primary_exc:
        # Roll back on error, ensuring rollback failure is observable without masking primary error
        try:
            conn.execute("ROLLBACK;")
        except Exception as rb_exc:
            raise RollbackFailedError(
                f"Rollback failed after transaction error ({rb_exc}); connection remains in transaction: {conn.in_transaction}",
                original_exception=primary_exc,
                rollback_exception=rb_exc,
            ) from primary_exc
        raise
