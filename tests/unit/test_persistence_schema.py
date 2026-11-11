"""
Unit Tests for SQLite Persistence Schema and Transaction Layer.
Baseline: EpistemicOS Persistence Architecture Specification v5.1.1 (Phase 1).
"""

import os
import sqlite3
import tempfile
import pytest

from epistemicos.persistence.schema import (
    initialize_database,
    open_database,
    get_schema_version,
    SCHEMA_VERSION,
    transaction,
    SchemaVersionError,
    TransactionError,
)


@pytest.fixture
def temp_db_path():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    yield path
    for ext in ("", "-wal", "-shm"):
        p = path + ext
        if os.path.exists(p):
            try:
                os.unlink(p)
            except OSError:
                pass


def test_initialize_new_database(temp_db_path):
    """Verify new database initializes cleanly with target version and tables."""
    conn = initialize_database(temp_db_path)
    try:
        assert get_schema_version(conn) == SCHEMA_VERSION

        # Verify all required tables exist
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
            ).fetchall()
        ]
        assert "ledger_metadata" in tables
        assert "segment_watermarks" in tables
        assert "seen_events" in tables
        assert "schema_migrations" in tables
    finally:
        conn.close()


def test_idempotent_initialization(temp_db_path):
    """Verify repeated initialization on an already-initialized database is non-destructive and idempotent."""
    conn1 = initialize_database(temp_db_path)
    # Insert dummy metadata record
    with transaction(conn1):
        conn1.execute(
            """INSERT INTO ledger_metadata (ledger_id, active_segment_sequence, manifest_generation, checkpoint_sequence, created_at_utc, updated_at_utc)
               VALUES (?, 0, 0, 0, datetime('now'), datetime('now'));""",
            ("test_ledger",),
        )
    conn1.close()

    # Re-initialize on existing database
    conn2 = initialize_database(temp_db_path)
    try:
        assert get_schema_version(conn2) == SCHEMA_VERSION
        row = conn2.execute("SELECT ledger_id FROM ledger_metadata;").fetchone()
        assert row is not None
        assert row[0] == "test_ledger"
    finally:
        conn2.close()


def test_wal_mode_and_durability_pragmas(temp_db_path):
    """Verify PRAGMA journal_mode is WAL and synchronous is FULL (2)."""
    conn = initialize_database(temp_db_path)
    try:
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert journal_mode.upper() == "WAL"

        synchronous = conn.execute("PRAGMA synchronous;").fetchone()[0]
        # In SQLite: 0=OFF, 1=NORMAL, 2=FULL, 3=EXTRA
        assert synchronous == 2

        foreign_keys = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
        assert foreign_keys == 1

        busy_timeout = conn.execute("PRAGMA busy_timeout;").fetchone()[0]
        assert busy_timeout >= 5000
    finally:
        conn.close()


def test_foreign_key_and_constraint_enforcement(temp_db_path):
    """Verify segment-scoped watermark references and check constraints."""
    conn = initialize_database(temp_db_path)
    try:
        with transaction(conn):
            conn.execute(
                """INSERT INTO ledger_metadata (ledger_id, active_segment_sequence, created_at_utc, updated_at_utc)
                   VALUES ('audit_ledger', 0, datetime('now'), datetime('now'));"""
            )
            conn.execute(
                """INSERT INTO segment_watermarks (ledger_id, segment_sequence, contiguous_watermark_offset, updated_at_utc)
                   VALUES ('audit_ledger', 0, 0, datetime('now'));"""
            )

        # Foreign key violation: segment_watermarks referencing non-existent ledger
        with pytest.raises(sqlite3.IntegrityError):
            with transaction(conn):
                conn.execute(
                    """INSERT INTO segment_watermarks (ledger_id, segment_sequence, contiguous_watermark_offset, updated_at_utc)
                       VALUES ('missing_ledger', 0, 0, datetime('now'));"""
                )

        # Constraint violation: negative offset
        with pytest.raises(sqlite3.IntegrityError):
            with transaction(conn):
                conn.execute(
                    """INSERT INTO segment_watermarks (ledger_id, segment_sequence, contiguous_watermark_offset, updated_at_utc)
                       VALUES ('audit_ledger', 1, -10, datetime('now'));"""
                )

        # Unique constraint on seen_events (ledger_id, segment_sequence, byte_offset)
        valid_hash = "a" * 64
        with transaction(conn):
            conn.execute(
                """INSERT INTO seen_events (ledger_id, event_id, segment_sequence, byte_offset, record_length, entry_hash, appended_at_utc)
                   VALUES ('audit_ledger', 'ev_001', 0, 0, 100, ?, datetime('now'));""",
                (valid_hash,),
            )

        # Attempt duplicate event_id
        with pytest.raises(sqlite3.IntegrityError):
            with transaction(conn):
                conn.execute(
                    """INSERT INTO seen_events (ledger_id, event_id, segment_sequence, byte_offset, record_length, entry_hash, appended_at_utc)
                       VALUES ('audit_ledger', 'ev_001', 0, 100, 100, ?, datetime('now'));""",
                    (valid_hash,),
                )

        # Attempt duplicate byte offset within same segment
        with pytest.raises(sqlite3.IntegrityError):
            with transaction(conn):
                conn.execute(
                    """INSERT INTO seen_events (ledger_id, event_id, segment_sequence, byte_offset, record_length, entry_hash, appended_at_utc)
                       VALUES ('audit_ledger', 'ev_002', 0, 0, 100, ?, datetime('now'));""",
                    (valid_hash,),
                )

        # Invalid entry_hash length
        with pytest.raises(sqlite3.IntegrityError):
            with transaction(conn):
                conn.execute(
                    """INSERT INTO seen_events (ledger_id, event_id, segment_sequence, byte_offset, record_length, entry_hash, appended_at_utc)
                       VALUES ('audit_ledger', 'ev_003', 0, 200, 100, 'short_hash', datetime('now'));"""
                )
    finally:
        conn.close()


def test_explicit_transaction_commit_and_rollback(temp_db_path):
    """Verify transaction helper commits on success and rolls back on exception."""
    conn = initialize_database(temp_db_path)
    try:
        # Commit behavior
        with transaction(conn):
            conn.execute(
                """INSERT INTO ledger_metadata (ledger_id, active_segment_sequence, created_at_utc, updated_at_utc)
                   VALUES ('commit_ledger', 0, datetime('now'), datetime('now'));"""
            )

        row = conn.execute("SELECT ledger_id FROM ledger_metadata WHERE ledger_id = 'commit_ledger';").fetchone()
        assert row is not None

        # Rollback behavior
        with pytest.raises(RuntimeError, match="Intentional failure"):
            with transaction(conn):
                conn.execute(
                    """INSERT INTO ledger_metadata (ledger_id, active_segment_sequence, created_at_utc, updated_at_utc)
                       VALUES ('rollback_ledger', 0, datetime('now'), datetime('now'));"""
                )
                raise RuntimeError("Intentional failure")

        row = conn.execute("SELECT ledger_id FROM ledger_metadata WHERE ledger_id = 'rollback_ledger';").fetchone()
        assert row is None
        assert not conn.in_transaction
    finally:
        conn.close()


def test_nested_transaction_rejection(temp_db_path):
    """Verify attempting nested transactions raises TransactionError without silent deferred fallback."""
    conn = initialize_database(temp_db_path)
    try:
        with transaction(conn):
            with pytest.raises(TransactionError, match="Nested transactions are not supported"):
                with transaction(conn):
                    pass
    finally:
        conn.close()


def test_newer_schema_version_rejection(temp_db_path):
    """Verify opening a database with a schema version newer than supported raises SchemaVersionError."""
    conn = initialize_database(temp_db_path)
    # Artificially insert a future schema version
    with transaction(conn):
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at_utc, description) VALUES (?, datetime('now'), ?);",
            (SCHEMA_VERSION + 1, "Future schema version"),
        )
    conn.close()

    with pytest.raises(SchemaVersionError, match="newer than supported"):
        initialize_database(temp_db_path)
