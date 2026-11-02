"""
Unit test suite for VectorHygieneManager middleware.
Validates thread-safe vector staging, commits, revokes, and atomic context management.
"""

from unittest.mock import MagicMock
import pytest

from epistemicos.vector_hygiene import VectorHygieneManager


def test_stage_and_commit():
    """Validates basic vector staging and clean commit."""
    manager = VectorHygieneManager()
    traj_id = "traj_001"

    manager.stage_vectors(traj_id, ["vec_1", "vec_2"])
    assert manager.get_staged_count(traj_id) == 2

    committed = manager.commit_trajectory(traj_id)
    assert committed == ["vec_1", "vec_2"]
    assert manager.get_staged_count(traj_id) == 0


def test_stage_and_revoke_with_mock_db():
    """Validates backend revocation trigger on trajectory failure."""
    mock_db = MagicMock()
    mock_db.delete = MagicMock(return_value=True)

    manager = VectorHygieneManager(db_client=mock_db)
    traj_id = "traj_002"

    manager.stage_vectors(traj_id, ["vec_100", "vec_101"])
    revoked = manager.revoke_trajectory(traj_id, namespace="production")

    assert revoked == ["vec_100", "vec_101"]
    assert manager.get_staged_count(traj_id) == 0
    mock_db.delete.assert_called_once_with(ids=["vec_100", "vec_101"], namespace="production")


def test_trajectory_context_manager_auto_commit():
    """Validates transactional context manager auto-commits on clean exit."""
    manager = VectorHygieneManager()
    traj_id = "traj_ctx_clean"

    with manager.trajectory_scope(traj_id):
        manager.stage_vectors(traj_id, ["vec_a", "vec_b"])
        assert manager.get_staged_count(traj_id) == 2

    assert manager.get_staged_count(traj_id) == 0


def test_trajectory_context_manager_auto_revoke_on_exception():
    """Validates transactional context manager auto-revokes if an exception occurs."""
    mock_db = MagicMock()
    mock_db.delete = MagicMock()
    manager = VectorHygieneManager(db_client=mock_db)
    traj_id = "traj_ctx_error"

    with pytest.raises(RuntimeError):
        with manager.trajectory_scope(traj_id):
            manager.stage_vectors(traj_id, ["vec_err_1"])
            raise RuntimeError("Mid-flight token entropy blowout!")

    assert manager.get_staged_count(traj_id) == 0
    mock_db.delete.assert_called_once_with(ids=["vec_err_1"])

# ==========================================
# COVERAGE GAPS: ADAPTER FALLBACKS & EXCEPTIONS
# ==========================================

def test_purge_vectors_chromadb_interface():
    """Validates fallback to ChromaDB/Qdrant 'delete_vectors' interface."""
    mock_db = MagicMock()
    mock_db.delete_vectors = MagicMock()
    del mock_db.delete  # Erase Pinecone interface to force fallback
    
    manager = VectorHygieneManager(db_client=mock_db)
    manager.adapter.purge_vectors(["vec_1"])
    mock_db.delete_vectors.assert_called_once_with(vector_ids=["vec_1"])


def test_purge_vectors_generic_interface():
    """Validates fallback to generic 'delete_by_ids' interface."""
    mock_db = MagicMock()
    mock_db.delete_by_ids = MagicMock()
    del mock_db.delete
    del mock_db.delete_vectors
    
    manager = VectorHygieneManager(db_client=mock_db)
    manager.adapter.purge_vectors(["vec_1"])
    mock_db.delete_by_ids.assert_called_once_with(["vec_1"])


def test_purge_vectors_no_supported_interface():
    """Validates safe failure when no known deletion methods exist."""
    mock_db = MagicMock()
    del mock_db.delete
    del mock_db.delete_vectors
    del mock_db.delete_by_ids
    
    manager = VectorHygieneManager(db_client=mock_db)
    assert manager.adapter.purge_vectors(["vec_1"]) is False


def test_purge_vectors_exception_handling():
    """Validates exception swallowing during backend outage."""
    mock_db = MagicMock()
    mock_db.delete.side_effect = Exception("Simulated DB Connection Timeout")
    
    manager = VectorHygieneManager(db_client=mock_db)
    assert manager.adapter.purge_vectors(["vec_1"]) is False


def test_purge_vectors_empty_list():
    """Validates early exit when purging an empty array."""
    manager = VectorHygieneManager(db_client=MagicMock())
    assert manager.adapter.purge_vectors([]) is True


def test_purge_vectors_no_db_client():
    """Validates early exit when no db_client is provided."""
    manager = VectorHygieneManager(db_client=None)
    assert manager.adapter.purge_vectors(["vec_1"]) is True


def test_stage_vectors_empty_list():
    """Validates early exit when staging an empty array."""
    manager = VectorHygieneManager()
    manager.stage_vectors("traj_empty", [])
    assert manager.get_staged_count("traj_empty") == 0


def test_commit_unknown_trajectory_returns_empty_list():
    """Validates committing a non-existent or un-staged trajectory returns an empty list."""
    manager = VectorHygieneManager()
    committed = manager.commit_trajectory("non_existent_traj")
    assert committed == []


def test_revoke_unknown_trajectory_returns_empty_list():
    """Validates revoking a non-existent or un-staged trajectory returns an empty list without invoking backend adapter."""
    mock_db = MagicMock()
    manager = VectorHygieneManager(db_client=mock_db)
    revoked = manager.revoke_trajectory("non_existent_traj", namespace="production")
    assert revoked == []
    mock_db.delete.assert_not_called()


def test_get_staged_count_unknown_trajectory_returns_zero():
    """Validates get_staged_count for an unknown trajectory ID returns 0."""
    manager = VectorHygieneManager()
    assert manager.get_staged_count("non_existent_traj") == 0


def test_trajectory_scope_no_vectors_staged():
    """Validates trajectory commit block bypass when count is 0."""
    manager = VectorHygieneManager()
    with manager.trajectory_scope("traj_empty"):
        pass  # Do not stage any vectors
    assert manager.get_staged_count("traj_empty") == 0


def test_revoke_trajectory_backend_failure_quarantines_unpurged_vectors():
    """
    Validates GAP-HALT-07 fix:
    When backend vector purge fails (e.g. timeout or exception swallowed returning False),
    VectorHygieneManager preserves failed vector IDs in the unpurged dead-letter quarantine,
    returns an empty list indicating zero successfully purged vectors, and makes the failed
    IDs observable via get_unpurged_vectors().
    """
    mock_db = MagicMock()
    mock_db.delete.side_effect = Exception("Backend store connection timeout")

    manager = VectorHygieneManager(db_client=mock_db)
    traj_id = "traj_fail_001"
    vectors = ["vec_fail_1", "vec_fail_2"]

    manager.stage_vectors(traj_id, vectors)
    assert manager.get_staged_count(traj_id) == 2

    # Attempt revocation which encounters backend purge failure
    revoked = manager.revoke_trajectory(traj_id, namespace="production")

    # Staged count must be cleared from active tracking
    assert manager.get_staged_count(traj_id) == 0
    # Revoked return must reflect failure (no vectors confirmed revoked)
    assert revoked == []

    # Unpurged vectors must be preserved in quarantine
    unpurged_for_traj = manager.get_unpurged_vectors(traj_id)
    assert unpurged_for_traj == ["vec_fail_1", "vec_fail_2"]

    all_unpurged = manager.get_unpurged_vectors()
    assert traj_id in all_unpurged
    assert all_unpurged[traj_id] == ["vec_fail_1", "vec_fail_2"]

    # Subsequent successful purge clears quarantine
    mock_db.delete.side_effect = None
    mock_db.delete.return_value = True

    manager.stage_vectors(traj_id, ["vec_fail_1", "vec_fail_2"])
    success_revoked = manager.revoke_trajectory(traj_id, namespace="production")
    assert success_revoked == ["vec_fail_1", "vec_fail_2"]
    assert manager.get_unpurged_vectors(traj_id) == []


# =====================================================================
# DETERMINISTIC CONCURRENCY & ADAPTER FAILURE REGRESSION TESTS
# =====================================================================

def test_concurrent_staging_during_successful_purge():
    """
    Validates that vectors staged concurrently while a purge is in flight
    are NOT discarded when the in-flight purge succeeds.
    Uses threading.Event for deterministic synchronization without sleeps.
    """
    import threading

    in_purge_event = threading.Event()
    continue_purge_event = threading.Event()

    def mock_delete(ids, **kwargs):
        in_purge_event.set()
        continue_purge_event.wait(timeout=5)
        return True

    mock_db = MagicMock()
    mock_db.delete = MagicMock(side_effect=mock_delete)

    manager = VectorHygieneManager(db_client=mock_db)
    traj_id = "traj_conc_success"

    # Initial staging
    manager.stage_vectors(traj_id, ["vec_batch1_a", "vec_batch1_b"])
    assert manager.get_staged_count(traj_id) == 2

    revocation_thread_result = []

    def revoker():
        res = manager.revoke_trajectory(traj_id)
        revocation_thread_result.append(res)

    t = threading.Thread(target=revoker)
    t.start()

    # Wait until revoker captures batch and enters adapter.purge_vectors
    assert in_purge_event.wait(timeout=5) is True

    # Concurrently stage new vectors into the same trajectory
    manager.stage_vectors(traj_id, ["vec_batch2_c", "vec_batch2_d"])

    # Release backend purge to complete
    continue_purge_event.set()
    t.join(timeout=5)

    # Invariants:
    # 1. Batch 1 was confirmed revoked
    assert len(revocation_thread_result) == 1
    assert revocation_thread_result[0] == ["vec_batch1_a", "vec_batch1_b"]

    # 2. Concurrently staged vectors in Batch 2 are preserved in active tracking
    assert manager.get_staged_count(traj_id) == 2
    assert manager._active_trajectories[traj_id] == ["vec_batch2_c", "vec_batch2_d"]
    assert manager.get_unpurged_vectors(traj_id) == []


def test_concurrent_staging_during_failed_purge():
    """
    Validates that vectors staged concurrently while a purge is in flight
    are NOT discarded when the in-flight purge fails.
    The failed batch moves to unpurged quarantine, while the concurrent batch remains active.
    Uses threading.Event for deterministic synchronization.
    """
    import threading

    in_purge_event = threading.Event()
    continue_purge_event = threading.Event()

    def mock_delete(ids, **kwargs):
        in_purge_event.set()
        continue_purge_event.wait(timeout=5)
        return False

    mock_db = MagicMock()
    mock_db.delete = MagicMock(side_effect=mock_delete)

    manager = VectorHygieneManager(db_client=mock_db)
    traj_id = "traj_conc_fail"

    manager.stage_vectors(traj_id, ["vec_fail1_a", "vec_fail1_b"])

    revocation_thread_result = []

    def revoker():
        res = manager.revoke_trajectory(traj_id)
        revocation_thread_result.append(res)

    t = threading.Thread(target=revoker)
    t.start()

    assert in_purge_event.wait(timeout=5) is True

    # Concurrent stage
    manager.stage_vectors(traj_id, ["vec_active2_c"])

    continue_purge_event.set()
    t.join(timeout=5)

    # Invariants:
    # 1. Batch 1 failed, so revocation returned []
    assert revocation_thread_result[0] == []

    # 2. Batch 1 preserved in quarantine
    assert manager.get_unpurged_vectors(traj_id) == ["vec_fail1_a", "vec_fail1_b"]

    # 3. Concurrent Batch 2 preserved in active tracking
    assert manager.get_staged_count(traj_id) == 1
    assert manager._active_trajectories[traj_id] == ["vec_active2_c"]


def test_adapter_explicit_false_return_across_interfaces():
    """
    Validates that an explicit backend False is never treated as confirmed deletion across:
    1. Pinecone 'delete'
    2. ChromaDB/Qdrant 'delete_vectors'
    3. Generic 'delete_by_ids'
    """
    # 1. delete returning False
    mock_pinecone = MagicMock()
    mock_pinecone.delete.return_value = False
    manager1 = VectorHygieneManager(db_client=mock_pinecone)
    assert manager1.adapter.purge_vectors(["v1"]) is False

    # 2. delete_vectors returning False
    mock_chroma = MagicMock()
    del mock_chroma.delete
    mock_chroma.delete_vectors.return_value = False
    manager2 = VectorHygieneManager(db_client=mock_chroma)
    assert manager2.adapter.purge_vectors(["v2"]) is False

    # 3. delete_by_ids returning False
    mock_generic = MagicMock()
    del mock_generic.delete
    del mock_generic.delete_vectors
    mock_generic.delete_by_ids.return_value = False
    manager3 = VectorHygieneManager(db_client=mock_generic)
    assert manager3.adapter.purge_vectors(["v3"]) is False


def test_adapter_none_return_success_compatibility():
    """
    Validates backwards-compatibility with backends whose synchronous deletion methods return None
    (e.g., Pinecone delete() returning None on clean execution).
    """
    mock_pinecone = MagicMock()
    mock_pinecone.delete.return_value = None
    manager = VectorHygieneManager(db_client=mock_pinecone)
    assert manager.adapter.purge_vectors(["v1"]) is True


def test_retry_quarantined_vectors_without_restaging():
    """
    Validates retry_quarantined_vectors:
    1. Purge initially fails -> vectors quarantined.
    2. Backend recovers -> retry_quarantined_vectors() purges them without restaging.
    3. Quarantine is cleared.
    """
    mock_db = MagicMock()
    mock_db.delete.return_value = False

    manager = VectorHygieneManager(db_client=mock_db)
    traj_id = "traj_retry_001"

    manager.stage_vectors(traj_id, ["vec_retry_1", "vec_retry_2"])
    revoked = manager.revoke_trajectory(traj_id)
    assert revoked == []
    assert manager.get_unpurged_vectors(traj_id) == ["vec_retry_1", "vec_retry_2"]
    assert manager.get_staged_count(traj_id) == 0

    # Backend recovers
    mock_db.delete.return_value = True

    # Retry without restaging
    retry_results = manager.retry_quarantined_vectors(trajectory_id=traj_id)
    assert traj_id in retry_results
    assert retry_results[traj_id] == ["vec_retry_1", "vec_retry_2"]

    # Quarantine is now clean
    assert manager.get_unpurged_vectors(traj_id) == []


def test_repeated_failed_retry_preserves_quarantined_vectors():
    """
    Validates that repeated failed retries safely preserve quarantined IDs without losing them.
    """
    mock_db = MagicMock()
    mock_db.delete.return_value = False

    manager = VectorHygieneManager(db_client=mock_db)
    traj_id = "traj_repeat_fail"

    manager.stage_vectors(traj_id, ["vec_persist_1"])
    manager.revoke_trajectory(traj_id)

    # First retry fails
    r1 = manager.retry_quarantined_vectors(trajectory_id=traj_id)
    assert r1[traj_id] == []
    assert manager.get_unpurged_vectors(traj_id) == ["vec_persist_1"]

    # Second retry fails
    r2 = manager.retry_quarantined_vectors(trajectory_id=traj_id)
    assert r2[traj_id] == []
    assert manager.get_unpurged_vectors(traj_id) == ["vec_persist_1"]


def test_revoke_trajectory_include_quarantined():
    """
    Validates revoke_trajectory(include_quarantined=True) purges both active staged vectors
    and previously quarantined vectors in a single operation.
    """
    mock_db = MagicMock()
    mock_db.delete.return_value = False

    manager = VectorHygieneManager(db_client=mock_db)
    traj_id = "traj_combo"

    # Batch 1 fails -> quarantined
    manager.stage_vectors(traj_id, ["vec_old_fail"])
    manager.revoke_trajectory(traj_id)
    assert manager.get_unpurged_vectors(traj_id) == ["vec_old_fail"]

    # Batch 2 staged into active
    manager.stage_vectors(traj_id, ["vec_new_active"])
    assert manager.get_staged_count(traj_id) == 1

    # Backend recovers
    mock_db.delete.return_value = True

    # Revoke both
    purged = manager.revoke_trajectory(traj_id, include_quarantined=True)
    assert set(purged) == {"vec_old_fail", "vec_new_active"}
    assert manager.get_staged_count(traj_id) == 0
    assert manager.get_unpurged_vectors(traj_id) == []


# =====================================================================
# ATOMIC ABORT BOUNDARY TESTS (TESTS A, B, C)
# =====================================================================

def test_atomic_abort_boundary_staging_before_abort():
    """
    Test A — staging before abort:
    - Stage Batch A.
    - Abort the trajectory.
    - Verify Batch A remains discoverable and cannot be auto-committed on context exit.
    - Verify cleanup can still revoke it.
    """
    mock_db = MagicMock()
    mock_db.delete.return_value = True

    manager = VectorHygieneManager(db_client=mock_db)
    traj_id = "traj_test_a"

    with manager.trajectory_scope(traj_id):
        manager.stage_vectors(traj_id, ["vec_A_1", "vec_A_2"])
        assert manager.get_staged_count(traj_id) == 2
        manager.abort_trajectory_scope(traj_id)
        assert manager.is_scope_aborted(traj_id) is True

    # Upon context exit, auto-commit was bypassed because scope was aborted
    # Batch A remains in active staging rather than being committed to primary index
    assert manager.get_staged_count(traj_id) == 2

    # Verify cleanup can still revoke Batch A
    revoked = manager.revoke_trajectory(traj_id)
    assert revoked == ["vec_A_1", "vec_A_2"]
    assert manager.get_staged_count(traj_id) == 0


def test_atomic_abort_boundary_staging_after_abort():
    """
    Test B — staging after abort:
    - Abort the trajectory.
    - Attempt to stage Batch B.
    - Verify the operation is explicitly rejected with RuntimeError.
    - Verify Batch B is not silently accepted, discarded, or reported as purged.
    - Verify the rejection is observable to the caller.
    """
    manager = VectorHygieneManager()
    traj_id = "traj_test_b"

    with manager.trajectory_scope(traj_id):
        manager.abort_trajectory_scope(traj_id)
        assert manager.is_scope_aborted(traj_id) is True

        with pytest.raises(RuntimeError, match="Cannot stage vectors for aborted trajectory"):
            manager.stage_vectors(traj_id, ["vec_B_1", "vec_B_2"])

        # Batch B was not accepted into active staging
        assert manager.get_staged_count(traj_id) == 0
        assert manager.get_outstanding_vectors(traj_id) == []


def test_atomic_abort_boundary_concurrent_abort_vs_staging():
    """
    Test C — concurrent abort versus staging:
    - Races stage_vectors() against abort_trajectory_scope() at the manager lock.
    - Uses threading.Barrier for deterministic lock contention.
    - Verifies exactly one valid ordering occurs:
      1) Staging wins lock first: Batch is accepted into active tracking, then abort marks scope; or
      2) Abort wins lock first: Staging is rejected with RuntimeError.
    """
    import threading

    manager = VectorHygieneManager()
    traj_id = "traj_test_c"

    barrier = threading.Barrier(2)
    stage_error = []
    stage_succeeded = []

    def stager():
        try:
            barrier.wait(timeout=5)
            manager.stage_vectors(traj_id, ["vec_race_1", "vec_race_2"])
            stage_succeeded.append(True)
        except Exception as e:
            stage_error.append(e)

    def aborter():
        try:
            barrier.wait(timeout=5)
            manager.abort_trajectory_scope(traj_id)
        except Exception:
            pass

    t1 = threading.Thread(target=stager)
    t2 = threading.Thread(target=aborter)

    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)

    assert t1.is_alive() is False
    assert t2.is_alive() is False

    # Assert exactly one valid outcome occurred
    if stage_succeeded:
        # Staging won the lock first: vectors were accepted and are now outstanding under aborted scope
        assert len(stage_succeeded) == 1
        assert manager.get_staged_count(traj_id) == 2
        assert manager.is_scope_aborted(traj_id) is True
    else:
        # Abort won the lock first: staging was rejected with RuntimeError
        assert len(stage_error) == 1
        assert isinstance(stage_error[0], RuntimeError)
        assert "Cannot stage vectors for aborted trajectory" in str(stage_error[0])
        assert manager.get_staged_count(traj_id) == 0
