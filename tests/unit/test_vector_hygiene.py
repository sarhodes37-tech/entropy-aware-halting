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
