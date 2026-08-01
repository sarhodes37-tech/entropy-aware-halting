"""
EpistemicOS Vector Hygiene Middleware.
Prevents State Contagion by transactionally staging, committing, or revoking
vector embeddings generated during active agentic trajectories.
"""

import logging
from threading import RLock
from typing import List, Dict, Any, Optional, Union
from contextlib import contextmanager

logger = logging.getLogger("EpistemicOS.VectorHygiene")


class VectorStoreAdapter:
    """Unified deletion interface supporting standard vector database clients."""

    def __init__(self, db_client: Any = None):
        self.db_client = db_client

    def purge_vectors(self, vector_ids: List[Union[str, int]], namespace: Optional[str] = None) -> bool:
        """Executes deletion across common vector store APIs (Pinecone, ChromaDB, Qdrant, etc.)."""
        if not self.db_client or not vector_ids:
            return True

        try:
            # 1. Pinecone Client Interface
            if hasattr(self.db_client, "delete"):
                if namespace:
                    self.db_client.delete(ids=vector_ids, namespace=namespace)
                else:
                    self.db_client.delete(ids=vector_ids)
                return True

            # 2. ChromaDB / Qdrant Interface
            elif hasattr(self.db_client, "delete_vectors"):
                self.db_client.delete_vectors(vector_ids=vector_ids)
                return True

            # 3. Generic ID-based Deletion Interface
            elif hasattr(self.db_client, "delete_by_ids"):
                self.db_client.delete_by_ids(vector_ids)
                return True

            logger.warning("db_client provided but no supported purge method found on backend adapter.")
            return False
        except Exception as e:
            logger.error(f"Failed to execute backend vector deletion: {e}", exc_info=True)
            return False


class VectorHygieneManager:
    """
    Manages the lifecycle of vector embeddings during an active agentic trajectory.
    Staged vectors remain in quarantine until explicitly committed. If a trajectory halts
    due to high entropy or policy veto, staged vectors are purged to prevent state contagion.
    """

    def __init__(self, db_client: Any = None):
        self.adapter = VectorStoreAdapter(db_client)
        self._active_trajectories: Dict[str, List[Union[str, int]]] = {}
        self._lock = RLock()

    def stage_vectors(self, trajectory_id: str, vector_ids: List[Union[str, int]]) -> None:
        """Stages new vector IDs into the quarantined trajectory scope."""
        if not vector_ids:
            return

        with self._lock:
            if trajectory_id not in self._active_trajectories:
                self._active_trajectories[trajectory_id] = []
            self._active_trajectories[trajectory_id].extend(vector_ids)

        logger.info(f"Staged {len(vector_ids)} vector(s) for trajectory [{trajectory_id}].")

    def commit_trajectory(self, trajectory_id: str) -> List[Union[str, int]]:
        """
        Promotes staged vectors to primary index.
        Returns list of committed vector IDs.
        """
        with self._lock:
            committed_ids = self._active_trajectories.pop(trajectory_id, [])

        logger.info(f"Trajectory [{trajectory_id}] committed successfully. {len(committed_ids)} vector(s) finalized.")
        return committed_ids

    def revoke_trajectory(self, trajectory_id: str, namespace: Optional[str] = None) -> List[Union[str, int]]:
        """
        Purges staged vectors from storage backend upon trajectory failure/veto.
        Returns list of revoked vector IDs.
        """
        with self._lock:
            revoked_ids = self._active_trajectories.pop(trajectory_id, [])

        if not revoked_ids:
            logger.info(f"No staged vectors found to revoke for trajectory [{trajectory_id}].")
            return []

        logger.warning(f"NEGATIVE_YIELD / VETO triggered. Revoking {len(revoked_ids)} vector(s) for trajectory [{trajectory_id}].")
        success = self.adapter.purge_vectors(revoked_ids, namespace=namespace)

        if success:
            logger.info(f"State contagion prevented. Trajectory [{trajectory_id}] purged successfully.")
        else:
            logger.error(f"Vector purge failed for trajectory [{trajectory_id}]. Manual index maintenance required.")

        return revoked_ids

    def get_staged_count(self, trajectory_id: str) -> int:
        """Returns the current count of quarantined vectors for a given trajectory."""
        with self._lock:
            return len(self._active_trajectories.get(trajectory_id, []))

    @contextmanager
    def trajectory_scope(self, trajectory_id: str, namespace: Optional[str] = None):
        """
        Context manager providing atomic transactional boundaries for vector staging.
        Auto-revokes if an exception or unhandled error occurs during execution.
        """
        try:
            yield self
            with self._lock:
                if trajectory_id in self._active_trajectories:
                    self.commit_trajectory(trajectory_id)
        except Exception as err:
            logger.error(f"Trajectory [{trajectory_id}] aborted due to exception: {err}. Auto-revoking vectors.")
            self.revoke_trajectory(trajectory_id, namespace=namespace)
            raise