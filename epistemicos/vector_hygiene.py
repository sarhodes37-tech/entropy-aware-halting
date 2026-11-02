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
            if hasattr(self.db_client, "delete") and callable(getattr(self.db_client, "delete")):
                if namespace:
                    res = self.db_client.delete(ids=vector_ids, namespace=namespace)
                else:
                    res = self.db_client.delete(ids=vector_ids)
                if res is False:
                    logger.warning("Pinecone backend returned explicit False on delete.")
                    return False
                return True

            # 2. ChromaDB / Qdrant Interface
            if hasattr(self.db_client, "delete_vectors") and callable(getattr(self.db_client, "delete_vectors")):
                res = self.db_client.delete_vectors(vector_ids=vector_ids)
                if res is False:
                    logger.warning("ChromaDB/Qdrant backend returned explicit False on delete_vectors.")
                    return False
                return True

            # 3. Generic ID-based Deletion Interface
            if hasattr(self.db_client, "delete_by_ids") and callable(getattr(self.db_client, "delete_by_ids")):
                res = self.db_client.delete_by_ids(vector_ids)
                if res is False:
                    logger.warning("Generic vector backend returned explicit False on delete_by_ids.")
                    return False
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
        self._unpurged_vectors: Dict[str, List[Union[str, int]]] = {}
        self._lock = RLock()

    def get_unpurged_vectors(self, trajectory_id: Optional[str] = None) -> Union[List[Union[str, int]], Dict[str, List[Union[str, int]]]]:
        """
        Returns quarantined vector IDs whose backend purge failed.
        If trajectory_id is provided, returns the list for that trajectory.
        Otherwise returns a copy of the dictionary mapping trajectory IDs to unpurged vectors.
        """
        with self._lock:
            if trajectory_id is not None:
                return list(self._unpurged_vectors.get(trajectory_id, []))
            return {k: list(v) for k, v in self._unpurged_vectors.items()}

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

    def revoke_trajectory(
        self,
        trajectory_id: str,
        namespace: Optional[str] = None,
        include_quarantined: bool = False
    ) -> List[Union[str, int]]:
        """
        Purges staged vectors from storage backend upon trajectory failure/veto.
        Returns list of successfully purged vector IDs, or an empty list if purge failed.
        Failed vector IDs are preserved in `_unpurged_vectors` dead-letter quarantine for manual or deferred maintenance.

        Concurrency Invariant:
        Captures the exact batch to revoke under lock. Removes only the captured batch IDs from active
        tracking upon completion, so vectors staged concurrently after batch capture are never lost or cleared.
        """
        with self._lock:
            active_list = self._active_trajectories.get(trajectory_id, [])
            quarantined = self._unpurged_vectors.get(trajectory_id, [])
            batch_to_purge = list(active_list)
            # If active list has items that were also in quarantine, ensure they are tracked for quarantine clearing on success
            if include_quarantined:
                for q_id in quarantined:
                    if q_id not in batch_to_purge:
                        batch_to_purge.append(q_id)

        if not batch_to_purge:
            logger.info(f"No staged vectors found to revoke for trajectory [{trajectory_id}].")
            return []

        logger.warning(f"NEGATIVE_YIELD / VETO triggered. Revoking {len(batch_to_purge)} vector(s) for trajectory [{trajectory_id}].")
        success = self.adapter.purge_vectors(batch_to_purge, namespace=namespace)

        with self._lock:
            if success:
                # Remove only the purged batch items from active tracking
                if trajectory_id in self._active_trajectories:
                    purged_set = set(batch_to_purge)
                    self._active_trajectories[trajectory_id] = [
                        vid for vid in self._active_trajectories[trajectory_id]
                        if vid not in purged_set
                    ]
                    if not self._active_trajectories[trajectory_id]:
                        del self._active_trajectories[trajectory_id]

                # Remove confirmed deleted IDs from quarantine as well if present
                if trajectory_id in self._unpurged_vectors:
                    purged_set = set(batch_to_purge)
                    self._unpurged_vectors[trajectory_id] = [
                        vid for vid in self._unpurged_vectors[trajectory_id]
                        if vid not in purged_set
                    ]
                    if not self._unpurged_vectors[trajectory_id]:
                        del self._unpurged_vectors[trajectory_id]

                logger.info(f"State contagion prevented. Trajectory [{trajectory_id}] purged successfully.")
                return batch_to_purge
            else:
                # Failed purge: remove the batch from active tracking and preserve in quarantine
                purged_set = set(batch_to_purge)
                if trajectory_id in self._active_trajectories:
                    self._active_trajectories[trajectory_id] = [
                        vid for vid in self._active_trajectories[trajectory_id]
                        if vid not in purged_set
                    ]
                    if not self._active_trajectories[trajectory_id]:
                        del self._active_trajectories[trajectory_id]

                if trajectory_id not in self._unpurged_vectors:
                    self._unpurged_vectors[trajectory_id] = []
                existing_quarantine = set(self._unpurged_vectors[trajectory_id])
                for vid in batch_to_purge:
                    if vid not in existing_quarantine:
                        self._unpurged_vectors[trajectory_id].append(vid)

                logger.error(f"Vector purge failed for trajectory [{trajectory_id}]. Preserved {len(batch_to_purge)} vector ID(s) in unpurged quarantine for reconciliation.")
                return []

    def retry_quarantined_vectors(
        self,
        trajectory_id: Optional[str] = None,
        namespace: Optional[str] = None
    ) -> Dict[str, List[Union[str, int]]]:
        """
        Retries backend purge for quarantined vector IDs without requiring them to be re-staged.
        If trajectory_id is specified, only that trajectory's quarantined vectors are retried.
        Returns a dict mapping trajectory IDs to the list of vector IDs successfully purged.
        Failed vector IDs remain in quarantine.
        """
        results: Dict[str, List[Union[str, int]]] = {}
        with self._lock:
            if trajectory_id is not None:
                traj_map = {trajectory_id: list(self._unpurged_vectors.get(trajectory_id, []))} if trajectory_id in self._unpurged_vectors else {}
            else:
                traj_map = {t: list(v) for t, v in self._unpurged_vectors.items()}

        for t_id, vids in traj_map.items():
            if not vids:
                continue
            success = self.adapter.purge_vectors(vids, namespace=namespace)
            with self._lock:
                if success:
                    purged_set = set(vids)
                    if t_id in self._unpurged_vectors:
                        self._unpurged_vectors[t_id] = [
                            v for v in self._unpurged_vectors[t_id]
                            if v not in purged_set
                        ]
                        if not self._unpurged_vectors[t_id]:
                            del self._unpurged_vectors[t_id]
                    results[t_id] = vids
                    logger.info(f"Quarantine retry succeeded for trajectory [{t_id}]: {len(vids)} vector(s) purged.")
                else:
                    results[t_id] = []
                    logger.error(f"Quarantine retry failed for trajectory [{t_id}]: {len(vids)} vector(s) remain quarantined.")

        return results

    def get_staged_count(self, trajectory_id: str) -> int:
        """Returns the current count of quarantined vectors for a given trajectory."""
        with self._lock:
            return len(self._active_trajectories.get(trajectory_id, []))

    def abort_trajectory_scope(self, trajectory_id: str) -> None:
        """
        Marks an active trajectory scope as aborted, preventing trajectory_scope()
        from auto-committing remaining staged vectors on normal exit.
        """
        with self._lock:
            if not hasattr(self, "_aborted_scopes"):
                self._aborted_scopes = set()
            self._aborted_scopes.add(trajectory_id)

    def is_scope_aborted(self, trajectory_id: str) -> bool:
        with self._lock:
            if not hasattr(self, "_aborted_scopes"):
                self._aborted_scopes = set()
            return trajectory_id in self._aborted_scopes

    @contextmanager
    def trajectory_scope(self, trajectory_id: str, namespace: Optional[str] = None, auto_commit: bool = True):
        """
        Context manager providing atomic transactional boundaries for vector staging.
        Auto-revokes if an exception or unhandled error occurs during execution.
        If auto_commit is False or abort_trajectory_scope(trajectory_id) was called,
        remaining staged vectors are NOT committed on normal context-manager exit.
        """
        with self._lock:
            if not hasattr(self, "_aborted_scopes"):
                self._aborted_scopes = set()
            self._aborted_scopes.discard(trajectory_id)

        try:
            yield self
            should_commit = auto_commit and not self.is_scope_aborted(trajectory_id)
            if should_commit and self.get_staged_count(trajectory_id) > 0:
                self.commit_trajectory(trajectory_id)
        except Exception as err:
            logger.error(f"Trajectory [{trajectory_id}] aborted due to exception: {err}. Auto-revoking vectors.")
            self.revoke_trajectory(trajectory_id, namespace=namespace)
            raise
        finally:
            with self._lock:
                if hasattr(self, "_aborted_scopes"):
                    self._aborted_scopes.discard(trajectory_id)
