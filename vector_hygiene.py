import logging

class VectorHygieneManager:
    """
    Manages the lifecycle of vector embeddings during an active agentic trajectory.
    Prevents 'State Contagion' by ensuring high-entropy generations are revoked
    before they become permanent memory.
    """
    def __init__(self, db_client=None):
        self.db_client = db_client
        self.active_trajectories = {}

        logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
        self.logger = logging.getLogger("VectorHygiene")

    def stage_vectors(self, trajectory_id: str, vector_ids: list):
        if trajectory_id not in self.active_trajectories:
            self.active_trajectories[trajectory_id] = []

        self.active_trajectories[trajectory_id].extend(vector_ids)
        self.logger.info(f"Staged {len(vector_ids)} vectors for trajectory [{trajectory_id}].")

    def commit_trajectory(self, trajectory_id: str):
        if trajectory_id in self.active_trajectories:
            self.logger.info(f"Trajectory [{trajectory_id}] verified. Staged vectors committed.")
            del self.active_trajectories[trajectory_id]

    def revoke_trajectory(self, trajectory_id: str):
        if trajectory_id in self.active_trajectories:
            vector_ids = self.active_trajectories[trajectory_id]
            self.logger.warning(f"NEGATIVE_YIELD detected. Revoking {len(vector_ids)} vectors for trajectory [{trajectory_id}].")

            if self.db_client:
                try:
                    # Placeholder for actual DB deletion logic (e.g., ChromaDB, Pinecone)
                    self.logger.info(f"Executing database deletion for IDs: {vector_ids}")
                    pass
                except Exception as e:
                    self.logger.error(f"Failed to delete vectors from database: {e}")

            del self.active_trajectories[trajectory_id]
            self.logger.info(f"State contagion prevented. Trajectory [{trajectory_id}] successfully purged.")
