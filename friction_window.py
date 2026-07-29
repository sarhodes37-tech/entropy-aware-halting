import time
import uuid
import logging

class PreExecutionFrictionGate:
    def __init__(self, window_seconds=172800):
        self.window_seconds = window_seconds
        self.staging_queue = {}
        logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
        self.logger = logging.getLogger("FrictionGate")

    def stage_action(self, agent_id: str, target_api: str, payload: dict, rollback_script: dict):
        if not rollback_script:
            self.logger.error(f"Agent [{agent_id}] attempted execution without a rollback script.")
            raise ValueError("Reversible Autonomy Violation: Rollback script is mandatory.")

        action_id = str(uuid.uuid4())
        self.staging_queue[action_id] = {
            "agent_id": agent_id,
            "target_api": target_api,
            "payload": payload,
            "rollback_script": rollback_script,
            "expiration_time": time.time() + self.window_seconds,
            "status": "PENDING_HUMAN_REVIEW"
        }
        self.logger.warning(f"Action [{action_id}] staged in friction window for [{target_api}].")
        return action_id

    def approve_action(self, action_id: str, human_signature: str):
        self._prune_expired_actions()
        if action_id in self.staging_queue:
            action = self.staging_queue[action_id]
            self.logger.info(f"Action [{action_id}] AUTHORIZED by {human_signature}. Executing.")
            del self.staging_queue[action_id]
            return True
        return False

    def reject_or_rollback(self, action_id: str, reason: str):
        if action_id in self.staging_queue:
            action = self.staging_queue[action_id]
            self.logger.warning(f"Action [{action_id}] REJECTED: {reason}. Validating rollback.")
            del self.staging_queue[action_id]
            return True
        return False

    def _prune_expired_actions(self):
        current_time = time.time()
        expired = [k for k, v in self.staging_queue.items() if v['expiration_time'] < current_time]
        for k in expired:
            self.logger.error(f"Action [{k}] expired. Purged.")
            del self.staging_queue[k]
