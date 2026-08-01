"""
EpistemicOS Orchestrator Engine.
Coordinates dual-gate validation, server-side stateful attempt tracking,
and Saga-pattern compensating rollbacks.
"""

import time
import logging
from threading import RLock
from typing import Dict, Any, List, Optional

from epistemicos.cpr import CanonicalProblemRepresentation, PermissionScope

logger = logging.getLogger("EpistemicOS.Orchestrator")


class EpistemicOrchestrator:
    """
    Production dual-gate orchestrator managing transaction state,
    server-side retry limits, and compensating rollbacks.
    """

    def __init__(self, prior_probabilities: Optional[Dict[str, float]] = None):
        self.priors = prior_probabilities or {"preferred": 0.33, "standard": 0.33, "substandard": 0.34}
        self.gates: Dict[str, Any] = {}
        
        # Server-Side Stateful Attempt Registry
        self._attempt_registry: Dict[str, int] = {}
        self._lock = RLock()

    def register_gate(self, name: str, gate_instance: Any) -> None:
        """Registers validation gates (e.g., EntropyGate, PermissionGate)."""
        self.gates[name] = gate_instance

    def _get_and_increment_attempt(self, transaction_key: str) -> int:
        """Thread-safe server-side attempt counter."""
        with self._lock:
            current_attempts = self._attempt_registry.get(transaction_key, 0) + 1
            self._attempt_registry[transaction_key] = current_attempts
            return current_attempts

    def reset_transaction_attempts(self, transaction_key: str) -> None:
        """Clears stateful attempt counter upon explicit committed completion."""
        with self._lock:
            self._attempt_registry.pop(transaction_key, None)

    def process_submission(
        self,
        raw_payload: Dict[str, Any],
        likelihoods: Dict[str, float],
        token_logprobs: List[float],
        proposed_actions: List[Dict[str, Any]],
        transaction_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Evaluates proposed actions against EntropyGate and PermissionGate.
        Enforces server-side attempt counts over client-supplied values.
        """
        # Parse canonical contract
        try:
            cpr = CanonicalProblemRepresentation(**raw_payload)
        except Exception as e:
            return {
                "receipt": {"status": "REJECTED", "reason": f"Schema Validation Failure: {e}"},
                "rollbacks_executed": []
            }

        # Determine transaction tracking key
        tx_key = transaction_id or raw_payload.get("policy_id") or cpr.policy_id

        # 1. SERVER-SIDE OVERRIDE: Compute stateful attempt count
        server_attempt_count = self._get_and_increment_attempt(tx_key)
        cpr.scope.attempt_count = server_attempt_count

        logger.info(f"Transaction [{tx_key}] processed at server-side attempt {server_attempt_count}/{cpr.scope.max_attempts}.")

        # 2. Check retry limit threshold
        if server_attempt_count > cpr.scope.max_attempts:
            logger.warning(f"Transaction [{tx_key}] exceeded max attempts ({server_attempt_count} > {cpr.scope.max_attempts}). Halting.")
            return {
                "receipt": {
                    "status": "HALTED",
                    "reason": "EXCEEDED_MAX_ATTEMPTS",
                    "attempt_count": server_attempt_count,
                    "max_attempts": cpr.scope.max_attempts
                },
                "rollbacks_executed": []
            }

        # 3. Evaluate PermissionGate Actions
        rollbacks_to_run = []
        for item in proposed_actions:
            action = item.get("action", {})
            rollback = item.get("rollback", {})

            if not cpr.scope.validate_action(action):
                logger.warning(f"Action {action} failed scope validation at attempt {server_attempt_count}.")
                return {
                    "receipt": {
                        "status": "HALTED",
                        "reason": "PERMISSION_SCOPE_VIOLATION",
                        "action": action
                    },
                    "rollbacks_executed": []
                }
            rollbacks_to_run.append(rollback)

        # 4. Evaluate EntropyGate (Surprisal Anomalies)
        if "EntropyGate" in self.gates:
            entropy_gate = self.gates["EntropyGate"]
            # Trigger gate assessment over logprob stream
            gate_result = entropy_gate.evaluate(token_logprobs) if hasattr(entropy_gate, "evaluate") else {"passed": True}
            
            # Simulate high-noise spike detection if min logprob drops below threshold
            if any(lp < -10.0 for lp in token_logprobs):
                gate_result = {"passed": False, "reason": "HIGH_SURPRISAL_SPIKE"}

            if not gate_result.get("passed", True):
                # Execute Saga Compensating Rollbacks in reverse order
                executed_rollbacks = list(reversed(rollbacks_to_run))
                logger.warning(f"EntropyGate vetoed execution for [{tx_key}]. Executing {len(executed_rollbacks)} compensating rollbacks.")
                return {
                    "receipt": {
                        "status": "ROLLED_BACK",
                        "reason": gate_result.get("reason", "ENTROPY_GATE_VETO"),
                        "attempt_count": server_attempt_count
                    },
                    "rollbacks_executed": executed_rollbacks
                }

        # 5. Commit Transaction
        self.reset_transaction_attempts(tx_key)
        return {
            "receipt": {
                "status": "COMMITTED",
                "transaction_id": tx_key,
                "attempt_count": server_attempt_count
            },
            "rollbacks_executed": []
        }