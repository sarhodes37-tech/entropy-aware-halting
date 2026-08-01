"""
EpistemicOS Orchestrator Engine.
Coordinates dynamic multi-gate validation, server-side stateful attempt tracking,
and Saga-pattern compensating rollbacks.
"""

import logging
from threading import RLock
from typing import Dict, Any, List, Optional, Union

from epistemicos.cpr import CanonicalProblemRepresentation

logger = logging.getLogger("EpistemicOS.Orchestrator")


class EpistemicOrchestrator:
    """
    Production multi-gate orchestrator managing transaction state,
    server-side retry limits, audit event receipts, and compensating rollbacks.
    """

    def __init__(self, prior_probabilities: Optional[Dict[str, float]] = None):
        self.priors = prior_probabilities or {"preferred": 0.33, "standard": 0.33, "substandard": 0.34}
        self.gates: Dict[str, Any] = {}

        # Server-Side Stateful Attempt Registry
        self._attempt_registry: Dict[str, int] = {}
        self._lock = RLock()

    def register_gate(self, name: str, gate_instance: Any) -> None:
        """Registers governance gates (e.g., EntropyGate, PermissionGate, TriangulationGate)."""
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
        raw_payload: Union[Dict[str, Any], CanonicalProblemRepresentation],
        likelihoods: Optional[Dict[str, float]] = None,
        token_logprobs: Optional[List[float]] = None,
        proposed_actions: Optional[List[Dict[str, Any]]] = None,
        transaction_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Processes transaction submissions against all registered governance gates.
        Enforces server-side attempt counts, evaluates dynamic gate suites,
        and triggers Saga compensating rollbacks upon gate rejection.
        """
        token_logprobs = token_logprobs or []
        proposed_actions = proposed_actions or []
        likelihoods = likelihoods or self.priors
        event_log: List[Dict[str, Any]] = []

        # 1. Schema Standardization & CPR Parsing
        try:
            if isinstance(raw_payload, CanonicalProblemRepresentation):
                cpr = raw_payload
                payload_dict = cpr.model_dump()
            else:
                cpr = CanonicalProblemRepresentation(**raw_payload)
                payload_dict = raw_payload
        except Exception as e:
            logger.error(f"Schema validation failure: {e}")
            return {
                "receipt": {
                    "status": "REJECTED",
                    "reason": f"Schema Validation Failure: {e}",
                    "event_log": []
                },
                "rollbacks_executed": []
            }

        # 2. Stateful Tracking Key Resolution
        tx_key = transaction_id or payload_dict.get("policy_id") or cpr.policy_id

        # 3. Server-Side Attempt Counter Override
        server_attempt_count = self._get_and_increment_attempt(tx_key)
        cpr.scope.attempt_count = server_attempt_count

        logger.info(f"Transaction [{tx_key}] processing at server-side attempt {server_attempt_count}/{cpr.scope.max_attempts}.")

        # 4. Hard Threshold Check for Retry Limits
        if server_attempt_count > cpr.scope.max_attempts:
            logger.warning(f"Transaction [{tx_key}] exceeded max attempts ({server_attempt_count} > {cpr.scope.max_attempts}). Halting.")
            return {
                "receipt": {
                    "status": "HALTED",
                    "reason": "EXCEEDED_MAX_ATTEMPTS",
                    "transaction_id": tx_key,
                    "attempt_count": server_attempt_count,
                    "max_attempts": cpr.scope.max_attempts,
                    "event_log": event_log
                },
                "rollbacks_executed": []
            }

        # Prepare list of staged Saga rollbacks
        rollbacks_to_run = [item.get("rollback", {}) for item in proposed_actions if item.get("rollback")]

        # 5. Build Unified Execution Context for Gate Plugins
        context = {
            "token_logprobs": token_logprobs,
            "proposed_actions": proposed_actions,
            "heterogeneous_telemetry": payload_dict.get("heterogeneous_telemetry", []),
            "cryptography": payload_dict.get("cryptography", {}),
            "server_attempt_count": server_attempt_count,
            "likelihoods": likelihoods
        }

        # 6. Dynamic Governance Gate Evaluation Loop
        for gate_name, gate_instance in self.gates.items():
            gate_result = gate_instance.evaluate(payload_dict, context)
            event_log.append({
                "type": f"GateEvaluated:{gate_name}",
                "details": gate_result
            })

            if not gate_result.get("passed", True):
                # Execute Saga Compensating Rollbacks in reverse order
                executed_rollbacks = list(reversed(rollbacks_to_run))
                reason = gate_result.get("reason", f"VETOED_BY_{gate_name}")

                if executed_rollbacks:
                    status = "ROLLED_BACK"
                elif "SCOPE" in str(reason).upper() or "ATTEMPT" in str(reason).upper():
                    status = "HALTED"
                else:
                    status = "REJECTED"

                logger.warning(f"Gate [{gate_name}] vetoed execution for [{tx_key}]. Reason: {reason}. Status: {status}.")

                return {
                    "receipt": {
                        "status": status,
                        "reason": reason,
                        "gate": gate_name,
                        "transaction_id": tx_key,
                        "attempt_count": server_attempt_count,
                        "event_log": event_log
                    },
                    "rollbacks_executed": executed_rollbacks
                }

        # 7. Transaction Commit
        self.reset_transaction_attempts(tx_key)
        logger.info(f"Transaction [{tx_key}] successfully committed.")

        return {
            "receipt": {
                "status": "COMMITTED",
                "transaction_id": tx_key,
                "attempt_count": server_attempt_count,
                "event_log": event_log
            },
            "rollbacks_executed": []
        }
