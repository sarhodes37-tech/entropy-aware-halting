import time
from typing import Dict, Any, Tuple, Optional, List, Set

from epistemicos.audit import TamperEvidentAuditTrail, AuditLogLevel
from epistemicos.gates import GateAction


class EpistemicOrchestrator:
    """
    Consolidated runtime wrapper coordinating dynamic hard gates,
    stateful revocation, and cryptographic audit logging.
    """
    def __init__(
        self,
        prior_probabilities: Optional[Dict[str, float]] = None,
        model_id: str = "target-llm-v1",
        log_file_path: Optional[str] = None
    ):
        self.model_id = model_id
        self.prior_probabilities = prior_probabilities or {}
        
        # Dynamic registries to support stateful testing
        self.gate_registry: Dict[str, Any] = {}
        self.active_gates: Set[str] = set()

        if log_file_path:
            self.audit_logger = TamperEvidentAuditTrail(log_file_path=log_file_path)
        else:
            self.audit_logger = TamperEvidentAuditTrail()

    def register_gate(self, name: str, gate_instance: Any) -> None:
        """Dynamically add a gate to the execution pipeline."""
        self.gate_registry[name] = gate_instance
        self.active_gates.add(name)

    def process_submission(
        self,
        raw_payload: Dict[str, Any],
        likelihoods: Optional[Dict[str, float]] = None,
        token_logprobs: Optional[List[float]] = None,
        proposed_actions: Optional[List[Dict[str, Any]]] = None,
        crypto_metadata: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Evaluates payloads against all registered gates and returns a stateful receipt.
        """
        t_start = time.perf_counter()
        reasons = []  
        final_action = GateAction.ALLOW

        # Construct standard evaluation contexts 
        context = {
            "likelihoods": likelihoods or {},
            "token_logprobs": token_logprobs or [],
            "proposed_actions": proposed_actions or [],
            "cryptography": crypto_metadata or {},
            "prior_probabilities": self.prior_probabilities,
            **kwargs  # Absorbs any extra metadata seamlessly
        }

        # Stream evaluation pipeline
        for gate_name in self.active_gates:
            gate = self.gate_registry.get(gate_name)
            if not gate:
                continue

            res = gate.evaluate(raw_payload, context)

            if res.action != GateAction.ALLOW:
                final_action = res.action
                reason_str = res.reason or f"{gate_name} Boundary Violation"
                reasons.append(reason_str)

                # Map standard actions to audit log levels
                audit_level = AuditLogLevel.HALT if res.action == GateAction.HALT else AuditLogLevel.ROLLBACK

                self.audit_logger.record_event(
                    event_type=audit_level,
                    gate_name=gate_name,
                    reason=reason_str,
                    model_id=self.model_id,
                    execution_latency_ms=(time.perf_counter() - t_start) * 1000,
                    payload_snippet=str(raw_payload)
                )
                
                # Short-circuit on the first hard failure
                break

        total_latency = (time.perf_counter() - t_start) * 1000
        
        # Stateful Receipt Generation
        receipt = {
            "status": "APPROVED" if final_action == GateAction.ALLOW else "REJECTED",
            "latency_ms": total_latency,
            "reasons": reasons,
            "crypto_state": "VERIFIED" if (final_action == GateAction.ALLOW and crypto_metadata) else "REVOKED_OR_MISSING"
        }

        return {
            "action": final_action,
            "receipt": receipt
        }
