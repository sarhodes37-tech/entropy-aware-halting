import time
from typing import Dict, Any, Tuple, Optional, List, Set

from epistemicos.audit import TamperEvidentAuditTrail, AuditLogLevel
from epistemicos.gates import (
    GateAction, GateResult, EntropyGate, PermissionGate, 
    TriangulationGate, CryptoAttestationGate
)


class EpistemicOrchestrator:
    """
    The main runtime wrapper coordinating low-latency hard gates and
    cryptographic audit logging.
    """
    def __init__(
        self,
        allowed_tools: List[str],
        active_gates: Optional[List[str]] = None,
        model_id: str = "target-llm-v1",
        log_file_path: Optional[str] = None
    ):
        self.model_id = model_id
        
        # Initialize concrete gate instances mapped to keys
        self.gate_registry = {
            "entropy": EntropyGate(),
            "permission": PermissionGate(allowed_actions=allowed_tools),
            "triangulation": TriangulationGate(),
            "crypto": CryptoAttestationGate()
        }
        
        # Normalize active gates to a lookup set
        if active_gates is None:
            self.active_gates: Set[str] = {"entropy", "permission", "triangulation"}
        else:
            self.active_gates = {g.lower().replace("gate", "") for g in active_gates}

        if log_file_path:
            self.audit_logger = TamperEvidentAuditTrail(log_file_path=log_file_path)
        else:
            self.audit_logger = TamperEvidentAuditTrail()

    def process_step(
        self,
        token_logits: List[float],
        accumulated_output: str,
        raw_payload: Optional[Dict[str, Any]] = None,
        crypto_context: Optional[Dict[str, Any]] = None
    ) -> Tuple[GateAction, float, List[str]]:
        t_start = time.perf_counter()
        reasons = []  

        # Construct standard evaluation contexts 
        payload = raw_payload or {}
        context = {
            "token_logits": token_logits,
            "accumulated_output": accumulated_output,
            "cryptography": crypto_context or {}
        }

        # Stream evaluation pipeline
        for gate_name in self.active_gates:
            gate = self.gate_registry.get(gate_name)
            if not gate:
                continue

            res = gate.evaluate(payload, context)
            
            if res.action != GateAction.ALLOW:
                total_latency = (time.perf_counter() - t_start) * 1000
                reason_str = res.reason or f"{res.gate_name} Boundary Violation"
                reasons.append(reason_str)

                # Map standard actions to audit log levels
                audit_level = AuditLogLevel.HALT if res.action == GateAction.HALT else AuditLogLevel.ROLLBACK

                self.audit_logger.record_event(
                    event_type=audit_level,
                    gate_name=res.gate_name,
                    reason=reason_str,
                    model_id=self.model_id,
                    execution_latency_ms=total_latency,
                    payload_snippet=accumulated_output if accumulated_output else str(payload)
                )
                return res.action, total_latency, reasons

        total_latency = (time.perf_counter() - t_start) * 1000
        return GateAction.ALLOW, total_latency, []
