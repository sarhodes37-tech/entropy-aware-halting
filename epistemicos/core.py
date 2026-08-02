"""
EpistemicOS Main Orchestrator (core.py).

Unifies the domain models, hardware telemetry, governance gates, 
and tamper-evident audit logs into a single defense-in-depth pipeline.
"""
import json
from typing import Dict, Any
from epistemicos.scheduler import EntropyAwareScheduler, DecisionResult

class EpistemicOrchestrator:
    def __init__(self, scheduler: Optional[EntropyAwareScheduler] = None, ...):
        self.scheduler = scheduler or EntropyAwareScheduler()

    def process_step(self, probabilities, cost, state) -> DecisionResult:
        # Pass token probabilities directly into the scheduling loop
        decision = self.scheduler.step(probabilities, cost, state)
        if decision.halt:
            # Trigger governance logging or halt generation
            pass
        return decision

from epistemicos.models import CanonicalProblemRepresentation
from epistemicos.telemetry import ResourceProfiler
from epistemicos.audit import TamperEvidentAuditTrail, AuditLogLevel
from epistemicos.gates import (
    EntropyGate,
    PermissionGate,
    TriangulationGate,
    CryptoAttestationGate,
    GateAction
)

class EpistemicOrchestrator:
    def __init__(self, model_id: str = "epistemic-core-v1"):
        self.model_id = model_id
        self.audit_logger = TamperEvidentAuditTrail()
        
        # Initialize Governance Gates in priority order
        self.gates = [
            CryptoAttestationGate(),
            PermissionGate(),
            TriangulationGate(),
            EntropyGate(z_threshold=2.85, window_size=10)
        ]

    def process_submission(self, raw_payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ingests a raw payload, normalizes it into a CPR, evaluates it across 
        all governance gates under hardware telemetry, and immutably logs the outcome.
        """
        # 1. Normalize into the Domain Model
        try:
            cpr = CanonicalProblemRepresentation(**raw_payload)
        except Exception as e:
            # If it fails schema validation, halt and log immediately
            self.audit_logger.record_event(
                event_type=AuditLogLevel.HALT,
                gate_name="CPR_Validation",
                reason=f"Schema violation: {str(e)}",
                model_id=self.model_id,
                payload_snippet=json.dumps(raw_payload)
            )
            return {"status": "HALTED", "reason": "Schema validation failed"}

        # 2. Execute Defense-in-Depth Pipeline under Telemetry
        with ResourceProfiler(device="cuda", token_count=context.get("token_count", 1)) as profiler:
            payload_dump = cpr.model_dump()
            
            for gate in self.gates:
                result = gate.evaluate(payload=payload_dump, context=context)
                
                if result.action == GateAction.HALT:
                    # 3a. Pipeline Halt (e.g., prompt injection or permission breach detected)
                    telemetry = profiler.get_telemetry()
                    self.audit_logger.record_event(
                        event_type=AuditLogLevel.HALT,
                        gate_name=result.gate_name,
                        reason=result.reason,
                        model_id=self.model_id,
                        payload_snippet=json.dumps(raw_payload),
                        cpr_snapshot=cpr,
                        telemetry=telemetry
                    )
                    return {
                        "status": "HALTED", 
                        "gate": result.gate_name, 
                        "reason": result.reason
                    }
        
        # 3b. Pipeline Success
        telemetry = profiler.get_telemetry()
        self.audit_logger.record_event(
            event_type=AuditLogLevel.INFO,
            gate_name="Pipeline_Complete",
            reason="All governance gates passed",
            model_id=self.model_id,
            payload_snippet=json.dumps(raw_payload),
            cpr_snapshot=cpr,
            telemetry=telemetry
        )
        
        return {
            "status": "ALLOWED",
            # Context injection is strictly masked to prevent PII leakage
            "masked_payload": cpr.mask_egress_payload(),
            "telemetry": telemetry.__dict__
        }
