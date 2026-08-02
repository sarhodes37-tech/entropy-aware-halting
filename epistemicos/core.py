"""
EpistemicOS Main Orchestrator (core.py).

Unifies the domain models, hardware telemetry, governance gates, 
vector hygiene, and tamper-evident audit logs into a single 
defense-in-depth pipeline.
"""
import json
import uuid
from typing import Dict, Any, Optional

from epistemicos.models import CanonicalProblemRepresentation
from epistemicos.telemetry import ResourceProfiler
from epistemicos.audit import TamperEvidentAuditTrail, AuditLogLevel
from epistemicos.scheduler import EntropyAwareScheduler, DecisionResult
from epistemicos.vector_hygiene import VectorHygieneManager
from epistemicos.gates import (
    EntropyGate,
    PermissionGate,
    TriangulationGate,
    CryptoAttestationGate,
    GateAction
)

class EpistemicOrchestrator:
    def __init__(
        self, 
        model_id: str = "epistemic-core-v1",
        scheduler: Optional[EntropyAwareScheduler] = None,
        db_client: Any = None
    ):
        self.model_id = model_id
        
        # Core Subsystems
        self.scheduler = scheduler or EntropyAwareScheduler()
        self.audit_logger = TamperEvidentAuditTrail()
        self.vector_manager = VectorHygieneManager(db_client=db_client)

        # Initialize Governance Gates in priority order
        self.gates = [
            CryptoAttestationGate(),
            PermissionGate(),
            TriangulationGate(),
            EntropyGate(z_threshold=2.85, window_size=10)
        ]

    def process_step(self, probabilities, cost, state) -> DecisionResult:
        """Handles the low-level entropy scheduling loop."""
        decision = self.scheduler.step(probabilities, cost, state)
        if decision.halt:
            # You can link this directly to your audit logger if needed
            pass
        return decision

    def process_submission(
        self, 
        raw_payload: Dict[str, Any], 
        context: Dict[str, Any],
        trajectory_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Ingests a raw payload, evaluates it across governance gates, 
        and immutably logs the outcome. Automatically handles vector rollbacks 
        if a trajectory is halted.
        """
        # Assign a trajectory ID for vector tracking if one isn't provided
        traj_id = trajectory_id or str(uuid.uuid4())

        # 1. Normalize into the Domain Model
        try:
            cpr = CanonicalProblemRepresentation(**raw_payload)
        except Exception as e:
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
            
            # Wrap execution in the vector hygiene scope to catch runtime crashes
            with self.vector_manager.trajectory_scope(traj_id):
                payload_dump = cpr.model_dump()

                for gate in self.gates:
                    result = gate.evaluate(payload=payload_dump, context=context)

                    if result.action == GateAction.HALT:
                        # 3a. Pipeline Halt: Veto triggers audit log AND vector revocation
                        telemetry = profiler.get_telemetry()
                        
                        # Explicitly revoke vectors before returning
                        revoked_ids = self.vector_manager.revoke_trajectory(traj_id)
                        
                        self.audit_logger.record_event(
                            event_type=AuditLogLevel.HALT,
                            gate_name=result.gate_name,
                            reason=f"{result.reason} | Vectors Revoked: {len(revoked_ids)}",
                            model_id=self.model_id,
                            payload_snippet=json.dumps(raw_payload),
                            cpr_snapshot=cpr,
                            telemetry=telemetry
                        )
                        return {
                            "status": "HALTED", 
                            "gate": result.gate_name, 
                            "reason": result.reason,
                            "vectors_revoked": len(revoked_ids)
                        }

            # 3b. Pipeline Success: Vectors are automatically committed by the context manager
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
                "masked_payload": cpr.mask_egress_payload(),
                "telemetry": telemetry.__dict__,
                "trajectory_id": traj_id
            }
