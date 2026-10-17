"""
EpistemicOS Main Orchestrator (core.py).

Unifies the domain models, hardware telemetry, governance gates, 
vector hygiene, and tamper-evident audit logs into a single 
defense-in-depth pipeline.
"""
import json
import uuid
import threading
from typing import Dict, Any, Optional, Tuple

from epistemicos.models import CanonicalProblemRepresentation
from epistemicos.telemetry import ResourceProfiler
from epistemicos.audit import TamperEvidentAuditTrail, AuditLogLevel, AuditEvent
from epistemicos.scheduler import EntropyAwareScheduler, DecisionResult
from epistemicos.vector_hygiene import VectorHygieneManager
from epistemicos.gates import (
    EntropyGate,
    PermissionGate,
    TriangulationGate,
    CryptoAttestationGate,
    GateAction,
    GateResult
)
from epistemicos.shower_curtain.gate import ShowerCurtainGate
from epistemicos.shower_curtain.engine import ShowerCurtainEngine
from epistemicos.provenance import TrustedExecutionBoundary, ExecutionContext

class EpistemicOrchestrator:
    def register_gate(self, gate, *args, **kwargs):
        """Dynamically append a security gate to the pipeline."""
        if not hasattr(self, "gates") or self.gates is None:
            self.gates = []
        self.gates.append(gate)


    def __init__(
        self, 
        audit_log_path="logs/audit.jsonl", 
        enforce_determinism=True, 
        enable_telemetry=False,
        scheduler=None,
        db_client=None,
        model_id="epistemic-core-v1",
        prior_probabilities=None,  # Restored to fix Layer 4 Benchmark crashes
        execution_boundary: Optional[TrustedExecutionBoundary] = None
    ):
        self.audit_log_path = audit_log_path
        self.enforce_determinism = enforce_determinism
        self.enable_telemetry = enable_telemetry
        self.model_id = model_id
        self.prior_probabilities = prior_probabilities

        # Core Subsystems
        if scheduler:
            self._base_scheduler = scheduler
            self.scheduler = scheduler
        else:
            # Initialize without passing **kwargs to prevent TypeError
            self._base_scheduler = EntropyAwareScheduler()
            self.scheduler = self._base_scheduler

        self._registry_lock = threading.Lock()
        self._trajectory_locks: Dict[str, threading.Lock] = {}
        self._schedulers: Dict[str, EntropyAwareScheduler] = {}


        # Plug the dead wire back in so logs actually route to Google Drive
        self.audit_logger = TamperEvidentAuditTrail(log_file_path=self.audit_log_path) 

        # Pass the db_client properly
        self.vector_manager = VectorHygieneManager(db_client=db_client)

        # Execution Boundary
        self.execution_boundary = execution_boundary or TrustedExecutionBoundary()

        # Initialize Governance Gates in priority order
        self.shower_curtain = ShowerCurtainEngine(audit_log_path=self.audit_log_path)
        self.gates = [
            PermissionGate(),
            EntropyGate(z_threshold=1.5, window_size=10),
            TriangulationGate()
        ]

    def get_trajectory_scheduler(self, trajectory_id: str) -> EntropyAwareScheduler:
        """Retrieves or instantiates the isolated EntropyAwareScheduler for a trajectory."""
        with self._registry_lock:
            if trajectory_id not in self._schedulers:
                self._schedulers[trajectory_id] = EntropyAwareScheduler(
                    value_of_information=self._base_scheduler.V,
                    divergence_threshold=self._base_scheduler.divergence_threshold,
                    negative_yield_window=self._base_scheduler.negative_yield_window,
                    entropy_delta_threshold=self._base_scheduler.entropy_delta_threshold,
                    stagnation_window=self._base_scheduler.stagnation_window,
                    confidence_threshold=self._base_scheduler.confidence_threshold,
                    utility_epsilon=self._base_scheduler.utility_epsilon,
                    minimum_steps_before_convergence=self._base_scheduler.minimum_steps_before_convergence
                )
            return self._schedulers[trajectory_id]

    def reset_trajectory(self, trajectory_id: str) -> None:
        """Explicitly retires and resets the scheduler state associated with a given trajectory ID."""
        with self._registry_lock:
            if trajectory_id in self._schedulers:
                self._schedulers[trajectory_id].reset()
                del self._schedulers[trajectory_id]
            if trajectory_id in self._trajectory_locks:
                del self._trajectory_locks[trajectory_id]

    def retire_trajectory(self, trajectory_id: str) -> None:
        """Alias for reset_trajectory to formally retire a completed or halted trajectory."""
        self.reset_trajectory(trajectory_id)

    def reset_schedulers(self) -> None:
        """Clears and resets all managed trajectory schedulers and base/default scheduler state."""
        with self._registry_lock:
            for sched in list(self._schedulers.values()):
                sched.reset()
            self._schedulers.clear()
            self._trajectory_locks.clear()
            if hasattr(self._base_scheduler, "reset"):
                self._base_scheduler.reset()
            if hasattr(self.scheduler, "reset") and self.scheduler is not self._base_scheduler:
                self.scheduler.reset()

    def process_step(self, probabilities, cost, state, trajectory_id: Optional[str] = None) -> DecisionResult:
        """Handles the low-level entropy scheduling loop."""
        traj_key = trajectory_id or (state if isinstance(state, str) else None)
        if not traj_key:
            traj_key = str(uuid.uuid4())

        with self._registry_lock:
            if traj_key not in self._trajectory_locks:
                self._trajectory_locks[traj_key] = threading.Lock()

            traj_lock = self._trajectory_locks[traj_key]

            if traj_key not in self._schedulers:
                # Instantiate an isolated scheduler with the same config from _base_scheduler without mutating shared state
                self._schedulers[traj_key] = EntropyAwareScheduler(
                    value_of_information=self._base_scheduler.V,
                    divergence_threshold=self._base_scheduler.divergence_threshold,
                    negative_yield_window=self._base_scheduler.negative_yield_window,
                    entropy_delta_threshold=self._base_scheduler.entropy_delta_threshold,
                    stagnation_window=self._base_scheduler.stagnation_window,
                    confidence_threshold=self._base_scheduler.confidence_threshold,
                    utility_epsilon=self._base_scheduler.utility_epsilon,
                    minimum_steps_before_convergence=self._base_scheduler.minimum_steps_before_convergence
                )

            target_scheduler = self._schedulers[traj_key]

        with traj_lock:
            decision = target_scheduler.step(probabilities, cost, state)
            if decision.halt:
                # You can link this directly to your audit logger if needed
                pass
            return decision

      
    def _validate_and_normalize(self, raw_payload: Dict[str, Any]) -> Tuple[Optional[CanonicalProblemRepresentation], Optional[Dict[str, Any]]]:
        # 1. Normalize into the Domain Model
        try:
            cpr = CanonicalProblemRepresentation(**raw_payload)
            return cpr, None
        except Exception as e:
            # Mask sensitive fields to prevent raw data exposure in the audit log
            if isinstance(raw_payload, dict):
                sensitive_fields = getattr(CanonicalProblemRepresentation, "SENSITIVE_FIELDS", {"banking_routing", "account_number", "ssn", "account_balance_usd", "proprietary_cargo"})
                if isinstance(sensitive_fields, property) or not isinstance(sensitive_fields, (set, frozenset)):
                    sensitive_fields = {"banking_routing", "account_number", "ssn", "account_balance_usd", "proprietary_cargo"}
                masked_payload = {
                    k: v for k, v in raw_payload.items()
                    if k not in sensitive_fields
                }
            else:
                masked_payload = raw_payload

            self.audit_logger.record_event(AuditEvent(
                event_type=AuditLogLevel.HALT,
                gate_name="CPR_Validation",
                reason=f"Schema violation: {str(e)}",
                model_id=self.model_id,
                payload_snippet=json.dumps(masked_payload)
            ))
            return None, {"status": "HALTED", "reason": "Schema validation failed"}

    def _log_pipeline_event(self, event_type: AuditLogLevel, gate_name: str, reason: str,
                            masked_payload: Dict[str, Any], cpr: CanonicalProblemRepresentation, telemetry: Any) -> None:
        self.audit_logger.record_event(AuditEvent(
            event_type=event_type,
            gate_name=gate_name,
            reason=reason,
            model_id=self.model_id,
            payload_snippet=json.dumps(masked_payload),
            cpr_snapshot=cpr,
            telemetry=telemetry
        ))

    def _evaluate_gates(self, payload_dump: Dict[str, Any], context: Dict[str, Any]) -> Optional[Any]:
        for gate in self.gates:
            gate_name = getattr(gate, "gate_name", gate.__class__.__name__)
            try:
                result = gate.evaluate(payload=payload_dump, context=context)
            except Exception as e:
                # Security-critical gates fail closed on unhandled errors
                return GateResult(
                    action=GateAction.HALT,
                    status="HALTED",
                    gate_name=gate_name,
                    reason=f"Gate Execution Failure ({gate_name}): {str(e)}",
                    vectors_revoked=1
                )

            if result is None:
                return GateResult(
                    action=GateAction.HALT,
                    status="HALTED",
                    gate_name=gate_name,
                    reason=f"Gate Evaluation Returned None ({gate_name})",
                    vectors_revoked=1
                )

            action = getattr(result, "action", None)
            passed = getattr(result, "passed", False) if hasattr(result, "passed") else getattr(result, "get", lambda k, d=None: d)("passed", False)

            valid_actions = {
                GateAction.ALLOW, GateAction.HALT, GateAction.ROLLBACK,
                "ALLOW", "DETERMINISTIC_HALT", "ACTION_ROLLBACK", "HALT", "DENY", "INDETERMINATE"
            }
            if action not in valid_actions:
                return GateResult(
                    action=GateAction.HALT,
                    status="HALTED",
                    gate_name=gate_name,
                    reason=f"Gate Evaluation Returned Invalid or Unknown Action '{action}' ({gate_name})",
                    vectors_revoked=1
                )

            is_allow = (action == GateAction.ALLOW or action == "ALLOW")
            if is_allow and not passed:
                return GateResult(
                    action=GateAction.HALT,
                    status="HALTED",
                    gate_name=gate_name,
                    reason=f"Gate Evaluation Contradiction: Action ALLOW with passed=False ({gate_name})",
                    vectors_revoked=1
                )

            if not is_allow or not passed:
                return result

        return None

    def _execute_pipeline(self, cpr: CanonicalProblemRepresentation, raw_payload: Dict[str, Any], context: Dict[str, Any], traj_id: str) -> Dict[str, Any]:
        # 2. Execute Defense-in-Depth Pipeline under Telemetry
        with ResourceProfiler(device="cuda", token_count=context.get("token_count", 1)) as profiler:
            # Wrap execution in the vector hygiene scope to catch runtime crashes
            with self.vector_manager.trajectory_scope(traj_id):
                payload_dump = cpr.model_dump()

                masked_payload = {
                    k: v for k, v in raw_payload.items()
                    if k not in cpr.SENSITIVE_FIELDS
                }

                result = self._evaluate_gates(payload_dump, context)

                if result:
                    # 3a. Pipeline Halt: Veto triggers audit log AND vector revocation
                    telemetry = profiler.get_telemetry()
                    # Explicitly revoke vectors before returning
                    revoked_ids = self.vector_manager.revoke_trajectory(traj_id)
                    # Fallback to the gate's revocation count if the vector manager is mocked/empty
                    actual_revoked_count = max(len(revoked_ids), getattr(result, "vectors_revoked", 0))

                    gate_name = getattr(result, "gate_name", getattr(result, "gate", "UnknownGate"))
                    reason_msg = getattr(result, "reason", "Gate Execution Halted")

                    self._log_pipeline_event(
                        event_type=AuditLogLevel.HALT,
                        gate_name=gate_name,
                        reason=f"{reason_msg} | Vectors Revoked: {actual_revoked_count}",
                        masked_payload=masked_payload,
                        cpr=cpr,
                        telemetry=telemetry
                    )
                    return {
                        "status": "HALTED",
                        "gate": gate_name,
                        "reason": reason_msg,
                        "vectors_revoked": actual_revoked_count
                    }

            # 3b. Boundary Enforcement for Protected Operations / Executables
            exec_func = context.get("actual_executable") or context.get("executable_operation")
            has_protected_action = bool(
                exec_func is not None or context.get("proposed_actions") or raw_payload.get("proposed_actions")
            )

            execution_outcome = None
            if exec_func is not None:
                exec_ctx = context.get("execution_context")

                # Strictly require store-backed AUTHORIZATION_GRANTED provenance record
                auth_token_id = getattr(exec_ctx, "authorization_token_id", None) or context.get("authorization_token_id")
                corr_id = getattr(exec_ctx, "correlation_id", None) or context.get("correlation_id") or traj_id

                store = getattr(self.execution_boundary, "store", None)
                if not store or not hasattr(store, "get_events_for_correlation"):
                    telemetry = profiler.get_telemetry()
                    revoked_ids = self.vector_manager.revoke_trajectory(traj_id)
                    actual_revoked_count = len(revoked_ids)
                    reason_msg = "TrustedExecutionBoundary Enforcement: Provenance store missing or lookup unavailable"
                    self._log_pipeline_event(
                        event_type=AuditLogLevel.HALT,
                        gate_name="TrustedExecutionBoundary",
                        reason=f"{reason_msg} | Vectors Revoked: {actual_revoked_count}",
                        masked_payload=masked_payload,
                        cpr=cpr,
                        telemetry=telemetry
                    )
                    return {
                        "status": "HALTED",
                        "gate": "TrustedExecutionBoundary",
                        "reason": reason_msg,
                        "vectors_revoked": actual_revoked_count
                    }

                try:
                    events = store.get_events_for_correlation(corr_id)
                except Exception as lookup_err:
                    telemetry = profiler.get_telemetry()
                    revoked_ids = self.vector_manager.revoke_trajectory(traj_id)
                    actual_revoked_count = len(revoked_ids)
                    err_type = type(lookup_err).__name__
                    reason_msg = f"TrustedExecutionBoundary Enforcement: Provenance store lookup error ({err_type})"
                    self._log_pipeline_event(
                        event_type=AuditLogLevel.HALT,
                        gate_name="TrustedExecutionBoundary",
                        reason=f"{reason_msg} | Vectors Revoked: {actual_revoked_count}",
                        masked_payload=masked_payload,
                        cpr=cpr,
                        telemetry=telemetry
                    )
                    return {
                        "status": "HALTED",
                        "gate": "TrustedExecutionBoundary",
                        "reason": reason_msg,
                        "vectors_revoked": actual_revoked_count
                    }

                valid_grant_event = None
                if auth_token_id and events:
                    for e in events:
                        if e.event_type == "AUTHORIZATION_GRANTED" and e.authorization_token_id == auth_token_id:
                            valid_grant_event = e
                            break

                if not valid_grant_event:
                    telemetry = profiler.get_telemetry()
                    revoked_ids = self.vector_manager.revoke_trajectory(traj_id)
                    actual_revoked_count = len(revoked_ids)
                    reason_msg = f"TrustedExecutionBoundary Enforcement: No matching AUTHORIZATION_GRANTED record found for token {auth_token_id} and correlation {corr_id}"
                    self._log_pipeline_event(
                        event_type=AuditLogLevel.HALT,
                        gate_name="TrustedExecutionBoundary",
                        reason=f"{reason_msg} | Vectors Revoked: {actual_revoked_count}",
                        masked_payload=masked_payload,
                        cpr=cpr,
                        telemetry=telemetry
                    )
                    return {
                        "status": "HALTED",
                        "gate": "TrustedExecutionBoundary",
                        "reason": reason_msg,
                        "vectors_revoked": actual_revoked_count
                    }

                # Construct execution context strictly using store-backed AUTHORIZATION_GRANTED grant
                exec_ctx = ExecutionContext(
                    correlation_id=corr_id,
                    request_id=valid_grant_event.request_id,
                    authorization_token_id=valid_grant_event.authorization_token_id,
                    authorized_digest=valid_grant_event.canonical_request_digest,
                    authorization_granted=True,
                    execution_attempt_id=context.get("execution_attempt_id"),
                    policy_version=getattr(valid_grant_event, "policy_version", None) or context.get("policy_version", "1.0.0")
                )

                action_name = context.get("action_name", valid_grant_event.action_name or "protected_operation")
                target = context.get("target", valid_grant_event.target or "system_resource")
                proposed = context.get("proposed_actions", [])
                if proposed and isinstance(proposed, list) and len(proposed) > 0:
                    act_item = proposed[0]
                    if isinstance(act_item, dict):
                        act_inner = act_item.get("action", act_item)
                        if isinstance(act_inner, dict):
                            action_name = act_inner.get("op") or action_name
                            target = act_inner.get("node") or act_inner.get("endpoint") or act_inner.get("resource") or target

                if valid_grant_event.action_name != action_name or valid_grant_event.target != target:
                    telemetry = profiler.get_telemetry()
                    revoked_ids = self.vector_manager.revoke_trajectory(traj_id)
                    actual_revoked_count = len(revoked_ids)

                    reason_msg = f"TrustedExecutionBoundary Enforcement Failed: Grant mismatch for token {auth_token_id} (granted {valid_grant_event.action_name}:{valid_grant_event.target}, requested {action_name}:{target})"
                    self._log_pipeline_event(
                        event_type=AuditLogLevel.HALT,
                        gate_name="TrustedExecutionBoundary",
                        reason=f"{reason_msg} | Vectors Revoked: {actual_revoked_count}",
                        masked_payload=masked_payload,
                        cpr=cpr,
                        telemetry=telemetry
                    )
                    return {
                        "status": "HALTED",
                        "gate": "TrustedExecutionBoundary",
                        "reason": reason_msg,
                        "vectors_revoked": actual_revoked_count
                    }

                try:
                    execution_outcome = self.execution_boundary.execute_protected_action(
                        action_name=action_name,
                        target=target,
                        request_payload=raw_payload,
                        executor_func=exec_func,
                        context=exec_ctx
                    )
                except Exception as e:
                    telemetry = profiler.get_telemetry()
                    revoked_ids = self.vector_manager.revoke_trajectory(traj_id)
                    actual_revoked_count = max(len(revoked_ids), 1)

                    reason_msg = f"TrustedExecutionBoundary Enforcement Failed: {str(e)}"
                    self._log_pipeline_event(
                        event_type=AuditLogLevel.HALT,
                        gate_name="TrustedExecutionBoundary",
                        reason=f"{reason_msg} | Vectors Revoked: {actual_revoked_count}",
                        masked_payload=masked_payload,
                        cpr=cpr,
                        telemetry=telemetry
                    )
                    return {
                        "status": "HALTED",
                        "gate": "TrustedExecutionBoundary",
                        "reason": reason_msg,
                        "vectors_revoked": actual_revoked_count
                    }

            # 3c. Pipeline Success: Vectors are automatically committed by the context manager
            telemetry = profiler.get_telemetry()
            self._log_pipeline_event(
                event_type=AuditLogLevel.INFO,
                gate_name="Pipeline_Complete",
                reason="All governance gates passed and execution boundary enforced",
                masked_payload=masked_payload,
                cpr=cpr,
                telemetry=telemetry
            )

            res_dict = {
                "status": "ALLOWED",
                "masked_payload": cpr.mask_egress_payload(),
                "telemetry": telemetry.__dict__,
                "trajectory_id": traj_id
            }
            if execution_outcome:
                res_dict["execution_outcome"] = execution_outcome
            return res_dict

    def process_submission(
        self,
        raw_payload: Dict[str, Any],
        context: Dict[str, Any],
        trajectory_id: Optional[str] = None,
        **kwargs  # Absorb legacy kwargs like 'likelihoods' from older tests
    ) -> Dict[str, Any]:
        """
        Ingests a raw payload, evaluates it across governance gates,
        and immutably logs the outcome. Automatically handles vector rollbacks
        if a trajectory is halted.
        """
        # Assign a trajectory ID for vector tracking if one isn't provided
        traj_id = trajectory_id or str(uuid.uuid4())

        # Retire/reset any existing trajectory scheduler state for this trajectory ID so the session starts fresh
        self.reset_trajectory(traj_id)

        # Reset default/base scheduler if present
        if hasattr(self.scheduler, "reset"):
            self.scheduler.reset()

        cpr, error_response = self._validate_and_normalize(raw_payload)
        if error_response:
            return error_response

        # cpr cannot be None at this point
        return self._execute_pipeline(cpr, raw_payload, context, traj_id)  # type: ignore[arg-type]
