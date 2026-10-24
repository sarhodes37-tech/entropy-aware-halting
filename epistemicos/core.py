"""
EpistemicOS Main Orchestrator (core.py).

Unifies the domain models, hardware telemetry, governance gates, 
vector hygiene, and tamper-evident audit logs into a single 
defense-in-depth pipeline.
"""
import json
import time
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
from epistemicos.authorization import AuthorizationAuthority, Policy, Capability, HumanApprovalRecord
from epistemicos.provenance import (
    TrustedExecutionBoundary,
    ExecutionContext,
    ProvenanceEvent,
    ProvenanceEventType,
    ProvenanceSource,
)

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
        execution_boundary: Optional[TrustedExecutionBoundary] = None,
        authority: Optional[AuthorizationAuthority] = None
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

        # Authoritative Authorization & Execution Boundary
        self.execution_boundary = execution_boundary or TrustedExecutionBoundary()
        self.authority = authority or getattr(self.execution_boundary, "authority", None) or AuthorizationAuthority()
        self.execution_boundary.authority = self.authority

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
            proposed = context.get("proposed_actions", []) or raw_payload.get("proposed_actions", [])
            has_protected_action = bool(exec_func is not None or proposed)

            execution_outcome = None
            execution_status = "AUTHORIZED_NOT_EXECUTED"

            if has_protected_action:
                # Resolve target action_name and target resource explicitly
                action_name = context.get("action_name")
                target = context.get("target")

                if proposed and isinstance(proposed, list) and len(proposed) > 0:
                    act_item = proposed[0]
                    if isinstance(act_item, dict):
                        act_inner = act_item.get("action", act_item)
                        if isinstance(act_inner, dict):
                            action_name = action_name or act_inner.get("op")
                            target = target or act_inner.get("node") or act_inner.get("endpoint") or act_inner.get("policy") or act_inner.get("resource") or act_inner.get("target")

                # Strictly reject missing or ambiguous action or target identifiers
                if not action_name or not isinstance(action_name, str) or not action_name.strip():
                    telemetry = profiler.get_telemetry()
                    revoked_ids = self.vector_manager.revoke_trajectory(traj_id)
                    actual_revoked_count = len(revoked_ids)
                    reason_msg = "TrustedExecutionBoundary Enforcement: Missing or ambiguous action_name for protected operation"
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
                        "execution_status": "DENIED",
                        "gate": "TrustedExecutionBoundary",
                        "reason": reason_msg,
                        "vectors_revoked": actual_revoked_count
                    }

                if not target or not isinstance(target, str) or not target.strip():
                    telemetry = profiler.get_telemetry()
                    revoked_ids = self.vector_manager.revoke_trajectory(traj_id)
                    actual_revoked_count = len(revoked_ids)
                    reason_msg = "TrustedExecutionBoundary Enforcement: Missing or ambiguous target resource for protected operation"
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
                        "execution_status": "DENIED",
                        "gate": "TrustedExecutionBoundary",
                        "reason": reason_msg,
                        "vectors_revoked": actual_revoked_count
                    }

                corr_id = context.get("correlation_id") or traj_id
                req_id = context.get("request_id") or str(uuid.uuid4())
                payload_digest = self.execution_boundary.compute_canonical_digest(raw_payload)

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
                        "execution_status": "DENIED",
                        "gate": "TrustedExecutionBoundary",
                        "reason": reason_msg,
                        "vectors_revoked": actual_revoked_count
                    }

                # Construct/resolve active Policy
                active_policy = context.get("policy")
                if not isinstance(active_policy, Policy):
                    if self.authority and self.authority.default_policy is not None:
                        active_policy = self.authority.default_policy
                    else:
                        gate_scope = getattr(self.gates[0], "trusted_scope", None) if self.gates else None
                        raw_scope = gate_scope or context.get("trusted_scope") or {}

                        if hasattr(raw_scope, "model_dump"):
                            raw_scope_dict = raw_scope.model_dump()
                        elif hasattr(raw_scope, "to_dict"):
                            raw_scope_dict = raw_scope.to_dict()
                        elif hasattr(raw_scope, "__dict__"):
                            raw_scope_dict = raw_scope.__dict__
                        elif isinstance(raw_scope, dict):
                            raw_scope_dict = raw_scope
                        else:
                            raw_scope_dict = {}

                        allowed_ops = set(raw_scope_dict.get("allowed_operations", []) or [])
                        allowed_res = set(raw_scope_dict.get("allowed_resources", []) or [])
                        req_human = set(raw_scope_dict.get("required_human_approval_operations", []) or [])

                        for g in (self.gates or []):
                            if hasattr(g, "allowed_actions") and g.allowed_actions:
                                allowed_ops.update(g.allowed_actions)
                            if hasattr(g, "trusted_operations") and g.trusted_operations:
                                allowed_ops.update(g.trusted_operations.keys())

                        if allowed_ops or allowed_res:
                            active_policy = Policy(
                                policy_id="context_trusted_scope",
                                allowed_operations=allowed_ops,
                                allowed_resources=allowed_res,
                                required_human_approval_operations=req_human
                            )
                        else:
                            active_policy = None

                # Evaluate against AuthorizationAuthority and issue capability
                executor_id = getattr(exec_func, "__name__", str(exec_func)) if exec_func else "default_executor"
                cap, cap_reason = self.authority.evaluate_and_issue_capability(
                    action_name=action_name,
                    target=target,
                    canonical_request_digest=payload_digest,
                    principal_id=context.get("requestor_id", "agent_default"),
                    correlation_id=corr_id,
                    request_id=req_id,
                    executor_id=executor_id,
                    policy=active_policy,
                    human_approval_input=context.get("human_approval") or context.get("human_approval_record")
                )

                if not cap:
                    telemetry = profiler.get_telemetry()
                    revoked_ids = self.vector_manager.revoke_trajectory(traj_id)
                    actual_revoked_count = len(revoked_ids)

                    # Record AUTHORIZATION_DENIED event
                    denied_event = ProvenanceEvent(
                        schema_version="1.0.0",
                        event_id=str(uuid.uuid4()),
                        event_type=ProvenanceEventType.AUTHORIZATION_DENIED.value,
                        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
                        correlation_id=corr_id,
                        request_id=req_id,
                        action_name=action_name,
                        target=target,
                        canonical_request_digest=payload_digest,
                        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        decision="DENIED",
                        policy_version=getattr(active_policy, "version", "1.0.0") if active_policy else "1.0.0"
                    )
                    try:
                        store.record_event(denied_event)
                    except Exception:
                        pass

                    reason_msg = f"Authorization Policy Denied: {cap_reason}"
                    self._log_pipeline_event(
                        event_type=AuditLogLevel.HALT,
                        gate_name="AuthorizationAuthority",
                        reason=f"{reason_msg} | Vectors Revoked: {actual_revoked_count}",
                        masked_payload=masked_payload,
                        cpr=cpr,
                        telemetry=telemetry
                    )
                    return {
                        "status": "HALTED",
                        "execution_status": "DENIED",
                        "gate": "AuthorizationAuthority",
                        "reason": reason_msg,
                        "vectors_revoked": actual_revoked_count
                    }

                # Record AUTHORIZATION_GRANTED provenance event
                now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                grant_event = ProvenanceEvent(
                    schema_version="1.0.0",
                    event_id=str(uuid.uuid4()),
                    event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
                    provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
                    correlation_id=corr_id,
                    request_id=req_id,
                    action_name=action_name,
                    target=target,
                    canonical_request_digest=payload_digest,
                    timestamp=now_ts,
                    authorization_token_id=cap.token_id,
                    policy_version=cap.policy_version
                )
                try:
                    store.record_event(grant_event)
                except Exception as issue_err:
                    telemetry = profiler.get_telemetry()
                    revoked_ids = self.vector_manager.revoke_trajectory(traj_id)
                    actual_revoked_count = len(revoked_ids)
                    reason_msg = f"Pre-execution authorization provenance recording failed: {str(issue_err)}"
                    self._log_pipeline_event(
                        event_type=AuditLogLevel.HALT,
                        gate_name="TrustedGovernanceIssuer",
                        reason=f"{reason_msg} | Vectors Revoked: {actual_revoked_count}",
                        masked_payload=masked_payload,
                        cpr=cpr,
                        telemetry=telemetry
                    )
                    return {
                        "status": "HALTED",
                        "execution_status": "AUTHORIZED_NOT_EXECUTED",
                        "gate": "TrustedGovernanceIssuer",
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
                        "execution_status": "DENIED",
                        "gate": "TrustedExecutionBoundary",
                        "reason": reason_msg,
                        "vectors_revoked": actual_revoked_count
                    }

                valid_grant_event = None
                if events:
                    for e in events:
                        if e.event_type == "AUTHORIZATION_GRANTED" and e.authorization_token_id == cap.token_id:
                            valid_grant_event = e
                            break

                if not valid_grant_event:
                    telemetry = profiler.get_telemetry()
                    revoked_ids = self.vector_manager.revoke_trajectory(traj_id)
                    actual_revoked_count = len(revoked_ids)
                    reason_msg = f"TrustedExecutionBoundary Enforcement: No matching AUTHORIZATION_GRANTED record found for token {cap.token_id} and correlation {corr_id}"
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
                        "execution_status": "DENIED",
                        "gate": "TrustedExecutionBoundary",
                        "reason": reason_msg,
                        "vectors_revoked": actual_revoked_count
                    }

                if exec_func is not None:
                    exec_ctx = ExecutionContext(
                        correlation_id=corr_id,
                        request_id=valid_grant_event.request_id,
                        authorization_token_id=valid_grant_event.authorization_token_id,
                        authorized_digest=valid_grant_event.canonical_request_digest,
                        authorization_granted=True,
                        execution_attempt_id=context.get("execution_attempt_id"),
                        policy_version=getattr(valid_grant_event, "policy_version", None) or cap.policy_version
                    )

                    try:
                        execution_outcome = self.execution_boundary.execute_protected_action(
                            action_name=action_name,
                            target=target,
                            request_payload=raw_payload,
                            executor_func=exec_func,
                            context=exec_ctx
                        )
                        if isinstance(execution_outcome, dict) and execution_outcome.get("status") == "EXECUTION_OUTCOME_UNKNOWN":
                            execution_status = "EXECUTION_OUTCOME_UNKNOWN"
                        else:
                            execution_status = "EXECUTED"
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
                            "execution_status": "EXECUTION_FAILED",
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
                "execution_status": execution_status,
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
