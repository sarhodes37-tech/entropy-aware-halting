"""
EpistemicOS Execution Provenance Subsystem.

Provides an independent execution-provenance record for agent-proposed actions,
control-plane authorization decisions, and trusted executor activity.
Ensures separation of trust boundaries between agent claims and trusted execution attestations.
"""

import os
import json
import time
import uuid
import hmac
import hashlib
import threading
from enum import Enum
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple, Set

from epistemicos.audit import _sanitize_sensitive_data, ReceiptGenerator
from epistemicos.authorization import AuthorizationAuthority, CapabilityRegistry, Capability, get_callable_identity

try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False


class ProvenanceEventType(Enum):
    ACTION_PROPOSED = "ACTION_PROPOSED"
    AUTHORIZATION_GRANTED = "AUTHORIZATION_GRANTED"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    EXECUTION_STARTED = "EXECUTION_STARTED"
    EXECUTION_SUCCEEDED = "EXECUTION_SUCCEEDED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    EXECUTION_INTERRUPTED = "EXECUTION_INTERRUPTED"
    EGRESS_BLOCKED = "EGRESS_BLOCKED"
    RECONCILIATION_MISMATCH = "RECONCILIATION_MISMATCH"


class ProvenanceSource(Enum):
    AGENT_ADAPTER = "AGENT_ADAPTER"
    GOVERNANCE_GATE = "GOVERNANCE_GATE"
    EXECUTOR = "EXECUTOR"
    EGRESS_GATE = "EGRESS_GATE"
    RECONCILER = "RECONCILER"


@dataclass
class ExecutionContext:
    """
    Execution context grouping correlation, request, and authorization parameters
    for protected action execution.
    """
    correlation_id: str
    request_id: str
    authorization_token_id: str
    authorized_digest: str
    authorization_granted: bool = True
    execution_attempt_id: Optional[str] = None
    policy_version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProvenanceEvent:
    schema_version: str
    event_id: str
    event_type: str
    provenance_source: str
    correlation_id: str
    request_id: str
    action_name: str
    target: str
    canonical_request_digest: str
    timestamp: str
    authorization_token_id: Optional[str] = None
    execution_attempt_id: Optional[str] = None
    decision: Optional[str] = None
    policy_version: Optional[str] = None
    outcome: Optional[Dict[str, Any]] = None
    sequence_number: int = 0
    prev_hash: Optional[str] = None
    audit_record_link: Optional[str] = None
    receipt_link: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        return _sanitize_sensitive_data(data)

    def compute_event_digest(self) -> str:
        data = self.to_dict()
        check_data = {k: v for k, v in data.items() if k != "event_digest"}
        serialized = json.dumps(check_data, sort_keys=True).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()


class ProvenanceStore:
    """Interface for execution provenance event persistence."""

    def record_event(self, event: ProvenanceEvent) -> None:
        raise NotImplementedError

    def get_events_for_correlation(self, correlation_id: str) -> List[ProvenanceEvent]:
        raise NotImplementedError


class LocalProvenanceStore(ProvenanceStore):
    """
    Local file-backed append-only provenance store with hash chaining and file locking.
    Note: A local process or file is not an independent trust boundary against host-level compromise.
    """

    GENESIS_SEED = b"EPISTEMICOS_PROVENANCE_GENESIS"
    _VALID_EVENT_TYPES: Set[str] = frozenset(e.value for e in ProvenanceEventType)
    _VALID_PROVENANCE_SOURCES: Set[str] = frozenset(s.value for s in ProvenanceSource)

    def __init__(
        self,
        log_path: str = "logs/provenance_audit.jsonl",
        fail_closed: bool = True,
        hmac_key: Optional[bytes] = None
    ):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.fail_closed = fail_closed
        self.hmac_key = hmac_key
        self._lock = threading.Lock()
        if self.hmac_key:
            self.genesis_hash = hmac.new(self.hmac_key, self.GENESIS_SEED, hashlib.sha256).hexdigest()
        else:
            self.genesis_hash = hashlib.sha256(self.GENESIS_SEED).hexdigest()

    def _compute_chain_hash(self, prev_hash: str, payload: Dict[str, Any]) -> str:
        serialized = json.dumps(payload, sort_keys=True)
        combined = f"{prev_hash}:{serialized}".encode("utf-8")
        if self.hmac_key:
            return hmac.new(self.hmac_key, combined, hashlib.sha256).hexdigest()
        return hashlib.sha256(combined).hexdigest()

    def record_event(self, event: ProvenanceEvent) -> Dict[str, Any]:
        with self._lock:
            try:
                # Validate schema version
                if not event.schema_version or not isinstance(event.schema_version, str):
                    raise ValueError("Invalid or missing schema_version")

                if event.event_type not in self._VALID_EVENT_TYPES:
                    raise ValueError(f"Unsupported event_type: {event.event_type}")

                if event.provenance_source not in self._VALID_PROVENANCE_SOURCES:
                    raise ValueError(f"Unsupported provenance_source: {event.provenance_source}")

                # Acquire file lock FIRST before inspecting health and reading tail hash to avoid multi-process race conditions
                with open(self.log_path, "a+", encoding="utf-8") as f:
                    if HAS_FCNTL:
                        fcntl.flock(f, fcntl.LOCK_EX)
                    try:
                        healthy, last_hash, seq, seen_ids = self._inspect_health()
                        if not healthy:
                            raise RuntimeError("Provenance log corruption detected")

                        if event.event_id in seen_ids:
                            raise ValueError(f"Duplicate event_id: {event.event_id}")

                        event.sequence_number = seq + 1
                        event.prev_hash = last_hash

                        event_dict = event.to_dict()
                        entry_hash = self._compute_chain_hash(last_hash, event_dict)
                        event_dict["entry_hash"] = entry_hash

                        f.write(json.dumps(event_dict) + "\n")
                        f.flush()
                        try:
                            os.fsync(f.fileno())
                        except OSError:
                            pass
                        return event_dict
                    finally:
                        if HAS_FCNTL:
                            fcntl.flock(f, fcntl.LOCK_UN)
            except Exception as e:
                if self.fail_closed:
                    raise RuntimeError(f"Provenance recording failed (fail-closed enforced): {str(e)}") from e
                return {}

    def _inspect_health(self) -> Tuple[bool, str, int, Set[str]]:
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return True, self.genesis_hash, 0, set()

        expected_prev = self.genesis_hash
        seen_ids = set()
        count = 0

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, 1):
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    entry = json.loads(line_str)
                except json.JSONDecodeError:
                    return False, expected_prev, count, seen_ids

                recorded_id = entry.get("event_id")
                if recorded_id:
                    if recorded_id in seen_ids:
                        return False, expected_prev, count, seen_ids
                    seen_ids.add(recorded_id)

                recorded_prev = entry.get("prev_hash")
                recorded_hash = entry.get("entry_hash")

                if recorded_prev != expected_prev:
                    return False, expected_prev, count, seen_ids

                check_data = {k: v for k, v in entry.items() if k != "entry_hash"}
                computed_hash = self._compute_chain_hash(recorded_prev, check_data)
                if computed_hash != recorded_hash:
                    return False, expected_prev, count, seen_ids

                expected_prev = recorded_hash
                count += 1

        return True, expected_prev, count, seen_ids

    def get_events_for_correlation(self, correlation_id: str) -> List[ProvenanceEvent]:
        events = []
        if not self.log_path.exists():
            return events

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    data = json.loads(line_str)
                    if data.get("correlation_id") == correlation_id:
                        filtered_data = {
                            k: v for k, v in data.items()
                            if k in ProvenanceEvent.__dataclass_fields__
                        }
                        events.append(ProvenanceEvent(**filtered_data))
                except Exception:
                    continue
        return events


class TrustedExecutionBoundary:
    """
    Protected action execution boundary enforcing atomic authorization token consumption
    and authoritative provenance event generation directly from executor activity.
    """

    def __init__(
        self,
        provenance_store: Optional[ProvenanceStore] = None,
        authority: Optional[AuthorizationAuthority] = None,
        capability_registry: Optional[CapabilityRegistry] = None
    ):
        self.store = provenance_store or LocalProvenanceStore()
        self.authority = authority or AuthorizationAuthority(registry=capability_registry)
        self.registry = self.authority.registry
        self._consumed_tokens: Set[str] = set()
        self._consumed_attempts: Set[str] = set()
        self._lock = threading.Lock()

    def compute_canonical_digest(self, payload: Any) -> str:
        if isinstance(payload, bytes):
            canonical_bytes = payload
        elif isinstance(payload, str):
            canonical_bytes = payload.encode("utf-8")
        else:
            try:
                canonical_bytes = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
            except Exception:
                sanitized = _sanitize_sensitive_data(payload)
                canonical_bytes = json.dumps(sanitized, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()

    def execute_protected_action(
        self,
        action_name: str,
        target: str,
        request_payload: Any,
        correlation_id: Optional[Any] = None,
        request_id: Optional[Any] = None,
        authorization_token_id: Optional[str] = None,
        authorized_digest: Optional[str] = None,
        authorization_granted: Optional[bool] = None,
        executor_func: Optional[Any] = None,
        execution_attempt_id: Optional[str] = None,
        policy_version: str = "1.0.0",
        *,
        context: Optional[ExecutionContext] = None
    ) -> Dict[str, Any]:
        """
        Atomically validates authorization and executes the protected operation,
        emitting trusted EXECUTION_STARTED, EXECUTION_SUCCEEDED, EXECUTION_FAILED, or EXECUTION_INTERRUPTED events.
        Accepts parameters via an `ExecutionContext` instance or individual arguments for backward compatibility.
        """
        if isinstance(correlation_id, ExecutionContext):
            context = correlation_id
            if executor_func is None and callable(request_id):
                executor_func = request_id

        if context is not None:
            corr_id = context.correlation_id
            req_id = context.request_id
            auth_token_id = context.authorization_token_id
            auth_digest = context.authorized_digest
            auth_granted = context.authorization_granted
            attempt_id = execution_attempt_id or context.execution_attempt_id or str(uuid.uuid4())
            pol_version = policy_version if policy_version != "1.0.0" else context.policy_version
        else:
            corr_id = correlation_id
            req_id = request_id
            auth_token_id = authorization_token_id
            auth_digest = authorized_digest
            auth_granted = authorization_granted
            attempt_id = execution_attempt_id or str(uuid.uuid4())
            pol_version = policy_version

        # Enforce strict validation of authorization evidence, token ID, digest, and executor
        if auth_granted is not True:
            raise PermissionError(f"Execution rejected: Authorization was not granted for token {auth_token_id}")

        if not auth_token_id or not isinstance(auth_token_id, str) or not auth_token_id.strip():
            raise PermissionError("Execution rejected: Missing or invalid authorization token ID")

        if not auth_digest or not isinstance(auth_digest, str) or not auth_digest.strip():
            raise PermissionError("Execution rejected: Missing or invalid authorized digest")

        if executor_func is None or not callable(executor_func):
            raise ValueError("Execution rejected: executor_func must be a callable object")

        current_digest = self.compute_canonical_digest(request_payload)
        now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        if current_digest != auth_digest:
            raise ValueError("Request payload digest changed between authorization and execution")

        executor_id = get_callable_identity(executor_func)

        # Option A Strict Trusted Executor Binding Check:
        # A valid capability alone NEVER authorizes an unverified or unregistered callable object.
        # Execution is permitted if and only if the provided callable is registered in executor_registry
        # under token_id or executor_id, AND executor_func matches that registered object identity ('is').
        if self.authority and hasattr(self.authority, "executor_registry"):
            bound_callable = self.authority.executor_registry.get(auth_token_id)
            if not bound_callable:
                bound_callable = self.authority.executor_registry.get(executor_id)

            if bound_callable:
                if executor_func is not bound_callable:
                    raise PermissionError("Execution rejected: Executable object identity mismatch for authorized token")
            else:
                cap_temp = self.registry.get_capability(auth_token_id)
                bound_id = cap_temp.executor_id if cap_temp else executor_id
                raise PermissionError(f"Execution rejected: Unregistered callable object cannot execute capability bound to '{bound_id}'")

        # Verify capability via trusted AuthorizationAuthority / CapabilityRegistry
        valid, cap_reason, cap = self.authority.verify_capability(
            token_id=auth_token_id,
            action_name=action_name,
            target=target,
            canonical_request_digest=current_digest,
            executor_id=executor_id,
            correlation_id=corr_id,
            request_id=req_id,
            policy_version=pol_version
        )
        if not valid:
            raise PermissionError(f"Execution rejected: {cap_reason}")

        # Atomic token consumption and retry check
        with self._lock:
            if not self.registry.consume_token(auth_token_id):
                raise PermissionError(f"Authorization token {auth_token_id} has already been consumed (replay attempt)")

            if attempt_id in self._consumed_attempts:
                raise ValueError(f"Execution attempt ID {attempt_id} has already been processed")

            self._consumed_tokens.add(auth_token_id)
            self._consumed_attempts.add(attempt_id)

        # Emit EXECUTION_STARTED
        start_event = ProvenanceEvent(
            schema_version="1.0.0",
            event_id=str(uuid.uuid4()),
            event_type=ProvenanceEventType.EXECUTION_STARTED.value,
            provenance_source=ProvenanceSource.EXECUTOR.value,
            correlation_id=corr_id,
            request_id=req_id,
            action_name=action_name,
            target=target,
            canonical_request_digest=current_digest,
            timestamp=now_ts,
            authorization_token_id=auth_token_id,
            execution_attempt_id=attempt_id,
            policy_version=pol_version
        )
        self.store.record_event(start_event)

        # Execute under BaseException catching to handle interruptions and errors
        try:
            result = executor_func()
        except Exception as e:
            end_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            fail_event = ProvenanceEvent(
                schema_version="1.0.0",
                event_id=str(uuid.uuid4()),
                event_type=ProvenanceEventType.EXECUTION_FAILED.value,
                provenance_source=ProvenanceSource.EXECUTOR.value,
                correlation_id=corr_id,
                request_id=req_id,
                action_name=action_name,
                target=target,
                canonical_request_digest=current_digest,
                timestamp=end_ts,
                authorization_token_id=auth_token_id,
                execution_attempt_id=attempt_id,
                policy_version=pol_version,
                outcome={"status": "FAILED", "error": str(e)}
            )
            try:
                self.store.record_event(fail_event)
            except Exception:
                pass
            raise
        except BaseException as be:
            end_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            interrupt_event = ProvenanceEvent(
                schema_version="1.0.0",
                event_id=str(uuid.uuid4()),
                event_type=ProvenanceEventType.EXECUTION_INTERRUPTED.value,
                provenance_source=ProvenanceSource.EXECUTOR.value,
                correlation_id=corr_id,
                request_id=req_id,
                action_name=action_name,
                target=target,
                canonical_request_digest=current_digest,
                timestamp=end_ts,
                authorization_token_id=auth_token_id,
                execution_attempt_id=attempt_id,
                policy_version=pol_version,
                outcome={"status": "INTERRUPTED", "reason": str(be)}
            )
            try:
                self.store.record_event(interrupt_event)
            except Exception:
                pass
            raise

        end_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        success_event = ProvenanceEvent(
            schema_version="1.0.0",
            event_id=str(uuid.uuid4()),
            event_type=ProvenanceEventType.EXECUTION_SUCCEEDED.value,
            provenance_source=ProvenanceSource.EXECUTOR.value,
            correlation_id=corr_id,
            request_id=req_id,
            action_name=action_name,
            target=target,
            canonical_request_digest=current_digest,
            timestamp=end_ts,
            authorization_token_id=auth_token_id,
            execution_attempt_id=attempt_id,
            policy_version=pol_version,
            outcome={"status": "SUCCESS", "result": _sanitize_sensitive_data(result)}
        )
        try:
            self.store.record_event(success_event)
        except Exception as audit_err:
            return {
                "status": "EXECUTION_OUTCOME_UNKNOWN",
                "result": result,
                "attempt_id": attempt_id,
                "audit_recording_failed": True,
                "recovery_required": True,
                "reason": f"Execution completed but terminal audit logging failed: {str(audit_err)}"
            }

        return {"status": "SUCCESS", "result": result, "attempt_id": attempt_id}


@dataclass
class ReconciliationReport:
    valid: bool
    status: str
    violations: List[str]
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ProvenanceReconciler:
    """
    Reconciles proposed actions, control-plane authorization decisions, and executor activity.
    Detects unauthorized execution, target/digest mismatches, false success claims,
    egress bypasses, and missing/interrupted execution traces.
    """

    def reconcile_correlation(
        self,
        correlation_id: str,
        events: List[ProvenanceEvent],
        agent_claimed_success: bool = False
    ) -> ReconciliationReport:
        violations: List[str] = []
        details: Dict[str, Any] = {
            "correlation_id": correlation_id,
            "event_count": len(events),
            "event_types": [e.event_type for e in events]
        }

        if not events:
            return ReconciliationReport(
                valid=False,
                status="INCOMPLETE_EVIDENCE",
                violations=["No provenance events recorded for correlation ID"],
                details=details
            )

        # Categorize events
        proposed = [e for e in events if e.event_type == ProvenanceEventType.ACTION_PROPOSED.value]
        auth_granted = [e for e in events if e.event_type == ProvenanceEventType.AUTHORIZATION_GRANTED.value]
        auth_denied = [e for e in events if e.event_type == ProvenanceEventType.AUTHORIZATION_DENIED.value]
        exec_started = [e for e in events if e.event_type == ProvenanceEventType.EXECUTION_STARTED.value]
        exec_succeeded = [e for e in events if e.event_type == ProvenanceEventType.EXECUTION_SUCCEEDED.value]
        exec_failed = [e for e in events if e.event_type == ProvenanceEventType.EXECUTION_FAILED.value]
        exec_interrupted = [e for e in events if e.event_type == ProvenanceEventType.EXECUTION_INTERRUPTED.value]
        egress_blocked = [e for e in events if e.event_type == ProvenanceEventType.EGRESS_BLOCKED.value]

        # Map authorizations by token_id and request_id (unredacted fields if available)
        auth_by_token: Dict[str, ProvenanceEvent] = {}
        auth_by_req: Dict[str, ProvenanceEvent] = {}
        for g in auth_granted:
            tok = g.authorization_token_id
            if tok and tok != "[REDACTED]":
                auth_by_token[tok] = g
            req = g.request_id
            if req and req != "[REDACTED]":
                auth_by_req[req] = g

        # Rule 1: Execution without matching authorization
        if exec_started and not auth_granted:
            violations.append("Execution started without authorization granted")

        # Rule 2: Denied or halted action that reached execution
        if auth_denied and exec_started:
            violations.append("Execution started for action that was authorization-denied")

        # Rule 3 & Rule 4: Match execution events against specific authorization decision by token_id / request_id
        for s in exec_started:
            tok = s.authorization_token_id
            req = s.request_id
            g = (auth_by_token.get(tok) if tok and tok != "[REDACTED]" else None) or \
                (auth_by_req.get(req) if req and req != "[REDACTED]" else None)

            # Fallback for single auth_granted record if redacted
            if not g and len(auth_granted) == 1:
                g = auth_granted[0]

            if g:
                if s.target != g.target or s.action_name != g.action_name:
                    violations.append(f"Execution target or action name mismatch for token {s.authorization_token_id}: granted ({g.action_name}:{g.target}), executed ({s.action_name}:{s.target})")
                if s.canonical_request_digest != g.canonical_request_digest:
                    violations.append(f"Request digest changed between authorization ({g.canonical_request_digest}) and execution ({s.canonical_request_digest})")
            elif auth_granted:
                violations.append(f"Execution attempt {s.execution_attempt_id} could not be matched to an authorization grant")

        # Rule 5: Reported success without executor-issued success event
        if agent_claimed_success and not exec_succeeded:
            violations.append("Agent claimed execution success, but no trusted executor success event was emitted")

        # Rule 6: Duplicate execution attempts for a single-use authorization
        token_exec_counts: Dict[str, int] = {}
        for s in exec_started:
            tok = s.authorization_token_id or "UNKNOWN"
            token_exec_counts[tok] = token_exec_counts.get(tok, 0) + 1
            if token_exec_counts[tok] > 1:
                violations.append(f"Multiple execution attempts detected for single-use authorization token: {tok}")

        # Rule 7: Missing or interrupted execution records (started but no terminal event)
        started_attempts = {s.execution_attempt_id for s in exec_started if s.execution_attempt_id}
        ended_attempts = {e.execution_attempt_id for e in (exec_succeeded + exec_failed + exec_interrupted) if e.execution_attempt_id}
        unended_attempts = started_attempts - ended_attempts
        if unended_attempts:
            violations.append(f"Execution started but missing terminal outcome event for attempts: {list(unended_attempts)}")

        # Rule 8: Egress blocked by Shower Curtain despite agent reporting successful disclosure
        if egress_blocked and agent_claimed_success:
            violations.append("Agent claimed successful disclosure, but egress was blocked by Shower Curtain")

        # Determine status
        if violations:
            status = "RECONCILIATION_MISMATCH"
            valid = False
        elif not exec_succeeded and not exec_failed and not exec_interrupted and auth_granted:
            status = "INCOMPLETE_EVIDENCE"
            valid = False
        else:
            status = "RECONCILED"
            valid = True

        return ReconciliationReport(
            valid=valid,
            status=status,
            violations=violations,
            details=details
        )
