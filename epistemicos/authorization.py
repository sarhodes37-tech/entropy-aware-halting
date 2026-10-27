"""
EpistemicOS Authoritative Authorization & Verifiable Capability Subsystem.

Provides an independent, server-controlled policy authority and cryptographic/opaque capability issuer.
Ensures that protected side-effecting operations require an affirmative authorization decision
from a trusted policy authority, bound to principal, task, operation, target, argument digest,
registered executor, policy version, expiration, and authenticated human approval state.
"""

import time
import uuid
import hmac
import hashlib
import json
import math
import threading
from typing import Dict, Any, List, Optional, Set, Union, Tuple
from dataclasses import dataclass, field, asdict


GENERIC_CONTINUATION_PATTERNS = frozenset({
    "proceed",
    "continue",
    "please proceed",
    "please proceed to the next step using your best judgement",
    "please proceed to the next step using your best judgment",
    "go ahead",
    "ok",
    "yes",
    "approved",
    "do it",
    "next",
    "run",
})


@dataclass
class HumanApprovalRecord:
    """
    Typed, authenticated authorization input for human approval requirements.
    Forged, unsigned, expired, conversational text, generic encouragement, or automated harness replies
    are strictly rejected and cannot issue an authorization capability.
    """
    approval_id: str
    approver_id: str
    action_name: str
    target: str
    action_digest: str
    request_id: str
    policy_version: str = "1.0.0"
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    expires_at: Optional[float] = None
    task_id: Optional[str] = None
    signature: Optional[str] = None

    def compute_signature_payload(self) -> str:
        return f"{self.approval_id}:{self.approver_id}:{self.action_name}:{self.target}:{self.action_digest}:{self.request_id}:{self.policy_version}:{self.expires_at}:{self.task_id or ''}"

    def sign(self, signing_secret: bytes) -> str:
        payload = self.compute_signature_payload()
        self.signature = hmac.new(signing_secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return self.signature

    def verify_signature(self, signing_secret: bytes, current_time: Optional[float] = None) -> bool:
        if not self.signature or not isinstance(self.signature, str):
            return False

        now = current_time if current_time is not None else time.time()
        if self.expires_at is not None:
            if not isinstance(self.expires_at, (int, float)):
                try:
                    exp_val = float(self.expires_at)
                    if not math.isfinite(exp_val):
                        return False
                    self.expires_at = exp_val
                except (ValueError, TypeError):
                    return False
            if now >= self.expires_at:
                return False

        expected_sig = hmac.new(signing_secret, self.compute_signature_payload().encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected_sig)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_input(cls, val: Any) -> Optional["HumanApprovalRecord"]:
        """
        Parses and validates human approval input.
        Strictly rejects conversational strings and generic continuation text.
        """
        if val is None:
            return None

        if isinstance(val, str):
            # Pure string inputs (e.g. "please proceed", "continue") are strictly invalid
            return None

        if isinstance(val, cls):
            return val

        if isinstance(val, dict):
            # Ensure required typed fields are present and non-empty
            approval_id = val.get("approval_id") or val.get("id")
            approver_id = val.get("approver_id") or val.get("approver")
            action_name = val.get("action_name") or val.get("op")
            target = val.get("target") or val.get("node") or val.get("endpoint")
            action_digest = val.get("action_digest") or val.get("digest")
            request_id = val.get("request_id")

            if not all([approval_id, approver_id, action_name, target, action_digest, request_id]):
                return None

            exp_raw = val.get("expires_at")
            exp_val = None
            if exp_raw is not None:
                try:
                    exp_val = float(exp_raw)
                    if not math.isfinite(exp_val) or exp_val <= 0:
                        return None
                except (ValueError, TypeError):
                    return None

            return cls(
                approval_id=str(approval_id),
                approver_id=str(approver_id),
                action_name=str(action_name),
                target=str(target),
                action_digest=str(action_digest),
                request_id=str(request_id),
                policy_version=str(val.get("policy_version", "1.0.0")),
                timestamp=str(val.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))),
                expires_at=exp_val,
                task_id=str(val["task_id"]) if val.get("task_id") is not None else None,
                signature=val.get("signature")
            )

        return None


@dataclass
class TrustedTaskContract:
    """
    Explicit, versioned trusted task contract representing a task's authorized execution envelope.
    Binds task identity, contract version, permitted actions, resource scope, explicit prohibitions,
    approval requirements, and success evidence requirements.
    Explicit prohibitions strictly override broad permissions.
    """
    task_id: str
    contract_version: str = "1.0.0"
    permitted_actions: Set[str] = field(default_factory=set)
    resource_scope: Set[str] = field(default_factory=set)
    explicit_prohibitions: Set[str] = field(default_factory=set)
    prohibited_resources: Set[str] = field(default_factory=set)
    approval_requirements: Set[str] = field(default_factory=set)
    success_evidence_requirements: Set[str] = field(default_factory=set)
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    issuer_id: str = "TrustedTaskContractAuthority"
    signature: Optional[str] = None

    def compute_contract_digest(self) -> str:
        data = {
            "task_id": self.task_id,
            "contract_version": self.contract_version,
            "permitted_actions": sorted(list(self.permitted_actions)),
            "resource_scope": sorted(list(self.resource_scope)),
            "explicit_prohibitions": sorted(list(self.explicit_prohibitions)),
            "prohibited_resources": sorted(list(self.prohibited_resources)),
            "approval_requirements": sorted(list(self.approval_requirements)),
            "success_evidence_requirements": sorted(list(self.success_evidence_requirements)),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "issuer_id": self.issuer_id,
        }
        serialized = json.dumps(data, sort_keys=True).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def sign(self, signing_secret: bytes) -> str:
        digest = self.compute_contract_digest()
        self.signature = hmac.new(signing_secret, digest.encode("utf-8"), hashlib.sha256).hexdigest()
        return self.signature

    def verify_signature(self, signing_secret: bytes, current_time: Optional[float] = None) -> bool:
        if not self.signature or not isinstance(self.signature, str):
            return False

        if self.is_expired(current_time=current_time):
            return False

        digest = self.compute_contract_digest()
        expected_sig = hmac.new(signing_secret, digest.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected_sig)

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        if self.expires_at is None:
            return False
        now = current_time if current_time is not None else time.time()
        return now >= self.expires_at

    def is_action_prohibited(self, action_name: str, target: str) -> bool:
        """
        Precedence rule: Explicit prohibitions strictly override permissions.
        """
        if "*" in self.explicit_prohibitions or action_name in self.explicit_prohibitions:
            return True
        if "*" in self.prohibited_resources or target in self.prohibited_resources:
            return True
        return False

    def is_action_permitted(self, action_name: str, target: str) -> bool:
        if self.is_action_prohibited(action_name, target):
            return False

        action_allowed = ("*" in self.permitted_actions) or (action_name in self.permitted_actions)
        if not action_allowed:
            return False

        target_allowed = ("*" in self.resource_scope) or (target in self.resource_scope)
        if not target_allowed:
            return False

        return True

    def requires_human_approval(self, action_name: str) -> bool:
        return ("*" in self.approval_requirements) or (action_name in self.approval_requirements)

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "task_id": self.task_id,
            "contract_version": self.contract_version,
            "permitted_actions": list(self.permitted_actions),
            "resource_scope": list(self.resource_scope),
            "explicit_prohibitions": list(self.explicit_prohibitions),
            "prohibited_resources": list(self.prohibited_resources),
            "approval_requirements": list(self.approval_requirements),
            "success_evidence_requirements": list(self.success_evidence_requirements),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "issuer_id": self.issuer_id,
            "signature": self.signature,
            "contract_digest": self.compute_contract_digest()
        }
        return data

    @classmethod
    def from_dict(cls, val: Dict[str, Any]) -> "TrustedTaskContract":
        return cls(
            task_id=str(val["task_id"]),
            contract_version=str(val.get("contract_version", "1.0.0")),
            permitted_actions=set(val.get("permitted_actions", [])),
            resource_scope=set(val.get("resource_scope", [])),
            explicit_prohibitions=set(val.get("explicit_prohibitions", [])),
            prohibited_resources=set(val.get("prohibited_resources", [])),
            approval_requirements=set(val.get("approval_requirements", [])),
            success_evidence_requirements=set(val.get("success_evidence_requirements", [])),
            created_at=float(val.get("created_at", time.time())),
            expires_at=float(val["expires_at"]) if val.get("expires_at") is not None else None,
            issuer_id=str(val.get("issuer_id", "TrustedTaskContractAuthority")),
            signature=val.get("signature")
        )


@dataclass
class Policy:
    """
    Explicit, server-controlled authorization policy.
    An allowed operation against an unlisted target is strictly denied (fails closed).
    Defaults allowed_principals, allowed_executors, and allowed_approvers to wildcard {"*"}
    for unconstrained policies, but fails closed if an explicit empty set () is provided.
    """
    policy_id: str
    version: str = "1.0.0"
    allowed_operations: Set[str] = field(default_factory=set)
    allowed_resources: Set[str] = field(default_factory=set)
    required_human_approval_operations: Set[str] = field(default_factory=set)
    allowed_principals: Set[str] = field(default_factory=lambda: {"*"})
    allowed_executors: Set[str] = field(default_factory=lambda: {"*"})
    allowed_approvers: Set[str] = field(default_factory=lambda: {"*"})
    token_ttl_seconds: float = 300.0

    def is_operation_allowed(self, action_name: str) -> bool:
        if not self.allowed_operations:
            return False
        if "*" in self.allowed_operations:
            return True
        return action_name in self.allowed_operations

    def is_target_allowed(self, target: str) -> bool:
        """
        An allowed operation against an unlisted resource target is denied (fail closed).
        Supports wildcard '*' for unconstrained resource policies.
        """
        if not self.allowed_resources:
            return False
        if "*" in self.allowed_resources:
            return True
        return target in self.allowed_resources

    def requires_human_approval(self, action_name: str) -> bool:
        return action_name in self.required_human_approval_operations

    def is_principal_allowed(self, principal_id: str) -> bool:
        if not self.allowed_principals:
            return False  # Fail closed on empty allowed_principals set
        if "*" in self.allowed_principals:
            return True
        return principal_id in self.allowed_principals

    def is_executor_allowed(self, executor_id: str) -> bool:
        if not self.allowed_executors:
            return False  # Fail closed on empty allowed_executors set
        if "*" in self.allowed_executors:
            return True
        return executor_id in self.allowed_executors


@dataclass
class Capability:
    """
    Server-issued, verifiable authorization token/capability.
    Immutably binds action details, target, arguments, executor, principal, task identity, contract version, success evidence requirements, and approval state.
    """
    token_id: str
    principal_id: str
    correlation_id: str
    request_id: str
    action_name: str
    target: str
    canonical_request_digest: str
    executor_id: str
    policy_version: str
    created_at: float
    expires_at: float
    task_id: Optional[str] = None
    contract_version: Optional[str] = None
    contract_digest: Optional[str] = None
    required_success_evidence: Set[str] = field(default_factory=set)
    human_approval: Optional[HumanApprovalRecord] = None
    issuer_id: str = "TrustedAuthorizationAuthority"
    signature: Optional[str] = None

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        now = current_time if current_time is not None else time.time()
        return now >= self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.human_approval and hasattr(self.human_approval, "to_dict"):
            data["human_approval"] = self.human_approval.to_dict()
        return data


import contextlib


class CapabilityRegistry:
    """
    Thread-safe, persistent server-side capability registry and single-use token manager.

    Deployment Replay Guarantee Notice:
    Cross-process durable denial tracking and clearance serialization use atomic append-only file persistence
    with fsync and file locking (fcntl.flock). Single-use capability token consumption and approval replay tracking
    are thread-safe and process-synchronous.
    """

    def __init__(
        self,
        signing_secret: Optional[bytes] = None,
        denial_log_path: str = "logs/denial_registry.jsonl",
        fail_closed_persistence: bool = True
    ):
        self._lock = threading.RLock()
        self._capabilities: Dict[str, Capability] = {}
        self._consumed_tokens: Set[str] = set()
        self._consumed_approvals: Set[str] = set()
        self._revoked_tokens: Set[str] = set()
        self._denied_records: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self.denial_log_path = denial_log_path
        self.fail_closed_persistence = fail_closed_persistence

        if self.fail_closed_persistence and not self.denial_log_path:
            raise ValueError("Configuration error: denial_log_path is required when fail_closed_persistence=True")

        self.signing_secret = signing_secret or hashlib.sha256(f"EPISTEMICOS_CAP_KEY_{uuid.uuid4()}".encode("utf-8")).digest()
        self._load_persistent_denials()

    @contextlib.contextmanager
    def lock_registry(self):
        """
        Acquires both thread-level lock (_lock) and interprocess file-level lock (fcntl.flock)
        on the denial log lockfile to ensure strict atomicity across processes during authorization evaluations.
        """
        import os
        try:
            import fcntl
            has_fcntl = True
        except ImportError:
            has_fcntl = False

        lock_file_obj = None
        lock_path = (self.denial_log_path + ".lock") if self.denial_log_path else None

        with self._lock:
            if has_fcntl and lock_path:
                try:
                    os.makedirs(os.path.dirname(lock_path) or ".", exist_ok=True)
                    lock_file_obj = open(lock_path, "a", encoding="utf-8")
                    fcntl.flock(lock_file_obj.fileno(), fcntl.LOCK_EX)
                except Exception as e:
                    if lock_file_obj:
                        try:
                            lock_file_obj.close()
                        except Exception:
                            pass
                    if self.fail_closed_persistence:
                        raise RuntimeError(f"Lock registry failure: unable to acquire interprocess file lock ({str(e)})") from e

            try:
                yield
            finally:
                if lock_file_obj:
                    try:
                        if has_fcntl:
                            fcntl.flock(lock_file_obj.fileno(), fcntl.LOCK_UN)
                    except Exception as e:
                        if self.fail_closed_persistence:
                            raise RuntimeError(f"Lock registry release failure ({str(e)})") from e
                    finally:
                        try:
                            lock_file_obj.close()
                        except Exception:
                            pass

    def _load_persistent_denials(self) -> None:
        import os
        try:
            import fcntl
            has_fcntl = True
        except ImportError:
            has_fcntl = False

        if not self.denial_log_path or not os.path.exists(self.denial_log_path):
            return

        try:
            with open(self.denial_log_path, "r", encoding="utf-8") as f:
                if has_fcntl:
                    try:
                        fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                    except (OSError, IOError):
                        pass
                try:
                    for line in f:
                        line_str = line.strip()
                        if not line_str:
                            continue
                        try:
                            rec = json.loads(line_str)
                            if not isinstance(rec, dict) or "task_id" not in rec:
                                if self.fail_closed_persistence:
                                    raise RuntimeError(f"Corrupted record in denial log: {line_str}")
                                continue
                            key = (str(rec["task_id"]), str(rec["action_name"]), str(rec["target"]))
                            if rec.get("status") == "CLEARED":
                                self._denied_records.pop(key, None)
                                cleared_by = rec.get("cleared_by_approval")
                                if cleared_by and isinstance(cleared_by, str):
                                    self._consumed_approvals.add(cleared_by)
                            else:
                                self._denied_records[key] = rec
                        except Exception as parse_err:
                            if self.fail_closed_persistence:
                                raise RuntimeError(f"Failed to parse persistent denial log record: {str(parse_err)}") from parse_err
                            continue
                finally:
                    if has_fcntl:
                        try:
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                        except (OSError, IOError):
                            pass
        except Exception as e:
            if self.fail_closed_persistence:
                raise RuntimeError(f"Failed to load persistent denial log: {str(e)}") from e

    def sign_capability(self, cap: Capability) -> str:
        payload = f"{cap.token_id}:{cap.principal_id}:{cap.correlation_id}:{cap.request_id}:{cap.action_name}:{cap.target}:{cap.canonical_request_digest}:{cap.executor_id}:{cap.policy_version}:{cap.task_id or ''}:{cap.contract_version or ''}:{cap.contract_digest or ''}:{cap.expires_at}"
        return hmac.new(self.signing_secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def _record_denial_unlocked(
        self,
        task_id: str,
        action_name: str,
        target: str,
        reason: str,
        contract_version: str = "1.0.0",
        policy_version: str = "1.0.0"
    ) -> None:
        import os
        try:
            import fcntl
            has_fcntl = True
        except ImportError:
            has_fcntl = False

        rec = {
            "task_id": str(task_id),
            "action_name": str(action_name),
            "target": str(target),
            "reason": str(reason),
            "contract_version": str(contract_version),
            "policy_version": str(policy_version),
            "status": "ACTIVE",
            "timestamp": time.time()
        }

        # Transactional Persistence Ordering: Write, flush, and fsync to durable log FIRST
        if self.denial_log_path:
            try:
                os.makedirs(os.path.dirname(self.denial_log_path) or ".", exist_ok=True)
                with open(self.denial_log_path, "a", encoding="utf-8") as f:
                    if has_fcntl:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                    try:
                        f.write(json.dumps(rec) + "\n")
                        f.flush()
                        os.fsync(f.fileno())
                    finally:
                        if has_fcntl:
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except Exception as e:
                # If write fails: DO NOT MUTATE IN-MEMORY STATE, fail closed
                if self.fail_closed_persistence:
                    raise RuntimeError(f"Denial persistence failure: unable to durably record security decision ({str(e)})") from e

        # Durable file write succeeded -> Commit in-memory state mutation
        key = (str(task_id), str(action_name), str(target))
        self._denied_records[key] = rec

    def record_denial(
        self,
        task_id: str,
        action_name: str,
        target: str,
        reason: str,
        contract_version: str = "1.0.0",
        policy_version: str = "1.0.0"
    ) -> None:
        with self._lock:
            self._record_denial_unlocked(
                task_id=task_id,
                action_name=action_name,
                target=target,
                reason=reason,
                contract_version=contract_version,
                policy_version=policy_version
            )

    def clear_denial_with_approval(
        self,
        task_id: str,
        action_name: str,
        target: str,
        reauthorization_record: HumanApprovalRecord,
        signing_secret: bytes,
        current_time: Optional[float] = None
    ) -> Tuple[bool, str]:
        import os
        try:
            import fcntl
            has_fcntl = True
        except ImportError:
            has_fcntl = False

        if not reauthorization_record or not isinstance(reauthorization_record, HumanApprovalRecord):
            return False, "Invalid or missing reauthorization record"

        with self.lock_registry():
            # 1. Mandatory signature verification against trusted approval signing secret
            if not reauthorization_record.verify_signature(signing_secret, current_time=current_time):
                return False, "Reauthorization approval signature verification failed"

            # 2. Check task_id binding if present on reauthorization record
            if reauthorization_record.task_id and reauthorization_record.task_id != task_id:
                return False, f"Reauthorization approval task_id mismatch: bound to '{reauthorization_record.task_id}', requested '{task_id}'"

            # 3. Re-sync persistent state inside lock
            self._load_persistent_denials()

            # 4. Check replay prevention inside critical section
            if reauthorization_record.approval_id in self._consumed_approvals:
                return False, "Reauthorization approval record already consumed (replay attempt)"

            # 5. Check explicit clearance intent and strict field bindings
            has_clearance_intent = (
                "CLEAR_DENIAL" in reauthorization_record.action_name
                or "CLEAR_DENIAL" in reauthorization_record.target
            )
            if not has_clearance_intent:
                return False, "Approval record is an ordinary action approval and cannot be repurposed as denial clearance authorization"

            action_match = (
                reauthorization_record.action_name in (f"CLEAR_DENIAL:{action_name}", "CLEAR_DENIAL", action_name)
            )
            target_match = (
                reauthorization_record.target in (f"CLEAR_DENIAL:{target}", "CLEAR_DENIAL", target)
            )
            if not (action_match and target_match):
                return False, "Approval record does not match action_name and target for denial clearance"

            key = (str(task_id), str(action_name), str(target))
            rec = {
                "task_id": str(task_id),
                "action_name": str(action_name),
                "target": str(target),
                "status": "CLEARED",
                "cleared_by_approval": reauthorization_record.approval_id,
                "timestamp": time.time()
            }

            # Transactional Ordering: WRITE TO DURABLE LOG FILE FIRST BEFORE MUTATING IN-MEMORY STATE
            if self.denial_log_path:
                try:
                    os.makedirs(os.path.dirname(self.denial_log_path) or ".", exist_ok=True)
                    with open(self.denial_log_path, "a", encoding="utf-8") as f:
                        if has_fcntl:
                            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                        try:
                            f.write(json.dumps(rec) + "\n")
                            f.flush()
                            os.fsync(f.fileno())
                        finally:
                            if has_fcntl:
                                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                except Exception as e:
                    # Persistence failed -> DO NOT MUTATE IN-MEMORY DENIAL OR CONSUME APPROVAL
                    if self.fail_closed_persistence:
                        raise RuntimeError(f"Denial persistence failure: unable to durably record reauthorization clearance ({str(e)})") from e
                    return False, f"Denial persistence failure: {str(e)}"

            # Durable write succeeded! Now commit in-memory mutations
            self._denied_records.pop(key, None)
            self._consumed_approvals.add(reauthorization_record.approval_id)
            return True, "Denial successfully cleared with authenticated reauthorization"

    def _check_denial_unlocked(
        self,
        task_id: str,
        action_name: str,
        target: str,
        contract_version: str = "1.0.0",
        policy_version: str = "1.0.0"
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        # Re-sync from persistent storage to enforce cross-process durability
        self._load_persistent_denials()

        key = (str(task_id), str(action_name), str(target))
        rec = self._denied_records.get(key)
        if rec and rec.get("status") == "ACTIVE":
            # Denial is active regardless of contract_version changes, unless explicitly cleared
            return True, rec
        return False, None

    def check_denial(
        self,
        task_id: str,
        action_name: str,
        target: str,
        contract_version: str = "1.0.0",
        policy_version: str = "1.0.0"
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        with self._lock:
            return self._check_denial_unlocked(
                task_id=task_id,
                action_name=action_name,
                target=target,
                contract_version=contract_version,
                policy_version=policy_version
            )

    def register_capability(self, cap: Capability) -> None:
        with self._lock:
            cap.signature = self.sign_capability(cap)
            self._capabilities[cap.token_id] = cap

    def get_capability(self, token_id: str) -> Optional[Capability]:
        with self._lock:
            return self._capabilities.get(token_id)

    def is_consumed(self, token_id: str) -> bool:
        with self._lock:
            return token_id in self._consumed_tokens

    def is_revoked(self, token_id: str) -> bool:
        with self._lock:
            return token_id in self._revoked_tokens

    def is_approval_consumed(self, approval_id: str) -> bool:
        with self._lock:
            return approval_id in self._consumed_approvals

    def consume_token(self, token_id: str) -> bool:
        """
        Atomically consumes a single-use token. Returns True if consumed, False if already consumed or revoked.
        """
        with self._lock:
            if token_id in self._consumed_tokens or token_id in self._revoked_tokens:
                return False
            cap = self._capabilities.get(token_id)
            if cap and cap.human_approval:
                if cap.human_approval.approval_id in self._consumed_approvals:
                    return False
                self._consumed_approvals.add(cap.human_approval.approval_id)
            self._consumed_tokens.add(token_id)
            return True

    def revoke_token(self, token_id: str) -> None:
        with self._lock:
            self._revoked_tokens.add(token_id)


def get_callable_identity(func: Any) -> str:
    """
    Derives an authoritative, robust fully-qualified canonical identifier for a callable object.
    Uses module and qualname to prevent short-name collisions and name-spoofing via __name__ mutation.
    Caller-supplied attributes (such as __executor_id__) are strictly ignored.
    """
    if not func:
        return "default_executor"
    if isinstance(func, str):
        return func

    name = getattr(func, "__name__", str(func))
    if name == "<lambda>":
        return "<lambda>"

    module = getattr(func, "__module__", "")
    qualname = getattr(func, "__qualname__", name)

    if module and module not in ("builtins",):
        return f"{module}.{qualname}"
    return qualname


class AuthorizationAuthority:
    """
    Trusted policy authority for EpistemicOS.
    Evaluates proposed actions against explicit server policies, verifies typed human approval inputs,
    and issues signed, bound capability tokens.
    """

    def __init__(
        self,
        default_policy: Optional[Policy] = None,
        registry: Optional[CapabilityRegistry] = None,
        approval_signing_secret: Optional[bytes] = None,
        contract_signing_secret: Optional[bytes] = None,
        executor_registry: Optional[Dict[str, Any]] = None,
        require_task_contract: Optional[bool] = None
    ):
        import os
        self.default_policy = default_policy
        self.registry = registry or CapabilityRegistry()

        env_mode = os.getenv("EPISTEMICOS_ENV", os.getenv("ENVIRONMENT", "development")).strip().lower()
        self.is_production = env_mode in ("production", "prod")

        env_approval_sec = os.getenv("EPISTEMICOS_APPROVAL_SECRET")
        env_contract_sec = os.getenv("EPISTEMICOS_CONTRACT_SECRET")

        if self.is_production:
            if not env_approval_sec and not approval_signing_secret:
                raise ValueError("Production configuration error: EPISTEMICOS_APPROVAL_SECRET must be explicitly set in production mode")
            if not env_contract_sec and not contract_signing_secret:
                raise ValueError("Production configuration error: EPISTEMICOS_CONTRACT_SECRET must be explicitly set in production mode")
            if require_task_contract is False:
                raise ValueError("Production configuration error: task contract enforcement (require_task_contract) cannot be disabled in production mode")
            self.require_task_contract = True
        else:
            if require_task_contract is not None:
                self.require_task_contract = require_task_contract
            else:
                env_req = os.getenv("EPISTEMICOS_REQUIRE_TASK_CONTRACT", "").strip().lower()
                self.require_task_contract = env_req in ("1", "true", "yes", "on")

        if approval_signing_secret:
            self.approval_signing_secret = approval_signing_secret
        elif env_approval_sec:
            self.approval_signing_secret = env_approval_sec.encode("utf-8")
        else:
            self.approval_signing_secret = hashlib.sha256(f"EPISTEMICOS_APPROVAL_KEY_{uuid.uuid4()}".encode("utf-8")).digest()

        if contract_signing_secret:
            self.contract_signing_secret = contract_signing_secret
        elif env_contract_sec:
            self.contract_signing_secret = env_contract_sec.encode("utf-8")
        else:
            self.contract_signing_secret = hashlib.sha256(f"EPISTEMICOS_CONTRACT_KEY_{uuid.uuid4()}".encode("utf-8")).digest()

        self.executor_registry: Dict[str, Any] = dict(executor_registry or {})

    def clear_denial_with_approval(
        self,
        task_id: str,
        action_name: str,
        target: str,
        reauthorization_record: Any,
        current_time: Optional[float] = None
    ) -> Tuple[bool, str]:
        rec = HumanApprovalRecord.from_input(reauthorization_record)
        if not rec:
            return False, "Invalid reauthorization record format"
        return self.registry.clear_denial_with_approval(
            task_id=task_id,
            action_name=action_name,
            target=target,
            reauthorization_record=rec,
            signing_secret=self.approval_signing_secret,
            current_time=current_time
        )

    def register_executor(self, executor_id: str, executor_func: Any) -> None:
        """Registers an authoritative callable identity in the authority executor registry."""
        self.executor_registry[executor_id] = executor_func
        func_qual_id = get_callable_identity(executor_func)
        if func_qual_id != executor_id:
            self.executor_registry[func_qual_id] = executor_func

    def evaluate_and_issue_capability(
        self,
        action_name: str,
        target: str,
        canonical_request_digest: str,
        principal_id: str = "agent_default",
        correlation_id: Optional[str] = None,
        request_id: Optional[str] = None,
        executor_id: str = "default_executor",
        policy: Optional[Policy] = None,
        human_approval_input: Any = None,
        current_time: Optional[float] = None,
        task_contract: Optional[Union[TrustedTaskContract, Dict[str, Any]]] = None,
        task_id: Optional[str] = None
    ) -> Tuple[Optional[Capability], str]:
        """
        Evaluates authorization request against explicit policy and trusted task contract, returning (Capability, reason_code).
        Fails closed on missing policy, missing fields, explicit prohibitions, scope violations, or failed human approval.
        Atomic critical section across check_denial, policy evaluation, recording denial, and issuing capability.
        """
        active_policy = policy or self.default_policy
        if not active_policy:
            return None, "AUTHORIZATION_DENIED_NO_TRUSTED_POLICY"

        # If authority requires a task contract and none is provided, fail closed
        if self.require_task_contract and task_contract is None:
            return None, "AUTHORIZATION_DENIED_CONTRACT_REQUIRED"

        # Parse task contract if provided as dict
        contract_obj: Optional[TrustedTaskContract] = None
        if task_contract is not None:
            if isinstance(task_contract, TrustedTaskContract):
                contract_obj = task_contract
            elif isinstance(task_contract, dict):
                try:
                    contract_obj = TrustedTaskContract.from_dict(task_contract)
                except Exception:
                    return None, "AUTHORIZATION_DENIED_MALFORMED_TASK_CONTRACT"

        # Validate contract task_id vs task_id parameter if both provided
        effective_task_id = task_id or (contract_obj.task_id if contract_obj else None)
        if contract_obj and task_id and contract_obj.task_id != task_id:
            return None, "AUTHORIZATION_DENIED_TASK_IDENTITY_MISMATCH"

        # Validate action and target
        if not action_name or not isinstance(action_name, str) or not action_name.strip():
            return None, "AUTHORIZATION_DENIED_INVALID_ACTION_NAME"

        if not target or not isinstance(target, str) or not target.strip():
            return None, "AUTHORIZATION_DENIED_INVALID_TARGET"

        # Begin atomic critical section for checking denial, contract, policy, recording denial, and registering capability
        with self.registry.lock_registry():
            # Check durable denial registry if effective_task_id is known
            if effective_task_id:
                c_ver = contract_obj.contract_version if contract_obj else "1.0.0"
                is_denied, prev_denial = self.registry._check_denial_unlocked(effective_task_id, action_name, target, c_ver, active_policy.version)
                if is_denied and prev_denial:
                    return None, f"AUTHORIZATION_DENIED_DURABLE_DENIAL_ACTIVE:{prev_denial['reason']}"

            # Validate against TrustedTaskContract if present
            if contract_obj:
                # Mandatory contract signature verification against server-controlled contract signing secret
                if not contract_obj.verify_signature(self.contract_signing_secret, current_time=current_time):
                    return None, "AUTHORIZATION_DENIED_CONTRACT_SIGNATURE_INVALID"

                if contract_obj.is_expired(current_time=current_time):
                    return None, "AUTHORIZATION_DENIED_EXPIRED_TASK_CONTRACT"

                if contract_obj.is_action_prohibited(action_name, target):
                    reason = f"AUTHORIZATION_DENIED_CONTRACT_EXPLICIT_PROHIBITION:{action_name}:{target}"
                    if effective_task_id:
                        self.registry._record_denial_unlocked(effective_task_id, action_name, target, reason, contract_obj.contract_version, active_policy.version)
                    return None, reason

                if not contract_obj.is_action_permitted(action_name, target):
                    reason = f"AUTHORIZATION_DENIED_CONTRACT_SCOPE_VIOLATION:{action_name}:{target}"
                    if effective_task_id:
                        self.registry._record_denial_unlocked(effective_task_id, action_name, target, reason, contract_obj.contract_version, active_policy.version)
                    return None, reason

            if not active_policy.is_operation_allowed(action_name):
                reason = f"AUTHORIZATION_DENIED_OPERATION_NOT_ALLOWED:{action_name}"
                if effective_task_id:
                    c_ver = contract_obj.contract_version if contract_obj else "1.0.0"
                    self.registry._record_denial_unlocked(effective_task_id, action_name, target, reason, c_ver, active_policy.version)
                return None, reason

            if not active_policy.is_target_allowed(target):
                reason = f"AUTHORIZATION_DENIED_TARGET_NOT_ALLOWED:{target}"
                if effective_task_id:
                    c_ver = contract_obj.contract_version if contract_obj else "1.0.0"
                    self.registry._record_denial_unlocked(effective_task_id, action_name, target, reason, c_ver, active_policy.version)
                return None, reason

            if not active_policy.is_principal_allowed(principal_id):
                return None, f"AUTHORIZATION_DENIED_PRINCIPAL_NOT_ALLOWED:{principal_id}"

            if not active_policy.is_executor_allowed(executor_id):
                return None, f"AUTHORIZATION_DENIED_EXECUTOR_NOT_ALLOWED:{executor_id}"

            corr_id = correlation_id or str(uuid.uuid4())
            req_id = request_id or str(uuid.uuid4())

            # Check human approval requirement from policy OR task contract
            requires_approval = active_policy.requires_human_approval(action_name) or (contract_obj.requires_human_approval(action_name) if contract_obj else False)
            approval_record = None
            if requires_approval:
                approval_record = HumanApprovalRecord.from_input(human_approval_input)
                if not approval_record:
                    return None, "STOP_AND_ESCALATE_HUMAN_APPROVAL_REQUIRED"

                # Validate untrusted approver ID against policy allowed_approvers
                if active_policy.allowed_approvers is not None and "*" not in active_policy.allowed_approvers:
                    if approval_record.approver_id not in active_policy.allowed_approvers:
                        return None, f"AUTHORIZATION_DENIED_HUMAN_APPROVAL_UNTRUSTED_APPROVER:{approval_record.approver_id}"

                # Validate human approval binding
                if approval_record.approver_id == principal_id:
                    return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_SELF_APPROVAL_REJECTED"

                if approval_record.action_name != action_name or approval_record.target != target:
                    return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_BINDING_MISMATCH"

                if approval_record.action_digest != canonical_request_digest:
                    return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_DIGEST_MISMATCH"

                if approval_record.request_id != req_id:
                    return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_REQUEST_ID_MISMATCH"

                # Mandatory signature verification against trusted approval signing key
                if not approval_record.signature:
                    return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_MISSING_SIGNATURE"

                if not approval_record.verify_signature(self.approval_signing_secret, current_time=current_time):
                    return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_AUTHENTICATION_FAILED"

                if self.registry.is_approval_consumed(approval_record.approval_id):
                    return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_REPLAYED"

            now = current_time if current_time is not None else time.time()
            token_id = f"AUTH-CAP-{uuid.uuid4()}"
            expires_at = now + active_policy.token_ttl_seconds

            if callable(executor_id):
                exec_obj = executor_id
                executor_id_str = get_callable_identity(exec_obj)
                self.executor_registry[token_id] = exec_obj
                self.executor_registry[executor_id_str] = exec_obj
            else:
                executor_id_str = get_callable_identity(executor_id)
                if executor_id_str in self.executor_registry:
                    self.executor_registry[token_id] = self.executor_registry[executor_id_str]

            cap = Capability(
                token_id=token_id,
                principal_id=principal_id,
                correlation_id=corr_id,
                request_id=req_id,
                action_name=action_name,
                target=target,
                canonical_request_digest=canonical_request_digest,
                executor_id=executor_id_str,
                policy_version=active_policy.version,
                created_at=now,
                expires_at=expires_at,
                task_id=effective_task_id,
                contract_version=contract_obj.contract_version if contract_obj else None,
                contract_digest=contract_obj.compute_contract_digest() if contract_obj else None,
                required_success_evidence=set(contract_obj.success_evidence_requirements) if contract_obj else set(),
                human_approval=approval_record
            )

            self.registry.register_capability(cap)
            return cap, "AUTHORIZATION_GRANTED"

    def verify_capability(
        self,
        token_id: str,
        action_name: str,
        target: str,
        canonical_request_digest: str,
        executor_id: str,
        principal_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        request_id: Optional[str] = None,
        policy_version: Optional[str] = None,
        current_time: Optional[float] = None,
        task_id: Optional[str] = None,
        contract_version: Optional[str] = None
    ) -> Tuple[bool, str, Optional[Capability]]:
        """
        Independently verifies a capability for the execution boundary.
        Checks existence, signature, consumption, revocation, expiration, and strict field bindings
        (action_name, target, canonical_request_digest, executor_id, principal_id, correlation_id, request_id, policy_version, task_id, contract_version).
        Eliminates executor-binding wildcards (exact match required).
        """
        if not token_id or not isinstance(token_id, str):
            return False, "CAPABILITY_VERIFICATION_FAILED_INVALID_TOKEN_ID", None

        cap = self.registry.get_capability(token_id)
        if not cap:
            return False, "CAPABILITY_VERIFICATION_FAILED_UNKNOWN_TOKEN", None

        if self.registry.is_revoked(token_id):
            return False, "CAPABILITY_VERIFICATION_FAILED_REVOKED_TOKEN", None

        if self.registry.is_consumed(token_id):
            return False, "CAPABILITY_VERIFICATION_FAILED_REPLAY_TOKEN_ALREADY_CONSUMED: Authorization token has already been consumed", None

        if cap.is_expired(current_time):
            return False, "CAPABILITY_VERIFICATION_FAILED_EXPIRED_TOKEN", None

        # Verify cryptographic signature
        expected_sig = self.registry.sign_capability(cap)
        if not cap.signature or not hmac.compare_digest(cap.signature, expected_sig):
            return False, "CAPABILITY_VERIFICATION_FAILED_INVALID_SIGNATURE", None

        # Field binding verification
        if cap.action_name != action_name:
            return False, f"CAPABILITY_VERIFICATION_FAILED_ACTION_MISMATCH: granted '{cap.action_name}', requested '{action_name}'", cap

        if cap.target != target:
            return False, f"CAPABILITY_VERIFICATION_FAILED_TARGET_MISMATCH: granted '{cap.target}', requested '{target}'", cap

        if cap.canonical_request_digest != canonical_request_digest:
            return False, f"CAPABILITY_VERIFICATION_FAILED_DIGEST_MISMATCH: granted '{cap.canonical_request_digest}', requested '{canonical_request_digest}'", cap

        # Strict executor binding without wildcards: requires exact canonical executor identity match
        if cap.executor_id != executor_id:
            return False, f"CAPABILITY_VERIFICATION_FAILED_EXECUTOR_MISMATCH: granted '{cap.executor_id}', requested '{executor_id}'", cap

        if principal_id is not None and cap.principal_id != principal_id:
            return False, f"CAPABILITY_VERIFICATION_FAILED_PRINCIPAL_MISMATCH: granted '{cap.principal_id}', requested '{principal_id}'", cap

        if correlation_id is not None and cap.correlation_id != correlation_id:
            return False, f"CAPABILITY_VERIFICATION_FAILED_CORRELATION_ID_MISMATCH: granted '{cap.correlation_id}', requested '{correlation_id}'", cap

        if request_id is not None and cap.request_id != request_id:
            return False, f"CAPABILITY_VERIFICATION_FAILED_REQUEST_ID_MISMATCH: granted '{cap.request_id}', requested '{request_id}'", cap

        if policy_version is not None and cap.policy_version != policy_version:
            return False, f"CAPABILITY_VERIFICATION_FAILED_POLICY_VERSION_MISMATCH: granted '{cap.policy_version}', requested '{policy_version}'", cap

        if task_id is not None and cap.task_id != task_id:
            return False, f"CAPABILITY_VERIFICATION_FAILED_TASK_ID_MISMATCH: granted '{cap.task_id}', requested '{task_id}'", cap

        if contract_version is not None and cap.contract_version != contract_version:
            return False, f"CAPABILITY_VERIFICATION_FAILED_CONTRACT_VERSION_MISMATCH: granted '{cap.contract_version}', requested '{contract_version}'", cap

        return True, "CAPABILITY_VERIFIED", cap
