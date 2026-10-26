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
    signature: Optional[str] = None

    def compute_signature_payload(self) -> str:
        return f"{self.approval_id}:{self.approver_id}:{self.action_name}:{self.target}:{self.action_digest}:{self.request_id}:{self.policy_version}:{self.expires_at}"

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
    Immutably binds action details, target, arguments, executor, principal, task identity, contract version, and approval state.
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


class CapabilityRegistry:
    """
    Thread-safe, opaque server-side capability registry and single-use token manager.

    Deployment Replay Guarantee Notice:
    Single-use token consumption and replay prevention is thread-safe and process-local within this registry.
    Cross-worker replay prevention across independent processes or workers requires an atomic shared datastore
    (e.g., Redis or a distributed lock server).
    """

    def __init__(self, signing_secret: Optional[bytes] = None):
        self._lock = threading.Lock()
        self._capabilities: Dict[str, Capability] = {}
        self._consumed_tokens: Set[str] = set()
        self._consumed_approvals: Set[str] = set()
        self._revoked_tokens: Set[str] = set()
        self._denied_records: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self.signing_secret = signing_secret or hashlib.sha256(f"EPISTEMICOS_CAP_KEY_{uuid.uuid4()}".encode("utf-8")).digest()

    def sign_capability(self, cap: Capability) -> str:
        payload = f"{cap.token_id}:{cap.principal_id}:{cap.correlation_id}:{cap.request_id}:{cap.action_name}:{cap.target}:{cap.canonical_request_digest}:{cap.executor_id}:{cap.policy_version}:{cap.task_id or ''}:{cap.contract_version or ''}:{cap.contract_digest or ''}:{cap.expires_at}"
        return hmac.new(self.signing_secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()

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
            key = (str(task_id), str(action_name), str(target))
            self._denied_records[key] = {
                "task_id": str(task_id),
                "action_name": str(action_name),
                "target": str(target),
                "reason": str(reason),
                "contract_version": str(contract_version),
                "policy_version": str(policy_version),
                "timestamp": time.time()
            }

    def check_denial(
        self,
        task_id: str,
        action_name: str,
        target: str,
        contract_version: str = "1.0.0",
        policy_version: str = "1.0.0"
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        with self._lock:
            key = (str(task_id), str(action_name), str(target))
            rec = self._denied_records.get(key)
            if rec:
                # Same contract version and policy version means denial is active
                if rec.get("contract_version") == contract_version and rec.get("policy_version") == policy_version:
                    return True, rec
            return False, None

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
        executor_registry: Optional[Dict[str, Any]] = None
    ):
        self.default_policy = default_policy
        self.registry = registry or CapabilityRegistry()
        # Separate approval signing secret from capability signing key
        self.approval_signing_secret = approval_signing_secret or hashlib.sha256(f"EPISTEMICOS_APPROVAL_KEY_{uuid.uuid4()}".encode("utf-8")).digest()
        self.executor_registry: Dict[str, Any] = dict(executor_registry or {})

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
        """
        active_policy = policy or self.default_policy
        if not active_policy:
            return None, "AUTHORIZATION_DENIED_NO_TRUSTED_POLICY"

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

        # Validate against TrustedTaskContract if present
        if contract_obj:
            if contract_obj.is_expired(current_time=current_time):
                return None, "AUTHORIZATION_DENIED_EXPIRED_TASK_CONTRACT"

            if contract_obj.is_action_prohibited(action_name, target):
                reason = f"AUTHORIZATION_DENIED_CONTRACT_EXPLICIT_PROHIBITION:{action_name}:{target}"
                if effective_task_id:
                    self.registry.record_denial(effective_task_id, action_name, target, reason, contract_obj.contract_version, active_policy.version)
                return None, reason

            if not contract_obj.is_action_permitted(action_name, target):
                reason = f"AUTHORIZATION_DENIED_CONTRACT_SCOPE_VIOLATION:{action_name}:{target}"
                if effective_task_id:
                    self.registry.record_denial(effective_task_id, action_name, target, reason, contract_obj.contract_version, active_policy.version)
                return None, reason

        # Check durable denial registry if effective_task_id is known
        if effective_task_id:
            c_ver = contract_obj.contract_version if contract_obj else "1.0.0"
            is_denied, prev_denial = self.registry.check_denial(effective_task_id, action_name, target, c_ver, active_policy.version)
            if is_denied and prev_denial:
                return None, f"AUTHORIZATION_DENIED_DURABLE_DENIAL_ACTIVE:{prev_denial['reason']}"

        if not active_policy.is_operation_allowed(action_name):
            reason = f"AUTHORIZATION_DENIED_OPERATION_NOT_ALLOWED:{action_name}"
            if effective_task_id:
                c_ver = contract_obj.contract_version if contract_obj else "1.0.0"
                self.registry.record_denial(effective_task_id, action_name, target, reason, c_ver, active_policy.version)
            return None, reason

        if not active_policy.is_target_allowed(target):
            reason = f"AUTHORIZATION_DENIED_TARGET_NOT_ALLOWED:{target}"
            if effective_task_id:
                c_ver = contract_obj.contract_version if contract_obj else "1.0.0"
                self.registry.record_denial(effective_task_id, action_name, target, reason, c_ver, active_policy.version)
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
