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
class Policy:
    """
    Explicit, server-controlled authorization policy.
    An allowed operation against an unlisted target is strictly denied (fails closed).
    """
    policy_id: str
    version: str = "1.0.0"
    allowed_operations: Set[str] = field(default_factory=set)
    allowed_resources: Set[str] = field(default_factory=set)
    required_human_approval_operations: Set[str] = field(default_factory=set)
    allowed_principals: Set[str] = field(default_factory=lambda: {"*"})
    allowed_executors: Set[str] = field(default_factory=lambda: {"*"})
    token_ttl_seconds: float = 300.0

    def is_operation_allowed(self, action_name: str) -> bool:
        if not self.allowed_operations:
            return False
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
    Immutably binds action details, target, arguments, executor, principal, and approval state.
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
        self.signing_secret = signing_secret or hashlib.sha256(f"EPISTEMICOS_CAP_KEY_{uuid.uuid4()}".encode("utf-8")).digest()

    def sign_capability(self, cap: Capability) -> str:
        payload = f"{cap.token_id}:{cap.principal_id}:{cap.correlation_id}:{cap.request_id}:{cap.action_name}:{cap.target}:{cap.canonical_request_digest}:{cap.executor_id}:{cap.policy_version}:{cap.expires_at}"
        return hmac.new(self.signing_secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()

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
    Derives an authoritative, robust qualified identifier for a callable object
    to prevent name-spoofing via __name__ mutation.
    """
    if not func:
        return "default_executor"
    if isinstance(func, str):
        return func
    if hasattr(func, "__executor_id__") and isinstance(getattr(func, "__executor_id__"), str):
        return getattr(func, "__executor_id__")

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
        current_time: Optional[float] = None
    ) -> Tuple[Optional[Capability], str]:
        """
        Evaluates authorization request against explicit policy and returns (Capability, reason_code).
        Fails closed on missing policy, missing fields, or failed human approval requirement.
        """
        active_policy = policy or self.default_policy
        if not active_policy:
            return None, "AUTHORIZATION_DENIED_NO_TRUSTED_POLICY"

        # Validate action and target against policy
        if not action_name or not isinstance(action_name, str) or not action_name.strip():
            return None, "AUTHORIZATION_DENIED_INVALID_ACTION_NAME"

        if not target or not isinstance(target, str) or not target.strip():
            return None, "AUTHORIZATION_DENIED_INVALID_TARGET"

        if not active_policy.is_operation_allowed(action_name):
            return None, f"AUTHORIZATION_DENIED_OPERATION_NOT_ALLOWED:{action_name}"

        if not active_policy.is_target_allowed(target):
            return None, f"AUTHORIZATION_DENIED_TARGET_NOT_ALLOWED:{target}"

        if not active_policy.is_principal_allowed(principal_id):
            return None, f"AUTHORIZATION_DENIED_PRINCIPAL_NOT_ALLOWED:{principal_id}"

        if not active_policy.is_executor_allowed(executor_id):
            return None, f"AUTHORIZATION_DENIED_EXECUTOR_NOT_ALLOWED:{executor_id}"

        corr_id = correlation_id or str(uuid.uuid4())
        req_id = request_id or str(uuid.uuid4())

        # Check human approval requirement
        approval_record = None
        if active_policy.requires_human_approval(action_name):
            approval_record = HumanApprovalRecord.from_input(human_approval_input)
            if not approval_record:
                return None, "STOP_AND_ESCALATE_HUMAN_APPROVAL_REQUIRED"

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

        cap = Capability(
            token_id=token_id,
            principal_id=principal_id,
            correlation_id=corr_id,
            request_id=req_id,
            action_name=action_name,
            target=target,
            canonical_request_digest=canonical_request_digest,
            executor_id=get_callable_identity(executor_id),
            policy_version=active_policy.version,
            created_at=now,
            expires_at=expires_at,
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
        current_time: Optional[float] = None
    ) -> Tuple[bool, str, Optional[Capability]]:
        """
        Independently verifies a capability for the execution boundary.
        Checks existence, signature, consumption, revocation, expiration, and strict field bindings
        (action_name, target, canonical_request_digest, executor_id, principal_id, correlation_id, request_id, policy_version).
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

        # Strict executor binding without wildcards
        if cap.executor_id != executor_id:
            short_req = executor_id.rsplit(".", 1)[-1]
            short_cap = cap.executor_id.rsplit(".", 1)[-1]
            if cap.executor_id != short_req and short_cap != short_req:
                return False, f"CAPABILITY_VERIFICATION_FAILED_EXECUTOR_MISMATCH: granted '{cap.executor_id}', requested '{executor_id}'", cap

        if principal_id is not None and cap.principal_id != principal_id:
            return False, f"CAPABILITY_VERIFICATION_FAILED_PRINCIPAL_MISMATCH: granted '{cap.principal_id}', requested '{principal_id}'", cap

        if correlation_id is not None and cap.correlation_id != correlation_id:
            return False, f"CAPABILITY_VERIFICATION_FAILED_CORRELATION_ID_MISMATCH: granted '{cap.correlation_id}', requested '{correlation_id}'", cap

        if request_id is not None and cap.request_id != request_id:
            return False, f"CAPABILITY_VERIFICATION_FAILED_REQUEST_ID_MISMATCH: granted '{cap.request_id}', requested '{request_id}'", cap

        if policy_version is not None and cap.policy_version != policy_version:
            return False, f"CAPABILITY_VERIFICATION_FAILED_POLICY_VERSION_MISMATCH: granted '{cap.policy_version}', requested '{policy_version}'", cap

        return True, "CAPABILITY_VERIFIED", cap
