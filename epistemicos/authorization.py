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
import os
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Set, Union, Tuple
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, unquote


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


def normalize_target_scope(raw_target: str) -> str:
    """
    Canonicalizes target resource string into a normalized scope identifier.
    Strips trailing slashes, resolves traversal dots and unquotes percent-encoded paths,
    and isolates hostname/port if present.
    """
    if not raw_target:
        return "target:/:/"
    str_target = str(raw_target).strip()
    if "://" in str_target:
        parsed = urlparse(str_target)
        netloc = parsed.netloc.lower().strip() if parsed.netloc else ""
        raw_path = parsed.path or "/"
    else:
        netloc = ""
        raw_path = str_target if str_target.startswith("/") else "/" + str_target
        if "?" in raw_path or "#" in raw_path:
            parsed = urlparse("http://localhost" + raw_path)
            raw_path = parsed.path or "/"
    clean_path = unquote(raw_path).replace("\\", "/")
    norm_path = os.path.normpath(clean_path)
    if norm_path in (".", "", "/"):
        norm_path = "/"
    else:
        norm_path = norm_path.rstrip("/")
    return f"target:{netloc}:{norm_path}"


def canonicalize_fencing_scope(task_id: Optional[str], target: str) -> str:
    """
    Derives canonical execution scope key for monotonic fencing token generation and tracking.
    Binds the canonical task_id and normalized target path/endpoint.
    """
    t_id = (task_id or "").strip()
    task_part = f"task:{t_id}" if t_id else "task:__GLOBAL__"
    target_part = normalize_target_scope(target)
    return f"{task_part}|{target_part}"


class AuthorizationStore(ABC):
    """
    Abstract interface for authoritative capability and fencing token storage.
    Provides atomic, fail-closed state transitions for capability registration,
    consumption, revocation, and scope-level monotonic fencing token allocation.
    """

    @abstractmethod
    def issue_and_register_capability(self, cap: Any, signing_func: Any) -> Any:
        """
        Atomically allocates the next fencing token generation for the capability scope,
        finalizes the capability (fencing_token, scope_key), invokes signing_func(cap),
        and commits the registration record and fencing advance as a single atomic transaction.
        """
        pass

    @abstractmethod
    def register_capability(self, cap: Any) -> None:
        """Atomically registers a signed capability in authoritative storage."""
        pass

    @abstractmethod
    def get_capability(self, token_id: str) -> Optional[Any]:
        """Retrieves a capability by token_id from authoritative storage."""
        pass

    @abstractmethod
    def is_consumed(self, token_id: str) -> bool:
        """Checks if a capability token has already been consumed."""
        pass

    @abstractmethod
    def is_revoked(self, token_id: str) -> bool:
        """Checks if a capability token has been revoked."""
        pass

    @abstractmethod
    def is_approval_consumed(self, approval_id: str) -> bool:
        """Checks if a human approval ID has been consumed."""
        pass

    @abstractmethod
    def consume_capability(self, token_id: str, expected_fencing_token: Optional[int] = None) -> Tuple[bool, str]:
        """
        Atomically consumes a single-use capability token.
        Linearization Point: Committing the CONSUME transaction in authoritative storage.
        Rejects replay attempts, revoked tokens, and stale fencing tokens.
        Returns (success, reason_code).
        """
        pass

    @abstractmethod
    def revoke_capability(self, token_id: str, reason: str = "") -> Tuple[bool, str]:
        """
        Atomically revokes a capability token.
        Linearization Point: Committing the REVOKE transaction in authoritative storage.
        If already consumed, revocation cannot undo completed consumption.
        Returns (success, reason_code).
        """
        pass

    @abstractmethod
    def get_scope_fencing_token(self, scope_key: str) -> int:
        """Returns the authoritative highest fencing generation allocated for scope_key."""
        pass

    @abstractmethod
    def allocate_fencing_token(self, scope_key: str) -> int:
        """
        Atomically allocates and advances the monotonic fencing token generation for scope_key.
        Returns the newly allocated fencing token generation >= 1.
        """
        pass


class InMemoryAuthorizationStore(AuthorizationStore):
    """
    In-memory reference AuthorizationStore protected by threading.RLock.
    Suitable for single-process test isolation; does NOT provide cross-process safety.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._capabilities: Dict[str, Any] = {}
        self._consumed_tokens: Set[str] = set()
        self._revoked_tokens: Set[str] = set()
        self._consumed_approvals: Set[str] = set()
        self._scope_fencing_generations: Dict[str, int] = {}

    def issue_and_register_capability(self, cap: Any, signing_func: Any) -> Any:
        with self._lock:
            scope_key = getattr(cap, "scope_key", None) or canonicalize_fencing_scope(cap.task_id, cap.target)
            cap.scope_key = scope_key
            cur_fence = self._scope_fencing_generations.get(scope_key, 0)
            new_fence = cur_fence + 1
            cap.fencing_token = new_fence
            self._scope_fencing_generations[scope_key] = new_fence
            if signing_func:
                cap.signature = signing_func(cap)
            data = cap.to_dict() if hasattr(cap, "to_dict") else cap
            self._capabilities[cap.token_id] = cap
            return cap

    def register_capability(self, cap: Any) -> None:
        with self._lock:
            scope_key = getattr(cap, "scope_key", None) or canonicalize_fencing_scope(getattr(cap, "task_id", None), getattr(cap, "target", ""))
            cap.scope_key = scope_key
            fence_val = getattr(cap, "fencing_token", 1) or 1
            cur_fence = self._scope_fencing_generations.get(scope_key, 0)
            if fence_val > cur_fence:
                self._scope_fencing_generations[scope_key] = fence_val
            self._capabilities[cap.token_id] = cap

    def get_capability(self, token_id: str) -> Optional[Any]:
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

    def consume_capability(self, token_id: str, expected_fencing_token: Optional[int] = None) -> Tuple[bool, str]:
        with self._lock:
            if token_id in self._revoked_tokens:
                return False, "CAPABILITY_CONSUMPTION_FAILED_REVOKED"
            if token_id in self._consumed_tokens:
                return False, "CAPABILITY_CONSUMPTION_FAILED_ALREADY_CONSUMED"
            cap_obj = self._capabilities.get(token_id)
            if not cap_obj:
                return False, "CAPABILITY_CONSUMPTION_FAILED_UNKNOWN_TOKEN"

            scope_key = getattr(cap_obj, "scope_key", None) or (cap_obj.get("scope_key") if isinstance(cap_obj, dict) else None)
            cap_fence = getattr(cap_obj, "fencing_token", None) or (cap_obj.get("fencing_token") if isinstance(cap_obj, dict) else 1)
            if expected_fencing_token is not None and expected_fencing_token != cap_fence:
                return False, f"CAPABILITY_CONSUMPTION_FAILED_FENCING_TOKEN_MISMATCH: expected {expected_fencing_token}, got {cap_fence}"

            if scope_key:
                auth_fence = self._scope_fencing_generations.get(scope_key, 0)
                if cap_fence < auth_fence:
                    return False, f"CAPABILITY_CONSUMPTION_FAILED_STALE_FENCING_TOKEN: token generation {cap_fence} < authoritative scope generation {auth_fence}"
                if cap_fence > auth_fence:
                    return False, f"CAPABILITY_CONSUMPTION_FAILED_FUTURE_FENCING_TOKEN: token generation {cap_fence} > authoritative scope generation {auth_fence}"

            approval_id = None
            human_app = getattr(cap_obj, "human_approval", None) or (cap_obj.get("human_approval") if isinstance(cap_obj, dict) else None)
            if human_app:
                approval_id = getattr(human_app, "approval_id", None) or (human_app.get("approval_id") if isinstance(human_app, dict) else None)
                if approval_id and approval_id in self._consumed_approvals:
                    return False, "CAPABILITY_CONSUMPTION_FAILED_APPROVAL_REPLAYED"

            self._consumed_tokens.add(token_id)
            if approval_id:
                self._consumed_approvals.add(approval_id)
            return True, "CAPABILITY_CONSUMED_SUCCESSFULLY"

    def revoke_capability(self, token_id: str, reason: str = "") -> Tuple[bool, str]:
        with self._lock:
            if token_id in self._consumed_tokens:
                return False, "CAPABILITY_REVOCATION_REJECTED_ALREADY_CONSUMED"
            if token_id in self._revoked_tokens:
                return True, "CAPABILITY_ALREADY_REVOKED"
            self._revoked_tokens.add(token_id)
            return True, "CAPABILITY_REVOKED_SUCCESSFULLY"

    def get_scope_fencing_token(self, scope_key: str) -> int:
        with self._lock:
            return self._scope_fencing_generations.get(scope_key, 0)

    def allocate_fencing_token(self, scope_key: str) -> int:
        with self._lock:
            cur = self._scope_fencing_generations.get(scope_key, 0)
            nxt = cur + 1
            self._scope_fencing_generations[scope_key] = nxt
            return nxt


class FileAuthorizationStore(AuthorizationStore):
    """
    Authoritative file-backed AuthorizationStore providing cross-process synchronization
    via advisory POSIX file locking (fcntl.flock) and synchronous fsync updates.

    Architectural Boundary and Deployment Notice:
    - Supported Environment: Local multi-process or container environments sharing a POSIX-compliant
      local filesystem supporting fcntl.flock advisory locking.
    - Unsupported Environments / Limitations: Does NOT provide cross-node or distributed atomicity
      over NFS, SMB, CIFS, or distributed filesystems where fcntl flock semantics or fsync guarantees
      may be broken or decoupled. For multi-node distributed deployments, an external consensus-backed
      store (e.g. distributed transactional KV or Raft-backed coordinator) is required.
    - Transactional Model: Complete read-modify-write transactions are executed inside exclusive flock (LOCK_EX).
      All transactions write to durable append-only journal with f.flush() and os.fsync() before state mutation.
    - Fail-Closed Semantics: Any corrupted record, malformed JSON, unparseable line, lock failure,
      or I/O error immediately fails closed by raising RuntimeError and halting execution.
    """

    def __init__(
        self,
        store_path: str = "logs/authorization_store.jsonl",
        lock_path: Optional[str] = None,
        fail_closed: bool = True
    ):
        self.store_path = store_path
        self.lock_path = lock_path or (store_path + ".lock")
        self.fail_closed = fail_closed
        self._thread_lock = threading.RLock()
        self._lock_file = None
        self._lock_depth = 0

        self._capabilities: Dict[str, Any] = {}
        self._consumed_tokens: Set[str] = set()
        self._revoked_tokens: Set[str] = set()
        self._consumed_approvals: Set[str] = set()
        self._scope_fencing_generations: Dict[str, int] = {}

        os.makedirs(os.path.dirname(os.path.abspath(store_path)) or ".", exist_ok=True)
        self._sync_from_disk(acquire_lock=True)

    def _acquire_flock(self):
        try:
            import fcntl
            has_fcntl = True
        except ImportError:
            has_fcntl = False

        if not has_fcntl and self.fail_closed:
            raise RuntimeError("FileAuthorizationStore requires fcntl.flock for interprocess authorization atomicity")

        if self._lock_depth == 0:
            os.makedirs(os.path.dirname(os.path.abspath(self.lock_path)) or ".", exist_ok=True)
            self._lock_file = open(self.lock_path, "a", encoding="utf-8")
            if has_fcntl:
                try:
                    fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX)
                except Exception as e:
                    try:
                        self._lock_file.close()
                    except Exception:
                        pass
                    self._lock_file = None
                    if self.fail_closed:
                        raise RuntimeError(f"Failed to acquire interprocess flock on {self.lock_path}: {e}") from e
                    raise
        self._lock_depth += 1

    def _release_flock(self):
        try:
            import fcntl
            has_fcntl = True
        except ImportError:
            has_fcntl = False

        if self._lock_depth > 0:
            self._lock_depth -= 1
            if self._lock_depth == 0 and self._lock_file:
                try:
                    if has_fcntl:
                        fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
                except Exception as e:
                    if self.fail_closed:
                        raise RuntimeError(f"Failed to release interprocess flock on {self.lock_path}: {e}") from e
                finally:
                    try:
                        self._lock_file.close()
                    except Exception:
                        pass
                    self._lock_file = None

    def _sync_from_disk(self, acquire_lock: bool = True):
        with self._thread_lock:
            if acquire_lock:
                self._acquire_flock()
            try:
                if not os.path.exists(self.store_path):
                    return
                caps: Dict[str, Any] = {}
                consumed: Set[str] = set()
                revoked: Set[str] = set()
                approvals: Set[str] = set()
                fencing: Dict[str, int] = {}

                with open(self.store_path, "r", encoding="utf-8") as f:
                    for line_idx, line in enumerate(f, start=1):
                        l = line.strip()
                        if not l:
                            continue
                        try:
                            rec = json.loads(l)
                            if not isinstance(rec, dict):
                                raise ValueError("Record is not a JSON object")
                        except Exception as e:
                            if self.fail_closed:
                                raise RuntimeError(f"Corrupted or ambiguous authorization journal record at line {line_idx} in {self.store_path}: {l}") from e
                            continue

                        rec_type = rec.get("type")
                        if rec_type == "ISSUE_CAPABILITY":
                            tok = rec.get("token_id")
                            sk = rec.get("scope_key")
                            f_val = rec.get("fencing_token")
                            if not tok or not sk or f_val is None:
                                if self.fail_closed:
                                    raise RuntimeError(f"Corrupted ISSUE_CAPABILITY record at line {line_idx} in {self.store_path}")
                                continue
                            caps[tok] = rec.get("data")
                            fencing[sk] = max(fencing.get(sk, 0), int(f_val))
                        elif rec_type == "REGISTER_CAPABILITY":
                            tok = rec.get("token_id")
                            if not tok:
                                if self.fail_closed:
                                    raise RuntimeError(f"Corrupted REGISTER_CAPABILITY missing token_id at line {line_idx}")
                                continue
                            caps[tok] = rec.get("data")
                        elif rec_type == "CONSUME":
                            tok = rec.get("token_id")
                            if not tok:
                                if self.fail_closed:
                                    raise RuntimeError(f"Corrupted CONSUME missing token_id at line {line_idx}")
                                continue
                            consumed.add(tok)
                            app_id = rec.get("approval_id")
                            if app_id:
                                approvals.add(app_id)
                        elif rec_type == "REVOKE":
                            tok = rec.get("token_id")
                            if not tok:
                                if self.fail_closed:
                                    raise RuntimeError(f"Corrupted REVOKE missing token_id at line {line_idx}")
                                continue
                            revoked.add(tok)
                        elif rec_type == "FENCE":
                            sk = rec.get("scope_key")
                            tok = rec.get("fencing_token")
                            if not sk or tok is None:
                                if self.fail_closed:
                                    raise RuntimeError(f"Corrupted FENCE record at line {line_idx}")
                                continue
                            tok_int = int(tok)
                            fencing[sk] = max(fencing.get(sk, 0), tok_int)
                        elif rec_type == "INIT":
                            pass
                        else:
                            if self.fail_closed:
                                raise RuntimeError(f"Unknown or ambiguous record type '{rec_type}' at line {line_idx} in {self.store_path}")

                self._capabilities = caps
                self._consumed_tokens = consumed
                self._revoked_tokens = revoked
                self._consumed_approvals = approvals
                self._scope_fencing_generations = fencing
            finally:
                if acquire_lock:
                    self._release_flock()

    def _append_record_under_lock(self, rec: Dict[str, Any]):
        try:
            def _json_default(obj):
                if isinstance(obj, (set, frozenset)):
                    return list(obj)
                if hasattr(obj, "to_dict"):
                    return obj.to_dict()
                raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

            with open(self.store_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, default=_json_default) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            if self.fail_closed:
                raise RuntimeError(f"Authoritative storage failure: unable to persist authorization journal record ({str(e)})") from e
            raise

    def issue_and_register_capability(self, cap: Any, signing_func: Any) -> Any:
        with self._thread_lock:
            self._acquire_flock()
            try:
                self._sync_from_disk(acquire_lock=False)
                scope_key = getattr(cap, "scope_key", None) or canonicalize_fencing_scope(cap.task_id, cap.target)
                cap.scope_key = scope_key
                cur_fence = self._scope_fencing_generations.get(scope_key, 0)
                new_fence = cur_fence + 1
                cap.fencing_token = new_fence
                if signing_func:
                    cap.signature = signing_func(cap)
                data = cap.to_dict() if hasattr(cap, "to_dict") else cap

                # Atomic single-event journal commit: ISSUE_CAPABILITY
                issue_rec = {
                    "type": "ISSUE_CAPABILITY",
                    "scope_key": scope_key,
                    "fencing_token": new_fence,
                    "token_id": cap.token_id,
                    "data": data,
                    "timestamp": time.time()
                }
                self._append_record_under_lock(issue_rec)

                self._scope_fencing_generations[scope_key] = new_fence
                self._capabilities[cap.token_id] = data
                return cap
            finally:
                self._release_flock()

    def register_capability(self, cap: Any) -> None:
        with self._thread_lock:
            self._acquire_flock()
            try:
                self._sync_from_disk(acquire_lock=False)
                scope_key = getattr(cap, "scope_key", None) or canonicalize_fencing_scope(getattr(cap, "task_id", None), getattr(cap, "target", ""))
                cap.scope_key = scope_key
                fence_val = getattr(cap, "fencing_token", 1) or 1
                cur_fence = self._scope_fencing_generations.get(scope_key, 0)
                records = []
                if fence_val > cur_fence:
                    records.append({
                        "type": "FENCE",
                        "scope_key": scope_key,
                        "fencing_token": fence_val,
                        "timestamp": time.time()
                    })
                    self._scope_fencing_generations[scope_key] = fence_val
                data = cap.to_dict() if hasattr(cap, "to_dict") else cap
                records.append({
                    "type": "REGISTER_CAPABILITY",
                    "token_id": cap.token_id,
                    "data": data,
                    "timestamp": time.time()
                })
                for r in records:
                    self._append_record_under_lock(r)
                self._capabilities[cap.token_id] = data
            finally:
                self._release_flock()

    def get_capability(self, token_id: str) -> Optional[Any]:
        with self._thread_lock:
            self._acquire_flock()
            try:
                self._sync_from_disk(acquire_lock=False)
                cap_data = self._capabilities.get(token_id)
                if isinstance(cap_data, dict):
                    app_record = None
                    app_data = cap_data.get("human_approval")
                    if app_data and isinstance(app_data, dict):
                        app_record = HumanApprovalRecord.from_input(app_data)
                    elif isinstance(app_data, HumanApprovalRecord):
                        app_record = app_data
                    return Capability(
                        token_id=cap_data["token_id"],
                        principal_id=cap_data["principal_id"],
                        correlation_id=cap_data["correlation_id"],
                        request_id=cap_data["request_id"],
                        action_name=cap_data["action_name"],
                        target=cap_data["target"],
                        canonical_request_digest=cap_data["canonical_request_digest"],
                        executor_id=cap_data["executor_id"],
                        policy_version=cap_data["policy_version"],
                        created_at=float(cap_data["created_at"]),
                        expires_at=float(cap_data["expires_at"]),
                        task_id=cap_data.get("task_id"),
                        contract_version=cap_data.get("contract_version"),
                        contract_digest=cap_data.get("contract_digest"),
                        required_success_evidence=set(cap_data.get("required_success_evidence") or []),
                        human_approval=app_record,
                        issuer_id=cap_data.get("issuer_id", "TrustedAuthorizationAuthority"),
                        signature=cap_data.get("signature"),
                        fencing_token=int(cap_data.get("fencing_token", 1)),
                        scope_key=cap_data.get("scope_key")
                    )
                return cap_data
            finally:
                self._release_flock()

    def is_consumed(self, token_id: str) -> bool:
        with self._thread_lock:
            self._acquire_flock()
            try:
                self._sync_from_disk(acquire_lock=False)
                return token_id in self._consumed_tokens
            finally:
                self._release_flock()

    def is_revoked(self, token_id: str) -> bool:
        with self._thread_lock:
            self._acquire_flock()
            try:
                self._sync_from_disk(acquire_lock=False)
                return token_id in self._revoked_tokens
            finally:
                self._release_flock()

    def is_approval_consumed(self, approval_id: str) -> bool:
        with self._thread_lock:
            self._acquire_flock()
            try:
                self._sync_from_disk(acquire_lock=False)
                return approval_id in self._consumed_approvals
            finally:
                self._release_flock()

    def consume_capability(self, token_id: str, expected_fencing_token: Optional[int] = None) -> Tuple[bool, str]:
        with self._thread_lock:
            self._acquire_flock()
            try:
                self._sync_from_disk(acquire_lock=False)
                if token_id in self._revoked_tokens:
                    return False, "CAPABILITY_CONSUMPTION_FAILED_REVOKED"
                if token_id in self._consumed_tokens:
                    return False, "CAPABILITY_CONSUMPTION_FAILED_ALREADY_CONSUMED"

                cap_data = self._capabilities.get(token_id)
                if not cap_data:
                    return False, "CAPABILITY_CONSUMPTION_FAILED_UNKNOWN_TOKEN"

                scope_key = cap_data.get("scope_key") if isinstance(cap_data, dict) else getattr(cap_data, "scope_key", None)
                cap_fence = int(cap_data.get("fencing_token", 1) if isinstance(cap_data, dict) else getattr(cap_data, "fencing_token", 1))
                if expected_fencing_token is not None and expected_fencing_token != cap_fence:
                    return False, f"CAPABILITY_CONSUMPTION_FAILED_FENCING_TOKEN_MISMATCH: expected {expected_fencing_token}, got {cap_fence}"

                if scope_key:
                    auth_fence = self._scope_fencing_generations.get(scope_key, 0)
                    if cap_fence < auth_fence:
                        return False, f"CAPABILITY_CONSUMPTION_FAILED_STALE_FENCING_TOKEN: token generation {cap_fence} < authoritative scope generation {auth_fence}"
                    if cap_fence > auth_fence:
                        return False, f"CAPABILITY_CONSUMPTION_FAILED_FUTURE_FENCING_TOKEN: token generation {cap_fence} > authoritative scope generation {auth_fence}"

                approval_id = None
                human_app = cap_data.get("human_approval") if isinstance(cap_data, dict) else getattr(cap_data, "human_approval", None)
                if human_app:
                    approval_id = human_app.get("approval_id") if isinstance(human_app, dict) else getattr(human_app, "approval_id", None)
                    if approval_id and approval_id in self._consumed_approvals:
                        return False, "CAPABILITY_CONSUMPTION_FAILED_APPROVAL_REPLAYED"

                rec = {
                    "type": "CONSUME",
                    "token_id": token_id,
                    "approval_id": approval_id,
                    "fencing_token": cap_fence,
                    "timestamp": time.time()
                }
                self._append_record_under_lock(rec)
                self._consumed_tokens.add(token_id)
                if approval_id:
                    self._consumed_approvals.add(approval_id)
                return True, "CAPABILITY_CONSUMED_SUCCESSFULLY"
            finally:
                self._release_flock()

    def revoke_capability(self, token_id: str, reason: str = "") -> Tuple[bool, str]:
        with self._thread_lock:
            self._acquire_flock()
            try:
                self._sync_from_disk(acquire_lock=False)
                if token_id in self._consumed_tokens:
                    return False, "CAPABILITY_REVOCATION_REJECTED_ALREADY_CONSUMED"
                if token_id in self._revoked_tokens:
                    return True, "CAPABILITY_ALREADY_REVOKED"

                rec = {
                    "type": "REVOKE",
                    "token_id": token_id,
                    "reason": reason,
                    "timestamp": time.time()
                }
                self._append_record_under_lock(rec)
                self._revoked_tokens.add(token_id)
                return True, "CAPABILITY_REVOKED_SUCCESSFULLY"
            finally:
                self._release_flock()

    def get_scope_fencing_token(self, scope_key: str) -> int:
        with self._thread_lock:
            self._acquire_flock()
            try:
                self._sync_from_disk(acquire_lock=False)
                return self._scope_fencing_generations.get(scope_key, 0)
            finally:
                self._release_flock()

    def allocate_fencing_token(self, scope_key: str) -> int:
        with self._thread_lock:
            self._acquire_flock()
            try:
                self._sync_from_disk(acquire_lock=False)
                cur = self._scope_fencing_generations.get(scope_key, 0)
                nxt = cur + 1
                rec = {
                    "type": "FENCE",
                    "scope_key": scope_key,
                    "fencing_token": nxt,
                    "timestamp": time.time()
                }
                self._append_record_under_lock(rec)
                self._scope_fencing_generations[scope_key] = nxt
                return nxt
            finally:
                self._release_flock()


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """
    Cryptographically and authoritatively verified identity assertion representing
    an authenticated principal.
    A caller-supplied string, dictionary, or manually constructed object without
    a valid cryptographic signature from an independently trusted PrincipalProvider is strictly rejected.
    """
    principal_id: str
    issuer_id: str
    timestamp: float
    signature: str

    def __post_init__(self):
        if not self.principal_id or not isinstance(self.principal_id, str) or not self.principal_id.strip():
            raise ValueError("AuthenticatedPrincipal: principal_id must be a non-empty string")
        if not self.issuer_id or not isinstance(self.issuer_id, str) or not self.issuer_id.strip():
            raise ValueError("AuthenticatedPrincipal: issuer_id must be a non-empty string")
        if not self.signature or not isinstance(self.signature, str) or not self.signature.strip():
            raise ValueError("AuthenticatedPrincipal: signature must be a non-empty string")


class PrincipalVerifier:
    """
    Independent identity verifier that validates AuthenticatedPrincipal assertions.
    Holds ONLY verification keys/secrets; does NOT hold private signing keys or identity-minting APIs.
    Enforces issuer validation, signature verification, clock skew tolerance, and expiry.
    """

    def __init__(
        self,
        verification_secret: Optional[bytes] = None,
        trusted_issuer_id: str = "TrustedIdentityAuthority",
        clock_skew_seconds: float = 5.0
    ):
        if verification_secret:
            self.verification_secret = verification_secret
        else:
            env_sec = os.getenv("EPISTEMICOS_IDENTITY_VERIFICATION_SECRET", os.getenv("EPISTEMICOS_IDENTITY_SECRET"))
            if env_sec:
                self.verification_secret = env_sec.encode("utf-8")
            else:
                self.verification_secret = None
        self.trusted_issuer_id = trusted_issuer_id.strip() if trusted_issuer_id and isinstance(trusted_issuer_id, str) else "TrustedIdentityAuthority"
        self.clock_skew_seconds = clock_skew_seconds

    def _compute_signature(self, principal_id: str, issuer_id: str, timestamp: float) -> Optional[str]:
        if not self.verification_secret:
            return None
        payload = f"{principal_id}:{issuer_id}:{timestamp}"
        return hmac.new(self.verification_secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_principal(
        self,
        principal: Any,
        max_age_seconds: float = 3600.0,
        current_time: Optional[float] = None
    ) -> Tuple[bool, str, Optional[str]]:
        if not self.verification_secret:
            return False, "PrincipalVerifier is not configured with a trusted verification secret", None

        if not isinstance(principal, AuthenticatedPrincipal):
            return False, "Object is not a valid AuthenticatedPrincipal assertion", None

        if not principal.signature or not isinstance(principal.signature, str):
            return False, "Missing or invalid signature on principal assertion", None

        if principal.issuer_id != self.trusted_issuer_id:
            return False, f"Untrusted identity issuer: expected '{self.trusted_issuer_id}', got '{principal.issuer_id}'", None

        now = current_time if current_time is not None else time.time()

        # Reject future-dated assertions (beyond permitted clock skew)
        if principal.timestamp > (now + self.clock_skew_seconds):
            return False, f"Future-dated principal assertion rejected (timestamp {principal.timestamp} > current time {now})", None

        # Reject expired assertions
        if (now - principal.timestamp) > max_age_seconds:
            return False, f"Principal assertion expired (age {now - principal.timestamp:.1f}s > max {max_age_seconds}s)", None

        expected_sig = self._compute_signature(principal.principal_id, principal.issuer_id, principal.timestamp)
        if not expected_sig or not hmac.compare_digest(principal.signature, expected_sig):
            return False, "Cryptographic signature verification failed on principal assertion", None

        return True, "Principal verified", principal.principal_id


# Alias for backward compatibility if imported by test harnesses
PrincipalProvider = PrincipalVerifier


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
    fencing_token: int = 1
    scope_key: Optional[str] = None

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        now = current_time if current_time is not None else time.time()
        return now >= self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if isinstance(data.get("required_success_evidence"), (set, frozenset)):
            data["required_success_evidence"] = list(data["required_success_evidence"])
        if self.human_approval and hasattr(self.human_approval, "to_dict"):
            data["human_approval"] = self.human_approval.to_dict()
        return data


import contextlib


class CapabilityRegistry:
    """
    Thread-safe, persistent server-side capability registry and single-use token manager.

    Architectural Guarantees & Constraints:
    - Thread-level consumption atomicity is provided by the existing registry lock (_lock).
    - Ordinary approval-consumption state is process-local and thread-safe.
    - Independent processes do not share ordinary consumed-approval state unless backed by
      a synchronized AuthorizationStore (e.g., FileAuthorizationStore).
    - Ordinary consumed approvals in default in-memory storage are not durable across restarts.
    - Verification is a point-in-time check; atomic consumption remains the execution boundary's responsibility.
    - Interprocess durable denial tracking and clearance serialization use atomic append-only file persistence
      with fsync and file locking (fcntl.flock).
    - Fail-closed registry poisoning: If append or fsync fails and rollback truncation cannot be guaranteed
      under fail-closed persistence, the registry transitions to a poisoned state (_is_poisoned = True)
      and rejects all subsequent authorization, denial checking, clearance, and token operations.
    - Explicit Persistence Guarantee Limitation: Process-local registry poisoning protects the current OS
      process only. Ambiguous persistence failure (e.g. an un-fsynced append write where rollback truncation
      fails) can leave a complete valid JSON record on disk that is visible to a new process instance.
      Restart recovery after failed fsync and failed rollback is not currently guaranteed to preserve
      the in-memory failure/poisoned state across process termination/restart. Multiphase transaction logging
      is deferred pending a formal persistence recovery protocol.
    """

    def __init__(
        self,
        signing_secret: Optional[bytes] = None,
        denial_log_path: str = "logs/denial_registry.jsonl",
        fail_closed_persistence: bool = True,
        storage_backend: Optional[AuthorizationStore] = None
    ):
        self._lock = threading.RLock()
        self._is_poisoned: bool = False
        self._file_lock_count = 0
        self._lock_file_obj = None
        self._denied_records: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self.denial_log_path = denial_log_path
        self.fail_closed_persistence = fail_closed_persistence

        if self.fail_closed_persistence and not self.denial_log_path:
            raise ValueError("Configuration error: denial_log_path is required when fail_closed_persistence=True")

        self.storage = storage_backend if storage_backend is not None else InMemoryAuthorizationStore()

        self.signing_secret = signing_secret or hashlib.sha256(f"EPISTEMICOS_CAP_KEY_{uuid.uuid4()}".encode("utf-8")).digest()
        self._load_persistent_denials()

    def _check_poisoned(self) -> None:
        """Enforces fail-closed rejection if registry entered an unrecoverable poisoned state."""
        if self._is_poisoned:
            raise RuntimeError("CapabilityRegistry is in a poisoned state due to unrecoverable persistence rollback failure")

    @contextlib.contextmanager
    def lock_registry(self):
        """
        Acquires both thread-level lock (_lock) and interprocess file-level lock (fcntl.flock)
        on the denial log lockfile to ensure strict atomicity across processes during authorization evaluations.
        Re-entrant for nested acquisitions on the same process thread.
        """
        self._check_poisoned()
        import os
        try:
            import fcntl
            has_fcntl = True
        except ImportError:
            has_fcntl = False

        lock_path = (self.denial_log_path + ".lock") if self.denial_log_path else None

        with self._lock:
            self._check_poisoned()
            if lock_path:
                if not has_fcntl:
                    if self.fail_closed_persistence:
                        raise RuntimeError("Lock registry failure: interprocess file locking (fcntl) is unsupported on this operating system")
                else:
                    if self._file_lock_count == 0:
                        try:
                            os.makedirs(os.path.dirname(lock_path) or ".", exist_ok=True)
                            self._lock_file_obj = open(lock_path, "a", encoding="utf-8")
                            fcntl.flock(self._lock_file_obj.fileno(), fcntl.LOCK_EX)
                        except Exception as e:
                            if self._lock_file_obj:
                                try:
                                    self._lock_file_obj.close()
                                except Exception:
                                    pass
                                self._lock_file_obj = None
                            if self.fail_closed_persistence:
                                raise RuntimeError(f"Lock registry failure: unable to acquire interprocess file lock ({str(e)})") from e
                    self._file_lock_count += 1

            # Re-verify poisoned state under the interprocess file lock and thread lock
            self._check_poisoned()
            try:
                yield
            finally:
                with self._lock:
                    if lock_path and has_fcntl and self._file_lock_count > 0:
                        self._file_lock_count -= 1
                        if self._file_lock_count == 0 and self._lock_file_obj:
                            try:
                                fcntl.flock(self._lock_file_obj.fileno(), fcntl.LOCK_UN)
                            except Exception as e:
                                if self.fail_closed_persistence:
                                    raise RuntimeError(f"Lock registry release failure ({str(e)})") from e
                            finally:
                                try:
                                    self._lock_file_obj.close()
                                except Exception:
                                    pass
                                self._lock_file_obj = None

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
                    except (OSError, IOError) as flock_err:
                        if self.fail_closed_persistence:
                            raise RuntimeError(f"Lock acquisition failure loading persistent denial log: {str(flock_err)}") from flock_err
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
                            task_id_str = str(rec["task_id"]).strip()
                            action_name_str = str(rec["action_name"]).strip()
                            target_str = str(rec["target"]).strip()
                            key = (task_id_str, action_name_str, target_str)
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
                        except (OSError, IOError) as unlock_err:
                            if self.fail_closed_persistence:
                                raise RuntimeError(f"Lock release failure loading persistent denial log: {str(unlock_err)}") from unlock_err
        except Exception as e:
            if self.fail_closed_persistence:
                raise RuntimeError(f"Failed to load persistent denial log: {str(e)}") from e

    def sign_capability(self, cap: Capability) -> str:
        effective_scope = getattr(cap, "scope_key", None) or canonicalize_fencing_scope(cap.task_id, cap.target)
        effective_fence = getattr(cap, "fencing_token", 1)
        payload = f"{cap.token_id}:{cap.principal_id}:{cap.correlation_id}:{cap.request_id}:{cap.action_name}:{cap.target}:{cap.canonical_request_digest}:{cap.executor_id}:{cap.policy_version}:{cap.task_id or ''}:{cap.contract_version or ''}:{cap.contract_digest or ''}:{cap.expires_at}:{effective_fence}:{effective_scope}"
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
        self._check_poisoned()
        import os
        try:
            import fcntl
            has_fcntl = True
        except ImportError:
            has_fcntl = False

        task_id = str(task_id).strip()
        action_name = str(action_name).strip()
        target = str(target).strip()

        rec = {
            "task_id": task_id,
            "action_name": action_name,
            "target": target,
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
                with open(self.denial_log_path, "a+", encoding="utf-8") as f:
                    if has_fcntl:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                    pre_pos = f.tell()
                    try:
                        f.write(json.dumps(rec) + "\n")
                        f.flush()
                        os.fsync(f.fileno())
                    except Exception as primary_err:
                        rollback_failed = False
                        try:
                            f.seek(pre_pos)
                            os.ftruncate(f.fileno(), pre_pos)
                            f.flush()
                        except Exception:
                            try:
                                f.truncate(pre_pos)
                                f.flush()
                            except Exception:
                                rollback_failed = True

                        if rollback_failed and self.fail_closed_persistence:
                            self._is_poisoned = True
                            raise RuntimeError(f"Denial persistence failure and rollback truncation failure: on-disk state uncertain ({str(primary_err)})") from primary_err
                        raise
                    finally:
                        if has_fcntl:
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except Exception as e:
                # If write fails: DO NOT MUTATE IN-MEMORY STATE, fail closed
                if self.fail_closed_persistence:
                    if isinstance(e, RuntimeError):
                        raise
                    raise RuntimeError(f"Denial persistence failure: unable to durably record security decision ({str(e)})") from e

        # Durable file write succeeded -> Commit in-memory state mutation
        key = (task_id, action_name, target)
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
        with self.lock_registry():
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
        expected_action_digest: Optional[str] = None,
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

        task_id = str(task_id).strip()
        action_name = str(action_name).strip()
        target = str(target).strip()

        with self.lock_registry():
            # 1. Mandatory signature verification against trusted approval signing secret
            if not reauthorization_record.verify_signature(signing_secret, current_time=current_time):
                return False, "Reauthorization approval signature verification failed"

            # 2. Require non-empty task_id binding matching task_id
            if not reauthorization_record.task_id or not reauthorization_record.task_id.strip():
                return False, "Reauthorization approval record missing required task_id binding"

            if reauthorization_record.task_id != task_id:
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

            # Action digest validation: fail closed if expected_action_digest is supplied
            if expected_action_digest:
                rec_digest = getattr(reauthorization_record, "action_digest", None)
                if not rec_digest or not str(rec_digest).strip():
                    return False, "Reauthorization approval record missing required action_digest"
                if str(rec_digest).strip() != str(expected_action_digest).strip():
                    return False, f"Reauthorization approval action_digest mismatch: expected '{expected_action_digest}', got '{reauthorization_record.action_digest}'"

            key = (task_id, action_name, target)
            rec = {
                "task_id": task_id,
                "action_name": action_name,
                "target": target,
                "status": "CLEARED",
                "cleared_by_approval": reauthorization_record.approval_id,
                "timestamp": time.time()
            }

            # Transactional Ordering: WRITE TO DURABLE LOG FILE FIRST BEFORE MUTATING IN-MEMORY STATE
            if self.denial_log_path:
                try:
                    os.makedirs(os.path.dirname(self.denial_log_path) or ".", exist_ok=True)
                    with open(self.denial_log_path, "a+", encoding="utf-8") as f:
                        if has_fcntl:
                            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                        pre_pos = f.tell()
                        try:
                            f.write(json.dumps(rec) + "\n")
                            f.flush()
                            os.fsync(f.fileno())
                        except Exception as primary_err:
                            rollback_failed = False
                            try:
                                f.seek(pre_pos)
                                os.ftruncate(f.fileno(), pre_pos)
                                f.flush()
                            except Exception:
                                try:
                                    f.truncate(pre_pos)
                                    f.flush()
                                except Exception:
                                    rollback_failed = True

                            if rollback_failed and self.fail_closed_persistence:
                                self._is_poisoned = True
                                raise RuntimeError(f"Denial persistence failure and rollback truncation failure: on-disk clearance state uncertain ({str(primary_err)})") from primary_err
                            raise
                        finally:
                            if has_fcntl:
                                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                except Exception as e:
                    # Persistence failed -> DO NOT MUTATE IN-MEMORY DENIAL OR CONSUME APPROVAL
                    if self.fail_closed_persistence:
                        if isinstance(e, RuntimeError):
                            raise
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
        self._check_poisoned()
        task_id = str(task_id).strip()
        action_name = str(action_name).strip()
        target = str(target).strip()
    @staticmethod
    def _normalize_target_path(raw_target: str) -> Tuple[str, str]:
        """
        Normalizes target string into (netloc, norm_path) tuple.
        Extracts host network location if URL, unquotes percent-encoded separators,
        converts backslashes, and eliminates dot segments.
        """
        import os
        from urllib.parse import urlparse, unquote

        if not raw_target:
            return "", "/"
        str_target = str(raw_target).strip()
        if "://" in str_target:
            parsed = urlparse(str_target)
            netloc = parsed.netloc.lower().strip() if parsed.netloc else ""
            raw_path = parsed.path or "/"
        else:
            netloc = ""
            raw_path = str_target if str_target.startswith("/") else "/" + str_target
            if "?" in raw_path or "#" in raw_path:
                parsed = urlparse("http://localhost" + raw_path)
                raw_path = parsed.path or "/"

        # Unquote percent-encoded separators (%2F, %5C) to resolve encoded traversal paths
        unquoted_path = unquote(raw_path)

        # Collapse backslashes to forward slashes and eliminate dot segments
        clean_path = unquoted_path.replace("\\", "/")
        norm_path = os.path.normpath(clean_path)
        if norm_path in (".", "", "/"):
            norm_path = "/"
        else:
            norm_path = norm_path.rstrip("/")
        return netloc, norm_path

    def _find_inherited_denial(
        self,
        task_id: str,
        action_name: str,
        target: str
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates downward restriction inheritance across alternative execution paths/endpoints
        for the same task. Matches by host, subpath inheritance, and action category or wildcard.
        """
        from epistemicos.action_policy import ActionRegistry

        registry = getattr(self, "_action_registry", None) or ActionRegistry()
        req_cat = registry.classify_action(action_name)
        target_host, target_norm = self._normalize_target_path(target)

        for (d_task_id, d_action, d_target), d_rec in self._denied_records.items():
            if d_rec.get("status") != "ACTIVE" or d_task_id != task_id:
                continue

            d_host, d_target_norm = self._normalize_target_path(d_target)

            # Strict host matching: exact match or explicit wildcard
            host_matches = (
                target_host == d_host
                or d_host == "*"
                or target_host == "*"
                or d_target == "*"
                or target == "*"
            )

            # Downward path inheritance: a restriction on a parent path or exact path/wildcard applies to subpaths
            path_matches = (
                d_target == target
                or d_target == "*"
                or target == "*"
                or d_target_norm == target_norm
                or (d_target_norm == "/" and target_norm.startswith("/"))
                or (d_target_norm != "/" and target_norm.startswith(d_target_norm + "/"))
            )

            target_matches = host_matches and path_matches

            d_cat = registry.classify_action(d_action)
            same_action = (d_action == action_name)
            same_category = (req_cat == d_cat and req_cat is not None)
            wildcard_action = (d_action == "*")

            if target_matches and (same_action or same_category or wildcard_action):
                inherited_rec = dict(d_rec)
                inherited_rec["inherited_from"] = {
                    "action_name": d_action,
                    "target": d_target,
                    "reason": d_rec.get("reason")
                }
                return inherited_rec

        return None

    def _check_denial_unlocked(
        self,
        task_id: str,
        action_name: str,
        target: str,
        contract_version: str = "1.0.0",
        policy_version: str = "1.0.0"
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        task_id = str(task_id).strip()
        action_name = str(action_name).strip()
        target = str(target).strip()

        # Re-sync from persistent storage to enforce cross-process durability
        self._load_persistent_denials()

        key = (task_id, action_name, target)
        rec = self._denied_records.get(key)
        if rec and rec.get("status") == "ACTIVE":
            # Denial is active regardless of contract_version changes, unless explicitly cleared
            return True, rec

        # Restriction Inheritance Check across alternative execution paths/endpoints for same task
        inherited_rec = self._find_inherited_denial(task_id, action_name, target)
        if inherited_rec:
            return True, inherited_rec

        return False, None

    def check_denial(
        self,
        task_id: str,
        action_name: str,
        target: str,
        contract_version: str = "1.0.0",
        policy_version: str = "1.0.0"
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        with self.lock_registry():
            return self._check_denial_unlocked(
                task_id=task_id,
                action_name=action_name,
                target=target,
                contract_version=contract_version,
                policy_version=policy_version
            )

    @property
    def _capabilities(self) -> Dict[str, Any]:
        if hasattr(self.storage, "_capabilities"):
            return self.storage._capabilities
        return {}

    @property
    def _consumed_tokens(self) -> Set[str]:
        if hasattr(self.storage, "_consumed_tokens"):
            return self.storage._consumed_tokens
        return set()

    @property
    def _revoked_tokens(self) -> Set[str]:
        if hasattr(self.storage, "_revoked_tokens"):
            return self.storage._revoked_tokens
        return set()

    @property
    def _consumed_approvals(self) -> Set[str]:
        if hasattr(self.storage, "_consumed_approvals"):
            return self.storage._consumed_approvals
        return set()

    def issue_and_register_capability(self, cap: Capability) -> Capability:
        with self._lock:
            self._check_poisoned()
            return self.storage.issue_and_register_capability(cap, self.sign_capability)

    def register_capability(self, cap: Capability) -> None:
        with self._lock:
            self._check_poisoned()
            if not getattr(cap, "scope_key", None):
                cap.scope_key = canonicalize_fencing_scope(cap.task_id, cap.target)
            if getattr(cap, "fencing_token", None) is None:
                cap.fencing_token = 1
            cap.signature = self.sign_capability(cap)
            self.storage.register_capability(cap)

    def get_capability(self, token_id: str) -> Optional[Capability]:
        with self._lock:
            self._check_poisoned()
            cap = self.storage.get_capability(token_id)
            if cap is not None and not isinstance(cap, Capability):
                pass
            return cap

    def is_consumed(self, token_id: str) -> bool:
        with self._lock:
            self._check_poisoned()
            return self.storage.is_consumed(token_id)

    def is_revoked(self, token_id: str) -> bool:
        with self._lock:
            self._check_poisoned()
            return self.storage.is_revoked(token_id)

    def is_approval_consumed(self, approval_id: str) -> bool:
        with self._lock:
            self._check_poisoned()
            return self.storage.is_approval_consumed(approval_id)

    def consume_token(self, token_id: str, expected_fencing_token: Optional[int] = None) -> bool:
        """
        Atomically consumes a single-use token in authoritative storage.
        Returns True if consumed successfully, False if already consumed, revoked, or stale fencing token.
        """
        with self._lock:
            self._check_poisoned()
            ok, _ = self.storage.consume_capability(token_id, expected_fencing_token=expected_fencing_token)
            return ok

    def revoke_token(self, token_id: str, reason: str = "") -> Tuple[bool, str]:
        with self._lock:
            self._check_poisoned()
            return self.storage.revoke_capability(token_id, reason=reason)

    def get_scope_fencing_token(self, scope_key: str) -> int:
        with self._lock:
            self._check_poisoned()
            return self.storage.get_scope_fencing_token(scope_key)


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


class ExecutorRegistry:
    """
    Thread-safe, encapsulated registry mapping executor IDs and single-use token IDs
    to trusted executor callables.
    Restricts public retrieval and mutation methods (.get(), __getitem__, __setitem__, keys(), values(), items(), __iter__)
    to prevent ordinary callers from retrieving or replacing registered raw executor function references.
    Exposes narrow internal methods (_get_executor_for_boundary, _register_internal, _pop_internal)
    used exclusively by AuthorizationAuthority and TrustedExecutionBoundary.
    """

    def __init__(self, initial_mapping: Optional[Union[Dict[str, Any], "ExecutorRegistry"]] = None):
        self._lock = threading.RLock()
        self._store: Dict[str, Any] = {}
        if initial_mapping:
            if isinstance(initial_mapping, ExecutorRegistry):
                with initial_mapping._lock:
                    self._store.update(initial_mapping._store)
            elif isinstance(initial_mapping, dict):
                self._store.update(initial_mapping)

    def _register_internal(self, key: str, executor_func: Any, allow_overwrite: bool = False) -> None:
        """
        Internal registration method used exclusively by AuthorizationAuthority.
        Re-binding an existing registered key to a different callable object is strictly rejected
        unless allow_overwrite=True or the registered function identity matches ('is').
        """
        with self._lock:
            if key in self._store and not allow_overwrite:
                existing = self._store[key]
                if existing is not executor_func:
                    raise ValueError(f"Registration rejected: Cannot overwrite existing executor ID '{key}' with a different callable object")
            self._store[key] = executor_func

    def _get_executor_for_boundary(self, key: str, default: Any = None) -> Any:
        """Internal lookup method used exclusively by AuthorizationAuthority & TrustedExecutionBoundary."""
        with self._lock:
            return self._store.get(key, default)

    def _pop_internal(self, key: str, default: Any = None) -> Any:
        """Internal removal method used exclusively by AuthorizationAuthority & TrustedExecutionBoundary."""
        with self._lock:
            return self._store.pop(key, default)

    def contains(self, key: str) -> bool:
        """Public metadata check: returns True if an executor is registered for key, without exposing the raw callable."""
        with self._lock:
            return key in self._store

    def __contains__(self, key: Any) -> bool:
        """Public metadata check: supports 'key in registry' syntax without exposing raw callables."""
        with self._lock:
            return key in self._store

    def __len__(self) -> int:
        """Public metadata check: returns count of registered executors."""
        with self._lock:
            return len(self._store)

    def get(self, key: str, default: Any = None) -> Any:
        raise PermissionError("Access denied: Raw executor retrieval via ExecutorRegistry.get() is restricted")

    def __getitem__(self, key: str) -> Any:
        raise PermissionError("Access denied: Raw executor retrieval via ExecutorRegistry item lookup is restricted")

    def __setitem__(self, key: str, value: Any) -> None:
        raise PermissionError("Access denied: Direct ExecutorRegistry mutation via item assignment is restricted")

    def keys(self):
        raise TypeError("ExecutorRegistry object does not support iteration or key enumeration")

    def values(self):
        raise TypeError("ExecutorRegistry object does not support iteration or value enumeration")

    def items(self):
        raise TypeError("ExecutorRegistry object does not support iteration or item enumeration")

    def __iter__(self):
        raise TypeError("ExecutorRegistry object is not iterable")


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
        require_task_contract: Optional[bool] = None,
        principal_provider: Optional[PrincipalVerifier] = None
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

        if isinstance(executor_registry, ExecutorRegistry):
            self.executor_registry = executor_registry
        else:
            self.executor_registry = ExecutorRegistry(executor_registry)

        # SEC-01: Independent identity verifier integration.
        # AuthorizationAuthority holds verification keys, NEVER identity-issuing keys.
        self.principal_provider = principal_provider
        if not self.principal_provider:
            env_id_sec = os.getenv("EPISTEMICOS_IDENTITY_VERIFICATION_SECRET", os.getenv("EPISTEMICOS_IDENTITY_SECRET"))
            if env_id_sec:
                self.principal_provider = PrincipalVerifier(
                    verification_secret=env_id_sec.encode("utf-8"),
                    trusted_issuer_id=os.getenv("EPISTEMICOS_IDENTITY_ISSUER", "TrustedIdentityAuthority")
                )

    def clear_denial_with_approval(
        self,
        task_id: str,
        action_name: str,
        target: str,
        reauthorization_record: Any,
        expected_action_digest: Optional[str] = None,
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
            expected_action_digest=expected_action_digest,
            current_time=current_time
        )

    def register_executor(self, executor_id: str, executor_func: Any) -> None:
        """Registers an authoritative callable identity in the authority executor registry atomically."""
        with self.executor_registry._lock:
            self.executor_registry._register_internal(executor_id, executor_func)
            func_qual_id = get_callable_identity(executor_func)
            if func_qual_id != executor_id and func_qual_id not in self.executor_registry._store:
                self.executor_registry._register_internal(func_qual_id, executor_func)

    def evaluate_and_issue_capability(
        self,
        action_name: str,
        target: str,
        canonical_request_digest: str,
        principal_id: Union[str, AuthenticatedPrincipal] = "agent_default",
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

        # SEC-01: Authenticate principal assertion
        if isinstance(principal_id, AuthenticatedPrincipal):
            if not self.principal_provider:
                return None, "AUTHORIZATION_DENIED_NO_IDENTITY_PROVIDER_CONFIGURED: AuthenticatedPrincipal presented but authority has no trusted PrincipalProvider"
            valid, p_reason, pid = self.principal_provider.verify_principal(principal_id, current_time=current_time)
            if not valid:
                return None, f"AUTHORIZATION_DENIED_PRINCIPAL_AUTHENTICATION_FAILED: {p_reason}"
            effective_principal = pid
        elif isinstance(principal_id, str):
            clean_str = principal_id.strip()
            # If policy restricts principals, an unauthenticated raw string CANNOT assert identity
            if active_policy.allowed_principals != {"*"}:
                return None, f"AUTHORIZATION_DENIED_AUTHENTICATED_PRINCIPAL_REQUIRED: Claiming privileged principal '{principal_id}' requires AuthenticatedPrincipal"
            effective_principal = clean_str if clean_str else "agent_default"
        else:
            return None, "AUTHORIZATION_DENIED_INVALID_PRINCIPAL_TYPE"

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

        # Validate and canonicalize action and target
        if not action_name or not isinstance(action_name, str) or not action_name.strip():
            return None, "AUTHORIZATION_DENIED_INVALID_ACTION_NAME"

        if not target or not isinstance(target, str) or not target.strip():
            return None, "AUTHORIZATION_DENIED_INVALID_TARGET"

        action_name = action_name.strip()
        target = target.strip()
        if effective_task_id:
            effective_task_id = str(effective_task_id).strip()

        # Begin atomic critical section for checking denial, contract, policy, recording denial, and registering capability
        with self.registry.lock_registry():
            # Check durable denial registry if effective_task_id is known
            if effective_task_id:
                c_ver = contract_obj.contract_version if contract_obj else "1.0.0"
                is_denied, prev_denial = self.registry._check_denial_unlocked(effective_task_id, action_name, target, c_ver, active_policy.version)
                if is_denied and prev_denial:
                    return None, f"AUTHORIZATION_DENIED_DURABLE_DENIAL_ACTIVE:{prev_denial['reason']}"

            # Execute test/synchronization hook if present
            if getattr(self, "_pre_issuance_hook", None) and callable(self._pre_issuance_hook):
                try:
                    import fcntl
                    has_fcntl_local = True
                except ImportError:
                    has_fcntl_local = False

                lock_file = getattr(self.registry, "_lock_file_obj", None)
                if lock_file and has_fcntl_local:
                    try:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                    except Exception:
                        pass
                try:
                    self._pre_issuance_hook()
                finally:
                    if lock_file and has_fcntl_local:
                        try:
                            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                        except Exception:
                            pass
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

            if not active_policy.is_principal_allowed(effective_principal):
                return None, f"AUTHORIZATION_DENIED_PRINCIPAL_NOT_ALLOWED:{effective_principal}"

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
                self.executor_registry._register_internal(token_id, exec_obj)
                if not self.executor_registry.contains(executor_id_str):
                    self.executor_registry._register_internal(executor_id_str, exec_obj)
            else:
                executor_id_str = get_callable_identity(executor_id)
                if executor_id_str in self.executor_registry:
                    bound_exec = self.executor_registry._get_executor_for_boundary(executor_id_str)
                    if bound_exec:
                        self.executor_registry._register_internal(token_id, bound_exec)

            canonical_scope = canonicalize_fencing_scope(effective_task_id, target)
            cap = Capability(
                token_id=token_id,
                principal_id=effective_principal,
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
                human_approval=approval_record,
                scope_key=canonical_scope
            )

            # Atomic issuance: advances fencing generation and persists capability atomically
            cap = self.registry.issue_and_register_capability(cap)
            return cap, "AUTHORIZATION_GRANTED"

    def verify_capability(
        self,
        token_id: str,
        action_name: str,
        target: str,
        canonical_request_digest: str,
        executor_id: str,
        principal_id: Optional[Union[str, AuthenticatedPrincipal]] = None,
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

        # Check whether associated human approval ID has already been consumed (read-only verification)
        human_app = getattr(cap, "human_approval", None) or (cap.get("human_approval") if isinstance(cap, dict) else None)
        if human_app:
            approval_id = getattr(human_app, "approval_id", None) or (human_app.get("approval_id") if isinstance(human_app, dict) else None)
            if approval_id and self.registry.is_approval_consumed(approval_id):
                return False, "CAPABILITY_VERIFICATION_FAILED_REPLAY_HUMAN_APPROVAL_ALREADY_CONSUMED", None

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

        # SEC-01: Principal verification
        if isinstance(principal_id, AuthenticatedPrincipal):
            if not self.principal_provider:
                return False, "CAPABILITY_VERIFICATION_FAILED_NO_IDENTITY_PROVIDER: Authority has no configured PrincipalProvider to verify assertion", cap
            valid, p_reason, pid = self.principal_provider.verify_principal(principal_id, current_time=current_time)
            if not valid:
                return False, f"CAPABILITY_VERIFICATION_FAILED_PRINCIPAL_AUTHENTICATION_FAILED: {p_reason}", cap
            req_principal = pid
        elif isinstance(principal_id, str):
            req_principal = principal_id.strip() if principal_id.strip() else None
        else:
            req_principal = None

        if req_principal is not None and cap.principal_id != req_principal:
            return False, f"CAPABILITY_VERIFICATION_FAILED_PRINCIPAL_MISMATCH: granted '{cap.principal_id}', requested '{req_principal}'", cap

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

        # Strict Exact Fencing Generation Verification against authoritative storage
        scope_key = getattr(cap, "scope_key", None) or canonicalize_fencing_scope(cap.task_id, cap.target)
        auth_fencing_gen = self.registry.get_scope_fencing_token(scope_key)
        cap_fencing_gen = getattr(cap, "fencing_token", 1)

        if auth_fencing_gen > 0 and cap_fencing_gen != auth_fencing_gen:
            if cap_fencing_gen < auth_fencing_gen:
                return False, f"CAPABILITY_VERIFICATION_FAILED_STALE_FENCING_TOKEN: token generation {cap_fencing_gen} < authoritative scope generation {auth_fencing_gen}", cap
            else:
                return False, f"CAPABILITY_VERIFICATION_FAILED_FUTURE_FENCING_TOKEN: token generation {cap_fencing_gen} > authoritative scope generation {auth_fencing_gen}", cap

        return True, "CAPABILITY_VERIFIED", cap
