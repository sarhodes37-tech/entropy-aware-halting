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
import re
from abc import ABC, abstractmethod
from functools import lru_cache
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



MIN_TIMESTAMP_BOUND = -(1 << 63)
MAX_TIMESTAMP_BOUND = (1 << 63) - 1

_ED25519_Q = 2**255 - 19
_ED25519_L = 2**252 + 27742317777372353535851937790883648493


def _ed_H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _ed_expmod(b: int, e: int, m: int) -> int:
    return pow(b, e, m)


def _ed_inv(x: int) -> int:
    return _ed_expmod(x, _ED25519_Q - 2, _ED25519_Q)


_ed_d = -121665 * _ed_inv(121666)
_ed_I = _ed_expmod(2, (_ED25519_Q - 1) // 4, _ED25519_Q)


def _ed_xrecover(y: int) -> int:
    xx = (y * y - 1) * _ed_inv(_ed_d * y * y + 1)
    x = _ed_expmod(xx, (_ED25519_Q + 3) // 8, _ED25519_Q)
    if (x * x - xx) % _ED25519_Q != 0:
        x = (x * _ed_I) % _ED25519_Q
    if x % 2 != 0:
        x = _ED25519_Q - x
    return x


_ed_By = 4 * _ed_inv(5)
_ed_Bx = _ed_xrecover(_ed_By)
_ed_B = [_ed_Bx % _ED25519_Q, _ed_By % _ED25519_Q]


def _ed_edwards(P: List[int], Q: List[int]) -> List[int]:
    x1, y1 = P[0], P[1]
    x2, y2 = Q[0], Q[1]
    x3 = (x1 * y2 + x2 * y1) * _ed_inv(1 + _ed_d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _ed_inv(1 - _ed_d * x1 * x2 * y1 * y2)
    return [x3 % _ED25519_Q, y3 % _ED25519_Q]


def _ed_scalarmult(P: List[int], e: int) -> List[int]:
    if e == 0:
        return [0, 1]
    Q = _ed_scalarmult(P, e // 2)
    Q = _ed_edwards(Q, Q)
    if e & 1:
        Q = _ed_edwards(Q, P)
    return Q


def _ed_decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _ed_decodepoint(s: bytes) -> List[int]:
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _ed_xrecover(y)
    if bool(x & 1) != bool(s[31] & 0x80):
        x = _ED25519_Q - x
    P = [x, y]
    if not ((-x * x + y * y - 1 - _ed_d * x * x * y * y) % _ED25519_Q == 0):
        raise ValueError("decoding point that is not on curve")
    return P


def _ed25519_verify_pure(sig_bytes: bytes, msg_bytes: bytes, pubkey_bytes: bytes) -> bool:
    try:
        if len(sig_bytes) != 64 or len(pubkey_bytes) != 32:
            return False
        R = _ed_decodepoint(sig_bytes[:32])
        A = _ed_decodepoint(pubkey_bytes)
        S = _ed_decodeint(sig_bytes[32:])
        if S >= _ED25519_L:
            return False
        h = _ed_decodeint(_ed_H(sig_bytes[:32] + pubkey_bytes + msg_bytes))
        v1 = _ed_scalarmult(_ed_B, S)
        v2 = _ed_edwards(R, _ed_scalarmult(A, h))
        return v1 == v2
    except Exception:
        return False


try:
    import ctypes
    import ctypes.util
    _libcrypto_path = ctypes.util.find_library("crypto")
    if _libcrypto_path:
        _libcrypto = ctypes.CDLL(_libcrypto_path)
        _EVP_PKEY_ED25519 = 1087
        _libcrypto.EVP_MD_CTX_new.restype = ctypes.c_void_p
        _libcrypto.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]
        _libcrypto.EVP_PKEY_new_raw_public_key.restype = ctypes.c_void_p
        _libcrypto.EVP_PKEY_new_raw_public_key.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
        _libcrypto.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
        _libcrypto.EVP_DigestVerifyInit.restype = ctypes.c_int
        _libcrypto.EVP_DigestVerifyInit.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        _libcrypto.EVP_DigestVerify.restype = ctypes.c_int
        _libcrypto.EVP_DigestVerify.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
        _HAS_LIBCRYPTO = True
    else:
        _HAS_LIBCRYPTO = False
except Exception:
    _HAS_LIBCRYPTO = False


def verify_ed25519_signature(sig_bytes: bytes, msg_bytes: bytes, pubkey_bytes: bytes) -> bool:
    """Verifies an Ed25519 signature (RFC 8032) using libcrypto when available or pure Python."""
    if len(sig_bytes) != 64 or len(pubkey_bytes) != 32:
        return False
    if _HAS_LIBCRYPTO:
        try:
            pkey = _libcrypto.EVP_PKEY_new_raw_public_key(_EVP_PKEY_ED25519, None, pubkey_bytes, len(pubkey_bytes))
            if not pkey:
                return _ed25519_verify_pure(sig_bytes, msg_bytes, pubkey_bytes)
            ctx = _libcrypto.EVP_MD_CTX_new()
            if not ctx:
                _libcrypto.EVP_PKEY_free(pkey)
                return _ed25519_verify_pure(sig_bytes, msg_bytes, pubkey_bytes)
            try:
                init_res = _libcrypto.EVP_DigestVerifyInit(ctx, None, None, None, pkey)
                if init_res != 1:
                    return False
                res = _libcrypto.EVP_DigestVerify(ctx, sig_bytes, len(sig_bytes), msg_bytes, len(msg_bytes))
                return res == 1
            finally:
                _libcrypto.EVP_MD_CTX_free(ctx)
                _libcrypto.EVP_PKEY_free(pkey)
        except Exception:
            return _ed25519_verify_pure(sig_bytes, msg_bytes, pubkey_bytes)
    return _ed25519_verify_pure(sig_bytes, msg_bytes, pubkey_bytes)


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """
    Cryptographically and authoritatively verified identity assertion representing
    an authenticated principal.
    A caller-supplied string, dictionary, or manually constructed object without
    a valid asymmetric cryptographic signature from an independently trusted external Identity Provider
    is strictly rejected.
    """
    principal_id: str
    issuer_id: str
    timestamp: float
    signature: str
    expires_at: Optional[float] = None
    key_id: Optional[str] = None

    def __post_init__(self):
        if not self.principal_id or not isinstance(self.principal_id, str) or not self.principal_id.strip():
            raise ValueError("AuthenticatedPrincipal: principal_id must be a non-empty string")
        if not self.issuer_id or not isinstance(self.issuer_id, str) or not self.issuer_id.strip():
            raise ValueError("AuthenticatedPrincipal: issuer_id must be a non-empty string")
        if not self.signature or not isinstance(self.signature, str) or not self.signature.strip():
            raise ValueError("AuthenticatedPrincipal: signature must be a non-empty string")

        self._validate_timestamp_fields()

    def _validate_timestamp_fields(self) -> None:
        """Strictly validates timestamp and expires_at against type ambiguity and overflow."""
        # Validate timestamp field
        if isinstance(self.timestamp, bool) or not isinstance(self.timestamp, (int, float)):
            raise TypeError(f"AuthenticatedPrincipal: timestamp must be a numeric timestamp, got {type(self.timestamp).__name__}")
        if isinstance(self.timestamp, int):
            if not (MIN_TIMESTAMP_BOUND <= self.timestamp <= MAX_TIMESTAMP_BOUND):
                raise ValueError("AuthenticatedPrincipal: timestamp integer overflows signed 64-bit limits")
        else:
            if not math.isfinite(self.timestamp):
                raise ValueError(f"AuthenticatedPrincipal: timestamp must be a finite number, got {self.timestamp}")
            if not (MIN_TIMESTAMP_BOUND <= self.timestamp <= MAX_TIMESTAMP_BOUND):
                raise ValueError("AuthenticatedPrincipal: timestamp float overflows signed 64-bit limits")

        # Validate expires_at field if present
        if self.expires_at is not None:
            if isinstance(self.expires_at, bool) or not isinstance(self.expires_at, (int, float)):
                raise TypeError(f"AuthenticatedPrincipal: expires_at must be a numeric timestamp, got {type(self.expires_at).__name__}")
            if isinstance(self.expires_at, int):
                if not (MIN_TIMESTAMP_BOUND <= self.expires_at <= MAX_TIMESTAMP_BOUND):
                    raise ValueError("AuthenticatedPrincipal: expires_at integer overflows signed 64-bit limits")
            else:
                if not math.isfinite(self.expires_at):
                    raise ValueError(f"AuthenticatedPrincipal: expires_at must be a finite number, got {self.expires_at}")
                if not (MIN_TIMESTAMP_BOUND <= self.expires_at <= MAX_TIMESTAMP_BOUND):
                    raise ValueError("AuthenticatedPrincipal: expires_at float overflows signed 64-bit limits")

    def compute_signature_payload(self) -> bytes:
        self._validate_timestamp_fields()
        exp_str = f"{self.expires_at:.6f}" if self.expires_at is not None else ""
        kid_str = self.key_id or ""
        payload = f"{self.principal_id}:{self.issuer_id}:{self.timestamp:.6f}:{exp_str}:{kid_str}"
        return payload.encode("utf-8")

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
    requesting_principal: Optional[str] = None
    approver_assertion: Optional[Union[AuthenticatedPrincipal, Dict[str, Any]]] = None
    signature: Optional[str] = None

    def compute_assertion_digest(self) -> str:
        """
        Computes a deterministic canonical digest of approver_assertion if present.
        If no assertion is attached, returns empty string.
        """
        if not self.approver_assertion:
            return ""
        if hasattr(self.approver_assertion, "compute_signature_payload"):
            payload_bytes = self.approver_assertion.compute_signature_payload()
            sig = getattr(self.approver_assertion, "signature", "")
            return hashlib.sha256(payload_bytes + b":" + sig.encode("utf-8")).hexdigest()
        elif isinstance(self.approver_assertion, dict):
            canonical_json = json.dumps(self.approver_assertion, sort_keys=True, separators=(",", ":"))
            return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        return hashlib.sha256(str(self.approver_assertion).encode("utf-8")).hexdigest()

    def compute_signature_payload(self) -> str:
        base_payload = f"{self.approval_id}:{self.approver_id}:{self.action_name}:{self.target}:{self.action_digest}:{self.request_id}:{self.policy_version}:{self.expires_at}:{self.task_id or ''}"
        if self.requesting_principal is not None or self.approver_assertion is not None:
            req_p = self.requesting_principal or ""
            ast_dig = self.compute_assertion_digest()
            return f"{base_payload}:{req_p}:{ast_dig}"
        return base_payload

    def sign(self, signing_secret: bytes) -> str:
        if not isinstance(signing_secret, (bytes, bytearray)):
            raise TypeError(f"signing_secret must be bytes or bytearray, got {type(signing_secret).__name__}")
        if len(signing_secret) == 0:
            raise ValueError("signing_secret cannot be empty")
        payload = self.compute_signature_payload()
        self.signature = hmac.new(signing_secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return self.signature

    def verify_signature(self, signing_secret: bytes, current_time: Optional[float] = None) -> bool:
        if not isinstance(signing_secret, (bytes, bytearray)) or len(signing_secret) == 0:
            return False
        if not self.signature or not isinstance(self.signature, str) or len(self.signature) != 64:
            return False
        try:
            int(self.signature, 16)
        except ValueError:
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
        return hmac.compare_digest(self.signature.lower(), expected_sig.lower())

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

            raw_assertion = val.get("approver_assertion") or val.get("assertion")
            parsed_assertion = None
            if raw_assertion is not None:
                if isinstance(raw_assertion, AuthenticatedPrincipal):
                    parsed_assertion = raw_assertion
                elif isinstance(raw_assertion, dict):
                    try:
                        parsed_assertion = AuthenticatedPrincipal(
                            principal_id=str(raw_assertion.get("principal_id", "")),
                            issuer_id=str(raw_assertion.get("issuer_id", "")),
                            timestamp=float(raw_assertion.get("timestamp", 0.0)),
                            signature=str(raw_assertion.get("signature", "")),
                            expires_at=float(raw_assertion["expires_at"]) if raw_assertion.get("expires_at") is not None else None,
                            key_id=str(raw_assertion["key_id"]) if raw_assertion.get("key_id") is not None else None
                        )
                    except Exception:
                        parsed_assertion = raw_assertion

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
                requesting_principal=str(val["requesting_principal"]) if val.get("requesting_principal") is not None else None,
                approver_assertion=parsed_assertion,
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

    def __post_init__(self):
        if not self.task_id or not isinstance(self.task_id, str) or not self.task_id.strip():
            raise ValueError("TrustedTaskContract: task_id must be a non-empty string")
        self._validate_timestamp_fields()

    def _validate_timestamp_fields(self) -> None:
        """Strictly validates created_at and expires_at against type ambiguity and overflow."""
        if isinstance(self.created_at, bool) or not isinstance(self.created_at, (int, float)):
            raise TypeError(f"TrustedTaskContract: created_at must be a numeric timestamp, got {type(self.created_at).__name__}")
        if isinstance(self.created_at, int):
            if not (MIN_TIMESTAMP_BOUND <= self.created_at <= MAX_TIMESTAMP_BOUND):
                raise ValueError("TrustedTaskContract: created_at integer overflows signed 64-bit limits")
        else:
            if not math.isfinite(self.created_at):
                raise ValueError(f"TrustedTaskContract: created_at must be a finite number, got {self.created_at}")
            if not (MIN_TIMESTAMP_BOUND <= self.created_at <= MAX_TIMESTAMP_BOUND):
                raise ValueError("TrustedTaskContract: created_at float overflows signed 64-bit limits")

        if self.expires_at is not None:
            if isinstance(self.expires_at, bool) or not isinstance(self.expires_at, (int, float)):
                raise TypeError(f"TrustedTaskContract: expires_at must be a numeric timestamp, got {type(self.expires_at).__name__}")
            if isinstance(self.expires_at, int):
                if not (MIN_TIMESTAMP_BOUND <= self.expires_at <= MAX_TIMESTAMP_BOUND):
                    raise ValueError("TrustedTaskContract: expires_at integer overflows signed 64-bit limits")
            else:
                if not math.isfinite(self.expires_at):
                    raise ValueError(f"TrustedTaskContract: expires_at must be a finite number, got {self.expires_at}")
                if not (MIN_TIMESTAMP_BOUND <= self.expires_at <= MAX_TIMESTAMP_BOUND):
                    raise ValueError("TrustedTaskContract: expires_at float overflows signed 64-bit limits")

    def compute_contract_digest(self) -> str:
        self._validate_timestamp_fields()
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
        if not isinstance(signing_secret, (bytes, bytearray)):
            raise TypeError(f"signing_secret must be bytes or bytearray, got {type(signing_secret).__name__}")
        if len(signing_secret) == 0:
            raise ValueError("signing_secret cannot be empty")
        digest = self.compute_contract_digest()
        self.signature = hmac.new(signing_secret, digest.encode("utf-8"), hashlib.sha256).hexdigest()
        return self.signature

    def verify_signature(self, signing_secret: bytes, current_time: Optional[float] = None) -> bool:
        if not isinstance(signing_secret, (bytes, bytearray)) or len(signing_secret) == 0:
            return False
        if not self.signature or not isinstance(self.signature, str) or len(self.signature) != 64:
            return False
        try:
            int(self.signature, 16)
        except ValueError:
            return False

        if self.is_expired(current_time=current_time):
            return False

        try:
            digest = self.compute_contract_digest()
        except (TypeError, ValueError):
            return False
        expected_sig = hmac.new(signing_secret, digest.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature.lower(), expected_sig.lower())

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        if self.expires_at is None:
            return False

        if isinstance(self.expires_at, bool) or not isinstance(self.expires_at, (int, float)):
            return True
        if isinstance(self.expires_at, int):
            if not (MIN_TIMESTAMP_BOUND <= self.expires_at <= MAX_TIMESTAMP_BOUND):
                return True
            exp_val: Union[int, float] = self.expires_at
        else:
            if not math.isfinite(self.expires_at) or not (MIN_TIMESTAMP_BOUND <= self.expires_at <= MAX_TIMESTAMP_BOUND):
                return True
            exp_val = self.expires_at

        if current_time is not None:
            if isinstance(current_time, bool) or not isinstance(current_time, (int, float)):
                return True
            if isinstance(current_time, int):
                if not (MIN_TIMESTAMP_BOUND <= current_time <= MAX_TIMESTAMP_BOUND):
                    return True
                now: Union[int, float] = current_time
            else:
                if not math.isfinite(current_time) or not (MIN_TIMESTAMP_BOUND <= current_time <= MAX_TIMESTAMP_BOUND):
                    return True
                now = current_time
        else:
            now = time.time()
        return now >= exp_val

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
            task_id=val["task_id"],
            contract_version=str(val.get("contract_version", "1.0.0")),
            permitted_actions=set(val.get("permitted_actions", [])),
            resource_scope=set(val.get("resource_scope", [])),
            explicit_prohibitions=set(val.get("explicit_prohibitions", [])),
            prohibited_resources=set(val.get("prohibited_resources", [])),
            approval_requirements=set(val.get("approval_requirements", [])),
            success_evidence_requirements=set(val.get("success_evidence_requirements", [])),
            created_at=val.get("created_at", time.time()),
            expires_at=val.get("expires_at"),
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


# Conservative maximum URL and authorization target input length bounded to 4096 characters to prevent DoS.
MAX_TARGET_INPUT_LEN = 4096

# Precompiled character-class patterns for hot validation in _normalize_target_scope_impl.
# Replaces slow Python generator any() loops with fast C-level regex character searches (~3.8x-4.8x speedup on uncached targets).
_TARGET_UNENCODED_CTRL_REGEX = re.compile(r"[\s\x00\x0b\x0c]")
_TARGET_AUTHORITY_CTRL_REGEX = re.compile(r"[\s\x00-\x1f\x7f]")
_TARGET_DECODED_CTRL_REGEX = re.compile(r"[\x00\r\n\t\x0b\x0c]")


def _normalize_target_scope_impl(raw_target: str) -> str:
    """Internal canonicalization kernel for target resource scopes."""
    if not isinstance(raw_target, str) or not raw_target:
        raise ValueError(
            f"Target resource must be a non-empty string, got {type(raw_target).__name__}: "
            f"{raw_target!r}"
        )

    # Strict resource bounds on target input length before urlparse or unquote
    if len(raw_target) > MAX_TARGET_INPUT_LEN:
        raise ValueError(
            f"Target resource exceeds maximum input length of {MAX_TARGET_INPUT_LEN} characters: "
            f"length={len(raw_target)}"
        )

    str_raw = raw_target
    # Reject unencoded control characters and whitespace anomalies that cause parser differential or scope collision
    if _TARGET_UNENCODED_CTRL_REGEX.search(str_raw):
        raise ValueError(f"Malformed target resource contains unencoded whitespace or control characters: {raw_target!r}")
    str_target = str_raw
    if "://" in str_target:
        parsed = urlparse(str_target)
        raw_netloc = parsed.netloc or ""
        unquoted_netloc = unquote(raw_netloc)
        # Reject decoded whitespace and C0 control characters in authority
        if _TARGET_AUTHORITY_CTRL_REGEX.search(unquoted_netloc):
            raise ValueError(f"Malformed target resource contains decoded whitespace or control characters in authority: {raw_target!r}")
        netloc = unquoted_netloc.lower()
        raw_path = parsed.path or "/"
    else:
        netloc = ""
        raw_path = str_target if str_target.startswith("/") else "/" + str_target
        if "?" in raw_path or "#" in raw_path:
            parsed = urlparse("http://localhost" + raw_path)
            raw_path = parsed.path or "/"
    clean_path = unquote(raw_path).replace("\\", "/")
    # Reject decoded NUL and control characters (CR, LF, TAB, vertical tab, form feed, NUL) after percent-decoding
    if _TARGET_DECODED_CTRL_REGEX.search(clean_path):
        raise ValueError(f"Malformed target resource contains decoded control characters or NUL: {raw_target!r}")
    norm_path = os.path.normpath(clean_path)
    if norm_path in (".", "", "/"):
        norm_path = "/"
    else:
        norm_path = norm_path.rstrip("/")
    return f"target:{netloc}:{norm_path}"


# Performance optimization: memoize canonical target scopes for bounded lengths (<= 512 chars).
# Prevents repeated urlparse, unquoting, and os.path.normpath overhead across capability checks.
@lru_cache(maxsize=4096)
def _cached_normalize_target_scope(raw_target: str) -> str:
    """Bounded memoization for canonical target scope normalization."""
    return _normalize_target_scope_impl(raw_target)


def normalize_target_scope(raw_target: str) -> str:
    """
    Canonicalizes target resource string into a normalized scope identifier.
    Strips trailing slashes, resolves traversal dots and unquotes percent-encoded paths,
    and isolates hostname/port if present.
    Raises ValueError for missing, empty, non-string, oversized, or malformed inputs containing
    unencoded control characters, whitespace anomalies, or null bytes to prevent
    collision with valid root targets and pre-empt parser DoS.
    Uses bounded LRU caching for lengths <= 512 to avoid repetitive parsing (~38x speedup).
    """
    if not isinstance(raw_target, str) or not raw_target:
        raise ValueError(
            f"Target resource must be a non-empty string, got {type(raw_target).__name__}: "
            f"{raw_target!r}"
        )

    # Bypass bounded cache for large strings to prevent cache churn/memory bloat
    if len(raw_target) > 512:
        return _normalize_target_scope_impl(raw_target)
    return _cached_normalize_target_scope(raw_target)


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
    def consume_token_and_record_dispatch(
        self,
        token_id: str,
        attempt_id: str,
        dispatched_executor_id: str,
        started_at: float,
        expected_fencing_token: Optional[int] = None,
        dispatch_metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Atomically consumes the capability token and records the execution attempt dispatch
        as a single indivisible transaction under exclusive lock.
        Validates token existence, revocation, replay, and expiration at started_at.
        Returns (success, reason_code, execution_record).
        """
        pass

    @abstractmethod
    def record_execution_outcome(
        self,
        token_id: str,
        attempt_id: str,
        outcome_status: str,
        terminal_ts: float,
        details: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Atomically records terminal execution outcome. Outcomes are immutable once committed.
        Returns (success, reason_code, updated_record).
        """
        pass

    @abstractmethod
    def get_execution_record(self, token_id: str, attempt_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves authoritative execution attempt record."""
        pass

    @abstractmethod
    def get_revocation_record(self, token_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves authoritative revocation record including ordering sequence and timestamp."""
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
        self._seq: int = 0
        self._capabilities: Dict[str, Any] = {}
        self._consumed_tokens: Set[str] = set()
        self._revoked_tokens: Set[str] = set()
        self._revocation_records: Dict[str, Dict[str, Any]] = {}
        self._consumed_approvals: Set[str] = set()
        self._scope_fencing_generations: Dict[str, int] = {}
        self._execution_attempts: Dict[str, Dict[str, Any]] = {}
        self._token_to_attempts: Dict[str, Set[str]] = {}

    def issue_and_register_capability(self, cap: Any, signing_func: Any) -> Any:
        with self._lock:
            canonical_scope = canonicalize_fencing_scope(cap.task_id, cap.target)
            if getattr(cap, "scope_key", None) and cap.scope_key != canonical_scope:
                raise ValueError(f"Capability scope_key mismatch: {cap.scope_key!r} != {canonical_scope!r}")
            scope_key = canonical_scope
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
            target_val = getattr(cap, "target", "")
            task_id_val = getattr(cap, "task_id", None)
            canonical_scope = canonicalize_fencing_scope(task_id_val, target_val)
            if getattr(cap, "scope_key", None) and cap.scope_key != canonical_scope:
                raise ValueError(f"Capability scope_key mismatch: {cap.scope_key!r} != {canonical_scope!r}")
            scope_key = canonical_scope
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

            self._seq += 1
            self._consumed_tokens.add(token_id)
            if approval_id:
                self._consumed_approvals.add(approval_id)
            return True, "CAPABILITY_CONSUMED_SUCCESSFULLY"

    def consume_token_and_record_dispatch(
        self,
        token_id: str,
        attempt_id: str,
        dispatched_executor_id: str,
        started_at: float,
        expected_fencing_token: Optional[int] = None,
        dispatch_metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        with self._lock:
            if not token_id or not isinstance(token_id, str):
                return False, "CAPABILITY_CONSUMPTION_FAILED_INVALID_TOKEN_ID", None
            if not attempt_id or not isinstance(attempt_id, str):
                return False, "CAPABILITY_CONSUMPTION_FAILED_INVALID_ATTEMPT_ID", None

            if attempt_id in self._execution_attempts:
                return False, f"EXECUTION_DISPATCH_FAILED_DUPLICATE_ATTEMPT_ID: attempt {attempt_id} already exists", None

            if token_id in self._revoked_tokens:
                return False, "CAPABILITY_CONSUMPTION_FAILED_REVOKED", None

            if token_id in self._consumed_tokens:
                return False, "CAPABILITY_CONSUMPTION_FAILED_ALREADY_CONSUMED", None

            cap_obj = self._capabilities.get(token_id)
            if not cap_obj:
                return False, "CAPABILITY_CONSUMPTION_FAILED_UNKNOWN_TOKEN", None

            # Expiration check at dispatch time
            is_expired = False
            if hasattr(cap_obj, "is_expired"):
                is_expired = cap_obj.is_expired(started_at)
            elif isinstance(cap_obj, dict):
                exp = cap_obj.get("expires_at")
                if exp is not None and float(started_at) > float(exp):
                    is_expired = True
            if is_expired:
                return False, "CAPABILITY_CONSUMPTION_FAILED_EXPIRED_TOKEN", None

            scope_key = getattr(cap_obj, "scope_key", None) or (cap_obj.get("scope_key") if isinstance(cap_obj, dict) else None)
            cap_fence = getattr(cap_obj, "fencing_token", None) or (cap_obj.get("fencing_token") if isinstance(cap_obj, dict) else 1)
            if expected_fencing_token is not None and expected_fencing_token != cap_fence:
                return False, f"CAPABILITY_CONSUMPTION_FAILED_FENCING_TOKEN_MISMATCH: expected {expected_fencing_token}, got {cap_fence}", None

            if scope_key:
                auth_fence = self._scope_fencing_generations.get(scope_key, 0)
                if cap_fence < auth_fence:
                    return False, f"CAPABILITY_CONSUMPTION_FAILED_STALE_FENCING_TOKEN: token generation {cap_fence} < authoritative scope generation {auth_fence}", None
                if cap_fence > auth_fence:
                    return False, f"CAPABILITY_CONSUMPTION_FAILED_FUTURE_FENCING_TOKEN: token generation {cap_fence} > authoritative scope generation {auth_fence}", None

            approval_id = None
            human_app = getattr(cap_obj, "human_approval", None) or (cap_obj.get("human_approval") if isinstance(cap_obj, dict) else None)
            if human_app:
                approval_id = getattr(human_app, "approval_id", None) or (human_app.get("approval_id") if isinstance(human_app, dict) else None)
                if approval_id and approval_id in self._consumed_approvals:
                    return False, "CAPABILITY_CONSUMPTION_FAILED_APPROVAL_REPLAYED", None

            # Atomic transaction commit
            self._seq += 1
            self._consumed_tokens.add(token_id)
            if approval_id:
                self._consumed_approvals.add(approval_id)

            rec = {
                "token_id": token_id,
                "attempt_id": attempt_id,
                "dispatched_executor_id": dispatched_executor_id,
                "started_at": float(started_at),
                "fencing_token": cap_fence,
                "scope_key": scope_key,
                "dispatch_seq": self._seq,
                "outcome_status": "DISPATCHED",
                "terminal_ts": None,
                "details": dispatch_metadata or {}
            }
            self._execution_attempts[attempt_id] = rec
            self._token_to_attempts.setdefault(token_id, set()).add(attempt_id)
            return True, "DISPATCH_RECORDED_SUCCESSFULLY", dict(rec)

    def record_execution_outcome(
        self,
        token_id: str,
        attempt_id: str,
        outcome_status: str,
        terminal_ts: float,
        details: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        with self._lock:
            rec = self._execution_attempts.get(attempt_id)
            if not rec:
                return False, f"EXECUTION_OUTCOME_FAILED_UNKNOWN_ATTEMPT: attempt {attempt_id} not found", None
            if rec.get("token_id") != token_id:
                return False, f"EXECUTION_OUTCOME_FAILED_TOKEN_MISMATCH: attempt bound to token {rec.get('token_id')}, got {token_id}", None

            existing_outcome = rec.get("outcome_status")
            if existing_outcome in ("SUCCESS", "FAILED", "INTERRUPTED", "UNVERIFIED_SUCCESS"):
                return False, f"EXECUTION_OUTCOME_FAILED_ALREADY_COMMITTED: attempt {attempt_id} outcome is immutable ({existing_outcome})", None

            self._seq += 1
            rec["outcome_status"] = outcome_status
            rec["terminal_ts"] = float(terminal_ts)
            rec["terminal_seq"] = self._seq
            if details:
                rec_details = rec.setdefault("details", {})
                if isinstance(rec_details, dict):
                    rec_details["outcome_details"] = details
            return True, "OUTCOME_RECORDED_SUCCESSFULLY", dict(rec)

    def get_execution_record(self, token_id: str, attempt_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            rec = self._execution_attempts.get(attempt_id)
            if rec and rec.get("token_id") == token_id:
                return dict(rec)
            return None

    def get_revocation_record(self, token_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            rec = self._revocation_records.get(token_id)
            if rec:
                return dict(rec)
            return None

    def revoke_capability(self, token_id: str, reason: str = "") -> Tuple[bool, str]:
        with self._lock:
            if token_id in self._consumed_tokens:
                return False, "CAPABILITY_REVOCATION_REJECTED_ALREADY_CONSUMED"
            if token_id in self._revoked_tokens:
                return True, "CAPABILITY_ALREADY_REVOKED"
            self._seq += 1
            now_ts = time.time()
            self._revoked_tokens.add(token_id)
            self._revocation_records[token_id] = {
                "token_id": token_id,
                "reason": reason,
                "timestamp": now_ts,
                "seq": self._seq
            }
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

        self._seq: int = 0
        self._capabilities: Dict[str, Any] = {}
        self._consumed_tokens: Set[str] = set()
        self._revoked_tokens: Set[str] = set()
        self._revocation_records: Dict[str, Dict[str, Any]] = {}
        self._consumed_approvals: Set[str] = set()
        self._scope_fencing_generations: Dict[str, int] = {}
        self._execution_attempts: Dict[str, Dict[str, Any]] = {}
        self._token_to_attempts: Dict[str, Set[str]] = {}

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
                revocation_recs: Dict[str, Dict[str, Any]] = {}
                approvals: Set[str] = set()
                fencing: Dict[str, int] = {}
                attempts: Dict[str, Dict[str, Any]] = {}
                token_attempts: Dict[str, Set[str]] = {}
                max_seq = 0

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

                        rec_seq = rec.get("seq", line_idx)
                        if isinstance(rec_seq, int):
                            max_seq = max(max_seq, rec_seq)

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
                        elif rec_type == "CONSUME_AND_DISPATCH":
                            tok = rec.get("token_id")
                            att_id = rec.get("attempt_id")
                            if not tok or not att_id:
                                if self.fail_closed:
                                    raise RuntimeError(f"Corrupted CONSUME_AND_DISPATCH at line {line_idx}")
                                continue
                            consumed.add(tok)
                            app_id = rec.get("approval_id")
                            if app_id:
                                approvals.add(app_id)
                            attempts[att_id] = {
                                "token_id": tok,
                                "attempt_id": att_id,
                                "dispatched_executor_id": rec.get("dispatched_executor_id"),
                                "started_at": float(rec.get("started_at", 0.0)),
                                "fencing_token": rec.get("fencing_token"),
                                "scope_key": rec.get("scope_key"),
                                "dispatch_seq": rec_seq,
                                "outcome_status": "DISPATCHED",
                                "terminal_ts": None,
                                "details": rec.get("details") or {}
                            }
                            token_attempts.setdefault(tok, set()).add(att_id)
                        elif rec_type == "RECORD_OUTCOME":
                            tok = rec.get("token_id")
                            att_id = rec.get("attempt_id")
                            status = rec.get("outcome_status")
                            if not tok or not att_id or not status:
                                if self.fail_closed:
                                    raise RuntimeError(f"Corrupted RECORD_OUTCOME at line {line_idx}")
                                continue
                            att_rec = attempts.get(att_id)
                            if att_rec:
                                att_rec["outcome_status"] = status
                                att_rec["terminal_ts"] = float(rec.get("terminal_ts", 0.0))
                                att_rec["terminal_seq"] = rec_seq
                                if rec.get("details"):
                                    d = att_rec.setdefault("details", {})
                                    if isinstance(d, dict):
                                        d["outcome_details"] = rec.get("details")
                        elif rec_type == "REVOKE":
                            tok = rec.get("token_id")
                            if not tok:
                                if self.fail_closed:
                                    raise RuntimeError(f"Corrupted REVOKE missing token_id at line {line_idx}")
                                continue
                            revoked.add(tok)
                            revocation_recs[tok] = {
                                "token_id": tok,
                                "reason": rec.get("reason", ""),
                                "timestamp": float(rec.get("timestamp", 0.0)),
                                "seq": rec_seq
                            }
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

                self._seq = max_seq
                self._capabilities = caps
                self._consumed_tokens = consumed
                self._revoked_tokens = revoked
                self._revocation_records = revocation_recs
                self._consumed_approvals = approvals
                self._scope_fencing_generations = fencing
                self._execution_attempts = attempts
                self._token_to_attempts = token_attempts
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
                canonical_scope = canonicalize_fencing_scope(cap.task_id, cap.target)
                if getattr(cap, "scope_key", None) and cap.scope_key != canonical_scope:
                    raise ValueError(f"Capability scope_key mismatch: {cap.scope_key!r} != {canonical_scope!r}")
                scope_key = canonical_scope
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
                target_val = getattr(cap, "target", "")
                task_id_val = getattr(cap, "task_id", None)
                canonical_scope = canonicalize_fencing_scope(task_id_val, target_val)
                if getattr(cap, "scope_key", None) and cap.scope_key != canonical_scope:
                    raise ValueError(f"Capability scope_key mismatch: {cap.scope_key!r} != {canonical_scope!r}")
                scope_key = canonical_scope
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
                        approver_principal=cap_data.get("approver_principal"),
                        approver_provenance=cap_data.get("approver_provenance"),
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

    def consume_token_and_record_dispatch(
        self,
        token_id: str,
        attempt_id: str,
        dispatched_executor_id: str,
        started_at: float,
        expected_fencing_token: Optional[int] = None,
        dispatch_metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        with self._thread_lock:
            self._acquire_flock()
            try:
                self._sync_from_disk(acquire_lock=False)
                if not token_id or not isinstance(token_id, str):
                    return False, "CAPABILITY_CONSUMPTION_FAILED_INVALID_TOKEN_ID", None
                if not attempt_id or not isinstance(attempt_id, str):
                    return False, "CAPABILITY_CONSUMPTION_FAILED_INVALID_ATTEMPT_ID", None

                if attempt_id in self._execution_attempts:
                    return False, f"EXECUTION_DISPATCH_FAILED_DUPLICATE_ATTEMPT_ID: attempt {attempt_id} already exists", None

                if token_id in self._revoked_tokens:
                    return False, "CAPABILITY_CONSUMPTION_FAILED_REVOKED", None

                if token_id in self._consumed_tokens:
                    return False, "CAPABILITY_CONSUMPTION_FAILED_ALREADY_CONSUMED", None

                cap_data = self._capabilities.get(token_id)
                if not cap_data:
                    return False, "CAPABILITY_CONSUMPTION_FAILED_UNKNOWN_TOKEN", None

                # Expiration check at dispatch time
                expires_at_val = None
                if isinstance(cap_data, dict):
                    expires_at_val = cap_data.get("expires_at")
                else:
                    expires_at_val = getattr(cap_data, "expires_at", None)
                if expires_at_val is not None and float(started_at) > float(expires_at_val):
                    return False, "CAPABILITY_CONSUMPTION_FAILED_EXPIRED_TOKEN", None

                scope_key = cap_data.get("scope_key") if isinstance(cap_data, dict) else getattr(cap_data, "scope_key", None)
                cap_fence = int(cap_data.get("fencing_token", 1) if isinstance(cap_data, dict) else getattr(cap_data, "fencing_token", 1))
                if expected_fencing_token is not None and expected_fencing_token != cap_fence:
                    return False, f"CAPABILITY_CONSUMPTION_FAILED_FENCING_TOKEN_MISMATCH: expected {expected_fencing_token}, got {cap_fence}", None

                if scope_key:
                    auth_fence = self._scope_fencing_generations.get(scope_key, 0)
                    if cap_fence < auth_fence:
                        return False, f"CAPABILITY_CONSUMPTION_FAILED_STALE_FENCING_TOKEN: token generation {cap_fence} < authoritative scope generation {auth_fence}", None
                    if cap_fence > auth_fence:
                        return False, f"CAPABILITY_CONSUMPTION_FAILED_FUTURE_FENCING_TOKEN: token generation {cap_fence} > authoritative scope generation {auth_fence}", None

                approval_id = None
                human_app = cap_data.get("human_approval") if isinstance(cap_data, dict) else getattr(cap_data, "human_approval", None)
                if human_app:
                    approval_id = human_app.get("approval_id") if isinstance(human_app, dict) else getattr(human_app, "approval_id", None)
                    if approval_id and approval_id in self._consumed_approvals:
                        return False, "CAPABILITY_CONSUMPTION_FAILED_APPROVAL_REPLAYED", None

                next_seq = self._seq + 1
                rec = {
                    "type": "CONSUME_AND_DISPATCH",
                    "seq": next_seq,
                    "token_id": token_id,
                    "attempt_id": attempt_id,
                    "dispatched_executor_id": dispatched_executor_id,
                    "started_at": float(started_at),
                    "approval_id": approval_id,
                    "fencing_token": cap_fence,
                    "scope_key": scope_key,
                    "details": dispatch_metadata or {},
                    "timestamp": time.time()
                }
                self._append_record_under_lock(rec)
                self._seq = next_seq
                self._consumed_tokens.add(token_id)
                if approval_id:
                    self._consumed_approvals.add(approval_id)

                stored_rec = {
                    "token_id": token_id,
                    "attempt_id": attempt_id,
                    "dispatched_executor_id": dispatched_executor_id,
                    "started_at": float(started_at),
                    "fencing_token": cap_fence,
                    "scope_key": scope_key,
                    "dispatch_seq": next_seq,
                    "outcome_status": "DISPATCHED",
                    "terminal_ts": None,
                    "details": dispatch_metadata or {}
                }
                self._execution_attempts[attempt_id] = stored_rec
                self._token_to_attempts.setdefault(token_id, set()).add(attempt_id)
                return True, "DISPATCH_RECORDED_SUCCESSFULLY", dict(stored_rec)
            finally:
                self._release_flock()

    def record_execution_outcome(
        self,
        token_id: str,
        attempt_id: str,
        outcome_status: str,
        terminal_ts: float,
        details: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        with self._thread_lock:
            self._acquire_flock()
            try:
                self._sync_from_disk(acquire_lock=False)
                rec = self._execution_attempts.get(attempt_id)
                if not rec:
                    return False, f"EXECUTION_OUTCOME_FAILED_UNKNOWN_ATTEMPT: attempt {attempt_id} not found", None
                if rec.get("token_id") != token_id:
                    return False, f"EXECUTION_OUTCOME_FAILED_TOKEN_MISMATCH: attempt bound to token {rec.get('token_id')}, got {token_id}", None

                existing_outcome = rec.get("outcome_status")
                if existing_outcome in ("SUCCESS", "FAILED", "INTERRUPTED", "UNVERIFIED_SUCCESS"):
                    return False, f"EXECUTION_OUTCOME_FAILED_ALREADY_COMMITTED: attempt {attempt_id} outcome is immutable ({existing_outcome})", None

                next_seq = self._seq + 1
                journal_rec = {
                    "type": "RECORD_OUTCOME",
                    "seq": next_seq,
                    "token_id": token_id,
                    "attempt_id": attempt_id,
                    "outcome_status": outcome_status,
                    "terminal_ts": float(terminal_ts),
                    "details": details or {},
                    "timestamp": time.time()
                }
                self._append_record_under_lock(journal_rec)
                self._seq = next_seq
                rec["outcome_status"] = outcome_status
                rec["terminal_ts"] = float(terminal_ts)
                rec["terminal_seq"] = next_seq
                if details:
                    d = rec.setdefault("details", {})
                    if isinstance(d, dict):
                        d["outcome_details"] = details
                return True, "OUTCOME_RECORDED_SUCCESSFULLY", dict(rec)
            finally:
                self._release_flock()

    def get_execution_record(self, token_id: str, attempt_id: str) -> Optional[Dict[str, Any]]:
        with self._thread_lock:
            self._acquire_flock()
            try:
                self._sync_from_disk(acquire_lock=False)
                rec = self._execution_attempts.get(attempt_id)
                if rec and rec.get("token_id") == token_id:
                    return dict(rec)
                return None
            finally:
                self._release_flock()

    def get_revocation_record(self, token_id: str) -> Optional[Dict[str, Any]]:
        with self._thread_lock:
            self._acquire_flock()
            try:
                self._sync_from_disk(acquire_lock=False)
                rec = self._revocation_records.get(token_id)
                if rec:
                    return dict(rec)
                return None
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

                next_seq = self._seq + 1
                now_ts = time.time()
                rec = {
                    "type": "REVOKE",
                    "seq": next_seq,
                    "token_id": token_id,
                    "reason": reason,
                    "timestamp": now_ts
                }
                self._append_record_under_lock(rec)
                self._seq = next_seq
                self._revoked_tokens.add(token_id)
                self._revocation_records[token_id] = {
                    "token_id": token_id,
                    "reason": reason,
                    "timestamp": now_ts,
                    "seq": next_seq
                }
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


import base64

# RFC 8032 pure-python Ed25519 verification with optional libcrypto acceleration
_ED25519_B = 256


import types


class PrincipalVerifier:
    """
    Independent identity verifier that validates AuthenticatedPrincipal assertions
    using public-key cryptography (Ed25519).
    Holds ONLY configured public verification keys (by issuer); does NOT hold private signing
    keys or identity-minting APIs.
    The trust store is strictly immutable after initialization to prevent callers from
    registering unauthorized issuers or establishing attacker-controlled trust relationships at runtime.
    Enforces issuer validation, asymmetric signature verification, clock skew tolerance, and expiry.
    """

    def __init__(
        self,
        trusted_public_keys: Optional[Dict[str, Union[bytes, str]]] = None,
        clock_skew_seconds: Union[int, float] = 5.0
    ):
        if isinstance(clock_skew_seconds, bool) or not isinstance(clock_skew_seconds, (int, float)):
            raise ValueError(f"clock_skew_seconds must be a finite non-negative number, got {type(clock_skew_seconds).__name__}")
        clock_skew_val = float(clock_skew_seconds)
        if not math.isfinite(clock_skew_val) or clock_skew_val < 0.0:
            raise ValueError(f"clock_skew_seconds must be a finite non-negative number, got {clock_skew_seconds}")

        raw_keys: Dict[str, bytes] = {}
        super().__setattr__("_clock_skew_seconds", clock_skew_val)

        keys_input = trusted_public_keys
        if keys_input is None:
            # Check environment for configured issuer public keys:
            # e.g., EPISTEMICOS_IDP_ISSUER="CorpIdP", EPISTEMICOS_IDP_PUBLIC_KEY="<base64 or hex>"
            env_issuer = os.getenv("EPISTEMICOS_IDP_ISSUER")
            env_key = os.getenv("EPISTEMICOS_IDP_PUBLIC_KEY")
            if env_issuer and env_key:
                keys_input = {env_issuer: env_key}

        if keys_input:
            for issuer, key_val in keys_input.items():
                if not issuer or not isinstance(issuer, str) or not issuer.strip():
                    raise ValueError("issuer_id must be a non-empty string")
                iss = issuer.strip()
                if isinstance(key_val, str):
                    clean_k = key_val.strip()
                    # Handle PEM format if provided
                    if "-----BEGIN PUBLIC KEY-----" in clean_k:
                        lines = [l.strip() for l in clean_k.splitlines() if "---" not in l]
                        der = base64.b64decode("".join(lines))
                        # SubjectPublicKeyInfo for ED25519 is 44 bytes, raw key is the last 32 bytes
                        raw_k = der[-32:]
                    else:
                        try:
                            raw_k = bytes.fromhex(clean_k)
                        except ValueError:
                            raw_k = base64.b64decode(clean_k)
                elif isinstance(key_val, (bytes, bytearray)):
                    raw_k = bytes(key_val)
                else:
                    raise TypeError("public_key must be bytes or str")

                if len(raw_k) != 32:
                    raise ValueError(f"Ed25519 public key must be exactly 32 bytes (got {len(raw_k)})")
                raw_keys[iss] = raw_k

        # Immutable MappingProxyType prevents runtime modification of trusted public keys
        super().__setattr__("_trusted_public_keys", types.MappingProxyType(raw_keys))

    @property
    def clock_skew_seconds(self) -> float:
        """Read-only clock skew tolerance. Reassignment is prohibited."""
        return self._clock_skew_seconds

    def __setattr__(self, name: str, value: Any) -> None:
        if "_trusted_public_keys" in self.__dict__ and name in ("_trusted_public_keys", "trusted_public_keys"):
            raise PermissionError("Access denied: PrincipalVerifier._trusted_public_keys is immutable and cannot be reassigned")
        if "_clock_skew_seconds" in self.__dict__ and name in ("_clock_skew_seconds", "clock_skew_seconds"):
            raise PermissionError("Access denied: PrincipalVerifier.clock_skew_seconds is immutable and cannot be reassigned")
        super().__setattr__(name, value)

    def __delattr__(self, name: str) -> None:
        if name in ("_trusted_public_keys", "trusted_public_keys"):
            raise PermissionError("Access denied: PrincipalVerifier._trusted_public_keys cannot be deleted")
        if name in ("_clock_skew_seconds", "clock_skew_seconds"):
            raise PermissionError("Access denied: PrincipalVerifier.clock_skew_seconds cannot be deleted")
        super().__delattr__(name)

    def has_trusted_issuers(self) -> bool:
        return bool(self._trusted_public_keys)

    def verify_principal(
        self,
        principal: Any,
        max_age_seconds: float = 3600.0,
        current_time: Optional[float] = None
    ) -> Tuple[bool, str, Optional[str]]:
        if not self._trusted_public_keys:
            return False, "PrincipalVerifier is not configured with any trusted public verification keys", None

        if not isinstance(principal, AuthenticatedPrincipal):
            return False, "Object is not a valid AuthenticatedPrincipal assertion", None

        if not principal.signature or not isinstance(principal.signature, str):
            return False, "Missing or invalid signature on principal assertion", None

        trusted_pubkey = self._trusted_public_keys.get(principal.issuer_id)
        if not trusted_pubkey:
            return False, f"Untrusted identity issuer: '{principal.issuer_id}' is not in configured trusted issuers", None

        # Validate clock override if provided
        if current_time is not None:
            if isinstance(current_time, bool) or not isinstance(current_time, (int, float)):
                return False, "Invalid current_time clock override: must be a numeric timestamp", None
            if isinstance(current_time, int):
                if not (MIN_TIMESTAMP_BOUND <= current_time <= MAX_TIMESTAMP_BOUND):
                    return False, "Invalid current_time clock override: integer overflows signed 64-bit limits", None
                now = float(current_time)
            else:
                if not math.isfinite(current_time) or not (MIN_TIMESTAMP_BOUND <= current_time <= MAX_TIMESTAMP_BOUND):
                    return False, "Invalid current_time clock override: must be a finite number within signed 64-bit limits", None
                now = current_time
        else:
            now = time.time()

        # Runtime validation of principal.timestamp before any arithmetic
        if isinstance(principal.timestamp, bool) or not isinstance(principal.timestamp, (int, float)):
            return False, "Principal assertion has invalid non-numeric timestamp", None
        if isinstance(principal.timestamp, int):
            if not (MIN_TIMESTAMP_BOUND <= principal.timestamp <= MAX_TIMESTAMP_BOUND):
                return False, "Principal assertion timestamp integer overflows signed 64-bit limits", None
            ts_val = float(principal.timestamp)
        else:
            if not math.isfinite(principal.timestamp) or not (MIN_TIMESTAMP_BOUND <= principal.timestamp <= MAX_TIMESTAMP_BOUND):
                return False, "Principal assertion timestamp is non-finite or overflows signed 64-bit limits", None
            ts_val = principal.timestamp

        # Reject future-dated assertions (beyond permitted clock skew)
        if ts_val > (now + self.clock_skew_seconds):
            return False, f"Future-dated principal assertion rejected (timestamp {ts_val} > current time {now})", None

        # Reject expired assertions by timestamp + max_age_seconds
        if (now - ts_val) > max_age_seconds:
            return False, f"Principal assertion expired (age {now - ts_val:.1f}s > max {max_age_seconds}s)", None

        # Reject expired assertions by explicit expires_at field if present
        if principal.expires_at is not None:
            if isinstance(principal.expires_at, bool) or not isinstance(principal.expires_at, (int, float)):
                return False, "Principal assertion has invalid non-numeric expires_at", None
            if isinstance(principal.expires_at, int):
                if not (MIN_TIMESTAMP_BOUND <= principal.expires_at <= MAX_TIMESTAMP_BOUND):
                    return False, "Principal assertion expires_at integer overflows signed 64-bit limits", None
                exp_val = float(principal.expires_at)
            else:
                if not math.isfinite(principal.expires_at) or not (MIN_TIMESTAMP_BOUND <= principal.expires_at <= MAX_TIMESTAMP_BOUND):
                    return False, "Principal assertion expires_at is non-finite or overflows signed 64-bit limits", None
                exp_val = principal.expires_at

            if now >= exp_val:
                return False, f"Principal assertion expired (current time {now} >= expires_at {exp_val})", None

        # Decode signature
        try:
            sig_bytes = bytes.fromhex(principal.signature)
            if len(sig_bytes) != 64:
                sig_bytes = base64.b64decode(principal.signature)
        except Exception:
            try:
                sig_bytes = base64.b64decode(principal.signature)
            except Exception:
                return False, "Invalid signature encoding on principal assertion", None

        if len(sig_bytes) != 64:
            return False, f"Invalid signature length on principal assertion (expected 64 bytes, got {len(sig_bytes)})", None

        # Verify asymmetric Ed25519 signature
        msg_bytes = principal.compute_signature_payload()
        if not verify_ed25519_signature(sig_bytes, msg_bytes, trusted_pubkey):
            return False, "Cryptographic asymmetric signature verification failed on principal assertion", None

        return True, "Principal verified", principal.principal_id


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
    approver_principal: Optional[str] = None
    approver_provenance: Optional[Dict[str, Any]] = None
    issuer_id: str = "TrustedAuthorizationAuthority"
    signature: Optional[str] = None
    fencing_token: int = 1
    scope_key: Optional[str] = None

    def __post_init__(self):
        self._validate_timestamp_fields()

    def _validate_timestamp_fields(self) -> None:
        """Strictly validates created_at and expires_at against type ambiguity and overflow."""
        for field_name, val in (("created_at", self.created_at), ("expires_at", self.expires_at)):
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                raise TypeError(f"Capability: {field_name} must be a numeric timestamp, got {type(val).__name__}")
            if isinstance(val, int):
                if not (MIN_TIMESTAMP_BOUND <= val <= MAX_TIMESTAMP_BOUND):
                    raise ValueError(f"Capability: {field_name} integer overflows signed 64-bit limits")
            else:
                if not math.isfinite(val):
                    raise ValueError(f"Capability: {field_name} must be a finite number, got {val}")
                if not (MIN_TIMESTAMP_BOUND <= val <= MAX_TIMESTAMP_BOUND):
                    raise ValueError(f"Capability: {field_name} float overflows signed 64-bit limits")

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        if isinstance(self.expires_at, bool) or not isinstance(self.expires_at, (int, float)):
            return True
        if isinstance(self.expires_at, int):
            if not (MIN_TIMESTAMP_BOUND <= self.expires_at <= MAX_TIMESTAMP_BOUND):
                return True
            exp_val: Union[int, float] = self.expires_at
        else:
            if not math.isfinite(self.expires_at) or not (MIN_TIMESTAMP_BOUND <= self.expires_at <= MAX_TIMESTAMP_BOUND):
                return True
            exp_val = self.expires_at

        if current_time is not None:
            if isinstance(current_time, bool) or not isinstance(current_time, (int, float)):
                return True
            if isinstance(current_time, int):
                if not (MIN_TIMESTAMP_BOUND <= current_time <= MAX_TIMESTAMP_BOUND):
                    return True
                now: Union[int, float] = current_time
            else:
                if not math.isfinite(current_time) or not (MIN_TIMESTAMP_BOUND <= current_time <= MAX_TIMESTAMP_BOUND):
                    return True
                now = current_time
        else:
            now = time.time()
        return now >= exp_val

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
        signing_secret: Optional[Union[bytes, bytearray]] = None,
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

        # Fail-closed signing secret validation and secure environment variable resolution
        import os
        if signing_secret is None:
            env_cap_sec = os.getenv("EPISTEMICOS_CAP_SECRET")
            if env_cap_sec is not None:
                signing_secret = env_cap_sec.encode("utf-8")

        if signing_secret is not None:
            if not isinstance(signing_secret, (bytes, bytearray)):
                sec_type = type(signing_secret).__name__
                raise TypeError(f"signing_secret must be bytes or bytearray, got {sec_type}")
            if len(signing_secret) == 0:
                raise ValueError("signing_secret cannot be empty")
            self.signing_secret = bytes(signing_secret)
        else:
            entropy_tag = f"EPISTEMICOS_CAP_KEY_{uuid.uuid4()}".encode("utf-8")
            self.signing_secret = hashlib.sha256(entropy_tag).digest()

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

        # Cryptographically bind approval record and approver provenance into the capability HMAC payload
        approval_binding_digest = ""
        human_app = getattr(cap, "human_approval", None)
        if human_app:
            app_dict = human_app.to_dict() if hasattr(human_app, "to_dict") else dict(human_app)
            if "approver_assertion" in app_dict and app_dict["approver_assertion"]:
                raw_ast = app_dict["approver_assertion"]
                if hasattr(raw_ast, "to_dict"):
                    ast_dict = raw_ast.to_dict()
                elif isinstance(raw_ast, dict):
                    ast_dict = raw_ast
                else:
                    ast_dict = raw_ast.__dict__
                app_dict["approver_assertion"] = ast_dict
            prov_data = getattr(cap, "approver_provenance", None)
            prov_dict = prov_data.copy() if isinstance(prov_data, dict) else {}
            app_bound_obj = {
                "approval_record": app_dict,
                "approver_principal": str(getattr(cap, "approver_principal", "") or ""),
                "approver_provenance": prov_dict
            }
            canon_json = json.dumps(app_bound_obj, sort_keys=True, separators=(",", ":"))
            approval_binding_digest = hashlib.sha256(canon_json.encode("utf-8")).hexdigest()

        payload = (
            f"{cap.token_id}:{cap.principal_id}:{cap.correlation_id}:{cap.request_id}:"
            f"{cap.action_name}:{cap.target}:{cap.canonical_request_digest}:{cap.executor_id}:"
            f"{cap.policy_version}:{cap.task_id or ''}:{cap.contract_version or ''}:"
            f"{cap.contract_digest or ''}:{cap.expires_at}:{effective_fence}:{effective_scope}:"
            f"{approval_binding_digest}"
        )
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

    def consume_token_and_record_dispatch(
        self,
        token_id: str,
        attempt_id: str,
        dispatched_executor_id: str,
        started_at: float,
        expected_fencing_token: Optional[int] = None,
        dispatch_metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Atomically consumes capability and records execution dispatch under exclusive storage lock.
        """
        with self._lock:
            self._check_poisoned()
            return self.storage.consume_token_and_record_dispatch(
                token_id=token_id,
                attempt_id=attempt_id,
                dispatched_executor_id=dispatched_executor_id,
                started_at=started_at,
                expected_fencing_token=expected_fencing_token,
                dispatch_metadata=dispatch_metadata
            )

    def record_execution_outcome(
        self,
        token_id: str,
        attempt_id: str,
        outcome_status: str,
        terminal_ts: float,
        details: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Atomically records terminal execution outcome in authoritative storage.
        """
        with self._lock:
            self._check_poisoned()
            return self.storage.record_execution_outcome(
                token_id=token_id,
                attempt_id=attempt_id,
                outcome_status=outcome_status,
                terminal_ts=terminal_ts,
                details=details
            )

    def get_execution_record(self, token_id: str, attempt_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            self._check_poisoned()
            return self.storage.get_execution_record(token_id, attempt_id)

    def get_revocation_record(self, token_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            self._check_poisoned()
            return self.storage.get_revocation_record(token_id)

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

        # Fail-closed resolution and strict validation for approval signing secret
        if approval_signing_secret is None:
            env_approval_sec = os.getenv("EPISTEMICOS_APPROVAL_SECRET")
            if env_approval_sec is not None:
                approval_signing_secret = env_approval_sec.encode("utf-8")

        if approval_signing_secret is not None:
            if not isinstance(approval_signing_secret, (bytes, bytearray)):
                sec_type = type(approval_signing_secret).__name__
                raise TypeError(
                    f"approval_signing_secret must be bytes or bytearray, got {sec_type}"
                )
            if len(approval_signing_secret) == 0:
                raise ValueError("approval_signing_secret cannot be empty")
            self.approval_signing_secret = bytes(approval_signing_secret)
        elif self.is_production:
            raise ValueError(
                "Production configuration error: EPISTEMICOS_APPROVAL_SECRET must be explicitly set in production mode"
            )
        else:
            entropy_tag = f"EPISTEMICOS_APPROVAL_KEY_{uuid.uuid4()}".encode("utf-8")
            self.approval_signing_secret = hashlib.sha256(entropy_tag).digest()

        # Fail-closed resolution and strict validation for contract signing secret
        if contract_signing_secret is None:
            env_contract_sec = os.getenv("EPISTEMICOS_CONTRACT_SECRET")
            if env_contract_sec is not None:
                contract_signing_secret = env_contract_sec.encode("utf-8")

        if contract_signing_secret is not None:
            if not isinstance(contract_signing_secret, (bytes, bytearray)):
                sec_type = type(contract_signing_secret).__name__
                raise TypeError(
                    f"contract_signing_secret must be bytes or bytearray, got {sec_type}"
                )
            if len(contract_signing_secret) == 0:
                raise ValueError("contract_signing_secret cannot be empty")
            self.contract_signing_secret = bytes(contract_signing_secret)
        elif self.is_production:
            raise ValueError(
                "Production configuration error: EPISTEMICOS_CONTRACT_SECRET must be explicitly set in production mode"
            )
        else:
            entropy_tag = f"EPISTEMICOS_CONTRACT_KEY_{uuid.uuid4()}".encode("utf-8")
            self.contract_signing_secret = hashlib.sha256(entropy_tag).digest()

        if self.is_production:
            if require_task_contract is False:
                raise ValueError(
                    "Production configuration error: task contract enforcement (require_task_contract) cannot be disabled in production mode"
                )
            self.require_task_contract = True
        else:
            if require_task_contract is not None:
                self.require_task_contract = require_task_contract
            else:
                env_req = os.getenv("EPISTEMICOS_REQUIRE_TASK_CONTRACT", "").strip().lower()
                self.require_task_contract = env_req in ("1", "true", "yes", "on")

        if isinstance(executor_registry, ExecutorRegistry):
            self.executor_registry = executor_registry
        else:
            self.executor_registry = ExecutorRegistry(executor_registry)

        # SEC-01: Independent identity verifier integration.
        # AuthorizationAuthority holds verification keys, NEVER identity-issuing keys or private signing material.
        # The verifier is immutable after initialization and cannot be replaced by callers.
        if principal_provider:
            resolved_provider = principal_provider
        else:
            env_issuer = os.getenv("EPISTEMICOS_IDP_ISSUER")
            env_key = os.getenv("EPISTEMICOS_IDP_PUBLIC_KEY")
            if env_issuer and env_key:
                resolved_provider = PrincipalVerifier(
                    trusted_public_keys={env_issuer: env_key}
                )
            else:
                resolved_provider = None

        super().__setattr__("_principal_provider", resolved_provider)

    @property
    def principal_provider(self) -> Optional[PrincipalVerifier]:
        """Read-only access to configured PrincipalVerifier. Attribute replacement is prohibited."""
        return self._principal_provider

    def __setattr__(self, name: str, value: Any) -> None:
        if "_principal_provider" in self.__dict__ and name in ("principal_provider", "_principal_provider"):
            raise PermissionError(f"Access denied: AuthorizationAuthority.{name} is immutable and cannot be reassigned")
        super().__setattr__(name, value)

    def __delattr__(self, name: str) -> None:
        if name in ("principal_provider", "_principal_provider"):
            raise PermissionError(f"Access denied: AuthorizationAuthority.{name} cannot be deleted")
        super().__delattr__(name)

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
            verified_approver_principal: Optional[str] = None
            approver_provenance_data: Optional[Dict[str, Any]] = None

            if requires_approval:
                approval_record = HumanApprovalRecord.from_input(human_approval_input)
                if not approval_record:
                    return None, "STOP_AND_ESCALATE_HUMAN_APPROVAL_REQUIRED"

                # 1. Structural Binding Validations
                if approval_record.action_name != action_name or approval_record.target != target:
                    return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_BINDING_MISMATCH"

                if approval_record.action_digest != canonical_request_digest:
                    return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_DIGEST_MISMATCH"

                if approval_record.request_id != req_id:
                    return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_REQUEST_ID_MISMATCH"

                # 2. Cryptographic Approval Record Integrity & Freshness (HMAC)
                if not approval_record.signature:
                    return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_MISSING_SIGNATURE"

                if not approval_record.verify_signature(self.approval_signing_secret, current_time=current_time):
                    return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_AUTHENTICATION_FAILED"

                # 3. Replay Protection
                if self.registry.is_approval_consumed(approval_record.approval_id):
                    return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_REPLAYED"

                # 4. Immediate Self-Approval & Raw Approver Allowlist Check
                if approval_record.approver_id == effective_principal or approval_record.approver_id == principal_id:
                    return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_SELF_APPROVAL_REJECTED"

                if active_policy.allowed_approvers is not None and "*" not in active_policy.allowed_approvers:
                    if approval_record.approver_id not in active_policy.allowed_approvers:
                        return None, f"AUTHORIZATION_DENIED_HUMAN_APPROVAL_UNTRUSTED_APPROVER:{approval_record.approver_id}"

                # 5. Independent Approver Identity Verification
                if not self.principal_provider:
                    return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_NO_IDENTITY_PROVIDER_CONFIGURED"

                if not approval_record.approver_assertion:
                    return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_MISSING_APPROVER_ASSERTION"

                appr_valid, appr_reason, verified_pid = self.principal_provider.verify_principal(
                    approval_record.approver_assertion,
                    current_time=current_time
                )
                if not appr_valid or not verified_pid:
                    return None, f"AUTHORIZATION_DENIED_HUMAN_APPROVAL_APPROVER_AUTHENTICATION_FAILED: {appr_reason}"

                verified_approver_principal = verified_pid

                # Assert that verified approver identity matches approver_id
                if approval_record.approver_id != verified_approver_principal:
                    return None, f"AUTHORIZATION_DENIED_HUMAN_APPROVAL_APPROVER_ID_MISMATCH: claimed '{approval_record.approver_id}', verified '{verified_approver_principal}'"

                # 6. Approver Authorization under Applicable Policy
                if active_policy.allowed_approvers is not None and "*" not in active_policy.allowed_approvers:
                    if verified_approver_principal not in active_policy.allowed_approvers:
                        return None, f"AUTHORIZATION_DENIED_HUMAN_APPROVAL_UNAUTHORIZED_APPROVER:{verified_approver_principal}"

                # 7. Requesting Principal and Task Context Binding (Mandatory)
                # Prevent self-approval (approver cannot be the requesting principal)
                if verified_approver_principal == effective_principal:
                    return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_SELF_APPROVAL_REJECTED"

                if not approval_record.requesting_principal or not str(approval_record.requesting_principal).strip():
                    return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_MISSING_REQUESTING_PRINCIPAL"

                if str(approval_record.requesting_principal).strip() != effective_principal:
                    return None, f"AUTHORIZATION_DENIED_HUMAN_APPROVAL_REQUESTING_PRINCIPAL_MISMATCH: bound '{approval_record.requesting_principal}', requested '{effective_principal}'"

                if effective_task_id:
                    if not approval_record.task_id or not str(approval_record.task_id).strip():
                        return None, "AUTHORIZATION_DENIED_HUMAN_APPROVAL_MISSING_TASK_ID"
                    if str(approval_record.task_id).strip() != str(effective_task_id).strip():
                        return None, f"AUTHORIZATION_DENIED_HUMAN_APPROVAL_TASK_ID_MISMATCH: bound '{approval_record.task_id}', requested '{effective_task_id}'"

                # Record provenance evidence of the independent verification decision
                assertion_obj = approval_record.approver_assertion
                approver_provenance_data = {
                    "approver_id": verified_approver_principal,
                    "issuer_id": getattr(assertion_obj, "issuer_id", "") if hasattr(assertion_obj, "issuer_id") else assertion_obj.get("issuer_id", "") if isinstance(assertion_obj, dict) else "",
                    "assertion_timestamp": getattr(assertion_obj, "timestamp", 0.0) if hasattr(assertion_obj, "timestamp") else assertion_obj.get("timestamp", 0.0) if isinstance(assertion_obj, dict) else 0.0,
                    "verified_at": current_time if current_time is not None else time.time(),
                    "approval_id": approval_record.approval_id
                }

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
                approver_principal=verified_approver_principal,
                approver_provenance=approver_provenance_data,
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

        # Downstream Human Approval Provenance & Integrity Verification
        if human_app:
            # 1. Verify approval record HMAC integrity against authority approval secret
            if not human_app.verify_signature(self.approval_signing_secret, current_time=current_time):
                return False, "CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_SIGNATURE_INVALID", cap

            # 2. Verify approver provenance and identity consistency
            approver_principal = getattr(cap, "approver_principal", None)
            approver_prov = getattr(cap, "approver_provenance", None)
            if not approver_principal or not approver_prov:
                return False, "CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_PROVENANCE_MISSING", cap

            if approver_principal != human_app.approver_id:
                return False, f"CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_APPROVER_MISMATCH: capability approver '{approver_principal}' != record approver '{human_app.approver_id}'", cap

            # 3. Verify that approver assertion remains verifiable via configured PrincipalVerifier
            if not human_app.approver_assertion:
                return False, "CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_ASSERTION_MISSING", cap

            if not self.principal_provider:
                return False, "CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_NO_IDENTITY_PROVIDER", cap

            appr_valid, appr_reason, verified_appr_pid = self.principal_provider.verify_principal(
                human_app.approver_assertion,
                current_time=current_time
            )
            if not appr_valid or verified_appr_pid != approver_principal:
                return False, f"CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_APPROVER_VERIFICATION_FAILED: {appr_reason}", cap

            # Explicitly validate the provenance dictionary against the independently verified assertion
            ast_obj = human_app.approver_assertion
            if hasattr(ast_obj, "to_dict"):
                ast_dict = ast_obj.to_dict()
            elif isinstance(ast_obj, dict):
                ast_dict = ast_obj
            else:
                ast_dict = ast_obj.__dict__
            expected_issuer = str(ast_dict.get("issuer_id") or "")
            expected_ts = float(ast_dict.get("timestamp") or 0.0)

            if not isinstance(approver_prov, dict):
                return False, "CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_PROVENANCE_MALFORMED", cap

            if approver_prov.get("approver_id") != verified_appr_pid:
                return False, f"CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_PROVENANCE_APPROVER_MISMATCH: provenance approver '{approver_prov.get('approver_id')}' != verified '{verified_appr_pid}'", cap

            if approver_prov.get("issuer_id") != expected_issuer:
                return False, f"CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_PROVENANCE_ISSUER_MISMATCH: provenance issuer '{approver_prov.get('issuer_id')}' != assertion issuer '{expected_issuer}'", cap

            ast_ts_val = approver_prov.get("assertion_timestamp")
            if (
                ast_ts_val is None
                or isinstance(ast_ts_val, bool)
                or not isinstance(ast_ts_val, (int, float))
                or not math.isfinite(float(ast_ts_val))
            ):
                return False, "CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_PROVENANCE_INVALID_ASSERTION_TIMESTAMP", cap

            if abs(float(ast_ts_val) - expected_ts) > 1e-4:
                return False, f"CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_PROVENANCE_TIMESTAMP_MISMATCH: provenance ts '{ast_ts_val}' != assertion ts '{expected_ts}'", cap

            if approver_prov.get("approval_id") != human_app.approval_id:
                return False, f"CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_PROVENANCE_APPROVAL_ID_MISMATCH: provenance approval_id '{approver_prov.get('approval_id')}' != record '{human_app.approval_id}'", cap

            verified_at_val = approver_prov.get("verified_at")
            if verified_at_val is None or isinstance(verified_at_val, bool) or not isinstance(verified_at_val, (int, float)) or not math.isfinite(float(verified_at_val)):
                return False, "CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_PROVENANCE_INVALID_VERIFIED_AT", cap

            # 4. Verify bindings between approval record and capability fields
            if human_app.action_name != cap.action_name:
                return False, f"CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_ACTION_MISMATCH: approval '{human_app.action_name}' != capability '{cap.action_name}'", cap

            if human_app.target != cap.target:
                return False, f"CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_TARGET_MISMATCH: approval '{human_app.target}' != capability '{cap.target}'", cap

            if human_app.action_digest != cap.canonical_request_digest:
                return False, f"CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_DIGEST_MISMATCH: approval '{human_app.action_digest}' != capability '{cap.canonical_request_digest}'", cap

            if not human_app.requesting_principal or not str(human_app.requesting_principal).strip():
                return False, "CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_MISSING_REQUESTING_PRINCIPAL", cap

            if str(human_app.requesting_principal).strip() != cap.principal_id:
                return False, f"CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_REQUESTING_PRINCIPAL_MISMATCH: approval '{human_app.requesting_principal}' != capability '{cap.principal_id}'", cap

            if cap.task_id:
                if not human_app.task_id or not str(human_app.task_id).strip():
                    return False, "CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_MISSING_TASK_ID", cap
                if str(human_app.task_id).strip() != str(cap.task_id).strip():
                    return False, f"CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_TASK_ID_MISMATCH: approval '{human_app.task_id}' != capability '{cap.task_id}'", cap

            if human_app.request_id != cap.request_id:
                return False, f"CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_REQUEST_ID_MISMATCH: approval '{human_app.request_id}' != capability '{cap.request_id}'", cap

        return True, "CAPABILITY_VERIFIED", cap

    def verify_historical_capability(
        self,
        token_id: str,
        action_name: str,
        target: str,
        canonical_request_digest: str,
        execution_attempt_id: Optional[str] = None,
        dispatched_executor_id: Optional[str] = None,
        execution_start_time: Optional[float] = None,
        expected_outcome_status: Optional[str] = None,
        correlation_id: Optional[str] = None,
        request_id: Optional[str] = None,
        task_id: Optional[str] = None,
        principal_id: Optional[str] = None
    ) -> Tuple[bool, str, Optional[Capability], Optional[Dict[str, Any]]]:
        """
        Historical verification of an issued capability and its execution lifecycle.
        Verifies:
        1. Authoritative issuance in registry storage.
        2. Cryptographic HMAC signature integrity.
        3. Immutable field bindings (action_name, target, canonical_request_digest, correlation_id, request_id, task_id).
        4. Temporal validity: evaluates expiration and revocation status AT EXECUTION TIME using monotonic journal ordering
           or execution start timestamp, ensuring post-execution revocation/expiration does not invalidate past executions.
        5. Execution attempt and terminal outcome binding against authoritative storage.
        Returns: (is_valid, reason, capability_obj, execution_record)
        """
        if not token_id or not isinstance(token_id, str):
            return False, "HISTORICAL_VERIFICATION_FAILED_INVALID_TOKEN_ID", None, None

        cap = self.registry.get_capability(token_id)
        if not cap:
            return False, f"HISTORICAL_VERIFICATION_FAILED_UNKNOWN_TOKEN: token {token_id} was never issued by authoritative registry", None, None

        # Verify cryptographic HMAC signature
        expected_sig = self.registry.sign_capability(cap)
        if not cap.signature or not hmac.compare_digest(cap.signature, expected_sig):
            return False, f"HISTORICAL_VERIFICATION_FAILED_INVALID_SIGNATURE: token {token_id} has invalid cryptographic signature", None, None

        # Field binding verification
        if cap.action_name != action_name:
            return False, f"HISTORICAL_VERIFICATION_FAILED_ACTION_MISMATCH: granted '{cap.action_name}', event '{action_name}'", cap, None

        if cap.target != target:
            return False, f"HISTORICAL_VERIFICATION_FAILED_TARGET_MISMATCH: granted '{cap.target}', event '{target}'", cap, None

        if cap.canonical_request_digest != canonical_request_digest:
            return False, f"HISTORICAL_VERIFICATION_FAILED_DIGEST_MISMATCH: granted '{cap.canonical_request_digest}', event '{canonical_request_digest}'", cap, None

        if correlation_id is not None and cap.correlation_id != correlation_id:
            return False, f"HISTORICAL_VERIFICATION_FAILED_CORRELATION_ID_MISMATCH: granted '{cap.correlation_id}', event '{correlation_id}'", cap, None

        if request_id is not None and cap.request_id != request_id:
            return False, f"HISTORICAL_VERIFICATION_FAILED_REQUEST_ID_MISMATCH: granted '{cap.request_id}', event '{request_id}'", cap, None

        if task_id is not None and cap.task_id and cap.task_id != task_id:
            return False, f"HISTORICAL_VERIFICATION_FAILED_TASK_ID_MISMATCH: granted '{cap.task_id}', event '{task_id}'", cap, None

        if principal_id is not None and cap.principal_id != "agent_default" and cap.principal_id != principal_id:
            return False, f"HISTORICAL_VERIFICATION_FAILED_PRINCIPAL_MISMATCH: granted '{cap.principal_id}', event '{principal_id}'", cap, None

        # Authoritative executor binding check against capability
        if dispatched_executor_id is not None and getattr(cap, "executor_id", None):
            norm_disp = get_callable_identity(dispatched_executor_id)
            if norm_disp != cap.executor_id:
                return False, f"HISTORICAL_VERIFICATION_FAILED_EXECUTOR_MISMATCH: capability bound to '{cap.executor_id}', event claims '{norm_disp}'", cap, None

        # Retrieve execution record if attempt_id is provided
        exec_record = None
        if execution_attempt_id:
            exec_record = self.registry.get_execution_record(token_id, execution_attempt_id)
            if not exec_record:
                return False, f"HISTORICAL_VERIFICATION_FAILED_NO_DISPATCH_RECORD: execution attempt {execution_attempt_id} was never dispatched by trusted boundary", cap, None

            # Authoritative Executor Identity Verification:
            # Compare the executor identity recorded by TrustedExecutionBoundary against the signed capability
            rec_exec = exec_record.get("dispatched_executor_id")
            cap_exec = getattr(cap, "executor_id", None)
            if cap_exec and cap_exec != "default_executor":
                if not rec_exec:
                    return False, f"HISTORICAL_VERIFICATION_FAILED_EXECUTOR_MISSING: capability bound to '{cap_exec}', but dispatch record is missing dispatched_executor_id", cap, exec_record
                if cap_exec != rec_exec:
                    return False, f"HISTORICAL_VERIFICATION_FAILED_EXECUTOR_MISMATCH: capability bound to '{cap_exec}', dispatched to '{rec_exec}'", cap, exec_record
            elif cap_exec and rec_exec and cap_exec != rec_exec:
                return False, f"HISTORICAL_VERIFICATION_FAILED_EXECUTOR_MISMATCH: capability bound to '{cap_exec}', dispatched to '{rec_exec}'", cap, exec_record

            if dispatched_executor_id and rec_exec and rec_exec != dispatched_executor_id:
                return False, f"HISTORICAL_VERIFICATION_FAILED_EXECUTOR_MISMATCH: dispatched to '{rec_exec}', event claims '{dispatched_executor_id}'", cap, exec_record

            # Authoritative Principal and Task Attribution Verification:
            rec_meta = exec_record.get("details") or {}
            if not isinstance(rec_meta, dict):
                rec_meta = {}

            # Principal attribution verification:
            if cap.principal_id and cap.principal_id != "agent_default":
                rec_principal = rec_meta.get("principal_id")
                if not rec_principal:
                    return False, f"HISTORICAL_VERIFICATION_FAILED_PRINCIPAL_MISSING: capability bound to principal '{cap.principal_id}', but dispatch record is missing principal_id attribution", cap, exec_record
                if cap.principal_id != rec_principal:
                    return False, f"HISTORICAL_VERIFICATION_FAILED_PRINCIPAL_MISMATCH: capability bound to '{cap.principal_id}', dispatched for '{rec_principal}'", cap, exec_record

            # Task attribution verification:
            if cap.task_id:
                rec_task = rec_meta.get("task_id")
                if not rec_task:
                    return False, f"HISTORICAL_VERIFICATION_FAILED_TASK_ID_MISSING: capability bound to task_id '{cap.task_id}', but dispatch record is missing task_id attribution", cap, exec_record
                if cap.task_id != rec_task:
                    return False, f"HISTORICAL_VERIFICATION_FAILED_TASK_ID_MISMATCH: capability bound to '{cap.task_id}', dispatched for '{rec_task}'", cap, exec_record

            # Verify terminal outcome match against authoritative record
            if expected_outcome_status:
                rec_status = exec_record.get("outcome_status")
                if expected_outcome_status == "SUCCESS" and rec_status != "SUCCESS":
                    return False, f"HISTORICAL_VERIFICATION_FAILED_OUTCOME_CONTRADICTION: event claims SUCCESS, but authoritative boundary recorded '{rec_status}'", cap, exec_record
                elif expected_outcome_status in ("FAILED", "INTERRUPTED") and rec_status not in ("FAILED", "INTERRUPTED", "DISPATCHED"):
                    return False, f"HISTORICAL_VERIFICATION_FAILED_OUTCOME_MISMATCH: event claims '{expected_outcome_status}', but authoritative boundary recorded '{rec_status}'", cap, exec_record

        # Temporal validity verification (Revocation and Expiration at Execution Time)
        exec_time = execution_start_time
        if exec_time is None and exec_record:
            exec_time = exec_record.get("started_at")

        # 1. Expiration check at execution time
        if exec_time is not None and cap.expires_at is not None:
            if float(exec_time) > float(cap.expires_at):
                return False, f"HISTORICAL_VERIFICATION_FAILED_EXPIRED_BEFORE_EXECUTION: capability expired at {cap.expires_at}, execution started at {exec_time}", cap, exec_record

        # 2. Revocation ordering check
        rev_record = self.registry.get_revocation_record(token_id)
        if rev_record:
            # Check monotonic journal sequence ordering first if available
            rev_seq = rev_record.get("seq")
            dispatch_seq = exec_record.get("dispatch_seq") if exec_record else None
            if rev_seq is not None and dispatch_seq is not None:
                if rev_seq <= dispatch_seq:
                    return False, f"HISTORICAL_VERIFICATION_FAILED_REVOKED_BEFORE_DISPATCH: revocation seq {rev_seq} <= dispatch seq {dispatch_seq}", cap, exec_record
            elif exec_time is not None:
                rev_ts = float(rev_record.get("timestamp", 0.0))
                if rev_ts <= float(exec_time):
                    return False, f"HISTORICAL_VERIFICATION_FAILED_REVOKED_BEFORE_EXECUTION: revoked at {rev_ts} <= execution at {exec_time}", cap, exec_record

        return True, "HISTORICAL_CAPABILITY_VERIFIED", cap, exec_record
