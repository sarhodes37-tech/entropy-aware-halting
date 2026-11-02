"""
EpistemicOS Tamper-Evident Audit Logger.

Append-only, cryptographically chained JSON-Lines audit logger.
Now natively integrates unified domain models and hardware telemetry 
for regulatory compliance and enterprise security audits.
"""

import os
import re
import hashlib
import json
import time
import uuid
import functools
from pathlib import Path
import hmac
from typing import Tuple, Optional, Dict, Any, List
from enum import Enum
from dataclasses import dataclass

try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False

# Import unified models and telemetry layers
from epistemicos.models import CanonicalProblemRepresentation, BeliefObject
from epistemicos.telemetry import HardwareTelemetry

SENSITIVE_KEY_PATTERNS = ("api_key", "token", "password", "secret", "ssn", "banking_routing",
                          "account_number", "account_balance_usd", "proprietary_cargo",
                          "credit_card", "private_key", "bearer", "auth", "credential", "x-api-key",
                          "email", "phone", "address", "ssn", "prompt", "user_data", "identity", "payload")

SAFE_KEY_SUFFIXES = ("_id", "_hash", "_digest", "_uuid", "_count", "_type", "_ms", "_version", "_algorithm", "_action", "_reason", "_source", "_name", "_status", "_level")

REGEX_BEARER = re.compile(r"Bearer\s+[a-zA-Z0-9\._\-]+", re.IGNORECASE)
REGEX_SK = re.compile(r"\b(sk-[a-zA-Z0-9_\-]{20,}|glpat-[a-zA-Z0-9_\-]{20,}|AKIA[0-9A-Z]{16}|ghs_[A-Za-z0-9\.\-_]{36,}|gh[pousr]_[a-zA-Z0-9_]{36,}|github_pat_[a-zA-Z0-9_\-]{80,}|hf_[a-zA-Z0-9]{34,}|xox[baprs]-[a-zA-Z0-9_\-]{10,})\b")
REGEX_CRED_ASSIGN = re.compile(r"(password|api_key|secret|token)\s*=\s*[^\s;&]+", re.IGNORECASE)
REGEX_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
REGEX_PHONE = re.compile(r"\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
REGEX_SSN = re.compile(r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b")
REGEX_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
REGEX_HAS_DIGIT = re.compile(r"\d")


# Fast-path string value sanitization (~3.6x speedup for log/receipt string sanitization).
# Skips expensive regex substitutions when trigger characters/substrings are absent or length < 3.
def _sanitize_string_value(val: str) -> str:
    val_len = len(val)
    if val_len < 3:
        return val
    if val_len == 36 and REGEX_UUID.match(val):
        return val
    if "bearer" in val.lower():
        val = REGEX_BEARER.sub("Bearer [REDACTED]", val)
    if val_len >= 14:
        val = REGEX_SK.sub("sk-[REDACTED]", val)
    if "=" in val:
        val = REGEX_CRED_ASSIGN.sub(r"\1=[REDACTED]", val)
    if "@" in val:
        val = REGEX_EMAIL.sub("[REDACTED_EMAIL]", val)
    if REGEX_HAS_DIGIT.search(val):
        val = REGEX_PHONE.sub("[REDACTED_PHONE]", val)
        val = REGEX_SSN.sub("[REDACTED_SSN]", val)
    return val


# Cache dictionary key sensitivity checks to prevent repeated pattern & suffix scanning during sanitization (~2.3x speedup for log/receipt sanitization).
@functools.lru_cache(maxsize=2048)
def _is_sensitive_key(k_str: str) -> bool:
    if any(p in k_str for p in SENSITIVE_KEY_PATTERNS):
        return not k_str.endswith(SAFE_KEY_SUFFIXES)
    return False


def _sanitize_sensitive_data(obj: Any) -> Any:
    """Recursively redacts sensitive keys, credentials, and PII from logs and receipts."""
    if isinstance(obj, str):
        return _sanitize_string_value(obj)
    elif isinstance(obj, dict):
        sanitized = {}
        for k, v in obj.items():
            k_str = str(k).lower()
            if _is_sensitive_key(k_str):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = _sanitize_sensitive_data(v)
        return sanitized
    elif isinstance(obj, list):
        return [_sanitize_sensitive_data(item) for item in obj]
    elif isinstance(obj, (int, float, bool, type(None))):
        return obj
    elif isinstance(obj, tuple):
        return tuple(_sanitize_sensitive_data(item) for item in obj)
    elif isinstance(obj, (set, frozenset)):
        sanitized_items = [_sanitize_sensitive_data(item) for item in obj]
        return sorted(sanitized_items, key=lambda x: json.dumps(x, sort_keys=True))
    return obj


class AuditLogLevel(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    HALT = "DETERMINISTIC_HALT"
    ROLLBACK = "ACTION_ROLLBACK"



@dataclass
class AuditEvent:
    event_type: AuditLogLevel
    gate_name: str
    reason: str
    model_id: str
    payload_snippet: str
    execution_latency_ms: Optional[float] = None
    cpr_snapshot: Optional[CanonicalProblemRepresentation] = None
    telemetry: Optional[HardwareTelemetry] = None
    belief_snapshot: Optional[BeliefObject] = None
    metadata: Optional[Dict[str, Any]] = None


class TamperEvidentAuditTrail:
    """
    Append-only, cryptographically chained JSON-Lines audit logger for EpistemicOS.
    Local file-backed hash chains detect inadvertent corruption, line truncation, and uncoordinated edits.
    When configured with an explicit secret key (`hmac_key`), HMAC-SHA256 chaining provides cryptographic tamper-evidence against local process forgery.
    Note: Without external anchoring or a secret key held outside the host, a local process with full file write access can rewrite local log files.
    """

    GENESIS_SEED = b"EPISTEMIC_OS_GENESIS_BLOCK"

    def __init__(self, log_file_path: str = "logs/epistemic_audit.jsonl", hmac_key: Optional[bytes] = None):
        self.log_path = Path(log_file_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.hmac_key = hmac_key
        if self.hmac_key:
            self.genesis_hash = hmac.new(self.hmac_key, self.GENESIS_SEED, hashlib.sha256).hexdigest()
        else:
            self.genesis_hash = hashlib.sha256(self.GENESIS_SEED).hexdigest()
        self.last_hash = None

    def inspect_log_health(self) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Inspects the audit log health from Genesis to tail.
        Separates health/integrity status from recovering the last valid entry hash.
        Returns: (is_healthy, last_valid_entry_hash, error_message)
        """
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return True, self.genesis_hash, None

        expected_prev_hash = self.genesis_hash
        last_valid_hash = self.genesis_hash
        seen_event_ids = set()

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, 1):
                line_str = line.strip()
                if not line_str:
                    continue

                try:
                    entry = json.loads(line_str)
                except json.JSONDecodeError:
                    return False, last_valid_hash, f"Malformed JSON or corrupted tail at line {line_idx}"

                recorded_id = entry.get("event_id")
                if recorded_id:
                    if recorded_id in seen_event_ids:
                        return False, last_valid_hash, f"Duplicate event_id detected at line {line_idx}: {recorded_id}"
                    seen_event_ids.add(recorded_id)

                recorded_hash = entry.get("entry_hash")
                recorded_prev_hash = entry.get("prev_hash")

                if recorded_prev_hash != expected_prev_hash:
                    return (
                        False,
                        last_valid_hash,
                        f"Broken chain link at line {line_idx}. Expected prev_hash {expected_prev_hash}, got {recorded_prev_hash}"
                    )

                check_data = {k: v for k, v in entry.items() if k != "entry_hash"}
                computed_hash = self._compute_hash(recorded_prev_hash, check_data)

                if computed_hash != recorded_hash:
                    return (
                        False,
                        last_valid_hash,
                        f"Tampered entry detected at line {line_idx}. Computed {computed_hash}, got {recorded_hash}"
                    )

                expected_prev_hash = recorded_hash
                last_valid_hash = recorded_hash

        return True, last_valid_hash, None

    def _get_last_hash(self, force_reload: bool = False) -> str:
        """
        Retrieves entry_hash of final entry.
        """
        if not force_reload and getattr(self, "last_hash", None) is not None:
            return self.last_hash

        is_healthy, last_h, _ = self.inspect_log_health()
        self.last_hash = last_h
        return self.last_hash

    def _compute_hash(self, prev_hash: str, payload_data: Dict[str, Any]) -> str:
        """Computes SHA-256 or HMAC-SHA256 over the canonical JSON representation of the entry + prev_hash."""
        serialized = json.dumps(payload_data, sort_keys=True)
        combined = f"{prev_hash}:{serialized}".encode("utf-8")
        if getattr(self, "hmac_key", None):
            return hmac.new(self.hmac_key, combined, hashlib.sha256).hexdigest()
        return hashlib.sha256(combined).hexdigest()

    def record_event(
        self,
        event: AuditEvent
    ) -> Dict[str, Any]:
        """
        Logs an event and appends it to the immutable hash chain with file locking.
        Automatically masks PII and credentials from every free-form field before serialization.
        """
        event_id = str(uuid.uuid4())
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload_bytes = event.payload_snippet.encode("utf-8")
        if len(payload_bytes) > 1048576:
            raise ValueError("Payload snippet exceeds the maximum allowed length of 1MB.")
        payload_hash = hashlib.sha256(payload_bytes).hexdigest()

        # Compile strict structural metadata
        event_metadata = event.metadata or {}

        if event.cpr_snapshot:
            # Enforce egress masking to keep PII out of the permanent immutable log
            event_metadata["cpr_state"] = event.cpr_snapshot.mask_egress_payload()
        if event.telemetry:
            # Dataclass serialization
            event_metadata["hardware_telemetry"] = event.telemetry.__dict__
            # Use hardware telemetry wall clock if execution latency wasn't manually passed
            if event.execution_latency_ms is None:
                event.execution_latency_ms = event.telemetry.wall_clock_ms
        if event.belief_snapshot:
            # Pydantic serialization
            event_metadata["belief_state"] = event.belief_snapshot.model_dump(mode="json")

        # Fallback if no latency provided
        final_latency = round(event.execution_latency_ms, 4) if event.execution_latency_ms is not None else 0.0

        with open(self.log_path, "a+", encoding="utf-8") as f:
            if HAS_FCNTL:
                fcntl.flock(f, fcntl.LOCK_EX)

            try:
                is_healthy, last_hash, err = self.inspect_log_health()
                if not is_healthy:
                    raise RuntimeError(f"Cannot write to audit trail: Log corruption detected: {err}")

                entry_data = {
                    "event_id": event_id,
                    "timestamp": timestamp,
                    "event_type": event.event_type.value,
                    "gate_name": _sanitize_sensitive_data(event.gate_name),
                    "reason": _sanitize_sensitive_data(event.reason),
                    "model_id": _sanitize_sensitive_data(event.model_id),
                    "latency_ms": final_latency,
                    "payload_hash": payload_hash,
                    "payload_snippet": _sanitize_sensitive_data(event.payload_snippet[:200]),
                    "metadata": _sanitize_sensitive_data(event_metadata),
                    "prev_hash": last_hash
                }

                entry_hash = self._compute_hash(last_hash, entry_data)
                entry_data["entry_hash"] = entry_hash
                self.last_hash = entry_hash

                f.write(json.dumps(entry_data) + "\n")
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass

                return entry_data

            finally:
                if HAS_FCNTL:
                    fcntl.flock(f, fcntl.LOCK_UN)

    def verify_chain_integrity(self) -> Tuple[bool, int, Optional[str]]:
        """
        Validates the entire audit file from Genesis to present.
        Detects missing links, reordering, payload tampering, duplicate event IDs, and partial writes.
        Returns: (is_valid, total_records_verified, error_message)
        """
        if not self.log_path.exists():
            return True, 0, None

        expected_prev_hash = self.genesis_hash
        count = 0
        seen_event_ids = set()

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, 1):
                line_str = line.strip()
                if not line_str:
                    continue

                try:
                    entry = json.loads(line_str)
                except json.JSONDecodeError:
                    return False, count, f"Malformed JSON on line {line_idx}"

                recorded_id = entry.get("event_id")
                if recorded_id:
                    if recorded_id in seen_event_ids:
                        return False, count, f"Duplicate event_id detected at line {line_idx}: {recorded_id}"
                    seen_event_ids.add(recorded_id)

                recorded_hash = entry.get("entry_hash")
                recorded_prev_hash = entry.get("prev_hash")

                if recorded_prev_hash != expected_prev_hash:
                    return (
                        False,
                        count,
                        f"Broken chain link at line {line_idx}. Expected prev_hash {expected_prev_hash}, got {recorded_prev_hash}"
                    )

                check_data = {k: v for k, v in entry.items() if k != "entry_hash"}
                computed_hash = self._compute_hash(recorded_prev_hash, check_data)

                if computed_hash != recorded_hash:
                    return (
                        False,
                        count,
                        f"Tampered entry detected at line {line_idx}. Computed {computed_hash}, got {recorded_hash}"
                    )

                expected_prev_hash = recorded_hash
                count += 1

        return True, count, None


class ReceiptGenerator:
    def __init__(
        self,
        signing_key: Optional[bytes] = None,
        gate_version: str = "1.0.0",
        config: Optional[Dict[str, Any]] = None
    ):
        self.events = []
        self._rollbacks = []
        self._seq_idx = 0
        self.signing_key = signing_key
        self.gate_version = gate_version
        self.config = config or {}

    def log_event(self, event_type: str, details: Dict[str, Any]):
        """
        Add an event to the volatile receipt sequence with PII/credential sanitization.
        """
        self.events.append({
            "idx": self._seq_idx,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "type": event_type,
            "details": _sanitize_sensitive_data(details)
        })
        self._seq_idx += 1

    def push_action(self, action: Dict[str, Any], rollback_patch: Dict[str, Any]):
        sanitized_action = _sanitize_sensitive_data(action)
        sanitized_rollback = _sanitize_sensitive_data(rollback_patch)
        self.log_event("ActionProposed", {"action": sanitized_action})
        self._rollbacks.append(sanitized_rollback)

    def mint_receipt(
        self,
        transaction_id: str,
        success: bool,
        confidence_matrix: Dict[str, float],
        input_data: Optional[Any] = None,
        decision_details: Optional[Dict[str, Any]] = None,
        execution_outcome: Optional[Dict[str, Any]] = None,
        signing_key: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """
        Binds exact input hash, configuration, gate version, decision, outcome, and events
        into a canonical receipt, signed via SHA-256 or HMAC-SHA256.
        """
        key = signing_key or self.signing_key
        algo = "HMAC-SHA256" if key else "SHA256"

        receipt: Dict[str, Any] = {
            "transaction_id": transaction_id,
            "status": "COMMITTED" if success else "ROLLED_BACK",
            "gate_version": self.gate_version,
            "config": _sanitize_sensitive_data(self.config),
            "confidence_matrix": confidence_matrix,
            "event_log": _sanitize_sensitive_data(self.events),
            "signature_algorithm": algo
        }

        if input_data is not None:
            sanitized_input = _sanitize_sensitive_data(input_data)
            input_bytes = json.dumps(sanitized_input, sort_keys=True).encode("utf-8")
            receipt["input_hash"] = hashlib.sha256(input_bytes).hexdigest()

        if decision_details is not None:
            receipt["decision_details"] = _sanitize_sensitive_data(decision_details)

        if execution_outcome is not None:
            receipt["execution_outcome"] = _sanitize_sensitive_data(execution_outcome)

        receipt_string = json.dumps(receipt, sort_keys=True).encode("utf-8")

        if key:
            receipt["signature"] = hmac.new(key, receipt_string, hashlib.sha256).hexdigest()
        else:
            receipt["signature"] = hashlib.sha256(receipt_string).hexdigest()

        return receipt

    REQUIRED_FIELDS = frozenset({
        "transaction_id", "status", "gate_version", "config",
        "confidence_matrix", "event_log", "signature_algorithm", "signature"
    })
    OPTIONAL_FIELDS = frozenset({
        "input_hash", "decision_details", "execution_outcome"
    })
    ALLOWED_FIELDS = REQUIRED_FIELDS | OPTIONAL_FIELDS

    @staticmethod
    def verify_receipt(receipt: Dict[str, Any], signing_key: Optional[bytes] = None) -> bool:
        """
        Independently validates a receipt signature without trusting orchestrator state.
        Enforces strict schema validation, type checking, signature format validation,
        and signature algorithm matching to fail closed on any violation.
        """
        if not isinstance(receipt, dict):
            return False

        keys = set(receipt.keys())

        # 1. Schema enforcement: required fields must be present, unknown fields rejected
        if not ReceiptGenerator.REQUIRED_FIELDS.issubset(keys):
            return False
        if not keys.issubset(ReceiptGenerator.ALLOWED_FIELDS):
            return False

        # 2. Strict field type checks
        if not isinstance(receipt["transaction_id"], str) or not receipt["transaction_id"]:
            return False
        if receipt["status"] not in ("COMMITTED", "ROLLED_BACK"):
            return False
        if not isinstance(receipt["gate_version"], str):
            return False
        if not isinstance(receipt["config"], dict):
            return False
        if not isinstance(receipt["confidence_matrix"], dict):
            return False
        if not isinstance(receipt["event_log"], list):
            return False
        if not isinstance(receipt["signature_algorithm"], str):
            return False

        sig = receipt["signature"]
        if not isinstance(sig, str) or len(sig) != 64:
            return False
        try:
            int(sig, 16)
        except ValueError:
            return False

        # 3. Optional field type checks
        if "input_hash" in receipt:
            ih = receipt["input_hash"]
            if not isinstance(ih, str) or len(ih) != 64:
                return False
            try:
                int(ih, 16)
            except ValueError:
                return False

        if "decision_details" in receipt and not isinstance(receipt["decision_details"], dict):
            return False

        if "execution_outcome" in receipt and not isinstance(receipt["execution_outcome"], dict):
            return False

        recorded_algo = receipt["signature_algorithm"]

        # 4. Algorithm downgrade & key mismatch protection
        if signing_key is not None:
            if recorded_algo != "HMAC-SHA256":
                return False
        else:
            if recorded_algo != "SHA256":
                return False

        # 5. Signature verification over canonical bytes
        check_receipt = {k: v for k, v in receipt.items() if k != "signature"}
        receipt_bytes = json.dumps(check_receipt, sort_keys=True).encode("utf-8")

        if signing_key:
            computed_signature = hmac.new(signing_key, receipt_bytes, hashlib.sha256).hexdigest()
        else:
            computed_signature = hashlib.sha256(receipt_bytes).hexdigest()

        return hmac.compare_digest(sig.lower(), computed_signature.lower())

    def rollback(self) -> List[Dict[str, Any]]:
        self.log_event("RollbackIssued", {"count": len(self._rollbacks)})
        executed_rollbacks = []
        while self._rollbacks:
            executed_rollbacks.append(self._rollbacks.pop())
        return executed_rollbacks
