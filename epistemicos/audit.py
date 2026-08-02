"""
EpistemicOS Tamper-Evident Audit Logger.

Append-only, cryptographically chained JSON-Lines audit logger.
Now natively integrates unified domain models and hardware telemetry 
for regulatory compliance and enterprise security audits.
"""

import os
import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Tuple, Optional, Dict, Any
from enum import Enum

try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False

# Import unified models and telemetry layers
from epistemicos.models import CanonicalProblemRepresentation, BeliefObject
from epistemicos.telemetry import HardwareTelemetry


class AuditLogLevel(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    HALT = "DETERMINISTIC_HALT"
    ROLLBACK = "ACTION_ROLLBACK"


class TamperEvidentAuditTrail:
    """
    Append-only, cryptographically chained JSON-Lines audit logger for EpistemicOS.
    Ensures tamper-evident records for regulatory compliance and enterprise security audits.
    """

    GENESIS_SEED = b"EPISTEMIC_OS_GENESIS_BLOCK"

    def __init__(self, log_file_path: str = "logs/epistemic_audit.jsonl"):
        self.log_path = Path(log_file_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.genesis_hash = hashlib.sha256(self.GENESIS_SEED).hexdigest()

    def _get_last_hash(self) -> str:
        """
        Efficiently retrieves the entry_hash of the final line without loading 
        the entire log file into memory (O(1) tail read).
        """
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return self.genesis_hash

        try:
            with open(self.log_path, "rb") as f:
                f.seek(0, os.SEEK_END)
                pointer = f.tell()
                buffer_size = 1024
                lines = []

                while pointer > 0 and len(lines) < 2:
                    read_size = min(buffer_size, pointer)
                    pointer -= read_size
                    f.seek(pointer)
                    chunk = f.read(read_size)
                    lines = chunk.split(b"\n")

                for line in reversed(lines):
                    line_str = line.strip().decode("utf-8")
                    if line_str:
                        last_entry = json.loads(line_str)
                        return last_entry.get("entry_hash", self.genesis_hash)
        except Exception:
            pass

        return self.genesis_hash

    def _compute_hash(self, prev_hash: str, payload_data: Dict[str, Any]) -> str:
        """Computes SHA-256 over the canonical JSON representation of the entry + prev_hash."""
        serialized = json.dumps(payload_data, sort_keys=True)
        combined = f"{prev_hash}:{serialized}".encode("utf-8")
        return hashlib.sha256(combined).hexdigest()

    def record_event(
        self,
        event_type: AuditLogLevel,
        gate_name: str,
        reason: str,
        model_id: str,
        payload_snippet: str,
        execution_latency_ms: Optional[float] = None,
        cpr_snapshot: Optional[CanonicalProblemRepresentation] = None,
        telemetry: Optional[HardwareTelemetry] = None,
        belief_snapshot: Optional[BeliefObject] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Logs an event and appends it to the immutable hash chain with file locking.
        Automatically masks PII from CPR before serialization.
        """
        event_id = str(uuid.uuid4())
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload_hash = hashlib.sha256(payload_snippet.encode("utf-8")).hexdigest()

        # Compile strict structural metadata
        event_metadata = metadata or {}
        
        if cpr_snapshot:
            # Enforce egress masking to keep PII out of the permanent immutable log
            event_metadata["cpr_state"] = cpr_snapshot.mask_egress_payload()
        if telemetry:
            # Dataclass serialization
            event_metadata["hardware_telemetry"] = telemetry.__dict__
            # Use hardware telemetry wall clock if execution latency wasn't manually passed
            if execution_latency_ms is None:
                execution_latency_ms = telemetry.wall_clock_ms
        if belief_snapshot:
            # Pydantic serialization
            event_metadata["belief_state"] = belief_snapshot.model_dump()

        # Fallback if no latency provided
        final_latency = round(execution_latency_ms, 4) if execution_latency_ms is not None else 0.0

        with open(self.log_path, "a+", encoding="utf-8") as f:
            if HAS_FCNTL:
                fcntl.flock(f, fcntl.LOCK_EX)

            try:
                last_hash = self._get_last_hash()

                entry_data = {
                    "event_id": event_id,
                    "timestamp": timestamp,
                    "event_type": event_type.value,
                    "gate_name": gate_name,
                    "reason": reason,
                    "model_id": model_id,
                    "latency_ms": final_latency,
                    "payload_hash": payload_hash,
                    "payload_snippet": payload_snippet[:200],
                    "metadata": event_metadata,
                    "prev_hash": last_hash
                }

                entry_hash = self._compute_hash(last_hash, entry_data)
                entry_data["entry_hash"] = entry_hash

                f.write(json.dumps(entry_data) + "\n")
                f.flush()

                return entry_data

            finally:
                if HAS_FCNTL:
                    fcntl.flock(f, fcntl.LOCK_UN)

    def verify_chain_integrity(self) -> Tuple[bool, int, Optional[str]]:
        """
        Validates the entire audit file from Genesis to present.
        Returns: (is_valid, total_records_verified, error_message)
        """
        if not self.log_path.exists():
            return True, 0, None

        expected_prev_hash = self.genesis_hash
        count = 0

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, 1):
                line_str = line.strip()
                if not line_str:
                    continue

                try:
                    entry = json.loads(line_str)
                except json.JSONDecodeError:
                    return False, count, f"Malformed JSON on line {line_idx}"

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
