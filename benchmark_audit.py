import time
import os
from epistemicos.audit import TamperEvidentAuditTrail, AuditEvent, AuditLogLevel
from epistemicos.models import BeliefObject
from epistemicos.telemetry import HardwareTelemetry

def benchmark_record_event():
    log_path = "logs/benchmark_audit.jsonl"
    if os.path.exists(log_path):
        os.remove(log_path)

    audit_trail = TamperEvidentAuditTrail(log_path)

    # Pre-populate with some events to simulate an existing log file
    event = AuditEvent(
        event_type=AuditLogLevel.INFO,
        gate_name="TestGate",
        reason="Testing",
        model_id="test_model",
        payload_snippet="test payload",
        execution_latency_ms=10.0
    )

    for _ in range(1000):
        audit_trail.record_event(event)

    # Force the last_hash to None to simulate multiple instances or script restarts
    # The actual bug is that `last_hash` is maintained in memory per instance, but `_get_last_hash`
    # re-reads the file from disk if it was modified, though `record_event` actually uses
    # `with open(self.log_path, "a+", encoding="utf-8") as f:`.
    # Wait, the issue says:
    # "In `_get_last_hash`, the loop reads file chunks backwards to find the last line. If `_get_last_hash` is called continuously under heavy load by `record_event`, it opens and scans the file repeatedly. We should maintain `self.last_hash` in memory after initialization or the first read."

    # Wait, `last_hash` IS maintained in memory:
    # if getattr(self, "last_hash", None) is not None:
    #     return self.last_hash
    # But wait! Look at the current code for `_get_last_hash`:
    # It has this block! So why is it re-reading?

    # Let me check if there's a memory entry about this.
    # "To optimize audit logging performance in epistemicos/audit.py, TamperEvidentAuditTrail caches self.last_hash in memory, which prevents redundant backward file reads in _get_last_hash during repeated record_event calls."
    # Let me re-read `_get_last_hash` in `epistemicos/audit.py`.
