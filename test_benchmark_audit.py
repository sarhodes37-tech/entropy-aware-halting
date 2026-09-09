import time
import os
import uuid
import hashlib
from epistemicos.audit import TamperEvidentAuditTrail, AuditEvent, AuditLogLevel

def benchmark_record_event():
    log_path = "logs/benchmark_audit_heavy.jsonl"
    if os.path.exists(log_path):
        os.remove(log_path)

    audit_trail = TamperEvidentAuditTrail(log_path)

    event = AuditEvent(
        event_type=AuditLogLevel.INFO,
        gate_name="TestGate",
        reason="Testing",
        model_id="test_model",
        payload_snippet="A" * 100000, # Large payload snippet
        execution_latency_ms=10.0
    )

    # Pre-populate some events
    for _ in range(50):
        audit_trail.record_event(event)

    start = time.time()
    for _ in range(200):
        # We need to simulate the bug. The bug happens if _get_last_hash is called and doesn't find the hash in memory.
        # Wait, the instruction says:
        # "In _get_last_hash, the loop reads file chunks backwards to find the last line. If _get_last_hash is called continuously under heavy load by record_event, it opens and scans the file repeatedly. We should maintain self.last_hash in memory after initialization or the first read."
        # BUT the code ALREADY has:
        # if getattr(self, "last_hash", None) is not None:
        #     return self.last_hash
        # And when `record_event` is called, it does:
        # self.last_hash = entry_hash
        # So `last_hash` IS maintained in memory?

        # Let's read the code carefully.
        # Yes, `record_event` sets `self.last_hash = entry_hash` on success.
        # However, what if `_get_last_hash()` is called and fails to decode the line?
        # Then it swallows the exception and falls back to:
        # self.last_hash = self.genesis_hash
        # return self.last_hash
        pass

benchmark_record_event()
