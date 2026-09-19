import time
import pytest
import os
from epistemicos.audit import TamperEvidentAuditTrail, AuditEvent, AuditLogLevel

def test_last_hash_caching_under_load(tmp_path):
    log_file = str(tmp_path / "test_benchmark_audit.jsonl")
    audit_trail = TamperEvidentAuditTrail(log_file)

    event = AuditEvent(
        event_type=AuditLogLevel.INFO,
        gate_name="benchmark_gate",
        reason="load_test",
        model_id="benchmark_model",
        payload_snippet="A" * 100000, # Large payload snippet
        execution_latency_ms=10.0
    )

    # Pre-populate some events
    for _ in range(50):
        audit_trail.record_event(event)

    audit_trail_reader = TamperEvidentAuditTrail(log_file)

    start = time.time()
    for _ in range(200):
        # We need to simulate the bug. The bug happens if _get_last_hash is called and doesn't find the hash in memory.
        # BUT the code ALREADY has:
        # if getattr(self, "last_hash", None) is not None:
        #     return self.last_hash
        # And when `record_event` is called, it does:
        # self.last_hash = entry_hash

        # Test tail reading logic to ensure it doesn't fail under heavy load/large payloads
        # Unsetting last_hash simulates reading the tail each time
        audit_trail_reader.last_hash = None
        hash_val = audit_trail_reader._get_last_hash()
        assert hash_val != audit_trail_reader.genesis_hash
        assert audit_trail_reader.last_hash == hash_val

    elapsed = time.time() - start
    assert elapsed < 5.0, f"Tail read too slow: {elapsed}s"
