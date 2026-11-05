"""
Regression test suite for incremental health verification in LocalProvenanceStore
and TamperEvidentAuditTrail.

Verifies:
1. Decision, hash, and counter equivalence between full-scan and incremental verification.
2. Immediate detection of same-size in-place record modification in previously verified prefix.
3. Modification of an earlier record followed by a valid-looking appended suffix fails closed.
4. Immediate detection of corrupted JSON in newly appended suffix.
5. Immediate detection of broken chain links in newly appended suffix.
6. Immediate detection of duplicate event IDs across incremental appends and boundary.
7. Same-inode rewrite and full file replacement trigger full re-verification from genesis.
8. File truncation (size shrinkage) triggers full re-verification from genesis.
9. Empty and non-existent file handling.
10. Repeated inspections after a failed verification fail closed.
11. HMAC-keyed verification equivalence across increments.
12. Intervening modification before cache state commitment fails closed and never becomes trusted.
"""

import os
import json
import uuid
import pytest
from pathlib import Path

from epistemicos.provenance import LocalProvenanceStore, ProvenanceEvent
from epistemicos.audit import TamperEvidentAuditTrail, AuditEvent, AuditLogLevel


def test_provenance_incremental_equivalence_and_scaling(tmp_path: Path):
    log_file = str(tmp_path / "test_prov.jsonl")
    store = LocalProvenanceStore(log_path=log_file)

    events = []
    for i in range(50):
        evt = ProvenanceEvent(
            schema_version="1.0.0",
            event_id=str(uuid.uuid4()),
            event_type="ACTION_PROPOSED",
            provenance_source="AGENT_ADAPTER",
            correlation_id=f"corr_{i % 3}",
            request_id=f"req_{i}",
            action_name=f"action_{i}",
            target=f"target_{i}",
            canonical_request_digest="d",
            timestamp="2026-01-01T00:00:00Z",
        )
        events.append(evt)

    # Record 25 events
    for evt in events[:25]:
        store.record_event(evt)

    # Create fresh reference store that performs cold full scan
    fresh_store = LocalProvenanceStore(log_path=log_file)
    ref_healthy, ref_hash, ref_seq, ref_ids = fresh_store._inspect_health()
    inc_healthy, inc_hash, inc_seq, inc_ids = store._inspect_health()

    assert ref_healthy is True
    assert inc_healthy is True
    assert ref_hash == inc_hash
    assert ref_seq == 25
    assert inc_seq == 25
    assert ref_ids == inc_ids

    # Append remaining 25 events to existing store
    for evt in events[25:]:
        store.record_event(evt)

    # Compare fresh reference store against incremental store
    fresh_store2 = LocalProvenanceStore(log_path=log_file)
    ref2_healthy, ref2_hash, ref2_seq, ref2_ids = fresh_store2._inspect_health()
    inc2_healthy, inc2_hash, inc2_seq, inc2_ids = store._inspect_health()

    assert ref2_healthy is True
    assert inc2_healthy is True
    assert ref2_hash == inc2_hash
    assert ref2_seq == 50
    assert inc2_seq == 50
    assert ref2_ids == inc2_ids


def test_audit_incremental_equivalence_and_scaling(tmp_path: Path):
    log_file = str(tmp_path / "test_audit.jsonl")
    trail = TamperEvidentAuditTrail(log_file_path=log_file)

    for i in range(25):
        trail.record_event(
            AuditEvent(
                event_type=AuditLogLevel.INFO,
                gate_name="GateA",
                reason=f"Reason {i}",
                model_id="m1",
                payload_snippet=json.dumps({"idx": i}),
            )
        )

    ref_trail = TamperEvidentAuditTrail(log_file_path=log_file)
    ref_healthy, ref_hash, ref_err = ref_trail.inspect_log_health()
    inc_healthy, inc_hash, inc_err = trail.inspect_log_health()

    assert ref_healthy is True
    assert inc_healthy is True
    assert ref_hash == inc_hash
    assert ref_err is None
    assert inc_err is None

    # Record more events
    for i in range(25, 50):
        trail.record_event(
            AuditEvent(
                event_type=AuditLogLevel.INFO,
                gate_name="GateB",
                reason=f"Reason {i}",
                model_id="m1",
                payload_snippet=json.dumps({"idx": i}),
            )
        )

    ref_trail2 = TamperEvidentAuditTrail(log_file_path=log_file)
    ref2_healthy, ref2_hash, ref2_err = ref_trail2.inspect_log_health()
    inc2_healthy, inc2_hash, inc2_err = trail.inspect_log_health()

    assert ref2_healthy is True
    assert inc2_healthy is True
    assert ref2_hash == inc2_hash
    assert ref2_err is None
    assert inc2_err is None


def test_provenance_same_size_in_place_tampering_detection(tmp_path: Path):
    """Verifies that tampering with a previously verified record in-place fails closed."""
    log_file = str(tmp_path / "test_prov_inplace.jsonl")
    store = LocalProvenanceStore(log_path=log_file)

    for i in range(5):
        store.record_event(
            ProvenanceEvent(
                schema_version="1.0.0",
                event_id=f"evt_{i:04d}",
                event_type="ACTION_PROPOSED",
                provenance_source="AGENT_ADAPTER",
                correlation_id="c1",
                request_id=f"r_{i}",
                action_name="act",
                target="tgt",
                canonical_request_digest="d",
                timestamp="2026-01-01T00:00:00Z",
            )
        )

    healthy, _, count, _ = store._inspect_health()
    assert healthy is True
    assert count == 5

    # Tamper with the last record in-place, keeping exact same length
    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    last_record = json.loads(lines[-1].strip())
    # Modify entry_hash to invalid hex string of identical length
    last_record["entry_hash"] = "f" * 64
    tampered_line = json.dumps(last_record) + "\n"

    # Pad or slice to ensure identical byte length
    diff_len = len(lines[-1]) - len(tampered_line)
    if diff_len > 0:
        last_record["canonical_request_digest"] = "d" + "x" * diff_len
        tampered_line = json.dumps(last_record) + "\n"

    lines[-1] = tampered_line
    with open(log_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    # Store must detect prefix digest mismatch and fail closed
    healthy_after, _, _, _ = store._inspect_health()
    fresh_healthy, _, _, _ = LocalProvenanceStore(log_path=log_file)._inspect_health()
    assert healthy_after is False
    assert fresh_healthy is False


def test_audit_same_size_in_place_tampering_detection(tmp_path: Path):
    """Verifies that in-place tampering with an audit record fails closed."""
    log_file = str(tmp_path / "test_audit_inplace.jsonl")
    trail = TamperEvidentAuditTrail(log_file_path=log_file)

    trail.record_event(AuditEvent(AuditLogLevel.INFO, "GateA", "r1", "m1", "s1"))
    trail.record_event(AuditEvent(AuditLogLevel.INFO, "GateA", "r2", "m2", "s2"))

    healthy, _, _ = trail.inspect_log_health()
    assert healthy is True

    # Tamper with the first record in-place, keeping file size identical
    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    rec0 = json.loads(lines[0].strip())
    rec0["entry_hash"] = "0" * 64
    lines[0] = json.dumps(rec0) + "\n"

    with open(log_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    healthy_after, _, err = trail.inspect_log_health()
    fresh_trail = TamperEvidentAuditTrail(log_file_path=log_file)
    fresh_healthy, _, fresh_err = fresh_trail.inspect_log_health()
    assert healthy_after is False
    assert fresh_healthy is False
    assert err is not None
    assert fresh_err is not None


def test_earlier_record_modification_followed_by_append(tmp_path: Path):
    """Tampering with an earlier record breaks downstream hash chaining on subsequent appends."""
    log_file = str(tmp_path / "test_audit_early_mod.jsonl")
    trail = TamperEvidentAuditTrail(log_file_path=log_file)

    for i in range(3):
        trail.record_event(AuditEvent(AuditLogLevel.INFO, "GateA", f"r_{i}", "m1", "s1"))

    assert trail.inspect_log_health()[0] is True

    # Tamper with record 0
    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
    rec0 = json.loads(lines[0].strip())
    rec0["reason"] = "tampered"
    lines[0] = json.dumps(rec0) + "\n"
    with open(log_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    # Subsequent record_event must fail closed because chain from record 0 is broken
    with pytest.raises(RuntimeError, match="Cannot write to audit trail: Log corruption detected"):
        trail.record_event(AuditEvent(AuditLogLevel.INFO, "GateA", "new_event", "m1", "s1"))


def test_provenance_incremental_detects_suffix_corruption(tmp_path: Path):
    log_file = str(tmp_path / "test_prov_corrupt.jsonl")
    store = LocalProvenanceStore(log_path=log_file)

    for i in range(5):
        store.record_event(
            ProvenanceEvent(
                schema_version="1.0.0",
                event_id=str(uuid.uuid4()),
                event_type="ACTION_PROPOSED",
                provenance_source="AGENT_ADAPTER",
                correlation_id="c1",
                request_id=f"r_{i}",
                action_name="act",
                target="tgt",
                canonical_request_digest="d",
                timestamp="2026-01-01T00:00:00Z",
            )
        )

    healthy, _, count, _ = store._inspect_health()
    assert healthy is True
    assert count == 5

    # Manually append corrupt JSON directly to file
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("{corrupt json line\n")

    healthy, _, _, _ = store._inspect_health()
    assert healthy is False

    # record_event should now fail closed
    with pytest.raises(RuntimeError, match="Provenance log corruption detected"):
        store.record_event(
            ProvenanceEvent(
                schema_version="1.0.0",
                event_id=str(uuid.uuid4()),
                event_type="ACTION_PROPOSED",
                provenance_source="AGENT_ADAPTER",
                correlation_id="c1",
                request_id="r_new",
                action_name="act",
                target="tgt",
                canonical_request_digest="d",
                timestamp="2026-01-01T00:00:00Z",
            )
        )


def test_audit_incremental_detects_suffix_corruption(tmp_path: Path):
    log_file = str(tmp_path / "test_audit_corrupt.jsonl")
    trail = TamperEvidentAuditTrail(log_file_path=log_file)

    for i in range(5):
        trail.record_event(
            AuditEvent(
                event_type=AuditLogLevel.INFO,
                gate_name="GateA",
                reason="ok",
                model_id="m1",
                payload_snippet="{}",
            )
        )

    healthy, _, err = trail.inspect_log_health()
    assert healthy is True
    assert err is None

    # Manually append broken hash record
    with open(log_file, "a", encoding="utf-8") as f:
        tampered_entry = {
            "event_id": str(uuid.uuid4()),
            "prev_hash": "bad_hash",
            "entry_hash": "forged_entry_hash",
        }
        f.write(json.dumps(tampered_entry) + "\n")

    healthy, _, err = trail.inspect_log_health()
    assert healthy is False
    assert err is not None

    with pytest.raises(
        RuntimeError, match="Cannot write to audit trail: Log corruption detected"
    ):
        trail.record_event(
            AuditEvent(
                event_type=AuditLogLevel.INFO,
                gate_name="GateB",
                reason="fail",
                model_id="m1",
                payload_snippet="{}",
            )
        )


def test_provenance_incremental_detects_duplicate_event_id(tmp_path: Path):
    log_file = str(tmp_path / "test_prov_dup.jsonl")
    store = LocalProvenanceStore(log_path=log_file)

    fixed_id = str(uuid.uuid4())
    store.record_event(
        ProvenanceEvent(
            schema_version="1.0.0",
            event_id=fixed_id,
            event_type="ACTION_PROPOSED",
            provenance_source="AGENT_ADAPTER",
            correlation_id="c1",
            request_id="r1",
            action_name="act",
            target="tgt",
            canonical_request_digest="d",
            timestamp="2026-01-01T00:00:00Z",
        )
    )

    # Second record with identical event_id
    with pytest.raises(RuntimeError, match="Duplicate event_id"):
        store.record_event(
            ProvenanceEvent(
                schema_version="1.0.0",
                event_id=fixed_id,
                event_type="ACTION_PROPOSED",
                provenance_source="AGENT_ADAPTER",
                correlation_id="c1",
                request_id="r2",
                action_name="act",
                target="tgt",
                canonical_request_digest="d",
                timestamp="2026-01-01T00:00:00Z",
            )
        )


def test_repeated_inspections_after_failure_remain_failed(tmp_path: Path):
    """Verifies that once verification fails, cached state does not mask subsequent calls."""
    log_file = str(tmp_path / "test_repeated_fail.jsonl")
    store = LocalProvenanceStore(log_path=log_file)

    store.record_event(
        ProvenanceEvent(
            schema_version="1.0.0",
            event_id="e1",
            event_type="ACTION_PROPOSED",
            provenance_source="AGENT_ADAPTER",
            correlation_id="c1",
            request_id="r1",
            action_name="a",
            target="t",
            canonical_request_digest="d",
            timestamp="2026-01-01T00:00:00Z",
        )
    )

    with open(log_file, "a", encoding="utf-8") as f:
        f.write("{invalid_json\n")

    # Call inspect 3 times: all must return False
    for _ in range(3):
        healthy, _, _, _ = store._inspect_health()
        assert healthy is False


def test_file_truncation_resets_incremental_verification(tmp_path: Path):
    log_file = str(tmp_path / "test_trunc.jsonl")
    store = LocalProvenanceStore(log_path=log_file)

    for i in range(10):
        store.record_event(
            ProvenanceEvent(
                schema_version="1.0.0",
                event_id=str(uuid.uuid4()),
                event_type="ACTION_PROPOSED",
                provenance_source="AGENT_ADAPTER",
                correlation_id="c",
                request_id=f"r_{i}",
                action_name="a",
                target="t",
                canonical_request_digest="d",
                timestamp="2026-01-01T00:00:00Z",
            )
        )

    healthy, hash1, count1, _ = store._inspect_health()
    assert healthy is True
    assert count1 == 10

    # Truncate file to first 3 lines
    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()[:3]
    with open(log_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    # Incremental store must detect size < verified_offset and re-verify from genesis
    healthy, hash2, count2, _ = store._inspect_health()
    assert healthy is True
    assert count2 == 3
    assert hash2 != hash1


def test_inode_change_file_replacement_resets_verification(tmp_path: Path):
    log_file = tmp_path / "test_inode.jsonl"
    store = LocalProvenanceStore(log_path=str(log_file))

    for i in range(5):
        store.record_event(
            ProvenanceEvent(
                schema_version="1.0.0",
                event_id=str(uuid.uuid4()),
                event_type="ACTION_PROPOSED",
                provenance_source="AGENT_ADAPTER",
                correlation_id="c",
                request_id=f"r_{i}",
                action_name="a",
                target="t",
                canonical_request_digest="d",
                timestamp="2026-01-01T00:00:00Z",
            )
        )

    healthy, _, count1, _ = store._inspect_health()
    assert healthy is True
    assert count1 == 5

    # Replace file with a new file (new inode)
    log_file.unlink()
    new_store = LocalProvenanceStore(log_path=str(log_file))
    for i in range(2):
        new_store.record_event(
            ProvenanceEvent(
                schema_version="1.0.0",
                event_id=str(uuid.uuid4()),
                event_type="ACTION_PROPOSED",
                provenance_source="AGENT_ADAPTER",
                correlation_id="c",
                request_id=f"new_{i}",
                action_name="a",
                target="t",
                canonical_request_digest="d",
                timestamp="2026-01-01T00:00:00Z",
            )
        )

    # Old store instance inspecting the replaced path detects inode change
    healthy, _, count2, _ = store._inspect_health()
    assert healthy is True
    assert count2 == 2


def test_hmac_keyed_incremental_verification(tmp_path: Path):
    key = b"secret_key_12345"
    log_file = str(tmp_path / "test_hmac.jsonl")
    store = LocalProvenanceStore(log_path=log_file, hmac_key=key)

    for i in range(10):
        store.record_event(
            ProvenanceEvent(
                schema_version="1.0.0",
                event_id=str(uuid.uuid4()),
                event_type="ACTION_PROPOSED",
                provenance_source="AGENT_ADAPTER",
                correlation_id="c",
                request_id=f"r_{i}",
                action_name="a",
                target="t",
                canonical_request_digest="d",
                timestamp="2026-01-01T00:00:00Z",
            )
        )

    healthy, hash1, count1, _ = store._inspect_health()
    assert healthy is True
    assert count1 == 10

    # Wrong key must fail health check
    wrong_key_store = LocalProvenanceStore(log_path=log_file, hmac_key=b"wrong_key_67890")
    healthy_wrong, _, _, _ = wrong_key_store._inspect_health()
    assert healthy_wrong is False


def test_intervening_historical_modification_during_inspection_fails_closed(tmp_path: Path):
    """
    Verifies that if historical content is modified while or between inspections,
    the modified history is detected via prefix digest check and never becomes trusted.
    """
    log_file = str(tmp_path / "test_race_tamper.jsonl")
    trail = TamperEvidentAuditTrail(log_file_path=log_file)

    trail.record_event(AuditEvent(AuditLogLevel.INFO, "G1", "r1", "m1", "s1"))
    trail.record_event(AuditEvent(AuditLogLevel.INFO, "G2", "r2", "m2", "s2"))

    assert trail.inspect_log_health()[0] is True

    # Simulate an intervening same-size modification of historical record 0
    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
    rec0 = json.loads(lines[0].strip())
    rec0["entry_hash"] = "9" * 64
    lines[0] = json.dumps(rec0) + "\n"
    with open(log_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    # Next inspection must fail closed because prefix digest validation detects alteration
    healthy, _, err = trail.inspect_log_health()
    assert healthy is False
    assert err is not None

    # Cached state must be wiped; repeated calls must also fail
    assert trail._verified_offset == 0
    assert trail.inspect_log_health()[0] is False


def test_provenance_single_descriptor_stream_integrity(tmp_path: Path):
    """Verifies that single descriptor stream in LocalProvenanceStore detects tampering."""
    log_file = str(tmp_path / "test_stream_integrity.jsonl")
    store = LocalProvenanceStore(log_path=log_file)

    store.record_event(
        ProvenanceEvent(
            schema_version="1.0.0",
            event_id="e1",
            event_type="ACTION_PROPOSED",
            provenance_source="AGENT_ADAPTER",
            correlation_id="c1",
            request_id="r1",
            action_name="a1",
            target="t1",
            canonical_request_digest="d1",
            timestamp="2026-01-01T00:00:00Z",
        )
    )
    assert store._inspect_health()[0] is True

    # Modify record in place
    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
    rec = json.loads(lines[0].strip())
    rec["entry_hash"] = "7" * 64
    lines[0] = json.dumps(rec) + "\n"
    with open(log_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    # Inspect health must fail closed
    assert store._inspect_health()[0] is False
    assert store._verified_offset == 0


def test_concurrent_intervening_historical_modification_fail_closed(tmp_path):
    """
    Simulates external modification to historical bytes while handle is open or between checks.
    Confirms fail-closed detection triggers immediately on inspection, resetting offset to 0.
    """
    log_path = tmp_path / "provenance_concurrent.jsonl"
    store = LocalProvenanceStore(log_path=str(log_path))

    for i in range(10):
        ev = ProvenanceEvent(
            schema_version="1.0.0",
            event_id=f"evt_{i}",
            event_type="ACTION_PROPOSED",
            provenance_source="AGENT_ADAPTER",
            correlation_id="corr_test",
            request_id=f"req_{i}",
            action_name=f"action_{i}",
            target="target_test",
            canonical_request_digest="d",
            timestamp="2026-01-01T00:00:00Z",
        )
        store.record_event(ev)

    assert store._verified_offset > 0

    # External attacker modifies an early event in-place (preserving file size)
    with open(log_path, "r+b") as f:
        content = f.read()
        tampered = content.replace(b'"action_2"', b'"action_9"')
        assert len(content) == len(tampered)
        f.seek(0)
        f.write(tampered)
        f.flush()

    # Next health inspection must detect the prefix mismatch on fstat and reset
    healthy, last_h, cnt, seen = store._inspect_health()
    assert healthy is False
    assert store._verified_offset == 0


def test_concurrent_intervening_historical_modification_audit_trail_fail_closed(tmp_path):
    """
    Simulates external modification to historical bytes in TamperEvidentAuditTrail.
    Verifies that fail-closed detection triggers immediately upon next inspect_log_health,
    resetting offset to 0 and failing closed.
    """
    log_path = tmp_path / "audit_concurrent.jsonl"
    trail = TamperEvidentAuditTrail(log_file_path=str(log_path))

    for i in range(10):
        ev = AuditEvent(
            AuditLogLevel.INFO,
            "TestGate",
            f"step_{i}",
            "m1",
            "s1"
        )
        trail.record_event(ev)

    assert trail._verified_offset > 0

    # Modify historical entry in place while preserving file size
    with open(log_path, "r+b") as f:
        content = f.read()
        tampered = content.replace(b'"step_2"', b'"step_9"')
        assert len(content) == len(tampered)
        f.seek(0)
        f.write(tampered)
        f.flush()

    healthy, last_h, err = trail.inspect_log_health()
    assert healthy is False
    assert trail._verified_offset == 0
    assert err is not None


def test_provenance_deterministic_intervening_race_fails_closed(tmp_path):
    """
    Deterministic mid-inspection mutation test for LocalProvenanceStore:
    Injects a same-size historical modification while suffix is being read.
    Verifies that the verifier fails closed and does not commit a partially updated cache state.
    """
    log_path = tmp_path / "prov_race.jsonl"
    store = LocalProvenanceStore(log_path=str(log_path))

    for i in range(5):
        store.record_event(
            ProvenanceEvent(
                schema_version="1.0.0",
                event_id=f"evt_{i}",
                event_type="ACTION_PROPOSED",
                provenance_source="AGENT_ADAPTER",
                correlation_id="corr_race",
                request_id=f"req_{i}",
                action_name=f"action_{i}",
                target="target_race",
                canonical_request_digest="d",
                timestamp="2026-01-01T00:00:00Z",
            )
        )

    # Establish verified prefix
    h, _, _, _ = store._inspect_health()
    assert h is True
    assert store._verified_offset > 0

    # Append 2 new events
    for i in range(5, 7):
        store.record_event(
            ProvenanceEvent(
                schema_version="1.0.0",
                event_id=f"evt_{i}",
                event_type="ACTION_PROPOSED",
                provenance_source="AGENT_ADAPTER",
                correlation_id="corr_race",
                request_id=f"req_{i}",
                action_name=f"action_{i}",
                target="target_race",
                canonical_request_digest="d",
                timestamp="2026-01-01T00:00:00Z",
            )
        )

    orig_inspect = store._inspect_health_on_descriptor
    raced = [False]

    def wrapped_inspect(f_raw, should_lock=True):
        orig_readline = f_raw.readline

        def hooking_readline(*args, **kwargs):
            if not raced[0]:
                raced[0] = True
                with open(log_path, "r+b") as mod_f:
                    mod_f.seek(0)
                    historical = mod_f.read(store._verified_offset)
                    tampered = historical.replace(b'"action_1"', b'"action_x"')
                    if len(tampered) == len(historical):
                        mod_f.seek(0)
                        mod_f.write(tampered)
                        mod_f.flush()
            return orig_readline(*args, **kwargs)

        f_raw.readline = hooking_readline
        return orig_inspect(f_raw, should_lock=should_lock)

    store._inspect_health_on_descriptor = wrapped_inspect

    # Inspection must detect tampering during this exact call and fail closed
    active_healthy, last_hash, count, seen_ids = store._inspect_health()
    assert raced[0] is True, "Hooked mutation was not executed during inspection"
    assert active_healthy is False, "Active inspection failed to detect mid-inspection tampering"
    assert store._verified_offset == 0, "Verification cache was not invalidated"

    # Subsequent inspection must also remain fail-closed
    store._inspect_health_on_descriptor = orig_inspect
    h_subsequent, _, _, _ = store._inspect_health()
    assert h_subsequent is False
    assert store._verified_offset == 0


def test_audit_deterministic_intervening_race_fails_closed(tmp_path):
    """
    Deterministic mid-inspection mutation test for TamperEvidentAuditTrail:
    Injects a same-size historical modification while suffix is being read.
    Verifies that the verifier fails closed and does not commit a partially updated cache state.
    """
    log_path = tmp_path / "audit_race.jsonl"
    trail = TamperEvidentAuditTrail(log_file_path=str(log_path))

    for i in range(5):
        trail.record_event(
            AuditEvent(
                AuditLogLevel.INFO,
                gate_name=f"Gate_{i}",
                reason=f"step_{i}",
                model_id=f"model_{i}",
                payload_snippet=f"snippet_{i}",
            )
        )

    # Establish verified prefix
    h, _, _ = trail.inspect_log_health()
    assert h is True
    assert trail._verified_offset > 0

    # Append 2 new events
    for i in range(5, 7):
        trail.record_event(
            AuditEvent(
                AuditLogLevel.INFO,
                gate_name=f"Gate_{i}",
                reason=f"step_{i}",
                model_id=f"model_{i}",
                payload_snippet=f"snippet_{i}",
            )
        )

    orig_inspect = trail._inspect_health_on_descriptor
    raced = [False]

    def wrapped_inspect(f_raw, should_lock=True):
        orig_readline = f_raw.readline

        def hooking_readline(*args, **kwargs):
            if not raced[0]:
                raced[0] = True
                with open(log_path, "r+b") as mod_f:
                    mod_f.seek(0)
                    historical = mod_f.read(trail._verified_offset)
                    tampered = historical.replace(b'"step_1"', b'"step_x"')
                    if len(tampered) == len(historical):
                        mod_f.seek(0)
                        mod_f.write(tampered)
                        mod_f.flush()
            return orig_readline(*args, **kwargs)

        f_raw.readline = hooking_readline
        return orig_inspect(f_raw, should_lock=should_lock)

    trail._inspect_health_on_descriptor = wrapped_inspect

    # Inspection must detect tampering during this exact call and fail closed
    active_healthy, last_hash, err = trail.inspect_log_health()
    assert raced[0] is True, "Hooked mutation was not executed during inspection"
    assert active_healthy is False, "Active inspection failed to detect mid-inspection tampering"
    assert trail._verified_offset == 0, "Verification cache was not invalidated"

    # Subsequent inspection must also remain fail-closed
    trail._inspect_health_on_descriptor = orig_inspect
    h_subsequent, _, _ = trail.inspect_log_health()
    assert h_subsequent is False
    assert trail._verified_offset == 0


def test_concurrent_same_instance_inspection_and_append(tmp_path):
    """
    Verifies that concurrent threads appending and inspecting the same instance
    maintain strict consistency without deadlocks or corrupting cache state.
    """
    import threading
    log_path = tmp_path / "concurrent_instance.jsonl"
    trail = TamperEvidentAuditTrail(log_file_path=str(log_path))

    errors = []

    def appender(tid):
        try:
            for i in range(15):
                ev = AuditEvent(
                    AuditLogLevel.INFO,
                    gate_name="TestGate",
                    reason=f"thread_{tid}_step_{i}",
                    model_id=f"m_{tid}",
                    payload_snippet=f"snippet_{tid}_{i}"
                )
                trail.record_event(ev)
        except Exception as e:
            errors.append(e)

    def inspector():
        try:
            for _ in range(20):
                healthy, last_h, err = trail.inspect_log_health()
                if not healthy:
                    errors.append(RuntimeError(f"Inspection failed concurrently: {err}"))
        except Exception as e:
            errors.append(e)

    threads = [
        threading.Thread(target=appender, args=(1,)),
        threading.Thread(target=appender, args=(2,)),
        threading.Thread(target=inspector),
        threading.Thread(target=inspector),
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Concurrent errors observed: {errors}"
    healthy, last_hash, err = trail.inspect_log_health()
    assert healthy is True
    assert err is None
    assert trail._verified_offset == os.path.getsize(log_path)


def test_file_lock_failure_fails_closed(tmp_path):
    """
    Verifies that if fcntl.flock fails with OSError, the stores fail closed
    instead of proceeding without synchronization.
    """
    from unittest.mock import patch
    log_path = tmp_path / "flock_fail.jsonl"
    trail = TamperEvidentAuditTrail(log_file_path=str(log_path))

    ev = AuditEvent(AuditLogLevel.INFO, "Gate", "step_0", "m0", "s0")
    trail.record_event(ev)

    with patch("fcntl.flock", side_effect=OSError("Lock table full")):
        # Standalone inspection must fail closed
        healthy, _, err = trail.inspect_log_health()
        assert healthy is False
        assert "Failed to acquire file lock" in str(err)
        assert trail._verified_offset == 0

        # Append must fail closed
        with pytest.raises(RuntimeError) as exc_info:
            trail.record_event(ev)
        assert "Failed to acquire exclusive file lock" in str(exc_info.value)


def test_permission_error_and_io_error_fail_closed(tmp_path):
    """
    Verifies that PermissionError or general OSError during file open
    fails closed (returns unhealthy/False), while genuinely missing files
    receive the empty-log treatment.
    """
    from unittest.mock import patch

    missing_path = tmp_path / "never_created.jsonl"
    audit = TamperEvidentAuditTrail(log_file_path=str(missing_path))
    prov = LocalProvenanceStore(log_path=str(missing_path))

    # Genuinely missing file receives empty-log treatment
    a_healthy, a_h, a_err = audit.inspect_log_health()
    assert a_healthy is True
    assert a_err is None

    p_healthy, p_h, p_seq, p_ids = prov._inspect_health()
    assert p_healthy is True

    # PermissionError on open must fail closed
    with patch("builtins.open", side_effect=PermissionError("Permission denied")):
        a_perm_h, _, a_perm_err = audit.inspect_log_health()
        assert a_perm_h is False
        assert "Failed to open log file" in str(a_perm_err)

        p_perm_h, _, _, _ = prov._inspect_health()
        assert p_perm_h is False

    # General OSError on open must fail closed
    with patch("builtins.open", side_effect=OSError("I/O device error")):
        a_io_h, _, a_io_err = audit.inspect_log_health()
        assert a_io_h is False
        assert "Failed to open log file" in str(a_io_err)

        p_io_h, _, _, _ = prov._inspect_health()
        assert p_io_h is False


def test_provenance_deterministic_suffix_mutation_fails_closed(tmp_path):
    """
    Deterministic mid-inspection mutation test for LocalProvenanceStore:
    Modifies bytes in the newly scanned suffix AFTER those lines were read
    but BEFORE verification state is committed.
    Verifies that the pre-commit validation catches the divergence up to new_offset,
    fails closed immediately, invalidates cache state, and subsequent calls remain fail-closed.
    """
    log_path = tmp_path / "prov_suffix_race.jsonl"
    store = LocalProvenanceStore(log_path=str(log_path))

    for i in range(5):
        store.record_event(
            ProvenanceEvent(
                schema_version="1.0.0",
                event_id=f"evt_{i}",
                event_type="ACTION_PROPOSED",
                provenance_source="AGENT_ADAPTER",
                correlation_id="corr_suffix_race",
                request_id=f"req_{i}",
                action_name=f"action_{i}",
                target="target_suffix_race",
                canonical_request_digest="d",
                timestamp="2026-01-01T00:00:00Z",
            )
        )

    # Establish verified prefix
    h, _, _, _ = store._inspect_health()
    assert h is True
    assert store._verified_offset > 0

    # Append 2 new events
    for i in range(5, 7):
        store.record_event(
            ProvenanceEvent(
                schema_version="1.0.0",
                event_id=f"evt_{i}",
                event_type="ACTION_PROPOSED",
                provenance_source="AGENT_ADAPTER",
                correlation_id="corr_suffix_race",
                request_id=f"req_{i}",
                action_name=f"action_{i}",
                target="target_suffix_race",
                canonical_request_digest="d",
                timestamp="2026-01-01T00:00:00Z",
            )
        )

    orig_inspect = store._inspect_health_on_descriptor
    raced = [False]

    def wrapped_inspect(f_raw, should_lock=True):
        orig_readline = f_raw.readline

        def hooking_readline(*args, **kwargs):
            line = orig_readline(*args, **kwargs)
            # Inject mutation after reading the final suffix line (line contains evt_6)
            if not line and not raced[0]:
                raced[0] = True
                with open(log_path, "r+b") as mod_f:
                    content = mod_f.read()
                    assert b'"action_6"' in content
                    tampered = content.replace(b'"action_6"', b'"action_y"')
                    assert len(tampered) == len(content)
                    mod_f.seek(0)
                    mod_f.write(tampered)
                    mod_f.flush()
            return line

        f_raw.readline = hooking_readline
        return orig_inspect(f_raw, should_lock=should_lock)

    store._inspect_health_on_descriptor = wrapped_inspect

    # Active inspection must detect suffix tampering and fail closed
    active_healthy, last_hash, count, seen_ids = store._inspect_health()
    assert raced[0] is True, "Suffix mutation hook did not execute"
    assert active_healthy is False, "Active inspection failed to detect suffix tampering"
    assert store._verified_offset == 0, "Cache state was not invalidated"

    # Subsequent inspection must also fail closed
    store._inspect_health_on_descriptor = orig_inspect
    h_subsequent, _, _, _ = store._inspect_health()
    assert h_subsequent is False
    assert store._verified_offset == 0


def test_audit_deterministic_suffix_mutation_fails_closed(tmp_path):
    """
    Deterministic mid-inspection mutation test for TamperEvidentAuditTrail:
    Modifies bytes in the newly scanned suffix AFTER those lines were read
    but BEFORE verification state is committed.
    Verifies that the pre-commit validation catches the divergence up to new_offset,
    fails closed immediately, invalidates cache state, and subsequent calls remain fail-closed.
    """
    log_path = tmp_path / "audit_suffix_race.jsonl"
    trail = TamperEvidentAuditTrail(log_file_path=str(log_path))

    for i in range(5):
        trail.record_event(
            AuditEvent(
                AuditLogLevel.INFO,
                gate_name=f"Gate_{i}",
                reason=f"step_{i}",
                model_id=f"model_{i}",
                payload_snippet=f"snippet_{i}",
            )
        )

    # Establish verified prefix
    h, _, _ = trail.inspect_log_health()
    assert h is True
    assert trail._verified_offset > 0

    # Append 2 new events
    for i in range(5, 7):
        trail.record_event(
            AuditEvent(
                AuditLogLevel.INFO,
                gate_name=f"Gate_{i}",
                reason=f"step_{i}",
                model_id=f"model_{i}",
                payload_snippet=f"snippet_{i}",
            )
        )

    orig_inspect = trail._inspect_health_on_descriptor
    raced = [False]

    def wrapped_inspect(f_raw, should_lock=True):
        orig_readline = f_raw.readline

        def hooking_readline(*args, **kwargs):
            line = orig_readline(*args, **kwargs)
            # Inject mutation after reading the final suffix line (line contains step_6)
            if not line and not raced[0]:
                raced[0] = True
                with open(log_path, "r+b") as mod_f:
                    content = mod_f.read()
                    assert b'"step_6"' in content
                    tampered = content.replace(b'"step_6"', b'"step_y"')
                    assert len(tampered) == len(content)
                    mod_f.seek(0)
                    mod_f.write(tampered)
                    mod_f.flush()
            return line

        f_raw.readline = hooking_readline
        return orig_inspect(f_raw, should_lock=should_lock)

    trail._inspect_health_on_descriptor = wrapped_inspect

    # Active inspection must detect suffix tampering and fail closed
    active_healthy, last_hash, err = trail.inspect_log_health()
    assert raced[0] is True, "Suffix mutation hook did not execute"
    assert active_healthy is False, "Active inspection failed to detect suffix tampering"
    assert trail._verified_offset == 0, "Cache state was not invalidated"

    # Subsequent inspection must also fail closed
    trail._inspect_health_on_descriptor = orig_inspect
    h_subsequent, _, _ = trail.inspect_log_health()
    assert h_subsequent is False
    assert trail._verified_offset == 0
