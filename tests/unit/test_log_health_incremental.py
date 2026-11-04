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
