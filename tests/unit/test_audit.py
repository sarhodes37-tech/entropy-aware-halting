"""
Unit test suite for epistemicos.audit module.
Validates cryptographic log chain integrity, receipt generation, 
and hardware/OS fallback mechanisms.
"""

import os
import json
import importlib
import pytest
from unittest.mock import patch
from epistemicos.audit import (
    TamperEvidentAuditTrail,
    AuditLogLevel,
    ReceiptGenerator,
    AuditEvent
)


@pytest.fixture
def temp_audit_file(tmp_path):
    """Provides an isolated temporary path for audit log generation."""
    return str(tmp_path / "test_audit.jsonl")


# =====================================================================
# CHAIN INTEGRITY & TAMPER DETECTION
# =====================================================================

def test_verify_chain_integrity_json_error(temp_audit_file):
    """Validates chain verification handles malformed JSON gracefully (Line 166)."""
    with open(temp_audit_file, "w") as f:
        f.write('{"event_id": "1", "invalid_json": }\n')
        
    audit = TamperEvidentAuditTrail(temp_audit_file)
    is_valid, count, msg = audit.verify_chain_integrity()
    
    assert is_valid is False
    assert "Malformed JSON" in msg


def test_verify_chain_integrity_broken_link(temp_audit_file):
    """Validates chain verification flags mismatched previous hashes (Line 175)."""
    audit = TamperEvidentAuditTrail(temp_audit_file)
    audit.record_event(AuditEvent(AuditLogLevel.INFO, "gate", "reason", "model", "snippet"))
    
    # Manually append an entry with a fabricated prev_hash to break the chain
    bad_entry = {
        "event_id": "2",
        "timestamp": "2026-08-02T00:00:00Z",
        "event_type": "INFO",
        "gate_name": "gate",
        "reason": "reason",
        "model_id": "model",
        "latency_ms": 0.0,
        "payload_hash": "hash",
        "payload_snippet": "snippet",
        "metadata": {},
        "prev_hash": "INVALID_PREV_HASH"
    }
    # Compute an otherwise valid entry_hash so it passes the self-hash check, but fails the chain check
    bad_entry["entry_hash"] = audit._compute_hash("INVALID_PREV_HASH", bad_entry)
    
    with open(temp_audit_file, "a") as f:
        f.write(json.dumps(bad_entry) + "\n")
        
    is_valid, count, msg = audit.verify_chain_integrity()
    
    assert is_valid is False
    assert "Broken chain link" in msg


def test_verify_chain_integrity_tampered_entry(temp_audit_file):
    """Validates chain verification detects modified payload data (Lines 179-180, 186)."""
    audit = TamperEvidentAuditTrail(temp_audit_file)
    audit.record_event(AuditEvent(AuditLogLevel.INFO, "gate", "reason", "model", "snippet"))
    
    # Read the file and maliciously alter the data without updating the cryptographic hash
    with open(temp_audit_file, "r") as f:
        data = json.loads(f.read().strip())
    
    data["reason"] = "tampered_reason_inserted_by_attacker"
    
    with open(temp_audit_file, "w") as f:
        f.write(json.dumps(data) + "\n")
        
    is_valid, count, msg = audit.verify_chain_integrity()
    
    assert is_valid is False
    assert "Tampered entry detected" in msg


# =====================================================================
# RECEIPT GENERATION & TRANSACTION ROLLBACKS
# =====================================================================

def test_receipt_generator_log_event():
    """Validates direct logging of events in the ReceiptGenerator."""
    rg = ReceiptGenerator()
    rg.log_event("CustomEvent", {"key": "value"})

    assert len(rg.events) == 1
    event = rg.events[0]
    assert "idx" in event
    assert event["idx"] == 0
    assert event["type"] == "CustomEvent"
    assert event["details"] == {"key": "value"}
    assert rg._seq_idx == 1


def test_receipt_generator_lifecycle():
    """Validates atomic transaction logging, minting, and stack-based rollbacks (Lines 196-242)."""
    rg = ReceiptGenerator()
    
    # 1. Test pushing actions (Lines 210-211)
    rg.push_action({"action": "StageVectors"}, {"rollback": "PurgeVectors"})
    rg.push_action({"action": "CommitToLedger"}, {"rollback": "DropBlock"})
    
    # 2. Test minting receipt (Lines 215-220, 223-224, 227-229)
    receipt = rg.mint_receipt("tx_001", False, {"confidence": 0.82})
    
    assert receipt["transaction_id"] == "tx_001"
    assert receipt["status"] == "ROLLED_BACK"
    assert "signature" in receipt
    assert len(receipt["event_log"]) == 2
    
    # 3. Test LIFO rollback execution (Lines 230-235, 238-242)
    rollbacks = rg.rollback()
    
    assert len(rollbacks) == 2
    # Verify strict Last-In-First-Out (LIFO) order for state reconstruction
    assert rollbacks[0] == {"rollback": "DropBlock"}
    assert rollbacks[1] == {"rollback": "PurgeVectors"}


# =====================================================================
# OS/HARDWARE FALLBACKS
# =====================================================================

def test_audit_no_fcntl_fallback(tmp_path):
    """Simulates an OS environment without fcntl (e.g. Windows) to test lock bypassing (Lines 21-22, 122)."""
    test_file = str(tmp_path / "temp_no_fcntl.jsonl")
    
    # Force ImportError on fcntl and reload the module
    with patch.dict('sys.modules', {'fcntl': None}):
        import epistemicos.audit
        importlib.reload(epistemicos.audit)
        
        assert epistemicos.audit.HAS_FCNTL is False
        
        # Test fallback on record_event (bypassing fcntl.flock entirely)
        audit = epistemicos.audit.TamperEvidentAuditTrail(test_file)
        audit.record_event(epistemicos.audit.AuditEvent(epistemicos.audit.AuditLogLevel.INFO, "gate", "reason", "m", "s"))
        
        assert os.path.exists(test_file)
        
    # Restore normal state for subsequent test modules
    import epistemicos.audit
    importlib.reload(epistemicos.audit)


def test_record_event_payload_too_large(temp_audit_file):
    """Validates that payload snippets larger than 1MB are rejected to prevent DoS."""
    audit = TamperEvidentAuditTrail(temp_audit_file)
    large_snippet = "a" * (1048576 + 1)
    event = AuditEvent(AuditLogLevel.INFO, "gate", "reason", "model", large_snippet)
    with pytest.raises(ValueError, match="Payload snippet exceeds"):
        audit.record_event(event)


def test_verify_receipt_type_and_format_edge_cases():
    """Validates verify_receipt type and format error handling branches."""
    # Line 420: Non-dict receipt
    assert ReceiptGenerator.verify_receipt("not_a_dict") is False

    rg = ReceiptGenerator()
    valid_receipt = rg.mint_receipt("tx_edge", True, {"g": 1.0})

    # Line 444: signature_algorithm non-string
    rec_algo = dict(valid_receipt)
    rec_algo["signature_algorithm"] = 123
    assert ReceiptGenerator.verify_receipt(rec_algo) is False

    # Line 451-452: Non-hex signature of length 64
    rec_sig_hex = dict(valid_receipt)
    rec_sig_hex["signature"] = "Z" * 64
    assert ReceiptGenerator.verify_receipt(rec_sig_hex) is False

    # Line 458: Invalid length input_hash
    rec_ih_len = dict(valid_receipt)
    rec_ih_len["input_hash"] = "short"
    assert ReceiptGenerator.verify_receipt(rec_ih_len) is False

    # Line 461-462: Non-hex input_hash of length 64
    rec_ih_hex = dict(valid_receipt)
    rec_ih_hex["input_hash"] = "G" * 64
    assert ReceiptGenerator.verify_receipt(rec_ih_hex) is False

    # Line 465: decision_details not dict
    rec_dec = dict(valid_receipt)
    rec_dec["decision_details"] = "string_desc"
    assert ReceiptGenerator.verify_receipt(rec_dec) is False

    # Line 468: execution_outcome not dict
    rec_out = dict(valid_receipt)
    rec_out["execution_outcome"] = [1, 2, 3]
    assert ReceiptGenerator.verify_receipt(rec_out) is False


# =====================================================================
# ADVANCED AUDIT SECURITY & TAMPER TESTS
# =====================================================================

def test_audit_duplicate_event_id_detection(temp_audit_file):
    """Validates that replayed or duplicate event IDs are detected."""
    audit = TamperEvidentAuditTrail(temp_audit_file)
    e1 = audit.record_event(AuditEvent(AuditLogLevel.INFO, "gate1", "reason1", "model1", "snippet1"))
    e2 = audit.record_event(AuditEvent(AuditLogLevel.INFO, "gate2", "reason2", "model2", "snippet2"))

    # Read and duplicate entry 2 with duplicate event_id
    with open(temp_audit_file, "r") as f:
        lines = f.readlines()

    dup_entry = json.loads(lines[1])
    lines.append(json.dumps(dup_entry) + "\n")

    with open(temp_audit_file, "w") as f:
        f.writelines(lines)

    is_valid, count, msg = audit.verify_chain_integrity()
    assert is_valid is False
    assert "Duplicate event_id" in msg


def test_audit_reordering_detection(temp_audit_file):
    """Validates that swapping event sequence order breaks chain integrity."""
    audit = TamperEvidentAuditTrail(temp_audit_file)
    audit.record_event(AuditEvent(AuditLogLevel.INFO, "gate1", "reason1", "model1", "snippet1"))
    audit.record_event(AuditEvent(AuditLogLevel.INFO, "gate2", "reason2", "model2", "snippet2"))

    with open(temp_audit_file, "r") as f:
        lines = f.readlines()

    # Reorder lines
    swapped = [lines[1], lines[0]]
    with open(temp_audit_file, "w") as f:
        f.writelines(swapped)

    is_valid, count, msg = audit.verify_chain_integrity()
    assert is_valid is False
    assert "Broken chain link" in msg


def test_audit_truncation_detection(temp_audit_file):
    """Validates head, middle, and tail truncation behaviors."""
    audit = TamperEvidentAuditTrail(temp_audit_file)
    audit.record_event(AuditEvent(AuditLogLevel.INFO, "gate1", "r1", "m1", "s1"))
    audit.record_event(AuditEvent(AuditLogLevel.INFO, "gate2", "r2", "m2", "s2"))
    audit.record_event(AuditEvent(AuditLogLevel.INFO, "gate3", "r3", "m3", "s3"))

    with open(temp_audit_file, "r") as f:
        lines = f.readlines()

    # 1. Head truncation (delete line 1)
    with open(temp_audit_file, "w") as f:
        f.writelines(lines[1:])

    is_valid, count, msg = audit.verify_chain_integrity()
    assert is_valid is False
    assert "Broken chain link" in msg

    # 2. Middle truncation (delete line 2)
    with open(temp_audit_file, "w") as f:
        f.writelines([lines[0], lines[2]])

    is_valid, count, msg = audit.verify_chain_integrity()
    assert is_valid is False
    assert "Broken chain link" in msg

    # 3. Tail truncation (delete line 3): Internal hash chain alone cannot detect tail truncation
    with open(temp_audit_file, "w") as f:
        f.writelines(lines[:2])

    is_valid, count, msg = audit.verify_chain_integrity()
    assert is_valid is True
    assert count == 2


def test_audit_partial_write_detection(temp_audit_file):
    """Validates that partial line writes (corrupted JSON) are flagged."""
    audit = TamperEvidentAuditTrail(temp_audit_file)
    audit.record_event(AuditEvent(AuditLogLevel.INFO, "gate1", "r1", "m1", "s1"))

    # Append corrupted JSON line representing a crash during write
    with open(temp_audit_file, "a") as f:
        f.write('{"event_id": "partial_write_123", "event_type": "INF')

    is_valid, count, msg = audit.verify_chain_integrity()
    assert is_valid is False
    assert "Malformed JSON" in msg


def test_audit_sensitive_data_redaction(temp_audit_file):
    """Validates that sensitive credentials and PII are redacted from metadata and receipts."""
    audit = TamperEvidentAuditTrail(temp_audit_file)
    sensitive_metadata = {
        "api_key": "sk-secret-12345",
        "ssn": "000-00-0000",
        "nested": {"password": "SuperSecretPassword123"}
    }
    audit.record_event(AuditEvent(
        AuditLogLevel.INFO, "gate", "reason", "model", "snippet",
        metadata=sensitive_metadata
    ))

    with open(temp_audit_file, "r") as f:
        line = f.readline()
    entry = json.loads(line)

    metadata = entry["metadata"]
    assert metadata["api_key"] == "[REDACTED]"
    assert metadata["ssn"] == "[REDACTED]"
    assert metadata["nested"]["password"] == "[REDACTED]"

    # Test ReceiptGenerator sensitive data redaction
    rg = ReceiptGenerator()
    rg.log_event("ToolOutput", {"token": "bearer-token-abc", "safe_field": "public"})
    rg.push_action(
        {"op": "query", "secret": "shh"},
        {"rollback": "purge", "private_key": "0x123"}
    )
    receipt = rg.mint_receipt("tx_sens", True, {"conf": 0.99})

    assert receipt["event_log"][0]["details"]["token"] == "[REDACTED]"
    assert receipt["event_log"][0]["details"]["safe_field"] == "public"
    assert receipt["event_log"][1]["details"]["action"]["secret"] == "[REDACTED]"


def test_receipt_exact_binding_and_verification():
    """Validates receipt binding to input, config, gate_version, decision, outcome and independent verifier validation."""
    key = b"secret_signing_key_32bytes_long!"
    config = {"threshold": 0.95, "api_key": "should_be_masked"}
    input_payload = {"user_prompt": "run_analysis", "password": "user_pass"}
    decision = {"gate": "PermissionGate", "action": "ALLOW"}
    outcome = {"vectors_revoked": 0}

    rg = ReceiptGenerator(signing_key=key, gate_version="2.1.0", config=config)
    rg.log_event("GateEvaluation", {"result": "PASSED"})

    receipt = rg.mint_receipt(
        transaction_id="tx_bound_001",
        success=True,
        confidence_matrix={"model": 0.98},
        input_data=input_payload,
        decision_details=decision,
        execution_outcome=outcome
    )

    assert receipt["gate_version"] == "2.1.0"
    assert receipt["config"]["api_key"] == "[REDACTED]"
    assert "input_hash" in receipt
    assert receipt["decision_details"] == decision
    assert receipt["execution_outcome"] == outcome

    # Verify signature independently with ReceiptGenerator.verify_receipt
    assert ReceiptGenerator.verify_receipt(receipt, signing_key=key) is True

    # Verify that altering any field invalidates signature
    tampered_receipt = dict(receipt)
    tampered_receipt["status"] = "ROLLED_BACK"
    assert ReceiptGenerator.verify_receipt(tampered_receipt, signing_key=key) is False

    # Verify wrong signing key fails
    assert ReceiptGenerator.verify_receipt(receipt, signing_key=b"wrong_key") is False


def test_audit_trail_concurrency_force_reload(temp_audit_file):
    """Validates that two audit instances maintain chain link integrity via force_reload."""
    audit1 = TamperEvidentAuditTrail(temp_audit_file)
    audit2 = TamperEvidentAuditTrail(temp_audit_file)

    audit1.record_event(AuditEvent(AuditLogLevel.INFO, "g1", "r1", "m1", "s1"))
    audit2.record_event(AuditEvent(AuditLogLevel.INFO, "g2", "r2", "m2", "s2"))
    audit1.record_event(AuditEvent(AuditLogLevel.INFO, "g3", "r3", "m3", "s3"))

    is_valid, count, msg = audit1.verify_chain_integrity()
    assert is_valid is True
    assert count == 3


def _multiprocess_writer_worker(file_path: str, worker_id: int, count: int):
    """Helper target for multiprocessing concurrency tests."""
    audit = TamperEvidentAuditTrail(file_path)
    for i in range(count):
        audit.record_event(AuditEvent(
            AuditLogLevel.INFO,
            f"worker_{worker_id}",
            f"step_{i}",
            "model_mp",
            f"snippet_worker_{worker_id}_{i}"
        ))


def test_audit_multiprocess_concurrency(temp_audit_file):
    """Validates concurrent log appends from independent OS processes maintain chain integrity."""
    import multiprocessing

    processes = []
    num_workers = 4
    events_per_worker = 5

    for w_id in range(num_workers):
        p = multiprocessing.Process(
            target=_multiprocess_writer_worker,
            args=(temp_audit_file, w_id, events_per_worker)
        )
        processes.append(p)
        p.start()

    for p in processes:
        p.join(timeout=10)

    audit_verifier = TamperEvidentAuditTrail(temp_audit_file)
    is_valid, count, msg = audit_verifier.verify_chain_integrity()
    assert is_valid is True
    assert count == num_workers * events_per_worker


def test_audit_crash_recovery_last_hash(temp_audit_file):
    """Validates crash recovery, explicit corruption reporting, and repair workflow."""
    audit = TamperEvidentAuditTrail(temp_audit_file)
    e1 = audit.record_event(AuditEvent(AuditLogLevel.INFO, "g1", "r1", "m1", "s1"))
    e2 = audit.record_event(AuditEvent(AuditLogLevel.INFO, "g2", "r2", "m2", "s2"))
    e3 = audit.record_event(AuditEvent(AuditLogLevel.INFO, "g3", "r3", "m3", "s3"))

    # Simulate crash mid-write by writing partial trailing JSON fragment
    with open(temp_audit_file, "a") as f:
        f.write('{"event_id": "crashed_mid_write_123", "event_type": "INF')

    audit_after_crash = TamperEvidentAuditTrail(temp_audit_file)
    is_healthy, last_valid_h, err = audit_after_crash.inspect_log_health()

    # 1. Inspecting health flags corruption and identifies last valid hash
    assert is_healthy is False
    assert last_valid_h == e3["entry_hash"]
    assert "Malformed JSON" in err

    # 2. Attempting to record_event on a corrupted log MUST raise RuntimeError
    with pytest.raises(RuntimeError, match="Log corruption detected"):
        audit_after_crash.record_event(AuditEvent(AuditLogLevel.INFO, "g4", "r4", "m4", "s4"))

    # 3. Explicit repair policy: truncate unparseable trailing bytes
    with open(temp_audit_file, "r") as f:
        lines = f.readlines()
    clean_lines = [l for l in lines if not l.startswith('{"event_id": "crashed_mid_write_123"')]
    with open(temp_audit_file, "w") as f:
        f.writelines(clean_lines)

    # 4. After repair, health is restored and new event appends properly
    audit_repaired = TamperEvidentAuditTrail(temp_audit_file)
    is_healthy_now, _, _ = audit_repaired.inspect_log_health()
    assert is_healthy_now is True

    e4 = audit_repaired.record_event(AuditEvent(AuditLogLevel.INFO, "g4", "r4", "m4", "s4"))
    assert e4["prev_hash"] == e3["entry_hash"]

    is_valid, count, msg = audit_repaired.verify_chain_integrity()
    assert is_valid is True
    assert count == 4


def test_audit_unlinked_record_rejection(temp_audit_file):
    """Validates that appending after a complete but unlinked record is rejected."""
    audit = TamperEvidentAuditTrail(temp_audit_file)
    e1 = audit.record_event(AuditEvent(AuditLogLevel.INFO, "g1", "r1", "m1", "s1"))

    # Append an unlinked record with invalid prev_hash
    unlinked_entry = {
        "event_id": "unlinked_999",
        "timestamp": "2026-08-02T00:00:00Z",
        "event_type": "INFO",
        "gate_name": "g_bad",
        "reason": "bad_link",
        "model_id": "m1",
        "latency_ms": 0.0,
        "payload_hash": "hash",
        "payload_snippet": "s",
        "metadata": {},
        "prev_hash": "INVALID_PREV_HASH"
    }
    unlinked_entry["entry_hash"] = audit._compute_hash("INVALID_PREV_HASH", unlinked_entry)

    with open(temp_audit_file, "a") as f:
        f.write(json.dumps(unlinked_entry) + "\n")

    is_healthy, last_h, err = audit.inspect_log_health()
    assert is_healthy is False
    assert "Broken chain link" in err

    with pytest.raises(RuntimeError, match="Log corruption detected"):
        audit.record_event(AuditEvent(AuditLogLevel.INFO, "g2", "r2", "m2", "s2"))


def test_receipt_schema_enforcement_and_fail_closed():
    """Validates strict schema enforcement, missing required fields, insertion of unknown fields, nulls, and malformed sigs."""
    key = b"signing_key_12345"
    rg = ReceiptGenerator(signing_key=key)
    valid_receipt = rg.mint_receipt("tx_schema_001", True, {"g": 1.0})

    assert ReceiptGenerator.verify_receipt(valid_receipt, signing_key=key) is True

    # 1. Missing required field
    for req_field in ["transaction_id", "status", "gate_version", "config", "confidence_matrix", "event_log", "signature_algorithm"]:
        incomplete = dict(valid_receipt)
        del incomplete[req_field]
        assert ReceiptGenerator.verify_receipt(incomplete, signing_key=key) is False, f"Failed to reject missing field: {req_field}"

    # 2. Unknown extra field
    unknown_field_receipt = dict(valid_receipt)
    unknown_field_receipt["unauthorized_key"] = "malicious_injection"
    assert ReceiptGenerator.verify_receipt(unknown_field_receipt, signing_key=key) is False

    # 3. Null substitution for required fields
    for req_field in ["transaction_id", "status", "gate_version", "config", "confidence_matrix", "event_log"]:
        null_receipt = dict(valid_receipt)
        null_receipt[req_field] = None
        assert ReceiptGenerator.verify_receipt(null_receipt, signing_key=key) is False

    # 4. Invalid field types
    invalid_type_receipt = dict(valid_receipt)
    invalid_type_receipt["transaction_id"] = 12345
    assert ReceiptGenerator.verify_receipt(invalid_type_receipt, signing_key=key) is False

    invalid_status_receipt = dict(valid_receipt)
    invalid_status_receipt["status"] = "PENDING"
    assert ReceiptGenerator.verify_receipt(invalid_status_receipt, signing_key=key) is False

    # 5. Malformed signature
    malformed_sig_receipt = dict(valid_receipt)
    malformed_sig_receipt["signature"] = "not_a_valid_64_char_hex_string"
    assert ReceiptGenerator.verify_receipt(malformed_sig_receipt, signing_key=key) is False

    # 6. Unknown signature algorithm
    unknown_algo_receipt = dict(valid_receipt)
    unknown_algo_receipt["signature_algorithm"] = "MD5"
    assert ReceiptGenerator.verify_receipt(unknown_algo_receipt, signing_key=key) is False


def test_receipt_set_canonicalization_determinism():
    """Validates that sets and frozensets containing strings, mixed primitive types, and nested dicts are deterministically canonicalized, and unsupported un-serializable values fail explicitly."""
    from epistemicos.audit import _sanitize_sensitive_data

    rg = ReceiptGenerator()
    rg.log_event("SetEvent", {"tags": {"tag_z", "tag_a", "tag_m"}})
    receipt = rg.mint_receipt("tx_set_001", True, {"g": 1.0})

    tags = receipt["event_log"][0]["details"]["tags"]
    assert isinstance(tags, list)
    assert tags == ["tag_a", "tag_m", "tag_z"]
    assert ReceiptGenerator.verify_receipt(receipt) is True

    # Test mixed primitive types in set
    mixed_set = {10, "apple", True, None}
    canonical_mixed = _sanitize_sensitive_data(mixed_set)
    assert isinstance(canonical_mixed, list)
    assert canonical_mixed == [10, "apple", True, None] or len(canonical_mixed) == 4

    # Test that equivalent sets with mixed types yield identical canonical JSON bytes
    set1 = {"b", 1, None}
    set2 = {None, 1, "b"}
    assert json.dumps(_sanitize_sensitive_data(set1)) == json.dumps(_sanitize_sensitive_data(set2))

    # Test unsupported un-serializable value raises TypeError explicitly
    unsupported_set = {lambda x: x}
    with pytest.raises(TypeError):
        _sanitize_sensitive_data(unsupported_set)


def test_receipt_field_by_field_tampering():
    """Validates that altering any individual field in a receipt invalidates its signature."""
    key = b"signing_secret_key_123"
    rg = ReceiptGenerator(signing_key=key, gate_version="1.0.0", config={"setting": 1})
    rg.log_event("EventA", {"detail": "ok"})

    receipt = rg.mint_receipt(
        transaction_id="tx_test_tamper",
        success=True,
        confidence_matrix={"gate": 0.9},
        input_data={"prompt": "test"},
        decision_details={"action": "ALLOW"},
        execution_outcome={"revoked": 0}
    )

    assert ReceiptGenerator.verify_receipt(receipt, signing_key=key) is True

    # Test independent field modifications
    tamper_scenarios = [
        ("transaction_id", "tx_test_tamper_MODIFIED"),
        ("status", "ROLLED_BACK"),
        ("gate_version", "1.0.1"),
        ("config", {"setting": 2}),
        ("confidence_matrix", {"gate": 0.5}),
        ("event_log", []),
        ("input_hash", "0000000000000000000000000000000000000000000000000000000000000000"),
        ("decision_details", {"action": "HALT"}),
        ("execution_outcome", {"revoked": 1}),
        ("signature_algorithm", "SHA256")
    ]

    for key_to_tamper, tampered_val in tamper_scenarios:
        t_receipt = dict(receipt)
        t_receipt[key_to_tamper] = tampered_val
        assert ReceiptGenerator.verify_receipt(t_receipt, signing_key=key) is False, f"Failed to reject tampered key: {key_to_tamper}"


def test_receipt_algorithm_downgrade_prevention():
    """Validates protection against algorithm downgrade and key mismatch attacks."""
    key = b"secret_key"
    rg_hmac = ReceiptGenerator(signing_key=key)
    receipt_hmac = rg_hmac.mint_receipt("tx_hmac", True, {"m": 1.0})

    # HMAC receipt verified with key must pass
    assert ReceiptGenerator.verify_receipt(receipt_hmac, signing_key=key) is True

    # Verifying HMAC receipt without passing signing key must fail
    assert ReceiptGenerator.verify_receipt(receipt_hmac, signing_key=None) is False

    # Forging receipt: setting algorithm to SHA256 while keeping HMAC signature must fail
    forged_downgrade = dict(receipt_hmac)
    forged_downgrade["signature_algorithm"] = "SHA256"
    assert ReceiptGenerator.verify_receipt(forged_downgrade, signing_key=None) is False
    assert ReceiptGenerator.verify_receipt(forged_downgrade, signing_key=key) is False

    # Plain SHA256 receipt
    rg_sha = ReceiptGenerator(signing_key=None)
    receipt_sha = rg_sha.mint_receipt("tx_sha", True, {"m": 1.0})
    assert ReceiptGenerator.verify_receipt(receipt_sha, signing_key=None) is True

    # Verifying plain SHA256 receipt when expecting HMAC (key provided) must fail
    assert ReceiptGenerator.verify_receipt(receipt_sha, signing_key=key) is False


def test_sanitize_sensitive_data_deep_structures_and_text():
    """Validates redaction across sets, frozensets, unusual keys, and free-text token patterns."""
    from epistemicos.audit import _sanitize_sensitive_data

    raw_data = {
        "x-api-key": "sk-123456789012345678901234",
        "headers": {
            "Authorization": "Bearer my_secret_bearer_token_123",
            "Credential_Token": "secret_pass_123"
        },
        "tags_set": {"normal_tag", "password=my_raw_password"},
        "config_tuple": ("clean_val", "api_key=sk-999999999999999999999999")
    }

    sanitized = _sanitize_sensitive_data(raw_data)

    assert sanitized["x-api-key"] == "[REDACTED]"
    assert sanitized["headers"]["Authorization"] == "[REDACTED]"
    assert sanitized["headers"]["Credential_Token"] == "[REDACTED]"
    assert "password=[REDACTED]" in sanitized["tags_set"]
    assert "api_key=[REDACTED]" in sanitized["config_tuple"][1]


def test_record_event_payload_too_large_multibyte(temp_audit_file):
    """Validates that payload snippets larger than 1MB in bytes (even if fewer chars) are rejected."""
    audit = TamperEvidentAuditTrail(temp_audit_file)
    # The character '🌍' (Earth globe) is 4 bytes in UTF-8.
    # 262144 characters * 4 bytes = 1048576 bytes.
    # We add 1 character so it exceeds 1MB in bytes, but is only 262,145 characters long.
    large_snippet = "🌍" * (262144 + 1)
    event = AuditEvent(AuditLogLevel.INFO, "gate", "reason", "model", large_snippet)
    with pytest.raises(ValueError, match="Payload snippet exceeds"):
        audit.record_event(event)
