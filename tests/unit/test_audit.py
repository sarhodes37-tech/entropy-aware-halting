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
