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
