import pytest
from pathlib import Path
from epistemicos.audit import TamperEvidentAuditTrail, AuditLogLevel
from epistemicos.models import CanonicalProblemRepresentation

@pytest.fixture
def temp_audit_log(tmp_path):
    log_file = tmp_path / "test_audit.jsonl"
    return TamperEvidentAuditTrail(str(log_file))

def test_audit_chain_integrity_and_masking(temp_audit_log):
    cpr = CanonicalProblemRepresentation(
        policy_id="POL-TEST-01",
        fleet_data={"vehicle_count": 10}
    )
    
    # Record a normal event with CPR snapshot
    entry1 = temp_audit_log.record_event(
        event_type=AuditLogLevel.INFO,
        gate_name="TestGate",
        reason="Passed successfully",
        model_id="test-model",
        payload_snippet="{\"test\": true}",
        cpr_snapshot=cpr
    )
    
    # Ensure sensitive fields/scope are masked out of the metadata state
    metadata_cpr = entry1["metadata"]["cpr_state"]
    assert "scope" not in metadata_cpr
    assert "SENSITIVE_FIELDS" not in metadata_cpr

    # Record a second event to chain hashes
    temp_audit_log.record_event(
        event_type=AuditLogLevel.WARNING,
        gate_name="TestGate2",
        reason="Minor deviation",
        model_id="test-model",
        payload_snippet="{\"test\": false}"
    )

    # Verify chain integrity
    is_valid, count, error = temp_audit_log.verify_chain_integrity()
    assert is_valid is True
    assert count == 2
    assert error is None
