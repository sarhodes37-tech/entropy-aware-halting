"""
Unit test suite for epistemicos.gates module.
Validates EntropyGate, PermissionGate, CryptoAttestationGate, and TriangulationGate.
"""

import pytest
from epistemicos.gates import (
    EntropyGate,
    PermissionGate,
    CryptoAttestationGate,
    TriangulationGate
)
from epistemicos.models import CanonicalProblemRepresentation


def test_entropy_gate_clean_and_spike():
    gate = EntropyGate(z_threshold=2.85)

    # Clean trajectory
    clean_ctx = {"token_logprobs": [-0.01] * 20}
    res_clean = gate.evaluate({}, clean_ctx)
    assert res_clean["passed"] is True
    assert res_clean["confidence"] == 1.0

    # Spiked trajectory
    spiked_ctx = {"token_logprobs": ([-0.01] * 10) + [-12.5, -15.0]}
    res_spike = gate.evaluate({}, spiked_ctx)
    assert res_spike["passed"] is False
    assert res_spike["flagged_tokens"] > 0


def test_permission_gate():
    gate = PermissionGate(contract_model=CanonicalProblemRepresentation)
    
    # Explicitly define the operational scope in the payload. 
    # Without this boundary, the gate lacks the context to veto the invalid action.
    payload = {
        "policy_id": "POL-PERM-TEST",
        "scope": {
            "allowed_operations": ["update_db"],
            "allowed_resources": ["logistics_db"]
        }
    }

    # Flattened the 'op' structure to match the integration tests and Domain Model
    valid_actions = [{"op": "update_db", "node": "logistics_db"}]
    assert gate.evaluate(payload, {"proposed_actions": valid_actions})["passed"] is True

    invalid_actions = [{"op": "exec_shell", "node": "unauthorized_node"}]
    assert gate.evaluate(payload, {"proposed_actions": invalid_actions})["passed"] is False


def test_crypto_attestation_gate():
    gate = CryptoAttestationGate(required_algorithm="ML-DSA")

    # Valid PQC attestation
    valid_crypto = {"cryptography": {"algorithm": "ML-DSA", "key_id": "KEY-VALID-01"}}
    assert gate.evaluate({}, valid_crypto)["passed"] is True

    # Revoked key check
    revoked_crypto = {"cryptography": {"algorithm": "ML-DSA", "key_id": "KEY-000-COMPROMISED"}}
    res_revoked = gate.evaluate({}, revoked_crypto)
    assert res_revoked["passed"] is False
    assert "REVOKED" in res_revoked["reason"]

    # Deprecated RSA algorithm check
    deprecated_crypto = {"cryptography": {"algorithm": "RSA-2048", "key_id": "KEY-OLD"}}
    res_dep = gate.evaluate({}, deprecated_crypto)
    assert res_dep["passed"] is False
    assert "Deprecated" in res_dep["reason"]


def test_triangulation_gate():
    gate = TriangulationGate(max_divergence_threshold=0.15)

    # Clean triangulation
    clean_payload = {"primary_metric": 100.0}
    clean_ctx = {"heterogeneous_telemetry": [98.0, 101.0, 100.5]}
    assert gate.evaluate(clean_payload, clean_ctx)["passed"] is True

    # Manipulated/washed data
    washed_payload = {"primary_metric": 150.0}
    washed_ctx = {"heterogeneous_telemetry": [98.0, 101.0, 100.5]}
    res_washed = gate.evaluate(washed_payload, washed_ctx)
    assert res_washed["passed"] is False
    assert res_washed["divergence"] > 0.15
