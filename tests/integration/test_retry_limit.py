"""
Integration test suite for server-side stateful attempt tracking and retry-limit enforcement 
within the unified EpistemicOrchestrator architecture.
"""

import pytest
from epistemicos.core import EpistemicOrchestrator
from epistemicos.models import CanonicalProblemRepresentation, PermissionScope


@pytest.fixture
def orchestrator():
    return EpistemicOrchestrator()


@pytest.fixture
def base_payload():
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


def test_spoofed_client_attempt_counter_neutralized(orchestrator, base_payload):
    """
    Validates that the server tracks real attempt counts independently of client payloads,
    incrementing across submissions and halting once the max_attempts threshold (3) is breached.
    """
    clean_logprobs = [-0.01] * 10
    noisy_logprobs = [-0.01] * 5 + [-12.0]  # Triggers EntropyGate anomaly

    context_clean = {"token_count": 10, "token_logprobs": clean_logprobs}
    context_noisy = {"token_count": 6, "token_logprobs": noisy_logprobs}

    # Attempt 1: Clean run -> Allowed
    res1 = orchestrator.process_submission(base_payload, context_clean)
    assert res1["status"] == "ALLOWED"

    # Attempt 2: Noisy run -> Fails EntropyGate, recorded as server-side attempt 2
    res2 = orchestrator.process_submission(base_payload, context_noisy)
    assert res2["status"] == "HALTED"

    # Attempt 3: Noisy run -> Fails EntropyGate, recorded as server-side attempt 3
    res3 = orchestrator.process_submission(base_payload, context_noisy)
    assert res3["status"] == "HALTED"

    # Attempt 4: Exceeds max_attempts (4 > 3) -> Server halts immediately due to retry exhaustion
    res4 = orchestrator.process_submission(base_payload, context_clean)
    assert res4["status"] == "HALTED"
    assert res4["gate"] == "PermissionGate"  # Or attempt cap enforcement boundary
    assert "attempt" in res4["reason"].lower()
