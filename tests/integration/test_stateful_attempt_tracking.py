"""
Integration test verifying server-side stateful attempt tracking in EpistemicOrchestrator.
Validates that client attempt count spoofing is completely neutralized.
"""

import pytest
from epistemicos.engine import EpistemicOrchestrator
from epistemicos.gates import EntropyGate


@pytest.fixture
def orchestrator():
    engine = EpistemicOrchestrator()
    engine.register_gate("EntropyGate", EntropyGate(z_threshold=2.85))
    return engine


@pytest.fixture
def base_payload():
    return {
        "policy_id": "POL-SPOOF-TEST",
        "fleet_data": {"vehicle_count": 10, "operating_radius_miles": 100.0}
    }


@pytest.fixture
def base_action():
    return [
        {
            "action": {"op": "update_db", "node": "logistics_db", "status": "bound"},
            "rollback": {"op": "revert", "node": "logistics_db", "status": "pending"}
        }
    ]


def test_spoofed_client_attempt_counter_neutralized(orchestrator, base_payload, base_action):
    """
    Validates that if a client repeatedly passes 'attempt_count: 1', the server
    tracks the real attempt count (1, 2, 3, 4) and halts on attempt 4.
    """
    clean_logprobs = [-0.01] * 10
    likelihoods = {"preferred": 0.8, "standard": 0.1, "substandard": 0.1}

    # Attempt 1: Client sends attempt_count=1 -> Allowed
    res1 = orchestrator.process_submission(base_payload, likelihoods, clean_logprobs, base_action)
    assert res1["receipt"]["status"] == "COMMITTED"

    # Simulate retries with injected noise so the transaction fails to complete and increments attempts
    noisy_logprobs = clean_logprobs + [-12.0]

    # Attempt 2: Client again claims attempt_count=1 -> Server tracks attempt 2
    res2 = orchestrator.process_submission(base_payload, likelihoods, noisy_logprobs, base_action)
    assert res2["receipt"]["status"] == "ROLLED_BACK"
    assert res2["receipt"]["attempt_count"] == 2

    # Attempt 3: Client claims attempt_count=1 -> Server tracks attempt 3
    res3 = orchestrator.process_submission(base_payload, likelihoods, noisy_logprobs, base_action)
    assert res3["receipt"]["status"] == "ROLLED_BACK"
    assert res3["receipt"]["attempt_count"] == 3

    # Attempt 4: Server tracks attempt 4 (> max_attempts=3) -> HALTED
    res4 = orchestrator.process_submission(base_payload, likelihoods, clean_logprobs, base_action)
    assert res4["receipt"]["status"] == "HALTED"
    assert res4["receipt"]["reason"] == "EXCEEDED_MAX_ATTEMPTS"
    assert res4["receipt"]["attempt_count"] == 4