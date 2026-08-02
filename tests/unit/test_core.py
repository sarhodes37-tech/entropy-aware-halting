import pytest
from epistemicos.core import EpistemicOrchestrator

def test_orchestrator_success_pipeline():
    orchestrator = EpistemicOrchestrator()
    payload = {
        "policy_id": "POL-2026-N99",
        "fleet_data": {"vehicle_count": 25, "operating_radius_miles": 150}
    }
    context = {"token_count": 5, "token_logprobs": [-0.1, -0.12, -0.09]}
    
    result = orchestrator.process_submission(payload, context)
    assert result["status"] == "ALLOWED"
    assert "masked_payload" in result

def test_orchestrator_entropy_halt():
    orchestrator = EpistemicOrchestrator()
    payload = {
        "policy_id": "POL-2026-ANOMALY",
        "fleet_data": {"vehicle_count": 10}
    }
    # Injected massive token surprisal anomaly to trip EntropyGate
    context = {"token_count": 5, "token_logprobs": [-0.1, -0.1, -12.5, -0.1]}
    
    result = orchestrator.process_submission(payload, context)
    assert result["status"] == "HALTED"
    assert result["gate"] == "EntropyGate"
