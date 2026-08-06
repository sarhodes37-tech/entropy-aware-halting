import pytest
from unittest.mock import MagicMock
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

def test_register_gate_appends_to_pipeline():
    """Verifies that register_gate correctly initializes the list and appends a new gate."""
    orchestrator = EpistemicOrchestrator()
    
    # Create a dummy mock gate
    dummy_gate = MagicMock()
    dummy_gate.name = "TestGate"
    
    # Capture initial state 
    initial_length = len(orchestrator.gates) if hasattr(orchestrator, "gates") and orchestrator.gates is not None else 0
    
    # Execute the method
    orchestrator.register_gate(dummy_gate)
    
    # Assert the attribute was updated and the gate was appended
    assert hasattr(orchestrator, "gates")
    assert orchestrator.gates is not None
    assert dummy_gate in orchestrator.gates
    assert len(orchestrator.gates) == initial_length + 1
