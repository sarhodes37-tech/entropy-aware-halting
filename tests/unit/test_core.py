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

def test_cpr_validation_failure_sanitizes_payload():
    """Verifies that sensitive fields are sanitized when CPR validation fails."""
    import json
    orchestrator = EpistemicOrchestrator()
    # Replace audit logger with mock to inspect what it logs
    orchestrator.audit_logger = MagicMock()

    payload = {
        # Missing required field `policy_id` to trigger CPR validation failure
        "fleet_data": {"vehicle_count": 25, "operating_radius_miles": 150},
        "ssn": "123-45-6789",
        "account_number": "1234567890",
        "some_safe_field": "safe_value"
    }
    context = {"token_count": 5, "token_logprobs": [-0.1, -0.12, -0.09]}

    result = orchestrator.process_submission(payload, context)

    assert result["status"] == "HALTED"
    assert result["reason"] == "Schema validation failed"

    orchestrator.audit_logger.record_event.assert_called_once()
    event_arg = orchestrator.audit_logger.record_event.call_args.args[0]

    logged_payload_snippet = event_arg.payload_snippet
    assert logged_payload_snippet is not None

    logged_data = json.loads(logged_payload_snippet)

    assert "ssn" not in logged_data
    assert "account_number" not in logged_data
    assert "some_safe_field" in logged_data
    assert "fleet_data" in logged_data

def test_cpr_validation_failure_non_dict_payload():
    """Verifies that non-dictionary payloads don't crash the validation failure block."""
    import json
    orchestrator = EpistemicOrchestrator()
    orchestrator.audit_logger = MagicMock()

    payload = "malformed"
    context = {"token_count": 5, "token_logprobs": [-0.1, -0.12, -0.09]}

    result = orchestrator.process_submission(payload, context)

    assert result["status"] == "HALTED"
    assert result["reason"] == "Schema validation failed"

    orchestrator.audit_logger.record_event.assert_called_once()
    event_arg = orchestrator.audit_logger.record_event.call_args.args[0]

    logged_payload_snippet = event_arg.payload_snippet
    assert logged_payload_snippet is not None

    logged_data = json.loads(logged_payload_snippet)

    assert logged_data == "malformed"

def test_process_step_halt_true():
    orchestrator = EpistemicOrchestrator()
    orchestrator.scheduler = MagicMock()
    mock_decision = MagicMock()
    mock_decision.halt = True
    orchestrator.scheduler.step.return_value = mock_decision

    result = orchestrator.process_step(None, None, None)

    assert result == mock_decision
    assert result.halt is True
    orchestrator.scheduler.step.assert_called_once_with(None, None, None)

def test_process_step_halt_false():
    orchestrator = EpistemicOrchestrator()
    orchestrator.scheduler = MagicMock()
    mock_decision = MagicMock()
    mock_decision.halt = False
    orchestrator.scheduler.step.return_value = mock_decision

    result = orchestrator.process_step(None, None, None)

    assert result == mock_decision
    assert result.halt is False
    orchestrator.scheduler.step.assert_called_once_with(None, None, None)
