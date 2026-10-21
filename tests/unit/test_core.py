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


def test_reset_trajectory_existing_trajectory():
    """Verifies that reset_trajectory calls reset on the scheduler and removes it and its lock."""
    orchestrator = EpistemicOrchestrator()
    traj_id = "test-traj-123"

    scheduler = orchestrator.get_trajectory_scheduler(traj_id)
    # Put some dummy state via process_step
    orchestrator.process_step([0.8, 0.2], cost=0.1, state="step1", trajectory_id=traj_id)

    mock_scheduler = MagicMock(wraps=scheduler)
    orchestrator._schedulers[traj_id] = mock_scheduler

    assert traj_id in orchestrator._schedulers
    assert traj_id in orchestrator._trajectory_locks

    orchestrator.reset_trajectory(traj_id)

    mock_scheduler.reset.assert_called_once()
    assert traj_id not in orchestrator._schedulers
    assert traj_id not in orchestrator._trajectory_locks


def test_reset_trajectory_non_existent_trajectory():
    """Verifies that reset_trajectory on a non-existent trajectory ID operates gracefully without raising errors."""
    orchestrator = EpistemicOrchestrator()
    non_existent_id = "non-existent-traj-999"

    assert non_existent_id not in orchestrator._schedulers
    assert non_existent_id not in orchestrator._trajectory_locks

    # Should execute cleanly
    orchestrator.reset_trajectory(non_existent_id)

    assert non_existent_id not in orchestrator._schedulers
    assert non_existent_id not in orchestrator._trajectory_locks


def test_retire_trajectory_alias():
    """Verifies that retire_trajectory delegates to reset_trajectory to retire trajectory state."""
    orchestrator = EpistemicOrchestrator()
    orchestrator.reset_trajectory = MagicMock()

    orchestrator.retire_trajectory("traj-to-retire")
    orchestrator.reset_trajectory.assert_called_once_with("traj-to-retire")


def test_reset_trajectory_reinstantiates_fresh_state():
    """Verifies that accessing a trajectory scheduler after resetting it creates a fresh state."""
    orchestrator = EpistemicOrchestrator()
    traj_id = "traj-reinstantiate"

    sched1 = orchestrator.get_trajectory_scheduler(traj_id)
    orchestrator.process_step([0.6, 0.4], cost=0.5, state="step1", trajectory_id=traj_id)
    assert len(sched1.utility_history) > 0

    orchestrator.reset_trajectory(traj_id)
    assert traj_id not in orchestrator._schedulers

    sched2 = orchestrator.get_trajectory_scheduler(traj_id)
    assert sched2 is not sched1
    assert len(sched2.utility_history) == 0


def test_reset_schedulers_clears_all_trajectories_and_base():
    """Verifies that reset_schedulers resets all managed trajectories and base/default scheduler state."""
    orchestrator = EpistemicOrchestrator()

    orchestrator.get_trajectory_scheduler("traj-A")
    orchestrator.get_trajectory_scheduler("traj-B")

    mock_base = MagicMock()
    orchestrator._base_scheduler = mock_base
    orchestrator.scheduler = mock_base

    orchestrator.reset_schedulers()

    assert len(orchestrator._schedulers) == 0
    assert len(orchestrator._trajectory_locks) == 0
    mock_base.reset.assert_called()
