"""
Integration test suite for EpistemicOS Pipeline & EntropyAwareScheduler gamma sweeps
and noisy payload handling within the unified architecture.
"""

import json
from pathlib import Path
import pytest
from epistemicos.core import EpistemicOrchestrator
from epistemicos.audit import TamperEvidentAuditTrail, AuditLogLevel


def test_orchestrator_noisy_surprisal_halt_and_rollback(tmp_path):
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

    # Core Assertions
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

    # Record sample trace events to check chain and logging structure
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
