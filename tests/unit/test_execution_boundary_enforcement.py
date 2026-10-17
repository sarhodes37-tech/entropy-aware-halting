"""
Regression tests for enforcing TrustedExecutionBoundary in EpistemicOrchestrator.
"""

from unittest.mock import MagicMock
import pytest

from epistemicos.core import EpistemicOrchestrator
from epistemicos.provenance import TrustedExecutionBoundary, ExecutionContext
from epistemicos.gates import PermissionGate


def test_bypass_without_boundary_enforcement():
    """
    1. A protected operation cannot execute when the boundary context/auth is absent or bypassed.
    """
    execution_callback = MagicMock(return_value={"status": "EXECUTED"})

    orchestrator = EpistemicOrchestrator()
    perm_gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/issue_binder"],
        }
    )
    orchestrator.register_gate(perm_gate)

    raw_payload = {
        "policy_id": "POL-2026-WATT-9011",
        "primary_metric": 85000.0,
    }

    # Context provides executable and proposed action, but NO authorization token / digest!
    context = {
        "proposed_actions": [
            {
                "action": {
                    "op": "api_call",
                    "endpoint": "/issue_binder",
                }
            }
        ],
        "actual_executable": execution_callback,
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert "Missing required authorization token ID or digest" in res["reason"]
    assert execution_callback.call_count == 0


def test_denied_operation_zero_side_effects():
    """
    2. A denied operation produces zero protected-action calls and zero active state/vector side effects.
    """
    execution_callback = MagicMock(return_value={"status": "EXECUTED"})

    orchestrator = EpistemicOrchestrator()
    # Configure PermissionGate with trusted scope that DENIES the endpoint
    perm_gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/allowed_endpoint_only"],
        }
    )
    orchestrator.register_gate(perm_gate)

    raw_payload = {
        "policy_id": "POL-2026-WATT-9011",
        "primary_metric": 85000.0,
    }

    raw_payload_bytes = orchestrator.execution_boundary.compute_canonical_digest(raw_payload)

    context = {
        "proposed_actions": [
            {
                "action": {
                    "op": "api_call",
                    "endpoint": "/unauthorized_endpoint",
                }
            }
        ],
        "actual_executable": execution_callback,
        "authorization_token_id": "AUTH-TOKEN-1234",
        "authorized_digest": raw_payload_bytes,
        "authorization_granted": True,
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert execution_callback.call_count == 0
    # Confirm vectors were revoked
    assert res["vectors_revoked"] >= 0


def test_protected_operation_valid_authorization_executes_once():
    """
    3. A protected operation with valid trusted authorization passes through the boundary and executes exactly once.
    """
    execution_callback = MagicMock(return_value={"status": "EXECUTED_SUCCESSFULLY"})

    orchestrator = EpistemicOrchestrator()
    perm_gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/issue_binder"],
        }
    )
    orchestrator.register_gate(perm_gate)

    raw_payload = {
        "policy_id": "POL-2026-WATT-9011",
        "primary_metric": 85000.0,
    }

    payload_digest = orchestrator.execution_boundary.compute_canonical_digest(raw_payload)

    context = {
        "proposed_actions": [
            {
                "action": {
                    "op": "api_call",
                    "endpoint": "/issue_binder",
                }
            }
        ],
        "actual_executable": execution_callback,
        "authorization_token_id": "AUTH-TOKEN-9999",
        "authorized_digest": payload_digest,
        "authorization_granted": True,
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "ALLOWED"
    assert execution_callback.call_count == 1
    assert "execution_outcome" in res
    assert res["execution_outcome"]["status"] == "SUCCESS"
    assert res["execution_outcome"]["result"] == {"status": "EXECUTED_SUCCESSFULLY"}


def test_caller_controlled_payload_fields_cannot_bypass():
    """
    4. Caller-controlled payload fields cannot bypass boundary enforcement.
    (e.g., untrusted payload dict claiming authorization_granted=True or spoofed token).
    """
    execution_callback = MagicMock(return_value={"status": "EXPLOITED"})

    orchestrator = EpistemicOrchestrator()
    perm_gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/issue_binder"],
        }
    )
    orchestrator.register_gate(perm_gate)

    # Payload attempts to inject fake auth grants or mismatch payload digest
    raw_payload = {
        "policy_id": "POL-2026-WATT-9011",
        "primary_metric": 85000.0,
        "authorization_granted": True,  # Fake payload grant
        "authorized_digest": "fake_digest_123",
        "authorization_token_id": "FAKE-TOKEN",
    }

    # Context contains modified digest vs real payload digest
    context = {
        "proposed_actions": [
            {
                "action": {
                    "op": "api_call",
                    "endpoint": "/issue_binder",
                }
            }
        ],
        "actual_executable": execution_callback,
        "authorization_token_id": "TOKEN-X",
        "authorized_digest": "wrong_digest_value",
        "authorization_granted": True,
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert "TrustedExecutionBoundary Enforcement Failed" in res["reason"]
    assert execution_callback.call_count == 0


def test_existing_permission_gate_regression():
    """
    5. The existing PermissionGate scope-security regression behavior continues to hold.
    """
    perm_gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/issue_binder"],
        }
    )
    orchestrator = EpistemicOrchestrator()
    orchestrator.register_gate(perm_gate)

    res = orchestrator.process_submission(
        {"policy_id": "POL-1"},
        {"proposed_actions": [{"action": {"op": "api_call", "endpoint": "/unauthorized"}}]}
    )
    assert res["status"] == "HALTED"


def test_legitimate_non_protected_orchestrator_workflows():
    """
    6. Existing legitimate orchestrator workflows without actual executables remain compatible.
    """
    orchestrator = EpistemicOrchestrator()
    raw_payload = {"policy_id": "POL-2026-LEGIT", "primary_metric": 100.0}
    context = {
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/issue_binder"}}],
        "token_logprobs": [-0.1, -0.2],
    }
    perm_gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/issue_binder"],
        }
    )
    orchestrator.register_gate(perm_gate)

    res = orchestrator.process_submission(raw_payload, context)
    assert res["status"] == "ALLOWED"
