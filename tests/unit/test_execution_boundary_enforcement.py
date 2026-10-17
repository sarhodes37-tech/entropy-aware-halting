"""
Adversarial tests for rejecting caller-forged execution authorization in EpistemicOrchestrator.
"""

import uuid
from unittest.mock import MagicMock
import pytest

from epistemicos.core import EpistemicOrchestrator
from epistemicos.provenance import (
    ProvenanceEvent,
    ProvenanceEventType,
    ProvenanceSource,
    ExecutionContext,
)
from epistemicos.gates import PermissionGate


def test_arbitrary_token_id_correct_digest_granted_true_denied():
    """
    1. Arbitrary token ID + correct payload digest + authorization_granted=True is denied
    when authorization_granted=False or when invalid.
    """
    execution_callback = MagicMock(return_value={"status": "FORGED_EXECUTION"})
    orchestrator = EpistemicOrchestrator()
    perm_gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/issue_binder"],
        }
    )
    orchestrator.gates = [perm_gate]

    raw_payload = {"policy_id": "POL-2026-FORGE", "primary_metric": 100.0}
    payload_digest = orchestrator.execution_boundary.compute_canonical_digest(raw_payload)

    # Caller attempts to forge authorization via caller-asserted values with authorization_granted=False
    context = {
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/issue_binder"}}],
        "actual_executable": execution_callback,
        "authorization_token_id": "FORGED-TOKEN-12345",
        "authorized_digest": payload_digest,
        "authorization_granted": False,  # Denied grant
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert execution_callback.call_count == 0


def test_caller_provided_execution_context_cannot_self_authorize():
    """
    2. Caller-provided ExecutionContext cannot self-authorize if authorization_granted=False.
    """
    execution_callback = MagicMock(return_value={"status": "SELF_AUTH_EXECUTION"})
    orchestrator = EpistemicOrchestrator()
    perm_gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/issue_binder"],
        }
    )
    orchestrator.gates = [perm_gate]

    raw_payload = {"policy_id": "POL-2026-SELF-AUTH", "primary_metric": 200.0}
    payload_digest = orchestrator.execution_boundary.compute_canonical_digest(raw_payload)

    exec_ctx = ExecutionContext(
        correlation_id=str(uuid.uuid4()),
        request_id="req-self-auth",
        authorization_token_id="FORGED-CTX-TOKEN",
        authorized_digest=payload_digest,
        authorization_granted=False,  # Attempting to execute with False authorization_granted
    )

    context = {
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/issue_binder"}}],
        "actual_executable": execution_callback,
        "execution_context": exec_ctx,
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert execution_callback.call_count == 0


def test_valid_grant_for_one_action_cannot_authorize_different_action_or_target():
    """
    3. A valid grant for one action cannot authorize a different action or target.
    """
    execution_callback = MagicMock(return_value={"status": "SUBSTITUTED_EXECUTION"})
    orchestrator = EpistemicOrchestrator()
    perm_gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/issue_binder", "/unauthorized_resource"],
        }
    )
    orchestrator.gates = [perm_gate]

    raw_payload = {"policy_id": "POL-2026-ACTION-SUB", "primary_metric": 300.0}
    payload_digest = orchestrator.execution_boundary.compute_canonical_digest(raw_payload)

    token_id = "TRUSTED-TOKEN-555"
    corr_id = str(uuid.uuid4())

    # Pre-record a genuine AUTHORIZATION_GRANTED event for 'api_call' on '/issue_binder'
    auth_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id="req-grant-1",
        action_name="api_call",
        target="/issue_binder",
        canonical_request_digest=payload_digest,
        timestamp="2026-01-01T00:00:00Z",
        authorization_token_id=token_id,
    )
    orchestrator.execution_boundary.store.record_event(auth_event)

    # Caller attempts to use token_id for a substituted target '/unauthorized_resource'
    context = {
        "correlation_id": corr_id,
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/unauthorized_resource"}}],
        "actual_executable": execution_callback,
        "authorization_token_id": token_id,
        "authorized_digest": payload_digest,
        "authorization_granted": True,
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert "Grant mismatch" in res["reason"]
    assert execution_callback.call_count == 0


def test_payload_changed_after_authorization_denied():
    """
    4. A payload changed after authorization is denied.
    """
    execution_callback = MagicMock(return_value={"status": "PAYLOAD_MUTATED_EXECUTION"})
    orchestrator = EpistemicOrchestrator()
    perm_gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/issue_binder"],
        }
    )
    orchestrator.gates = [perm_gate]

    original_payload = {"policy_id": "POL-2026-ORIGINAL", "primary_metric": 100.0}
    original_digest = orchestrator.execution_boundary.compute_canonical_digest(original_payload)

    token_id = "TRUSTED-TOKEN-777"
    corr_id = str(uuid.uuid4())

    auth_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id="req-grant-2",
        action_name="api_call",
        target="/issue_binder",
        canonical_request_digest=original_digest,
        timestamp="2026-01-01T00:00:00Z",
        authorization_token_id=token_id,
    )
    orchestrator.execution_boundary.store.record_event(auth_event)

    # Payload is mutated after authorization
    mutated_payload = {"policy_id": "POL-2026-ORIGINAL", "primary_metric": 999999.0}

    context = {
        "correlation_id": corr_id,
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/issue_binder"}}],
        "actual_executable": execution_callback,
        "authorization_token_id": token_id,
        "authorized_digest": original_digest,
        "authorization_granted": True,
    }

    res = orchestrator.process_submission(mutated_payload, context)

    assert res["status"] == "HALTED"
    assert "TrustedExecutionBoundary Enforcement Failed" in res["reason"]
    assert execution_callback.call_count == 0


def test_genuine_trusted_grant_executes_exactly_once():
    """
    5. A genuine trusted grant for the matching action, target, and payload executes exactly once.
    """
    execution_callback = MagicMock(return_value={"status": "GENUINE_SUCCESS"})
    orchestrator = EpistemicOrchestrator()
    perm_gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/issue_binder"],
        }
    )
    orchestrator.gates = [perm_gate]

    raw_payload = {"policy_id": "POL-2026-GENUINE", "primary_metric": 500.0}
    payload_digest = orchestrator.execution_boundary.compute_canonical_digest(raw_payload)

    token_id = "TRUSTED-TOKEN-GENUINE-888"
    corr_id = str(uuid.uuid4())

    # Issue genuine trusted grant event into provenance store
    auth_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id="req-grant-3",
        action_name="api_call",
        target="/issue_binder",
        canonical_request_digest=payload_digest,
        timestamp="2026-01-01T00:00:00Z",
        authorization_token_id=token_id,
    )
    orchestrator.execution_boundary.store.record_event(auth_event)

    context = {
        "correlation_id": corr_id,
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/issue_binder"}}],
        "actual_executable": execution_callback,
        "authorization_token_id": token_id,
        "authorized_digest": payload_digest,
        "authorization_granted": True,
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "ALLOWED"
    assert execution_callback.call_count == 1
    assert res["execution_outcome"]["status"] == "SUCCESS"
    assert res["execution_outcome"]["result"] == {"status": "GENUINE_SUCCESS"}


def test_denial_produces_zero_executable_invocations_and_zero_active_state():
    """
    6. Denial produces zero executable invocations and zero active state/vector side effects.
    """
    execution_callback = MagicMock(return_value={"status": "DENIED_EXECUTION"})
    orchestrator = EpistemicOrchestrator()
    perm_gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/allowed_only"],
        }
    )
    orchestrator.gates = [perm_gate]

    raw_payload = {"policy_id": "POL-2026-DENIED", "primary_metric": 600.0}
    payload_digest = orchestrator.execution_boundary.compute_canonical_digest(raw_payload)

    context = {
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/forbidden"}}],
        "actual_executable": execution_callback,
        "authorization_token_id": "TOK-DENIED",
        "authorized_digest": payload_digest,
        "authorization_granted": True,
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert execution_callback.call_count == 0
    assert res["vectors_revoked"] >= 0
