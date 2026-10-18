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


def test_missing_provenance_store_fails_closed():
    """
    1. Missing store fails closed and produces zero executable calls and zero side effects.
    """
    execution_callback = MagicMock(return_value={"status": "FORGED"})
    orchestrator = EpistemicOrchestrator()
    orchestrator.execution_boundary.store = None  # Store missing

    raw_payload = {"policy_id": "POL-2026-NO-STORE", "primary_metric": 100.0}
    context = {
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/issue_binder"}}],
        "actual_executable": execution_callback,
        "authorization_token_id": "TOKEN-NO-STORE",
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert "Provenance store missing or lookup unavailable" in res["reason"]
    assert execution_callback.call_count == 0
    assert res["vectors_revoked"] == 0


def test_unavailable_lookup_method_fails_closed():
    """
    2. Unavailable lookup method fails closed.
    """
    execution_callback = MagicMock(return_value={"status": "FORGED"})
    orchestrator = EpistemicOrchestrator()
    # Mock store without get_events_for_correlation method
    orchestrator.execution_boundary.store = object()

    raw_payload = {"policy_id": "POL-2026-NO-METHOD", "primary_metric": 100.0}
    context = {
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/issue_binder"}}],
        "actual_executable": execution_callback,
        "authorization_token_id": "TOKEN-NO-METHOD",
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert "Provenance store missing or lookup unavailable" in res["reason"]
    assert execution_callback.call_count == 0


def test_lookup_exception_fails_closed():
    """
    3. Lookup exception fails closed.
    """
    execution_callback = MagicMock(return_value={"status": "FORGED"})
    orchestrator = EpistemicOrchestrator()
    orchestrator.execution_boundary.store = MagicMock()
    orchestrator.execution_boundary.store.get_events_for_correlation.side_effect = RuntimeError("Database I/O error")

    raw_payload = {"policy_id": "POL-2026-IO-ERR", "primary_metric": 100.0}
    context = {
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/issue_binder"}}],
        "actual_executable": execution_callback,
        "authorization_token_id": "TOKEN-IO-ERR",
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert "Provenance store lookup error" in res["reason"]
    assert execution_callback.call_count == 0


def test_nonexistent_grant_fails_closed():
    """
    4. Nonexistent grant fails closed.
    """
    execution_callback = MagicMock(return_value={"status": "FORGED"})
    orchestrator = EpistemicOrchestrator()

    raw_payload = {"policy_id": "POL-2026-NO-GRANT", "primary_metric": 100.0}
    context = {
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/issue_binder"}}],
        "actual_executable": execution_callback,
        "authorization_token_id": "NONEXISTENT-TOKEN",
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert "No matching AUTHORIZATION_GRANTED record found" in res["reason"]
    assert execution_callback.call_count == 0


def test_forged_grant_fields_denied():
    """
    5. Forged grant fields (caller asserts authorization_granted=True, fake digest) are denied.
    """
    execution_callback = MagicMock(return_value={"status": "FORGED"})
    orchestrator = EpistemicOrchestrator()

    raw_payload = {"policy_id": "POL-2026-FORGE-FIELDS", "primary_metric": 100.0}

    context = {
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/issue_binder"}}],
        "actual_executable": execution_callback,
        "authorization_token_id": "FORGED-TOKEN-999",
        "authorization_granted": True,
        "authorized_digest": "fake_digest_12345",
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert "No matching AUTHORIZATION_GRANTED record found" in res["reason"]
    assert execution_callback.call_count == 0


def test_wrong_correlation_id_denied():
    """
    6. Wrong correlation ID cannot pick up a grant recorded under a different correlation ID.
    """
    execution_callback = MagicMock(return_value={"status": "WRONG_CORR"})
    orchestrator = EpistemicOrchestrator()

    raw_payload = {"policy_id": "POL-2026-WRONG-CORR", "primary_metric": 100.0}
    payload_digest = orchestrator.execution_boundary.compute_canonical_digest(raw_payload)

    token_id = "TOKEN-CORR-111"
    correct_corr = str(uuid.uuid4())
    wrong_corr = str(uuid.uuid4())

    # Grant recorded under correct_corr
    auth_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=correct_corr,
        request_id="req-corr-1",
        action_name="api_call",
        target="/issue_binder",
        canonical_request_digest=payload_digest,
        timestamp="2026-01-01T00:00:00Z",
        authorization_token_id=token_id,
    )
    orchestrator.execution_boundary.store.record_event(auth_event)

    # Context uses wrong_corr
    context = {
        "correlation_id": wrong_corr,
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/issue_binder"}}],
        "actual_executable": execution_callback,
        "authorization_token_id": token_id,
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert "No matching AUTHORIZATION_GRANTED record found" in res["reason"]
    assert execution_callback.call_count == 0


def test_action_target_substitution_denied():
    """
    7. Valid grant for one action/target cannot authorize a substituted action or target.
    """
    execution_callback = MagicMock(return_value={"status": "SUBSTITUTED"})
    orchestrator = EpistemicOrchestrator()
    perm_gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/issue_binder", "/unauthorized_resource"],
        }
    )
    orchestrator.gates = [perm_gate]

    raw_payload = {"policy_id": "POL-2026-SUBST", "primary_metric": 100.0}
    payload_digest = orchestrator.execution_boundary.compute_canonical_digest(raw_payload)

    token_id = "TOKEN-SUBST-222"
    corr_id = str(uuid.uuid4())

    auth_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id="req-subst-1",
        action_name="api_call",
        target="/issue_binder",
        canonical_request_digest=payload_digest,
        timestamp="2026-01-01T00:00:00Z",
        authorization_token_id=token_id,
    )
    orchestrator.execution_boundary.store.record_event(auth_event)

    # Substituted target '/unauthorized_resource'
    context = {
        "correlation_id": corr_id,
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/unauthorized_resource"}}],
        "actual_executable": execution_callback,
        "authorization_token_id": token_id,
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert "Grant mismatch" in res["reason"]
    assert execution_callback.call_count == 0


def test_payload_mutation_after_authorization_denied():
    """
    8. Payload changed after authorization is denied.
    """
    execution_callback = MagicMock(return_value={"status": "MUTATED"})
    orchestrator = EpistemicOrchestrator()
    perm_gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/issue_binder"],
        }
    )
    orchestrator.gates = [perm_gate]

    original_payload = {"policy_id": "POL-2026-ORIG", "primary_metric": 100.0}
    original_digest = orchestrator.execution_boundary.compute_canonical_digest(original_payload)

    token_id = "TOKEN-MUT-333"
    corr_id = str(uuid.uuid4())

    auth_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id="req-mut-1",
        action_name="api_call",
        target="/issue_binder",
        canonical_request_digest=original_digest,
        timestamp="2026-01-01T00:00:00Z",
        authorization_token_id=token_id,
    )
    orchestrator.execution_boundary.store.record_event(auth_event)

    mutated_payload = {"policy_id": "POL-2026-ORIG", "primary_metric": 999999.0}

    context = {
        "correlation_id": corr_id,
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/issue_binder"}}],
        "actual_executable": execution_callback,
        "authorization_token_id": token_id,
    }

    res = orchestrator.process_submission(mutated_payload, context)

    assert res["status"] == "HALTED"
    assert "TrustedExecutionBoundary Enforcement Failed" in res["reason"]
    assert execution_callback.call_count == 0


def test_valid_trusted_grant_executes_exactly_once():
    """
    9. A valid trusted grant executes exactly once when store-backed grant matches.
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

    raw_payload = {"policy_id": "POL-2026-SUCCESS", "primary_metric": 500.0}
    payload_digest = orchestrator.execution_boundary.compute_canonical_digest(raw_payload)

    token_id = "TOKEN-GENUINE-444"
    corr_id = str(uuid.uuid4())

    auth_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id="req-succ-1",
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
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "ALLOWED"
    assert execution_callback.call_count == 1
    assert res["execution_outcome"]["status"] == "SUCCESS"
    assert res["execution_outcome"]["result"] == {"status": "GENUINE_SUCCESS"}


def test_automatic_trusted_grant_issuance_and_execution_contract():
    """
    10. End-to-end positive control:
    - No manual grant pre-seeded.
    - Governance gates pass.
    - Governance path automatically issues AUTHORIZATION_GRANTED event to LocalProvenanceStore.
    - TrustedExecutionBoundary verifies the store-backed grant and executes callback.
    - Synthetic side effect occurs and correlated provenance events are recorded.
    """
    synthetic_sink = []

    def test_callback():
        synthetic_sink.append("MUTATION_EXECUTED")
        return {"status": "SIDE_EFFECT_PRODUCED"}

    orchestrator = EpistemicOrchestrator()
    perm_gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["write_db"],
            "allowed_resources": ["synthetic_table"],
        }
    )
    orchestrator.gates = [perm_gate]

    raw_payload = {"policy_id": "POL-2026-AUTO-GRANT", "primary_metric": 200.0}
    corr_id = f"AUTO-GRANT-CORR-{uuid.uuid4()}"

    context = {
        "correlation_id": corr_id,
        "proposed_actions": [{"action": {"op": "write_db", "endpoint": "synthetic_table"}}],
        "actual_executable": test_callback,
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "ALLOWED"
    assert res["execution_outcome"]["status"] == "SUCCESS"
    assert len(synthetic_sink) == 1
    assert synthetic_sink[0] == "MUTATION_EXECUTED"

    # Verify store-backed grant and execution provenance events exist
    events = orchestrator.execution_boundary.store.get_events_for_correlation(corr_id)
    event_types = [e.event_type for e in events]
    assert "AUTHORIZATION_GRANTED" in event_types
    assert "EXECUTION_STARTED" in event_types
    assert "EXECUTION_SUCCEEDED" in event_types


def test_gate_rejection_prevents_issuance_and_side_effects():
    """
    11. Governance gate rejection prevents grant issuance, callback invocation, and side effects.
    """
    synthetic_sink = []

    def test_callback():
        synthetic_sink.append("UNAUTHORIZED_MUTATION")
        return {"status": "UNAUTHORIZED"}

    orchestrator = EpistemicOrchestrator()
    perm_gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["read_only"],
            "allowed_resources": ["synthetic_table"],
        }
    )
    orchestrator.gates = [perm_gate]

    raw_payload = {"policy_id": "POL-2026-GATE-REJECT", "primary_metric": 200.0}
    corr_id = f"GATE-REJECT-CORR-{uuid.uuid4()}"

    # Proposed action 'write_db' is not allowed by 'read_only' scope
    context = {
        "correlation_id": corr_id,
        "proposed_actions": [{"action": {"op": "write_db", "endpoint": "synthetic_table"}}],
        "actual_executable": test_callback,
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert len(synthetic_sink) == 0  # No forbidden side effect

    # Verify no AUTHORIZATION_GRANTED event was recorded
    events = orchestrator.execution_boundary.store.get_events_for_correlation(corr_id)
    event_types = [e.event_type for e in events]
    assert "AUTHORIZATION_GRANTED" not in event_types
    assert "EXECUTION_STARTED" not in event_types
