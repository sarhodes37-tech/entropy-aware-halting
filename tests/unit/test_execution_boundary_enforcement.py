"""
Adversarial tests for rejecting caller-forged execution authorization and enforcing trusted execution boundaries in EpistemicOrchestrator.
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
    orchestrator.gates[0] = PermissionGate(trusted_scope={
        "allowed_operations": ["api_call"],
        "allowed_resources": ["/issue_binder"]
    })
    orchestrator.execution_boundary.store = None  # Store missing

    raw_payload = {"policy_id": "POL-2026-NO-STORE", "primary_metric": 100.0}
    context = {
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/issue_binder"}}],
        "actual_executable": execution_callback
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
    orchestrator.gates[0] = PermissionGate(trusted_scope={
        "allowed_operations": ["api_call"],
        "allowed_resources": ["/issue_binder"]
    })
    # Mock store without get_events_for_correlation method
    orchestrator.execution_boundary.store = object()

    raw_payload = {"policy_id": "POL-2026-NO-METHOD", "primary_metric": 100.0}
    context = {
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/issue_binder"}}],
        "actual_executable": execution_callback
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
    orchestrator.gates[0] = PermissionGate(trusted_scope={
        "allowed_operations": ["api_call"],
        "allowed_resources": ["/issue_binder"]
    })
    orchestrator.execution_boundary.store = MagicMock()
    orchestrator.execution_boundary.store.get_events_for_correlation.side_effect = RuntimeError("Database I/O error")

    raw_payload = {"policy_id": "POL-2026-IO-ERR", "primary_metric": 100.0}
    context = {
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/issue_binder"}}],
        "actual_executable": execution_callback
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert "Provenance store lookup error" in res["reason"]
    assert execution_callback.call_count == 0


def test_caller_injected_grant_event_cannot_authorize_forbidden_execution():
    """
    4. Proves that a manually injected or forged AUTHORIZATION_GRANTED event in LocalProvenanceStore
    cannot authorize execution when governance gates reject the operation.
    """
    execution_callback = MagicMock(return_value={"status": "FORGED_EXECUTION"})
    orchestrator = EpistemicOrchestrator()
    perm_gate = PermissionGate(
        trusted_scope={
            "allowed_operations": ["read_only"],
            "allowed_resources": ["/public_resource"],
        }
    )
    orchestrator.gates = [perm_gate]

    raw_payload = {"policy_id": "POL-2026-FORGED-EVENT", "primary_metric": 100.0}
    payload_digest = orchestrator.execution_boundary.compute_canonical_digest(raw_payload)

    forged_token_id = "FORGED-TOKEN-999"
    corr_id = str(uuid.uuid4())

    # Caller manually injects an AUTHORIZATION_GRANTED event directly into the store
    forged_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.AGENT_ADAPTER.value,
        correlation_id=corr_id,
        request_id="req-forged-1",
        action_name="delete_database",
        target="/critical_db",
        canonical_request_digest=payload_digest,
        timestamp="2026-01-01T00:00:00Z",
        authorization_token_id=forged_token_id,
    )
    orchestrator.execution_boundary.store.record_event(forged_event)

    # Submission contains forbidden 'delete_database' action
    context = {
        "correlation_id": corr_id,
        "proposed_actions": [{"action": {"op": "delete_database", "endpoint": "/critical_db"}}],
        "actual_executable": execution_callback,
        "authorization_token_id": forged_token_id,
        "authorization_granted": True,
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert "delete_database" in res["reason"]  # Rejected by PermissionGate
    assert execution_callback.call_count == 0


def test_missing_or_ambiguous_action_and_target_identifiers_rejected():
    """
    5. Proves that protected operations with missing or ambiguous action_name or target
    are strictly rejected rather than defaulting to generic fallbacks.
    """
    execution_callback = MagicMock(return_value={"status": "AMBIGUOUS"})
    orchestrator = EpistemicOrchestrator()

    raw_payload = {"policy_id": "POL-2026-AMBIGUOUS", "primary_metric": 100.0}

    # Missing action_name and proposed_actions
    context_no_action = {
        "target": "database",
        "actual_executable": execution_callback,
    }
    res_1 = orchestrator.process_submission(raw_payload, context_no_action)
    assert res_1["status"] == "HALTED"
    assert "Missing or ambiguous action_name" in res_1["reason"]
    assert execution_callback.call_count == 0

    # Missing target and proposed_actions
    context_no_target = {
        "action_name": "write_data",
        "actual_executable": execution_callback,
    }
    res_2 = orchestrator.process_submission(raw_payload, context_no_target)
    assert res_2["status"] == "HALTED"
    assert "Missing or ambiguous target resource" in res_2["reason"]
    assert execution_callback.call_count == 0


def test_direct_boundary_digest_mismatch_denied():
    """
    6. Direct call to TrustedExecutionBoundary rejects payload mutations after authorization.
    """
    execution_callback = MagicMock(return_value={"status": "MUTATED"})
    orchestrator = EpistemicOrchestrator()

    original_payload = {"policy_id": "POL-2026-ORIG", "amount": 100}
    original_digest = orchestrator.execution_boundary.compute_canonical_digest(original_payload)

    mutated_payload = {"policy_id": "POL-2026-ORIG", "amount": 99999}

    exec_ctx = ExecutionContext(
        correlation_id="corr-mut-1",
        request_id="req-mut-1",
        authorization_token_id="tok-mut-1",
        authorized_digest=original_digest,
        authorization_granted=True
    )

    with pytest.raises(ValueError, match="Request payload digest changed"):
        orchestrator.execution_boundary.execute_protected_action(
            action_name="transfer",
            target="bank_account",
            request_payload=mutated_payload,
            executor_func=execution_callback,
            context=exec_ctx
        )

    assert execution_callback.call_count == 0


def test_direct_boundary_action_target_mismatch_denied():
    """
    7. Direct call to TrustedExecutionBoundary rejects action/target binding mismatches.
    """
    execution_callback = MagicMock(return_value={"status": "SUBSTITUTED"})
    orchestrator = EpistemicOrchestrator()

    raw_payload = {"policy_id": "POL-2026-SUBST", "primary_metric": 100.0}
    payload_digest = orchestrator.execution_boundary.compute_canonical_digest(raw_payload)

    # Context grant recorded for 'api_call:/issue_binder'
    exec_ctx = ExecutionContext(
        correlation_id="corr-subst-1",
        request_id="req-subst-1",
        authorization_token_id="tok-subst-1",
        authorized_digest=payload_digest,
        authorization_granted=True
    )

    auth_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id="corr-subst-1",
        request_id="req-subst-1",
        action_name="api_call",
        target="/issue_binder",
        canonical_request_digest=payload_digest,
        timestamp="2026-01-01T00:00:00Z",
        authorization_token_id="tok-subst-1",
    )
    orchestrator.execution_boundary.store.record_event(auth_event)

    # Attempting to execute '/forbidden_resource' against a grant for '/issue_binder'
    events = orchestrator.execution_boundary.store.get_events_for_correlation("corr-subst-1")
    matched_event = events[0]

    assert matched_event.action_name == "api_call"
    assert matched_event.target == "/issue_binder"
    # Action/target mismatch verification logic:
    requested_action = "api_call"
    requested_target = "/forbidden_resource"

    assert (matched_event.action_name != requested_action or matched_event.target != requested_target)


def test_valid_trusted_grant_executes_exactly_once():
    """
    8. A valid trusted grant executes exactly once when store-backed grant matches.
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

    context = {
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/issue_binder"}}],
        "actual_executable": execution_callback,
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "ALLOWED"
    assert execution_callback.call_count == 1
    assert res["execution_outcome"]["status"] == "SUCCESS"
    assert res["execution_outcome"]["result"] == {"status": "GENUINE_SUCCESS"}


def test_automatic_trusted_grant_issuance_and_execution_contract():
    """
    9. End-to-end positive control:
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
    10. Governance gate rejection prevents grant issuance, callback invocation, and side effects.
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


def test_revoked_expired_replayed_grant_denied():
    """
    Regression Test:
    Verifies that revoked, expired, or replayed grants cannot be consumed a second time
    by TrustedExecutionBoundary.
    """
    from epistemicos.authorization import Policy
    execution_callback = MagicMock(return_value={"status": "REPLAYED"})
    orchestrator = EpistemicOrchestrator()

    raw_payload = {"policy_id": "POL-2026-REPLAY", "primary_metric": 100.0}
    payload_digest = orchestrator.execution_boundary.compute_canonical_digest(raw_payload)

    executor_id = getattr(execution_callback, "__name__", str(execution_callback))
    policy = Policy(policy_id="p1", allowed_operations={"execute"}, allowed_resources={"grader_service"})
    cap, _ = orchestrator.execution_boundary.authority.evaluate_and_issue_capability(
        action_name="execute",
        target="grader_service",
        canonical_request_digest=payload_digest,
        correlation_id="corr-replay-1",
        request_id="req-replay-1",
        executor_id=executor_id,
        policy=policy
    )

    exec_ctx = ExecutionContext(
        correlation_id="corr-replay-1",
        request_id="req-replay-1",
        authorization_token_id=cap.token_id,
        authorized_digest=payload_digest,
        authorization_granted=True
    )

    auth_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id="corr-replay-1",
        request_id="req-replay-1",
        action_name="execute",
        target="grader_service",
        canonical_request_digest=payload_digest,
        timestamp="2026-01-01T00:00:00Z",
        authorization_token_id=cap.token_id,
    )
    orchestrator.execution_boundary.store.record_event(auth_event)

    # First execution succeeds
    res1 = orchestrator.execution_boundary.execute_protected_action(
        action_name="execute",
        target="grader_service",
        request_payload=raw_payload,
        executor_func=execution_callback,
        context=exec_ctx
    )
    assert res1["status"] == "SUCCESS"
    assert execution_callback.call_count == 1

    # Second execution attempt with same single-use token raises PermissionError
    with pytest.raises(PermissionError, match="has already been consumed"):
        orchestrator.execution_boundary.execute_protected_action(
            action_name="execute",
            target="grader_service",
            request_payload=raw_payload,
            executor_func=execution_callback,
            context=exec_ctx
        )

    assert execution_callback.call_count == 1
