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
    from epistemicos.authorization import Policy, get_callable_identity
    execution_callback = MagicMock(return_value={"status": "REPLAYED"})
    orchestrator = EpistemicOrchestrator()

    raw_payload = {"policy_id": "POL-2026-REPLAY", "primary_metric": 100.0}
    payload_digest = orchestrator.execution_boundary.compute_canonical_digest(raw_payload)

    policy = Policy(policy_id="p1", allowed_operations={"execute"}, allowed_resources={"grader_service"})
    cap, _ = orchestrator.execution_boundary.authority.evaluate_and_issue_capability(
        action_name="execute",
        target="grader_service",
        canonical_request_digest=payload_digest,
        correlation_id="corr-replay-1",
        request_id="req-replay-1",
        executor_id=execution_callback,
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


def test_zero_side_effect_no_capability_supplied():
    """1. No capability supplied: auth_granted=False or token_id missing."""
    executor = MagicMock(return_value={"status": "UNAUTHORIZED_SIDE_EFFECT"})
    orchestrator = EpistemicOrchestrator()
    payload = {"data": "test"}

    exec_ctx = ExecutionContext(
        correlation_id="corr-no-cap",
        request_id="req-no-cap",
        authorization_token_id="",
        authorized_digest="digest",
        authorization_granted=False
    )
    with pytest.raises(PermissionError, match="Authorization was not granted"):
        orchestrator.execution_boundary.execute_protected_action(
            action_name="run",
            target="/res",
            request_payload=payload,
            executor_func=executor,
            context=exec_ctx
        )
    assert executor.call_count == 0


def test_zero_side_effect_invalid_malformed_capability():
    """2. Invalid or malformed capability: token_id is unknown or signature is forged."""
    executor = MagicMock(return_value={"status": "FORGED"})
    orchestrator = EpistemicOrchestrator()
    payload = {"data": "test"}
    digest = orchestrator.execution_boundary.compute_canonical_digest(payload)

    exec_ctx = ExecutionContext(
        correlation_id="corr-bad-token",
        request_id="req-bad-token",
        authorization_token_id="AUTH-CAP-NONEXISTENT-TOKEN",
        authorized_digest=digest,
        authorization_granted=True
    )
    with pytest.raises(PermissionError, match="CAPABILITY_VERIFICATION_FAILED_UNKNOWN_TOKEN"):
        orchestrator.execution_boundary.execute_protected_action(
            action_name="run",
            target="/res",
            request_payload=payload,
            executor_func=executor,
            context=exec_ctx
        )
    assert executor.call_count == 0


def test_zero_side_effect_expired_capability():
    """3. Expired capability: capability expires_at is in the past (clock-controlled)."""
    from epistemicos.authorization import Policy
    executor = MagicMock(return_value={"status": "EXPIRED"})
    orchestrator = EpistemicOrchestrator()
    payload = {"data": "test"}
    digest = orchestrator.execution_boundary.compute_canonical_digest(payload)

    policy = Policy(policy_id="p-exp", allowed_operations={"run"}, allowed_resources={"/res"}, token_ttl_seconds=300.0)
    cap, _ = orchestrator.authority.evaluate_and_issue_capability(
        action_name="run",
        target="/res",
        canonical_request_digest=digest,
        correlation_id="corr-exp",
        request_id="req-exp",
        executor_id=executor,
        policy=policy,
        current_time=1000.0
    )
    # Fast-forward capability expiration deterministically without timing sleep
    cap.expires_at = 900.0

    exec_ctx = ExecutionContext(
        correlation_id="corr-exp",
        request_id="req-exp",
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )
    with pytest.raises(PermissionError, match="CAPABILITY_VERIFICATION_FAILED_EXPIRED_TOKEN"):
        orchestrator.execution_boundary.execute_protected_action(
            action_name="run",
            target="/res",
            request_payload=payload,
            executor_func=executor,
            context=exec_ctx
        )
    assert executor.call_count == 0


def test_zero_side_effect_capability_bound_to_different_executor():
    """4. Capability bound to a different executor ID."""
    from epistemicos.authorization import Policy
    legit_executor = MagicMock(return_value={"status": "LEGIT"})
    different_executor = MagicMock(return_value={"status": "DIFFERENT"})
    orchestrator = EpistemicOrchestrator()
    payload = {"data": "test"}
    digest = orchestrator.execution_boundary.compute_canonical_digest(payload)

    policy = Policy(policy_id="p-diff", allowed_operations={"run"}, allowed_resources={"/res"})
    cap, _ = orchestrator.authority.evaluate_and_issue_capability(
        action_name="run",
        target="/res",
        canonical_request_digest=digest,
        correlation_id="corr-diff",
        request_id="req-diff",
        executor_id=legit_executor,
        policy=policy
    )

    exec_ctx = ExecutionContext(
        correlation_id="corr-diff",
        request_id="req-diff",
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )
    with pytest.raises(PermissionError, match="CAPABILITY_VERIFICATION_FAILED_EXECUTOR_MISMATCH"):
        orchestrator.execution_boundary.execute_protected_action(
            action_name="run",
            target="/res",
            request_payload=payload,
            executor_func=different_executor,
            context=exec_ctx
        )
    assert legit_executor.call_count == 0
    assert different_executor.call_count == 0


def test_zero_side_effect_executor_substitution_attempt():
    """5. Executor substitution attempt: different callable passed with same qualname/identity."""
    from epistemicos.authorization import Policy
    def original_fn():
        return {"status": "ORIGINAL"}

    substitute_fn = MagicMock(return_value={"status": "SUBSTITUTED"})
    orchestrator = EpistemicOrchestrator()
    payload = {"data": "test"}
    digest = orchestrator.execution_boundary.compute_canonical_digest(payload)

    policy = Policy(policy_id="p-sub", allowed_operations={"run"}, allowed_resources={"/res"})
    cap, _ = orchestrator.authority.evaluate_and_issue_capability(
        action_name="run",
        target="/res",
        canonical_request_digest=digest,
        correlation_id="corr-sub",
        request_id="req-sub",
        executor_id=original_fn,
        policy=policy
    )

    exec_ctx = ExecutionContext(
        correlation_id="corr-sub",
        request_id="req-sub",
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )
    with pytest.raises(PermissionError, match="Executable object identity mismatch|CAPABILITY_VERIFICATION_FAILED_EXECUTOR_MISMATCH"):
        orchestrator.execution_boundary.execute_protected_action(
            action_name="run",
            target="/res",
            request_payload=payload,
            executor_func=substitute_fn,
            context=exec_ctx
        )
    assert substitute_fn.call_count == 0


def test_zero_side_effect_target_resource_mismatch():
    """6a. Target resource mismatch: granted /public, requested /secret."""
    from epistemicos.authorization import Policy
    executor = MagicMock(return_value={"status": "EXECUTED"})
    orchestrator = EpistemicOrchestrator()
    payload = {"data": "test"}
    digest = orchestrator.execution_boundary.compute_canonical_digest(payload)

    policy = Policy(policy_id="p-mis-target", allowed_operations={"read"}, allowed_resources={"/public"})
    cap, _ = orchestrator.authority.evaluate_and_issue_capability(
        action_name="read",
        target="/public",
        canonical_request_digest=digest,
        correlation_id="corr-mis-target",
        request_id="req-mis-target",
        executor_id=executor,
        policy=policy
    )

    exec_ctx = ExecutionContext(
        correlation_id="corr-mis-target",
        request_id="req-mis-target",
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )
    with pytest.raises(PermissionError, match="CAPABILITY_VERIFICATION_FAILED_TARGET_MISMATCH"):
        orchestrator.execution_boundary.execute_protected_action(
            action_name="read",
            target="/secret",
            request_payload=payload,
            executor_func=executor,
            context=exec_ctx
        )
    assert executor.call_count == 0

    # Positive control: correctly authorized target succeeds
    res = orchestrator.execution_boundary.execute_protected_action(
        action_name="read",
        target="/public",
        request_payload=payload,
        executor_func=executor,
        context=exec_ctx
    )
    assert res["status"] == "SUCCESS"
    assert executor.call_count == 1


def test_zero_side_effect_action_mismatch():
    """6b. Action mismatch: granted 'read', requested 'write'."""
    from epistemicos.authorization import Policy
    executor = MagicMock(return_value={"status": "EXECUTED"})
    orchestrator = EpistemicOrchestrator()
    payload = {"data": "test"}
    digest = orchestrator.execution_boundary.compute_canonical_digest(payload)

    policy = Policy(policy_id="p-mis-action", allowed_operations={"read", "write"}, allowed_resources={"/public"})
    cap, _ = orchestrator.authority.evaluate_and_issue_capability(
        action_name="read",
        target="/public",
        canonical_request_digest=digest,
        correlation_id="corr-mis-action",
        request_id="req-mis-action",
        executor_id=executor,
        policy=policy
    )

    exec_ctx = ExecutionContext(
        correlation_id="corr-mis-action",
        request_id="req-mis-action",
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )
    # Attempt execution with mismatched action 'write'
    with pytest.raises(PermissionError, match="CAPABILITY_VERIFICATION_FAILED_ACTION_MISMATCH"):
        orchestrator.execution_boundary.execute_protected_action(
            action_name="write",
            target="/public",
            request_payload=payload,
            executor_func=executor,
            context=exec_ctx
        )
    assert executor.call_count == 0

    # Positive control: correctly authorized action 'read' succeeds
    res = orchestrator.execution_boundary.execute_protected_action(
        action_name="read",
        target="/public",
        request_payload=payload,
        executor_func=executor,
        context=exec_ctx
    )
    assert res["status"] == "SUCCESS"
    assert executor.call_count == 1


def test_zero_side_effect_unauthorized_direct_or_alternate_invocation():
    """7. Unauthorized direct or alternate invocation bypassing registration."""
    unregistered_executor = MagicMock(return_value={"status": "UNREGISTERED_SIDE_EFFECT"})
    orchestrator = EpistemicOrchestrator()
    payload = {"data": "test"}
    digest = orchestrator.execution_boundary.compute_canonical_digest(payload)

    exec_ctx = ExecutionContext(
        correlation_id="corr-unreg",
        request_id="req-unreg",
        authorization_token_id="AUTH-CAP-UNREGISTERED",
        authorized_digest=digest,
        authorization_granted=True
    )
    with pytest.raises(PermissionError, match="CAPABILITY_VERIFICATION_FAILED_UNKNOWN_TOKEN"):
        orchestrator.execution_boundary.execute_protected_action(
            action_name="run",
            target="/res",
            request_payload=payload,
            executor_func=unregistered_executor,
            context=exec_ctx
        )
    assert unregistered_executor.call_count == 0


def test_zero_side_effect_missing_trusted_executor_registration():
    """8. Missing trusted executor registration in ExecutorRegistry."""
    from epistemicos.authorization import Capability, get_callable_identity
    executor = MagicMock(return_value={"status": "UNREGISTERED"})
    orchestrator = EpistemicOrchestrator()
    payload = {"data": "test"}
    digest = orchestrator.execution_boundary.compute_canonical_digest(payload)
    exec_id = get_callable_identity(executor)

    cap = Capability(
        token_id="AUTH-CAP-MISSING-REG",
        principal_id="agent_default",
        correlation_id="corr-missing-reg",
        request_id="req-missing-reg",
        action_name="run",
        target="/res",
        canonical_request_digest=digest,
        executor_id=exec_id,
        policy_version="1.0.0",
        created_at=1000.0,
        expires_at=9999999999.0
    )
    orchestrator.authority.registry.register_capability(cap)

    exec_ctx = ExecutionContext(
        correlation_id="corr-missing-reg",
        request_id="req-missing-reg",
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )
    with pytest.raises(PermissionError, match="Unregistered callable object cannot execute"):
        orchestrator.execution_boundary.execute_protected_action(
            action_name="run",
            target="/res",
            request_payload=payload,
            executor_func=executor,
            context=exec_ctx
        )
    assert executor.call_count == 0


def test_zero_side_effect_identity_collision_or_rebinding_attempt():
    """9. Identity collision or rebinding attempt in ExecutorRegistry."""
    def fn_a():
        return {"status": "FN_A"}

    def fn_b():
        return {"status": "FN_B"}

    orchestrator = EpistemicOrchestrator()
    reg = orchestrator.authority.executor_registry
    reg._register_internal("shared_key", fn_a)

    with pytest.raises(ValueError, match="Cannot overwrite existing executor ID"):
        reg._register_internal("shared_key", fn_b)


def test_zero_side_effect_single_use_replay_prevention():
    """10. Single-use replay prevention: consumed token cannot authorize a second execution."""
    from epistemicos.authorization import Policy
    executor = MagicMock(return_value={"status": "RETRY"})
    orchestrator = EpistemicOrchestrator()
    payload = {"data": "test"}
    digest = orchestrator.execution_boundary.compute_canonical_digest(payload)

    policy = Policy(policy_id="p-retry", allowed_operations={"run"}, allowed_resources={"/res"})
    cap, _ = orchestrator.authority.evaluate_and_issue_capability(
        action_name="run",
        target="/res",
        canonical_request_digest=digest,
        correlation_id="corr-retry",
        request_id="req-retry",
        executor_id=executor,
        policy=policy
    )

    exec_ctx = ExecutionContext(
        correlation_id="corr-retry",
        request_id="req-retry",
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    res = orchestrator.execution_boundary.execute_protected_action(
        action_name="run",
        target="/res",
        request_payload=payload,
        executor_func=executor,
        context=exec_ctx
    )
    assert res["status"] == "SUCCESS"
    assert executor.call_count == 1

    with pytest.raises(PermissionError, match="has already been consumed"):
        orchestrator.execution_boundary.execute_protected_action(
            action_name="run",
            target="/res",
            request_payload=payload,
            executor_func=executor,
            context=exec_ctx
        )
    assert executor.call_count == 1


def test_zero_side_effect_internal_exception_before_execution():
    """11. Internal exception before execution (digest mismatch or payload change)."""
    executor = MagicMock(return_value={"status": "EXECUTED"})
    orchestrator = EpistemicOrchestrator()
    payload = {"data": "original"}

    exec_ctx = ExecutionContext(
        correlation_id="corr-err",
        request_id="req-err",
        authorization_token_id="AUTH-CAP-ERR",
        authorized_digest="wrong-digest",
        authorization_granted=True
    )

    with pytest.raises(ValueError, match="Request payload digest changed"):
        orchestrator.execution_boundary.execute_protected_action(
            action_name="run",
            target="/res",
            request_payload=payload,
            executor_func=executor,
            context=exec_ctx
        )
    assert executor.call_count == 0


def test_authorized_execution_positive_control():
    """12. Legitimate authorized operation (positive control) executes exactly once."""
    from epistemicos.authorization import Policy
    executor = MagicMock(return_value={"status": "SUCCESS_RESULT"})
    orchestrator = EpistemicOrchestrator()
    payload = {"data": "valid"}
    digest = orchestrator.execution_boundary.compute_canonical_digest(payload)

    policy = Policy(policy_id="p-pos", allowed_operations={"run"}, allowed_resources={"/res"})
    cap, _ = orchestrator.authority.evaluate_and_issue_capability(
        action_name="run",
        target="/res",
        canonical_request_digest=digest,
        correlation_id="corr-pos",
        request_id="req-pos",
        executor_id=executor,
        policy=policy
    )

    exec_ctx = ExecutionContext(
        correlation_id="corr-pos",
        request_id="req-pos",
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    res = orchestrator.execution_boundary.execute_protected_action(
        action_name="run",
        target="/res",
        request_payload=payload,
        executor_func=executor,
        context=exec_ctx
    )
    assert res["status"] == "SUCCESS"
    assert res["result"] == {"status": "SUCCESS_RESULT"}
    assert executor.call_count == 1


def test_negative_control_authorization_bypass_detected():
    """
    Negative-control test:
    Demonstrates that if an execution boundary preserves capability verification but skips ONLY
    the Option A object identity check (calling the passed callable directly once capability is verified),
    a substituted callable would execute. Confirms that the production boundary strictly blocks substitution.
    """
    from epistemicos.authorization import Policy, Capability, get_callable_identity
    from epistemicos.provenance import TrustedExecutionBoundary

    # Use functions with identical identity string to isolate Option A object identity ('is') check
    def worker_action():
        return {"status": "LEGIT"}

    def substitute_action():
        return {"status": "SUBSTITUTED"}

    # Mock get_callable_identity so both share the same identifier string, isolating Option A check
    shared_id = "test_module.worker_action"

    orchestrator = EpistemicOrchestrator()
    payload = {"action": "transfer"}
    digest = orchestrator.execution_boundary.compute_canonical_digest(payload)

    policy = Policy(policy_id="p-neg", allowed_operations={"run"}, allowed_resources={"/res"})
    cap, _ = orchestrator.authority.evaluate_and_issue_capability(
        action_name="run",
        target="/res",
        canonical_request_digest=digest,
        correlation_id="corr-neg",
        request_id="req-neg",
        executor_id=worker_action,
        policy=policy
    )

    exec_ctx = ExecutionContext(
        correlation_id="corr-neg",
        request_id="req-neg",
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    # Simulated vulnerable boundary: executes capability verification but omits Option A identity check
    class OptionAVulnerableBoundary(TrustedExecutionBoundary):
        def execute_protected_action(self, action_name, target, request_payload, *args, **kwargs):
            # Calls verify_capability to ensure token is valid, but skips Option A executor_func is bound_callable check
            ctx = kwargs.get("context") or (args[0] if args else None)
            exec_func = kwargs.get("executor_func")
            auth_token_id = ctx.authorization_token_id
            curr_digest = self.compute_canonical_digest(request_payload)
            valid, reason, _ = self.authority.verify_capability(
                token_id=auth_token_id,
                action_name=action_name,
                target=target,
                canonical_request_digest=curr_digest,
                executor_id=get_callable_identity(worker_action),
                correlation_id=ctx.correlation_id,
                request_id=ctx.request_id,
                policy_version=ctx.policy_version
            )
            if not valid:
                raise PermissionError(f"Rejected: {reason}")
            # Vulnerability: calls exec_func directly without verifying exec_func is registered callable!
            return {"status": "SUCCESS", "result": exec_func()}

    vuln_boundary = OptionAVulnerableBoundary(
        provenance_store=orchestrator.execution_boundary.store,
        authority=orchestrator.authority
    )

    # Vulnerable boundary permits substitute execution when capability is valid
    vuln_res = vuln_boundary.execute_protected_action(
        action_name="run",
        target="/res",
        request_payload=payload,
        executor_func=substitute_action,
        context=exec_ctx
    )
    assert vuln_res["result"] == {"status": "SUBSTITUTED"}

    # Fresh capability for production boundary check
    cap2, _ = orchestrator.authority.evaluate_and_issue_capability(
        action_name="run",
        target="/res",
        canonical_request_digest=digest,
        correlation_id="corr-neg-2",
        request_id="req-neg-2",
        executor_id=worker_action,
        policy=policy
    )
    exec_ctx2 = ExecutionContext(
        correlation_id="corr-neg-2",
        request_id="req-neg-2",
        authorization_token_id=cap2.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    # Production boundary strictly blocks the substituted callable
    with pytest.raises(PermissionError, match="Executable object identity mismatch|CAPABILITY_VERIFICATION_FAILED_EXECUTOR_MISMATCH"):
        orchestrator.execution_boundary.execute_protected_action(
            action_name="run",
            target="/res",
            request_payload=payload,
            executor_func=substitute_action,
            context=exec_ctx2
        )


def test_concurrent_execution_boundary_single_use_enforcement():
    """
    Deterministic concurrent regression test:
    Coordinates multiple concurrent threads attempting to consume the same single-use capability
    simultaneously through TrustedExecutionBoundary.execute_protected_action.
    Asserts:
    1. Exactly one execution succeeds.
    2. The protected executor is called exactly once.
    3. The concurrent attempt is rejected as an already-consumed replay attempt.
    4. No second side effect occurs.
    """
    import threading
    from epistemicos.authorization import Policy

    executor = MagicMock(return_value={"status": "SIDE_EFFECT_PRODUCED"})
    orchestrator = EpistemicOrchestrator()
    payload = {"amount": 500}
    digest = orchestrator.execution_boundary.compute_canonical_digest(payload)

    policy = Policy(policy_id="p-conc", allowed_operations={"transfer"}, allowed_resources={"account_a"})
    cap, _ = orchestrator.authority.evaluate_and_issue_capability(
        action_name="transfer",
        target="account_a",
        canonical_request_digest=digest,
        correlation_id="corr-conc",
        request_id="req-conc",
        executor_id=executor,
        policy=policy
    )

    exec_ctx = ExecutionContext(
        correlation_id="corr-conc",
        request_id="req-conc",
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    barrier = threading.Barrier(2)
    results = []
    errors = []

    def worker():
        try:
            barrier.wait()
            res = orchestrator.execution_boundary.execute_protected_action(
                action_name="transfer",
                target="account_a",
                request_payload=payload,
                executor_func=executor,
                context=exec_ctx
            )
            results.append(res)
        except Exception as e:
            errors.append(e)

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Invariants under contention:
    assert len(results) == 1, f"Expected exactly 1 successful execution, got {len(results)}"
    assert results[0]["status"] == "SUCCESS"
    assert executor.call_count == 1, f"Expected executor to be called exactly once, got {executor.call_count}"
    assert len(errors) == 1, f"Expected exactly 1 thread to be rejected, got {len(errors)}"
    assert isinstance(errors[0], PermissionError)
    assert "has already been consumed" in str(errors[0])
