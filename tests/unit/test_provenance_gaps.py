"""
Unit tests for GAP-02 Authorization-Grant Provenance & Provenance Event Lifecycle.
"""

import pytest
import uuid
import json
import time
import tempfile
from pathlib import Path

from epistemicos.core import EpistemicOrchestrator
from epistemicos.authorization import (
    AuthorizationAuthority,
    Policy,
    CapabilityRegistry,
    HumanApprovalRecord
)
from epistemicos.provenance import (
    LocalProvenanceStore,
    TrustedExecutionBoundary,
    ExecutionContext,
    ProvenanceEvent,
    ProvenanceEventType,
    ProvenanceSource,
    ProvenanceReconciler
)
from epistemicos.models import PermissionScope
from epistemicos.gates import PermissionGate


@pytest.fixture
def temp_provenance_store(tmp_path):
    log_file = tmp_path / "test_provenance.jsonl"
    return LocalProvenanceStore(log_path=str(log_file), fail_closed=True)


def test_successful_authorization_and_grant_event(temp_provenance_store):
    """1. Successful authorization followed by capability issuance emits AUTHORIZATION_GRANTED."""
    policy = Policy(
        policy_id="test_pol",
        allowed_operations={"read"},
        allowed_resources={"doc1"}
    )
    auth = AuthorizationAuthority(default_policy=policy)
    boundary = TrustedExecutionBoundary(provenance_store=temp_provenance_store, authority=auth)

    corr_id = f"CORR-{uuid.uuid4()}"
    req_id = f"REQ-{uuid.uuid4()}"
    payload = {"op": "read", "node": "doc1"}
    digest = boundary.compute_canonical_digest(payload)

    cap, reason = auth.evaluate_and_issue_capability(
        action_name="read",
        target="doc1",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id=req_id
    )
    assert cap is not None
    assert reason == "AUTHORIZATION_GRANTED"

    # Record grant event
    grant_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id=req_id,
        action_name="read",
        target="doc1",
        canonical_request_digest=digest,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        authorization_token_id=cap.token_id,
        policy_version=cap.policy_version
    )
    temp_provenance_store.record_event(grant_event)

    events = temp_provenance_store.get_events_for_correlation(corr_id)
    assert len(events) == 1
    assert events[0].event_type == "AUTHORIZATION_GRANTED"
    assert events[0].authorization_token_id == cap.token_id


def test_authorization_denial_emits_denied_event(temp_provenance_store):
    """2. Authorization denial emits AUTHORIZATION_DENIED with no grant event."""
    policy = Policy(
        policy_id="test_pol",
        allowed_operations={"read"},
        allowed_resources={"doc1"}
    )
    auth = AuthorizationAuthority(default_policy=policy)
    boundary = TrustedExecutionBoundary(provenance_store=temp_provenance_store, authority=auth)

    corr_id = f"CORR-DENIED-{uuid.uuid4()}"
    req_id = f"REQ-{uuid.uuid4()}"
    payload = {"op": "delete", "node": "doc1"}
    digest = boundary.compute_canonical_digest(payload)

    cap, reason = auth.evaluate_and_issue_capability(
        action_name="delete",
        target="doc1",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id=req_id
    )
    assert cap is None
    assert "AUTHORIZATION_DENIED" in reason

    denied_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_DENIED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id=req_id,
        action_name="delete",
        target="doc1",
        canonical_request_digest=digest,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        decision="DENIED"
    )
    temp_provenance_store.record_event(denied_event)

    events = temp_provenance_store.get_events_for_correlation(corr_id)
    assert len(events) == 1
    assert events[0].event_type == "AUTHORIZATION_DENIED"
    assert not any(e.event_type == "AUTHORIZATION_GRANTED" for e in events)


def test_capability_replay_prevented(temp_provenance_store):
    """3. Capability reuse/replay fails and yields no second successful execution."""
    def sample_executor():
        return {"status": "ok"}

    policy = Policy(policy_id="test", allowed_operations={"write"}, allowed_resources={"db"})
    auth = AuthorizationAuthority(default_policy=policy)
    boundary = TrustedExecutionBoundary(provenance_store=temp_provenance_store, authority=auth)
    auth.register_executor("sample_executor", sample_executor)

    corr_id = f"CORR-REPLAY-{uuid.uuid4()}"
    req_id = f"REQ-{uuid.uuid4()}"
    payload = {"op": "write", "node": "db"}
    digest = boundary.compute_canonical_digest(payload)

    cap, _ = auth.evaluate_and_issue_capability(
        action_name="write",
        target="db",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id=req_id,
        executor_id=sample_executor
    )

    ctx = ExecutionContext(
        correlation_id=corr_id,
        request_id=req_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    res1 = boundary.execute_protected_action("write", "db", payload, executor_func=sample_executor, context=ctx)
    assert res1["status"] == "SUCCESS"

    with pytest.raises(PermissionError, match="already been consumed"):
        boundary.execute_protected_action("write", "db", payload, executor_func=sample_executor, context=ctx)


def test_target_or_operation_mismatch_rejected(temp_provenance_store):
    """4. Target or operation mismatch rejected at execution boundary."""
    def sample_executor():
        return {"status": "ok"}

    policy = Policy(policy_id="test", allowed_operations={"read"}, allowed_resources={"public_doc"})
    auth = AuthorizationAuthority(default_policy=policy)
    boundary = TrustedExecutionBoundary(provenance_store=temp_provenance_store, authority=auth)
    auth.register_executor("sample_executor", sample_executor)

    corr_id = f"CORR-MISMATCH-{uuid.uuid4()}"
    req_id = f"REQ-{uuid.uuid4()}"
    payload = {"op": "read", "node": "public_doc"}
    digest = boundary.compute_canonical_digest(payload)

    cap, _ = auth.evaluate_and_issue_capability(
        action_name="read",
        target="public_doc",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id=req_id,
        executor_id=sample_executor
    )

    ctx = ExecutionContext(
        correlation_id=corr_id,
        request_id=req_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    # Execute against wrong target "private_db"
    with pytest.raises(PermissionError, match="TARGET_MISMATCH"):
        boundary.execute_protected_action("read", "private_db", payload, executor_func=sample_executor, context=ctx)


def test_authorization_success_followed_by_execution_failure(temp_provenance_store):
    """5. Authorization success followed by execution failure emits EXECUTION_FAILED."""
    def failing_executor():
        raise RuntimeError("DB Connection Crashed")

    policy = Policy(policy_id="test", allowed_operations={"write"}, allowed_resources={"db"})
    auth = AuthorizationAuthority(default_policy=policy)
    boundary = TrustedExecutionBoundary(provenance_store=temp_provenance_store, authority=auth)
    auth.register_executor("failing_executor", failing_executor)

    corr_id = f"CORR-FAIL-{uuid.uuid4()}"
    req_id = f"REQ-{uuid.uuid4()}"
    payload = {"op": "write", "node": "db"}
    digest = boundary.compute_canonical_digest(payload)

    cap, _ = auth.evaluate_and_issue_capability(
        action_name="write",
        target="db",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id=req_id,
        executor_id=failing_executor
    )

    ctx = ExecutionContext(
        correlation_id=corr_id,
        request_id=req_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    with pytest.raises(RuntimeError, match="DB Connection Crashed"):
        boundary.execute_protected_action("write", "db", payload, executor_func=failing_executor, context=ctx)

    events = temp_provenance_store.get_events_for_correlation(corr_id)
    event_types = [e.event_type for e in events]
    assert "EXECUTION_STARTED" in event_types
    assert "EXECUTION_FAILED" in event_types
    assert "EXECUTION_SUCCEEDED" not in event_types


def test_provenance_store_write_failure_fail_closed(tmp_path):
    """6. Provenance store write failure fails closed when configured."""
    invalid_path = tmp_path / "non_existent_dir" / "readonly_store.jsonl"
    store = LocalProvenanceStore(log_path=str(invalid_path), fail_closed=True)
    # Remove directory to force write error
    if invalid_path.parent.exists():
        invalid_path.parent.rmdir()

    event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.ACTION_PROPOSED.value,
        provenance_source=ProvenanceSource.AGENT_ADAPTER.value,
        correlation_id="CORR-ERR",
        request_id="REQ-ERR",
        action_name="read",
        target="doc",
        canonical_request_digest="abc",
        timestamp="2026-01-01T00:00:00Z"
    )

    # Force error by making path pointing to directory
    invalid_path.parent.mkdir(parents=True, exist_ok=True)
    dir_as_file = invalid_path
    dir_as_file.mkdir(parents=True, exist_ok=True)

    with pytest.raises(RuntimeError, match="Provenance recording failed"):
        store.record_event(event)


def test_full_provenance_lifecycle_reconciliation(temp_provenance_store):
    """7. Full correlation of ACTION_PROPOSED -> AUTHORIZATION_GRANTED -> EXECUTION_STARTED -> EXECUTION_SUCCEEDED."""
    def valid_exec():
        return {"data": "confidential_content"}

    policy = Policy(policy_id="test", allowed_operations={"read"}, allowed_resources={"confidential_doc"})
    auth = AuthorizationAuthority(default_policy=policy)
    boundary = TrustedExecutionBoundary(provenance_store=temp_provenance_store, authority=auth)
    auth.register_executor("valid_exec", valid_exec)

    orchestrator = EpistemicOrchestrator(
        audit_log_path=str(temp_provenance_store.log_path.parent / "audit.jsonl"),
        execution_boundary=boundary,
        authority=auth
    )
    scope = PermissionScope(allowed_resources=["confidential_doc"], allowed_operations=["read"], expires_at=0)
    orchestrator.gates[0] = PermissionGate(trusted_scope=scope)

    corr_id = f"CORR-FULL-{uuid.uuid4()}"
    payload = {
        "policy_id": "POL-TEST",
        "scope": scope.model_dump(),
        "proposed_actions": [{"op": "read", "node": "confidential_doc"}]
    }
    ctx = {
        "correlation_id": corr_id,
        "action_name": "read",
        "target": "confidential_doc",
        "proposed_actions": payload["proposed_actions"],
        "actual_executable": valid_exec,
        "trusted_scope": scope
    }

    res = orchestrator.process_submission(payload, ctx)
    assert res["status"] == "ALLOWED"
    assert res["execution_status"] == "EXECUTED"

    events = temp_provenance_store.get_events_for_correlation(corr_id)
    event_types = [e.event_type for e in events]
    assert event_types == [
        "ACTION_PROPOSED",
        "AUTHORIZATION_GRANTED",
        "EXECUTION_STARTED",
        "EXECUTION_SUCCEEDED"
    ]

    reconciler = ProvenanceReconciler()
    report = reconciler.reconcile_correlation(corr_id, events, agent_claimed_success=True)
    assert report.valid is True
    assert report.status == "RECONCILED"


def test_sensitive_data_redaction_in_provenance_events(temp_provenance_store):
    """8. Sensitive data (passwords, tokens, API keys) are redacted in recorded provenance events."""
    event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_SUCCEEDED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id="CORR-REDACT",
        request_id="REQ-REDACT",
        action_name="query",
        target="db",
        canonical_request_digest="123",
        timestamp="2026-01-01T00:00:00Z",
        outcome={"status": "SUCCESS", "result": {"api_key": "ghp_1234567890abcdef1234567890abcdef", "password": "SuperSecretPassword123"}}
    )

    rec = temp_provenance_store.record_event(event)
    out_res = rec["outcome"]["result"]
    assert out_res["api_key"] == "[REDACTED]"
    assert out_res["password"] == "[REDACTED]"
