"""
Unit and Adversarial Test Suite for Execution Provenance Subsystem.
"""

import json
import uuid
import pytest
import threading
from epistemicos.provenance import (
    ProvenanceEvent,
    ProvenanceEventType,
    ProvenanceSource,
    LocalProvenanceStore,
    TrustedExecutionBoundary,
    ProvenanceReconciler,
    ReconciliationReport
)


def test_agent_success_claim_without_executor_event(tmp_path):
    log_file = str(tmp_path / "prov.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    reconciler = ProvenanceReconciler()
    corr_id = str(uuid.uuid4())

    # Record ACTION_PROPOSED and AUTHORIZATION_GRANTED only
    prop_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.ACTION_PROPOSED.value,
        provenance_source=ProvenanceSource.AGENT_ADAPTER.value,
        correlation_id=corr_id,
        request_id="req-1",
        action_name="TRANSFER",
        target="acct-123",
        canonical_request_digest="abc",
        timestamp="2025-01-01T00:00:00Z"
    )
    store.record_event(prop_event)

    auth_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id="req-1",
        action_name="TRANSFER",
        target="acct-123",
        canonical_request_digest="abc",
        timestamp="2025-01-01T00:00:01Z",
        authorization_token_id="tok-1"
    )
    store.record_event(auth_event)

    events = store.get_events_for_correlation(corr_id)
    # Agent claims success, but no EXECUTION_SUCCEEDED event exists
    report = reconciler.reconcile_correlation(corr_id, events, agent_claimed_success=True)

    assert not report.valid
    assert report.status == "RECONCILIATION_MISMATCH"
    assert any("Agent claimed execution success" in v for v in report.violations)


def test_unauthorized_execution(tmp_path):
    log_file = str(tmp_path / "prov.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    reconciler = ProvenanceReconciler()
    corr_id = str(uuid.uuid4())

    # EXECUTION_STARTED without AUTHORIZATION_GRANTED
    exec_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_STARTED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id=corr_id,
        request_id="req-1",
        action_name="DELETE",
        target="db-main",
        canonical_request_digest="xyz",
        timestamp="2025-01-01T00:00:02Z",
        authorization_token_id="unauthorized-tok"
    )
    store.record_event(exec_event)

    events = store.get_events_for_correlation(corr_id)
    report = reconciler.reconcile_correlation(corr_id, events, agent_claimed_success=True)

    assert not report.valid
    assert report.status == "RECONCILIATION_MISMATCH"
    assert any("without authorization granted" in v for v in report.violations)


def test_denied_action_reached_execution(tmp_path):
    log_file = str(tmp_path / "prov.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    reconciler = ProvenanceReconciler()
    corr_id = str(uuid.uuid4())

    denied_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_DENIED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id="req-1",
        action_name="SHUTDOWN",
        target="node-1",
        canonical_request_digest="abc",
        timestamp="2025-01-01T00:00:00Z"
    )
    store.record_event(denied_event)

    exec_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_STARTED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id=corr_id,
        request_id="req-1",
        action_name="SHUTDOWN",
        target="node-1",
        canonical_request_digest="abc",
        timestamp="2025-01-01T00:00:01Z",
        authorization_token_id="tok-denied"
    )
    store.record_event(exec_event)

    events = store.get_events_for_correlation(corr_id)
    report = reconciler.reconcile_correlation(corr_id, events)

    assert not report.valid
    assert any("authorization-denied" in v for v in report.violations)


def test_target_and_digest_mismatch(tmp_path):
    log_file = str(tmp_path / "prov.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    reconciler = ProvenanceReconciler()
    corr_id = str(uuid.uuid4())

    auth_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id="req-1",
        action_name="READ",
        target="public-doc",
        canonical_request_digest="digest-1",
        timestamp="2025-01-01T00:00:00Z",
        authorization_token_id="tok-read"
    )
    store.record_event(auth_event)

    exec_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_STARTED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id=corr_id,
        request_id="req-1",
        action_name="READ",
        target="secret-doc",  # Mismatched target
        canonical_request_digest="digest-2",  # Mismatched digest
        timestamp="2025-01-01T00:00:01Z",
        authorization_token_id="tok-read"
    )
    store.record_event(exec_event)

    events = store.get_events_for_correlation(corr_id)
    report = reconciler.reconcile_correlation(corr_id, events)

    assert not report.valid
    assert any("target or action name mismatch" in v for v in report.violations)
    assert any("digest changed" in v for v in report.violations)


def test_concurrent_single_use_token_consumption(tmp_path):
    log_file = str(tmp_path / "prov.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"amount": 100, "recipient": "user-A"}
    digest = boundary.compute_canonical_digest(payload)
    token_id = "single-use-token-999"
    corr_id = str(uuid.uuid4())

    results = []
    errors = []

    def run_execution():
        try:
            res = boundary.execute_protected_action(
                action_name="PAYMENT",
                target="stripe-api",
                request_payload=payload,
                correlation_id=corr_id,
                request_id="req-p",
                authorization_token_id=token_id,
                authorized_digest=digest,
                authorization_granted=True,
                executor_func=lambda: "PAID_100_USD"
            )
            results.append(res)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=run_execution) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly 1 success and 4 errors due to replay prevention
    assert len(results) == 1
    assert len(errors) == 4
    assert all(isinstance(err, PermissionError) and "already been consumed" in str(err) for err in errors)


def test_executor_exception_recording(tmp_path):
    log_file = str(tmp_path / "prov.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"op": "DIVIDE", "a": 1, "b": 0}
    digest = boundary.compute_canonical_digest(payload)
    corr_id = str(uuid.uuid4())

    def failing_executor():
        raise ZeroDivisionError("division by zero in executor")

    with pytest.raises(ZeroDivisionError):
        boundary.execute_protected_action(
            action_name="CALCULATE",
            target="math-engine",
            request_payload=payload,
            correlation_id=corr_id,
            request_id="req-div",
            authorization_token_id="tok-div",
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=failing_executor
        )

    events = store.get_events_for_correlation(corr_id)
    types = [e.event_type for e in events]
    assert ProvenanceEventType.EXECUTION_STARTED.value in types
    assert ProvenanceEventType.EXECUTION_FAILED.value in types

    fail_event = [e for e in events if e.event_type == ProvenanceEventType.EXECUTION_FAILED.value][0]
    assert fail_event.outcome["status"] == "FAILED"
    assert "division by zero" in fail_event.outcome["error"]


def test_keyboard_interrupt_propagation_and_recording(tmp_path):
    log_file = str(tmp_path / "prov.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"op": "LONG_TASK"}
    digest = boundary.compute_canonical_digest(payload)
    corr_id = str(uuid.uuid4())

    def interrupting_executor():
        raise KeyboardInterrupt("task interrupted by SIGINT")

    with pytest.raises(KeyboardInterrupt):
        boundary.execute_protected_action(
            action_name="COMPUTE",
            target="cpu-worker",
            request_payload=payload,
            correlation_id=corr_id,
            request_id="req-int",
            authorization_token_id="tok-int",
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=interrupting_executor
        )

    events = store.get_events_for_correlation(corr_id)
    types = [e.event_type for e in events]
    assert ProvenanceEventType.EXECUTION_STARTED.value in types
    assert ProvenanceEventType.EXECUTION_INTERRUPTED.value in types

    int_event = [e for e in events if e.event_type == ProvenanceEventType.EXECUTION_INTERRUPTED.value][0]
    assert int_event.outcome["status"] == "INTERRUPTED"


def test_multi_request_interleaved_reconciliation(tmp_path):
    log_file = str(tmp_path / "prov.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    reconciler = ProvenanceReconciler()
    corr_id = str(uuid.uuid4())

    # Request 1 (Authorized and Succeeded)
    auth1 = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id="req-1",
        action_name="READ",
        target="doc-1",
        canonical_request_digest="digest-1",
        timestamp="2025-01-01T00:00:00Z",
        authorization_token_id="tok-1"
    )
    store.record_event(auth1)

    # Request 2 (Authorized and Succeeded)
    auth2 = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id="req-2",
        action_name="WRITE",
        target="doc-2",
        canonical_request_digest="digest-2",
        timestamp="2025-01-01T00:00:01Z",
        authorization_token_id="tok-2"
    )
    store.record_event(auth2)

    # Interleaved execution for Request 2
    exec2_start = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_STARTED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id=corr_id,
        request_id="req-2",
        action_name="WRITE",
        target="doc-2",
        canonical_request_digest="digest-2",
        timestamp="2025-01-01T00:00:02Z",
        authorization_token_id="tok-2",
        execution_attempt_id="att-2"
    )
    store.record_event(exec2_start)

    exec2_succ = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_SUCCEEDED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id=corr_id,
        request_id="req-2",
        action_name="WRITE",
        target="doc-2",
        canonical_request_digest="digest-2",
        timestamp="2025-01-01T00:00:03Z",
        authorization_token_id="tok-2",
        execution_attempt_id="att-2"
    )
    store.record_event(exec2_succ)

    # Interleaved execution for Request 1
    exec1_start = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_STARTED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id=corr_id,
        request_id="req-1",
        action_name="READ",
        target="doc-1",
        canonical_request_digest="digest-1",
        timestamp="2025-01-01T00:00:04Z",
        authorization_token_id="tok-1",
        execution_attempt_id="att-1"
    )
    store.record_event(exec1_start)

    exec1_succ = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_SUCCEEDED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id=corr_id,
        request_id="req-1",
        action_name="READ",
        target="doc-1",
        canonical_request_digest="digest-1",
        timestamp="2025-01-01T00:00:05Z",
        authorization_token_id="tok-1",
        execution_attempt_id="att-1"
    )
    store.record_event(exec1_succ)

    events = store.get_events_for_correlation(corr_id)
    report = reconciler.reconcile_correlation(corr_id, events, agent_claimed_success=True)

    assert report.valid
    assert report.status == "RECONCILED"
    assert len(report.violations) == 0


def test_privacy_and_sensitive_payload_redaction(tmp_path):
    log_file = str(tmp_path / "prov.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    boundary = TrustedExecutionBoundary(provenance_store=store)

    sensitive_payload = {
        "api_key": "sk-secret-key-12345678901234567890",
        "bearer_token": "Bearer eyJhbGciOiJIUzI1NiJ9",
        "ssn": "000-12-3456",
        "user_email": "alice@example.com"
    }

    digest = boundary.compute_canonical_digest(sensitive_payload)
    corr_id = str(uuid.uuid4())

    boundary.execute_protected_action(
        action_name="USER_AUTH",
        target="auth-service",
        request_payload=sensitive_payload,
        correlation_id=corr_id,
        request_id="req-sec",
        authorization_token_id="tok-sec",
        authorized_digest=digest,
        authorization_granted=True,
        executor_func=lambda: {"api_key": "sk-returned-secret-key-12345678901234567890"}
    )

    with open(log_file, "r", encoding="utf-8") as f:
        log_content = f.read()

    assert "sk-secret-key" not in log_content
    assert "sk-returned-secret-key" not in log_content
    assert "[REDACTED]" in log_content


def test_corrupted_log_health_detection(tmp_path):
    log_file = tmp_path / "prov.jsonl"
    store = LocalProvenanceStore(log_path=str(log_file))

    event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id="e-1",
        event_type=ProvenanceEventType.ACTION_PROPOSED.value,
        provenance_source=ProvenanceSource.AGENT_ADAPTER.value,
        correlation_id="c-1",
        request_id="r-1",
        action_name="A",
        target="T",
        canonical_request_digest="dig",
        timestamp="2025-01-01T00:00:00Z"
    )
    store.record_event(event)

    # Corrupt log file
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("{corrupted json line\n")

    event2 = ProvenanceEvent(
        schema_version="1.0.0",
        event_id="e-2",
        event_type=ProvenanceEventType.ACTION_PROPOSED.value,
        provenance_source=ProvenanceSource.AGENT_ADAPTER.value,
        correlation_id="c-1",
        request_id="r-2",
        action_name="A",
        target="T",
        canonical_request_digest="dig",
        timestamp="2025-01-01T00:00:01Z"
    )

    with pytest.raises(RuntimeError) as exc_info:
        store.record_event(event2)

    assert "corruption detected" in str(exc_info.value).lower() or "fail-closed" in str(exc_info.value).lower()
