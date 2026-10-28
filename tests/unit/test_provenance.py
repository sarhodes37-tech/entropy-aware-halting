"""
Unit and Adversarial Test Suite for Execution Provenance Subsystem.
"""

import json
import uuid
import pytest
import threading
from dataclasses import asdict
from epistemicos.authorization import Policy, Capability
from epistemicos.provenance import (
    _sanitize_sensitive_data,
    ExecutionContext,
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
    corr_id = str(uuid.uuid4())

    exec_func = lambda: "PAID_100_USD"
    policy = Policy(policy_id="p1", allowed_operations={"PAYMENT"}, allowed_resources={"stripe-api"})
    cap, _ = boundary.authority.evaluate_and_issue_capability(
        action_name="PAYMENT",
        target="stripe-api",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id="req-p",
        executor_id=exec_func,
        policy=policy
    )
    token_id = cap.token_id

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
                executor_func=exec_func
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

    policy = Policy(policy_id="p1", allowed_operations={"CALCULATE"}, allowed_resources={"math-engine"})
    cap, _ = boundary.authority.evaluate_and_issue_capability(
        action_name="CALCULATE",
        target="math-engine",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id="req-div",
        executor_id=failing_executor,
        policy=policy
    )

    with pytest.raises(ZeroDivisionError):
        boundary.execute_protected_action(
            action_name="CALCULATE",
            target="math-engine",
            request_payload=payload,
            correlation_id=corr_id,
            request_id="req-div",
            authorization_token_id=cap.token_id,
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

    policy = Policy(policy_id="p1", allowed_operations={"COMPUTE"}, allowed_resources={"cpu-worker"})
    cap, _ = boundary.authority.evaluate_and_issue_capability(
        action_name="COMPUTE",
        target="cpu-worker",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id="req-int",
        executor_id=interrupting_executor,
        policy=policy
    )

    with pytest.raises(KeyboardInterrupt):
        boundary.execute_protected_action(
            action_name="COMPUTE",
            target="cpu-worker",
            request_payload=payload,
            correlation_id=corr_id,
            request_id="req-int",
            authorization_token_id=cap.token_id,
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

    exec_func = lambda: {"api_key": "sk-returned-secret-key-12345678901234567890"}
    policy = Policy(policy_id="p1", allowed_operations={"USER_AUTH"}, allowed_resources={"auth-service"})
    cap, _ = boundary.authority.evaluate_and_issue_capability(
        action_name="USER_AUTH",
        target="auth-service",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id="req-sec",
        executor_id=exec_func,
        policy=policy
    )

    boundary.execute_protected_action(
        action_name="USER_AUTH",
        target="auth-service",
        request_payload=sensitive_payload,
        correlation_id=corr_id,
        request_id="req-sec",
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        executor_func=exec_func
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


def test_provenance_store_input_validation(tmp_path):
    log_file = str(tmp_path / "prov_val.jsonl")
    store = LocalProvenanceStore(log_path=log_file, fail_closed=True)

    # Invalid schema_version
    bad_schema_evt = ProvenanceEvent(
        schema_version="",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.ACTION_PROPOSED.value,
        provenance_source=ProvenanceSource.AGENT_ADAPTER.value,
        correlation_id="c1",
        request_id="r1",
        action_name="ACT",
        target="TGT",
        canonical_request_digest="dig",
        timestamp="2025-01-01T00:00:00Z"
    )
    with pytest.raises(RuntimeError, match="Invalid or missing schema_version"):
        store.record_event(bad_schema_evt)

    # Unsupported event_type
    bad_type_evt = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type="UNSUPPORTED_TYPE",
        provenance_source=ProvenanceSource.AGENT_ADAPTER.value,
        correlation_id="c1",
        request_id="r1",
        action_name="ACT",
        target="TGT",
        canonical_request_digest="dig",
        timestamp="2025-01-01T00:00:00Z"
    )
    with pytest.raises(RuntimeError, match="Unsupported event_type"):
        store.record_event(bad_type_evt)

    # Unsupported provenance_source
    bad_src_evt = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.ACTION_PROPOSED.value,
        provenance_source="UNSUPPORTED_SOURCE",
        correlation_id="c1",
        request_id="r1",
        action_name="ACT",
        target="TGT",
        canonical_request_digest="dig",
        timestamp="2025-01-01T00:00:00Z"
    )
    with pytest.raises(RuntimeError, match="Unsupported provenance_source"):
        store.record_event(bad_src_evt)

    # Duplicate event_id
    dup_id = str(uuid.uuid4())
    good_evt = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=dup_id,
        event_type=ProvenanceEventType.ACTION_PROPOSED.value,
        provenance_source=ProvenanceSource.AGENT_ADAPTER.value,
        correlation_id="c1",
        request_id="r1",
        action_name="ACT",
        target="TGT",
        canonical_request_digest="dig",
        timestamp="2025-01-01T00:00:00Z"
    )
    store.record_event(good_evt)
    with pytest.raises(RuntimeError, match="Duplicate event_id"):
        store.record_event(good_evt)

    # Fail-open behavior
    open_store = LocalProvenanceStore(log_path=log_file, fail_closed=False)
    assert open_store.record_event(good_evt) == {}


def test_trusted_execution_boundary_validation(tmp_path):
    log_file = str(tmp_path / "prov_exec_val.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"data": "test"}
    digest = boundary.compute_canonical_digest(payload)

    exec_func = lambda: True
    policy = Policy(policy_id="p1", allowed_operations={"ACT"}, allowed_resources={"TGT"})
    cap3, _ = boundary.authority.evaluate_and_issue_capability("ACT", "TGT", digest, correlation_id="c1", request_id="r1", executor_id=exec_func, policy=policy)
    cap4, _ = boundary.authority.evaluate_and_issue_capability("ACT", "TGT", digest, correlation_id="c1", request_id="r1", executor_id=exec_func, policy=policy)

    # Reject authorization not granted
    with pytest.raises(PermissionError, match="Authorization was not granted"):
        boundary.execute_protected_action(
            action_name="ACT",
            target="TGT",
            request_payload=payload,
            correlation_id="c1",
            request_id="r1",
            authorization_token_id="tok1",
            authorized_digest=digest,
            authorization_granted=False,
            executor_func=exec_func
        )

    # Digest mismatch
    with pytest.raises(ValueError, match="digest changed"):
        boundary.execute_protected_action(
            action_name="ACT",
            target="TGT",
            request_payload=payload,
            correlation_id="c1",
            request_id="r1",
            authorization_token_id="tok2",
            authorized_digest="wrong_digest",
            authorization_granted=True,
            executor_func=exec_func
        )

    # Attempt ID reuse
    attempt_id = str(uuid.uuid4())
    boundary.execute_protected_action(
        action_name="ACT",
        target="TGT",
        request_payload=payload,
        correlation_id="c1",
        request_id="r1",
        authorization_token_id=cap3.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        execution_attempt_id=attempt_id,
        executor_func=exec_func
    )
    with pytest.raises(ValueError, match="has already been processed"):
        boundary.execute_protected_action(
            action_name="ACT",
            target="TGT",
            request_payload=payload,
            correlation_id="c1",
            request_id="r1",
            authorization_token_id=cap4.token_id,
            authorized_digest=digest,
            authorization_granted=True,
            execution_attempt_id=attempt_id,
            executor_func=exec_func
        )


def test_provenance_reconciler_edge_cases():
    reconciler = ProvenanceReconciler()

    # Rule 0: Empty events
    rep_empty = reconciler.reconcile_correlation("c_empty", [])
    assert not rep_empty.valid
    assert rep_empty.status == "INCOMPLETE_EVIDENCE"

    # Rule: Unmatched execution attempt despite auth_granted
    auth_redacted = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id="c_unmatch",
        request_id="[REDACTED]",
        action_name="READ",
        target="T1",
        canonical_request_digest="d1",
        timestamp="ts",
        authorization_token_id="[REDACTED]"
    )
    auth_redacted2 = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id="c_unmatch",
        request_id="[REDACTED]",
        action_name="WRITE",
        target="T2",
        canonical_request_digest="d2",
        timestamp="ts",
        authorization_token_id="[REDACTED]"
    )
    exec_unmatched = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_STARTED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id="c_unmatch",
        request_id="r_other",
        action_name="READ",
        target="T1",
        canonical_request_digest="d1",
        timestamp="ts",
        authorization_token_id="tok_other",
        execution_attempt_id="att1"
    )
    rep_unmatch = reconciler.reconcile_correlation("c_unmatch", [auth_redacted, auth_redacted2, exec_unmatched])
    assert not rep_unmatch.valid
    assert any("could not be matched" in v for v in rep_unmatch.violations)

    # Rule 6: Duplicate execution attempt for single-use token
    exec_dup_start = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_STARTED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id="c_unmatch",
        request_id="r_other",
        action_name="READ",
        target="T1",
        canonical_request_digest="d1",
        timestamp="ts",
        authorization_token_id="tok_other",
        execution_attempt_id="att2"
    )
    rep_dup_token = reconciler.reconcile_correlation("c_unmatch", [auth_redacted, auth_redacted2, exec_unmatched, exec_dup_start])
    assert any("Multiple execution attempts" in v for v in rep_dup_token.violations)

    # Rule 7 & Incomplete evidence: Missing terminal outcome event
    rep_unended = reconciler.reconcile_correlation("c_unended", [exec_unmatched])
    assert any("missing terminal outcome event" in v for v in rep_unended.violations)

    # Rule 8: Egress blocked by Shower Curtain
    egress_evt = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EGRESS_BLOCKED.value,
        provenance_source=ProvenanceSource.EGRESS_GATE.value,
        correlation_id="c_egress",
        request_id="r1",
        action_name="DISCLOSE",
        target="remote",
        canonical_request_digest="d1",
        timestamp="ts"
    )
    rep_egress = reconciler.reconcile_correlation("c_egress", [egress_evt], agent_claimed_success=True)
    assert any("egress was blocked" in v for v in rep_egress.violations)

    # Status: INCOMPLETE_EVIDENCE when auth_granted but no execution started/succeeded
    auth_only = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id="c_incomplete",
        request_id="r1",
        action_name="READ",
        target="T1",
        canonical_request_digest="d1",
        timestamp="ts",
        authorization_token_id="tok1"
    )
    rep_inc = reconciler.reconcile_correlation("c_incomplete", [auth_only])
    assert not rep_inc.valid
    assert rep_inc.status == "INCOMPLETE_EVIDENCE"


def test_provenance_store_corruption_detection_branches(tmp_path):
    log_file = tmp_path / "prov_corrupt_branches.jsonl"
    store = LocalProvenanceStore(log_path=str(log_file))

    e1 = ProvenanceEvent(
        schema_version="1.0.0",
        event_id="evt1",
        event_type=ProvenanceEventType.ACTION_PROPOSED.value,
        provenance_source=ProvenanceSource.AGENT_ADAPTER.value,
        correlation_id="c1",
        request_id="r1",
        action_name="A",
        target="T",
        canonical_request_digest="d1",
        timestamp="ts"
    )
    res1 = store.record_event(e1)

    # 1. Test duplicate event ID detection during log health inspection (Line 172)
    with open(log_file, "a") as f:
        f.write(json.dumps(res1) + "\n")

    healthy, _, count, ids = store._inspect_health()
    assert healthy is False

    # 2. Test broken chain prev_hash detection (Line 181)
    with open(log_file, "w") as f:
        broken_entry = dict(res1)
        broken_entry["event_id"] = "evt2"
        broken_entry["prev_hash"] = "WRONG_PREV"
        broken_entry["entry_hash"] = store._compute_chain_hash("WRONG_PREV", {k: v for k, v in broken_entry.items() if k != "entry_hash"})
        f.write(json.dumps(broken_entry) + "\n")

    healthy2, _, _, _ = store._inspect_health()
    assert healthy2 is False

    # 3. Test tampered entry hash detection (Line 188)
    with open(log_file, "w") as f:
        tampered_entry = dict(res1)
        tampered_entry["action_name"] = "MUTATED"
        f.write(json.dumps(tampered_entry) + "\n")

    healthy3, _, _, _ = store._inspect_health()
    assert healthy3 is False

    # 4. Test defensive skipping of malformed JSON lines during get_events_for_correlation (Line 203 & 209)
    with open(log_file, "w") as f:
        f.write("{malformed json line}\n")
        f.write(json.dumps(res1) + "\n")
        f.write("{another bad line\n")

    events = store.get_events_for_correlation("c1")
    assert len(events) == 1
    assert events[0].event_id == "evt1"


def test_provenance_reconciler_digest_mismatch_branch():
    reconciler = ProvenanceReconciler()
    auth = ProvenanceEvent(
        schema_version="1.0.0",
        event_id="e1",
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id="c_dig",
        request_id="r1",
        action_name="READ",
        target="T1",
        canonical_request_digest="dig_original",
        timestamp="ts",
        authorization_token_id="tok1"
    )
    exec_start = ProvenanceEvent(
        schema_version="1.0.0",
        event_id="e2",
        event_type=ProvenanceEventType.EXECUTION_STARTED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id="c_dig",
        request_id="r1",
        action_name="READ",
        target="T1",
        canonical_request_digest="dig_MUTATED",
        timestamp="ts",
        authorization_token_id="tok1",
        execution_attempt_id="att1"
    )
    report = reconciler.reconcile_correlation("c_dig", [auth, exec_start])
    assert not report.valid
    assert any("digest changed" in v for v in report.violations)


def test_reconciliation_report_to_dict_and_single_redacted_auth_fallback():
    reconciler = ProvenanceReconciler()

    # Redacted auth_granted single fallback (Line 438)
    auth_redacted = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id="c_single_redacted",
        request_id="[REDACTED]",
        action_name="READ",
        target="T1",
        canonical_request_digest="d1",
        timestamp="ts",
        authorization_token_id="[REDACTED]"
    )
    exec_started = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_STARTED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id="c_single_redacted",
        request_id="[REDACTED]",
        action_name="READ",
        target="T1",
        canonical_request_digest="d1",
        timestamp="ts",
        authorization_token_id="[REDACTED]",
        execution_attempt_id="att1"
    )
    exec_succ = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_SUCCEEDED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id="c_single_redacted",
        request_id="[REDACTED]",
        action_name="READ",
        target="T1",
        canonical_request_digest="d1",
        timestamp="ts",
        authorization_token_id="[REDACTED]",
        execution_attempt_id="att1"
    )

    report = reconciler.reconcile_correlation("c_single_redacted", [auth_redacted, exec_started, exec_succ], agent_claimed_success=True)
    assert report.valid is True
    assert report.status == "RECONCILED"

    # Line 369: ReconciliationReport.to_dict()
    rep_dict = report.to_dict()
    assert isinstance(rep_dict, dict)
    assert rep_dict["valid"] is True
    assert rep_dict["status"] == "RECONCILED"


def test_execution_context_dataclass():
    ctx = ExecutionContext(
        correlation_id="corr-ctx-1",
        request_id="req-ctx-1",
        authorization_token_id="tok-ctx-1",
        authorized_digest="digest-ctx-1",
        authorization_granted=True,
        execution_attempt_id="att-ctx-1",
        policy_version="1.1.0"
    )
    d = ctx.to_dict()
    assert d["correlation_id"] == "corr-ctx-1"
    assert d["request_id"] == "req-ctx-1"
    assert d["authorization_token_id"] == "tok-ctx-1"
    assert d["authorized_digest"] == "digest-ctx-1"
    assert d["authorization_granted"] is True
    assert d["execution_attempt_id"] == "att-ctx-1"
    assert d["policy_version"] == "1.1.0"


def test_execute_protected_action_with_execution_context_keyword(tmp_path):
    log_file = str(tmp_path / "prov_ctx_kw.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"action": "UPDATE_POLICY"}
    digest = boundary.compute_canonical_digest(payload)
    corr_id = str(uuid.uuid4())

    exec_func = lambda: "UPDATED"
    policy = Policy(policy_id="p1", version="2.0.0", allowed_operations={"UPDATE"}, allowed_resources={"policy-engine"})
    cap, _ = boundary.authority.evaluate_and_issue_capability("UPDATE", "policy-engine", digest, correlation_id=corr_id, request_id="req-kw", executor_id=exec_func, policy=policy)

    ctx = ExecutionContext(
        correlation_id=corr_id,
        request_id="req-kw",
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        policy_version="2.0.0"
    )

    res = boundary.execute_protected_action(
        action_name="UPDATE",
        target="policy-engine",
        request_payload=payload,
        executor_func=exec_func,
        context=ctx
    )

    assert res["status"] == "SUCCESS"
    assert res["result"] == "UPDATED"

    events = store.get_events_for_correlation(corr_id)
    assert len(events) == 2
    assert events[0].authorization_token_id == cap.token_id


# =====================================================================
# PROVENANCE EVENT DIGEST TESTS
# =====================================================================

def test_compute_event_digest_deterministic_and_known_hash():
    """Verify compute_event_digest produces stable deterministic SHA-256 digests matching fixed expected value."""
    event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id="evt-fixed-id-101",
        event_type=ProvenanceEventType.ACTION_PROPOSED.value,
        provenance_source=ProvenanceSource.AGENT_ADAPTER.value,
        correlation_id="corr-fixed-202",
        request_id="req-fixed-303",
        action_name="READ_FILE",
        target="/tmp/test_file.txt",
        canonical_request_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        timestamp="2025-01-01T12:00:00Z",
        sequence_number=1
    )

    digest1 = event.compute_event_digest()
    digest2 = event.compute_event_digest()

    assert isinstance(digest1, str)
    assert len(digest1) == 64
    assert digest1 == digest2

    # Manually build expected json with sorted keys and verify sha256 hash match
    expected_data = event.to_dict()
    assert "event_digest" not in expected_data
    expected_json = json.dumps(expected_data, sort_keys=True).encode("utf-8")
    import hashlib
    expected_hash = hashlib.sha256(expected_json).hexdigest()

    assert digest1 == expected_hash


def test_compute_event_digest_field_mutation_sensitivity():
    """Verify compute_event_digest changes when any single event field is mutated."""
    base_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id="evt-base",
        event_type=ProvenanceEventType.EXECUTION_STARTED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id="corr-base",
        request_id="req-base",
        action_name="RUN_SCRIPT",
        target="script.py",
        canonical_request_digest="digest-base",
        timestamp="2025-01-01T00:00:00Z",
        authorization_token_id="tok-base",
        execution_attempt_id="att-base",
        sequence_number=5,
        prev_hash="prev-hash-123"
    )

    base_digest = base_event.compute_event_digest()

    mutations = [
        ("action_name", "RUN_SCRIPT_MUTATED"),
        ("target", "script_v2.py"),
        ("timestamp", "2025-01-01T00:00:01Z"),
        ("sequence_number", 6),
        ("prev_hash", "prev-hash-456"),
        ("authorization_token_id", "tok-mutated"),
        ("outcome", {"status": "SUCCESS"}),
        ("metadata", {"env": "prod"})
    ]

    for attr, mutated_val in mutations:
        event_dict = asdict(base_event)
        event_dict[attr] = mutated_val
        mutated_event = ProvenanceEvent(**event_dict)
        mutated_digest = mutated_event.compute_event_digest()
        assert mutated_digest != base_digest, f"Digest failed to change for field mutation: {attr}"


def test_compute_event_digest_key_sorting_and_event_digest_exclusion():
    """Verify compute_event_digest excludes any event_digest attribute if present and sorts keys deterministically."""
    event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id="evt-sort",
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id="c-sort",
        request_id="r-sort",
        action_name="GRANT",
        target="res-1",
        canonical_request_digest="dig-sort",
        timestamp="2025-01-01T00:00:00Z"
    )

    digest_clean = event.compute_event_digest()

    # Even if to_dict had an 'event_digest' key added or attached, it should be excluded from digest calculation
    data = event.to_dict()
    data["event_digest"] = "DUMMY_OLD_DIGEST_STRING"
    check_data = {k: v for k, v in data.items() if k != "event_digest"}
    serialized = json.dumps(check_data, sort_keys=True).encode("utf-8")
    import hashlib
    expected_digest = hashlib.sha256(serialized).hexdigest()

    assert digest_clean == expected_digest


def test_compute_event_digest_integrates_with_sanitization():
    """Verify compute_event_digest operates on sanitized event dictionary output."""
    event_sensitive = ProvenanceEvent(
        schema_version="1.0.0",
        event_id="evt-sec",
        event_type=ProvenanceEventType.EXECUTION_SUCCEEDED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id="c-sec",
        request_id="r-sec",
        action_name="AUTH",
        target="auth-service",
        canonical_request_digest="dig-sec",
        timestamp="2025-01-01T00:00:00Z",
        outcome={"api_key": "sk-123456789012345678901234", "user_email": "admin@example.com"}
    )

    digest = event_sensitive.compute_event_digest()

    # The digest must be computed over the sanitized output where api_key and user_email are redacted
    sanitized_dict = event_sensitive.to_dict()
    assert sanitized_dict["outcome"]["api_key"] == "[REDACTED]"
    assert sanitized_dict["outcome"]["user_email"] == "[REDACTED]"

    import hashlib
    expected_digest = hashlib.sha256(json.dumps(sanitized_dict, sort_keys=True).encode("utf-8")).hexdigest()
    assert digest == expected_digest


# =====================================================================
# PROVENANCE SANITIZATION TESTS
# =====================================================================

def test_provenance_sanitize_sensitive_data_direct_dictionary_sanitization():
    """Validates direct sanitization behavior of _sanitize_sensitive_data imported in provenance.py."""
    data = {
        "user_secret": "top_secret_value",
        "api_key": "sk-123456789012345678901234",
        "account_password": "my_password_123",
        "auth_token": "Bearer eyJhbGciOiJIUzI1NiJ9",
        "user_id": "usr_999",
        "request_count": 42,
        "is_active": True,
        "null_field": None,
        "nested": {
            "private_key": "0xABCDEF1234567890",
            "safe_name": "John Doe"
        },
        "item_list": [
            {"secret_code": "007", "public_id": "item_1"},
            "clean_string"
        ],
        "tags_set": {"normal_tag", "password=raw_pass"},
        "tuple_info": ("info", "token=secret_tok_123")
    }

    sanitized = _sanitize_sensitive_data(data)

    assert sanitized["user_secret"] == "[REDACTED]"
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["account_password"] == "[REDACTED]"
    assert sanitized["auth_token"] == "[REDACTED]"
    assert sanitized["user_id"] == "usr_999"
    assert sanitized["request_count"] == 42
    assert sanitized["is_active"] is True
    assert sanitized["null_field"] is None
    assert sanitized["nested"]["private_key"] == "[REDACTED]"
    assert sanitized["nested"]["safe_name"] == "John Doe"
    assert sanitized["item_list"][0]["secret_code"] == "[REDACTED]"
    assert sanitized["item_list"][0]["public_id"] == "item_1"
    assert "password=[REDACTED]" in sanitized["tags_set"]
    assert "token=[REDACTED]" in sanitized["tuple_info"][1]


def test_provenance_sanitize_sensitive_data_pii_string_patterns():
    """Validates free-text credential and PII pattern redaction via _sanitize_sensitive_data."""
    plain_text = "Contact user at alice@example.com or +1-555-123-4567. Key: sk-1234567890123456789020."
    sanitized = _sanitize_sensitive_data(plain_text)

    assert "alice@example.com" not in sanitized
    assert "[REDACTED_EMAIL]" in sanitized
    assert "+1-555-123-4567" not in sanitized
    assert "[REDACTED_PHONE]" in sanitized
    assert "sk-1234567890123456789020" not in sanitized
    assert "sk-[REDACTED]" in sanitized


def test_provenance_event_to_dict_sanitization():
    """Validates that ProvenanceEvent.to_dict() automatically sanitizes sensitive fields."""
    event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_SUCCEEDED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id="corr-san-1",
        request_id="req-san-1",
        action_name="EXECUTE_MUTATION",
        target="database-main",
        canonical_request_digest="dig-san-1",
        timestamp="2025-01-01T00:00:00Z",
        outcome={
            "status": "SUCCESS",
            "api_key": "sk-secret-key-abcdef0123456789",
            "user_email": "admin@company.com"
        },
        metadata={
            "bearer_token": "Bearer token1234567890",
            "client_ip": "127.0.0.1"
        }
    )

    event_dict = event.to_dict()

    assert event_dict["outcome"]["api_key"] == "[REDACTED]"
    assert event_dict["outcome"]["user_email"] == "[REDACTED]"
    assert event_dict["metadata"]["bearer_token"] == "[REDACTED]"
    assert event_dict["metadata"]["client_ip"] == "127.0.0.1"


def test_trusted_execution_boundary_digest_fallback_sanitization(tmp_path):
    """Validates compute_canonical_digest exception fallback triggering _sanitize_sensitive_data."""
    from unittest.mock import patch

    store = LocalProvenanceStore(log_path=str(tmp_path / "prov_digest_fallback.jsonl"))
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"api_key": "sk-secret-key-1234567890"}

    # Mock json.dumps to fail on the initial call and succeed on the fallback call after _sanitize_sensitive_data
    with patch("json.dumps", side_effect=[TypeError("initial serialization failure"), '{"api_key": "[REDACTED]"}']):
        digest = boundary.compute_canonical_digest(payload)
        assert isinstance(digest, str)
        assert len(digest) == 64


def test_trusted_execution_boundary_outcome_sanitization_unverified_and_success(tmp_path):
    log_file = str(tmp_path / "prov_outcome_san.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    boundary = TrustedExecutionBoundary(provenance_store=store)

    sensitive_result = {
        "status_code": 200,
        "access_token": "secret_access_token_val_123",
        "user_email": "user@domain.com",
        "result_data": "public_data"
    }

    # 1. Test UNVERIFIED_SUCCESS outcome sanitization when required evidence is missing
    digest1 = boundary.compute_canonical_digest({"op": "AUTH_STEP_1"})
    corr_id1 = str(uuid.uuid4())
    exec_func1 = lambda: sensitive_result

    policy1 = Policy(policy_id="p1", allowed_operations={"AUTH"}, allowed_resources={"auth-srv"})
    cap1, _ = boundary.authority.evaluate_and_issue_capability("AUTH", "auth-srv", digest1, correlation_id=corr_id1, request_id="req-s1", executor_id=exec_func1, policy=policy1)

    ctx1 = ExecutionContext(
        correlation_id=corr_id1,
        request_id="req-s1",
        authorization_token_id=cap1.token_id,
        authorized_digest=digest1,
        authorization_granted=True,
        required_success_evidence={"missing_required_evidence_key"}
    )

    res1 = boundary.execute_protected_action(
        action_name="AUTH",
        target="auth-srv",
        request_payload={"op": "AUTH_STEP_1"},
        executor_func=exec_func1,
        context=ctx1
    )

    assert res1["status"] == "UNVERIFIED_SUCCESS"

    events1 = store.get_events_for_correlation(corr_id1)
    fail_ev = [e for e in events1 if e.event_type == ProvenanceEventType.EXECUTION_FAILED.value][0]
    assert fail_ev.outcome["result"]["access_token"] == "[REDACTED]"
    assert fail_ev.outcome["result"]["user_email"] == "[REDACTED]"
    assert fail_ev.outcome["result"]["result_data"] == "public_data"

    # 2. Test SUCCESS outcome sanitization
    digest2 = boundary.compute_canonical_digest({"op": "AUTH_STEP_2"})
    corr_id2 = str(uuid.uuid4())
    exec_func2 = lambda: sensitive_result

    policy2 = Policy(policy_id="p2", allowed_operations={"AUTH"}, allowed_resources={"auth-srv"})
    cap2, _ = boundary.authority.evaluate_and_issue_capability("AUTH", "auth-srv", digest2, correlation_id=corr_id2, request_id="req-s2", executor_id=exec_func2, policy=policy2)

    res2 = boundary.execute_protected_action(
        action_name="AUTH",
        target="auth-srv",
        request_payload={"op": "AUTH_STEP_2"},
        correlation_id=corr_id2,
        request_id="req-s2",
        authorization_token_id=cap2.token_id,
        authorized_digest=digest2,
        authorization_granted=True,
        executor_func=exec_func2
    )

    assert res2["status"] == "SUCCESS"

    events2 = store.get_events_for_correlation(corr_id2)
    succ_ev = [e for e in events2 if e.event_type == ProvenanceEventType.EXECUTION_SUCCEEDED.value][0]
    assert succ_ev.outcome["result"]["access_token"] == "[REDACTED]"
    assert succ_ev.outcome["result"]["user_email"] == "[REDACTED]"
    assert succ_ev.outcome["result"]["result_data"] == "public_data"


def test_execute_protected_action_with_execution_context_positional(tmp_path):
    log_file = str(tmp_path / "prov_ctx_pos.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"action": "RESET_CACHE"}
    digest = boundary.compute_canonical_digest(payload)
    corr_id = str(uuid.uuid4())

    exec_func = lambda: "CACHE_CLEARED"
    policy = Policy(policy_id="p1", allowed_operations={"CACHE_RESET"}, allowed_resources={"redis-cluster"})
    cap, _ = boundary.authority.evaluate_and_issue_capability("CACHE_RESET", "redis-cluster", digest, correlation_id=corr_id, request_id="req-pos", executor_id=exec_func, policy=policy)

    ctx = ExecutionContext(
        correlation_id=corr_id,
        request_id="req-pos",
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    res = boundary.execute_protected_action(
        "CACHE_RESET",
        "redis-cluster",
        payload,
        ctx,
        exec_func
    )

    assert res["status"] == "SUCCESS"
    assert res["result"] == "CACHE_CLEARED"

    events = store.get_events_for_correlation(corr_id)
    assert len(events) == 2
    assert events[0].authorization_token_id == cap.token_id
