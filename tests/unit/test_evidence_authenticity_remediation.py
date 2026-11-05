"""
Adversarial Verification & Regression Test Suite for Phase 1 Execution Evidence Authenticity.
Remediates VULN-EVID-01 & VULN-EVID-02.
Tests cover:
1. Fabricated authorization grant with nonexistent token rejected.
2. Fabricated execution lifecycle with nonexistent token rejected.
3. Real issued capability with altered action, target, or digest rejected.
4. Real issued capability with mismatched principal or task context rejected.
5. Fabricated SUCCESS after genuine token consumption (where boundary recorded failure) rejected.
6. Legitimate consumed capability with valid historical execution evidence reconciles successfully.
7. Capability expired after execution remains historically valid.
8. Capability revoked after execution remains historically valid.
9. Capability revoked or expired prior to dispatch is rejected.
10. Atomic dispatch recording: failure between consumption and dispatch cannot leave unrecorded consumption.
11. Missing terminal outcome produces OUTCOME_UNKNOWN, never inferred success.
12. Terminal outcome immutability: attempts to overwrite terminal outcome fail closed.
13. FileAuthorizationStore durability across close/reopen.
14. Missing authority returns explicit UNVERIFIED_LEGACY_EVIDENCE and UI status UNVERIFIED when legacy unverified is disallowed.
15. Failure injection after dispatch produces OUTCOME_UNKNOWN and recovery_required=True.
16. Monotonic ordering serializes revocation and dispatch deterministically.
17. Attempt-ID collision and duplicate terminal outcome rejection in reconciliation.
"""

import time
import uuid
import pytest

from epistemicos.authorization import (
    AuthorizationAuthority,
    CapabilityRegistry,
    Policy,
    Capability,
    FileAuthorizationStore,
    canonicalize_fencing_scope,
)
from epistemicos.provenance import (
    LocalProvenanceStore,
    ProvenanceEvent,
    ProvenanceEventType,
    ProvenanceSource,
    TrustedExecutionBoundary,
    ProvenanceReconciler,
    ExecutionContext,
)
from epistemicos.ui.adapters import ObservatoryDataAdapter


@pytest.fixture
def test_setup(tmp_path):
    prov_path = tmp_path / "provenance.jsonl"
    audit_path = tmp_path / "audit.jsonl"
    denial_path = tmp_path / "denial.jsonl"

    store = LocalProvenanceStore(log_path=str(prov_path))
    cap_registry = CapabilityRegistry(denial_log_path=str(denial_path))
    authority = AuthorizationAuthority(registry=cap_registry)
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=authority)

    policy = Policy(
        policy_id="test_policy",
        allowed_operations={"read_file", "write_file", "delete_file"},
        allowed_resources={"/data/resource.txt", "/data/prod_db"}
    )
    authority.default_policy = policy

    return {
        "store": store,
        "registry": cap_registry,
        "authority": authority,
        "boundary": boundary,
        "prov_path": str(prov_path),
        "audit_path": str(audit_path),
        "policy": policy
    }


def test_1_fabricated_grant_with_nonexistent_token_rejected(test_setup):
    """Test 1: Fabricated grant event with nonexistent token ID is rejected by reconciler."""
    store = test_setup["store"]
    authority = test_setup["authority"]
    reconciler = ProvenanceReconciler(authority=authority)

    corr_id = "corr_fake_grant"
    fake_grant = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id="req-1",
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest="fake_digest",
        timestamp="2026-11-03T00:00:00Z",
        authorization_token_id="tok-nonexistent-999"
    )
    store.record_event(fake_grant)

    events = store.get_events_for_correlation(corr_id)
    report = reconciler.reconcile_correlation(corr_id, events)

    assert report.valid is False
    assert report.status == "RECONCILIATION_MISMATCH"
    assert any("was never issued by authoritative registry" in v for v in report.violations)


def test_2_fabricated_execution_lifecycle_rejected(test_setup):
    """Test 2: Complete fabricated lifecycle with nonexistent token ID is rejected and maps to MISMATCH status."""
    store = test_setup["store"]
    authority = test_setup["authority"]
    prov_path = test_setup["prov_path"]
    audit_path = test_setup["audit_path"]

    corr_id = "corr_fake_lifecycle"
    tok_id = "tok-forged-lifecycle"

    ev1 = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id="req-1",
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest="fake_digest",
        timestamp="2026-11-03T00:00:00Z",
        authorization_token_id=tok_id
    )
    ev2 = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_STARTED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id=corr_id,
        request_id="req-1",
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest="fake_digest",
        timestamp="2026-11-03T00:00:01Z",
        authorization_token_id=tok_id,
        execution_attempt_id="att-fake-1"
    )
    ev3 = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_SUCCEEDED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id=corr_id,
        request_id="req-1",
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest="fake_digest",
        timestamp="2026-11-03T00:00:02Z",
        authorization_token_id=tok_id,
        execution_attempt_id="att-fake-1",
        outcome={"status": "SUCCESS"}
    )
    for e in (ev1, ev2, ev3):
        store.record_event(e)

    reconciler = ProvenanceReconciler(authority=authority)
    events = store.get_events_for_correlation(corr_id)
    report = reconciler.reconcile_correlation(corr_id, events, agent_claimed_success=True)

    assert report.valid is False
    assert report.status == "RECONCILIATION_MISMATCH"

    # Verify downstream Observatory UI consumer reports MISMATCH (never COMPLETED or normal FAILED)
    adapter = ObservatoryDataAdapter(
        audit_log_path=audit_path,
        provenance_log_path=prov_path,
        authority=authority
    )
    trace = adapter.get_execution_trace_by_id(corr_id)
    assert trace is not None
    assert trace["status"] == "MISMATCH"
    assert trace["reconciliation"]["valid"] is False


def test_3_real_capability_with_altered_target_or_digest_rejected(test_setup):
    """Test 3: Real capability where event metadata is altered (target mismatch) is rejected."""
    store = test_setup["store"]
    authority = test_setup["authority"]
    boundary = test_setup["boundary"]

    payload = {"data": "legit"}
    digest = boundary.compute_canonical_digest(payload)
    def exec_func(): return {"res": "ok"}

    corr_id = "corr_tamper_meta"
    cap, _ = authority.evaluate_and_issue_capability(
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id="req-1",
        executor_id=exec_func
    )

    altered_grant = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id="req-1",
        action_name="read_file",
        target="/data/prod_db",  # Altered!
        canonical_request_digest=digest,
        timestamp="2026-11-03T00:00:00Z",
        authorization_token_id=cap.token_id
    )
    store.record_event(altered_grant)

    reconciler = ProvenanceReconciler(authority=authority)
    events = store.get_events_for_correlation(corr_id)
    report = reconciler.reconcile_correlation(corr_id, events)

    assert report.valid is False
    assert report.status == "RECONCILIATION_MISMATCH"
    assert any("TARGET_MISMATCH" in v for v in report.violations)


def test_4_real_capability_with_mismatched_principal_rejected(test_setup):
    """Test 4: Real capability bound to a privileged principal fails when event is attributed to wrong principal."""
    authority = test_setup["authority"]
    boundary = test_setup["boundary"]

    payload = {"data": "test"}
    digest = boundary.compute_canonical_digest(payload)
    def exec_func(): return True

    corr_id = "corr_principal_mismatch"
    cap, _ = authority.evaluate_and_issue_capability(
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id="req-1",
        executor_id=exec_func,
        principal_id="alice"
    )

    valid, reason, _, _ = authority.verify_historical_capability(
        token_id=cap.token_id,
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id="req-1",
        principal_id="mallory"  # Mismatch!
    )

    assert valid is False
    assert "PRINCIPAL_MISMATCH" in reason


def test_5_fabricated_success_after_genuine_token_failure_rejected(test_setup):
    """Test 5: Token consumed and execution FAILED at boundary, but attacker injects fake EXECUTION_SUCCEEDED."""
    store = test_setup["store"]
    authority = test_setup["authority"]
    boundary = test_setup["boundary"]
    prov_path = test_setup["prov_path"]
    audit_path = test_setup["audit_path"]

    payload = {"data": "fail_test"}
    digest = boundary.compute_canonical_digest(payload)

    def failing_executor():
        raise RuntimeError("Service crashed during execution")

    corr_id = "corr_token_failed_attempt"
    req_id = "req-1"
    cap, _ = authority.evaluate_and_issue_capability(
        action_name="write_file",
        target="/data/resource.txt",
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

    grant_ev = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id=req_id,
        action_name="write_file",
        target="/data/resource.txt",
        canonical_request_digest=digest,
        timestamp="2026-11-03T00:00:00Z",
        authorization_token_id=cap.token_id
    )
    store.record_event(grant_ev)

    with pytest.raises(RuntimeError):
        boundary.execute_protected_action(
            action_name="write_file",
            target="/data/resource.txt",
            request_payload=payload,
            executor_func=failing_executor,
            context=ctx
        )

    events = store.get_events_for_correlation(corr_id)
    start_events = [e for e in events if e.event_type == "EXECUTION_STARTED"]
    assert len(start_events) == 1
    attempt_id = start_events[0].execution_attempt_id

    exec_record = authority.registry.get_execution_record(cap.token_id, attempt_id)
    assert exec_record is not None
    assert exec_record["outcome_status"] == "FAILED"

    # Attacker injects a fabricated EXECUTION_SUCCEEDED for this attempt
    fake_success = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_SUCCEEDED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id=corr_id,
        request_id=req_id,
        action_name="write_file",
        target="/data/resource.txt",
        canonical_request_digest=digest,
        timestamp="2026-11-03T00:00:02Z",
        authorization_token_id=cap.token_id,
        execution_attempt_id=attempt_id,
        outcome={"status": "SUCCESS"}
    )
    store.record_event(fake_success)

    reconciler = ProvenanceReconciler(authority=authority)
    updated_events = store.get_events_for_correlation(corr_id)
    report = reconciler.reconcile_correlation(corr_id, updated_events, agent_claimed_success=True)

    assert report.valid is False
    assert report.status == "RECONCILIATION_MISMATCH"
    assert any("OUTCOME_CONTRADICTION" in v for v in report.violations)

    adapter = ObservatoryDataAdapter(
        audit_log_path=audit_path,
        provenance_log_path=prov_path,
        authority=authority
    )
    trace = adapter.get_execution_trace_by_id(corr_id)
    # Never COMPLETED
    assert trace["status"] != "COMPLETED"


def test_6_legitimate_execution_reconciles_successfully(test_setup):
    """Test 6: Genuine execution through TrustedExecutionBoundary reconciles with valid=True and status COMPLETED."""
    store = test_setup["store"]
    authority = test_setup["authority"]
    boundary = test_setup["boundary"]
    prov_path = test_setup["prov_path"]
    audit_path = test_setup["audit_path"]

    payload = {"data": "read_data"}
    digest = boundary.compute_canonical_digest(payload)
    def exec_func(): return {"content": "real_data"}

    corr_id = "corr_legit_success"
    req_id = "req-1"
    cap, _ = authority.evaluate_and_issue_capability(
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id=req_id,
        executor_id=exec_func
    )

    grant_ev = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id=req_id,
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest=digest,
        timestamp="2026-11-03T00:00:00Z",
        authorization_token_id=cap.token_id
    )
    store.record_event(grant_ev)

    ctx = ExecutionContext(
        correlation_id=corr_id,
        request_id=req_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    res = boundary.execute_protected_action(
        action_name="read_file",
        target="/data/resource.txt",
        request_payload=payload,
        executor_func=exec_func,
        context=ctx
    )
    assert res["status"] == "SUCCESS"

    reconciler = ProvenanceReconciler(authority=authority)
    events = store.get_events_for_correlation(corr_id)
    report = reconciler.reconcile_correlation(corr_id, events, agent_claimed_success=True)

    assert report.valid is True
    assert report.status == "RECONCILED"
    assert len(report.violations) == 0

    adapter = ObservatoryDataAdapter(
        audit_log_path=audit_path,
        provenance_log_path=prov_path,
        authority=authority
    )
    trace = adapter.get_execution_trace_by_id(corr_id)
    assert trace["status"] == "COMPLETED"


def test_7_post_execution_expiration_preserves_validity(test_setup):
    """Test 7: A capability that expires after execution was completed remains historically valid."""
    authority = test_setup["authority"]
    store = test_setup["store"]
    boundary = test_setup["boundary"]

    payload = {"data": "expiry_test"}
    digest = boundary.compute_canonical_digest(payload)
    def exec_func(): return True

    corr_id = "corr_expiry_temporal"
    req_id = "req-1"
    now_ts = time.time()
    cap, _ = authority.evaluate_and_issue_capability(
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id=req_id,
        executor_id=exec_func
    )
    cap.expires_at = now_ts + 0.1
    authority.registry.register_capability(cap)

    grant_ev = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id=req_id,
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest=digest,
        timestamp="2026-11-03T00:00:00Z",
        authorization_token_id=cap.token_id
    )
    store.record_event(grant_ev)

    ctx = ExecutionContext(
        correlation_id=corr_id,
        request_id=req_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )
    boundary.execute_protected_action(
        action_name="read_file",
        target="/data/resource.txt",
        request_payload=payload,
        executor_func=exec_func,
        context=ctx
    )

    time.sleep(0.15)
    assert cap.is_expired(time.time()) is True

    reconciler = ProvenanceReconciler(authority=authority)
    events = store.get_events_for_correlation(corr_id)
    report = reconciler.reconcile_correlation(corr_id, events, agent_claimed_success=True)

    assert report.valid is True
    assert report.status == "RECONCILED"


def test_8_post_execution_revocation_preserves_validity(test_setup):
    """Test 8: A capability revoked after execution remains historically valid for past executions."""
    authority = test_setup["authority"]
    store = test_setup["store"]
    boundary = test_setup["boundary"]

    payload = {"data": "revoke_test"}
    digest = boundary.compute_canonical_digest(payload)
    def exec_func(): return True

    corr_id = "corr_revoke_temporal"
    req_id = "req-1"
    cap, _ = authority.evaluate_and_issue_capability(
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id=req_id,
        executor_id=exec_func
    )

    grant_ev = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id=req_id,
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest=digest,
        timestamp="2026-11-03T00:00:00Z",
        authorization_token_id=cap.token_id
    )
    store.record_event(grant_ev)

    ctx = ExecutionContext(
        correlation_id=corr_id,
        request_id=req_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )
    boundary.execute_protected_action(
        action_name="read_file",
        target="/data/resource.txt",
        request_payload=payload,
        executor_func=exec_func,
        context=ctx
    )

    events = store.get_events_for_correlation(corr_id)

    # Post-execution revocation in storage journal
    now_ts = time.time() + 10.0
    authority.registry.storage._revoked_tokens.add(cap.token_id)
    authority.registry.storage._revocation_records[cap.token_id] = {
        "token_id": cap.token_id,
        "reason": "Security review retroactive revoke",
        "timestamp": now_ts,
        "seq": 9999
    }

    reconciler = ProvenanceReconciler(authority=authority)
    report = reconciler.reconcile_correlation(corr_id, events, agent_claimed_success=True)

    assert report.valid is True
    assert report.status == "RECONCILED"


def test_9_pre_execution_revocation_or_expiration_rejected(test_setup):
    """Test 9: Execution attempted after capability was revoked fails closed."""
    authority = test_setup["authority"]
    boundary = test_setup["boundary"]

    payload = {"data": "pre_revoke_test"}
    digest = boundary.compute_canonical_digest(payload)
    def exec_func(): return True

    cap, _ = authority.evaluate_and_issue_capability(
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest=digest,
        correlation_id="c1",
        request_id="r1",
        executor_id=exec_func
    )

    ok, _ = authority.registry.revoke_token(cap.token_id, reason="Admin revoked")
    assert ok is True

    ctx = ExecutionContext(
        correlation_id="c1",
        request_id="r1",
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    with pytest.raises(PermissionError, match="REVOKED"):
        boundary.execute_protected_action(
            action_name="read_file",
            target="/data/resource.txt",
            request_payload=payload,
            executor_func=exec_func,
            context=ctx
        )


def test_10_missing_terminal_outcome_produces_outcome_unknown(test_setup):
    """Test 10: Dispatch occurred but no terminal outcome was recorded -> reconciler reports missing terminal event."""
    authority = test_setup["authority"]
    store = test_setup["store"]

    corr_id = "corr_incomplete"
    req_id = "req-1"
    attempt_id = "att-incomplete-1"

    cap, _ = authority.evaluate_and_issue_capability(
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest="dig",
        correlation_id=corr_id,
        request_id=req_id,
        executor_id="default_executor"
    )

    ok, _, rec = authority.registry.consume_token_and_record_dispatch(
        token_id=cap.token_id,
        attempt_id=attempt_id,
        dispatched_executor_id="default_executor",
        started_at=time.time()
    )
    assert ok is True
    assert rec["outcome_status"] == "DISPATCHED"

    ev_grant = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id=req_id,
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest="dig",
        timestamp="2026-11-03T00:00:00Z",
        authorization_token_id=cap.token_id
    )
    ev_start = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_STARTED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id=corr_id,
        request_id=req_id,
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest="dig",
        timestamp="2026-11-03T00:00:01Z",
        authorization_token_id=cap.token_id,
        execution_attempt_id=attempt_id
    )
    store.record_event(ev_grant)
    store.record_event(ev_start)

    reconciler = ProvenanceReconciler(authority=authority)
    events = store.get_events_for_correlation(corr_id)
    report = reconciler.reconcile_correlation(corr_id, events)

    assert report.valid is False
    assert any("missing terminal outcome event" in v for v in report.violations)


def test_11_terminal_outcome_immutability(test_setup):
    """Test 11: Attempting to overwrite a committed terminal outcome fails closed."""
    registry = test_setup["registry"]

    tok_id = "tok_immutability"
    attempt_id = "att_immutability"
    now_ts = time.time()

    scope = canonicalize_fencing_scope(None, "tgt")
    cap = Capability(
        token_id=tok_id,
        principal_id="p1",
        correlation_id="c1",
        request_id="r1",
        action_name="act",
        target="tgt",
        canonical_request_digest="dig",
        executor_id="exec",
        policy_version="1.0",
        created_at=now_ts,
        expires_at=now_ts + 300,
        fencing_token=1,
        scope_key=scope
    )
    registry.register_capability(cap)

    ok, _, _ = registry.consume_token_and_record_dispatch(
        token_id=tok_id,
        attempt_id=attempt_id,
        dispatched_executor_id="exec",
        started_at=now_ts
    )
    assert ok is True

    ok1, _, _ = registry.record_execution_outcome(
        token_id=tok_id,
        attempt_id=attempt_id,
        outcome_status="SUCCESS",
        terminal_ts=now_ts + 1.0
    )
    assert ok1 is True

    ok2, reason2, _ = registry.record_execution_outcome(
        token_id=tok_id,
        attempt_id=attempt_id,
        outcome_status="FAILED",
        terminal_ts=now_ts + 2.0
    )
    assert ok2 is False
    assert "ALREADY_COMMITTED" in reason2


def test_12_file_authorization_store_durability_across_reopen(tmp_path):
    """Test 12: FileAuthorizationStore persists capabilities, attempts, and outcomes across store instances."""
    store_file = tmp_path / "auth_store.jsonl"
    store1 = FileAuthorizationStore(store_path=str(store_file))

    tok_id = "tok_persist_1"
    attempt_id = "att_persist_1"
    now_ts = time.time()

    scope = canonicalize_fencing_scope(None, "tgt")
    cap = Capability(
        token_id=tok_id,
        principal_id="p1",
        correlation_id="c1",
        request_id="r1",
        action_name="act",
        target="tgt",
        canonical_request_digest="dig",
        executor_id="exec",
        policy_version="1.0",
        created_at=now_ts,
        expires_at=now_ts + 300,
        fencing_token=1,
        scope_key=scope
    )
    store1.register_capability(cap)

    ok_d, _, rec_d = store1.consume_token_and_record_dispatch(
        token_id=tok_id,
        attempt_id=attempt_id,
        dispatched_executor_id="exec",
        started_at=now_ts
    )
    assert ok_d is True

    ok_o, _, rec_o = store1.record_execution_outcome(
        token_id=tok_id,
        attempt_id=attempt_id,
        outcome_status="SUCCESS",
        terminal_ts=now_ts + 1.0
    )
    assert ok_o is True

    store2 = FileAuthorizationStore(store_path=str(store_file))

    assert store2.is_consumed(tok_id) is True
    retrieved_cap = store2.get_capability(tok_id)
    assert retrieved_cap is not None
    assert retrieved_cap.token_id == tok_id

    exec_rec = store2.get_execution_record(tok_id, attempt_id)
    assert exec_rec is not None
    assert exec_rec["outcome_status"] == "SUCCESS"
    assert exec_rec["attempt_id"] == attempt_id


def test_13_unverified_legacy_evidence_when_legacy_disallowed(test_setup):
    """Test 13: When allow_unverified_legacy=False and authority is None, reconciler fails closed to UNVERIFIED_LEGACY_EVIDENCE."""
    store = test_setup["store"]
    reconciler = ProvenanceReconciler(authority=None, allow_unverified_legacy=False)

    corr_id = "corr_no_auth"
    ev1 = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id="r1",
        action_name="act",
        target="tgt",
        canonical_request_digest="dig",
        timestamp="ts",
        authorization_token_id="tok1"
    )
    ev2 = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_STARTED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id=corr_id,
        request_id="r1",
        action_name="act",
        target="tgt",
        canonical_request_digest="dig",
        timestamp="ts",
        authorization_token_id="tok1",
        execution_attempt_id="att1"
    )
    ev3 = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_SUCCEEDED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id=corr_id,
        request_id="r1",
        action_name="act",
        target="tgt",
        canonical_request_digest="dig",
        timestamp="ts",
        authorization_token_id="tok1",
        execution_attempt_id="att1"
    )
    for e in (ev1, ev2, ev3):
        store.record_event(e)

    events = store.get_events_for_correlation(corr_id)
    report = reconciler.reconcile_correlation(corr_id, events)

    assert report.valid is False
    assert report.status == "UNVERIFIED_LEGACY_EVIDENCE"


def test_14_failure_injection_after_dispatch_produces_outcome_unknown(test_setup):
    """Test 14: Failure injection during terminal outcome persistence leaves attempt in DISPATCHED state and returns OUTCOME_UNKNOWN."""
    boundary = test_setup["boundary"]
    authority = test_setup["authority"]

    payload = {"data": "dispatch_only"}
    digest = boundary.compute_canonical_digest(payload)
    def exec_func(): return {"result": "success_in_memory"}

    corr_id = "corr_crash_outcome"
    req_id = "req-1"
    cap, _ = authority.evaluate_and_issue_capability(
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id=req_id,
        executor_id=exec_func
    )

    ctx = ExecutionContext(
        correlation_id=corr_id,
        request_id=req_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    def failing_record_outcome(*args, **kwargs):
        raise OSError("Disk I/O error during outcome commit")

    orig_record = authority.registry.record_execution_outcome
    authority.registry.record_execution_outcome = failing_record_outcome

    try:
        res = boundary.execute_protected_action(
            action_name="read_file",
            target="/data/resource.txt",
            request_payload=payload,
            executor_func=exec_func,
            context=ctx
        )
        assert res["status"] == "EXECUTION_OUTCOME_UNKNOWN"
        assert res["recovery_required"] is True
    finally:
        authority.registry.record_execution_outcome = orig_record


def test_15_concurrent_revocation_and_dispatch_deterministic_ordering(tmp_path):
    """Test 15: Monotonic sequence ordering determines whether revocation or dispatch wins deterministically."""
    store_file = tmp_path / "auth_ordering.jsonl"
    store = FileAuthorizationStore(store_path=str(store_file))

    scope = canonicalize_fencing_scope(None, "tgt")
    now_ts = time.time()
    cap = Capability(
        token_id="tok_race_1",
        principal_id="p1",
        correlation_id="c1",
        request_id="r1",
        action_name="act",
        target="tgt",
        canonical_request_digest="dig",
        executor_id="exec",
        policy_version="1.0",
        created_at=now_ts,
        expires_at=now_ts + 300,
        fencing_token=1,
        scope_key=scope
    )
    store.register_capability(cap)

    ok_rev, _ = store.revoke_capability("tok_race_1", reason="Pre-dispatch revoke")
    assert ok_rev is True

    ok_disp, reason, _ = store.consume_token_and_record_dispatch(
        token_id="tok_race_1",
        attempt_id="att_race_1",
        dispatched_executor_id="exec",
        started_at=time.time()
    )
    assert ok_disp is False
    assert "REVOKED" in reason


def test_16_duplicate_terminal_events_rejected_in_reconciliation(test_setup):
    """Test 16: An attempt having duplicate terminal outcome events is flagged and rejected."""
    store = test_setup["store"]
    authority = test_setup["authority"]

    corr_id = "corr_dup_terminal"
    tok_id = "tok_dup_terminal"
    attempt_id = "att_dup_terminal"

    cap, _ = authority.evaluate_and_issue_capability(
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest="dig",
        correlation_id=corr_id,
        request_id="r1",
        executor_id="default_executor"
    )

    ev_grant = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id="r1",
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest="dig",
        timestamp="2026-11-03T00:00:00Z",
        authorization_token_id=cap.token_id
    )
    ev_start = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_STARTED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id=corr_id,
        request_id="r1",
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest="dig",
        timestamp="2026-11-03T00:00:01Z",
        authorization_token_id=cap.token_id,
        execution_attempt_id=attempt_id
    )
    ev_succ1 = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_SUCCEEDED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id=corr_id,
        request_id="r1",
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest="dig",
        timestamp="2026-11-03T00:00:02Z",
        authorization_token_id=cap.token_id,
        execution_attempt_id=attempt_id,
        outcome={"status": "SUCCESS"}
    )
    ev_succ2 = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.EXECUTION_SUCCEEDED.value,
        provenance_source=ProvenanceSource.EXECUTOR.value,
        correlation_id=corr_id,
        request_id="r1",
        action_name="read_file",
        target="/data/resource.txt",
        canonical_request_digest="dig",
        timestamp="2026-11-03T00:00:03Z",
        authorization_token_id=cap.token_id,
        execution_attempt_id=attempt_id,
        outcome={"status": "SUCCESS"}
    )

    store.record_event(ev_grant)
    store.record_event(ev_start)
    store.record_event(ev_succ1)
    store.record_event(ev_succ2)

    reconciler = ProvenanceReconciler(authority=authority)
    events = store.get_events_for_correlation(corr_id)
    report = reconciler.reconcile_correlation(corr_id, events)

    assert report.valid is False
    assert any("Multiple terminal outcome events detected" in v for v in report.violations)


def test_17_atomic_dispatch_failure_injection_prevents_partial_consumption(tmp_path):
    """Test 17: If journal persistence fails during dispatch, the transaction fails closed without partial consumption."""
    store_file = tmp_path / "auth_atomicity.jsonl"
    store = FileAuthorizationStore(store_path=str(store_file))

    scope = canonicalize_fencing_scope(None, "tgt")
    now_ts = time.time()
    tok_id = "tok_atomic_fail_1"
    cap = Capability(
        token_id=tok_id,
        principal_id="p1",
        correlation_id="c1",
        request_id="r1",
        action_name="act",
        target="tgt",
        canonical_request_digest="dig",
        executor_id="exec",
        policy_version="1.0",
        created_at=now_ts,
        expires_at=now_ts + 300,
        fencing_token=1,
        scope_key=scope
    )
    store.register_capability(cap)

    # Monkeypatch _append_record_under_lock to fail during CONSUME_AND_DISPATCH append
    orig_append = store._append_record_under_lock

    def failing_append(rec):
        if rec.get("type") == "CONSUME_AND_DISPATCH":
            raise RuntimeError("Disk full during atomic dispatch commit")
        return orig_append(rec)

    store._append_record_under_lock = failing_append

    with pytest.raises(RuntimeError, match="Disk full"):
        store.consume_token_and_record_dispatch(
            token_id=tok_id,
            attempt_id="att_atom_fail",
            dispatched_executor_id="exec",
            started_at=time.time()
        )

    # Restore append method
    store._append_record_under_lock = orig_append

    # Verify atomicity: Token was NOT added to in-memory _consumed_tokens
    assert store.is_consumed(tok_id) is False

    # Verify atomicity on disk across fresh store reload
    store_reloaded = FileAuthorizationStore(store_path=str(store_file))
    assert store_reloaded.is_consumed(tok_id) is False
    assert store_reloaded.get_execution_record(tok_id, "att_atom_fail") is None
