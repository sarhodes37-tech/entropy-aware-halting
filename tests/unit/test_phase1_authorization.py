"""
Comprehensive Unit Test Suite for Phase 1 Authorization, Capabilities, and Execution Boundary.

Tests all 14 required authorization & execution boundary scenarios:
1. Missing trusted policy plus proposed protected action -> denied; callback count remains 0.
2. Empty or incomplete operation/resource allowlists -> denied for protected actions.
3. Caller-supplied or model-supplied 'trusted_scope' cannot create authority.
4. Fabricated token ID plus 'authorization_granted=True' cannot invoke an executor.
5. Capability forged, altered, expired, revoked, or issued by untrusted authority -> rejected.
6. Action, target, argument digest, task identity, or executor substitution -> rejected.
7. Replay and concurrent attempts cannot execute same one-use grant more than once.
8. Unauthorized action cannot receive grant merely because EntropyGate or other non-auth gate allows.
9. Valid explicitly authorized nested endpoint operations execute successfully.
10. Unauthorized nested endpoints and malformed actions are denied.
11. Failure to record required pre-execution authorization/execution event prevents callback.
12. Failure to record terminal event after callback run does not falsely claim execution never occurred.
13. Generic automated "continue/proceed" replies cannot be converted into explicit authorization.
14. Genuine valid authorization permits exactly bound operation, callback invoked once.
"""

import time
import uuid
import pytest
import threading
from unittest.mock import MagicMock

from epistemicos.core import EpistemicOrchestrator
from epistemicos.gates import PermissionGate, EntropyGate, GateAction
from epistemicos.authorization import (
    AuthorizationAuthority,
    CapabilityRegistry,
    Policy,
    Capability,
    HumanApprovalRecord
)
from epistemicos.provenance import (
    TrustedExecutionBoundary,
    LocalProvenanceStore,
    ExecutionContext,
    ProvenanceEvent,
    ProvenanceEventType,
    ProvenanceSource
)


# =====================================================================
# Scenario 1: Missing trusted policy plus proposed protected action
# =====================================================================
def test_scenario_1_missing_trusted_policy_denied(tmp_path):
    """Scenario 1: Missing trusted policy plus a proposed protected action: denied; callback count remains zero."""
    callback = MagicMock(return_value={"status": "FORBIDDEN"})
    orchestrator = EpistemicOrchestrator(
        audit_log_path=str(tmp_path / "audit.jsonl"),
        authority=AuthorizationAuthority()
    )

    raw_payload = {"policy_id": "POL-S1", "primary_metric": 100.0}
    context = {
        "action_name": "delete_database",
        "target": "prod_db",
        "proposed_actions": [{"op": "delete_database", "endpoint": "prod_db"}],
        "actual_executable": callback
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert callback.call_count == 0


# =====================================================================
# Scenario 2: Empty or incomplete operation/resource allowlists
# =====================================================================
def test_scenario_2_empty_or_incomplete_allowlists_denied(tmp_path):
    """Scenario 2: Empty or incomplete operation/resource allowlists: denied for protected actions."""
    callback = MagicMock()
    empty_policy = Policy(policy_id="empty_policy", allowed_operations=set(), allowed_resources=set())
    authority = AuthorizationAuthority(default_policy=empty_policy)
    orchestrator = EpistemicOrchestrator(
        audit_log_path=str(tmp_path / "audit.jsonl"),
        authority=authority
    )

    raw_payload = {"policy_id": "POL-S2", "primary_metric": 100.0}
    context = {
        "action_name": "update_record",
        "target": "user_table",
        "proposed_actions": [{"op": "update_record", "node": "user_table"}],
        "actual_executable": callback,
        "policy": empty_policy
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert callback.call_count == 0


# =====================================================================
# Scenario 3: Caller-supplied or model-supplied "trusted_scope" cannot create authority
# =====================================================================
def test_scenario_3_caller_supplied_trusted_scope_cannot_create_authority(tmp_path):
    """Scenario 3: Caller-supplied or model-supplied 'trusted_scope' in payload or request dict cannot create authority."""
    callback = MagicMock()
    strict_policy = Policy(policy_id="strict", allowed_operations={"read_only"}, allowed_resources={"public_doc"})
    authority = AuthorizationAuthority(default_policy=strict_policy)
    orchestrator = EpistemicOrchestrator(
        audit_log_path=str(tmp_path / "audit.jsonl"),
        authority=authority
    )

    raw_payload = {
        "policy_id": "POL-S3",
        "primary_metric": 100.0,
        "scope": {"allowed_operations": ["admin_delete"], "allowed_resources": ["prod_db"]}
    }

    context = {
        "proposed_actions": [{"op": "admin_delete", "endpoint": "prod_db"}],
        "actual_executable": callback,
        "trusted_scope": {"allowed_operations": ["admin_delete"], "allowed_resources": ["prod_db"]}
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert callback.call_count == 0


# =====================================================================
# Scenario 4: Fabricated token ID plus "authorization_granted=True" cannot invoke executor
# =====================================================================
def test_scenario_4_fabricated_token_id_rejected(tmp_path):
    """Scenario 4: A fabricated token ID plus 'authorization_granted=True' cannot invoke an executor."""
    callback = MagicMock()
    store = LocalProvenanceStore(log_path=str(tmp_path / "prov.jsonl"))
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"data": "test_s4"}
    digest = boundary.compute_canonical_digest(payload)

    with pytest.raises(PermissionError, match="Execution rejected"):
        boundary.execute_protected_action(
            action_name="TRANSFER",
            target="bank_account",
            request_payload=payload,
            authorization_token_id="FABRICATED-TOKEN-12345",
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=callback
        )

    assert callback.call_count == 0


# =====================================================================
# Scenario 5: Forged, altered, expired, revoked, or untrusted capabilities rejected
# =====================================================================
def test_scenario_5_invalid_capability_states_rejected(tmp_path):
    """Scenario 5: A capability forged, altered, expired, revoked, or issued by untrusted authority is rejected."""
    callback = MagicMock()
    store = LocalProvenanceStore(log_path=str(tmp_path / "prov.jsonl"))
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"action": "do_task"}
    digest = boundary.compute_canonical_digest(payload)
    now = time.time()

    # 1. Expired capability
    expired_cap = Capability(
        token_id="tok-expired",
        principal_id="user1",
        correlation_id="corr1",
        request_id="req1",
        action_name="DO_TASK",
        target="worker",
        canonical_request_digest=digest,
        executor_id="<MagicMock id='1'>",
        policy_version="1.0.0",
        created_at=now - 1000,
        expires_at=now - 100
    )
    boundary.registry.register_capability(expired_cap)

    with pytest.raises(PermissionError, match="EXPIRED_TOKEN"):
        boundary.execute_protected_action(
            action_name="DO_TASK",
            target="worker",
            request_payload=payload,
            authorization_token_id="tok-expired",
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=callback
        )

    # 2. Revoked capability
    policy = Policy(policy_id="p", allowed_operations={"DO_TASK"}, allowed_resources={"worker"})
    valid_cap, _ = boundary.authority.evaluate_and_issue_capability("DO_TASK", "worker", digest, executor_id="<MagicMock id='1'>", policy=policy)
    boundary.registry.revoke_token(valid_cap.token_id)

    with pytest.raises(PermissionError, match="REVOKED_TOKEN"):
        boundary.execute_protected_action(
            action_name="DO_TASK",
            target="worker",
            request_payload=payload,
            authorization_token_id=valid_cap.token_id,
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=callback
        )

    # 3. Forged signature
    forged_cap = Capability(
        token_id="tok-forged-sig",
        principal_id="user1",
        correlation_id="corr1",
        request_id="req1",
        action_name="DO_TASK",
        target="worker",
        canonical_request_digest=digest,
        executor_id="<MagicMock id='1'>",
        policy_version="1.0.0",
        created_at=now,
        expires_at=now + 300,
        signature="INVALID_FORGED_SIGNATURE"
    )
    boundary.registry._capabilities[forged_cap.token_id] = forged_cap

    with pytest.raises(PermissionError, match="INVALID_SIGNATURE"):
        boundary.execute_protected_action(
            action_name="DO_TASK",
            target="worker",
            request_payload=payload,
            authorization_token_id="tok-forged-sig",
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=callback
        )

    assert callback.call_count == 0


# =====================================================================
# Scenario 6: Action, target, argument digest, task identity, or executor substitution rejected
# =====================================================================
def test_scenario_6_parameter_substitutions_rejected(tmp_path):
    """Scenario 6: Action, target, argument digest, task identity, or executor substitution is rejected."""
    callback_original = MagicMock(__name__="callback_original")
    callback_substitute = MagicMock(__name__="callback_substitute")

    store = LocalProvenanceStore(log_path=str(tmp_path / "prov.jsonl"))
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload_orig = {"op": "transfer", "amount": 100}
    digest_orig = boundary.compute_canonical_digest(payload_orig)

    policy = Policy(policy_id="p1", allowed_operations={"TRANSFER"}, allowed_resources={"account_A"})
    cap, _ = boundary.authority.evaluate_and_issue_capability(
        action_name="TRANSFER",
        target="account_A",
        canonical_request_digest=digest_orig,
        correlation_id="corr-task-1",
        request_id="req-1",
        executor_id="callback_original",
        policy=policy
    )

    # 1. Action substitution
    with pytest.raises(PermissionError, match="ACTION_MISMATCH"):
        boundary.execute_protected_action(
            action_name="WITHDRAW",
            target="account_A",
            request_payload=payload_orig,
            authorization_token_id=cap.token_id,
            authorized_digest=digest_orig,
            authorization_granted=True,
            executor_func=callback_original
        )

    # 2. Target substitution
    with pytest.raises(PermissionError, match="TARGET_MISMATCH"):
        boundary.execute_protected_action(
            action_name="TRANSFER",
            target="account_B",
            request_payload=payload_orig,
            authorization_token_id=cap.token_id,
            authorized_digest=digest_orig,
            authorization_granted=True,
            executor_func=callback_original
        )

    # 3. Argument digest substitution
    payload_tampered = {"op": "transfer", "amount": 10000}
    with pytest.raises(ValueError, match="digest changed"):
        boundary.execute_protected_action(
            action_name="TRANSFER",
            target="account_A",
            request_payload=payload_tampered,
            authorization_token_id=cap.token_id,
            authorized_digest=digest_orig,
            authorization_granted=True,
            executor_func=callback_original
        )

    # 4. Executor substitution
    with pytest.raises(PermissionError, match="EXECUTOR_MISMATCH"):
        boundary.execute_protected_action(
            action_name="TRANSFER",
            target="account_A",
            request_payload=payload_orig,
            authorization_token_id=cap.token_id,
            authorized_digest=digest_orig,
            authorization_granted=True,
            executor_func=callback_substitute
        )

    # 5. Correlation ID substitution
    with pytest.raises(PermissionError, match="CORRELATION_ID_MISMATCH"):
        boundary.execute_protected_action(
            action_name="TRANSFER",
            target="account_A",
            request_payload=payload_orig,
            correlation_id="corr-task-TAMPERED",
            request_id="req-1",
            authorization_token_id=cap.token_id,
            authorized_digest=digest_orig,
            authorization_granted=True,
            executor_func=callback_original
        )

    # 6. Request ID substitution
    with pytest.raises(PermissionError, match="REQUEST_ID_MISMATCH"):
        boundary.execute_protected_action(
            action_name="TRANSFER",
            target="account_A",
            request_payload=payload_orig,
            correlation_id="corr-task-1",
            request_id="req-TAMPERED",
            authorization_token_id=cap.token_id,
            authorized_digest=digest_orig,
            authorization_granted=True,
            executor_func=callback_original
        )

    # 7. Policy version substitution
    with pytest.raises(PermissionError, match="POLICY_VERSION_MISMATCH"):
        boundary.execute_protected_action(
            action_name="TRANSFER",
            target="account_A",
            request_payload=payload_orig,
            correlation_id="corr-task-1",
            request_id="req-1",
            authorization_token_id=cap.token_id,
            authorized_digest=digest_orig,
            authorization_granted=True,
            executor_func=callback_original,
            policy_version="9.9.9"
        )

    assert callback_original.call_count == 0
    assert callback_substitute.call_count == 0


# =====================================================================
# Scenario 7: Replay and concurrent attempts cannot execute single-use grant twice
# =====================================================================
def test_scenario_7_replay_and_concurrent_attempts_prevented(tmp_path):
    """Scenario 7: Replay and concurrent attempts cannot execute the same one-use grant more than once."""
    store = LocalProvenanceStore(log_path=str(tmp_path / "prov.jsonl"))
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"tx": "single_use"}
    digest = boundary.compute_canonical_digest(payload)
    policy = Policy(policy_id="p", allowed_operations={"PAY"}, allowed_resources={"gateway"})
    cap, _ = boundary.authority.evaluate_and_issue_capability("PAY", "gateway", digest, executor_id="<lambda>", policy=policy)

    num_threads = 8
    barrier = threading.Barrier(num_threads)
    results = []
    errors = []

    def worker():
        barrier.wait()
        try:
            res = boundary.execute_protected_action(
                action_name="PAY",
                target="gateway",
                request_payload=payload,
                authorization_token_id=cap.token_id,
                authorized_digest=digest,
                authorization_granted=True,
                executor_func=lambda: "PAID"
            )
            results.append(res)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 1
    assert len(errors) == num_threads - 1


# =====================================================================
# Scenario 8: Unauthorized action cannot receive grant merely because EntropyGate allows
# =====================================================================
def test_scenario_8_gate_independence_unauthorized_action_denied(tmp_path):
    """Scenario 8: An unauthorized action cannot receive a grant merely because EntropyGate or another non-authorization gate allows."""
    callback = MagicMock()
    policy = Policy(policy_id="p1", allowed_operations={"read_only"}, allowed_resources={"public_db"})
    authority = AuthorizationAuthority(default_policy=policy)

    orchestrator = EpistemicOrchestrator(
        audit_log_path=str(tmp_path / "audit.jsonl"),
        authority=authority
    )
    orchestrator.gates = [
        EntropyGate(z_threshold=2.85),
        PermissionGate(allowed_actions=["read_only"])
    ]

    clean_logprobs = [-0.01] * 20
    raw_payload = {"policy_id": "POL-S8", "primary_metric": 100.0}
    context = {
        "token_logprobs": clean_logprobs,
        "action_name": "drop_table",
        "target": "public_db",
        "proposed_actions": [{"op": "drop_table", "node": "public_db"}],
        "actual_executable": callback
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert callback.call_count == 0


# =====================================================================
# Scenario 9 & 10: Valid vs Unauthorized nested endpoint operations and malformed actions
# =====================================================================
def test_scenario_9_and_10_nested_endpoints_valid_and_invalid(tmp_path):
    """Scenario 9 & 10: Valid nested endpoints execute; unauthorized nested endpoints and malformed actions are denied."""
    callback_valid = MagicMock(return_value={"status": "NESTED_SUCCESS"})
    callback_invalid = MagicMock()

    policy = Policy(policy_id="nested_pol", allowed_operations={"api_call"}, allowed_resources={"/issue_binder"})
    authority = AuthorizationAuthority(default_policy=policy)

    orchestrator = EpistemicOrchestrator(
        audit_log_path=str(tmp_path / "audit.jsonl"),
        authority=authority
    )
    orchestrator.gates[0] = PermissionGate(
        trusted_scope={
            "allowed_operations": ["api_call"],
            "allowed_resources": ["/issue_binder"]
        }
    )

    # Valid nested endpoint
    valid_payload = {"policy_id": "POL-NESTED-1"}
    valid_context = {
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/issue_binder", "data": "POL-NESTED-1"}}],
        "actual_executable": callback_valid,
        "token_logprobs": [-0.01] * 5
    }
    res_valid = orchestrator.process_submission(valid_payload, valid_context)
    assert res_valid["status"] == "ALLOWED"
    assert callback_valid.call_count == 1

    # Unauthorized nested endpoint
    invalid_context = {
        "proposed_actions": [{"action": {"op": "api_call", "endpoint": "/forbidden_admin"}}],
        "actual_executable": callback_invalid,
        "token_logprobs": [-0.01] * 5
    }
    res_invalid = orchestrator.process_submission(valid_payload, invalid_context)
    assert res_invalid["status"] == "HALTED"
    assert callback_invalid.call_count == 0

    # Malformed action structure (missing op)
    malformed_context = {
        "proposed_actions": [{"action": {"endpoint": "/issue_binder"}}],
        "actual_executable": callback_invalid,
        "token_logprobs": [-0.01] * 5
    }
    res_malformed = orchestrator.process_submission(valid_payload, malformed_context)
    assert res_malformed["status"] == "HALTED"
    assert "Missing or invalid operation" in res_malformed["reason"]


# =====================================================================
# Scenario 11 & 12: Pre and Post execution audit recording failures
# =====================================================================
def test_scenario_11_pre_execution_audit_failure_prevents_callback(tmp_path):
    """Scenario 11: Failure to record the required pre-execution authorization/execution event prevents the callback from running."""
    callback = MagicMock(__name__="mock_executor")
    mock_store = MagicMock()
    mock_store.record_event.side_effect = RuntimeError("Disk I/O error during EXECUTION_STARTED")

    boundary = TrustedExecutionBoundary(provenance_store=mock_store)

    payload = {"data": "s11"}
    digest = boundary.compute_canonical_digest(payload)
    policy = Policy(policy_id="p", allowed_operations={"WRITE"}, allowed_resources={"db"})
    cap, _ = boundary.authority.evaluate_and_issue_capability("WRITE", "db", digest, executor_id="mock_executor", policy=policy)

    with pytest.raises(RuntimeError, match="EXECUTION_STARTED"):
        boundary.execute_protected_action(
            action_name="WRITE",
            target="db",
            request_payload=payload,
            authorization_token_id=cap.token_id,
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=callback
        )

    assert callback.call_count == 0


def test_scenario_12_post_execution_audit_failure_reports_unknown_outcome(tmp_path):
    """Scenario 12: Failure to record terminal event after callback has run does not produce a false claim that execution never occurred."""
    mock_store = MagicMock()
    mock_store.record_event.side_effect = [{"status": "OK"}, RuntimeError("Disk full during EXECUTION_SUCCEEDED")]

    boundary = TrustedExecutionBoundary(provenance_store=mock_store)

    payload = {"data": "s12"}
    digest = boundary.compute_canonical_digest(payload)
    policy = Policy(policy_id="p", allowed_operations={"UPDATE"}, allowed_resources={"table"})
    cap, _ = boundary.authority.evaluate_and_issue_capability("UPDATE", "table", digest, executor_id="<lambda>", policy=policy)

    res = boundary.execute_protected_action(
        action_name="UPDATE",
        target="table",
        request_payload=payload,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        executor_func=lambda: "MUTATED_VALUE"
    )

    assert res["status"] == "EXECUTION_OUTCOME_UNKNOWN"
    assert res["recovery_required"] is True
    assert res["result"] == "MUTATED_VALUE"


# =====================================================================
# Scenario 13: Generic automated "continue/proceed" replies rejected as human approval
# =====================================================================
def test_scenario_13_generic_continuation_text_cannot_issue_authorization(tmp_path):
    """Scenario 13: Generic automated 'continue/proceed' replies cannot be converted into explicit authorization."""
    callback = MagicMock()
    policy = Policy(
        policy_id="human_approval_policy",
        allowed_operations={"nuclear_launch"},
        allowed_resources={"silo_1"},
        required_human_approval_operations={"nuclear_launch"}
    )
    authority = AuthorizationAuthority(default_policy=policy)
    orchestrator = EpistemicOrchestrator(
        audit_log_path=str(tmp_path / "audit.jsonl"),
        authority=authority
    )
    orchestrator.gates[0] = PermissionGate(
        trusted_scope={
            "allowed_operations": ["nuclear_launch"],
            "allowed_resources": ["silo_1"]
        }
    )

    raw_payload = {"policy_id": "POL-HUMAN-1", "action": "nuclear_launch"}
    payload_digest = orchestrator.execution_boundary.compute_canonical_digest(raw_payload)

    generic_text_replies = [
        "Please proceed to the next step using your best judgement",
        "continue",
        "proceed",
        "yes, go ahead",
        "approved"
    ]

    for reply in generic_text_replies:
        context = {
            "action_name": "nuclear_launch",
            "target": "silo_1",
            "proposed_actions": [{"op": "nuclear_launch", "endpoint": "silo_1"}],
            "actual_executable": callback,
            "human_approval": reply,
            "policy": policy
        }

        res = orchestrator.process_submission(raw_payload, context)
        assert res["status"] == "HALTED"
        assert res.get("execution_status") == "DENIED"
        assert "HUMAN_APPROVAL_REQUIRED" in res["reason"]
        assert callback.call_count == 0

    req_id = str(uuid.uuid4())
    typed_record = HumanApprovalRecord(
        approval_id="APP-999",
        approver_id="SEC_OFFICER_BOB",
        action_name="nuclear_launch",
        target="silo_1",
        action_digest=payload_digest,
        request_id=req_id
    )
    typed_record.sign(authority.approval_signing_secret)

    context_genuine = {
        "request_id": req_id,
        "action_name": "nuclear_launch",
        "target": "silo_1",
        "proposed_actions": [{"op": "nuclear_launch", "endpoint": "silo_1"}],
        "actual_executable": callback,
        "human_approval": typed_record,
        "policy": policy
    }

    res_genuine = orchestrator.process_submission(raw_payload, context_genuine)
    assert res_genuine["status"] == "ALLOWED"
    assert callback.call_count == 1


# =====================================================================
# Additional Human Approval Signature & Binding Unit Tests
# =====================================================================
def test_human_approval_signature_and_binding_validations():
    policy = Policy(
        policy_id="human_approval_policy",
        allowed_operations={"critical_action"},
        allowed_resources={"resource_1"},
        required_human_approval_operations={"critical_action"}
    )
    authority = AuthorizationAuthority(default_policy=policy)
    digest = "d" * 64
    req_id = "req-123"

    # 1. Complete but unsigned approval record
    unsigned_record = HumanApprovalRecord(
        approval_id="app-1",
        approver_id="approver_alice",
        action_name="critical_action",
        target="resource_1",
        action_digest=digest,
        request_id=req_id
    )
    cap, reason = authority.evaluate_and_issue_capability(
        action_name="critical_action",
        target="resource_1",
        canonical_request_digest=digest,
        request_id=req_id,
        human_approval_input=unsigned_record
    )
    assert cap is None
    assert reason == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_MISSING_SIGNATURE"

    # 2. Forged / invalid signature
    forged_record = HumanApprovalRecord(
        approval_id="app-2",
        approver_id="approver_alice",
        action_name="critical_action",
        target="resource_1",
        action_digest=digest,
        request_id=req_id,
        signature="invalid_signature_hex"
    )
    cap_forged, reason_forged = authority.evaluate_and_issue_capability(
        action_name="critical_action",
        target="resource_1",
        canonical_request_digest=digest,
        request_id=req_id,
        human_approval_input=forged_record
    )
    assert cap_forged is None
    assert reason_forged == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_AUTHENTICATION_FAILED"

    # 3. Expired approval record
    expired_record = HumanApprovalRecord(
        approval_id="app-3",
        approver_id="approver_alice",
        action_name="critical_action",
        target="resource_1",
        action_digest=digest,
        request_id=req_id,
        expires_at=time.time() - 100.0
    )
    expired_record.sign(authority.approval_signing_secret)
    cap_expired, reason_expired = authority.evaluate_and_issue_capability(
        action_name="critical_action",
        target="resource_1",
        canonical_request_digest=digest,
        request_id=req_id,
        human_approval_input=expired_record
    )
    assert cap_expired is None
    assert reason_expired == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_AUTHENTICATION_FAILED"

    # 4. Mismatched field (different target)
    mismatched_record = HumanApprovalRecord(
        approval_id="app-4",
        approver_id="approver_alice",
        action_name="critical_action",
        target="different_resource",
        action_digest=digest,
        request_id=req_id
    )
    mismatched_record.sign(authority.approval_signing_secret)
    cap_mismatched, reason_mismatched = authority.evaluate_and_issue_capability(
        action_name="critical_action",
        target="resource_1",
        canonical_request_digest=digest,
        request_id=req_id,
        human_approval_input=mismatched_record
    )
    assert cap_mismatched is None
    assert reason_mismatched == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_BINDING_MISMATCH"

    # 5. Valid, correctly signed approval
    valid_record = HumanApprovalRecord(
        approval_id="app-5",
        approver_id="approver_alice",
        action_name="critical_action",
        target="resource_1",
        action_digest=digest,
        request_id=req_id
    )
    valid_record.sign(authority.approval_signing_secret)
    cap_valid, reason_valid = authority.evaluate_and_issue_capability(
        action_name="critical_action",
        target="resource_1",
        canonical_request_digest=digest,
        request_id=req_id,
        human_approval_input=valid_record
    )
    assert cap_valid is not None
    assert reason_valid == "AUTHORIZATION_GRANTED"


# =====================================================================
# Resource Policy Regression Tests
# =====================================================================
def test_resource_policy_omitted_empty_restricted_wildcard(tmp_path):
    # 1. Omitted allowed_resources (set()) -> fails closed
    p_omitted = Policy(policy_id="omitted", allowed_operations={"op1"})
    assert p_omitted.is_target_allowed("res1") is False

    # 2. Empty allowed_resources -> fails closed
    p_empty = Policy(policy_id="empty", allowed_operations={"op1"}, allowed_resources=set())
    assert p_empty.is_target_allowed("res1") is False

    # 3. Restricted allowed_resources -> permits exact resource, rejects others
    p_restricted = Policy(policy_id="restricted", allowed_operations={"op1"}, allowed_resources={"/specific_resource"})
    assert p_restricted.is_target_allowed("/specific_resource") is True
    assert p_restricted.is_target_allowed("/other_resource") is False

    # 4. Negative Orchestrator Test: Permitted operation against unauthorized target is denied
    auth_restricted = AuthorizationAuthority(default_policy=p_restricted)
    orch_restricted = EpistemicOrchestrator(
        audit_log_path=str(tmp_path / "audit.jsonl"),
        authority=auth_restricted
    )
    orch_restricted.gates[0] = PermissionGate(
        trusted_scope={
            "allowed_operations": ["op1"],
            "allowed_resources": ["/specific_resource"]
        }
    )
    raw_payload = {"policy_id": "POL-RESTRICTED", "primary_metric": 100.0}
    context_unauthorized_target = {
        "action_name": "op1",
        "target": "/other_resource",
        "proposed_actions": [{"op": "op1", "endpoint": "/other_resource"}],
        "actual_executable": lambda: {"status": "SUCCESS"}
    }
    res_unauth = orch_restricted.process_submission(raw_payload, context_unauthorized_target)
    assert res_unauth["status"] == "HALTED"
    assert res_unauth["gate"] == "PermissionGate"
    assert "outside allowed scope resources" in res_unauth["reason"]

    # 5. Explicitly wildcarded allowed_resources -> permits any resource
    p_wildcard = Policy(policy_id="wildcard", allowed_operations={"op1"}, allowed_resources={"*"})
    assert p_wildcard.is_target_allowed("res1") is True
    assert p_wildcard.is_target_allowed("res2") is True


# =====================================================================
# Trusted Policy Provenance Test
# =====================================================================
def test_caller_supplied_permissive_policy_ignored(tmp_path):
    """Proves that a caller supplying a permissive Policy in context cannot override server policy."""
    callback = MagicMock()
    server_policy = Policy(policy_id="server", allowed_operations={"read_only"}, allowed_resources={"public_doc"})
    authority = AuthorizationAuthority(default_policy=server_policy)
    orchestrator = EpistemicOrchestrator(
        audit_log_path=str(tmp_path / "audit.jsonl"),
        authority=authority
    )

    caller_permissive_policy = Policy(policy_id="permissive", allowed_operations={"delete_all"}, allowed_resources={"*"})

    raw_payload = {"policy_id": "POL-OVERRIDE", "primary_metric": 100.0}
    context = {
        "action_name": "delete_all",
        "target": "database",
        "proposed_actions": [{"op": "delete_all", "endpoint": "database"}],
        "actual_executable": callback,
        "policy": caller_permissive_policy  # Caller attempting to inject permissive policy
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert res["gate"] == "PermissionGate"
    assert callback.call_count == 0


# =====================================================================
# Scenario 14: Genuine valid authorization permits exactly bound operation, callback invoked once
# =====================================================================
def test_scenario_14_genuine_valid_authorization_permits_exact_operation_once(tmp_path):
    """Scenario 14: A genuine valid authorization from configured authority permits exactly the bound operation, callback invoked once."""
    callback = MagicMock(return_value={"status": "BOUND_EXECUTION_SUCCESS"})
    policy = Policy(policy_id="valid_p1", allowed_operations={"issue_binder"}, allowed_resources={"/bind_policy"})
    authority = AuthorizationAuthority(default_policy=policy)

    orchestrator = EpistemicOrchestrator(
        audit_log_path=str(tmp_path / "audit.jsonl"),
        authority=authority
    )
    orchestrator.gates[0] = PermissionGate(
        trusted_scope={
            "allowed_operations": ["issue_binder"],
            "allowed_resources": ["/bind_policy"]
        }
    )

    raw_payload = {"policy_id": "POL-2026-BOUND", "primary_metric": 500.0}
    context = {
        "proposed_actions": [{"action": {"op": "issue_binder", "endpoint": "/bind_policy"}}],
        "actual_executable": callback,
        "token_logprobs": [-0.01] * 10
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "ALLOWED"
    assert res["execution_status"] == "EXECUTED"
    assert res["execution_outcome"]["status"] == "SUCCESS"
    assert callback.call_count == 1
