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
    HumanApprovalRecord,
    get_callable_identity
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
        executor_id=callback_original,
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
    with pytest.raises(PermissionError, match=r"(EXECUTOR_MISMATCH|identity mismatch)"):
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
    exec_func = lambda: "PAID"
    policy = Policy(policy_id="p", allowed_operations={"PAY"}, allowed_resources={"gateway"})
    cap, _ = boundary.authority.evaluate_and_issue_capability("PAY", "gateway", digest, executor_id=exec_func, policy=policy)

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
                executor_func=exec_func
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
    cap, _ = boundary.authority.evaluate_and_issue_capability("WRITE", "db", digest, executor_id=callback, policy=policy)

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
    exec_func = lambda: "MUTATED_VALUE"
    policy = Policy(policy_id="p", allowed_operations={"UPDATE"}, allowed_resources={"table"})
    cap, _ = boundary.authority.evaluate_and_issue_capability("UPDATE", "table", digest, executor_id=exec_func, policy=policy)

    res = boundary.execute_protected_action(
        action_name="UPDATE",
        target="table",
        request_payload=payload,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        executor_func=exec_func
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
# Audit Remediation Regression Tests (F6, F7)
# =====================================================================

def test_f6_executor_spoofing_prevented_with_registered_executor(tmp_path):
    """F6 Regression: Verifies that spoofing __name__ on a different callable is rejected when executor object identity is registered."""
    def authorized_exec():
        return "authorized"

    def spoofed_exec():
        return "spoofed"

    spoofed_exec.__name__ = "authorized_exec"

    policy = Policy(policy_id="p1", allowed_operations={"op1"}, allowed_resources={"res1"})
    authority = AuthorizationAuthority(default_policy=policy)
    authority.register_executor("authorized_exec", authorized_exec)

    store = LocalProvenanceStore(log_path=str(tmp_path / "prov.jsonl"))
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=authority)

    payload = {"data": "test"}
    digest = boundary.compute_canonical_digest(payload)

    cap, reason = authority.evaluate_and_issue_capability("op1", "res1", digest, executor_id="authorized_exec")
    assert cap is not None

    with pytest.raises(PermissionError, match=r"(Executable object identity mismatch|EXECUTOR_MISMATCH)"):
        boundary.execute_protected_action(
            action_name="op1",
            target="res1",
            request_payload=payload,
            authorization_token_id=cap.token_id,
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=spoofed_exec
        )


def test_f7_human_approval_self_approval_rejected():
    """F7 Regression: Verifies that self-approval (approver_id == principal_id) is strictly rejected."""
    policy = Policy(
        policy_id="p1",
        allowed_operations={"critical_op"},
        allowed_resources={"res1"},
        required_human_approval_operations={"critical_op"}
    )
    authority = AuthorizationAuthority(default_policy=policy)
    digest = "a" * 64
    req_id = "req-self-1"

    self_approval_record = HumanApprovalRecord(
        approval_id="app-self",
        approver_id="user_principal_1",
        action_name="critical_op",
        target="res1",
        action_digest=digest,
        request_id=req_id
    )
    self_approval_record.sign(authority.approval_signing_secret)

    cap, reason = authority.evaluate_and_issue_capability(
        action_name="critical_op",
        target="res1",
        canonical_request_digest=digest,
        principal_id="user_principal_1",
        request_id=req_id,
        human_approval_input=self_approval_record
    )

    assert cap is None
    assert reason == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_SELF_APPROVAL_REJECTED"


def test_f7_human_approval_untrusted_approver_rejected():
    """F7 Regression: Verifies that a signed approval from an untrusted approver_id is rejected when allowed_approvers is configured."""
    policy = Policy(
        policy_id="p1",
        allowed_operations={"critical_op"},
        allowed_resources={"res1"},
        required_human_approval_operations={"critical_op"},
        allowed_approvers={"security_lead_alice"}  # Only Alice is authorized
    )
    authority = AuthorizationAuthority(default_policy=policy)
    digest = "c" * 64
    req_id = "req-untrusted-1"

    untrusted_approval_record = HumanApprovalRecord(
        approval_id="app-untrusted",
        approver_id="untrusted_user_bob",
        action_name="critical_op",
        target="res1",
        action_digest=digest,
        request_id=req_id
    )
    untrusted_approval_record.sign(authority.approval_signing_secret)

    cap, reason = authority.evaluate_and_issue_capability(
        action_name="critical_op",
        target="res1",
        canonical_request_digest=digest,
        principal_id="principal_user_1",
        request_id=req_id,
        human_approval_input=untrusted_approval_record
    )

    assert cap is None
    assert "UNTRUSTED_APPROVER" in reason


def test_f7_human_approval_string_expires_at_handled_safely():
    """F7 Regression: Verifies that string expires_at input is parsed or rejected safely without raising uncaught TypeError."""
    digest = "b" * 64
    req_id = "req-str-exp"

    record = HumanApprovalRecord.from_input({
        "approval_id": "app-str",
        "approver_id": "approver_bob",
        "action_name": "critical_op",
        "target": "res1",
        "action_digest": digest,
        "request_id": req_id,
        "expires_at": "2030-01-01"  # Invalid non-numeric timestamp string
    })

    # Non-numeric timestamp string is rejected during parsing
    assert record is None


def test_f7_empty_principals_and_executors_fail_closed():
    """F7 Regression: Verifies that explicitly passing empty set for allowed_principals or allowed_executors fails closed."""
    p_empty_principals = Policy(policy_id="p1", allowed_operations={"op1"}, allowed_resources={"res1"}, allowed_principals=set())
    assert p_empty_principals.is_principal_allowed("user1") is False

    p_empty_executors = Policy(policy_id="p1", allowed_operations={"op1"}, allowed_resources={"res1"}, allowed_executors=set())
    assert p_empty_executors.is_executor_allowed("exec1") is False


def test_unambiguous_executor_identity_and_short_name_rejection(tmp_path):
    """PR #257 Follow-up: Verifies strict canonical executor identity matching without short-name confusion."""
    # 1. Capability issued for package_a.tools.execute cannot authorize package_b.tools.execute
    store = LocalProvenanceStore(log_path=str(tmp_path / "prov_exec_id.jsonl"))
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"data": "test_exec"}
    digest = boundary.compute_canonical_digest(payload)

    policy = Policy(policy_id="p1", allowed_operations={"op_exec"}, allowed_resources={"res_exec"})

    class PackageAExecutor:
        def __call__(self):
            return "package_a_ran"

    exec_a = PackageAExecutor()
    exec_a.__module__ = "package_a.tools"
    exec_a.__name__ = "execute"
    exec_a.__qualname__ = "execute"

    boundary.authority.register_executor("package_a.tools.execute", exec_a)

    cap_a, _ = boundary.authority.evaluate_and_issue_capability(
        action_name="op_exec",
        target="res_exec",
        canonical_request_digest=digest,
        executor_id=exec_a,
        policy=policy
    )

    # Calling with package_b.tools.execute must be rejected even though short name 'execute' matches
    class PackageBExecutor:
        def __call__(self):
            return "package_b_ran"

    exec_b = PackageBExecutor()
    exec_b.__module__ = "package_b.tools"
    exec_b.__name__ = "execute"
    exec_b.__qualname__ = "execute"

    with pytest.raises(PermissionError, match=r"(Executable object identity mismatch|Unregistered callable object|EXECUTOR_MISMATCH)"):
        boundary.execute_protected_action(
            action_name="op_exec",
            target="res_exec",
            request_payload=payload,
            authorization_token_id=cap_a.token_id,
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=exec_b
        )

    # 2. Legitimate execution by correctly registered callable continues to work
    res_a = boundary.execute_protected_action(
        action_name="op_exec",
        target="res_exec",
        request_payload=payload,
        authorization_token_id=cap_a.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        executor_func=exec_a
    )
    assert res_a["status"] == "SUCCESS"
    assert res_a["result"] == "package_a_ran"

    # 3. Spoofed __name__ mutation on registered executor fails object identity check
    def registered_target_exec():
        return "registered"

    def spoofed_attacker_exec():
        return "spoofed"

    spoofed_attacker_exec.__name__ = getattr(registered_target_exec, "__name__")

    boundary.authority.register_executor("target_op", registered_target_exec)

    cap_reg, _ = boundary.authority.evaluate_and_issue_capability(
        action_name="op_exec",
        target="res_exec",
        canonical_request_digest=digest,
        executor_id=registered_target_exec,
        policy=policy
    )

    with pytest.raises(PermissionError, match=r"(object identity mismatch|EXECUTOR_MISMATCH)"):
        boundary.execute_protected_action(
            action_name="op_exec",
            target="res_exec",
            request_payload=payload,
            authorization_token_id=cap_reg.token_id,
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=spoofed_attacker_exec
        )

    # 4. Non-callable or missing executor fails closed
    with pytest.raises(ValueError, match="must be a callable object"):
        boundary.execute_protected_action(
            action_name="op_exec",
            target="res_exec",
            request_payload=payload,
            authorization_token_id=cap_reg.token_id,
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=None
        )


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


# =====================================================================
# Unit Tests for Token Validation and Invalid Input Handling in verify_capability
# =====================================================================
def test_verify_capability_invalid_token_inputs():
    """Verifies that invalid token_id inputs (None, empty string, non-string, unknown, short/corrupted) are securely rejected."""
    policy = Policy(policy_id="test_p", allowed_operations={"op_test"}, allowed_resources={"res_test"})
    authority = AuthorizationAuthority(default_policy=policy)
    digest = "a" * 64

    # 1. None token_id
    valid, reason, cap = authority.verify_capability(
        token_id=None,
        action_name="op_test",
        target="res_test",
        canonical_request_digest=digest,
        executor_id="exec_test"
    )
    assert valid is False
    assert reason == "CAPABILITY_VERIFICATION_FAILED_INVALID_TOKEN_ID"
    assert cap is None

    # 2. Empty string token_id
    valid, reason, cap = authority.verify_capability(
        token_id="",
        action_name="op_test",
        target="res_test",
        canonical_request_digest=digest,
        executor_id="exec_test"
    )
    assert valid is False
    assert reason == "CAPABILITY_VERIFICATION_FAILED_INVALID_TOKEN_ID"
    assert cap is None

    # 3. Non-string token_id types (int, dict, list, bool)
    for invalid_token in [12345, {"token": "abc"}, ["token"], True]:
        valid, reason, cap = authority.verify_capability(
            token_id=invalid_token,
            action_name="op_test",
            target="res_test",
            canonical_request_digest=digest,
            executor_id="exec_test"
        )
        assert valid is False
        assert reason == "CAPABILITY_VERIFICATION_FAILED_INVALID_TOKEN_ID"
        assert cap is None

    # 4. Unknown or corrupted string tokens
    for corrupted_token in ["short", "corrupted_token_string_12345", "AUTH-CAP-NONEXISTENT"]:
        valid, reason, cap = authority.verify_capability(
            token_id=corrupted_token,
            action_name="op_test",
            target="res_test",
            canonical_request_digest=digest,
            executor_id="exec_test"
        )
        assert valid is False
        assert reason == "CAPABILITY_VERIFICATION_FAILED_UNKNOWN_TOKEN"
        assert cap is None


def test_verify_capability_token_lifecycle_and_field_mismatches():
    """Verifies revoked, consumed, expired, forged signature, and field mismatch token rejections in verify_capability."""
    policy = Policy(policy_id="test_p2", allowed_operations={"op1"}, allowed_resources={"res1"})
    authority = AuthorizationAuthority(default_policy=policy)
    digest = "b" * 64

    # Issue a valid capability
    valid_cap, reason_grant = authority.evaluate_and_issue_capability(
        action_name="op1",
        target="res1",
        canonical_request_digest=digest,
        principal_id="principal_1",
        correlation_id="corr_1",
        request_id="req_1",
        executor_id="exec_1",
        task_id="task_1"
    )
    assert valid_cap is not None
    assert reason_grant == "AUTHORIZATION_GRANTED"

    # 1. Valid token verification passes
    valid, reason, cap = authority.verify_capability(
        token_id=valid_cap.token_id,
        action_name="op1",
        target="res1",
        canonical_request_digest=digest,
        executor_id="exec_1",
        principal_id="principal_1",
        correlation_id="corr_1",
        request_id="req_1",
        task_id="task_1"
    )
    assert valid is True
    assert reason == "CAPABILITY_VERIFIED"
    assert cap == valid_cap

    # 2. Revoked token
    authority.registry.revoke_token(valid_cap.token_id)
    valid, reason, cap = authority.verify_capability(
        token_id=valid_cap.token_id,
        action_name="op1",
        target="res1",
        canonical_request_digest=digest,
        executor_id="exec_1"
    )
    assert valid is False
    assert reason == "CAPABILITY_VERIFICATION_FAILED_REVOKED_TOKEN"

    # 3. Consumed token
    consumed_cap, _ = authority.evaluate_and_issue_capability(
        action_name="op1",
        target="res1",
        canonical_request_digest=digest,
        executor_id="exec_1"
    )
    authority.registry.consume_token(consumed_cap.token_id)
    valid, reason, cap = authority.verify_capability(
        token_id=consumed_cap.token_id,
        action_name="op1",
        target="res1",
        canonical_request_digest=digest,
        executor_id="exec_1"
    )
    assert valid is False
    assert "CAPABILITY_VERIFICATION_FAILED_REPLAY_TOKEN_ALREADY_CONSUMED" in reason

    # 4. Expired token
    expired_cap, _ = authority.evaluate_and_issue_capability(
        action_name="op1",
        target="res1",
        canonical_request_digest=digest,
        executor_id="exec_1",
        current_time=1000.0
    )
    valid, reason, cap = authority.verify_capability(
        token_id=expired_cap.token_id,
        action_name="op1",
        target="res1",
        canonical_request_digest=digest,
        executor_id="exec_1",
        current_time=2000.0  # Exceeds expires_at
    )
    assert valid is False
    assert reason == "CAPABILITY_VERIFICATION_FAILED_EXPIRED_TOKEN"

    # 5. Tampered/forged signature
    forged_cap, _ = authority.evaluate_and_issue_capability(
        action_name="op1",
        target="res1",
        canonical_request_digest=digest,
        executor_id="exec_1"
    )
    forged_cap.signature = "bad_signature_hash"
    valid, reason, cap = authority.verify_capability(
        token_id=forged_cap.token_id,
        action_name="op1",
        target="res1",
        canonical_request_digest=digest,
        executor_id="exec_1"
    )
    assert valid is False
    assert reason == "CAPABILITY_VERIFICATION_FAILED_INVALID_SIGNATURE"

    # 6. Mismatched fields
    fresh_cap, _ = authority.evaluate_and_issue_capability(
        action_name="op1",
        target="res1",
        canonical_request_digest=digest,
        principal_id="p1",
        correlation_id="c1",
        request_id="r1",
        executor_id="exec_1",
        task_id="t1"
    )

    # Action mismatch
    valid, reason, _ = authority.verify_capability(
        token_id=fresh_cap.token_id,
        action_name="op_mismatch",
        target="res1",
        canonical_request_digest=digest,
        executor_id="exec_1"
    )
    assert valid is False
    assert "ACTION_MISMATCH" in reason

    # Target mismatch
    valid, reason, _ = authority.verify_capability(
        token_id=fresh_cap.token_id,
        action_name="op1",
        target="res_mismatch",
        canonical_request_digest=digest,
        executor_id="exec_1"
    )
    assert valid is False
    assert "TARGET_MISMATCH" in reason

    # Digest mismatch
    valid, reason, _ = authority.verify_capability(
        token_id=fresh_cap.token_id,
        action_name="op1",
        target="res1",
        canonical_request_digest="c" * 64,
        executor_id="exec_1"
    )
    assert valid is False
    assert "DIGEST_MISMATCH" in reason

    # Executor mismatch
    valid, reason, _ = authority.verify_capability(
        token_id=fresh_cap.token_id,
        action_name="op1",
        target="res1",
        canonical_request_digest=digest,
        executor_id="exec_mismatch"
    )
    assert valid is False
    assert "EXECUTOR_MISMATCH" in reason

    # Principal mismatch
    valid, reason, _ = authority.verify_capability(
        token_id=fresh_cap.token_id,
        action_name="op1",
        target="res1",
        canonical_request_digest=digest,
        executor_id="exec_1",
        principal_id="p_mismatch"
    )
    assert valid is False
    assert "PRINCIPAL_MISMATCH" in reason

    # Correlation ID mismatch
    valid, reason, _ = authority.verify_capability(
        token_id=fresh_cap.token_id,
        action_name="op1",
        target="res1",
        canonical_request_digest=digest,
        executor_id="exec_1",
        correlation_id="c_mismatch"
    )
    assert valid is False
    assert "CORRELATION_ID_MISMATCH" in reason

    # Request ID mismatch
    valid, reason, _ = authority.verify_capability(
        token_id=fresh_cap.token_id,
        action_name="op1",
        target="res1",
        canonical_request_digest=digest,
        executor_id="exec_1",
        request_id="r_mismatch"
    )
    assert valid is False
    assert "REQUEST_ID_MISMATCH" in reason

    # Policy version mismatch
    valid, reason, _ = authority.verify_capability(
        token_id=fresh_cap.token_id,
        action_name="op1",
        target="res1",
        canonical_request_digest=digest,
        executor_id="exec_1",
        policy_version="2.0.0"
    )
    assert valid is False
    assert "POLICY_VERSION_MISMATCH" in reason

    # Task ID mismatch
    valid, reason, _ = authority.verify_capability(
        token_id=fresh_cap.token_id,
        action_name="op1",
        target="res1",
        canonical_request_digest=digest,
        executor_id="exec_1",
        task_id="t_mismatch"
    )
    assert valid is False
    assert "TASK_ID_MISMATCH" in reason


# =====================================================================
# Phase 1: Human-Approval Replay Protection Regression Tests
# =====================================================================

def test_phase1_sequential_consumption_two_capabilities_sharing_approval(tmp_path):
    """
    Approval Replay Scenario 1:
    Sequential consumption of two capabilities sharing one human approval ID.
    First consumption succeeds; second consumption fails due to approval replay.
    """
    store = LocalProvenanceStore(log_path=str(tmp_path / "prov_seq.jsonl"))
    boundary = TrustedExecutionBoundary(provenance_store=store)
    authority = boundary.authority

    policy = Policy(
        policy_id="pol-seq",
        allowed_operations={"CRITICAL_ACTION"},
        allowed_resources={"server_1"},
        required_human_approval_operations={"CRITICAL_ACTION"}
    )
    authority.default_policy = policy

    payload = {"data": "seq_payload"}
    digest = boundary.compute_canonical_digest(payload)
    exec_func = lambda: "SUCCESS"
    authority.register_executor("exec_seq", exec_func)

    approval = HumanApprovalRecord(
        approval_id="APP-SEQ-001",
        approver_id="approver_alice",
        action_name="CRITICAL_ACTION",
        target="server_1",
        action_digest=digest,
        request_id="req-seq"
    )
    approval.sign(authority.approval_signing_secret)

    # Issue first capability with approval
    cap1, reason1 = authority.evaluate_and_issue_capability(
        action_name="CRITICAL_ACTION",
        target="server_1",
        canonical_request_digest=digest,
        executor_id="exec_seq",
        request_id="req-seq",
        human_approval_input=approval,
        policy=policy
    )
    assert cap1 is not None
    assert reason1 == "AUTHORIZATION_GRANTED"

    # Pre-issuance or separate issuance with same approval
    # Create cap2 with same approval record directly registered
    cap2 = Capability(
        token_id=f"AUTH-CAP-{uuid.uuid4()}",
        principal_id="agent_default",
        correlation_id=str(uuid.uuid4()),
        request_id="req-seq",
        action_name="CRITICAL_ACTION",
        target="server_1",
        canonical_request_digest=digest,
        executor_id=get_callable_identity(exec_func),
        policy_version=policy.version,
        created_at=time.time(),
        expires_at=time.time() + 300,
        human_approval=approval
    )
    authority.registry.register_capability(cap2)
    authority.executor_registry._register_internal(cap2.token_id, exec_func)

    # First capability consumption succeeds
    ok1 = authority.registry.consume_token(cap1.token_id)
    assert ok1 is True
    assert authority.registry.is_consumed(cap1.token_id) is True
    assert authority.registry.is_approval_consumed(approval.approval_id) is True

    # Second capability consumption sharing the same approval ID fails
    ok2 = authority.registry.consume_token(cap2.token_id)
    assert ok2 is False
    assert authority.registry.is_consumed(cap2.token_id) is False


def test_phase1_verification_rejection_after_approval_consumed(tmp_path):
    """
    Approval Replay Scenario 2:
    Verification rejection of the second capability after the first is consumed.
    Verify that verify_capability() returns False with stable reason code
    CAPABILITY_VERIFICATION_FAILED_REPLAY_HUMAN_APPROVAL_ALREADY_CONSUMED,
    while remaining strictly read-only.
    """
    policy = Policy(
        policy_id="pol-verify",
        allowed_operations={"TRANSFER"},
        allowed_resources={"account_vault"},
        required_human_approval_operations={"TRANSFER"}
    )
    authority = AuthorizationAuthority(default_policy=policy)
    digest = "e" * 64
    exec_func = lambda: "TRANSFERRED"
    authority.register_executor("exec_verify", exec_func)

    approval = HumanApprovalRecord(
        approval_id="APP-VERIFY-001",
        approver_id="approver_bob",
        action_name="TRANSFER",
        target="account_vault",
        action_digest=digest,
        request_id="req-verify"
    )
    approval.sign(authority.approval_signing_secret)

    cap1, _ = authority.evaluate_and_issue_capability(
        action_name="TRANSFER",
        target="account_vault",
        canonical_request_digest=digest,
        executor_id="exec_verify",
        request_id="req-verify",
        human_approval_input=approval,
        policy=policy
    )
    assert cap1 is not None

    cap2 = Capability(
        token_id=f"AUTH-CAP-{uuid.uuid4()}",
        principal_id="agent_default",
        correlation_id=str(uuid.uuid4()),
        request_id="req-verify",
        action_name="TRANSFER",
        target="account_vault",
        canonical_request_digest=digest,
        executor_id=get_callable_identity(exec_func),
        policy_version=policy.version,
        created_at=time.time(),
        expires_at=time.time() + 300,
        human_approval=approval
    )
    authority.registry.register_capability(cap2)

    # Before cap1 is consumed, cap2 verifies successfully (read-only verification)
    valid_before, reason_before, verified_cap = authority.verify_capability(
        token_id=cap2.token_id,
        action_name="TRANSFER",
        target="account_vault",
        canonical_request_digest=digest,
        executor_id=get_callable_identity(exec_func),
        request_id="req-verify"
    )
    assert valid_before is True
    assert reason_before == "CAPABILITY_VERIFIED"
    assert authority.registry.is_consumed(cap2.token_id) is False
    assert authority.registry.is_approval_consumed(approval.approval_id) is False

    # Consume cap1
    assert authority.registry.consume_token(cap1.token_id) is True
    assert authority.registry.is_approval_consumed(approval.approval_id) is True

    # Now verify cap2: must be rejected due to consumed approval
    valid_after, reason_after, cap_after = authority.verify_capability(
        token_id=cap2.token_id,
        action_name="TRANSFER",
        target="account_vault",
        canonical_request_digest=digest,
        executor_id=get_callable_identity(exec_func),
        request_id="req-verify"
    )
    assert valid_after is False
    assert reason_after == "CAPABILITY_VERIFICATION_FAILED_REPLAY_HUMAN_APPROVAL_ALREADY_CONSUMED"
    assert cap_after is None
    # Verify that verification remained read-only (cap2 itself is not marked consumed)
    assert authority.registry.is_consumed(cap2.token_id) is False


def test_phase1_concurrent_consumption_distinct_capabilities_sharing_approval():
    """
    Approval Replay Scenario 3:
    Concurrent consumption of distinct capabilities sharing one approval ID.
    Exact thread safety test across 10 threads: exactly 1 succeeds, 9 fail.
    """
    authority = AuthorizationAuthority()
    digest = "f" * 64
    approval = HumanApprovalRecord(
        approval_id="APP-CONC-001",
        approver_id="approver_carol",
        action_name="MUTATE",
        target="cluster_1",
        action_digest=digest,
        request_id="req-conc"
    )
    approval.sign(authority.approval_signing_secret)

    num_threads = 10
    caps = []
    for i in range(num_threads):
        cap = Capability(
            token_id=f"AUTH-CAP-CONC-{i}-{uuid.uuid4()}",
            principal_id="agent_default",
            correlation_id=str(uuid.uuid4()),
            request_id="req-conc",
            action_name="MUTATE",
            target="cluster_1",
            canonical_request_digest=digest,
            executor_id="exec_mutate",
            policy_version="1.0.0",
            created_at=time.time(),
            expires_at=time.time() + 300,
            human_approval=approval
        )
        authority.registry.register_capability(cap)
        caps.append(cap)

    barrier = threading.Barrier(num_threads)
    successes = []
    failures = []

    def worker(cap_item):
        barrier.wait()
        ok = authority.registry.consume_token(cap_item.token_id)
        if ok:
            successes.append(cap_item.token_id)
        else:
            failures.append(cap_item.token_id)

    threads = [threading.Thread(target=worker, args=(c,)) for c in caps]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(successes) == 1
    assert len(failures) == num_threads - 1
    assert authority.registry.is_approval_consumed(approval.approval_id) is True


def test_phase1_independent_approval_ids_independently_consumable():
    """
    Approval Replay Scenario 4:
    Independent approval IDs remain independently consumable.
    """
    authority = AuthorizationAuthority()
    digest = "a" * 64

    app1 = HumanApprovalRecord(
        approval_id="APP-INDEP-1",
        approver_id="approver_1",
        action_name="OP1",
        target="target1",
        action_digest=digest,
        request_id="req-1"
    )
    app1.sign(authority.approval_signing_secret)

    app2 = HumanApprovalRecord(
        approval_id="APP-INDEP-2",
        approver_id="approver_2",
        action_name="OP2",
        target="target2",
        action_digest=digest,
        request_id="req-2"
    )
    app2.sign(authority.approval_signing_secret)

    cap1 = Capability(
        token_id="AUTH-CAP-IND-1",
        principal_id="agent_default",
        correlation_id="corr-1",
        request_id="req-1",
        action_name="OP1",
        target="target1",
        canonical_request_digest=digest,
        executor_id="exec_1",
        policy_version="1.0.0",
        created_at=time.time(),
        expires_at=time.time() + 300,
        human_approval=app1
    )
    cap2 = Capability(
        token_id="AUTH-CAP-IND-2",
        principal_id="agent_default",
        correlation_id="corr-2",
        request_id="req-2",
        action_name="OP2",
        target="target2",
        canonical_request_digest=digest,
        executor_id="exec_2",
        policy_version="1.0.0",
        created_at=time.time(),
        expires_at=time.time() + 300,
        human_approval=app2
    )

    authority.registry.register_capability(cap1)
    authority.registry.register_capability(cap2)

    assert authority.registry.consume_token(cap1.token_id) is True
    assert authority.registry.is_approval_consumed(app1.approval_id) is True
    assert authority.registry.is_approval_consumed(app2.approval_id) is False

    # Second capability with independent approval ID consumes successfully
    assert authority.registry.consume_token(cap2.token_id) is True
    assert authority.registry.is_approval_consumed(app2.approval_id) is True


def test_phase1_capabilities_without_human_approval_retain_behavior():
    """
    Approval Replay Scenario 5:
    Capabilities without human approval retain their existing behavior.
    """
    authority = AuthorizationAuthority()
    digest = "b" * 64

    cap_no_app = Capability(
        token_id="AUTH-CAP-NO-APP",
        principal_id="agent_default",
        correlation_id="corr-no",
        request_id="req-no",
        action_name="READ_OP",
        target="public_store",
        canonical_request_digest=digest,
        executor_id="exec_read",
        policy_version="1.0.0",
        created_at=time.time(),
        expires_at=time.time() + 300,
        human_approval=None
    )
    authority.registry.register_capability(cap_no_app)

    valid, reason, c = authority.verify_capability(
        token_id=cap_no_app.token_id,
        action_name="READ_OP",
        target="public_store",
        canonical_request_digest=digest,
        executor_id="exec_read",
        request_id="req-no"
    )
    assert valid is True
    assert reason == "CAPABILITY_VERIFIED"
    assert c is not None

    ok = authority.registry.consume_token(cap_no_app.token_id)
    assert ok is True

    # Replay consumption fails with standard token consumption replay
    ok_replay = authority.registry.consume_token(cap_no_app.token_id)
    assert ok_replay is False

    valid_replay, reason_replay, _ = authority.verify_capability(
        token_id=cap_no_app.token_id,
        action_name="READ_OP",
        target="public_store",
        canonical_request_digest=digest,
        executor_id="exec_read",
        request_id="req-no"
    )
    assert valid_replay is False
    assert "CAPABILITY_VERIFICATION_FAILED_REPLAY_TOKEN_ALREADY_CONSUMED" in reason_replay


def test_phase1_execution_boundary_integration_executor_invoked_exactly_once(tmp_path):
    """
    Approval Replay Scenario 6:
    Execution boundary integration proving the underlying executor is invoked exactly once.
    The execution boundary rejects a second capability issued against an already-consumed
    human approval before invoking the executor.
    """
    callback = MagicMock(return_value={"status": "ORDER_PROCESSED"})
    store = LocalProvenanceStore(log_path=str(tmp_path / "prov_boundary.jsonl"))
    boundary = TrustedExecutionBoundary(provenance_store=store)
    authority = boundary.authority

    policy = Policy(
        policy_id="pol-exec-boundary",
        allowed_operations={"SUBMIT_PAYMENT"},
        allowed_resources={"payment_gateway"},
        required_human_approval_operations={"SUBMIT_PAYMENT"}
    )
    authority.default_policy = policy

    payload = {"account": "acc_100", "amount": 500}
    digest = boundary.compute_canonical_digest(payload)

    approval = HumanApprovalRecord(
        approval_id="APP-EXEC-BOUNDARY-001",
        approver_id="finance_lead",
        action_name="SUBMIT_PAYMENT",
        target="payment_gateway",
        action_digest=digest,
        request_id="req-pay-1"
    )
    approval.sign(authority.approval_signing_secret)

    # Issue first capability with approval passing callable callback as executor_id
    cap1, _ = authority.evaluate_and_issue_capability(
        action_name="SUBMIT_PAYMENT",
        target="payment_gateway",
        canonical_request_digest=digest,
        executor_id=callback,
        request_id="req-pay-1",
        human_approval_input=approval,
        policy=policy
    )

    # Issue second capability with the exact same human approval record
    cap2 = Capability(
        token_id=f"AUTH-CAP-{uuid.uuid4()}",
        principal_id="agent_default",
        correlation_id=str(uuid.uuid4()),
        request_id="req-pay-1",
        action_name="SUBMIT_PAYMENT",
        target="payment_gateway",
        canonical_request_digest=digest,
        executor_id=get_callable_identity(callback),
        policy_version=policy.version,
        created_at=time.time(),
        expires_at=time.time() + 300,
        human_approval=approval
    )
    authority.registry.register_capability(cap2)
    authority.executor_registry._register_internal(cap2.token_id, callback)

    # 1. Execute first capability: MUST SUCCEED
    res1 = boundary.execute_protected_action(
        action_name="SUBMIT_PAYMENT",
        target="payment_gateway",
        request_payload=payload,
        authorization_token_id=cap1.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        executor_func=callback,
        request_id="req-pay-1"
    )
    assert res1["status"] == "SUCCESS"
    assert callback.call_count == 1

    # 2. Attempt to execute second capability: MUST BE REJECTED BEFORE EXECUTOR IS INVOKED
    with pytest.raises(PermissionError) as exc_info:
        boundary.execute_protected_action(
            action_name="SUBMIT_PAYMENT",
            target="payment_gateway",
            request_payload=payload,
            authorization_token_id=cap2.token_id,
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=callback,
            request_id="req-pay-1"
        )

    # Check reason code in exception
    assert "CAPABILITY_VERIFICATION_FAILED_REPLAY_HUMAN_APPROVAL_ALREADY_CONSUMED" in str(exc_info.value)

    # Invariant: Underlying executor was NEVER reached during second execution
    assert callback.call_count == 1


# =====================================================================
# Phase 1: Authorization Persistence Failure and Poisoning Tests
# =====================================================================

def test_phase1_persistence_interprocess_lock_acquisition_failure(tmp_path):
    """
    Persistence Test: Interprocess lock acquisition failure under fail-closed persistence.
    Verifies RuntimeError is raised and execution fails closed.
    """
    denial_log = tmp_path / "denial_lock_fail.jsonl"
    registry = CapabilityRegistry(
        denial_log_path=str(denial_log),
        fail_closed_persistence=True
    )

    import fcntl
    mock_flock = MagicMock(side_effect=OSError("Interprocess lock acquisition failed: resource temporarily unavailable"))

    import unittest.mock as mock
    with mock.patch("fcntl.flock", mock_flock):
        with pytest.raises(RuntimeError, match="Lock registry failure: unable to acquire interprocess file lock"):
            with registry.lock_registry():
                pass


def test_phase1_persistence_corrupted_denial_log_startup(tmp_path):
    """
    Persistence Test: Corrupted denial log startup under fail-closed persistence.
    Verifies RuntimeError is raised on corrupted / non-JSON lines during startup.
    """
    denial_log = tmp_path / "corrupted_denial.jsonl"
    with open(denial_log, "w", encoding="utf-8") as f:
        f.write('{"task_id": "task1", "action_name": "op1", "target": "res1", "status": "ACTIVE"}\n')
        f.write("CORRUPTED_NON_JSON_RECORD_DATA_LINE\n")

    with pytest.raises(RuntimeError, match="Failed to parse persistent denial log record"):
        CapabilityRegistry(
            denial_log_path=str(denial_log),
            fail_closed_persistence=True
        )


def test_phase1_clearance_append_failure_and_rollback_failure_poisons_registry(tmp_path):
    """
    Persistence Test: Clearance append failure followed by rollback failure.
    Causes both os.ftruncate() and fallback f.truncate() to fail deterministically
    via a specialized file wrapper seam.
    Verifies:
    1. The original denial remains active in memory.
    2. The clearance approval is not consumed.
    3. The registry transitions to _is_poisoned = True.
    4. Subsequent operations raise RuntimeError and fail closed.
    5. The original log prefix is preserved on disk.
    6. Transaction state is verified.
    """
    denial_log = tmp_path / "denial_rollback_fail.jsonl"
    registry = CapabilityRegistry(
        denial_log_path=str(denial_log),
        fail_closed_persistence=True
    )

    # 1. Record an initial active denial
    registry.record_denial(
        task_id="task-poison",
        action_name="DELETE_DB",
        target="db_1",
        reason="Security violation"
    )

    denied, rec = registry.check_denial(task_id="task-poison", action_name="DELETE_DB", target="db_1")
    assert denied is True
    assert rec["status"] == "ACTIVE"

    # Read original log contents
    with open(denial_log, "r", encoding="utf-8") as f:
        original_log_content = f.read()

    # Create signed clearance approval
    signing_secret = b"test_secret_for_clearance_poison_32b!"
    app_clear = HumanApprovalRecord(
        approval_id="APP-CLEAR-POISON-001",
        approver_id="sec_admin",
        action_name="CLEAR_DENIAL:DELETE_DB",
        target="CLEAR_DENIAL:db_1",
        action_digest="d" * 64,
        request_id="req-clear",
        task_id="task-poison"
    )
    app_clear.sign(signing_secret)

    # Specialized file wrapper to fail os.fsync AND fail os.ftruncate AND fail f.truncate
    orig_open = open

    class RollbackFailingFileWrapper:
        def __init__(self, real_file):
            self._real_file = real_file

        def write(self, data):
            return self._real_file.write(data)

        def flush(self):
            return self._real_file.flush()

        def tell(self):
            return self._real_file.tell()

        def seek(self, offset, whence=0):
            return self._real_file.seek(offset, whence)

        def fileno(self):
            return self._real_file.fileno()

        def truncate(self, size=None):
            # Fallback f.truncate fails!
            raise OSError("Injected I/O error on fallback f.truncate")

        def close(self):
            return self._real_file.close()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return self._real_file.__exit__(exc_type, exc_val, exc_tb)

    def custom_open(path, mode="r", *args, **kwargs):
        real_file = orig_open(path, mode, *args, **kwargs)
        if "denial_rollback_fail.jsonl" in str(path) and "a+" in mode:
            return RollbackFailingFileWrapper(real_file)
        return real_file

    import os
    orig_fsync = os.fsync
    orig_ftruncate = os.ftruncate

    def failing_fsync(fd):
        # Cause fsync to fail after partial or full write
        raise OSError("Injected disk failure on os.fsync")

    def failing_ftruncate(fd, length):
        # Primary rollback os.ftruncate fails!
        raise OSError("Injected filesystem error on os.ftruncate")

    import unittest.mock as mock
    with mock.patch("builtins.open", custom_open), \
         mock.patch("os.fsync", failing_fsync), \
         mock.patch("os.ftruncate", failing_ftruncate):

        with pytest.raises(RuntimeError, match="Denial persistence failure and rollback truncation failure: on-disk clearance state uncertain"):
            registry.clear_denial_with_approval(
                task_id="task-poison",
                action_name="DELETE_DB",
                target="db_1",
                reauthorization_record=app_clear,
                signing_secret=signing_secret
            )

    # Verify:
    # 1. The original denial remains active in memory dictionary
    assert ("task-poison", "DELETE_DB", "db_1") in registry._denied_records
    assert registry._denied_records[("task-poison", "DELETE_DB", "db_1")]["status"] == "ACTIVE"

    # 2. The clearance approval is not consumed
    assert app_clear.approval_id not in registry._consumed_approvals

    # 3. Registry is poisoned
    assert registry._is_poisoned is True

    # 4. Registry cannot continue operating as though state were healthy
    with pytest.raises(RuntimeError, match="poisoned state"):
        registry.check_denial(task_id="task-poison", action_name="DELETE_DB", target="db_1")

    with pytest.raises(RuntimeError, match="poisoned state"):
        with registry.lock_registry():
            pass

    with pytest.raises(RuntimeError, match="poisoned state"):
        registry.record_denial("task-other", "op", "target", "reason")

    with pytest.raises(RuntimeError, match="poisoned state"):
        registry.clear_denial_with_approval(
            task_id="task-poison",
            action_name="DELETE_DB",
            target="db_1",
            reauthorization_record=app_clear,
            signing_secret=signing_secret
        )

    # 5. The original log prefix is preserved
    with open(denial_log, "r", encoding="utf-8") as f:
        current_content = f.read()
    assert current_content.startswith(original_log_content)


def test_phase1_unresolved_limitation_restart_recovery_after_rollback_failure(tmp_path):
    """
    Unresolved Failure-Model Characterization:
    Durable Restart Recovery After Persistence Rollback Failure.

    IMPORTANT ARCHITECTURAL LIMITATION NOTICE:
    This test characterizes an unresolved fail-open recovery limitation across OS process restarts.
    It proves that process-local poisoning (_is_poisoned = True) protects the current process only,
    and that if a complete clearance JSON line was written before fsync and rollback failure,
    a newly started CapabilityRegistry instance loading the log file will read the complete line
    and remove the active denial.

    Scenario:
    1. Initial active denial is durably recorded.
    2. A clearance record is completely written to the file buffer.
    3. fsync fails.
    4. Rollback fails (both os.ftruncate and f.truncate fail).
    5. Registry 1 enters _is_poisoned = True in memory.
    6. Process restarts: new CapabilityRegistry loads the same denial log.
    7. FINDING: Without a multi-phase commit journal, the uncommitted clearance is replayed on restart.
    """
    denial_log = tmp_path / "denial_restart_investigation.jsonl"
    reg1 = CapabilityRegistry(
        denial_log_path=str(denial_log),
        fail_closed_persistence=True
    )

    reg1.record_denial(
        task_id="task-investigate",
        action_name="DROP_DATABASE",
        target="cluster_prod",
        reason="Malicious drop attempt"
    )

    signing_secret = b"investigation_secret_key_32bytes!"
    app_clear = HumanApprovalRecord(
        approval_id="APP-INVESTIGATE-001",
        approver_id="admin_carol",
        action_name="CLEAR_DENIAL:DROP_DATABASE",
        target="CLEAR_DENIAL:cluster_prod",
        action_digest="c" * 64,
        request_id="req-inv",
        task_id="task-investigate"
    )
    app_clear.sign(signing_secret)

    # Simulate fsync failure and rollback failure during clearance append:
    # Notice that f.write(json.dumps(rec) + "\n") successfully wrote bytes into the OS buffer / file.
    orig_open = open

    class RollbackFailingWrapper:
        def __init__(self, real_file):
            self._real_file = real_file

        def write(self, data):
            return self._real_file.write(data)

        def flush(self):
            return self._real_file.flush()

        def tell(self):
            return self._real_file.tell()

        def seek(self, offset, whence=0):
            return self._real_file.seek(offset, whence)

        def fileno(self):
            return self._real_file.fileno()

        def truncate(self, size=None):
            raise OSError("Truncate failed")

        def close(self):
            return self._real_file.close()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return self._real_file.__exit__(exc_type, exc_val, exc_tb)

    def custom_open(path, mode="r", *args, **kwargs):
        rf = orig_open(path, mode, *args, **kwargs)
        if "denial_restart_investigation.jsonl" in str(path) and "a+" in mode:
            return RollbackFailingWrapper(rf)
        return rf

    import unittest.mock as mock
    with mock.patch("builtins.open", custom_open), \
         mock.patch("os.fsync", MagicMock(side_effect=OSError("Disk controller error on fsync"))), \
         mock.patch("os.ftruncate", MagicMock(side_effect=OSError("ftruncate failed"))):

        with pytest.raises(RuntimeError):
            reg1.clear_denial_with_approval(
                task_id="task-investigate",
                action_name="DROP_DATABASE",
                target="cluster_prod",
                reauthorization_record=app_clear,
                signing_secret=signing_secret
            )

    assert reg1._is_poisoned is True
    # In reg1, denial is still present
    assert ("task-investigate", "DROP_DATABASE", "cluster_prod") in reg1._denied_records

    # NOW RESTART: A new process / CapabilityRegistry instance loads the same denial log
    reg2 = CapabilityRegistry(
        denial_log_path=str(denial_log),
        fail_closed_persistence=True
    )

    # Check whether reg2 replayed the un-fsynced, un-rolled-back complete clearance line
    denied_after_restart, rec2 = reg2.check_denial(
        task_id="task-investigate",
        action_name="DROP_DATABASE",
        target="cluster_prod"
    )

    # CRITICAL INVESTIGATION RESULT:
    # If the bytes were flushed to disk before fsync failed and rollback failed, the file contains the CLEARED line.
    # Because _is_poisoned is strictly in-memory and not stored on-disk, reg2 reads the complete valid JSON line
    # with status == "CLEARED" and pops the denial!
    # This proves empirically that the in-memory _is_poisoned flag does NOT survive process termination/restart.
    assert denied_after_restart is False
    assert rec2 is None


def test_phase1_poison_guard_concurrency_race(tmp_path):
    """
    Concurrency Race Regression Test (Strictly Deterministic Lock Contention):
    Proves the exact check-then-lock TOCTOU sequence:
    1. Thread A acquires registry lock via lock_registry() and holds it.
    2. Thread B enters lock_registry() and passes the initial pre-lock _check_poisoned() check.
    3. Thread B reaches the lock boundary and attempts non-blocking acquire(), which returns False,
       conclusively demonstrating that Thread B is in contention and blocked by Thread A owning the lock.
    4. While Thread A STILL holds the lock and Thread B is demonstrably blocked, Thread A poisons the registry.
    5. Thread A releases the lock.
    6. Thread B completes blocking acquire() on the underlying lock and MUST fail at the in-lock _check_poisoned() check.
    7. Assert Thread B never enters the protected context and fails specifically with the poisoned RuntimeError.
    """
    log_path = tmp_path / "test_concurrency_poison.jsonl"
    registry = CapabilityRegistry(
        denial_log_path=str(log_path),
        fail_closed_persistence=False
    )

    class ContentionProvingLock:
        def __init__(self, real_lock):
            self._real = real_lock
            self.thread_b = None
            self.b_contention_proven = threading.Event()
            self.a_poisoned_signal = threading.Event()
            self.b_acquired_underlying = threading.Event()
            self._b_tested = False

        def acquire(self, blocking=True, timeout=-1):
            if self.thread_b is not None and threading.current_thread() == self.thread_b and not self._b_tested:
                self._b_tested = True
                # Thread B is entering lock acquisition for the first time.
                # Prove actual contention: non-blocking acquire MUST fail because Thread A holds the lock.
                contention_verified = not self._real.acquire(blocking=False)
                if contention_verified:
                    self.b_contention_proven.set()
                else:
                    # Contention was not verified (Thread A did not hold lock) -> fail closed
                    self._real.release()
                    raise RuntimeError("Contention verification failed: Thread B unexpectedly acquired lock")

                # Block Thread B until Thread A has poisoned the registry while holding the lock
                if not self.a_poisoned_signal.wait(timeout=5.0):
                    raise TimeoutError("Deadlock guard: Thread A did not signal poisoning within timeout")

                # Thread B now executes the real blocking acquire
                res = self._real.acquire(blocking=True)
                if res:
                    self.b_acquired_underlying.set()
                return res
            return self._real.acquire(blocking, timeout)

        def release(self):
            return self._real.release()

        def __enter__(self):
            return self.acquire()

        def __exit__(self, t, v, tb):
            self.release()

    real_lock = registry._lock
    contention_lock = ContentionProvingLock(real_lock)
    registry._lock = contention_lock

    t1_holding = threading.Event()
    worker_errors = {}
    thread_b_entered = []

    def thread_a_poisoner():
        try:
            with registry.lock_registry():
                # 1. Thread A holds lock
                t1_holding.set()
                # 3. Wait until Thread B has demonstrably proven contention on the underlying lock
                if not contention_lock.b_contention_proven.wait(timeout=5.0):
                    raise TimeoutError("Deadlock guard: Thread B never reached contention state")
                # 4. Set poison state while Thread A STILL holds the lock
                registry._is_poisoned = True
                # Signal Thread B that poisoning has occurred
                contention_lock.a_poisoned_signal.set()
        except Exception as e:
            worker_errors["thread_a"] = e

    def thread_b_waiter():
        try:
            # Wait until Thread A has acquired the lock
            if not t1_holding.wait(timeout=5.0):
                raise TimeoutError("Deadlock guard: Thread A never acquired lock")

            # Thread B enters lock_registry(): passes initial pre-lock check, blocks on lock
            with registry.lock_registry():
                # Invariant: Thread B must NEVER enter the protected block
                thread_b_entered.append(True)
        except Exception as e:
            worker_errors["thread_b"] = e

    t1 = threading.Thread(target=thread_a_poisoner)
    t2 = threading.Thread(target=thread_b_waiter)
    contention_lock.thread_b = t2

    try:
        t1.start()
        t2.start()
        t1.join(timeout=5.0)
        t2.join(timeout=5.0)
    finally:
        # Signal synchronization events to release any waiting workers on failure/cancellation
        t1_holding.set()
        contention_lock.b_contention_proven.set()
        contention_lock.a_poisoned_signal.set()

        t1.join(timeout=1.0)
        t2.join(timeout=1.0)

        # Verify termination established before restoring the underlying lock
        t1_alive = t1.is_alive()
        t2_alive = t2.is_alive()
        registry._lock = real_lock

    assert not t1_alive, "Thread A did not terminate"
    assert not t2_alive, "Thread B did not terminate"

    # Surface any worker errors from Thread A
    assert "thread_a" not in worker_errors, f"Thread A encountered unexpected error: {worker_errors.get('thread_a')}"

    # Verify Thread B was blocked on the lock and then acquired it
    assert contention_lock.b_contention_proven.is_set(), "Thread B never proved lock contention"
    assert contention_lock.b_acquired_underlying.is_set(), "Thread B never acquired underlying lock"

    # Invariant: Thread B was rejected by in-lock _check_poisoned() and never entered the protected context
    assert len(thread_b_entered) == 0, "Thread B entered protected context despite poisoned state!"
    assert "thread_b" in worker_errors, "Thread B did not raise an exception"
    assert isinstance(worker_errors["thread_b"], RuntimeError)
    assert "CapabilityRegistry is in a poisoned state" in str(worker_errors["thread_b"])


def test_phase1_public_issuance_same_approval_cross_target_replay_and_fencing():
    """
    Public Issuance & Fencing Analysis Test:
    Investigates evaluate_and_issue_capability() behavior when two capabilities share one approval ID.

    Scenario A: Same target / same scope
    - Capability 1 is issued at fencing generation G.
    - Capability 2 is issued at fencing generation G + 1.
    - Fencing tokens strictly advance per scope, invalidating Capability 1 for execution (STALE_FENCING_TOKEN).
    - However, Capability 2 remains executable.

    Scenario B: Different targets / independent scopes
    - If approvals could be repurposed across targets, both could be issued without mutual fencing invalidation.
    - However, HumanApprovalRecord binds action_name and target; cross-target issuance is rejected at issuance.

    Scenario C: When two capabilities sharing an approval are both issued, consuming one capability
    strictly invalidates the other via verification rejection and consumption rejection.
    """
    authority = AuthorizationAuthority()
    policy = Policy(
        policy_id="pol-pub-fencing",
        allowed_operations={"API_WRITE"},
        allowed_resources={"endpoint_a", "endpoint_b"},
        required_human_approval_operations={"API_WRITE"}
    )
    authority.default_policy = policy

    exec_func = lambda: "RUN"
    authority.register_executor("exec_api", exec_func)
    digest = "c" * 64

    # 1. Target binding check: an approval bound to endpoint_a CANNOT issue a capability for endpoint_b
    approval_a = HumanApprovalRecord(
        approval_id="APP-PUB-001",
        approver_id="approver_pub",
        action_name="API_WRITE",
        target="endpoint_a",
        action_digest=digest,
        request_id="req-pub-1"
    )
    approval_a.sign(authority.approval_signing_secret)

    cap_wrong_target, reason_wrong_target = authority.evaluate_and_issue_capability(
        action_name="API_WRITE",
        target="endpoint_b",
        canonical_request_digest=digest,
        executor_id="exec_api",
        request_id="req-pub-1",
        human_approval_input=approval_a,
        policy=policy
    )
    assert cap_wrong_target is None
    assert reason_wrong_target == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_BINDING_MISMATCH"

    # 2. Sequential public issuance for same scope
    cap1, r1 = authority.evaluate_and_issue_capability(
        action_name="API_WRITE",
        target="endpoint_a",
        canonical_request_digest=digest,
        executor_id="exec_api",
        request_id="req-pub-1",
        human_approval_input=approval_a,
        policy=policy
    )
    assert cap1 is not None
    assert r1 == "AUTHORIZATION_GRANTED"
    assert cap1.fencing_token == 1

    cap2, r2 = authority.evaluate_and_issue_capability(
        action_name="API_WRITE",
        target="endpoint_a",
        canonical_request_digest=digest,
        executor_id="exec_api",
        request_id="req-pub-1",
        human_approval_input=approval_a,
        policy=policy
    )
    assert cap2 is not None
    assert r2 == "AUTHORIZATION_GRANTED"
    assert cap2.fencing_token == 2

    # Invariant: cap1 fencing generation is now stale because cap2 advanced the scope generation
    valid_c1, reason_c1, _ = authority.verify_capability(
        token_id=cap1.token_id,
        action_name="API_WRITE",
        target="endpoint_a",
        canonical_request_digest=digest,
        executor_id="exec_api",
        request_id="req-pub-1"
    )
    assert valid_c1 is False
    assert "CAPABILITY_VERIFICATION_FAILED_STALE_FENCING_TOKEN" in reason_c1

    # Invariant: cap2 has generation 2 and verifies successfully before consumption
    valid_c2, reason_c2, _ = authority.verify_capability(
        token_id=cap2.token_id,
        action_name="API_WRITE",
        target="endpoint_a",
        canonical_request_digest=digest,
        executor_id="exec_api",
        request_id="req-pub-1"
    )
    assert valid_c2 is True
    assert reason_c2 == "CAPABILITY_VERIFIED"

    # Consume cap2
    assert authority.registry.consume_token(cap2.token_id) is True

    # After consumption of cap2, the approval is consumed; attempting to issue a third capability fails
    cap3, r3 = authority.evaluate_and_issue_capability(
        action_name="API_WRITE",
        target="endpoint_a",
        canonical_request_digest=digest,
        executor_id="exec_api",
        request_id="req-pub-1",
        human_approval_input=approval_a,
        policy=policy
    )
    assert cap3 is None
    assert r3 == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_REPLAYED"
