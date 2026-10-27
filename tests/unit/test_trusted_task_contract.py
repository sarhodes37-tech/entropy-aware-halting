"""
Unit, Adversarial, and Security Invariant Tests for EpistemicOS TrustedTaskContract.
Verifies contract integrity, prohibition precedence, approval binding, denial preservation,
delegation isolation, success evidence requirements, and audit trail reconciliation.
"""

import os
import time
import uuid
import pytest
from typing import Dict, Any, List

import epistemicos.provenance
from epistemicos.authorization import (
    TrustedTaskContract,
    AuthorizationAuthority,
    CapabilityRegistry,
    Policy,
    HumanApprovalRecord
)
from epistemicos.provenance import (
    TrustedExecutionBoundary,
    LocalProvenanceStore,
    ExecutionContext,
    ProvenanceReconciler,
    ProvenanceEventType,
    ProvenanceSource,
    ProvenanceEvent
)
from epistemicos.core import EpistemicOrchestrator


def dummy_executor():
    return {"status": "ok", "evidence_key": "valid_proof_123"}


def bad_executor():
    return {"status": "ok", "wrong_key": "no_proof"}


def test_contract_integrity_and_signature():
    secret = b"trusted_contract_signing_secret_32b"
    contract = TrustedTaskContract(
        task_id="TASK-INT-01",
        contract_version="1.0.0",
        permitted_actions={"local_read", "execute_cmd"},
        resource_scope={"/tmp/allowed"},
        explicit_prohibitions={"delete_file"},
        prohibited_resources={"/etc/shadow"}
    )
    sig = contract.sign(secret)
    assert sig is not None
    assert contract.verify_signature(secret) is True

    # Tamper with contract action
    contract.permitted_actions.add("admin_shell")
    assert contract.verify_signature(secret) is False


def test_contract_signature_verification_enforced_in_authority():
    authority = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"})
    )

    contract = TrustedTaskContract(
        task_id="TASK-AUTH-SIG",
        permitted_actions={"read_table"},
        resource_scope={"/db/users"}
    )

    # 1. Unsigned contract fails
    cap1, reason1 = authority.evaluate_and_issue_capability(
        action_name="read_table",
        target="/db/users",
        canonical_request_digest="dig1",
        task_contract=contract
    )
    assert cap1 is None
    assert reason1 == "AUTHORIZATION_DENIED_CONTRACT_SIGNATURE_INVALID"

    # 2. Forged signature fails
    contract.sign(b"wrong_untrusted_secret")
    cap2, reason2 = authority.evaluate_and_issue_capability(
        action_name="read_table",
        target="/db/users",
        canonical_request_digest="dig1",
        task_contract=contract
    )
    assert cap2 is None
    assert reason2 == "AUTHORIZATION_DENIED_CONTRACT_SIGNATURE_INVALID"

    # 3. Validly signed contract succeeds
    contract.sign(authority.contract_signing_secret)
    cap3, reason3 = authority.evaluate_and_issue_capability(
        action_name="read_table",
        target="/db/users",
        canonical_request_digest="dig1",
        task_contract=contract
    )
    assert cap3 is not None
    assert reason3 == "AUTHORIZATION_GRANTED"


def test_explicit_prohibition_precedence_over_broad_permissions():
    authority = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"})
    )

    contract = TrustedTaskContract(
        task_id="TASK-PROHIB-01",
        permitted_actions={"*"},
        resource_scope={"*"},
        explicit_prohibitions={"delete_database"},
        prohibited_resources={"/db/production"}
    )
    contract.sign(authority.contract_signing_secret)

    # Permitted action allowed
    cap, reason = authority.evaluate_and_issue_capability(
        action_name="read_table",
        target="/db/users",
        canonical_request_digest="dig1",
        task_contract=contract
    )
    assert cap is not None
    assert reason == "AUTHORIZATION_GRANTED"

    # Explicitly prohibited action denied despite broad permissions
    contract_p1 = TrustedTaskContract(
        task_id="TASK-PROHIB-01",
        permitted_actions={"*"},
        resource_scope={"*"},
        explicit_prohibitions={"delete_database"},
        prohibited_resources={"/db/production"}
    )
    contract_p1.sign(authority.contract_signing_secret)

    cap2, reason2 = authority.evaluate_and_issue_capability(
        action_name="delete_database",
        target="/db/users",
        canonical_request_digest="dig2",
        task_contract=contract_p1
    )
    assert cap2 is None
    assert "CONTRACT_EXPLICIT_PROHIBITION" in reason2

    # Prohibited resource denied
    contract_p2 = TrustedTaskContract(
        task_id="TASK-PROHIB-01",
        permitted_actions={"*"},
        resource_scope={"*"},
        explicit_prohibitions={"delete_database"},
        prohibited_resources={"/db/production"}
    )
    contract_p2.sign(authority.contract_signing_secret)

    cap3, reason3 = authority.evaluate_and_issue_capability(
        action_name="read_table",
        target="/db/production",
        canonical_request_digest="dig3",
        task_contract=contract_p2
    )
    assert cap3 is None
    assert "CONTRACT_EXPLICIT_PROHIBITION" in reason3


def test_durable_denial_preservation_across_retries_and_routes(tmp_path):
    log_file = tmp_path / "prov.jsonl"
    denial_log = tmp_path / "denials.jsonl"
    store = LocalProvenanceStore(log_path=str(log_file))
    registry = CapabilityRegistry(denial_log_path=str(denial_log))
    authority = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"local_read"}, allowed_resources={"/app/data"}),
        registry=registry
    )

    contract = TrustedTaskContract(
        task_id="TASK-DENIAL-01",
        permitted_actions={"local_read"},
        resource_scope={"/app/data"}
    )
    contract.sign(authority.contract_signing_secret)

    # Initial attempt for forbidden operation 'write_file' -> DENIED by contract scope check and recorded
    cap1, reason1 = authority.evaluate_and_issue_capability(
        action_name="write_file",
        target="/app/data",
        canonical_request_digest="digest_1",
        task_contract=contract
    )
    assert cap1 is None
    assert "CONTRACT_SCOPE_VIOLATION" in reason1

    # Now, present a newly signed contract for the SAME task_id that permits 'write_file'.
    # Because TASK-DENIAL-01 had a denial recorded under this task_id, action, and target,
    # the durable denial registry MUST actively block the retry!
    contract_permissive = TrustedTaskContract(
        task_id="TASK-DENIAL-01",
        permitted_actions={"local_read", "write_file"},
        resource_scope={"/app/data"}
    )
    contract_permissive.sign(authority.contract_signing_secret)

    cap2, reason2 = authority.evaluate_and_issue_capability(
        action_name="write_file",
        target="/app/data",
        canonical_request_digest="digest_alt_route",
        task_contract=contract_permissive
    )
    assert cap2 is None
    assert "DURABLE_DENIAL_ACTIVE" in reason2


def test_denial_persistence_failure_handling(tmp_path):
    unwritable_path = tmp_path / "non_existent_dir" / "readonly" / "denial.jsonl"
    registry = CapabilityRegistry(denial_log_path=str(unwritable_path), fail_closed_persistence=True)

    # Create invalid directory to trigger write failure
    os.makedirs(tmp_path / "non_existent_dir", mode=0o444, exist_ok=True)

    with pytest.raises(RuntimeError) as exc_info:
        registry.record_denial("TASK-FAIL-PERSIST", "delete", "/path", "Forbidden")
    assert "Denial persistence failure" in str(exc_info.value)


def test_denial_continuity_across_version_updates_and_explicit_reauthorization(tmp_path):
    denial_log = tmp_path / "denials_ver.jsonl"
    registry = CapabilityRegistry(denial_log_path=str(denial_log))
    authority = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"}),
        registry=registry
    )

    contract_v1 = TrustedTaskContract(
        task_id="TASK-VER-01",
        contract_version="1.0.0",
        explicit_prohibitions={"mutate_state"}
    )
    contract_v1.sign(authority.contract_signing_secret)

    # Initial attempt -> DENIED
    cap1, reason1 = authority.evaluate_and_issue_capability(
        action_name="mutate_state",
        target="/state",
        canonical_request_digest="dig1",
        task_contract=contract_v1
    )
    assert cap1 is None
    assert "CONTRACT_EXPLICIT_PROHIBITION" in reason1

    # Retry under updated contract_version '2.0.0' without reauthorization -> STILL DENIED
    contract_v2 = TrustedTaskContract(
        task_id="TASK-VER-01",
        contract_version="2.0.0",
        permitted_actions={"mutate_state"},
        resource_scope={"/state"}
    )
    contract_v2.sign(authority.contract_signing_secret)

    cap2, reason2 = authority.evaluate_and_issue_capability(
        action_name="mutate_state",
        target="/state",
        canonical_request_digest="dig2",
        task_contract=contract_v2
    )
    assert cap2 is None
    assert "DURABLE_DENIAL_ACTIVE" in reason2

    # 1. Ordinary action approval cannot clear denial
    ordinary_app = HumanApprovalRecord(
        approval_id="APP-ORD-01",
        approver_id="security_admin",
        action_name="mutate_state",
        target="/state",
        action_digest="dig3",
        request_id="REQ-CLEAR-01"
    )
    ordinary_app.sign(authority.approval_signing_secret)

    cleared_ord, msg_ord = authority.clear_denial_with_approval("TASK-VER-01", "mutate_state", "/state", ordinary_app)
    assert cleared_ord is False
    assert "cannot be repurposed" in msg_ord

    # 2. Unsigned clearance approval fails
    clearance_app = HumanApprovalRecord(
        approval_id="APP-CLEAR-01",
        approver_id="security_admin",
        action_name="CLEAR_DENIAL:mutate_state",
        target="/state",
        action_digest="dig3",
        request_id="REQ-CLEAR-01"
    )
    cleared_unsigned, msg_unsigned = authority.clear_denial_with_approval("TASK-VER-01", "mutate_state", "/state", clearance_app)
    assert cleared_unsigned is False
    assert "verification failed" in msg_unsigned

    # 3. Forged clearance signature fails
    clearance_app.sign(b"wrong_secret")
    cleared_forged, msg_forged = authority.clear_denial_with_approval("TASK-VER-01", "mutate_state", "/state", clearance_app)
    assert cleared_forged is False
    assert "verification failed" in msg_forged

    # 4. Properly signed clearance approval succeeds!
    clearance_app.sign(authority.approval_signing_secret)
    cleared, msg_success = authority.clear_denial_with_approval("TASK-VER-01", "mutate_state", "/state", clearance_app)
    assert cleared is True
    assert "successfully cleared" in msg_success

    # 5. Replaying the clearance approval fails
    cleared_replay, msg_replay = authority.clear_denial_with_approval("TASK-VER-01", "mutate_state", "/state", clearance_app)
    assert cleared_replay is False
    assert "already consumed" in msg_replay

    # Retry after explicit reauthorization -> GRANTED
    action_app = HumanApprovalRecord(
        approval_id="APP-ACTION-01",
        approver_id="security_admin",
        action_name="mutate_state",
        target="/state",
        action_digest="dig3",
        request_id="REQ-MUT-01"
    )
    action_app.sign(authority.approval_signing_secret)
    cap3, reason3 = authority.evaluate_and_issue_capability(
        action_name="mutate_state",
        target="/state",
        canonical_request_digest="dig3",
        request_id="REQ-MUT-01",
        task_contract=contract_v2,
        human_approval_input=action_app
    )
    assert cap3 is not None
    assert reason3 == "AUTHORIZATION_GRANTED"


def test_multi_instance_denial_synchronization(tmp_path):
    denial_log = tmp_path / "shared_denials.jsonl"
    registry_a = CapabilityRegistry(denial_log_path=str(denial_log))
    registry_b = CapabilityRegistry(denial_log_path=str(denial_log))

    # Instance A records denial
    registry_a.record_denial("TASK-SHARED-1", "drop_db", "/prod", "Prohibited by A")

    # Instance B queries denial -> must re-sync from shared persistent log and detect ACTIVE denial!
    is_denied, record = registry_b.check_denial("TASK-SHARED-1", "drop_db", "/prod")
    assert is_denied is True
    assert record["reason"] == "Prohibited by A"


def test_contract_required_execution_mode():
    authority = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"read"}, allowed_resources={"/data"}),
        require_task_contract=True
    )

    # Calling without task contract fails closed
    cap, reason = authority.evaluate_and_issue_capability(
        action_name="read",
        target="/data",
        canonical_request_digest="dig"
    )
    assert cap is None
    assert reason == "AUTHORIZATION_DENIED_CONTRACT_REQUIRED"


def test_null_and_empty_evidence_validation(tmp_path):
    log_file = tmp_path / "prov_null.jsonl"
    store = LocalProvenanceStore(log_path=str(log_file))
    authority = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"run"}, allowed_resources={"/res"})
    )
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=authority)

    def null_evidence_executor():
        return {"status": "ok", "proof": None}

    def empty_evidence_executor():
        return {"status": "ok", "proof": ""}

    boundary.authority.register_executor("null_exec", null_evidence_executor)
    boundary.authority.register_executor("empty_exec", empty_evidence_executor)

    req_payload = {"cmd": "test"}
    d = boundary.compute_canonical_digest(req_payload)

    corr1 = str(uuid.uuid4())
    cap1, _ = authority.evaluate_and_issue_capability(action_name="run", target="/res", canonical_request_digest=d, executor_id=null_evidence_executor, correlation_id=corr1)
    ctx1 = ExecutionContext(correlation_id=corr1, request_id=cap1.request_id, authorization_token_id=cap1.token_id, authorized_digest=d, required_success_evidence={"proof"})
    res1 = boundary.execute_protected_action(action_name="run", target="/res", request_payload=req_payload, executor_func=null_evidence_executor, context=ctx1)
    assert res1["status"] == "UNVERIFIED_SUCCESS"

    corr2 = str(uuid.uuid4())
    cap2, _ = authority.evaluate_and_issue_capability(action_name="run", target="/res", canonical_request_digest=d, executor_id=empty_evidence_executor, correlation_id=corr2)
    ctx2 = ExecutionContext(correlation_id=corr2, request_id=cap2.request_id, authorization_token_id=cap2.token_id, authorized_digest=d, required_success_evidence={"proof"})
    res2 = boundary.execute_protected_action(action_name="run", target="/res", request_payload=req_payload, executor_func=empty_evidence_executor, context=ctx2)
    assert res2["status"] == "UNVERIFIED_SUCCESS"


def test_end_to_end_adversarial_side_effect_isolation(tmp_path):
    audit_file = tmp_path / "audit_adv.jsonl"
    orchestrator = EpistemicOrchestrator(audit_log_path=str(audit_file))
    orchestrator.authority.require_task_contract = True
    authority = orchestrator.authority
    contract_secret = authority.contract_signing_secret

    side_effect_counter = [0]

    def side_effecting_executor():
        side_effect_counter[0] += 1
        return {"status": "ok", "evidence_key": "valid_proof_999"}

    authority.register_executor("side_effect_exec", side_effecting_executor)
    authority.default_policy = Policy(policy_id="p1", allowed_operations={"consequential_op"}, allowed_resources={"/target"})

    # Attack 1: Omitted contract when required -> Callback NOT executed
    res1 = orchestrator.process_submission(
        raw_payload={"policy_id": "p1"},
        context={"action_name": "consequential_op", "target": "/target", "actual_executable": side_effecting_executor}
    )
    assert res1["status"] == "HALTED"
    assert side_effect_counter[0] == 0

    # Attack 2: Tampered contract signature -> Callback NOT executed
    contract_forged = TrustedTaskContract(task_id="TASK-ADV-1", permitted_actions={"consequential_op"}, resource_scope={"/target"})
    contract_forged.sign(b"forged_key")

    res2 = orchestrator.process_submission(
        raw_payload={"policy_id": "p1"},
        context={"action_name": "consequential_op", "target": "/target", "actual_executable": side_effecting_executor, "task_contract": contract_forged}
    )
    assert res2["status"] == "HALTED"
    assert side_effect_counter[0] == 0

    # Attack 3: Task identity substitution -> Callback NOT executed
    contract_valid = TrustedTaskContract(task_id="TASK-ORIGINAL", permitted_actions={"consequential_op"}, resource_scope={"/target"})
    contract_valid.sign(contract_secret)

    res3 = orchestrator.process_submission(
        raw_payload={"policy_id": "p1"},
        context={"action_name": "consequential_op", "target": "/target", "actual_executable": side_effecting_executor, "task_contract": contract_valid, "task_id": "TASK-SUBSTITUTE"}
    )
    assert res3["status"] == "HALTED"
    assert side_effect_counter[0] == 0

    # Valid execution -> Callback executed exactly ONCE
    contract_valid_e2e = TrustedTaskContract(task_id="TASK-LEGIT", permitted_actions={"consequential_op"}, resource_scope={"/target"}, success_evidence_requirements={"evidence_key"})
    contract_valid_e2e.sign(contract_secret)

    res_valid = orchestrator.process_submission(
        raw_payload={"policy_id": "p1"},
        context={"action_name": "consequential_op", "target": "/target", "actual_executable": side_effecting_executor, "task_contract": contract_valid_e2e}
    )
    assert res_valid["status"] == "ALLOWED"
    assert side_effect_counter[0] == 1
