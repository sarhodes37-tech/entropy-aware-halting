"""
Unit, Adversarial, and Security Invariant Tests for EpistemicOS TrustedTaskContract.
Verifies contract integrity, prohibition precedence, approval binding, denial preservation,
delegation isolation, success evidence requirements, and audit trail reconciliation.
"""

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
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=authority)

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


def test_worker_delegation_and_identity_mismatch():
    authority = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"worker_task"}, allowed_resources={"*"})
    )
    contract = TrustedTaskContract(
        task_id="TASK-ORIGINATOR-99",
        permitted_actions={"worker_task"},
        resource_scope={"/data/task"}
    )
    contract.sign(authority.contract_signing_secret)

    # Worker attempts to present caller's contract under a substituted task_id -> DENIED
    cap, reason = authority.evaluate_and_issue_capability(
        action_name="worker_task",
        target="/data/task",
        canonical_request_digest="dig_worker",
        task_contract=contract,
        task_id="TASK-WORKER-SUBSTITUTE"
    )
    assert cap is None
    assert reason == "AUTHORIZATION_DENIED_TASK_IDENTITY_MISMATCH"


def test_success_evidence_verification(tmp_path):
    log_file = tmp_path / "prov_ev.jsonl"
    store = LocalProvenanceStore(log_path=str(log_file))
    authority = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"process_data"}, allowed_resources={"/data"})
    )
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=authority)
    boundary.authority.register_executor("dummy_executor", dummy_executor)
    boundary.authority.register_executor("bad_executor", bad_executor)

    req_payload = {"cmd": "run"}
    digest = boundary.compute_canonical_digest(req_payload)
    corr_id = str(uuid.uuid4())

    contract = TrustedTaskContract(
        task_id="TASK-EVIDENCE-01",
        permitted_actions={"process_data"},
        resource_scope={"/data"},
        success_evidence_requirements={"evidence_key"}
    )
    contract.sign(authority.contract_signing_secret)

    # Issue capability for dummy_executor with contract
    cap, reason = authority.evaluate_and_issue_capability(
        action_name="process_data",
        target="/data",
        canonical_request_digest=digest,
        executor_id=dummy_executor,
        correlation_id=corr_id,
        task_contract=contract
    )
    assert cap is not None
    assert "evidence_key" in cap.required_success_evidence
    req_id = cap.request_id

    # Record grant event
    store.record_event(ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id=req_id,
        action_name="process_data",
        target="/data",
        canonical_request_digest=digest,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        authorization_token_id=cap.token_id,
        policy_version="1.0.0"
    ))

    # Context automatically inheriting requirements from capability
    ctx_good = ExecutionContext(
        correlation_id=corr_id,
        request_id=req_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        required_success_evidence=cap.required_success_evidence
    )

    res = boundary.execute_protected_action(
        action_name="process_data",
        target="/data",
        request_payload=req_payload,
        executor_func=dummy_executor,
        context=ctx_good
    )
    assert res["status"] == "SUCCESS"

    # Now test missing evidence key with bad_executor
    digest2 = boundary.compute_canonical_digest(req_payload)
    corr_id2 = str(uuid.uuid4())
    contract_bad = TrustedTaskContract(
        task_id="TASK-EVIDENCE-02",
        permitted_actions={"process_data"},
        resource_scope={"/data"},
        success_evidence_requirements={"evidence_key"}
    )
    contract_bad.sign(authority.contract_signing_secret)

    cap_bad, _ = authority.evaluate_and_issue_capability(
        action_name="process_data",
        target="/data",
        canonical_request_digest=digest2,
        executor_id=bad_executor,
        correlation_id=corr_id2,
        task_contract=contract_bad
    )
    req_id2 = cap_bad.request_id
    store.record_event(ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id2,
        request_id=req_id2,
        action_name="process_data",
        target="/data",
        canonical_request_digest=digest2,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        authorization_token_id=cap_bad.token_id,
        policy_version="1.0.0"
    ))

    ctx_bad = ExecutionContext(
        correlation_id=corr_id2,
        request_id=req_id2,
        authorization_token_id=cap_bad.token_id,
        authorized_digest=digest2,
        authorization_granted=True,
        required_success_evidence=cap_bad.required_success_evidence
    )

    res_bad = boundary.execute_protected_action(
        action_name="process_data",
        target="/data",
        request_payload=req_payload,
        executor_func=bad_executor,
        context=ctx_bad
    )
    assert res_bad["status"] == "UNVERIFIED_SUCCESS"
    assert "Missing required success evidence key" in res_bad["reason"]


def test_orchestrator_end_to_end_contract_and_evidence_propagation(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    orchestrator = EpistemicOrchestrator(audit_log_path=str(audit_file))
    authority = orchestrator.authority
    contract_secret = authority.contract_signing_secret

    authority.register_executor("dummy_executor", dummy_executor)
    authority.register_executor("bad_executor", bad_executor)

    # Set policy allowing local_read
    authority.default_policy = Policy(policy_id="p1", allowed_operations={"process_data"}, allowed_resources={"/data"})

    contract = TrustedTaskContract(
        task_id="TASK-E2E-01",
        permitted_actions={"process_data"},
        resource_scope={"/data"},
        success_evidence_requirements={"evidence_key"}
    )
    contract.sign(contract_secret)

    # Execute with bad_executor -> returns UNVERIFIED_SUCCESS and top-level HALTED status
    res = orchestrator.process_submission(
        raw_payload={"policy_id": "p1", "item_id": "test1"},
        context={
            "action_name": "process_data",
            "target": "/data",
            "actual_executable": bad_executor,
            "task_contract": contract
        }
    )
    assert res["status"] == "HALTED"
    assert res["execution_status"] == "UNVERIFIED_SUCCESS"
    assert "Execution boundary verification failed" in res["reason"]

    # Execute with dummy_executor -> returns ALLOWED status and SUCCESS outcome
    contract2 = TrustedTaskContract(
        task_id="TASK-E2E-02",
        permitted_actions={"process_data"},
        resource_scope={"/data"},
        success_evidence_requirements={"evidence_key"}
    )
    contract2.sign(contract_secret)

    res2 = orchestrator.process_submission(
        raw_payload={"policy_id": "p1", "item_id": "test2"},
        context={
            "action_name": "process_data",
            "target": "/data",
            "actual_executable": dummy_executor,
            "task_contract": contract2
        }
    )
    assert res2["status"] == "ALLOWED"
    assert res2["execution_status"] == "EXECUTED"
    assert res2["execution_outcome"]["status"] == "SUCCESS"
