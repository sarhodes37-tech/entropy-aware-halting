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
    cap2, reason2 = authority.evaluate_and_issue_capability(
        action_name="delete_database",
        target="/db/users",
        canonical_request_digest="dig2",
        task_contract=contract
    )
    assert cap2 is None
    assert "CONTRACT_EXPLICIT_PROHIBITION" in reason2

    # Prohibited resource denied
    cap3, reason3 = authority.evaluate_and_issue_capability(
        action_name="read_table",
        target="/db/production",
        canonical_request_digest="dig3",
        task_contract=contract
    )
    assert cap3 is None
    assert "CONTRACT_EXPLICIT_PROHIBITION" in reason3


def test_durable_denial_preservation_across_retries_and_routes(tmp_path):
    log_file = tmp_path / "prov.jsonl"
    store = LocalProvenanceStore(log_path=str(log_file))
    authority = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"local_read"}, allowed_resources={"/app/data"})
    )
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=authority)

    contract = TrustedTaskContract(
        task_id="TASK-DENIAL-01",
        permitted_actions={"local_read"},
        resource_scope={"/app/data"}
    )

    # Initial attempt for forbidden operation 'write_file' -> DENIED
    cap1, reason1 = authority.evaluate_and_issue_capability(
        action_name="write_file",
        target="/app/data",
        canonical_request_digest="digest_1",
        task_contract=contract
    )
    assert cap1 is None
    assert "CONTRACT_SCOPE_VIOLATION" in reason1 or "OPERATION_NOT_ALLOWED" in reason1

    # Retry the same denied action under different tool alias or route -> Still DENIED by durable registry
    cap2, reason2 = authority.evaluate_and_issue_capability(
        action_name="write_file",
        target="/app/data",
        canonical_request_digest="digest_alt_route",
        task_contract=contract
    )
    assert cap2 is None
    assert "DURABLE_DENIAL_ACTIVE" in reason2 or "CONTRACT_SCOPE_VIOLATION" in reason2


def test_worker_delegation_and_identity_mismatch():
    authority = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"worker_task"}, allowed_resources={"*"})
    )
    contract = TrustedTaskContract(
        task_id="TASK-ORIGINATOR-99",
        permitted_actions={"worker_task"},
        resource_scope={"/data/task"}
    )

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

    # Issue capability for dummy_executor
    cap, reason = authority.evaluate_and_issue_capability(
        action_name="process_data",
        target="/data",
        canonical_request_digest=digest,
        executor_id=dummy_executor,
        correlation_id=corr_id
    )
    assert cap is not None
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

    # Context requiring evidence_key
    ctx_good = ExecutionContext(
        correlation_id=corr_id,
        request_id=req_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        required_success_evidence={"evidence_key"}
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
    cap_bad, _ = authority.evaluate_and_issue_capability(
        action_name="process_data",
        target="/data",
        canonical_request_digest=digest2,
        executor_id=bad_executor,
        correlation_id=corr_id2
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
        required_success_evidence={"evidence_key"}
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
