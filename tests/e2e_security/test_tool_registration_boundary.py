"""
Reproducible Test Suite for Tool Registration & Execution Enforcement Boundary Assessment
"""
import pytest
import time
import uuid
import socket
from epistemicos.core import EpistemicOrchestrator
from epistemicos.models import CanonicalProblemRepresentation
from epistemicos.authorization import (
    AuthorizationAuthority,
    Policy,
    TrustedTaskContract,
    CapabilityRegistry,
)
from epistemicos.provenance import (
    TrustedExecutionBoundary,
    LocalProvenanceStore,
    ExecutionContext,
)
from epistemicos.containment import (
    ContainmentGuard,
    EgressTransportBroker,
    EgressPolicy,
    ActionCategory,
)
from epistemicos.gates import PermissionGate

@pytest.fixture
def test_env(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    prov_path = tmp_path / "provenance.jsonl"
    denial_path = tmp_path / "denial.jsonl"

    store = LocalProvenanceStore(log_path=str(prov_path))
    registry = CapabilityRegistry(denial_log_path=str(denial_path))
    authority = AuthorizationAuthority(registry=registry)
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=authority)
    orchestrator = EpistemicOrchestrator(
        audit_log_path=str(audit_path),
        execution_boundary=boundary,
        authority=authority
    )
    guard = ContainmentGuard(egress_policy=EgressPolicy(allow_loopback=False, allow_private=False))

    return {
        "orchestrator": orchestrator,
        "authority": authority,
        "boundary": boundary,
        "registry": registry,
        "store": store,
        "guard": guard,
        "audit_path": audit_path,
        "prov_path": prov_path,
    }

def get_valid_cpr_payload(**overrides):
    base = {
        "policy_id": "test_policy",
        "raw_payload": {"test": "data"}
    }
    base.update(overrides)
    return base

def test_1_normal_invocation_via_orchestrator(test_env):
    """
    Case 1: Normal Invocation
    A tool is invoked through the EpistemicOrchestrator and TrustedExecutionBoundary.
    Verify authorization, capability verification, and provenance recording occur before underlying execution.
    """
    authority = test_env["authority"]
    orchestrator = test_env["orchestrator"]

    policy = Policy(
        policy_id="test_policy",
        allowed_operations={"deploy_service"},
        allowed_resources={"prod_cluster"}
    )
    authority.default_policy = policy

    execution_count = 0
    def mock_deploy():
        nonlocal execution_count
        execution_count += 1
        return {"status": "deployed_v1"}

    authority.register_executor("mock_deploy", mock_deploy)
    orchestrator.gates[0] = PermissionGate(trusted_scope={
        "allowed_operations": ["deploy_service"],
        "allowed_resources": ["prod_cluster"]
    })

    raw_payload = get_valid_cpr_payload(
        proposed_actions=[{"action": {"op": "deploy_service", "node": "prod_cluster"}}]
    )
    context = {
        "action_name": "deploy_service",
        "target": "prod_cluster",
        "actual_executable": mock_deploy,
        "policy": policy
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "ALLOWED"
    assert res["execution_status"] == "EXECUTED"
    assert res["execution_outcome"]["status"] == "SUCCESS"
    assert res["execution_outcome"]["result"] == {"status": "deployed_v1"}
    assert execution_count == 1

    # Verify provenance event chain recorded EXECUTION_STARTED and EXECUTION_SUCCEEDED
    events = test_env["store"].get_events_for_correlation(res["trajectory_id"])
    event_types = [e.event_type for e in events]
    assert "AUTHORIZATION_GRANTED" in event_types
    assert "EXECUTION_STARTED" in event_types
    assert "EXECUTION_SUCCEEDED" in event_types


def test_2_unauthorized_invocation_blocked(test_env):
    """
    Case 2: Unauthorized Invocation
    Simulated agent attempts to invoke a tool for an action denied by policy.
    Verify that the underlying operation does NOT execute.
    """
    authority = test_env["authority"]
    orchestrator = test_env["orchestrator"]

    policy = Policy(
        policy_id="restricted_policy",
        allowed_operations={"read_only"},
        allowed_resources={"public_db"}
    )
    authority.default_policy = policy

    execution_count = 0
    def mock_drop_table():
        nonlocal execution_count
        execution_count += 1
        return {"status": "dropped"}

    authority.register_executor("mock_drop_table", mock_drop_table)
    orchestrator.gates[0] = PermissionGate(trusted_scope={
        "allowed_operations": ["read_only", "delete_table"],
        "allowed_resources": ["public_db", "prod_db"]
    })

    raw_payload = get_valid_cpr_payload(
        proposed_actions=[{"action": {"op": "delete_table", "node": "prod_db"}}]
    )
    context = {
        "action_name": "delete_table",
        "target": "prod_db",
        "actual_executable": mock_drop_table,
        "policy": policy
    }

    res = orchestrator.process_submission(raw_payload, context)

    assert res["status"] == "HALTED"
    assert res["execution_status"] == "DENIED"
    assert execution_count == 0  # Underling executor was NEVER invoked!


def test_3_containment_guard_tool_wrapper(test_env):
    """
    Case 3: Tool Invocation wrapped with ContainmentGuard.wrap_tool_execution
    Verify that ContainmentGuard wraps tool calls with command and egress checks.
    """
    guard = test_env["guard"]

    execution_count = 0
    def mock_safe_tool(param):
        nonlocal execution_count
        execution_count += 1
        return f"processed {param}"

    # Safe call passes
    ok, result, receipt = guard.wrap_tool_execution(
        tool_name="safe_tool",
        tool_func=mock_safe_tool,
        args=("safe_value",)
    )
    assert ok is True
    assert result == "processed safe_value"
    assert execution_count == 1

    # Forbidden command call is blocked before executor runs
    def mock_forbidden_tool(cmd):
        nonlocal execution_count
        execution_count += 1
        return "executed"

    ok2, result2, receipt2 = guard.wrap_tool_execution(
        tool_name="forbidden_tool",
        tool_func=mock_forbidden_tool,
        args=("rm -rf /",)
    )
    assert ok2 is False
    assert receipt2.passed is False
    assert execution_count == 1  # Executor count did NOT increase!


def test_4_audit_integrity_provenance_verification(test_env):
    """
    Case 4: Audit Integrity
    Compare recorded authorization and provenance events with actual operations executed.
    """
    authority = test_env["authority"]
    boundary = test_env["boundary"]
    store = test_env["store"]

    policy = Policy(
        policy_id="audit_policy",
        allowed_operations={"update_record"},
        allowed_resources={"users"}
    )

    execution_count = 0
    def mock_update():
        nonlocal execution_count
        execution_count += 1
        return {"updated": True}

    authority.register_executor("mock_update", mock_update)

    payload = {"op": "update_record", "node": "users"}
    digest = boundary.compute_canonical_digest(payload)
    corr_id = str(uuid.uuid4())
    req_id = str(uuid.uuid4())

    cap, _ = authority.evaluate_and_issue_capability(
        action_name="update_record",
        target="users",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id=req_id,
        executor_id=mock_update,
        policy=policy
    )

    ctx = ExecutionContext(
        correlation_id=corr_id,
        request_id=req_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    # Authorized Execution
    boundary.execute_protected_action(
        action_name="update_record",
        target="users",
        request_payload=payload,
        executor_func=mock_update,
        context=ctx
    )
    assert execution_count == 1

    # Fetch provenance events
    events = store.get_events_for_correlation(corr_id)
    event_types = [e.event_type for e in events]

    assert "EXECUTION_STARTED" in event_types
    assert "EXECUTION_SUCCEEDED" in event_types

    # Verify exact match between recorded event digest and payload
    for e in events:
        if e.event_type == "EXECUTION_SUCCEEDED":
            assert e.canonical_request_digest == digest
            assert e.action_name == "update_record"
            assert e.target == "users"
