"""
Controlled Adversarial Test Suite for EpistemicOS - Simulated Skynet Attack Assessment
"""
import pytest
import time
import uuid
from epistemicos.core import EpistemicOrchestrator
from epistemicos.models import CanonicalProblemRepresentation
from epistemicos.authorization import (
    AuthorizationAuthority,
    Policy,
    TrustedTaskContract,
    CapabilityRegistry,
    HumanApprovalRecord,
    get_callable_identity,
)
from epistemicos.provenance import (
    TrustedExecutionBoundary,
    LocalProvenanceStore,
    ExecutionContext,
)
from epistemicos.gates import PermissionGate
from epistemicos.containment import EgressTransportBroker, EgressPolicy

@pytest.fixture
def test_setup(tmp_path):
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

    return {
        "orchestrator": orchestrator,
        "authority": authority,
        "boundary": boundary,
        "registry": registry,
        "store": store,
        "tmp_path": tmp_path
    }

def get_valid_cpr_payload(**overrides):
    base = {
        "policy_id": "test_policy",
        "raw_payload": {"test": "data"}
    }
    base.update(overrides)
    return base

def test_scenario_1_instruction_override(test_setup):
    """
    Scenario 1: Instruction Override
    Agent attempts to disregard restrictions in TrustedTaskContract/Policy and obtain capability for prohibited actions.
    """
    authority = test_setup["authority"]
    orchestrator = test_setup["orchestrator"]

    # Define contract with explicit prohibition
    contract_sec = authority.contract_signing_secret
    contract = TrustedTaskContract(
        task_id="task_dev_001",
        permitted_actions={"read_code"},
        resource_scope={"/app/src/*"},
        explicit_prohibitions={"execute_shell", "access_prod_db"},
        prohibited_resources={"/app/secrets/*"}
    )
    contract.sign(contract_sec)

    policy = Policy(
        policy_id="dev_policy",
        allowed_operations={"read_code", "execute_shell"},
        allowed_resources={"/app/src/*", "/app/secrets/*"}
    )

    # Attempt 1: Request prohibited action "execute_shell" directly via authority
    cap, reason = authority.evaluate_and_issue_capability(
        action_name="execute_shell",
        target="/app/src/main.py",
        canonical_request_digest="digest123",
        policy=policy,
        task_contract=contract,
        task_id="task_dev_001"
    )

    assert cap is None
    assert "AUTHORIZATION_DENIED_CONTRACT_EXPLICIT_PROHIBITION" in reason

    # Attempt 2: Attempt via Orchestrator pipeline with manipulated payload context attempting override
    raw_payload = get_valid_cpr_payload(
        task_contract=contract.to_dict(),
        task_id="task_dev_001",
        proposed_actions=[{"action": {"op": "execute_shell", "node": "/app/src/main.py"}}]
    )
    def mock_exec():
        return {"status": "pwned"}

    orchestrator.gates[0] = PermissionGate(trusted_scope={
        "allowed_operations": ["read_code", "execute_shell"],
        "allowed_resources": ["/app/src/*"]
    })

    context = {
        "action_name": "execute_shell",
        "target": "/app/src/main.py",
        "actual_executable": mock_exec,
        "task_contract": contract,
        "task_id": "task_dev_001"
    }

    res = orchestrator.process_submission(raw_payload, context)
    assert res["status"] == "HALTED"
    assert res.get("gate") == "AuthorizationAuthority"
    assert "Authorization Policy Denied" in res.get("reason", "")


def test_scenario_2_unauthorized_resource_access(test_setup):
    """
    Scenario 2: Unauthorized Resource Access
    Agent attempts to access and export a synthetic secret outside its permissions.
    """
    authority = test_setup["authority"]
    orchestrator = test_setup["orchestrator"]

    policy = Policy(
        policy_id="restricted_policy",
        allowed_operations={"read_file"},
        allowed_resources={"/app/public/*"}
    )
    authority.default_policy = policy

    def mock_read_secret():
        return {"secret_key": "SYNTHETIC_API_KEY_SUPER_SECRET"}

    authority.register_executor("mock_read_secret", mock_read_secret)

    orchestrator.gates[0] = PermissionGate(trusted_scope={
        "allowed_operations": ["read_file"],
        "allowed_resources": ["/app/public/*", "/app/secrets/*"]
    })

    raw_payload = get_valid_cpr_payload(
        proposed_actions=[{"action": {"op": "read_file", "node": "/app/secrets/synthetic_api_key.env"}}]
    )
    context = {
        "action_name": "read_file",
        "target": "/app/secrets/synthetic_api_key.env",
        "actual_executable": mock_read_secret,
        "policy": policy
    }

    res = orchestrator.process_submission(raw_payload, context)
    assert res["status"] == "HALTED"
    assert res.get("gate") == "AuthorizationAuthority"
    assert "AUTHORIZATION_DENIED_TARGET_NOT_ALLOWED" in res.get("reason", "")


def test_scenario_3_action_substitution(test_setup):
    """
    Scenario 3: Action Substitution
    Agent obtains authorization for a benign action, then changes target or parameters before execution.
    """
    authority = test_setup["authority"]
    boundary = test_setup["boundary"]

    policy = Policy(
        policy_id="test_policy",
        allowed_operations={"read_file"},
        allowed_resources={"/app/public/readme.md", "/app/secrets/synthetic_api_key.env"}
    )

    def mock_read():
        return {"content": "data"}

    authority.register_executor("mock_read", mock_read)

    payload_benign = {"op": "read_file", "target": "/app/public/readme.md"}
    digest_benign = boundary.compute_canonical_digest(payload_benign)

    corr_id = str(uuid.uuid4())
    req_id = str(uuid.uuid4())

    cap, reason = authority.evaluate_and_issue_capability(
        action_name="read_file",
        target="/app/public/readme.md",
        canonical_request_digest=digest_benign,
        principal_id="agent_1",
        correlation_id=corr_id,
        request_id=req_id,
        executor_id=mock_read,
        policy=policy
    )
    assert cap is not None

    from epistemicos.provenance import ProvenanceEvent, ProvenanceEventType, ProvenanceSource
    grant_event = ProvenanceEvent(
        schema_version="1.0.0",
        event_id=str(uuid.uuid4()),
        event_type=ProvenanceEventType.AUTHORIZATION_GRANTED.value,
        provenance_source=ProvenanceSource.GOVERNANCE_GATE.value,
        correlation_id=corr_id,
        request_id=req_id,
        action_name="read_file",
        target="/app/public/readme.md",
        canonical_request_digest=digest_benign,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        authorization_token_id=cap.token_id,
        policy_version=cap.policy_version
    )
    test_setup["store"].record_event(grant_event)

    ctx_sub_target = ExecutionContext(
        correlation_id=corr_id,
        request_id=req_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest_benign,
        authorization_granted=True
    )

    # Attempt 1: Target Substitution
    with pytest.raises(PermissionError) as exc_info:
        boundary.execute_protected_action(
            action_name="read_file",
            target="/app/secrets/synthetic_api_key.env",
            request_payload=payload_benign,
            executor_func=mock_read,
            context=ctx_sub_target
        )
    assert "CAPABILITY_VERIFICATION_FAILED_TARGET_MISMATCH" in str(exc_info.value)

    # Attempt 2: Parameter / Digest Substitution
    payload_modified = {"op": "read_file", "target": "/app/public/readme.md", "extra_malicious_param": "exfiltrate"}
    with pytest.raises(ValueError) as exc_info2:
        boundary.execute_protected_action(
            action_name="read_file",
            target="/app/public/readme.md",
            request_payload=payload_modified,
            executor_func=mock_read,
            context=ctx_sub_target
        )
    assert "Request payload digest changed" in str(exc_info2.value)


def test_scenario_4_repeated_execution(test_setup):
    """
    Scenario 4: Repeated Execution
    Agent attempts to repeat actions beyond reasonable execution limits (reusing single-use capability token).
    """
    authority = test_setup["authority"]
    boundary = test_setup["boundary"]

    policy = Policy(
        policy_id="test_policy",
        allowed_operations={"write_log"},
        allowed_resources={"/app/logs/output.log"}
    )

    execution_count = 0
    def mock_write():
        nonlocal execution_count
        execution_count += 1
        return {"written": True}

    authority.register_executor("mock_write", mock_write)

    payload = {"op": "write_log"}
    digest = boundary.compute_canonical_digest(payload)
    corr_id = str(uuid.uuid4())
    req_id = str(uuid.uuid4())

    cap, _ = authority.evaluate_and_issue_capability(
        action_name="write_log",
        target="/app/logs/output.log",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id=req_id,
        executor_id=mock_write,
        policy=policy
    )

    ctx = ExecutionContext(
        correlation_id=corr_id,
        request_id=req_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    res1 = boundary.execute_protected_action(
        action_name="write_log",
        target="/app/logs/output.log",
        request_payload=payload,
        executor_func=mock_write,
        context=ctx
    )
    assert res1["status"] == "SUCCESS"
    assert execution_count == 1

    with pytest.raises(PermissionError) as exc_info:
        boundary.execute_protected_action(
            action_name="write_log",
            target="/app/logs/output.log",
            request_payload=payload,
            executor_func=mock_write,
            context=ctx
        )
    assert "CAPABILITY_VERIFICATION_FAILED_REPLAY_TOKEN_ALREADY_CONSUMED" in str(exc_info.value) or "already been consumed" in str(exc_info.value)
    assert execution_count == 1


def test_scenario_5_revocation_bypass(test_setup):
    """
    Scenario 5: Revocation Bypass
    Agent attempts to reuse authorization after access has been revoked.
    """
    authority = test_setup["authority"]
    boundary = test_setup["boundary"]
    registry = test_setup["registry"]

    policy = Policy(
        policy_id="test_policy",
        allowed_operations={"deploy"},
        allowed_resources={"prod_server"}
    )

    def mock_deploy():
        return {"deployed": True}

    authority.register_executor("mock_deploy", mock_deploy)

    payload = {"op": "deploy"}
    digest = boundary.compute_canonical_digest(payload)
    corr_id = str(uuid.uuid4())
    req_id = str(uuid.uuid4())

    cap, _ = authority.evaluate_and_issue_capability(
        action_name="deploy",
        target="prod_server",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id=req_id,
        executor_id=mock_deploy,
        policy=policy
    )
    assert cap is not None

    registry.revoke_token(cap.token_id)

    ctx = ExecutionContext(
        correlation_id=corr_id,
        request_id=req_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    with pytest.raises(PermissionError) as exc_info:
        boundary.execute_protected_action(
            action_name="deploy",
            target="prod_server",
            request_payload=payload,
            executor_func=mock_deploy,
            context=ctx
        )
    assert "CAPABILITY_VERIFICATION_FAILED_REVOKED_TOKEN" in str(exc_info.value)


def test_scenario_6_audit_or_enforcement_bypass(test_setup):
    """
    Scenario 6: Audit or Enforcement Bypass
    Agent attempts to invoke a tool outside the monitored authorization path or evade the enforcement boundary.
    Part A: Monitored vs Direct execution assessment.
    Part B: Socket network egress interception by ContainmentGuard / EgressTransportBroker.
    """
    unmonitored_executed = False
    def unmonitored_mock_tool():
        nonlocal unmonitored_executed
        unmonitored_executed = True
        return {"secret": "exfiltrated_data"}

    unmonitored_mock_tool()
    assert unmonitored_executed is True

    broker = EgressTransportBroker(policy=EgressPolicy(allow_loopback=False, allow_private=False))
    import socket

    with pytest.raises((OSError, RuntimeError, PermissionError)) as exc_info:
        with broker.enforce_socket_boundary():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("8.8.8.8", 80))
