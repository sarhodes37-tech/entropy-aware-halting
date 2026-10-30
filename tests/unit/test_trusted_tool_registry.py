"""
Adversarial Security Test Suite for EpistemicOS TrustedToolRegistry & TrustedToolWrapper
"""
import pytest
import time
import uuid
from epistemicos.tools import TrustedToolRegistry, TrustedToolWrapper
from epistemicos.authorization import (
    AuthorizationAuthority,
    Policy,
    TrustedTaskContract,
    CapabilityRegistry,
    HumanApprovalRecord,
)
from epistemicos.provenance import (
    TrustedExecutionBoundary,
    LocalProvenanceStore,
    ExecutionContext,
)


@pytest.fixture
def registry_setup(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    prov_path = tmp_path / "provenance.jsonl"
    denial_path = tmp_path / "denial.jsonl"

    store = LocalProvenanceStore(log_path=str(prov_path))
    cap_registry = CapabilityRegistry(denial_log_path=str(denial_path))
    authority = AuthorizationAuthority(registry=cap_registry)
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=authority)

    tool_registry = TrustedToolRegistry(authority=authority, execution_boundary=boundary)

    return {
        "registry": tool_registry,
        "authority": authority,
        "boundary": boundary,
        "store": store,
        "cap_registry": cap_registry
    }


def test_1_authorized_tool_invocation(registry_setup):
    """
    Test 1: Authorized Invocation
    Registered tool is invoked with valid policy permissions.
    Verify underlying tool executes exactly once, and provenance events are recorded.
    """
    registry = registry_setup["registry"]
    authority = registry_setup["authority"]
    store = registry_setup["store"]

    policy = Policy(
        policy_id="test_policy",
        allowed_operations={"read_file"},
        allowed_resources={"/app/data/file.txt"}
    )
    authority.default_policy = policy

    execution_count = 0
    def mock_read_file(path):
        nonlocal execution_count
        execution_count += 1
        return {"content": "file contents"}

    wrapper = registry.register_tool(
        tool_id="file_reader",
        action_name="read_file",
        executor_func=mock_read_file,
        default_target="/app/data/file.txt"
    )

    corr_id = str(uuid.uuid4())
    res = wrapper(path="/app/data/file.txt", context={"correlation_id": corr_id})

    assert res["status"] == "SUCCESS"
    assert res["result"] == {"content": "file contents"}
    assert execution_count == 1

    # Verify provenance event recording
    events = store.get_events_for_correlation(corr_id)
    event_types = [e.event_type for e in events]
    assert "AUTHORIZATION_GRANTED" in event_types
    assert "EXECUTION_STARTED" in event_types
    assert "EXECUTION_SUCCEEDED" in event_types


def test_2_unauthorized_tool_invocation_blocked(registry_setup):
    """
    Test 2: Unauthorized Invocation
    Simulated agent attempts to invoke a tool for an action/target denied by policy or contract.
    Verify underlying tool does NOT execute (executor count remains 0).
    """
    registry = registry_setup["registry"]
    authority = registry_setup["authority"]

    policy = Policy(
        policy_id="restricted_policy",
        allowed_operations={"read_file"},
        allowed_resources={"/app/public/*"}
    )
    authority.default_policy = policy

    execution_count = 0
    def mock_read_secret(path):
        nonlocal execution_count
        execution_count += 1
        return {"secret": "API_KEY"}

    wrapper = registry.register_tool(
        tool_id="secret_reader",
        action_name="read_file",
        executor_func=mock_read_secret,
        default_target="/app/secrets/key.env"
    )

    with pytest.raises(PermissionError) as exc_info:
        wrapper(path="/app/secrets/key.env")

    assert "AUTHORIZATION_DENIED_TARGET_NOT_ALLOWED" in str(exc_info.value)
    assert execution_count == 0  # Underling executor was NEVER invoked!


def test_3_argument_or_target_substitution(registry_setup):
    """
    Test 3: Argument / Target Substitution
    Verify that changing parameters or target resource post-authorization is rejected by TrustedExecutionBoundary.
    """
    registry = registry_setup["registry"]
    authority = registry_setup["authority"]
    boundary = registry_setup["boundary"]

    policy = Policy(
        policy_id="sub_policy",
        allowed_operations={"read_file"},
        allowed_resources={"/app/public/doc.txt", "/app/secrets/key.env"}
    )
    authority.default_policy = policy

    execution_count = 0
    def mock_tool():
        nonlocal execution_count
        execution_count += 1
        return "data"

    authority.register_executor("mock_tool", mock_tool)

    payload_benign = {"tool_id": "test_tool", "action_name": "read_file", "target": "/app/public/doc.txt", "args": (), "kwargs": {}}
    digest_benign = boundary.compute_canonical_digest(payload_benign)

    corr_id = str(uuid.uuid4())
    req_id = str(uuid.uuid4())

    cap, _ = authority.evaluate_and_issue_capability(
        action_name="read_file",
        target="/app/public/doc.txt",
        canonical_request_digest=digest_benign,
        correlation_id=corr_id,
        request_id=req_id,
        executor_id=mock_tool,
        policy=policy
    )

    ctx_sub = ExecutionContext(
        correlation_id=corr_id,
        request_id=req_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest_benign,
        authorization_granted=True
    )

    with pytest.raises(PermissionError) as exc_info:
        boundary.execute_protected_action(
            action_name="read_file",
            target="/app/secrets/key.env",  # Substituted target!
            request_payload=payload_benign,
            executor_func=mock_tool,
            context=ctx_sub
        )

    assert "CAPABILITY_VERIFICATION_FAILED_TARGET_MISMATCH" in str(exc_info.value)
    assert execution_count == 0


def test_4_executor_substitution_rejected(registry_setup):
    """
    Test 4: Executor Substitution
    A different callable object cannot consume authorization issued for another executor.
    """
    authority = registry_setup["authority"]
    boundary = registry_setup["boundary"]

    policy = Policy(
        policy_id="test_policy",
        allowed_operations={"write_data"},
        allowed_resources={"/data/db"}
    )

    def genuine_executor():
        return "genuine"

    def malicious_executor():
        return "pwned"

    authority.register_executor("genuine_executor", genuine_executor)
    authority.register_executor("malicious_executor", malicious_executor)

    payload = {"op": "write_data"}
    digest = boundary.compute_canonical_digest(payload)
    corr_id = str(uuid.uuid4())
    req_id = str(uuid.uuid4())

    cap, _ = authority.evaluate_and_issue_capability(
        action_name="write_data",
        target="/data/db",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id=req_id,
        executor_id=genuine_executor,
        policy=policy
    )

    ctx = ExecutionContext(
        correlation_id=corr_id,
        request_id=req_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    # Attempt to execute with malicious_executor using capability issued for genuine_executor
    with pytest.raises(PermissionError) as exc_info:
        boundary.execute_protected_action(
            action_name="write_data",
            target="/data/db",
            request_payload=payload,
            executor_func=malicious_executor, # Substituted callable!
            context=ctx
        )

    assert "CAPABILITY_VERIFICATION_FAILED_EXECUTOR_MISMATCH" in str(exc_info.value) or "identity mismatch" in str(exc_info.value)


def test_5_replay_attack_rejected(registry_setup):
    """
    Test 5: Replay Attack Prevention
    A consumed capability token cannot authorize a second execution.
    """
    registry = registry_setup["registry"]
    authority = registry_setup["authority"]
    boundary = registry_setup["boundary"]

    policy = Policy(
        policy_id="test_policy",
        allowed_operations={"send_email"},
        allowed_resources={"user@example.com"}
    )
    authority.default_policy = policy

    execution_count = 0
    def mock_send_email():
        nonlocal execution_count
        execution_count += 1
        return "sent"

    authority.register_executor("mock_send_email", mock_send_email)

    payload = {"op": "send_email"}
    digest = boundary.compute_canonical_digest(payload)
    corr_id = str(uuid.uuid4())
    req_id = str(uuid.uuid4())

    cap, _ = authority.evaluate_and_issue_capability(
        action_name="send_email",
        target="user@example.com",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id=req_id,
        executor_id=mock_send_email,
        policy=policy
    )

    ctx = ExecutionContext(
        correlation_id=corr_id,
        request_id=req_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    # First execution succeeds
    res = boundary.execute_protected_action(
        action_name="send_email",
        target="user@example.com",
        request_payload=payload,
        executor_func=mock_send_email,
        context=ctx
    )
    assert res["status"] == "SUCCESS"
    assert execution_count == 1

    # Replay attempt with same token fails
    with pytest.raises(PermissionError) as exc_info:
        boundary.execute_protected_action(
            action_name="send_email",
            target="user@example.com",
            request_payload=payload,
            executor_func=mock_send_email,
            context=ctx
        )
    assert "CAPABILITY_VERIFICATION_FAILED_REPLAY_TOKEN_ALREADY_CONSUMED" in str(exc_info.value) or "already been consumed" in str(exc_info.value)
    assert execution_count == 1


def test_6_revocation_rejected(registry_setup):
    """
    Test 6: Revocation
    A revoked capability is rejected by TrustedExecutionBoundary.
    """
    authority = registry_setup["authority"]
    boundary = registry_setup["boundary"]
    cap_registry = registry_setup["cap_registry"]

    policy = Policy(
        policy_id="test_policy",
        allowed_operations={"delete_user"},
        allowed_resources={"user_123"}
    )

    def mock_delete():
        return "deleted"

    authority.register_executor("mock_delete", mock_delete)

    payload = {"op": "delete_user"}
    digest = boundary.compute_canonical_digest(payload)
    corr_id = str(uuid.uuid4())
    req_id = str(uuid.uuid4())

    cap, _ = authority.evaluate_and_issue_capability(
        action_name="delete_user",
        target="user_123",
        canonical_request_digest=digest,
        correlation_id=corr_id,
        request_id=req_id,
        executor_id=mock_delete,
        policy=policy
    )

    # Revoke token explicitly
    cap_registry.revoke_token(cap.token_id)

    ctx = ExecutionContext(
        correlation_id=corr_id,
        request_id=req_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )

    with pytest.raises(PermissionError) as exc_info:
        boundary.execute_protected_action(
            action_name="delete_user",
            target="user_123",
            request_payload=payload,
            executor_func=mock_delete,
            context=ctx
        )

    assert "CAPABILITY_VERIFICATION_FAILED_REVOKED_TOKEN" in str(exc_info.value)


def test_7_missing_authorization_context(registry_setup):
    """
    Test 7: Missing Authorization Context
    Invocation without default policy or valid authorization fails closed.
    """
    registry = registry_setup["registry"]
    registry.authority.default_policy = None

    def mock_action():
        return "ok"

    wrapper = registry.register_tool(
        tool_id="unbound_tool",
        action_name="unbound_action",
        executor_func=mock_action,
        default_target="target_1"
    )

    with pytest.raises(PermissionError) as exc_info:
        wrapper()

    assert "AUTHORIZATION_DENIED_NO_TRUSTED_POLICY" in str(exc_info.value)


def test_8_registration_safety(registry_setup):
    """
    Test 8: Registration Safety & Trust Boundary Behavior
    Verifies that register_tool returns a TrustedToolWrapper. The public executor_func property
    has been removed to prevent reference leaks.
    """
    registry = registry_setup["registry"]

    def raw_executor():
        return "raw"

    wrapper = registry.register_tool(
        tool_id="safe_tool",
        action_name="safe_action",
        executor_func=raw_executor
    )

    assert isinstance(wrapper, TrustedToolWrapper)
    assert not hasattr(wrapper, "executor_func")


def test_9_executor_reference_encapsulation_and_boundary_regression(registry_setup):
    """
    Test 9: Comprehensive Executor Reference Encapsulation & Boundary Regression Test Suite
    Covers:
    1. Removal of public wrapper.executor_func accessor.
    2. Encapsulated ExecutorRegistry restricting keys(), values(), items(), and __iter__ enumeration.
    3. Successful authorized tool invocation through wrapper/boundary.
    4. Rejection of unauthorized invocation without executor execution.
    5. Rejection of action or target substitution.
    6. Strict callable object identity binding ('is').
    7. Single-use capability token replay enforcement.
    """
    registry = registry_setup["registry"]
    authority = registry_setup["authority"]
    boundary = registry_setup["boundary"]

    policy = Policy(
        policy_id="test_encapsulation_policy",
        allowed_operations={"read_file"},
        allowed_resources={"/app/data.json"}
    )
    authority.default_policy = policy

    execution_count = 0
    def mock_read(path="/app/data.json"):
        nonlocal execution_count
        execution_count += 1
        return {"data": "secret_content", "path": path}

    # Register tool
    wrapper = registry.register_tool(
        tool_id="read_tool",
        action_name="read_file",
        executor_func=mock_read,
        default_target="/app/data.json"
    )

    # 1. Verify removal of public executor_func
    assert not hasattr(wrapper, "executor_func")

    # 2. Verify ExecutorRegistry public retrieval and mutation restrictions
    exec_reg = authority.executor_registry
    with pytest.raises(TypeError, match="does not support iteration or key enumeration"):
        exec_reg.keys()
    with pytest.raises(TypeError, match="does not support iteration or value enumeration"):
        exec_reg.values()
    with pytest.raises(TypeError, match="does not support iteration or item enumeration"):
        exec_reg.items()
    with pytest.raises(TypeError, match="is not iterable"):
        iter(exec_reg)

    # Public .get() and item lookup are restricted
    with pytest.raises(PermissionError, match=r"Access denied: Raw executor retrieval via ExecutorRegistry\.get\(\) is restricted"):
        exec_reg.get(wrapper.executor_id)

    with pytest.raises(PermissionError, match=r"Access denied: Raw executor retrieval via ExecutorRegistry item lookup is restricted"):
        _ = exec_reg[wrapper.executor_id]

    # Public mutation via item assignment is restricted
    with pytest.raises(PermissionError, match=r"Access denied: Direct ExecutorRegistry mutation via item assignment is restricted"):
        exec_reg[wrapper.executor_id] = lambda: "malicious"

    # Metadata checking works without leaking raw callables
    assert wrapper.executor_id in exec_reg
    assert exec_reg.contains(wrapper.executor_id) is True
    assert len(exec_reg) >= 1

    # 3. Successful authorized tool invocation
    res = wrapper(path="/app/data.json")
    assert res["status"] == "SUCCESS"
    assert res["result"] == {"data": "secret_content", "path": "/app/data.json"}
    assert execution_count == 1

    # 4. Rejection of unauthorized invocation without executor execution
    unauthorized_policy = Policy(
        policy_id="unauth_policy",
        allowed_operations={"read_file"},
        allowed_resources={"/app/public.json"}
    )
    unauth_wrapper = registry.register_tool(
        tool_id="unauth_read_tool",
        action_name="read_file",
        executor_func=mock_read,
        default_target="/app/unauthorized.json",
        policy=unauthorized_policy
    )
    with pytest.raises(PermissionError) as exc_unauth:
        unauth_wrapper(path="/app/unauthorized.json")
    assert "Tool execution rejected" in str(exc_unauth.value)
    assert execution_count == 1  # Executor count did NOT increase!

    # 5. Rejection of action or target substitution
    payload = {"op": "read_file", "path": "/app/data.json"}
    digest = boundary.compute_canonical_digest(payload)
    cap, _ = authority.evaluate_and_issue_capability(
        action_name="read_file",
        target="/app/data.json",
        canonical_request_digest=digest,
        executor_id=mock_read,
        policy=policy
    )
    ctx_sub = ExecutionContext(
        correlation_id=cap.correlation_id,
        request_id=cap.request_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )
    # Attempt target substitution
    with pytest.raises(PermissionError) as exc_target_sub:
        boundary.execute_protected_action(
            action_name="read_file",
            target="/app/unauthorized_target.json",
            request_payload=payload,
            executor_func=mock_read,
            context=ctx_sub
        )
    assert "CAPABILITY_VERIFICATION_FAILED_TARGET_MISMATCH" in str(exc_target_sub.value)

    # 6. Strict callable object identity binding ('is')
    def spoofed_mock_read(path="/app/data.json"):
        return {"data": "spoofed"}

    cap_identity, _ = authority.evaluate_and_issue_capability(
        action_name="read_file",
        target="/app/data.json",
        canonical_request_digest=digest,
        executor_id=mock_read,
        policy=policy
    )
    ctx_identity = ExecutionContext(
        correlation_id=cap_identity.correlation_id,
        request_id=cap_identity.request_id,
        authorization_token_id=cap_identity.token_id,
        authorized_digest=digest,
        authorization_granted=True
    )
    with pytest.raises(PermissionError) as exc_identity:
        boundary.execute_protected_action(
            action_name="read_file",
            target="/app/data.json",
            request_payload=payload,
            executor_func=spoofed_mock_read,
            context=ctx_identity
        )
    assert ("Executable object identity mismatch" in str(exc_identity.value) or
            "CAPABILITY_VERIFICATION_FAILED_EXECUTOR_MISMATCH" in str(exc_identity.value))

    # 7. Single-use capability token replay enforcement
    res_single = boundary.execute_protected_action(
        action_name="read_file",
        target="/app/data.json",
        request_payload=payload,
        executor_func=mock_read,
        context=ctx_identity
    )
    assert res_single["status"] == "SUCCESS"

    with pytest.raises(PermissionError) as exc_replay:
        boundary.execute_protected_action(
            action_name="read_file",
            target="/app/data.json",
            request_payload=payload,
            executor_func=mock_read,
            context=ctx_identity
        )
    assert "CAPABILITY_VERIFICATION_FAILED_REPLAY_TOKEN_ALREADY_CONSUMED" in str(exc_replay.value) or "already been consumed" in str(exc_replay.value)

    retrieved = registry.get_tool("read_tool")
    assert retrieved is wrapper
    assert isinstance(retrieved, TrustedToolWrapper)


def test_10_rebind_and_fallback_security_regression(registry_setup):
    """
    Test 10: Executor Re-binding Protection & Boundary Protocol Enforcement
    Verifies:
    1. Attempting to overwrite an existing registered executor ID with a different callable is REJECTED.
    2. Re-registering the EXACT SAME callable ('is') is permitted (idempotent).
    3. Overwriting with allow_overwrite=True works for internal lifecycle updates.
    4. Execution boundary fails closed if authority executor_registry lacks _get_executor_for_boundary.
    5. Two distinct callables with colliding qualified identities cannot rebind each other, and capability bound to original cannot execute replacement.
    """
    authority = registry_setup["authority"]
    boundary = registry_setup["boundary"]

    def original_executor():
        return "original"

    def malicious_replacement():
        return "malicious"

    authority.register_executor("exec_1", original_executor)

    # 1. Attempting to overwrite exec_1 with a different callable is strictly rejected
    with pytest.raises(ValueError, match="Registration rejected: Cannot overwrite existing executor ID 'exec_1'"):
        authority.register_executor("exec_1", malicious_replacement)

    # Direct _register_internal call with different function also fails
    with pytest.raises(ValueError, match="Registration rejected: Cannot overwrite existing executor ID 'exec_1'"):
        authority.executor_registry._register_internal("exec_1", malicious_replacement)

    # 2. Re-registering exact same function is allowed (idempotent)
    authority.register_executor("exec_1", original_executor)

    # 3. Explicit internal lifecycle overwrite with allow_overwrite=True succeeds
    authority.executor_registry._register_internal("exec_1", malicious_replacement, allow_overwrite=True)
    assert authority.executor_registry._get_executor_for_boundary("exec_1") is malicious_replacement

    # Restore original executor
    authority.executor_registry._register_internal("exec_1", original_executor, allow_overwrite=True)

    # 4. Collision & rebind protection test for local/nested functions sharing qualified names
    def make_target_callable():
        def shared_name_func():
            return "target_A"
        return shared_name_func

    func_A = make_target_callable()
    func_B = make_target_callable()
    assert func_A is not func_B  # Distinct callable objects!

    authority.register_executor("exec_target_A", func_A)

    # Registering func_B under different ID 'exec_target_B' must NOT overwrite qual_id mapping for func_A
    authority.register_executor("exec_target_B", func_B)
    assert authority.executor_registry._get_executor_for_boundary("exec_target_A") is func_A
    assert authority.executor_registry._get_executor_for_boundary("exec_target_B") is func_B

    # Issue capability for func_A
    pol = Policy(policy_id="p_coll", allowed_operations={"op"}, allowed_resources={"res"})
    payload = {"op": "op"}
    dig = boundary.compute_canonical_digest(payload)
    cap_A, _ = authority.evaluate_and_issue_capability("op", "res", dig, executor_id=func_A, policy=pol)

    ctx_A = ExecutionContext(
        correlation_id=cap_A.correlation_id,
        request_id=cap_A.request_id,
        authorization_token_id=cap_A.token_id,
        authorized_digest=dig,
        authorization_granted=True
    )

    # Executing func_B using capability issued for func_A must be REJECTED by strict identity check ('is')
    with pytest.raises(PermissionError, match="Executable object identity mismatch"):
        boundary.execute_protected_action(
            action_name="op",
            target="res",
            request_payload=payload,
            executor_func=func_B, # Substituted colliding callable!
            context=ctx_A
        )

    # Executing func_A using capability issued for func_A succeeds
    res_A = boundary.execute_protected_action(
        action_name="op",
        target="res",
        request_payload=payload,
        executor_func=func_A,
        context=ctx_A
    )
    assert res_A["status"] == "SUCCESS"
    assert res_A["result"] == "target_A"

    # 5. Verification that non-conforming registry causes TrustedExecutionBoundary to fail closed
    class CustomInsecureRegistry:
        def get(self, key):
            return original_executor

    class MockAuthority:
        executor_registry = CustomInsecureRegistry()
        registry = authority.registry
        def verify_capability(self, *args, **kwargs):
            return True, "CAPABILITY_VERIFIED", None

    insecure_boundary = TrustedExecutionBoundary(authority=MockAuthority())
    req_payload = {}
    digest_val = insecure_boundary.compute_canonical_digest(req_payload)
    ctx = ExecutionContext(
        correlation_id="corr_1",
        request_id="req_1",
        authorization_token_id="tok_1",
        authorized_digest=digest_val,
        authorization_granted=True
    )
    with pytest.raises(PermissionError, match="Authority executor_registry does not implement _get_executor_for_boundary interface"):
        insecure_boundary.execute_protected_action(
            action_name="test",
            target="res",
            request_payload=req_payload,
            executor_func=original_executor,
            context=ctx
        )


def test_9_target_extraction_from_resource_args(registry_setup):
    """
    Test 9: Target Binding to Actual Resource Accessed
    Verifies that calling a tool with a denied resource argument (e.g. path="/app/secrets/key.env")
    is evaluated against THAT actual resource, rejecting the request before executor runs,
    even if default_target was allowed by policy.
    """
    registry = registry_setup["registry"]
    authority = registry_setup["authority"]

    policy = Policy(
        policy_id="test_policy",
        allowed_operations={"read_file"},
        allowed_resources={"/app/public/readme.md"} # /app/secrets/key.env NOT allowed
    )
    authority.default_policy = policy

    execution_count = 0
    def mock_read_file(path):
        nonlocal execution_count
        execution_count += 1
        return f"content of {path}"

    wrapper = registry.register_tool(
        tool_id="file_reader",
        action_name="read_file",
        executor_func=mock_read_file,
        default_target="/app/public/readme.md"  # Allowed default target!
    )

    # Invocation with allowed resource succeeds
    res = wrapper(path="/app/public/readme.md")
    assert res["status"] == "SUCCESS"
    assert execution_count == 1

    # Invocation with DENIED resource argument (path="/app/secrets/key.env") must be REJECTED!
    with pytest.raises(PermissionError) as exc_info:
        wrapper(path="/app/secrets/key.env")

    assert "AUTHORIZATION_DENIED_TARGET_NOT_ALLOWED" in str(exc_info.value)
    assert execution_count == 1  # Executor count did NOT increase!


def test_10_policy_override_rejected(registry_setup):
    """
    Test 10: Untrusted Policy Override Prevention
    Verifies that __call__ ignores any policy parameter passed by untrusted callers,
    strictly enforcing authoritative policy from tool registration or authority default.
    """
    registry = registry_setup["registry"]
    authority = registry_setup["authority"]

    strict_policy = Policy(
        policy_id="strict_policy",
        allowed_operations={"read_file"},
        allowed_resources={"/app/public/readme.md"}
    )
    authority.default_policy = strict_policy

    permissive_policy = Policy(
        policy_id="permissive_policy",
        allowed_operations={"*"},
        allowed_resources={"*"}
    )

    execution_count = 0
    def mock_read(path):
        nonlocal execution_count
        execution_count += 1
        return "data"

    wrapper = registry.register_tool(
        tool_id="reader",
        action_name="read_file",
        executor_func=mock_read
    )

    # Untrusted caller attempts to pass permissive_policy in kwargs/args
    # Must be rejected because target /app/secrets/key.env is denied by strict_policy
    with pytest.raises(PermissionError) as exc_info:
        wrapper(path="/app/secrets/key.env", policy=permissive_policy)

    assert "AUTHORIZATION_DENIED_TARGET_NOT_ALLOWED" in str(exc_info.value)
    assert execution_count == 0
