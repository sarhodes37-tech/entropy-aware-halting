"""
Adversarial Regression Test Suite for SEC-01 and SEC-03.

Verifies:
SEC-01 (Principal Binding at Execution Boundary):
- Capability issued to Alice, presented by Bob (Denied, 0 side effects).
- Caller attempts to spoof Alice through a context dictionary (Denied, 0 side effects).
- Missing authenticated principal (Denied, 0 side effects).
- Forged AuthenticatedPrincipal object (Denied, 0 side effects).
- Valid authenticated Alice context (Allowed, 1 side effect).
- Principal identity altered between issuance and execution (Denied, 0 side effects).
- Ordinary caller cannot mint an assertion for another principal (Denied, 0 side effects).
- Caller-provided string cannot satisfy principal authentication at execution boundary (Denied, 0 side effects).
- Assertion from an untrusted issuer is rejected (Denied, 0 side effects).
- Future-dated assertions are rejected (Denied, 0 side effects).

SEC-03 (Explicit Resource Target Binding):
- Benign first positional argument with a sensitive second target (Denied, 0 side effects).
- Target supplied through keyword arguments (Allowed, 1 side effect).
- Missing target (Denied, 0 side effects).
- Conflicting target parameters (Denied, 0 side effects).
- Custom extractor returning an invalid or ambiguous target (Denied, 0 side effects).
- Existing legitimate registered tools (Allowed, 1 side effect).
- Mutating tool without explicit target (Registration or execution rejected, 0 side effects).
- Unknown action classification (Denied, 0 side effects).
- Authorized target differs from executor target across filepath, filename, url, and destination (Denied, 0 side effects).
- Signature binding failure on mutating operation fails closed (Denied, 0 side effects).
"""

import time
import uuid
import pytest
from unittest.mock import MagicMock

from epistemicos.authorization import (
    AuthorizationAuthority,
    Policy,
    Capability,
    PrincipalProvider,
    AuthenticatedPrincipal,
    get_callable_identity
)
from epistemicos.provenance import (
    TrustedExecutionBoundary,
    ExecutionContext,
    LocalProvenanceStore
)
from epistemicos.tools import TrustedToolRegistry, TrustedToolWrapper


# =============================================================================
# SEC-01: Principal Binding at Execution Boundary Tests
# =============================================================================

def test_sec01_alice_capability_presented_by_bob_rejected(tmp_path):
    """
    SEC-01: Capability issued to Alice, presented by Bob.
    Must be rejected with zero executor side effects.
    """
    side_effect_mock = MagicMock()
    def sensitive_executor():
        side_effect_mock()
        return {"status": "executed"}

    store = LocalProvenanceStore(log_path=str(tmp_path / "prov.jsonl"))
    trusted_provider = PrincipalProvider(signing_secret=b"independent_identity_secret_key_123")
    auth = AuthorizationAuthority(
        default_policy=Policy(
            policy_id="alice_bob_policy",
            allowed_operations={"transfer"},
            allowed_resources={"/accounts/alice"},
            allowed_principals={"principal_alice", "principal_bob"}
        ),
        principal_provider=trusted_provider
    )
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=auth)

    alice_principal = trusted_provider.issue_principal("principal_alice")
    bob_principal = trusted_provider.issue_principal("principal_bob")

    raw_payload = {"op": "transfer", "amount": 1000}
    payload_digest = boundary.compute_canonical_digest(raw_payload)

    # Issue capability to Alice
    cap, reason = auth.evaluate_and_issue_capability(
        action_name="transfer",
        target="/accounts/alice",
        canonical_request_digest=payload_digest,
        principal_id=alice_principal,
        executor_id=sensitive_executor
    )
    assert cap is not None
    assert reason == "AUTHORIZATION_GRANTED"
    assert cap.principal_id == "principal_alice"

    # Bob attempts to present Alice's capability in Bob's execution context
    bob_ctx = ExecutionContext(
        correlation_id=cap.correlation_id,
        request_id=cap.request_id,
        authorization_token_id=cap.token_id,
        authorized_digest=payload_digest,
        authorization_granted=True,
        authenticated_principal=bob_principal
    )

    with pytest.raises(PermissionError) as exc_info:
        boundary.execute_protected_action(
            action_name="transfer",
            target="/accounts/alice",
            request_payload=raw_payload,
            executor_func=sensitive_executor,
            context=bob_ctx
        )

    assert "PRINCIPAL_MISMATCH" in str(exc_info.value)
    assert side_effect_mock.call_count == 0


def test_sec01_caller_attempts_to_spoof_alice_through_context_dictionary(tmp_path):
    """
    SEC-01: Caller attempts to spoof Alice through a context dictionary in TrustedToolWrapper.
    Must be rejected before capability issuance or execution with zero side effects.
    """
    side_effect_mock = MagicMock()
    def mutate_account(account_id: str, amount: float):
        side_effect_mock(account_id, amount)
        return {"account_id": account_id, "amount": amount}

    trusted_provider = PrincipalProvider(signing_secret=b"sec01_key_456")
    reg = TrustedToolRegistry()
    reg.authority.principal_provider = trusted_provider
    reg.authority.default_policy = Policy(
        policy_id="alice_only_policy",
        allowed_operations={"mutate"},
        allowed_resources={"/accounts/alice"},
        allowed_principals={"principal_alice"}
    )

    tool = reg.register_tool(
        tool_id="account_mutator",
        action_name="mutate",
        executor_func=mutate_account,
        target_param="account_id"
    )

    # Untrusted caller supplies a plain dictionary claiming principal_id="principal_alice"
    with pytest.raises(PermissionError) as exc_info:
        tool(
            account_id="/accounts/alice",
            amount=500.0,
            context={"principal_id": "principal_alice"}
        )

    assert "Caller-controlled context dictionary cannot assert principal identity" in str(exc_info.value)
    assert side_effect_mock.call_count == 0


def test_sec01_missing_authenticated_principal_rejected(tmp_path):
    """
    SEC-01: Capability bound to a specific principal is presented with missing authenticated principal.
    Must be rejected with zero side effects.
    """
    side_effect_mock = MagicMock()
    def sensitive_task():
        side_effect_mock()
        return "done"

    trusted_provider = PrincipalProvider(signing_secret=b"sec01_provider_key_789")
    auth = AuthorizationAuthority(
        default_policy=Policy(
            policy_id="p1",
            allowed_operations={"task"},
            allowed_resources={"/res1"},
            allowed_principals={"alice"}
        ),
        principal_provider=trusted_provider
    )
    boundary = TrustedExecutionBoundary(authority=auth)

    alice_princ = trusted_provider.issue_principal("alice")
    payload = {"task": "run"}
    digest = boundary.compute_canonical_digest(payload)

    cap, _ = auth.evaluate_and_issue_capability(
        action_name="task",
        target="/res1",
        canonical_request_digest=digest,
        principal_id=alice_princ,
        executor_id=sensitive_task
    )
    assert cap is not None

    # Context without authenticated principal (None)
    ctx_no_principal = ExecutionContext(
        correlation_id=cap.correlation_id,
        request_id=cap.request_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        authenticated_principal=None
    )

    with pytest.raises(PermissionError) as exc_info:
        boundary.execute_protected_action(
            action_name="task",
            target="/res1",
            request_payload=payload,
            executor_func=sensitive_task,
            context=ctx_no_principal
        )

    assert "requires authenticated principal in ExecutionContext" in str(exc_info.value)
    assert side_effect_mock.call_count == 0


def test_sec01_forged_authenticated_principal_object_rejected(tmp_path):
    """
    SEC-01: Forged AuthenticatedPrincipal object (created without valid signature from trusted provider).
    Must be rejected with zero side effects.
    """
    side_effect_mock = MagicMock()
    def admin_op():
        side_effect_mock()
        return "admin_ok"

    trusted_provider = PrincipalProvider(signing_secret=b"sec01_admin_key_abc")
    auth = AuthorizationAuthority(
        default_policy=Policy(
            policy_id="admin_policy",
            allowed_operations={"admin"},
            allowed_resources={"/admin/panel"},
            allowed_principals={"admin_user"}
        ),
        principal_provider=trusted_provider
    )
    boundary = TrustedExecutionBoundary(authority=auth)

    # Attacker crafts an AuthenticatedPrincipal object manually
    forged_principal = AuthenticatedPrincipal(
        principal_id="admin_user",
        issuer_id="TrustedIdentityAuthority",
        timestamp=time.time(),
        signature="forged_invalid_hmac_signature"
    )

    payload = {"op": "admin"}
    digest = boundary.compute_canonical_digest(payload)

    # 1. Issuance rejection
    cap, reason = auth.evaluate_and_issue_capability(
        action_name="admin",
        target="/admin/panel",
        canonical_request_digest=digest,
        principal_id=forged_principal,
        executor_id=admin_op
    )
    assert cap is None
    assert "PRINCIPAL_AUTHENTICATION_FAILED" in reason

    # 2. Execution boundary presentation rejection
    valid_admin_princ = trusted_provider.issue_principal("admin_user")
    valid_cap, _ = auth.evaluate_and_issue_capability(
        action_name="admin",
        target="/admin/panel",
        canonical_request_digest=digest,
        principal_id=valid_admin_princ,
        executor_id=admin_op
    )

    ctx_forged = ExecutionContext(
        correlation_id=valid_cap.correlation_id,
        request_id=valid_cap.request_id,
        authorization_token_id=valid_cap.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        authenticated_principal=forged_principal
    )

    with pytest.raises(PermissionError) as exc_exec:
        boundary.execute_protected_action(
            action_name="admin",
            target="/admin/panel",
            request_payload=payload,
            executor_func=admin_op,
            context=ctx_forged
        )

    assert "PRINCIPAL_AUTHENTICATION_FAILED" in str(exc_exec.value)
    assert side_effect_mock.call_count == 0


def test_sec01_valid_authenticated_alice_context_allowed(tmp_path):
    """
    SEC-01: Valid authenticated Alice context is allowed through TrustedToolWrapper and execution boundary.
    Produces exactly 1 side effect.
    """
    side_effect_mock = MagicMock()
    def transfer_executor(target: str, amount: float):
        side_effect_mock(target, amount)
        return {"target": target, "amount": amount}

    trusted_provider = PrincipalProvider(signing_secret=b"sec01_valid_key_def")
    reg = TrustedToolRegistry()
    reg.authority.principal_provider = trusted_provider
    reg.authority.default_policy = Policy(
        policy_id="p_valid",
        allowed_operations={"transfer"},
        allowed_resources={"/vault/alice"},
        allowed_principals={"alice"}
    )

    tool = reg.register_tool(
        tool_id="vault_transfer",
        action_name="transfer",
        executor_func=transfer_executor,
        target_param="target"
    )

    alice_princ = trusted_provider.issue_principal("alice")

    res = tool(
        target="/vault/alice",
        amount=250.0,
        authenticated_principal=alice_princ
    )

    assert res["status"] == "SUCCESS"
    assert res["result"] == {"target": "/vault/alice", "amount": 250.0}
    assert side_effect_mock.call_count == 1


def test_sec01_principal_identity_altered_between_issuance_and_execution(tmp_path):
    """
    SEC-01: Alice authenticates, capability is issued, and then execution context
    is replaced with Bob's identity before calling execute_protected_action.
    Must be rejected with zero side effects.
    """
    side_effect_mock = MagicMock()
    def privileged_closure():
        side_effect_mock()
        return "privileged_action"

    trusted_provider = PrincipalProvider(signing_secret=b"sec01_altered_key_ghi")
    auth = AuthorizationAuthority(
        default_policy=Policy(
            policy_id="p_mutate",
            allowed_operations={"mutate"},
            allowed_resources={"/secure/record"},
            allowed_principals={"alice", "bob"}
        ),
        principal_provider=trusted_provider
    )
    boundary = TrustedExecutionBoundary(authority=auth)

    alice_princ = trusted_provider.issue_principal("alice")
    bob_princ = trusted_provider.issue_principal("bob")

    payload = {"mutate": True}
    digest = boundary.compute_canonical_digest(payload)

    cap, _ = auth.evaluate_and_issue_capability(
        action_name="mutate",
        target="/secure/record",
        canonical_request_digest=digest,
        principal_id=alice_princ,
        executor_id=privileged_closure
    )
    assert cap is not None
    assert cap.principal_id == "alice"

    # Context replaced with Bob
    tampered_ctx = ExecutionContext(
        correlation_id=cap.correlation_id,
        request_id=cap.request_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        authenticated_principal=bob_princ
    )

    with pytest.raises(PermissionError) as exc_info:
        boundary.execute_protected_action(
            action_name="mutate",
            target="/secure/record",
            request_payload=payload,
            executor_func=privileged_closure,
            context=tampered_ctx
        )

    assert "PRINCIPAL_MISMATCH" in str(exc_info.value)
    assert side_effect_mock.call_count == 0


def test_sec01_ordinary_caller_cannot_mint_assertions():
    """
    SEC-01: AuthorizationAuthority does not expose an identity-minting method
    that lets callers manufacture identities.
    """
    auth = AuthorizationAuthority()
    assert not hasattr(auth, "issue_principal")
    assert not hasattr(auth, "mint_principal")


def test_sec01_caller_provided_string_cannot_satisfy_boundary_authentication(tmp_path):
    """
    SEC-01: A caller-provided string cannot satisfy principal authentication at the execution boundary.
    """
    side_effect_mock = MagicMock()
    def write_task():
        side_effect_mock()
        return "written"

    trusted_provider = PrincipalProvider(signing_secret=b"sec01_str_key_jkl")
    auth = AuthorizationAuthority(
        default_policy=Policy(
            policy_id="p_str",
            allowed_operations={"write"},
            allowed_resources={"/res"},
            allowed_principals={"alice"}
        ),
        principal_provider=trusted_provider
    )
    boundary = TrustedExecutionBoundary(authority=auth)

    alice_princ = trusted_provider.issue_principal("alice")
    payload = {"k": "v"}
    digest = boundary.compute_canonical_digest(payload)

    cap, _ = auth.evaluate_and_issue_capability(
        action_name="write",
        target="/res",
        canonical_request_digest=digest,
        principal_id=alice_princ,
        executor_id=write_task
    )

    # Caller presents plain string "alice" in ExecutionContext
    ctx_string = ExecutionContext(
        correlation_id=cap.correlation_id,
        request_id=cap.request_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        authenticated_principal="alice"  # Plain string!
    )

    with pytest.raises(PermissionError) as exc_info:
        boundary.execute_protected_action(
            action_name="write",
            target="/res",
            request_payload=payload,
            executor_func=write_task,
            context=ctx_string
        )

    assert "Plain string or unverified context cannot satisfy principal authentication" in str(exc_info.value)
    assert side_effect_mock.call_count == 0


def test_sec01_assertion_from_untrusted_issuer_rejected(tmp_path):
    """
    SEC-01: Assertion created by an untrusted identity issuer is rejected.
    """
    trusted_provider = PrincipalProvider(signing_secret=b"trusted_secret", provider_id="TrustedCorpIdP")
    rogue_provider = PrincipalProvider(signing_secret=b"trusted_secret", provider_id="RogueCorpIdP")

    auth = AuthorizationAuthority(
        default_policy=Policy(policy_id="p", allowed_operations={"op"}, allowed_resources={"/res"}, allowed_principals={"alice"}),
        principal_provider=trusted_provider
    )

    # Rogue provider signs for alice
    rogue_alice = rogue_provider.issue_principal("alice")

    cap, reason = auth.evaluate_and_issue_capability(
        action_name="op",
        target="/res",
        canonical_request_digest="d" * 64,
        principal_id=rogue_alice
    )
    assert cap is None
    assert "Untrusted identity issuer" in reason


def test_sec01_future_dated_assertion_rejected(tmp_path):
    """
    SEC-01: An assertion timestamped in the future is rejected.
    """
    provider = PrincipalProvider(signing_secret=b"sec01_future_key")
    auth = AuthorizationAuthority(
        default_policy=Policy(policy_id="p", allowed_operations={"op"}, allowed_resources={"/res"}, allowed_principals={"alice"}),
        principal_provider=provider
    )

    # Issue assertion timestamped 1 hour in the future
    future_time = time.time() + 3600.0
    future_alice = provider.issue_principal("alice", current_time=future_time)

    cap, reason = auth.evaluate_and_issue_capability(
        action_name="op",
        target="/res",
        canonical_request_digest="d" * 64,
        principal_id=future_alice
    )
    assert cap is None
    assert "Future-dated principal assertion rejected" in reason


# =============================================================================
# SEC-03: Explicit Resource Target Binding Tests
# =============================================================================

def test_sec03_benign_first_positional_argument_with_sensitive_target_rejected(tmp_path):
    """
    SEC-03: Benign first positional argument with sensitive second target on mutating operation.
    Must be rejected; ambiguous positional extraction is disallowed for mutating operations.
    """
    side_effect_mock = MagicMock()
    def write_db(audit_note: str, destination_table: str, data: dict):
        side_effect_mock(destination_table)
        return "mutated"

    reg = TrustedToolRegistry()
    reg.authority.default_policy = Policy(
        policy_id="test_policy",
        allowed_operations={"*"},
        allowed_resources={"audit_note_harmless"}
    )

    # Mutating tool registered without target_param
    tool = reg.register_tool(
        tool_id="db_writer",
        action_name="delete_db",  # DESTRUCTIVE_COMMAND (mutating)
        executor_func=write_db
    )

    with pytest.raises(PermissionError) as exc_info:
        tool("audit_note_harmless", "critical_db", {"drop": True})

    assert "requires explicit target parameter ('target_param' or 'target_extractor')" in str(exc_info.value)
    assert side_effect_mock.call_count == 0


def test_sec03_target_supplied_through_keyword_argument_allowed(tmp_path):
    """
    SEC-03: Target supplied through explicit keyword arguments is correctly extracted and allowed.
    """
    side_effect_mock = MagicMock()
    def update_table(table_name: str, row_id: int):
        side_effect_mock(table_name, row_id)
        return {"updated": table_name, "row": row_id}

    reg = TrustedToolRegistry()
    reg.authority.default_policy = Policy(
        policy_id="kw_policy",
        allowed_operations={"update_db"},
        allowed_resources={"users_table"}
    )

    tool = reg.register_tool(
        tool_id="table_updater",
        action_name="update_db",
        executor_func=update_table,
        target_param="table_name"
    )

    res = tool(table_name="users_table", row_id=42)
    assert res["status"] == "SUCCESS"
    assert side_effect_mock.call_count == 1


def test_sec03_missing_target_rejected(tmp_path):
    """
    SEC-03: Mutating tool invoked with missing target.
    Must fail closed before executor invocation.
    """
    side_effect_mock = MagicMock()
    def mutate_op():
        side_effect_mock()
        return "ok"

    reg = TrustedToolRegistry()
    reg.authority.default_policy = Policy(
        policy_id="p_default",
        allowed_operations={"*"},
        allowed_resources={"*"}
    )

    tool = reg.register_tool(
        tool_id="empty_mutator",
        action_name="financial_state_mutation",
        executor_func=mutate_op
    )

    with pytest.raises(PermissionError) as exc_info:
        tool()

    assert ("Unable to determine actual resource target" in str(exc_info.value) or
            "requires explicit target parameter" in str(exc_info.value))
    assert side_effect_mock.call_count == 0


def test_sec03_conflicting_target_parameters_rejected(tmp_path):
    """
    SEC-03: Invocation providing conflicting target values across parameter sources.
    Must be rejected with zero side effects.
    """
    side_effect_mock = MagicMock()
    def file_op(path: str, target: str):
        side_effect_mock(path, target)
        return "ok"

    reg = TrustedToolRegistry()
    reg.authority.default_policy = Policy(
        policy_id="p_conflict",
        allowed_operations={"*"},
        allowed_resources={"*"}
    )

    tool = reg.register_tool(
        tool_id="conflict_tool",
        action_name="delete_db",
        executor_func=file_op,
        target_param="path"
    )

    with pytest.raises(PermissionError) as exc_info:
        tool(path="/etc/passwd", target="/tmp/safe")

    assert "Conflicting target values detected" in str(exc_info.value)
    assert side_effect_mock.call_count == 0


def test_sec03_custom_extractor_returning_invalid_target_rejected(tmp_path):
    """
    SEC-03: Custom target_extractor returning an empty or invalid target fails closed.
    """
    side_effect_mock = MagicMock()
    def sensitive_shell(cmd: str):
        side_effect_mock(cmd)
        return "ok"

    reg = TrustedToolRegistry()
    reg.authority.default_policy = Policy(
        policy_id="p_ext",
        allowed_operations={"*"},
        allowed_resources={"*"}
    )

    tool = reg.register_tool(
        tool_id="shell_tool",
        action_name="destructive_shell",
        executor_func=sensitive_shell,
        target_extractor=lambda *args, **kwargs: ""
    )

    with pytest.raises(PermissionError) as exc_info:
        tool(cmd="rm -rf /")

    assert "Custom extractor returned invalid target" in str(exc_info.value)
    assert side_effect_mock.call_count == 0


def test_sec03_existing_legitimate_registered_tools_allowed(tmp_path):
    """
    SEC-03: Legitimate registered tools (read_only or explicit target_param) succeed without regression.
    """
    read_mock = MagicMock()
    def read_func(file_path: str):
        read_mock(file_path)
        return f"contents of {file_path}"

    reg = TrustedToolRegistry()
    reg.authority.default_policy = Policy(
        policy_id="read_policy",
        allowed_operations={"read_file"},
        allowed_resources={"/app/data/file.txt"}
    )

    tool = reg.register_tool(
        tool_id="file_reader",
        action_name="read_file",
        executor_func=read_func,
        default_target="/app/data/file.txt"
    )

    res = tool("/app/data/file.txt")
    assert res["status"] == "SUCCESS"
    assert read_mock.call_count == 1


def test_sec03_mutating_tool_with_default_target_and_dynamic_args_rejected(tmp_path):
    """
    SEC-03: A mutating tool configured only with default_target cannot rely on default_target
    when dynamic arguments are supplied without target_param or extractor.
    """
    side_effect_mock = MagicMock()
    def mutate_func(arg1: str):
        side_effect_mock(arg1)
        return "mutated"

    reg = TrustedToolRegistry()
    reg.authority.default_policy = Policy(
        policy_id="p_default_mut",
        allowed_operations={"*"},
        allowed_resources={"/default/target"}
    )

    tool = reg.register_tool(
        tool_id="mut_tool",
        action_name="state_mutation",
        executor_func=mutate_func,
        default_target="/default/target"
    )

    with pytest.raises(PermissionError) as exc_info:
        tool("unexpected_dynamic_arg")

    assert "cannot rely on default_target when arguments are supplied" in str(exc_info.value)
    assert side_effect_mock.call_count == 0


def test_sec03_unknown_action_classification_denied(tmp_path):
    """
    SEC-03: Unknown action classification fails closed as state mutation,
    rejecting ambiguous positional extraction.
    """
    side_effect_mock = MagicMock()
    def unknown_func(note: str, real_target: str):
        side_effect_mock(note, real_target)
        return "executed"

    reg = TrustedToolRegistry()
    reg.authority.default_policy = Policy(
        policy_id="p_unk",
        allowed_operations={"*"},
        allowed_resources={"*"}
    )

    tool = reg.register_tool(
        tool_id="unknown_tool",
        action_name="some_completely_unrecognized_custom_operation",
        executor_func=unknown_func
    )

    with pytest.raises(PermissionError) as exc_info:
        tool("audit_comment", "/critical/data")

    assert "State-mutating operation" in str(exc_info.value)
    assert side_effect_mock.call_count == 0


def test_sec03_target_mismatch_across_recognized_parameters_rejected(tmp_path):
    """
    SEC-03: Tests target mismatch attacks across filepath, filename, url, and destination.
    A custom extractor or parameter must not authorize one target while the executor targets another.
    """
    test_cases = [
        ("filepath", lambda filepath, data: "modified"),
        ("filename", lambda filename, data: "modified"),
        ("url", lambda url, data: "modified"),
        ("destination", lambda destination, data: "modified"),
    ]

    for param_name, func in test_cases:
        side_effect_mock = MagicMock()
        def executor_wrapper(*args, **kwargs):
            side_effect_mock()
            return func(*args, **kwargs)

        reg = TrustedToolRegistry()
        reg.authority.default_policy = Policy(
            policy_id="mismatch_policy",
            allowed_operations={"modify"},
            allowed_resources={"/authorized/resource"}
        )

        tool = reg.register_tool(
            tool_id=f"tool_{param_name}",
            action_name="modify",
            executor_func=executor_wrapper,
            target_extractor=lambda *args, **kwargs: "/authorized/resource"
        )

        # Attacker supplies sensitive resource via parameter
        call_kwargs = {param_name: "/unauthorized/sensitive_resource", "data": {}}
        with pytest.raises(PermissionError) as exc_info:
            tool(**call_kwargs)

        assert ("Authorized target '/authorized/resource' differs from executor target parameter" in str(exc_info.value) or
                "Conflicting target values detected" in str(exc_info.value))
        assert side_effect_mock.call_count == 0


def test_sec03_signature_binding_failure_on_mutating_tool_fails_closed(tmp_path):
    """
    SEC-03: Do not silently skip target validation when signature binding or argument inspection fails.
    Fails closed for mutating operations.
    """
    side_effect_mock = MagicMock()
    # A callable that cannot be inspected cleanly or takes conflicting arguments
    def strict_mutating(req_arg1, req_arg2):
        side_effect_mock()
        return "ok"

    reg = TrustedToolRegistry()
    reg.authority.default_policy = Policy(
        policy_id="p_strict",
        allowed_operations={"*"},
        allowed_resources={"*"}
    )

    tool = reg.register_tool(
        tool_id="strict_tool",
        action_name="financial_state_mutation",
        executor_func=strict_mutating,
        target_param="req_arg1"
    )

    # Calling with invalid arguments causes failure and must fail closed with zero side effects
    with pytest.raises(PermissionError) as exc_info:
        tool("arg1", "arg2", "unexpected_third_arg", target_param="req_arg1")

    assert ("Signature binding failure" in str(exc_info.value) or
            "Conflicting target values" in str(exc_info.value) or
            "requires explicit target parameter" in str(exc_info.value))
    assert side_effect_mock.call_count == 0
