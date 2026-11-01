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

SEC-03 (Explicit Resource Target Binding):
- Benign first positional argument with a sensitive second target (Denied, 0 side effects).
- Target supplied through keyword arguments (Allowed, 1 side effect).
- Missing target (Denied, 0 side effects).
- Conflicting target parameters (Denied, 0 side effects).
- Custom extractor returning an invalid or ambiguous target (Denied, 0 side effects).
- Existing legitimate registered tools (Allowed, 1 side effect).
- Mutating tool without explicit target (Registration or execution rejected, 0 side effects).
- Unknown action classification (Denied, 0 side effects).
- Authorized target differs from executor target (Denied, 0 side effects).
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
    auth = AuthorizationAuthority(
        default_policy=Policy(
            policy_id="alice_bob_policy",
            allowed_operations={"transfer"},
            allowed_resources={"/accounts/alice"},
            allowed_principals={"principal_alice", "principal_bob"}
        )
    )
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=auth)

    alice_principal = auth.principal_provider.issue_principal("principal_alice")
    bob_principal = auth.principal_provider.issue_principal("principal_bob")

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
        correlation_id=str(uuid.uuid4()),
        request_id=str(uuid.uuid4()),
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
    # Zero side effects!
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

    reg = TrustedToolRegistry()
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

    auth = AuthorizationAuthority(
        default_policy=Policy(
            policy_id="p1",
            allowed_operations={"task"},
            allowed_resources={"/res1"},
            allowed_principals={"alice"}
        )
    )
    boundary = TrustedExecutionBoundary(authority=auth)

    alice_princ = auth.principal_provider.issue_principal("alice")
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

    auth = AuthorizationAuthority(
        default_policy=Policy(
            policy_id="admin_policy",
            allowed_operations={"admin"},
            allowed_resources={"/admin/panel"},
            allowed_principals={"admin_user"}
        )
    )
    boundary = TrustedExecutionBoundary(authority=auth)

    # Attacker crafts an AuthenticatedPrincipal object manually
    forged_principal = AuthenticatedPrincipal(
        principal_id="admin_user",
        issuer_id="TrustedPrincipalAuthority",
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
    # Even if an existing token existed:
    valid_admin_princ = auth.principal_provider.issue_principal("admin_user")
    valid_cap, _ = auth.evaluate_and_issue_capability(
        action_name="admin",
        target="/admin/panel",
        canonical_request_digest=digest,
        principal_id=valid_admin_princ,
        executor_id=admin_op
    )

    ctx_forged = ExecutionContext(
        correlation_id=str(uuid.uuid4()),
        request_id=str(uuid.uuid4()),
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

    reg = TrustedToolRegistry()
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

    alice_princ = reg.authority.principal_provider.issue_principal("alice")

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

    auth = AuthorizationAuthority(
        default_policy=Policy(
            policy_id="p_mutate",
            allowed_operations={"mutate"},
            allowed_resources={"/secure/record"},
            allowed_principals={"alice", "bob"}
        )
    )
    boundary = TrustedExecutionBoundary(authority=auth)

    alice_princ = auth.principal_provider.issue_principal("alice")
    bob_princ = auth.principal_provider.issue_principal("bob")

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
        correlation_id=str(uuid.uuid4()),
        request_id=str(uuid.uuid4()),
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
    # Unconstrained policy on operations, but target only allows audit_note_harmless
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

    # Attacker supplies "audit_note_harmless" as first positional arg, but writes to "critical_db"
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

    # path is /etc/passwd, target is /tmp/safe. Conflicting!
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

    # Extractor returns None or empty string
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

    # Dynamic argument supplied to mutating tool without target_param or extractor
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

    # Must fail closed because unclassified action is treated as state-mutating
    with pytest.raises(PermissionError) as exc_info:
        tool("audit_comment", "/critical/data")

    assert "State-mutating operation" in str(exc_info.value)
    assert side_effect_mock.call_count == 0


def test_sec03_authorized_target_differs_from_executor_target_rejected(tmp_path):
    """
    SEC-03: If the authorized target differs from the target argument bound for the executor,
    execution must be rejected with zero side effects.
    """
    side_effect_mock = MagicMock()
    def modify_resource(target: str, data: dict):
        side_effect_mock(target, data)
        return "modified"

    reg = TrustedToolRegistry()
    reg.authority.default_policy = Policy(
        policy_id="diff_policy",
        allowed_operations={"modify"},
        allowed_resources={"authorized_target"}
    )

    # Extractor extracts "authorized_target", but kwargs passes target="unauthorized_target"
    # Even if extractor overrides, the executor binding check detects that target != authorized_target!
    tool = reg.register_tool(
        tool_id="diff_tool",
        action_name="modify",
        executor_func=modify_resource,
        target_extractor=lambda *args, **kwargs: "authorized_target"
    )

    with pytest.raises(PermissionError) as exc_info:
        tool(target="unauthorized_target", data={})

    # Either conflicting targets or authorized target differs
    assert ("Conflicting target values detected" in str(exc_info.value) or
            "Authorized target" in str(exc_info.value))
    assert side_effect_mock.call_count == 0
