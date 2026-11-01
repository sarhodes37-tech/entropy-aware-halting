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
- A caller with access to AuthorizationAuthority cannot mint an assertion for another principal.
- An assertion signed by an untrusted key is rejected.
- An assertion signed by a trusted external test issuer is accepted.
- Missing identity-provider configuration denies principal-bound execution.
- Every rejected attempt produces zero executor side effects.

SEC-03 (Explicit Resource Target Binding):
- Benign first positional argument with a sensitive second target (Denied, 0 side effects).
- Target supplied through keyword arguments (Allowed, 1 side effect).
- Missing target (Denied, 0 side effects).
- Conflicting target parameters (Denied, 0 side effects).
- Custom extractor returning an invalid or ambiguous target (Denied, 0 side effects).
- Existing legitimate registered tools (Allowed, 1 side effect).
- Mutating tool without explicit target (Registration or execution rejected, 0 side effects).
- Unknown action classification (Denied, 0 side effects).
- Authorized target differs from executor target across filepath, filename, url, destination, and custom account_key (Denied, 0 side effects).
- Signature binding failure on mutating operation fails closed (Denied, 0 side effects).
"""

import time
import uuid
import hmac
import hashlib
import pytest
from unittest.mock import MagicMock

from epistemicos.authorization import (
    AuthorizationAuthority,
    Policy,
    Capability,
    PrincipalVerifier,
    AuthenticatedPrincipal,
    get_callable_identity
)
from epistemicos.provenance import (
    TrustedExecutionBoundary,
    ExecutionContext,
    LocalProvenanceStore
)
from epistemicos.tools import TrustedToolRegistry, TrustedToolWrapper


class ExternalTestIdentityAuthority:
    """
    Simulated external identity provider holding the private signing key for test assertions.
    AuthorizationAuthority holds ONLY the verification secret / verifier, NEVER this issuer.
    """

    def __init__(self, signing_secret: bytes, issuer_id: str = "ExternalTrustedIdP"):
        self.signing_secret = signing_secret
        self.issuer_id = issuer_id

    def issue_principal(self, principal_id: str, current_time: float = None) -> AuthenticatedPrincipal:
        ts = current_time if current_time is not None else time.time()
        payload = f"{principal_id}:{self.issuer_id}:{ts}"
        sig = hmac.new(self.signing_secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return AuthenticatedPrincipal(
            principal_id=principal_id,
            issuer_id=self.issuer_id,
            timestamp=ts,
            signature=sig
        )


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
    idp_secret = b"external_idp_private_key_123"
    external_idp = ExternalTestIdentityAuthority(signing_secret=idp_secret, issuer_id="CorpIdP")
    verifier = PrincipalVerifier(verification_secret=idp_secret, trusted_issuer_id="CorpIdP")

    auth = AuthorizationAuthority(
        default_policy=Policy(
            policy_id="alice_bob_policy",
            allowed_operations={"transfer"},
            allowed_resources={"/accounts/alice"},
            allowed_principals={"principal_alice", "principal_bob"}
        ),
        principal_provider=verifier
    )
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=auth)

    alice_principal = external_idp.issue_principal("principal_alice")
    bob_principal = external_idp.issue_principal("principal_bob")

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

    idp_secret = b"external_idp_secret_456"
    verifier = PrincipalVerifier(verification_secret=idp_secret, trusted_issuer_id="CorpIdP")

    reg = TrustedToolRegistry()
    reg.authority.principal_provider = verifier
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

    idp_secret = b"external_idp_secret_789"
    external_idp = ExternalTestIdentityAuthority(signing_secret=idp_secret, issuer_id="CorpIdP")
    verifier = PrincipalVerifier(verification_secret=idp_secret, trusted_issuer_id="CorpIdP")

    auth = AuthorizationAuthority(
        default_policy=Policy(
            policy_id="p1",
            allowed_operations={"task"},
            allowed_resources={"/res1"},
            allowed_principals={"alice"}
        ),
        principal_provider=verifier
    )
    boundary = TrustedExecutionBoundary(authority=auth)

    alice_princ = external_idp.issue_principal("alice")
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

    idp_secret = b"external_idp_secret_abc"
    external_idp = ExternalTestIdentityAuthority(signing_secret=idp_secret, issuer_id="CorpIdP")
    verifier = PrincipalVerifier(verification_secret=idp_secret, trusted_issuer_id="CorpIdP")

    auth = AuthorizationAuthority(
        default_policy=Policy(
            policy_id="admin_policy",
            allowed_operations={"admin"},
            allowed_resources={"/admin/panel"},
            allowed_principals={"admin_user"}
        ),
        principal_provider=verifier
    )
    boundary = TrustedExecutionBoundary(authority=auth)

    # Attacker crafts an AuthenticatedPrincipal object manually
    forged_principal = AuthenticatedPrincipal(
        principal_id="admin_user",
        issuer_id="CorpIdP",
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
    valid_admin_princ = external_idp.issue_principal("admin_user")
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

    idp_secret = b"external_idp_secret_def"
    external_idp = ExternalTestIdentityAuthority(signing_secret=idp_secret, issuer_id="CorpIdP")
    verifier = PrincipalVerifier(verification_secret=idp_secret, trusted_issuer_id="CorpIdP")

    reg = TrustedToolRegistry()
    reg.authority.principal_provider = verifier
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

    alice_princ = external_idp.issue_principal("alice")

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

    idp_secret = b"external_idp_secret_ghi"
    external_idp = ExternalTestIdentityAuthority(signing_secret=idp_secret, issuer_id="CorpIdP")
    verifier = PrincipalVerifier(verification_secret=idp_secret, trusted_issuer_id="CorpIdP")

    auth = AuthorizationAuthority(
        default_policy=Policy(
            policy_id="p_mutate",
            allowed_operations={"mutate"},
            allowed_resources={"/secure/record"},
            allowed_principals={"alice", "bob"}
        ),
        principal_provider=verifier
    )
    boundary = TrustedExecutionBoundary(authority=auth)

    alice_princ = external_idp.issue_principal("alice")
    bob_princ = external_idp.issue_principal("bob")

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


def test_sec01_authority_cannot_mint_assertions():
    """
    SEC-01: AuthorizationAuthority and PrincipalVerifier do not expose identity minting methods.
    """
    auth = AuthorizationAuthority()
    assert not hasattr(auth, "issue_principal")
    assert not hasattr(auth, "mint_principal")

    verifier = PrincipalVerifier(verification_secret=b"dummy_secret")
    assert not hasattr(verifier, "issue_principal")
    assert not hasattr(verifier, "mint_principal")


def test_sec01_caller_provided_string_cannot_satisfy_boundary_authentication(tmp_path):
    """
    SEC-01: A caller-provided string cannot satisfy principal authentication at the execution boundary.
    """
    side_effect_mock = MagicMock()
    def write_task():
        side_effect_mock()
        return "written"

    idp_secret = b"external_idp_secret_jkl"
    external_idp = ExternalTestIdentityAuthority(signing_secret=idp_secret, issuer_id="CorpIdP")
    verifier = PrincipalVerifier(verification_secret=idp_secret, trusted_issuer_id="CorpIdP")

    auth = AuthorizationAuthority(
        default_policy=Policy(
            policy_id="p_str",
            allowed_operations={"write"},
            allowed_resources={"/res"},
            allowed_principals={"alice"}
        ),
        principal_provider=verifier
    )
    boundary = TrustedExecutionBoundary(authority=auth)

    alice_princ = external_idp.issue_principal("alice")
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
    trusted_idp = ExternalTestIdentityAuthority(signing_secret=b"key_a", issuer_id="TrustedCorpIdP")
    rogue_idp = ExternalTestIdentityAuthority(signing_secret=b"key_a", issuer_id="RogueCorpIdP")

    verifier = PrincipalVerifier(verification_secret=b"key_a", trusted_issuer_id="TrustedCorpIdP")

    auth = AuthorizationAuthority(
        default_policy=Policy(policy_id="p", allowed_operations={"op"}, allowed_resources={"/res"}, allowed_principals={"alice"}),
        principal_provider=verifier
    )

    # Rogue provider signs for alice
    rogue_alice = rogue_idp.issue_principal("alice")

    cap, reason = auth.evaluate_and_issue_capability(
        action_name="op",
        target="/res",
        canonical_request_digest="d" * 64,
        principal_id=rogue_alice
    )
    assert cap is None
    assert "Untrusted identity issuer" in reason


def test_sec01_assertion_signed_by_untrusted_key_rejected(tmp_path):
    """
    SEC-01: Assertion signed by an untrusted key is rejected.
    """
    external_idp = ExternalTestIdentityAuthority(signing_secret=b"attacker_secret_key", issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(verification_secret=b"legit_secret_key", trusted_issuer_id="TrustedCorpIdP")

    auth = AuthorizationAuthority(
        default_policy=Policy(policy_id="p", allowed_operations={"op"}, allowed_resources={"/res"}, allowed_principals={"alice"}),
        principal_provider=verifier
    )

    signed_with_wrong_key = external_idp.issue_principal("alice")

    cap, reason = auth.evaluate_and_issue_capability(
        action_name="op",
        target="/res",
        canonical_request_digest="d" * 64,
        principal_id=signed_with_wrong_key
    )
    assert cap is None
    assert "signature verification failed" in reason.lower()


def test_sec01_future_dated_assertion_rejected(tmp_path):
    """
    SEC-01: An assertion timestamped in the future is rejected.
    """
    idp_secret = b"future_secret_key"
    external_idp = ExternalTestIdentityAuthority(signing_secret=idp_secret, issuer_id="CorpIdP")
    verifier = PrincipalVerifier(verification_secret=idp_secret, trusted_issuer_id="CorpIdP")

    auth = AuthorizationAuthority(
        default_policy=Policy(policy_id="p", allowed_operations={"op"}, allowed_resources={"/res"}, allowed_principals={"alice"}),
        principal_provider=verifier
    )

    # Issue assertion timestamped 1 hour in the future
    future_time = time.time() + 3600.0
    future_alice = external_idp.issue_principal("alice", current_time=future_time)

    cap, reason = auth.evaluate_and_issue_capability(
        action_name="op",
        target="/res",
        canonical_request_digest="d" * 64,
        principal_id=future_alice
    )
    assert cap is None
    assert "Future-dated principal assertion rejected" in reason


def test_sec01_missing_identity_provider_configuration_denies_execution(tmp_path):
    """
    SEC-01: When no identity provider/verifier is configured on AuthorizationAuthority,
    principal-bound execution fails closed with zero side effects.
    """
    side_effect_mock = MagicMock()
    def sensitive_action():
        side_effect_mock()
        return "ok"

    # Authority with NO principal_provider
    auth = AuthorizationAuthority(
        default_policy=Policy(
            policy_id="p_strict",
            allowed_operations={"op"},
            allowed_resources={"/res"},
            allowed_principals={"privileged_principal"}
        ),
        principal_provider=None
    )
    boundary = TrustedExecutionBoundary(authority=auth)

    # Attacker tries to present an assertion or string
    cap, reason = auth.evaluate_and_issue_capability(
        action_name="op",
        target="/res",
        canonical_request_digest="d" * 64,
        principal_id="privileged_principal",
        executor_id=sensitive_action
    )
    # Denied at issuance
    assert cap is None
    assert "AUTHORIZATION_DENIED_AUTHENTICATED_PRINCIPAL_REQUIRED" in reason
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


def test_sec03_custom_parameter_account_key_mismatch_rejected(tmp_path):
    """
    SEC-03: Adversarial test using custom parameter name 'account_key', where the extractor
    returns an authorized resource, but the executor receives a different sensitive resource.
    Must be denied with zero executor side effects.
    """
    side_effect_mock = MagicMock()
    def update_account(account_key: str, payload: dict):
        side_effect_mock(account_key, payload)
        return {"updated": account_key}

    reg = TrustedToolRegistry()
    reg.authority.default_policy = Policy(
        policy_id="p_acc",
        allowed_operations={"update_account"},
        allowed_resources={"authorized_public_account"}
    )

    # Tool registered with custom extractor returning authorized_public_account
    tool = reg.register_tool(
        tool_id="acc_updater",
        action_name="update_account",
        executor_func=update_account,
        target_extractor=lambda *args, **kwargs: "authorized_public_account"
    )

    # Attacker calls tool supplying sensitive private account in account_key
    with pytest.raises(PermissionError) as exc_info:
        tool(account_key="sensitive_private_account_999", payload={"credit": 10000})

    assert ("Authorized target 'authorized_public_account' differs from executor argument 'sensitive_private_account_999'" in str(exc_info.value) or
            "differ" in str(exc_info.value).lower())
    assert side_effect_mock.call_count == 0


def test_sec03_target_param_signature_validation_fails_at_registration():
    """
    SEC-03: Validates that target_param exists in executor's inspectable signature during registration.
    """
    def sample_func(arg1: str):
        return arg1

    reg = TrustedToolRegistry()
    with pytest.raises(ValueError) as exc_info:
        reg.register_tool(
            tool_id="bad_tool",
            action_name="modify",
            executor_func=sample_func,
            target_param="non_existent_param"
        )

    assert "does not exist in executor signature parameters" in str(exc_info.value)


def test_sec03_signature_binding_failure_on_mutating_tool_fails_closed(tmp_path):
    """
    SEC-03: Do not silently skip target validation when signature binding or argument inspection fails.
    Fails closed for mutating operations.
    """
    side_effect_mock = MagicMock()
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
