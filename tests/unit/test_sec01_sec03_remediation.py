"""
Adversarial Regression Test Suite for SEC-01 and SEC-03.

Verifies:
SEC-01 (Principal Binding at Execution Boundary):
- Caller with access to AuthorizationAuthority cannot obtain signing material or mint an accepted assertion.
- An assertion signed with an untrusted private key is rejected.
- An assertion signed by a trusted external test issuer is accepted.
- An assertion with a modified principal ID, issuer, or timestamp is rejected.
- Expired and future-dated assertions are rejected.
- Missing public-key configuration denies principal-restricted operations.
- Cross-principal capability presentation remains rejected (Alice capability presented by Bob).
- Plain strings and caller-controlled context dictionaries cannot assert principal identity.
- Every rejected execution produces zero executor side effects.

SEC-03 (Bind authorization to the exact executor resource argument):
- Mutating executor with explicit target_param receives exactly the target authorized by policy.
- A custom extractor returning an authorized resource while the executor receives a different resource is rejected.
- Target mismatch tests with arbitrary parameter names: tenant_ref, object_handle, account_key.
- Positional and keyword invocation paths resolve the same target.
- Missing target, conflicting target, and signature-binding failure are rejected.
- Existing legitimate explicitly bound mutating tools continue to work.
- Demonstrably read-only local/network tools continue to support safe positional target extraction.
- Every rejected case produces zero executor invocations.
"""

import time
import os
import hashlib
from typing import Optional, Dict, Any
from unittest.mock import MagicMock
import pytest

from epistemicos.authorization import (
    AuthorizationAuthority,
    Policy,
    PrincipalVerifier,
    AuthenticatedPrincipal,
)
from epistemicos.provenance import (
    TrustedExecutionBoundary,
    ExecutionContext,
    LocalProvenanceStore,
)
from epistemicos.tools import TrustedToolRegistry


# =============================================================================
# RFC 8032 Ed25519 External Test Issuer (Self-contained test identity provider)
# Holds the private signing key completely isolated from EpistemicOS components.
# =============================================================================

_ED_B = 256
_ED_Q = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493


def _ed_H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _ed_expmod(b: int, e: int, m: int) -> int:
    return pow(b, e, m)


def _ed_inv(x: int) -> int:
    return _ed_expmod(x, _ED_Q - 2, _ED_Q)


_ed_d = -121665 * _ed_inv(121666)
_ed_I = _ed_expmod(2, (_ED_Q - 1) // 4, _ED_Q)


def _ed_xrecover(y: int) -> int:
    xx = (y * y - 1) * _ed_inv(_ed_d * y * y + 1)
    x = _ed_expmod(xx, (_ED_Q + 3) // 8, _ED_Q)
    if (x * x - xx) % _ED_Q != 0:
        x = (x * _ed_I) % _ED_Q
    if x % 2 != 0:
        x = _ED_Q - x
    return x


_ed_By = 4 * _ed_inv(5)
_ed_Bx = _ed_xrecover(_ed_By)
_ed_B = [_ed_Bx % _ED_Q, _ed_By % _ED_Q]


def _ed_edwards(P, Q):
    x1, y1 = P[0], P[1]
    x2, y2 = Q[0], Q[1]
    x3 = (x1 * y2 + x2 * y1) * _ed_inv(1 + _ed_d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _ed_inv(1 - _ed_d * x1 * x2 * y1 * y2)
    return [x3 % _ED_Q, y3 % _ED_Q]


def _ed_scalarmult(P, e: int):
    if e == 0:
        return [0, 1]
    Q = _ed_scalarmult(P, e // 2)
    Q = _ed_edwards(Q, Q)
    if e & 1:
        Q = _ed_edwards(Q, P)
    return Q


def _ed_encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _ed_encodepoint(P) -> bytes:
    x = P[0]
    y = P[1]
    bits = [(y >> i) & 1 for i in range(_ED_B - 1)] + [x & 1]
    return bytes(sum([bits[i * 8 + j] << j for j in range(8)]) for i in range(_ED_B // 8))


def _ed_decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _ed25519_publickey(sk: bytes) -> bytes:
    h = _ed_H(sk)
    a = 2**(_ED_B - 2) + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, _ED_B - 2))
    A = _ed_scalarmult(_ed_B, a)
    return _ed_encodepoint(A)


def _ed25519_sign(m: bytes, sk: bytes, pk: bytes) -> bytes:
    h = _ed_H(sk)
    a = 2**(_ED_B - 2) + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, _ED_B - 2))
    r = _ed_decodeint(_ed_H(h[32:] + m))
    R = _ed_scalarmult(_ed_B, r)
    k = _ed_decodeint(_ed_H(_ed_encodepoint(R) + pk + m))
    S = (r + k * a) % _ED_L
    return _ed_encodepoint(R) + _ed_encodeint(S)


class ExternalTestIdentityAuthority:
    """
    Test-only external Identity Provider that holds its own Ed25519 private signing key.
    The production verifier receives ONLY the public key.
    The private key is never passed to AuthorizationAuthority or PrincipalVerifier.
    """

    def __init__(self, seed: Optional[bytes] = None, issuer_id: str = "ExternalTrustedIdP"):
        self.private_seed = seed if seed and len(seed) == 32 else os.urandom(32)
        self.public_key = _ed25519_publickey(self.private_seed)
        self.issuer_id = issuer_id

    def issue_principal(
        self,
        principal_id: str,
        current_time: Optional[float] = None,
        expires_at: Optional[float] = None,
        key_id: Optional[str] = None
    ) -> AuthenticatedPrincipal:
        ts = current_time if current_time is not None else time.time()
        exp_str = f"{expires_at:.6f}" if expires_at is not None else ""
        kid_str = key_id or ""
        payload = f"{principal_id}:{self.issuer_id}:{ts:.6f}:{exp_str}:{kid_str}".encode("utf-8")
        sig_bytes = _ed25519_sign(payload, self.private_seed, self.public_key)
        return AuthenticatedPrincipal(
            principal_id=principal_id,
            issuer_id=self.issuer_id,
            timestamp=ts,
            signature=sig_bytes.hex(),
            expires_at=expires_at,
            key_id=key_id
        )


# =============================================================================
# SEC-01: Principal Identity Binding & Independent Trust Boundary Tests
# =============================================================================

def test_sec01_authority_and_verifier_do_not_expose_private_keys_or_minting():
    """
    SEC-01: A caller with access to AuthorizationAuthority and PrincipalVerifier cannot
    obtain signing material or mint an accepted assertion.
    """
    trusted_idp = ExternalTestIdentityAuthority(issuer_id="CorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"CorpIdP": trusted_idp.public_key})
    auth = AuthorizationAuthority(principal_provider=verifier)

    # Verify no private key or signing secret is accessible
    assert not hasattr(verifier, "signing_secret")
    assert not hasattr(verifier, "private_key")
    assert not hasattr(verifier, "issue_principal")
    assert not hasattr(verifier, "mint_principal")

    assert not hasattr(auth, "issue_principal")
    assert not hasattr(auth, "mint_principal")
    assert not hasattr(auth, "identity_signing_secret")


def test_sec01_assertion_signed_by_trusted_external_issuer_accepted(tmp_path):
    """
    SEC-01: An assertion signed by a trusted external test issuer is accepted.
    """
    trusted_idp = ExternalTestIdentityAuthority(issuer_id="TrustedCorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": trusted_idp.public_key})

    alice_principal = trusted_idp.issue_principal("alice")
    valid, reason, pid = verifier.verify_principal(alice_principal)
    assert valid is True
    assert reason == "Principal verified"
    assert pid == "alice"


def test_sec01_assertion_signed_with_untrusted_key_rejected():
    """
    SEC-01: An assertion signed with an untrusted private key is rejected.
    """
    trusted_idp = ExternalTestIdentityAuthority(issuer_id="TrustedCorpIdP")
    rogue_idp = ExternalTestIdentityAuthority(issuer_id="TrustedCorpIdP")  # Claims same issuer, different key

    verifier = PrincipalVerifier(trusted_public_keys={"TrustedCorpIdP": trusted_idp.public_key})

    # Rogue IdP signs assertion for alice
    rogue_principal = rogue_idp.issue_principal("alice")
    valid, reason, pid = verifier.verify_principal(rogue_principal)
    assert valid is False
    assert "signature verification failed" in reason.lower()
    assert pid is None


def test_sec01_assertion_with_modified_fields_rejected():
    """
    SEC-01: An assertion with a modified principal ID, issuer, or timestamp is rejected.
    """
    trusted_idp = ExternalTestIdentityAuthority(issuer_id="CorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"CorpIdP": trusted_idp.public_key})

    valid_assertion = trusted_idp.issue_principal("alice")

    # 1. Tampered principal_id
    tampered_pid = AuthenticatedPrincipal(
        principal_id="bob",
        issuer_id=valid_assertion.issuer_id,
        timestamp=valid_assertion.timestamp,
        signature=valid_assertion.signature,
        expires_at=valid_assertion.expires_at,
        key_id=valid_assertion.key_id
    )
    v1, r1, _ = verifier.verify_principal(tampered_pid)
    assert v1 is False
    assert "signature verification failed" in r1.lower()

    # 2. Tampered issuer
    tampered_issuer = AuthenticatedPrincipal(
        principal_id=valid_assertion.principal_id,
        issuer_id="OtherIdP",
        timestamp=valid_assertion.timestamp,
        signature=valid_assertion.signature,
        expires_at=valid_assertion.expires_at,
        key_id=valid_assertion.key_id
    )
    v2, r2, _ = verifier.verify_principal(tampered_issuer)
    assert v2 is False
    assert "untrusted identity issuer" in r2.lower()

    # 3. Tampered timestamp
    tampered_ts = AuthenticatedPrincipal(
        principal_id=valid_assertion.principal_id,
        issuer_id=valid_assertion.issuer_id,
        timestamp=valid_assertion.timestamp - 100.0,
        signature=valid_assertion.signature,
        expires_at=valid_assertion.expires_at,
        key_id=valid_assertion.key_id
    )
    v3, r3, _ = verifier.verify_principal(tampered_ts)
    assert v3 is False
    assert "signature verification failed" in r3.lower()


def test_sec01_expired_and_future_dated_assertions_rejected():
    """
    SEC-01: Expired and future-dated assertions are rejected.
    """
    trusted_idp = ExternalTestIdentityAuthority(issuer_id="CorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"CorpIdP": trusted_idp.public_key}, clock_skew_seconds=5.0)

    now = time.time()

    # Future-dated beyond clock skew
    future_principal = trusted_idp.issue_principal("alice", current_time=now + 10.0)
    v_fut, r_fut, _ = verifier.verify_principal(future_principal, current_time=now)
    assert v_fut is False
    assert "future-dated" in r_fut.lower()

    # Expired by max_age_seconds
    old_principal = trusted_idp.issue_principal("alice", current_time=now - 4000.0)
    v_exp, r_exp, _ = verifier.verify_principal(old_principal, max_age_seconds=3600.0, current_time=now)
    assert v_exp is False
    assert "expired" in r_exp.lower()

    # Expired by explicit expires_at
    explicit_exp_principal = trusted_idp.issue_principal("alice", current_time=now - 50.0, expires_at=now - 10.0)
    v_exp2, r_exp2, _ = verifier.verify_principal(explicit_exp_principal, current_time=now)
    assert v_exp2 is False
    assert "expired" in r_exp2.lower()


def test_sec01_missing_public_key_configuration_fails_closed(tmp_path):
    """
    SEC-01: Missing public-key configuration denies principal-restricted operations
    with zero executor side effects.
    """
    side_effect_mock = MagicMock()
    def sensitive_action(target: str):
        side_effect_mock(target)
        return "done"

    # Verifier with no public keys configured
    unconfigured_verifier = PrincipalVerifier(trusted_public_keys={})

    reg = TrustedToolRegistry()
    reg.authority.principal_provider = unconfigured_verifier
    reg.authority.default_policy = Policy(
        policy_id="strict_policy",
        allowed_operations={"transfer"},
        allowed_resources={"/accounts/123"},
        allowed_principals={"alice"}
    )

    tool = reg.register_tool(
        tool_id="transfer_tool",
        action_name="transfer",
        executor_func=sensitive_action,
        target_param="target"
    )

    idp = ExternalTestIdentityAuthority(issuer_id="CorpIdP")
    alice_princ = idp.issue_principal("alice")

    with pytest.raises(PermissionError) as exc_info:
        tool(target="/accounts/123", authenticated_principal=alice_princ)

    assert "not configured with any trusted public verification keys" in str(exc_info.value)
    assert side_effect_mock.call_count == 0


def test_sec01_cross_principal_capability_presentation_rejected(tmp_path):
    """
    SEC-01: Capability issued to Alice, presented by Bob at execution boundary.
    Must be rejected with zero executor side effects.
    """
    side_effect_mock = MagicMock()
    def sensitive_executor(account: str):
        side_effect_mock(account)
        return {"status": "executed"}

    store = LocalProvenanceStore(log_path=str(tmp_path / "prov.jsonl"))
    trusted_idp = ExternalTestIdentityAuthority(issuer_id="CorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"CorpIdP": trusted_idp.public_key})

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

    alice_principal = trusted_idp.issue_principal("principal_alice")
    bob_principal = trusted_idp.issue_principal("principal_bob")

    raw_payload = {"op": "transfer", "account": "/accounts/alice"}
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
    Must be rejected with zero side effects.
    """
    side_effect_mock = MagicMock()
    def mutate_account(account_id: str, amount: float):
        side_effect_mock(account_id, amount)
        return {"account_id": account_id, "amount": amount}

    trusted_idp = ExternalTestIdentityAuthority(issuer_id="CorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"CorpIdP": trusted_idp.public_key})

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

    with pytest.raises(PermissionError) as exc_info:
        tool(
            account_id="/accounts/alice",
            amount=500.0,
            context={"principal_id": "principal_alice"}
        )

    assert "Caller-controlled context dictionary cannot assert principal identity" in str(exc_info.value)
    assert side_effect_mock.call_count == 0


def test_sec01_caller_provided_string_rejected_at_execution_boundary(tmp_path):
    """
    SEC-01: A caller-provided string cannot satisfy principal authentication at the execution boundary.
    """
    side_effect_mock = MagicMock()
    def write_task(target: str):
        side_effect_mock(target)
        return "written"

    trusted_idp = ExternalTestIdentityAuthority(issuer_id="CorpIdP")
    verifier = PrincipalVerifier(trusted_public_keys={"CorpIdP": trusted_idp.public_key})

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

    alice_princ = trusted_idp.issue_principal("alice")
    payload = {"k": "v", "target": "/res"}
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
        authenticated_principal="alice"
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


# =============================================================================
# SEC-03: Explicit Resource Target Binding Tests
# =============================================================================

def test_sec03_mutating_executor_with_explicit_target_param_receives_authorized_target(tmp_path):
    """
    SEC-03: Mutating executor with explicit target_param receives exactly the target
    authorized by policy.
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
    assert res["result"] == {"updated": "users_table", "row": 42}
    assert side_effect_mock.call_count == 1
    side_effect_mock.assert_called_once_with("users_table", 42)


def test_sec03_custom_extractor_target_mismatch_rejected(tmp_path):
    """
    SEC-03: A custom extractor returning an authorized resource while the executor
    receives a different resource is rejected with zero side effects.
    """
    side_effect_mock = MagicMock()
    def mutate_account(target_account: str, amount: float):
        side_effect_mock(target_account, amount)
        return "mutated"

    reg = TrustedToolRegistry()
    reg.authority.default_policy = Policy(
        policy_id="p_ext_mismatch",
        allowed_operations={"mutate"},
        allowed_resources={"/accounts/authorized_public"}
    )

    # Tool registered with target_param and an extractor that returns the authorized target
    tool = reg.register_tool(
        tool_id="acc_mutator",
        action_name="mutate",
        executor_func=mutate_account,
        target_param="target_account",
        target_extractor=lambda *args, **kwargs: "/accounts/authorized_public"
    )

    # Invocation specifies sensitive account for executor
    with pytest.raises(PermissionError) as exc_info:
        tool(target_account="/accounts/sensitive_private", amount=100.0)

    assert "Custom extractor target '/accounts/authorized_public' does not match executor parameter 'target_account'='/accounts/sensitive_private'" in str(exc_info.value)
    assert side_effect_mock.call_count == 0


def test_sec03_arbitrary_parameter_names_tenant_ref_and_object_handle_mismatch(tmp_path):
    """
    SEC-03: Target mismatch tests with arbitrary parameter names including 'tenant_ref'
    and 'object_handle'. Verifies that explicit target_param binds the exact parameter.
    """
    for param_name in ("tenant_ref", "object_handle", "account_key"):
        side_effect_mock = MagicMock()

        # Dynamic function definition with custom parameter name
        def make_func(p_name):
            if p_name == "tenant_ref":
                def func(tenant_ref: str, payload: dict):
                    side_effect_mock(tenant_ref, payload)
                    return "ok"
                return func
            elif p_name == "object_handle":
                def func(object_handle: str, payload: dict):
                    side_effect_mock(object_handle, payload)
                    return "ok"
                return func
            else:
                def func(account_key: str, payload: dict):
                    side_effect_mock(account_key, payload)
                    return "ok"
                return func

        executor = make_func(param_name)

        reg = TrustedToolRegistry()
        reg.authority.default_policy = Policy(
            policy_id=f"p_{param_name}",
            allowed_operations={"modify"},
            allowed_resources={"public_resource"}
        )

        tool = reg.register_tool(
            tool_id=f"tool_{param_name}",
            action_name="modify",
            executor_func=executor,
            target_param=param_name
        )

        # 1. Calling with unauthorized target in custom parameter fails authorization
        with pytest.raises(PermissionError) as exc_info:
            tool(**{param_name: "unauthorized_resource", "payload": {}})

        assert "AUTHORIZATION_DENIED_TARGET_NOT_ALLOWED" in str(exc_info.value)
        assert side_effect_mock.call_count == 0

        # 2. Calling with conflicting explicit target fails before authorization
        with pytest.raises(PermissionError) as exc_conflict:
            tool(**{param_name: "public_resource", "target": "different_target", "payload": {}})

        assert "Conflicting target values detected" in str(exc_conflict.value)
        assert side_effect_mock.call_count == 0


def test_sec03_positional_and_keyword_invocation_resolve_same_target(tmp_path):
    """
    SEC-03: Positional and keyword invocation paths resolve the same target for mutating operations.
    """
    side_effect_mock = MagicMock()
    def mutate_file(filepath: str, content: str):
        side_effect_mock(filepath, content)
        return {"filepath": filepath}

    reg = TrustedToolRegistry()
    reg.authority.default_policy = Policy(
        policy_id="p_pos_kw",
        allowed_operations={"write"},
        allowed_resources={"/tmp/test.txt"}
    )

    tool = reg.register_tool(
        tool_id="writer",
        action_name="write",
        executor_func=mutate_file,
        target_param="filepath"
    )

    # 1. Positional invocation
    res1 = tool("/tmp/test.txt", "content1")
    assert res1["status"] == "SUCCESS"
    assert side_effect_mock.call_count == 1

    # 2. Keyword invocation
    res2 = tool(filepath="/tmp/test.txt", content="content2")
    assert res2["status"] == "SUCCESS"
    assert side_effect_mock.call_count == 2


def test_sec03_missing_target_rejected(tmp_path):
    """
    SEC-03: Mutating tool invoked with missing target is rejected with zero side effects.
    """
    side_effect_mock = MagicMock()
    def mutate_op(target: str):
        side_effect_mock(target)
        return "ok"

    reg = TrustedToolRegistry()
    reg.authority.default_policy = Policy(
        policy_id="p_default",
        allowed_operations={"*"},
        allowed_resources={"*"}
    )

    tool = reg.register_tool(
        tool_id="mutator",
        action_name="delete_db",
        executor_func=mutate_op,
        target_param="target"
    )

    with pytest.raises(PermissionError) as exc_info:
        tool()

    assert "Missing required target parameter 'target'" in str(exc_info.value)
    assert side_effect_mock.call_count == 0


def test_sec03_conflicting_target_parameters_rejected(tmp_path):
    """
    SEC-03: Invocation providing conflicting target values across parameter sources
    is rejected with zero side effects.
    """
    side_effect_mock = MagicMock()
    def file_op(path: str, data: str):
        side_effect_mock(path, data)
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
        tool(path="/etc/passwd", target="/tmp/safe", data="none")

    assert "Conflicting target values detected" in str(exc_info.value)
    assert side_effect_mock.call_count == 0


def test_sec03_signature_binding_failure_rejected(tmp_path):
    """
    SEC-03: Invocation with invalid signature arguments fails closed for mutating operations.
    """
    side_effect_mock = MagicMock()
    def strict_mutating(req_arg1: str, req_arg2: int):
        side_effect_mock(req_arg1, req_arg2)
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

    # Calling with too many positional arguments causes signature binding error
    with pytest.raises(PermissionError) as exc_info:
        tool("arg1", 42, "unexpected_third_arg")

    assert "Signature binding error" in str(exc_info.value)
    assert side_effect_mock.call_count == 0


def test_sec03_mutating_tool_without_explicit_target_param_fails_at_registration():
    """
    SEC-03: Mutating tool without explicit target_param fails closed at registration.
    """
    def delete_records(table: str):
        return "deleted"

    reg = TrustedToolRegistry()
    with pytest.raises(ValueError) as exc_info:
        reg.register_tool(
            tool_id="bad_delete_tool",
            action_name="delete_db",
            executor_func=delete_records
            # target_param omitted!
        )

    assert "requires explicit 'target_param' bound to executor signature" in str(exc_info.value)


def test_sec03_target_param_not_in_signature_fails_at_registration():
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


def test_sec03_read_only_tools_support_positional_extraction():
    """
    SEC-03: Demonstrably read-only tools continue to support safe positional target extraction.
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
    read_mock.assert_called_once_with("/app/data/file.txt")
