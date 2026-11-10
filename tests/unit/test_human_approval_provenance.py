"""
Deterministic Regression Test Suite: Human Approval Provenance and Authority Verification.

Verifies the Priority 1 security invariants:
A. Valid signature, unverified authority (denial, no capability issued)
B. Valid signature, unauthorized approver under applicable policy (denial)
C. Valid approver, wrong operation / action mismatch (denial)
D. Valid approver, wrong target or resource scope mismatch (denial)
E. Valid approver, wrong requesting principal or task (denial)
F. Valid approval: authenticated & authorized approver, exact bindings, valid signature
G. Missing or malformed provenance (missing assertion, malformed, missing IDP) fails closed
H. Replay and mutation: signature tampering, field mutation, replay prevention
"""

import time
import uuid
import hashlib
import pytest

from epistemicos.authorization import (
    _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN,
    AuthorizationAuthority,
    CapabilityRegistry,
    Policy,
    Capability,
    HumanApprovalRecord,
    PrincipalVerifier,
    AuthenticatedPrincipal,
    get_callable_identity,
)
from epistemicos.provenance import (
    TrustedExecutionBoundary,
    LocalProvenanceStore,
    ExecutionContext,
)
from tests.unit.test_sec01_sec03_remediation import ExternalTestIdentityAuthority


@pytest.fixture
def auth_setup(tmp_path):
    """
    Standard test fixture providing an external IdP, a verifier configured with its public key,
    an AuthorizationAuthority, and an append-only provenance store.
    """
    test_idp = ExternalTestIdentityAuthority(issuer_id="TestIdP_Authority")
    verifier = PrincipalVerifier(trusted_public_keys={"TestIdP_Authority": test_idp.public_key})

    prov_store = LocalProvenanceStore(log_path=str(tmp_path / "provenance.jsonl"))
    boundary = TrustedExecutionBoundary(provenance_store=prov_store)

    policy = Policy(
        policy_id="pol-human-approval",
        allowed_operations={"deploy_ransomware_defense", "wipe_database", "read_telemetry"},
        allowed_resources={"cluster_primary", "db_primary", "telemetry_endpoint"},
        required_human_approval_operations={"wipe_database", "deploy_ransomware_defense"},
        allowed_approvers={"security_lead_alice", "ciso_carol"},
        tenant_domain="enterprise-defense-corp"
    )

    authority = AuthorizationAuthority(
        default_policy=policy,
        principal_provider=verifier,
        registry=CapabilityRegistry()
    )
    boundary.authority = authority
    boundary.registry = authority.registry

    return {
        "test_idp": test_idp,
        "verifier": verifier,
        "boundary": boundary,
        "authority": authority,
        "policy": policy,
        "prov_store": prov_store,
    }


# =====================================================================
# Test A: Valid signature, unverified authority (Central Regression Test)
# =====================================================================

def test_a_valid_signature_unverified_authority_rejected(auth_setup):
    """
    Test A (Central Acceptance Criterion):
    Construct a structurally valid approval with a valid HMAC signature made with the legitimate
    approval signing secret. Supply an approver identity that has NOT been independently verified
    (i.e. missing or unverified approver_assertion).
    Attempt to authorize an approval-required operation.
    Assert denial, no capability issuance, and no authorization success.
    """
    authority = auth_setup["authority"]
    policy = auth_setup["policy"]
    req_id = str(uuid.uuid4())
    digest = hashlib.sha256(b"wipe_database_args").hexdigest()

    # Approver claims to be "security_lead_alice" (which is in allowed_approvers),
    # signed with legitimate authority.approval_signing_secret,
    # but does NOT provide an independently verifiable AuthenticatedPrincipal assertion.
    approval = HumanApprovalRecord(
        approval_id="APP-TEST-A",
        approver_id="security_lead_alice",
        action_name="wipe_database",
        target="db_primary",
        action_digest=digest,
        request_id=req_id,
        requesting_principal="agent_bob",
        approver_assertion=None  # Unverified claim!
    )
    approval.sign(authority.approval_signing_secret)
    assert approval.verify_signature(authority.approval_signing_secret) is True

    cap, reason = authority.evaluate_and_issue_capability(
        action_name="wipe_database",
        target="db_primary",
        canonical_request_digest=digest,
        principal_id="agent_bob",
        request_id=req_id,
        human_approval_input=approval,
        policy=policy
    )

    assert cap is None
    assert reason == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_MISSING_APPROVER_ASSERTION"


# =====================================================================
# Test B: Valid signature, unauthorized approver under applicable policy
# =====================================================================

def test_b_valid_signature_unauthorized_approver_rejected(auth_setup):
    """
    Test B:
    Approver identity is independently authenticated by the trusted IdP, but the principal
    is not authorized to approve under policy.allowed_approvers.
    Assert denial.
    """
    authority = auth_setup["authority"]
    policy = auth_setup["policy"]
    test_idp = auth_setup["test_idp"]
    req_id = str(uuid.uuid4())
    digest = hashlib.sha256(b"wipe_database_args").hexdigest()

    # Authenticate "intern_dave" via test_idp
    intern_assertion = test_idp.issue_principal("intern_dave")

    approval = HumanApprovalRecord(
        approval_id="APP-TEST-B",
        approver_id="intern_dave",
        action_name="wipe_database",
        target="db_primary",
        action_digest=digest,
        request_id=req_id,
        requesting_principal="agent_bob",
        approver_assertion=intern_assertion
    )
    approval.sign(authority.approval_signing_secret)

    cap, reason = authority.evaluate_and_issue_capability(
        action_name="wipe_database",
        target="db_primary",
        canonical_request_digest=digest,
        principal_id="agent_bob",
        request_id=req_id,
        human_approval_input=approval,
        policy=policy
    )

    assert cap is None
    assert "UNAUTHORIZED_APPROVER" in reason or "UNTRUSTED_APPROVER" in reason
    assert "intern_dave" in reason


# =====================================================================
# Test C: Valid approver, wrong operation / action mismatch
# =====================================================================

def test_c_valid_approver_wrong_operation_rejected(auth_setup):
    """
    Test C:
    Approver is authenticated and authorized, but the requested action differs from the approval.
    Assert denial at issuance.
    """
    authority = auth_setup["authority"]
    policy = auth_setup["policy"]
    test_idp = auth_setup["test_idp"]
    req_id = str(uuid.uuid4())
    digest = hashlib.sha256(b"wipe_database_args").hexdigest()

    alice_assertion = test_idp.issue_principal("security_lead_alice")

    # Approval was granted for "deploy_ransomware_defense"
    approval = HumanApprovalRecord(
        approval_id="APP-TEST-C",
        approver_id="security_lead_alice",
        action_name="deploy_ransomware_defense",
        target="cluster_primary",
        action_digest=digest,
        request_id=req_id,
        requesting_principal="agent_bob",
        approver_assertion=alice_assertion
    )
    approval.sign(authority.approval_signing_secret)

    # Attempt to use for "wipe_database"
    cap, reason = authority.evaluate_and_issue_capability(
        action_name="wipe_database",
        target="cluster_primary",
        canonical_request_digest=digest,
        principal_id="agent_bob",
        request_id=req_id,
        human_approval_input=approval,
        policy=policy
    )

    assert cap is None
    assert reason == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_BINDING_MISMATCH"


# =====================================================================
# Test D: Valid approver, wrong target or resource scope mismatch
# =====================================================================

def test_d_valid_approver_wrong_target_rejected(auth_setup):
    """
    Test D:
    Approver is authenticated and authorized, but target resource differs from the approval.
    Assert denial at issuance.
    """
    authority = auth_setup["authority"]
    policy = auth_setup["policy"]
    test_idp = auth_setup["test_idp"]
    req_id = str(uuid.uuid4())
    digest = hashlib.sha256(b"wipe_database_args").hexdigest()

    alice_assertion = test_idp.issue_principal("security_lead_alice")

    approval = HumanApprovalRecord(
        approval_id="APP-TEST-D",
        approver_id="security_lead_alice",
        action_name="wipe_database",
        target="db_staging",  # Approved for staging only
        action_digest=digest,
        request_id=req_id,
        requesting_principal="agent_bob",
        approver_assertion=alice_assertion
    )
    approval.sign(authority.approval_signing_secret)

    # Requested against db_primary
    cap, reason = authority.evaluate_and_issue_capability(
        action_name="wipe_database",
        target="db_primary",
        canonical_request_digest=digest,
        principal_id="agent_bob",
        request_id=req_id,
        human_approval_input=approval,
        policy=policy
    )

    assert cap is None
    assert reason == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_BINDING_MISMATCH"


# =====================================================================
# Test E: Valid approver, wrong requesting principal or task
# =====================================================================

def test_e_valid_approver_wrong_requesting_principal_or_task_rejected(auth_setup):
    """
    Test E:
    Attempt to reuse a valid approval under a different requesting principal or task context.
    Assert denial.
    """
    authority = auth_setup["authority"]
    policy = auth_setup["policy"]
    test_idp = auth_setup["test_idp"]
    req_id = str(uuid.uuid4())
    digest = hashlib.sha256(b"wipe_database_args").hexdigest()

    alice_assertion = test_idp.issue_principal("security_lead_alice")

    # Approval bound to requester "agent_bob" and task "TASK-ALPHA"
    approval = HumanApprovalRecord(
        approval_id="APP-TEST-E",
        approver_id="security_lead_alice",
        action_name="wipe_database",
        target="db_primary",
        action_digest=digest,
        request_id=req_id,
        task_id="TASK-ALPHA",
        requesting_principal="agent_bob",
        approver_assertion=alice_assertion
    )
    approval.sign(authority.approval_signing_secret)

    # Attempt 1: Wrong requesting principal "agent_eve"
    cap_eve, reason_eve = authority.evaluate_and_issue_capability(
        action_name="wipe_database",
        target="db_primary",
        canonical_request_digest=digest,
        principal_id="agent_eve",
        request_id=req_id,
        task_id="TASK-ALPHA",
        human_approval_input=approval,
        policy=policy
    )
    assert cap_eve is None
    assert "REQUESTING_PRINCIPAL_MISMATCH" in reason_eve

    # Attempt 2: Wrong task ID "TASK-OMEGA"
    cap_task, reason_task = authority.evaluate_and_issue_capability(
        action_name="wipe_database",
        target="db_primary",
        canonical_request_digest=digest,
        principal_id="agent_bob",
        request_id=req_id,
        task_id="TASK-OMEGA",
        human_approval_input=approval,
        policy=policy
    )
    assert cap_task is None
    assert "TASK_ID_MISMATCH" in reason_task

    # Attempt 3: Missing requesting principal in approval record
    app_no_req = HumanApprovalRecord(
        approval_id="APP-TEST-E-NO-REQ",
        approver_id="security_lead_alice",
        action_name="wipe_database",
        target="db_primary",
        action_digest=digest,
        request_id=req_id,
        task_id="TASK-ALPHA",
        requesting_principal=None,
        approver_assertion=alice_assertion
    )
    app_no_req.sign(authority.approval_signing_secret)
    cap_no_req, reason_no_req = authority.evaluate_and_issue_capability(
        action_name="wipe_database",
        target="db_primary",
        canonical_request_digest=digest,
        principal_id="agent_bob",
        request_id=req_id,
        task_id="TASK-ALPHA",
        human_approval_input=app_no_req,
        policy=policy
    )
    assert cap_no_req is None
    assert reason_no_req == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_MISSING_REQUESTING_PRINCIPAL"

    # Attempt 4: Empty / whitespace requesting principal in approval record
    app_ws_req = HumanApprovalRecord(
        approval_id="APP-TEST-E-WS-REQ",
        approver_id="security_lead_alice",
        action_name="wipe_database",
        target="db_primary",
        action_digest=digest,
        request_id=req_id,
        task_id="TASK-ALPHA",
        requesting_principal="   ",
        approver_assertion=alice_assertion
    )
    app_ws_req.sign(authority.approval_signing_secret)
    cap_ws_req, reason_ws_req = authority.evaluate_and_issue_capability(
        action_name="wipe_database",
        target="db_primary",
        canonical_request_digest=digest,
        principal_id="agent_bob",
        request_id=req_id,
        task_id="TASK-ALPHA",
        human_approval_input=app_ws_req,
        policy=policy
    )
    assert cap_ws_req is None
    assert reason_ws_req == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_MISSING_REQUESTING_PRINCIPAL"

    # Attempt 5: Missing task ID in approval when request has effective task ID
    app_no_task = HumanApprovalRecord(
        approval_id="APP-TEST-E-NO-TASK",
        approver_id="security_lead_alice",
        action_name="wipe_database",
        target="db_primary",
        action_digest=digest,
        request_id=req_id,
        task_id=None,
        requesting_principal="agent_bob",
        approver_assertion=alice_assertion
    )
    app_no_task.sign(authority.approval_signing_secret)
    cap_no_task, reason_no_task = authority.evaluate_and_issue_capability(
        action_name="wipe_database",
        target="db_primary",
        canonical_request_digest=digest,
        principal_id="agent_bob",
        request_id=req_id,
        task_id="TASK-ALPHA",
        human_approval_input=app_no_task,
        policy=policy
    )
    assert cap_no_task is None
    assert reason_no_task == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_MISSING_TASK_ID"

    # Attempt 6: Empty / whitespace task ID in approval when request has effective task ID
    app_ws_task = HumanApprovalRecord(
        approval_id="APP-TEST-E-WS-TASK",
        approver_id="security_lead_alice",
        action_name="wipe_database",
        target="db_primary",
        action_digest=digest,
        request_id=req_id,
        task_id="   ",
        requesting_principal="agent_bob",
        approver_assertion=alice_assertion
    )
    app_ws_task.sign(authority.approval_signing_secret)
    cap_ws_task, reason_ws_task = authority.evaluate_and_issue_capability(
        action_name="wipe_database",
        target="db_primary",
        canonical_request_digest=digest,
        principal_id="agent_bob",
        request_id=req_id,
        task_id="TASK-ALPHA",
        human_approval_input=app_ws_task,
        policy=policy
    )
    assert cap_ws_task is None
    assert reason_ws_task == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_MISSING_TASK_ID"


# =====================================================================
# Test F: Valid approval - Complete end-to-end authorization path
# =====================================================================

def test_f_valid_approval_end_to_end_success(auth_setup):
    """
    Test F:
    - Authenticated and authorized approver.
    - Exact matching requesting principal, task, action, target, scope, and digest.
    - Valid HMAC signature and unconsumed approval.
    - Assert capability issuance succeeds, carries approver provenance, passes verify_capability,
      and executes successfully at execution boundary.
    """
    authority = auth_setup["authority"]
    boundary = auth_setup["boundary"]
    policy = auth_setup["policy"]
    test_idp = auth_setup["test_idp"]

    req_id = str(uuid.uuid4())
    corr_id = str(uuid.uuid4())
    raw_payload = {"command": "wipe_tables", "scope": "db_primary"}
    digest = boundary.compute_canonical_digest(raw_payload)

    side_effect = [0]

    def safe_wipe_exec():
        side_effect[0] += 1
        return {"status": "SUCCESS"}

    exec_qual_id = get_callable_identity(safe_wipe_exec)
    authority.register_executor(exec_qual_id, safe_wipe_exec)

    alice_assertion = test_idp.issue_principal("security_lead_alice")
    bob_assertion = test_idp.issue_principal("agent_bob")

    approval = HumanApprovalRecord(
        approval_id="APP-TEST-F",
        approver_id="security_lead_alice",
        action_name="wipe_database",
        target="db_primary",
        action_digest=digest,
        request_id=req_id,
        task_id="TASK-PROD-1",
        requesting_principal="agent_bob",
        approver_assertion=alice_assertion
    )
    approval.sign(authority.approval_signing_secret)

    # 1. Issuance
    cap, reason = authority.evaluate_and_issue_capability(
        action_name="wipe_database",
        target="db_primary",
        canonical_request_digest=digest,
        principal_id=bob_assertion,
        correlation_id=corr_id,
        request_id=req_id,
        task_id="TASK-PROD-1",
        executor_id=exec_qual_id,
        human_approval_input=approval,
        policy=policy
    )

    assert cap is not None
    assert reason == "AUTHORIZATION_GRANTED"
    assert cap.approver_principal == "security_lead_alice"
    assert cap.approver_provenance is not None
    assert cap.approver_provenance["approver_id"] == "security_lead_alice"
    assert cap.approver_provenance["issuer_id"] == "TestIdP_Authority"

    # 2. Downstream Capability Verification
    verified, v_reason, verified_cap = authority.verify_capability(
        token_id=cap.token_id,
        action_name="wipe_database",
        target="db_primary",
        canonical_request_digest=digest,
        executor_id=exec_qual_id,
        principal_id=bob_assertion,
        correlation_id=corr_id,
        request_id=req_id,
        task_id="TASK-PROD-1"
    )
    assert verified is True
    assert v_reason == "CAPABILITY_VERIFIED"
    assert verified_cap is not None

    # 3. Execution at TrustedExecutionBoundary
    ctx = ExecutionContext(
        correlation_id=corr_id,
        request_id=req_id,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authenticated_principal=bob_assertion
    )

    result = boundary.execute_protected_action(
        action_name="wipe_database",
        target="db_primary",
        request_payload=raw_payload,
        executor_func=safe_wipe_exec,
        context=ctx
    )

    assert result["status"] == "SUCCESS"
    assert side_effect[0] == 1


# =====================================================================
# Test G: Missing or malformed provenance fails closed
# =====================================================================

def test_g_missing_or_malformed_provenance_fails_closed(auth_setup):
    """
    Test G:
    - Missing identity-verification evidence.
    - Forged / invalid signature on approver assertion.
    - Expired approver assertion.
    - Mismatched claimed approver_id vs verified assertion principal.
    - Missing Authority PrincipalVerifier.
    Assert fail-closed behavior for all cases.
    """
    authority = auth_setup["authority"]
    policy = auth_setup["policy"]
    test_idp = auth_setup["test_idp"]
    digest = hashlib.sha256(b"wipe_database_args").hexdigest()

    # Case 1: Forged Ed25519 signature on assertion
    bad_sig_assertion = AuthenticatedPrincipal(
        principal_id="security_lead_alice",
        issuer_id="TestIdP_Authority",
        timestamp=time.time(),
        signature="deadbeef" * 16  # Invalid signature
    )
    app1 = HumanApprovalRecord(
        approval_id="APP-G-1",
        approver_id="security_lead_alice",
        action_name="wipe_database",
        target="db_primary",
        action_digest=digest,
        request_id="req-g-1",
        requesting_principal="agent_bob",
        approver_assertion=bad_sig_assertion
    )
    app1.sign(authority.approval_signing_secret)
    cap1, reason1 = authority.evaluate_and_issue_capability(
        action_name="wipe_database", target="db_primary", canonical_request_digest=digest,
        principal_id="agent_bob", request_id="req-g-1", human_approval_input=app1, policy=policy
    )
    assert cap1 is None
    assert "APPROVER_AUTHENTICATION_FAILED" in reason1

    # Case 2: Expired assertion
    expired_assertion = test_idp.issue_principal(
        "security_lead_alice",
        current_time=time.time() - 7200,
        expires_at=time.time() - 3600
    )
    app2 = HumanApprovalRecord(
        approval_id="APP-G-2",
        approver_id="security_lead_alice",
        action_name="wipe_database",
        target="db_primary",
        action_digest=digest,
        request_id="req-g-2",
        requesting_principal="agent_bob",
        approver_assertion=expired_assertion
    )
    app2.sign(authority.approval_signing_secret)
    cap2, reason2 = authority.evaluate_and_issue_capability(
        action_name="wipe_database", target="db_primary", canonical_request_digest=digest,
        principal_id="agent_bob", request_id="req-g-2", human_approval_input=app2, policy=policy
    )
    assert cap2 is None
    assert "APPROVER_AUTHENTICATION_FAILED" in reason2

    # Case 3: Approver ID spoofing (claims "ciso_carol" but assertion is for "security_lead_alice")
    alice_assertion = test_idp.issue_principal("security_lead_alice")
    app3 = HumanApprovalRecord(
        approval_id="APP-G-3",
        approver_id="ciso_carol",
        action_name="wipe_database",
        target="db_primary",
        action_digest=digest,
        request_id="req-g-3",
        requesting_principal="agent_bob",
        approver_assertion=alice_assertion
    )
    app3.sign(authority.approval_signing_secret)
    cap3, reason3 = authority.evaluate_and_issue_capability(
        action_name="wipe_database", target="db_primary", canonical_request_digest=digest,
        principal_id="agent_bob", request_id="req-g-3", human_approval_input=app3, policy=policy
    )
    assert cap3 is None
    assert "APPROVER_ID_MISMATCH" in reason3

    # Case 4: Authority has no configured PrincipalVerifier
    unconfigured_authority = AuthorizationAuthority(default_policy=policy, principal_provider=None)
    app4 = HumanApprovalRecord(
        approval_id="APP-G-4",
        approver_id="security_lead_alice",
        action_name="wipe_database",
        target="db_primary",
        action_digest=digest,
        request_id="req-g-4",
        requesting_principal="agent_bob",
        approver_assertion=alice_assertion
    )
    app4.sign(unconfigured_authority.approval_signing_secret)
    cap4, reason4 = unconfigured_authority.evaluate_and_issue_capability(
        action_name="wipe_database", target="db_primary", canonical_request_digest=digest,
        principal_id="agent_bob", request_id="req-g-4", human_approval_input=app4, policy=policy
    )
    assert cap4 is None
    assert reason4 == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_NO_IDENTITY_PROVIDER_CONFIGURED"


# =====================================================================
# Test H: Replay and Mutation Protection
# =====================================================================

def test_h_replay_and_field_mutation_protection(auth_setup):
    """
    Test H:
    - Modifying any bound approval field (requester, task, target, action, digest) invalidates HMAC.
    - Attempting to consume an approval a second time triggers replay protection.
    - Modifying capability fields breaks downstream capability verification.
    """
    authority = auth_setup["authority"]
    boundary = auth_setup["boundary"]
    policy = auth_setup["policy"]
    test_idp = auth_setup["test_idp"]

    req_id = str(uuid.uuid4())
    corr_id = str(uuid.uuid4())
    raw_payload = {"action": "wipe"}
    digest = boundary.compute_canonical_digest(raw_payload)

    def exec_wipe():
        return {"status": "SUCCESS"}
    exec_qual_id = get_callable_identity(exec_wipe)
    authority.register_executor(exec_qual_id, exec_wipe)

    alice_assertion = test_idp.issue_principal("security_lead_alice")
    bob_assertion = test_idp.issue_principal("agent_bob")

    approval = HumanApprovalRecord(
        approval_id="APP-TEST-H",
        approver_id="security_lead_alice",
        action_name="wipe_database",
        target="db_primary",
        action_digest=digest,
        request_id=req_id,
        task_id="TASK-H",
        requesting_principal="agent_bob",
        approver_assertion=alice_assertion
    )
    approval.sign(authority.approval_signing_secret)

    # 1. Tamper with bound field after signing (substitute requesting principal)
    approval.requesting_principal = "agent_attacker"
    cap_tampered, reason_tampered = authority.evaluate_and_issue_capability(
        action_name="wipe_database", target="db_primary", canonical_request_digest=digest,
        principal_id="agent_attacker", request_id=req_id, task_id="TASK-H",
        human_approval_input=approval, policy=policy
    )
    assert cap_tampered is None
    assert reason_tampered == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_AUTHENTICATION_FAILED"

    # Restore legitimate field and re-sign
    approval.requesting_principal = "agent_bob"
    approval.sign(authority.approval_signing_secret)

    # 2. Legitimate issuance
    cap, reason = authority.evaluate_and_issue_capability(
        action_name="wipe_database", target="db_primary", canonical_request_digest=digest,
        principal_id=bob_assertion, correlation_id=corr_id, request_id=req_id, task_id="TASK-H",
        executor_id=exec_qual_id, human_approval_input=approval, policy=policy
    )
    assert cap is not None

    # 3. Downstream mutation: Tampering with approver_principal breaks capability signature
    cap.approver_principal = "forged_approver"
    v_ok, v_reason, _ = authority.verify_capability(
        token_id=cap.token_id, action_name="wipe_database", target="db_primary",
        canonical_request_digest=digest, executor_id=exec_qual_id, principal_id=bob_assertion,
        correlation_id=corr_id, request_id=req_id, task_id="TASK-H"
    )
    assert v_ok is False
    assert v_reason == "CAPABILITY_VERIFICATION_FAILED_INVALID_SIGNATURE"

    # Re-sign with forged approver_principal: semantic check rejects approver mismatch
    cap.signature = authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)
    v_ok_sem, v_reason_sem, _ = authority.verify_capability(
        token_id=cap.token_id, action_name="wipe_database", target="db_primary",
        canonical_request_digest=digest, executor_id=exec_qual_id, principal_id=bob_assertion,
        correlation_id=corr_id, request_id=req_id, task_id="TASK-H"
    )
    assert v_ok_sem is False
    assert "APPROVER_MISMATCH" in v_reason_sem
    cap.approver_principal = "security_lead_alice"
    cap.signature = authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)

    # 3b. Downstream mutation: Mutating approver_provenance fields invalidates capability signature
    orig_prov = dict(cap.approver_provenance)

    # Mutate approver_id
    cap.approver_provenance["approver_id"] = "forged_id"
    v_ok, v_reason, _ = authority.verify_capability(
        token_id=cap.token_id, action_name="wipe_database", target="db_primary",
        canonical_request_digest=digest, executor_id=exec_qual_id, principal_id=bob_assertion,
        correlation_id=corr_id, request_id=req_id, task_id="TASK-H"
    )
    assert v_ok is False
    assert v_reason == "CAPABILITY_VERIFICATION_FAILED_INVALID_SIGNATURE"
    cap.approver_provenance = dict(orig_prov)

    # Mutate issuer_id
    cap.approver_provenance["issuer_id"] = "forged_issuer"
    v_ok, v_reason, _ = authority.verify_capability(
        token_id=cap.token_id, action_name="wipe_database", target="db_primary",
        canonical_request_digest=digest, executor_id=exec_qual_id, principal_id=bob_assertion,
        correlation_id=corr_id, request_id=req_id, task_id="TASK-H"
    )
    assert v_ok is False
    assert v_reason == "CAPABILITY_VERIFICATION_FAILED_INVALID_SIGNATURE"
    cap.approver_provenance = dict(orig_prov)

    # Mutate assertion_timestamp
    cap.approver_provenance["assertion_timestamp"] = 999999.0
    v_ok, v_reason, _ = authority.verify_capability(
        token_id=cap.token_id, action_name="wipe_database", target="db_primary",
        canonical_request_digest=digest, executor_id=exec_qual_id, principal_id=bob_assertion,
        correlation_id=corr_id, request_id=req_id, task_id="TASK-H"
    )
    assert v_ok is False
    assert v_reason == "CAPABILITY_VERIFICATION_FAILED_INVALID_SIGNATURE"
    cap.approver_provenance = dict(orig_prov)

    # Mutate verified_at
    cap.approver_provenance["verified_at"] = 123456.0
    v_ok, v_reason, _ = authority.verify_capability(
        token_id=cap.token_id, action_name="wipe_database", target="db_primary",
        canonical_request_digest=digest, executor_id=exec_qual_id, principal_id=bob_assertion,
        correlation_id=corr_id, request_id=req_id, task_id="TASK-H"
    )
    assert v_ok is False
    assert v_reason == "CAPABILITY_VERIFICATION_FAILED_INVALID_SIGNATURE"
    cap.approver_provenance = dict(orig_prov)

    # 3c. Downstream mutation: Mutating attached HumanApprovalRecord invalidates signature
    cap.human_approval.approver_id = "attacker_approver"
    v_ok, v_reason, _ = authority.verify_capability(
        token_id=cap.token_id, action_name="wipe_database", target="db_primary",
        canonical_request_digest=digest, executor_id=exec_qual_id, principal_id=bob_assertion,
        correlation_id=corr_id, request_id=req_id, task_id="TASK-H"
    )
    assert v_ok is False
    assert v_reason == "CAPABILITY_VERIFICATION_FAILED_INVALID_SIGNATURE"
    cap.human_approval.approver_id = "security_lead_alice"

    # 3d. Downstream verification failure on missing requester or task bindings
    cap.human_approval.requesting_principal = None
    cap.human_approval.sign(authority.approval_signing_secret)
    cap.signature = authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)
    v_ok, v_reason, _ = authority.verify_capability(
        token_id=cap.token_id, action_name="wipe_database", target="db_primary",
        canonical_request_digest=digest, executor_id=exec_qual_id, principal_id=bob_assertion,
        correlation_id=corr_id, request_id=req_id, task_id="TASK-H"
    )
    assert v_ok is False
    assert "MISSING_REQUESTING_PRINCIPAL" in v_reason

    cap.human_approval.requesting_principal = "agent_bob"
    cap.human_approval.task_id = None
    cap.human_approval.sign(authority.approval_signing_secret)
    cap.signature = authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)
    v_ok, v_reason, _ = authority.verify_capability(
        token_id=cap.token_id, action_name="wipe_database", target="db_primary",
        canonical_request_digest=digest, executor_id=exec_qual_id, principal_id=bob_assertion,
        correlation_id=corr_id, request_id=req_id, task_id="TASK-H"
    )
    assert v_ok is False
    assert "MISSING_TASK_ID" in v_reason

    # Restore legitimate approval record and signature
    cap.human_approval.task_id = "TASK-H"
    cap.human_approval.sign(authority.approval_signing_secret)
    cap.signature = authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)

    # 3e. A correctly signed capability with internally inconsistent provenance is rejected
    cap.approver_provenance["issuer_id"] = "forged_issuer"
    cap.signature = authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)
    v_ok_incon, v_reason_incon, _ = authority.verify_capability(
        token_id=cap.token_id, action_name="wipe_database", target="db_primary",
        canonical_request_digest=digest, executor_id=exec_qual_id, principal_id=bob_assertion,
        correlation_id=corr_id, request_id=req_id, task_id="TASK-H"
    )
    assert v_ok_incon is False
    assert "PROVENANCE_ISSUER_MISMATCH" in v_reason_incon
    cap.approver_provenance = dict(orig_prov)
    cap.signature = authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)

    # 3e-2. Malformed assertion_timestamp rejection tests (missing, string, bool, NaN, +inf, -inf)
    import math
    for bad_ts in [None, "12345.67", True, False, float("nan"), float("inf"), float("-inf")]:
        cap.approver_provenance["assertion_timestamp"] = bad_ts
        cap.signature = authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)
        v_ok_ts, v_reason_ts, _ = authority.verify_capability(
            token_id=cap.token_id, action_name="wipe_database", target="db_primary",
            canonical_request_digest=digest, executor_id=exec_qual_id, principal_id=bob_assertion,
            correlation_id=corr_id, request_id=req_id, task_id="TASK-H"
        )
        assert v_ok_ts is False
        assert v_reason_ts == (
            "CAPABILITY_VERIFICATION_FAILED_HUMAN_APPROVAL_PROVENANCE_INVALID_ASSERTION_TIMESTAMP"
        )
    cap.approver_provenance = dict(orig_prov)
    cap.signature = authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)

    # 3f. Test valid persisted capability verification after serialization / reload
    cap_dict = cap.to_dict() if hasattr(cap, "to_dict") else cap.__dict__.copy()
    restored_cap = Capability._restore_from_storage(cap_dict, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)
    assert authority.registry._sign_capability_internal(restored_cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN) == restored_cap.signature
    v_ok_res, v_reason_res, _ = authority.verify_capability(
        token_id=restored_cap.token_id, action_name="wipe_database", target="db_primary",
        canonical_request_digest=digest, executor_id=exec_qual_id, principal_id=bob_assertion,
        correlation_id=corr_id, request_id=req_id, task_id="TASK-H"
    )
    assert v_ok_res is True
    assert v_reason_res == "CAPABILITY_VERIFIED"

    # 4. First execution consumes capability and approval
    ctx = ExecutionContext(
        correlation_id=corr_id, request_id=req_id, authorization_token_id=cap.token_id,
        authorized_digest=digest, authenticated_principal=bob_assertion
    )
    res = boundary.execute_protected_action(
        action_name="wipe_database", target="db_primary", request_payload=raw_payload,
        executor_func=exec_wipe, context=ctx
    )
    assert res["status"] == "SUCCESS"

    # 5. Replay attempt using same approval ID is rejected at issuance
    cap_replay, reason_replay = authority.evaluate_and_issue_capability(
        action_name="wipe_database", target="db_primary", canonical_request_digest=digest,
        principal_id=bob_assertion, request_id=req_id, task_id="TASK-H",
        human_approval_input=approval, policy=policy
    )
    assert cap_replay is None
    assert reason_replay == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_REPLAYED"
