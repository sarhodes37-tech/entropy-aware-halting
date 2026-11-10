"""
Focused Acceptance Tests for Phase 0.4.2 Stage A — Step 3:
Trusted Effective-Policy Resolution, Trusted Contract Resolution,
and Trusted Authorization-Basis Derivation.
"""

import copy
import time
import uuid
import pytest

from epistemicos.authorization import (
    Capability,
    Policy,
    TrustedTaskContract,
    HumanApprovalRecord,
    AuthorizationAuthority,
    PrincipalVerifier,
    build_capability_canonical_payload,
    _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN
)
from tests.unit.test_sec01_sec03_remediation import ExternalTestIdentityAuthority


@pytest.fixture
def test_setup():
    test_idp = ExternalTestIdentityAuthority(issuer_id="TestIdP_Authority")
    verifier = PrincipalVerifier(trusted_public_keys={"TestIdP_Authority": test_idp.public_key})

    policy = Policy(
        policy_id="pol-prod-sec",
        version="1.0.0",
        allowed_operations={"deploy_firmware", "query_status", "reboot_node"},
        allowed_resources={"/cluster/primary", "/status"},
        required_human_approval_operations={"deploy_firmware"},
        allowed_approvers={"ciso_carol", "sec_lead_alice"},
        tenant_domain="tenant-defense-corp"
    )

    authority = AuthorizationAuthority(
        default_policy=policy,
        principal_provider=verifier,
        tenant_domain="tenant-defense-corp"
    )

    return {
        "authority": authority,
        "policy": policy,
        "test_idp": test_idp,
        "verifier": verifier
    }


class TestEffectivePolicyResolution:
    """Verifies trusted effective-policy resolution and override protections."""

    def test_trusted_policy_resolution_for_correct_tenant(self, test_setup):
        authority = test_setup["authority"]
        test_idp = test_setup["test_idp"]
        p_assert = test_idp.issue_principal("operator_alice")
        cap, reason = authority.evaluate_and_issue_capability(
            action_name="query_status",
            target="/status",
            canonical_request_digest="1" * 64,
            principal_id=p_assert
        )
        assert cap is not None
        assert reason == "AUTHORIZATION_GRANTED"
        assert cap.policy_id == "pol-prod-sec"
        assert cap.tenant_domain == "tenant-defense-corp"
        assert cap.authorization_basis == "AUTONOMOUS"

    def test_caller_supplied_permissive_policy_cannot_override_trusted_policy(self, test_setup):
        """Caller presenting a modified permissive policy for registered policy_id is rejected."""
        authority = test_setup["authority"]
        test_idp = test_setup["test_idp"]
        p_assert = test_idp.issue_principal("operator_alice")
        malicious_policy = Policy(
            policy_id="pol-prod-sec",
            allowed_operations={"*"},
            allowed_resources={"*"},
            tenant_domain="tenant-defense-corp",
            version="2.0.0"  # Version mismatch vs trusted policy
        )
        cap, reason = authority.evaluate_and_issue_capability(
            action_name="query_status",
            target="/status",
            canonical_request_digest="1" * 64,
            principal_id=p_assert,
            policy=malicious_policy
        )
        assert cap is None
        assert reason == "AUTHORIZATION_DENIED_POLICY_TENANT_MISMATCH"

    def test_cross_tenant_policy_substitution_rejected(self, test_setup):
        """Policy with conflicting tenant domain is rejected immediately."""
        authority = test_setup["authority"]
        test_idp = test_setup["test_idp"]
        p_assert = test_idp.issue_principal("operator_alice")
        foreign_policy = Policy(
            policy_id="pol-foreign",
            allowed_operations={"query_status"},
            allowed_resources={"/status"},
            tenant_domain="foreign.tenant.attacker"
        )
        authority.register_policy(foreign_policy)

        cap, reason = authority.evaluate_and_issue_capability(
            action_name="query_status",
            target="/status",
            canonical_request_digest="1" * 64,
            principal_id=p_assert,
            policy=foreign_policy
        )
        assert cap is None
        assert reason == "AUTHORIZATION_DENIED_CROSS_TENANT_POLICY_REJECTED"

    def test_missing_trusted_identity_fails_closed(self):
        """Authority and policy with missing tenant domain fails closed."""
        no_tenant_policy = Policy(
            policy_id="pol-no-tenant",
            allowed_operations={"query_status"},
            allowed_resources={"/status"},
            tenant_domain=None
        )
        test_idp = ExternalTestIdentityAuthority(issuer_id="TestIdP_Authority")
        verifier = PrincipalVerifier(trusted_public_keys={"TestIdP_Authority": test_idp.public_key})
        p_assert = test_idp.issue_principal("operator_alice")
        authority = AuthorizationAuthority(default_policy=no_tenant_policy, principal_provider=verifier, tenant_domain=None)
        cap, reason = authority.evaluate_and_issue_capability(
            action_name="query_status",
            target="/status",
            canonical_request_digest="1" * 64,
            principal_id=p_assert
        )
        assert cap is None
        assert reason == "AUTHORIZATION_DENIED_MISSING_TENANT_DOMAIN"


class TestTrustedContractResolution:
    """Verifies trusted contract resolution, digest verification, and approval requirement inheritance."""

    def test_correct_trusted_contract_resolved(self, test_setup):
        authority = test_setup["authority"]
        test_idp = test_setup["test_idp"]
        p_assert = test_idp.issue_principal("operator_alice")
        contract = TrustedTaskContract(
            task_id="TASK-CORRECT-001",
            permitted_actions={"reboot_node"},
            resource_scope={"/cluster/primary"},
            tenant_domain="tenant-defense-corp"
        )
        contract.sign(authority.contract_signing_secret)
        authority.register_contract(contract)

        cap, reason = authority.evaluate_and_issue_capability(
            action_name="reboot_node",
            target="/cluster/primary",
            canonical_request_digest="2" * 64,
            principal_id=p_assert,
            task_id="TASK-CORRECT-001"
        )
        assert cap is not None
        assert reason == "AUTHORIZATION_GRANTED"
        assert cap.contract_id == "TASK-CORRECT-001"
        assert cap.contract_digest == contract.compute_contract_digest()
        assert cap.authorization_basis == "AUTONOMOUS"

    def test_contract_identity_mismatch_rejected(self, test_setup):
        authority = test_setup["authority"]
        test_idp = test_setup["test_idp"]
        p_assert = test_idp.issue_principal("operator_alice")
        trusted_contract = TrustedTaskContract(
            task_id="TASK-TRUSTED-10",
            permitted_actions={"reboot_node"},
            resource_scope={"/cluster/primary"},
            tenant_domain="tenant-defense-corp"
        )
        trusted_contract.sign(authority.contract_signing_secret)
        authority.register_contract(trusted_contract)

        caller_contract = TrustedTaskContract(
            task_id="TASK-CALLER-FORGED",
            permitted_actions={"reboot_node"},
            resource_scope={"/cluster/primary"},
            tenant_domain="tenant-defense-corp"
        )
        cap, reason = authority.evaluate_and_issue_capability(
            action_name="reboot_node",
            target="/cluster/primary",
            canonical_request_digest="2" * 64,
            principal_id=p_assert,
            task_id="TASK-TRUSTED-10",
            task_contract=caller_contract
        )
        assert cap is None
        assert reason == "AUTHORIZATION_DENIED_CONTRACT_IDENTITY_MISMATCH"

    def test_cross_tenant_contract_substitution_rejected(self, test_setup):
        authority = test_setup["authority"]
        test_idp = test_setup["test_idp"]
        p_assert = test_idp.issue_principal("operator_alice")
        foreign_contract = TrustedTaskContract(
            task_id="TASK-FOREIGN-01",
            permitted_actions={"reboot_node"},
            resource_scope={"/cluster/primary"},
            tenant_domain="foreign.tenant.domain"
        )
        foreign_contract.sign(authority.contract_signing_secret)
        authority.register_contract(foreign_contract)

        cap, reason = authority.evaluate_and_issue_capability(
            action_name="reboot_node",
            target="/cluster/primary",
            canonical_request_digest="2" * 64,
            principal_id=p_assert,
            task_id="TASK-FOREIGN-01"
        )
        assert cap is None
        assert reason == "AUTHORIZATION_DENIED_CROSS_TENANT_CONTRACT_REJECTED"

    def test_contract_required_approval_under_permissive_policy_enforced(self, test_setup):
        """Even if policy does not require approval for reboot_node, bound contract requires it."""
        authority = test_setup["authority"]
        # In policy: reboot_node is autonomous (not in required_human_approval_operations)
        # But in contract: reboot_node requires approval
        test_idp = test_setup["test_idp"]
        p_assert = test_idp.issue_principal("operator_alice")
        strict_contract = TrustedTaskContract(
            task_id="TASK-STRICT-01",
            permitted_actions={"reboot_node"},
            resource_scope={"/cluster/primary"},
            approval_requirements={"reboot_node"},
            tenant_domain="tenant-defense-corp"
        )
        strict_contract.sign(authority.contract_signing_secret)
        authority.register_contract(strict_contract)

        # Without approval input: cannot produce autonomous authorization
        cap, reason = authority.evaluate_and_issue_capability(
            action_name="reboot_node",
            target="/cluster/primary",
            canonical_request_digest="2" * 64,
            principal_id=p_assert,
            task_id="TASK-STRICT-01"
        )
        assert cap is None
        assert reason == "STOP_AND_ESCALATE_HUMAN_APPROVAL_REQUIRED"


class TestAuthorizationBasisDerivationAndIntegrity:
    """Verifies trusted derivation of AUTONOMOUS vs HUMAN_APPROVED and assignment integrity."""

    def test_autonomous_basis_derived_when_approval_not_required(self, test_setup):
        authority = test_setup["authority"]
        test_idp = test_setup["test_idp"]
        p_assert = test_idp.issue_principal("operator_alice")
        cap, reason = authority.evaluate_and_issue_capability(
            action_name="query_status",
            target="/status",
            canonical_request_digest="3" * 64,
            principal_id=p_assert
        )
        assert cap is not None
        assert reason == "AUTHORIZATION_GRANTED"
        assert cap.authorization_basis == "AUTONOMOUS"

        # Canonical signature binds AUTONOMOUS
        payload = build_capability_canonical_payload(cap)
        assert b'"authorization_basis":"AUTONOMOUS"' in payload

    def test_human_approved_basis_derived_on_verified_approval(self, test_setup):
        authority = test_setup["authority"]
        test_idp = test_setup["test_idp"]
        ciso_assertion = test_idp.issue_principal("ciso_carol")
        agent_assertion = test_idp.issue_principal("agent_operator")

        digest = "4" * 64
        req_id = str(uuid.uuid4())
        corr_id = str(uuid.uuid4())

        approval = HumanApprovalRecord(
            approval_id="APP-DERIVE-001",
            approver_id="ciso_carol",
            action_name="deploy_firmware",
            target="/cluster/primary",
            action_digest=digest,
            request_id=req_id,
            requesting_principal="agent_operator",
            approver_assertion=ciso_assertion,
            tenant_domain="tenant-defense-corp"
        )
        approval.sign(authority.approval_signing_secret)

        cap, reason = authority.evaluate_and_issue_capability(
            action_name="deploy_firmware",
            target="/cluster/primary",
            canonical_request_digest=digest,
            principal_id=agent_assertion,
            correlation_id=corr_id,
            request_id=req_id,
            human_approval_input=approval
        )
        assert cap is not None
        assert reason == "AUTHORIZATION_GRANTED"
        assert cap.authorization_basis == "HUMAN_APPROVED"

        # Canonical signature binds HUMAN_APPROVED
        payload = build_capability_canonical_payload(cap)
        assert b'"authorization_basis":"HUMAN_APPROVED"' in payload

    def test_missing_approval_cannot_produce_autonomous_fallback(self, test_setup):
        authority = test_setup["authority"]
        test_idp = test_setup["test_idp"]
        p_assert = test_idp.issue_principal("operator_alice")
        cap, reason = authority.evaluate_and_issue_capability(
            action_name="deploy_firmware",
            target="/cluster/primary",
            canonical_request_digest="5" * 64,
            principal_id=p_assert
        )
        assert cap is None
        assert reason == "STOP_AND_ESCALATE_HUMAN_APPROVAL_REQUIRED"

    def test_caller_selected_basis_values_rejected(self):
        """Callers cannot select basis values directly."""
        kwargs = {
            "token_id": "AUTH-CAP-NO-CALLER-BASIS",
            "principal_id": "user1",
            "correlation_id": "c1",
            "request_id": "r1",
            "action_name": "op1",
            "target": "/t",
            "canonical_request_digest": "6" * 64,
            "executor_id": "exec",
            "policy_version": "1.0",
            "created_at": 100.0,
            "expires_at": 200.0,
            "tenant_domain": "tenant1",
            "policy_id": "pol1",
            "authorization_basis": "AUTONOMOUS"  # Caller trying to select
        }
        with pytest.raises(ValueError, match="Caller authorization_basis selection prohibited"):
            Capability(**kwargs)

        kwargs["authorization_basis"] = "HUMAN_APPROVED"
        with pytest.raises(ValueError, match="Caller authorization_basis selection prohibited"):
            Capability(**kwargs)

    def test_post_construction_caller_mutation_rejected(self, test_setup):
        authority = test_setup["authority"]
        test_idp = test_setup["test_idp"]
        p_assert = test_idp.issue_principal("operator_alice")
        cap, _ = authority.evaluate_and_issue_capability(
            action_name="query_status",
            target="/status",
            canonical_request_digest="7" * 64,
            principal_id=p_assert
        )
        assert cap is not None
        assert cap.authorization_basis == "AUTONOMOUS"

        # Attempting post-construction mutation raises PermissionError
        with pytest.raises(PermissionError, match="Direct mutation of authorization_basis is prohibited"):
            cap.authorization_basis = "HUMAN_APPROVED"


class TestIndependentApprovalVerification:
    """Verifies approval verification constraints under Step 3."""

    def test_cross_tenant_approval_rejected(self, test_setup):
        authority = test_setup["authority"]
        test_idp = test_setup["test_idp"]
        ciso_assertion = test_idp.issue_principal("ciso_carol")
        agent_assertion = test_idp.issue_principal("agent_operator")

        digest = "8" * 64
        req_id = str(uuid.uuid4())
        corr_id = str(uuid.uuid4())

        approval = HumanApprovalRecord(
            approval_id="APP-CROSS-TENANT",
            approver_id="ciso_carol",
            action_name="deploy_firmware",
            target="/cluster/primary",
            action_digest=digest,
            request_id=req_id,
            requesting_principal="agent_operator",
            approver_assertion=ciso_assertion,
            tenant_domain="cross.tenant.attacker"  # Mismatch!
        )
        approval.sign(authority.approval_signing_secret)

        cap, reason = authority.evaluate_and_issue_capability(
            action_name="deploy_firmware",
            target="/cluster/primary",
            canonical_request_digest=digest,
            principal_id=agent_assertion,
            correlation_id=corr_id,
            request_id=req_id,
            human_approval_input=approval
        )
        assert cap is None
        assert reason == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_CROSS_TENANT_MISMATCH"

    def test_wildcard_approver_rejected_by_default(self, test_setup):
        """Authority has allow_wildcard_approver=False by default."""
        test_idp = test_setup["test_idp"]
        bob_assertion = test_idp.issue_principal("approver_bob")
        agent_assertion = test_idp.issue_principal("agent_operator")

        wildcard_policy = Policy(
            policy_id="pol-wildcard-appr",
            allowed_operations={"deploy_firmware"},
            allowed_resources={"/cluster/primary"},
            required_human_approval_operations={"deploy_firmware"},
            allowed_approvers={"*"},  # Wildcard approver
            tenant_domain="tenant-defense-corp"
        )
        authority = AuthorizationAuthority(
            default_policy=wildcard_policy,
            principal_provider=test_setup["verifier"],
            tenant_domain="tenant-defense-corp"
        )
        assert authority.allow_wildcard_approver is False

        digest = "9" * 64
        req_id = str(uuid.uuid4())
        approval = HumanApprovalRecord(
            approval_id="APP-WILDCARD",
            approver_id="approver_bob",
            action_name="deploy_firmware",
            target="/cluster/primary",
            action_digest=digest,
            request_id=req_id,
            requesting_principal="agent_operator",
            approver_assertion=bob_assertion,
            tenant_domain="tenant-defense-corp"
        )
        approval.sign(authority.approval_signing_secret)

        cap, reason = authority.evaluate_and_issue_capability(
            action_name="deploy_firmware",
            target="/cluster/primary",
            canonical_request_digest=digest,
            principal_id=agent_assertion,
            request_id=req_id,
            human_approval_input=approval
        )
        assert cap is None
        assert reason == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_WILDCARD_APPROVER_RESTRICTED"
