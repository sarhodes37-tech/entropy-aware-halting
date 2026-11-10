"""
Focused Acceptance Tests for Phase 0.4.2 Stage A — Step 2:
Canonical JSON Capability Signature Generation and Verification.
"""

import copy
import json
import time
import pytest

from epistemicos.authorization import (
    _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN,
    Capability,
    Policy,
    HumanApprovalRecord,
    AuthorizationAuthority,
    build_capability_canonical_payload,
    compute_capability_approval_binding_digest,
    canonicalize_fencing_scope
)


def _sample_capability():
    return Capability(
        token_id="AUTH-CAP-SIG-TEST-001",
        principal_id="principal_alice",
        correlation_id="corr-sig-001",
        request_id="req-sig-001",
        action_name="execute_transfer",
        target="/vault/transfer",
        canonical_request_digest="d" * 64,
        executor_id="default_executor",
        policy_version="1.0.0",
        created_at=1000.0,
        expires_at=1300.0,
        tenant_domain="tenant.sig.internal",
        policy_id="pol-sig-v1",
        contract_id=None,
        task_id="TASK-SIG-100",
        contract_version="1.0.0",
        contract_digest="c" * 64,
        authorization_basis=None,
        fencing_token=1,
        scope_key="task:TASK-SIG-100|target::/vault/transfer"
    )


class TestCanonicalJsonSerializationProperties:
    """Proves deterministic canonical JSON serialization properties."""

    def test_key_insertion_order_invariance(self):
        """Proves equivalent dictionaries with different key insertion orders produce bit-for-bit identical canonical JSON."""
        d1 = {
            "token_id": "tok1",
            "action_name": "op1",
            "tenant_domain": "tenant1",
            "expires_at": 100.0,
            "contract_id": None
        }
        # Inverted insertion order
        d2 = {
            "contract_id": None,
            "expires_at": 100.0,
            "tenant_domain": "tenant1",
            "action_name": "op1",
            "token_id": "tok1"
        }
        b1 = json.dumps(d1, sort_keys=True, separators=(",", ":")).encode("utf-8")
        b2 = json.dumps(d2, sort_keys=True, separators=(",", ":")).encode("utf-8")
        assert b1 == b2

    def test_delimiter_containing_values_cannot_cause_ambiguity(self):
        """Colon, comma, newline, quote delimiters in values cannot cause delimiter concatenation collisions."""
        authority = AuthorizationAuthority(tenant_domain="tenant.sig.internal")
        cap1 = _sample_capability()
        cap1.action_name = "action:name:with:colons"
        cap1.target = "/target,with,commas"

        cap2 = _sample_capability()
        cap2.action_name = "action"
        cap2.target = "name:with:colons:/target,with,commas"

        payload1 = build_capability_canonical_payload(cap1)
        payload2 = build_capability_canonical_payload(cap2)
        assert payload1 != payload2

        sig1 = authority.registry._sign_capability_internal(cap1, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)
        sig2 = authority.registry._sign_capability_internal(cap2, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)
        assert sig1 != sig2

    def test_signing_and_verification_use_identical_canonical_serialization(self):
        """Verifies that signing and verification share the single canonical payload builder."""
        authority = AuthorizationAuthority(tenant_domain="tenant.sig.internal")
        policy = Policy(
            policy_id="pol-sig-v1",
            allowed_operations={"execute_transfer"},
            allowed_resources={"/vault/transfer"},
            tenant_domain="tenant.sig.internal"
        )
        authority.default_policy = policy

        cap, reason = authority.evaluate_and_issue_capability(
            action_name="execute_transfer",
            target="/vault/transfer",
            canonical_request_digest="d" * 64,
            principal_id="principal_alice",
            correlation_id="corr-sig-001",
            request_id="req-sig-001",
            task_id="TASK-SIG-100"
        )
        assert cap is not None
        assert reason == "AUTHORIZATION_GRANTED"

        # The signature generated during issuance matches the signature computed directly from canonical bytes
        expected_sig = authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)
        assert cap.signature == expected_sig

        # Verification uses the exact same signature computation and succeeds
        valid, v_reason, verified_cap = authority.verify_capability(
            token_id=cap.token_id,
            action_name="execute_transfer",
            target="/vault/transfer",
            canonical_request_digest="d" * 64,
            executor_id="default_executor",
            principal_id="principal_alice",
            correlation_id="corr-sig-001",
            request_id="req-sig-001",
            task_id="TASK-SIG-100"
        )
        assert valid is True
        assert v_reason == "CAPABILITY_VERIFIED"


class TestAllBoundFieldsAffectSignatureIndependently:
    """Proves that bound fields independently change the HMAC signature."""

    def test_bound_fields_independently_change_signature(self):
        authority = AuthorizationAuthority(tenant_domain="tenant.sig.internal")
        base_cap = _sample_capability()
        base_sig = authority.registry._sign_capability_internal(base_cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)

        mutations = [
            ("token_id", "AUTH-CAP-MUTATED"),
            ("principal_id", "principal_bob"),
            ("correlation_id", "corr-mutated"),
            ("request_id", "req-mutated"),
            ("task_id", "TASK-MUTATED-999"),
            ("action_name", "execute_other_action"),
            ("target", "/other/target"),
            ("canonical_request_digest", "e" * 64),
            ("executor_id", "other_executor"),
            ("tenant_domain", "other.tenant.domain"),
            ("policy_id", "other-policy-id"),
            ("policy_version", "2.0.0"),
            ("contract_id", "CONTRACT-NEW-123"),
            ("contract_version", "2.0.0"),
            ("contract_digest", "f" * 64),
            ("expires_at", 2000.0),
            ("fencing_token", 2),
            ("scope_key", "custom_scope_key_mutation"),
            ("issuer_id", "AlternativeIssuer")
        ]

        for field_name, new_val in mutations:
            mutated_cap = copy.copy(base_cap)
            setattr(mutated_cap, field_name, new_val)
            mutated_sig = authority.registry._sign_capability_internal(mutated_cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)
            assert mutated_sig != base_sig, f"Field {field_name} failed to change capability signature!"

    def test_null_and_non_null_optional_values_produce_distinct_signatures(self):
        """Optional fields produce distinct signatures between None (JSON null) and non-null values."""
        authority = AuthorizationAuthority(tenant_domain="tenant.sig.internal")
        base_cap = _sample_capability()

        # contract_id: None vs "CONTRACT-01"
        base_cap.contract_id = None
        sig_none = authority.registry._sign_capability_internal(base_cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)

        base_cap.contract_id = "CONTRACT-01"
        sig_bound = authority.registry._sign_capability_internal(base_cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)
        assert sig_none != sig_bound

        # contract_digest: None vs "digest"
        base_cap.contract_digest = None
        sig_dig_none = authority.registry._sign_capability_internal(base_cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)

        base_cap.contract_digest = "c" * 64
        sig_dig_bound = authority.registry._sign_capability_internal(base_cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)
        assert sig_dig_none != sig_dig_bound

    def test_distinct_contract_identity_task_identity_contract_digest(self):
        """Contract identity, contract version, contract digest, and task identity are independently bound."""
        authority = AuthorizationAuthority(tenant_domain="tenant.sig.internal")
        c1 = _sample_capability()
        c1.task_id = "TASK-01"
        c1.contract_id = "CONTRACT-01"
        c1.contract_version = "1.0.0"
        c1.contract_digest = "1" * 64
        sig1 = authority.registry._sign_capability_internal(c1, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)

        # Mutate contract_id only
        c2 = copy.copy(c1)
        c2.contract_id = "CONTRACT-02"
        assert authority.registry._sign_capability_internal(c2, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN) != sig1

        # Mutate task_id only
        c3 = copy.copy(c1)
        c3.task_id = "TASK-02"
        assert authority.registry._sign_capability_internal(c3, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN) != sig1

        # Mutate contract_version only
        c4 = copy.copy(c1)
        c4.contract_version = "1.0.1"
        assert authority.registry._sign_capability_internal(c4, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN) != sig1

        # Mutate contract_digest only
        c5 = copy.copy(c1)
        c5.contract_digest = "2" * 64
        assert authority.registry._sign_capability_internal(c5, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN) != sig1


class TestApprovalBindingDigestAndProvenanceTampering:
    """Proves approval record and approver provenance changes invalidate the capability signature."""

    def test_approval_record_mutation_invalidates_signature(self):
        authority = AuthorizationAuthority(tenant_domain="tenant.sig.internal")
        approval = HumanApprovalRecord(
            approval_id="APP-001",
            approver_id="security_officer_carol",
            action_name="execute_transfer",
            target="/vault/transfer",
            action_digest="d" * 64,
            request_id="req-sig-001",
            task_id="TASK-SIG-100",
            requesting_principal="principal_alice"
        )
        approval.sign(authority.approval_signing_secret)

        cap = _sample_capability()
        cap.human_approval = approval
        cap.approver_principal = "security_officer_carol"
        cap.approver_provenance = {
            "approver_id": "security_officer_carol",
            "issuer_id": "TrustedIdP",
            "assertion_timestamp": 1000.0,
            "verified_at": 1005.0,
            "approval_id": "APP-001"
        }
        sig_legit = authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)
        cap.signature = sig_legit

        # Mutate approval record action_name
        cap.human_approval.action_name = "different_action"
        sig_mutated = authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)
        assert sig_mutated != sig_legit

    def test_approver_provenance_mutation_invalidates_signature(self):
        authority = AuthorizationAuthority(tenant_domain="tenant.sig.internal")
        approval = HumanApprovalRecord(
            approval_id="APP-001",
            approver_id="security_officer_carol",
            action_name="execute_transfer",
            target="/vault/transfer",
            action_digest="d" * 64,
            request_id="req-sig-001",
            task_id="TASK-SIG-100",
            requesting_principal="principal_alice"
        )
        approval.sign(authority.approval_signing_secret)

        cap = _sample_capability()
        cap.human_approval = approval
        cap.approver_principal = "security_officer_carol"
        cap.approver_provenance = {
            "approver_id": "security_officer_carol",
            "issuer_id": "TrustedIdP",
            "assertion_timestamp": 1000.0,
            "verified_at": 1005.0,
            "approval_id": "APP-001"
        }
        sig_legit = authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)

        # Mutate approver_provenance verified_at
        cap.approver_provenance["verified_at"] = 9999.0
        sig_mutated = authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)
        assert sig_mutated != sig_legit

        # Mutate approver_principal
        cap.approver_provenance["verified_at"] = 1005.0
        cap.approver_principal = "unauthorized_approver"
        sig_mutated2 = authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)
        assert sig_mutated2 != sig_legit

    def test_verification_rejects_modified_capability(self):
        authority = AuthorizationAuthority(tenant_domain="tenant.sig.internal")
        policy = Policy(
            policy_id="pol-sig-v1",
            allowed_operations={"execute_transfer"},
            allowed_resources={"/vault/transfer"},
            tenant_domain="tenant.sig.internal"
        )
        authority.default_policy = policy

        cap, _ = authority.evaluate_and_issue_capability(
            action_name="execute_transfer",
            target="/vault/transfer",
            canonical_request_digest="d" * 64,
            principal_id="principal_alice",
            correlation_id="corr-sig-001",
            request_id="req-sig-001"
        )
        assert cap is not None

        # Verify legitimate capability succeeds
        ok, reason, _ = authority.verify_capability(
            token_id=cap.token_id,
            action_name="execute_transfer",
            target="/vault/transfer",
            canonical_request_digest="d" * 64,
            executor_id="default_executor",
            principal_id="principal_alice",
            correlation_id="corr-sig-001",
            request_id="req-sig-001"
        )
        assert ok is True

        # Tampering with tenant_domain breaks signature verification
        cap.tenant_domain = "forged.tenant.attacker"
        ok_tampered, reason_tampered, _ = authority.verify_capability(
            token_id=cap.token_id,
            action_name="execute_transfer",
            target="/vault/transfer",
            canonical_request_digest="d" * 64,
            executor_id="default_executor",
            principal_id="principal_alice",
            correlation_id="corr-sig-001",
            request_id="req-sig-001"
        )
        assert ok_tampered is False
        assert reason_tampered == "CAPABILITY_VERIFICATION_FAILED_INVALID_SIGNATURE"


class TestStep2CorrectionsAndBoundaryValidations:
    """Verifies:
    1. Scope key: preserves explicit null (serialized as JSON null), validates invalid values, does not silently derive.
    2. Authorization basis: restricts to None, rejects all caller-supplied strings, serializes as JSON null.
    3. Fencing token: strict positive integer without silent coercion of floats/strings/bools.
    4. Post-init mutation & non-finite numeric boundary tests.
    """

    def test_scope_key_null_serialized_as_json_null(self):
        """When scope_key is None, it serializes as JSON null without silent derivation."""
        cap = _sample_capability()
        cap.scope_key = None
        payload = build_capability_canonical_payload(cap)
        assert b'"scope_key":null' in payload

    def test_scope_key_explicit_valid_string_preserved_exactly(self):
        """A valid explicit scope key is preserved exactly."""
        cap = _sample_capability()
        cap.scope_key = "task:T1|target::/custom/scope"
        payload = build_capability_canonical_payload(cap)
        assert b'"scope_key":"task:T1|target::/custom/scope"' in payload

    def test_scope_key_none_and_explicit_produce_different_payloads_and_signatures(self):
        """None and an explicit scope key produce different canonical payloads and signatures."""
        authority = AuthorizationAuthority(tenant_domain="tenant.sig.internal")
        cap = _sample_capability()

        cap.scope_key = None
        payload_none = build_capability_canonical_payload(cap)
        sig_none = authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)

        cap.scope_key = canonicalize_fencing_scope(cap.task_id, cap.target)
        payload_explicit = build_capability_canonical_payload(cap)
        sig_explicit = authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)

        assert payload_none != payload_explicit
        assert sig_none != sig_explicit

    def test_scope_key_empty_whitespace_and_non_string_rejected(self):
        """Empty, whitespace-only, and non-string scope values are rejected."""
        cap = _sample_capability()

        cap.scope_key = ""
        with pytest.raises(ValueError, match="Invalid value for scope_key: cannot be empty or whitespace-only"):
            build_capability_canonical_payload(cap)

        cap.scope_key = "   \t  "
        with pytest.raises(ValueError, match="Invalid value for scope_key: cannot be empty or whitespace-only"):
            build_capability_canonical_payload(cap)

        cap.scope_key = 12345
        with pytest.raises(TypeError, match="Invalid type for scope_key: expected str, got int"):
            build_capability_canonical_payload(cap)

    def test_authorization_basis_none_accepted_and_serialized_as_json_null(self):
        """authorization_basis=None is accepted and serialized as JSON null."""
        cap = _sample_capability()
        cap.authorization_basis = None
        payload = build_capability_canonical_payload(cap)
        assert b'"authorization_basis":null' in payload

    def test_authorization_basis_all_caller_strings_rejected_at_construction(self):
        """All caller-supplied strings (including NOT_DERIVED, AUTONOMOUS, HUMAN_APPROVED) are rejected."""
        kwargs = {
            "token_id": "AUTH-CAP-TEST-003",
            "principal_id": "user_alice",
            "correlation_id": "corr-003",
            "request_id": "req-003",
            "action_name": "execute_trade",
            "target": "/finance/trade",
            "canonical_request_digest": "a" * 64,
            "executor_id": "default_executor",
            "policy_version": "1.0.0",
            "created_at": 1000.0,
            "expires_at": 1300.0,
            "tenant_domain": "corp.finance.internal",
            "policy_id": "pol-trade-v1"
        }

        for bad_basis in ["NOT_DERIVED", "AUTONOMOUS", "HUMAN_APPROVED", "CUSTOM", "   "]:
            kwargs["authorization_basis"] = bad_basis
            with pytest.raises(ValueError, match="Caller authorization_basis selection prohibited"):
                Capability(**kwargs)

    def test_authorization_basis_post_construction_mutation_rejected_at_builder(self):
        """Post-construction mutation of authorization_basis to any string is rejected."""
        cap = _sample_capability()
        for bad_basis in ["NOT_DERIVED", "AUTONOMOUS", "HUMAN_APPROVED", "ATTACKER"]:
            with pytest.raises(PermissionError, match="Direct mutation of authorization_basis is prohibited"):
                cap.authorization_basis = bad_basis

    def test_fencing_token_no_silent_coercion_of_bools_floats_strings(self):
        cap = _sample_capability()
        authority = AuthorizationAuthority(tenant_domain="tenant.sig.internal")

        # Boolean rejected
        cap.fencing_token = True
        with pytest.raises(TypeError, match="Invalid type for fencing_token: expected int, got bool"):
            build_capability_canonical_payload(cap)
        with pytest.raises(TypeError, match="Invalid type for fencing_token: expected int, got bool"):
            authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)

        # Float rejected (no silent int(1.5) -> 1 truncation)
        cap.fencing_token = 1.5
        with pytest.raises(TypeError, match="Invalid type for fencing_token: expected int, got float"):
            build_capability_canonical_payload(cap)

        # String rejected
        cap.fencing_token = "2"
        with pytest.raises(TypeError, match="Invalid type for fencing_token: expected int, got str"):
            build_capability_canonical_payload(cap)

        # Non-positive integer rejected
        cap.fencing_token = 0
        with pytest.raises(ValueError, match="must be positive integer"):
            build_capability_canonical_payload(cap)

        cap.fencing_token = -5
        with pytest.raises(ValueError, match="must be positive integer"):
            build_capability_canonical_payload(cap)

        # Valid positive int succeeds
        cap.fencing_token = 5
        payload = build_capability_canonical_payload(cap)
        assert b'"fencing_token":5' in payload

    def test_non_finite_numeric_values_rejected_at_canonical_builder_boundary(self):
        """Mutating expires_at to NaN or +/- inf after construction is caught at builder boundary."""
        cap = _sample_capability()

        cap.expires_at = float("nan")
        with pytest.raises(ValueError, match="non-finite values"):
            build_capability_canonical_payload(cap)

        cap.expires_at = float("inf")
        with pytest.raises(ValueError, match="non-finite values"):
            build_capability_canonical_payload(cap)

        cap.expires_at = float("-inf")
        with pytest.raises(ValueError, match="non-finite values"):
            build_capability_canonical_payload(cap)

        cap.expires_at = True
        with pytest.raises(TypeError, match="bool is not allowed"):
            build_capability_canonical_payload(cap)
