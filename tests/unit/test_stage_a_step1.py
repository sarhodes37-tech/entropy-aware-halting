from epistemicos.authorization import PrincipalVerifier
from tests.unit.test_sec01_sec03_remediation import ExternalTestIdentityAuthority
"""
Focused Acceptance Tests for Phase 0.4.2 Stage A — Step 1:
Capability Identity, Expiry, and Contract-Binding Hardening.
"""

import math
import time
import pytest
from dataclasses import asdict

from epistemicos.authorization import (
    Capability,
    Policy,
    AuthorizationAuthority,
    FileAuthorizationStore,
    InMemoryAuthorizationStore,
    canonicalize_fencing_scope
)


def _valid_capability_kwargs():
    return {
        "token_id": "AUTH-CAP-TEST-001",
        "principal_id": "user_alice",
        "correlation_id": "corr-001",
        "request_id": "req-001",
        "action_name": "execute_trade",
        "target": "/finance/trade",
        "canonical_request_digest": "a" * 64,
        "executor_id": "default_executor",
        "policy_version": "1.0.0",
        "created_at": 1000.0,
        "expires_at": 1300.0,
        "tenant_domain": "corp.finance.internal",
        "policy_id": "pol-trade-v1",
        "contract_id": None
    }


class TestCapabilityIdentityValidation:
    """Verifies mandatory nonempty string constraints on tenant_domain, policy_id, policy_version."""

    def test_missing_tenant_domain_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["tenant_domain"] = None
        with pytest.raises(TypeError, match="tenant_domain cannot be None"):
            Capability(**kwargs)

        del kwargs["tenant_domain"]
        with pytest.raises(TypeError):
            Capability(**kwargs)
        with pytest.raises(TypeError, match="tenant_domain cannot be None"):
            Capability.from_dict(kwargs)

    def test_empty_tenant_domain_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["tenant_domain"] = ""
        with pytest.raises(ValueError, match="tenant_domain: cannot be empty"):
            Capability(**kwargs)
        with pytest.raises(ValueError, match="tenant_domain: cannot be empty"):
            Capability.from_dict(kwargs)

    def test_whitespace_only_tenant_domain_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["tenant_domain"] = "   \t\n  "
        with pytest.raises(ValueError, match="tenant_domain: cannot be empty or whitespace-only"):
            Capability(**kwargs)
        with pytest.raises(ValueError, match="tenant_domain: cannot be empty or whitespace-only"):
            Capability.from_dict(kwargs)

    def test_invalid_tenant_domain_type_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["tenant_domain"] = 12345
        with pytest.raises(TypeError, match="expected str, got int"):
            Capability(**kwargs)
        with pytest.raises(TypeError, match="expected str, got int"):
            Capability.from_dict(kwargs)

    def test_missing_policy_id_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["policy_id"] = None
        with pytest.raises(TypeError, match="policy_id cannot be None"):
            Capability(**kwargs)

        del kwargs["policy_id"]
        with pytest.raises(TypeError):
            Capability(**kwargs)
        with pytest.raises(TypeError, match="policy_id cannot be None"):
            Capability.from_dict(kwargs)

    def test_empty_or_whitespace_policy_id_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["policy_id"] = "   "
        with pytest.raises(ValueError, match="policy_id: cannot be empty"):
            Capability(**kwargs)
        with pytest.raises(ValueError, match="policy_id: cannot be empty"):
            Capability.from_dict(kwargs)

    def test_invalid_policy_id_type_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["policy_id"] = ["invalid", "list"]
        with pytest.raises(TypeError, match="expected str, got list"):
            Capability(**kwargs)
        with pytest.raises(TypeError, match="expected str, got list"):
            Capability.from_dict(kwargs)

    def test_missing_policy_version_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["policy_version"] = None
        with pytest.raises(TypeError, match="policy_version cannot be None"):
            Capability(**kwargs)

        del kwargs["policy_version"]
        with pytest.raises(TypeError):
            Capability(**kwargs)
        with pytest.raises(TypeError, match="policy_version cannot be None"):
            Capability.from_dict(kwargs)

    def test_empty_or_whitespace_policy_version_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["policy_version"] = " "
        with pytest.raises(ValueError, match="policy_version: cannot be empty"):
            Capability(**kwargs)
        with pytest.raises(ValueError, match="policy_version: cannot be empty"):
            Capability.from_dict(kwargs)

    def test_invalid_policy_version_type_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["policy_version"] = 1.0  # float instead of str
        with pytest.raises(TypeError, match="expected str, got float"):
            Capability(**kwargs)
        with pytest.raises(TypeError, match="expected str, got float"):
            Capability.from_dict(kwargs)

    def test_identifiers_are_preserved_exactly_without_silent_normalization(self):
        kwargs = _valid_capability_kwargs()
        kwargs["tenant_domain"] = "Tenant-Domain-Exact-Case"
        kwargs["policy_id"] = "POL_UnderScore_Exact"
        cap = Capability(**kwargs)
        assert cap.tenant_domain == "Tenant-Domain-Exact-Case"
        assert cap.policy_id == "POL_UnderScore_Exact"
        assert cap.to_dict()["tenant_domain"] == "Tenant-Domain-Exact-Case"
        assert cap.to_dict()["policy_id"] == "POL_UnderScore_Exact"

    def test_leading_trailing_whitespace_not_silently_stripped(self):
        """Valid non-whitespace string containing surrounding spaces is preserved exactly without stripping."""
        kwargs = _valid_capability_kwargs()
        kwargs["tenant_domain"] = "  tenant.domain.with.spaces  "
        cap = Capability(**kwargs)
        assert cap.tenant_domain == "  tenant.domain.with.spaces  "
        assert cap.tenant_domain != "tenant.domain.with.spaces"
        assert cap.to_dict()["tenant_domain"] == "  tenant.domain.with.spaces  "

        roundtrip = Capability.from_dict(cap.to_dict())
        assert roundtrip.tenant_domain == "  tenant.domain.with.spaces  "


class TestCapabilityExpiryValidation:
    """Verifies structural numeric validation on expires_at distinct from runtime expiration."""

    def test_valid_numeric_expiry_int_and_float(self):
        kwargs = _valid_capability_kwargs()
        kwargs["expires_at"] = 1500.5
        cap1 = Capability(**kwargs)
        assert cap1.expires_at == 1500.5

        kwargs["expires_at"] = 2000
        cap2 = Capability(**kwargs)
        assert cap2.expires_at == 2000

    def test_boolean_expiry_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["expires_at"] = True
        with pytest.raises(TypeError, match="bool is not allowed"):
            Capability(**kwargs)
        with pytest.raises(TypeError, match="bool is not allowed"):
            Capability.from_dict(kwargs)

        kwargs["expires_at"] = False
        with pytest.raises(TypeError, match="bool is not allowed"):
            Capability(**kwargs)
        with pytest.raises(TypeError, match="bool is not allowed"):
            Capability.from_dict(kwargs)

    def test_string_expiry_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["expires_at"] = "1700000000.0"
        with pytest.raises(TypeError, match="expected int or float, got str"):
            Capability(**kwargs)
        with pytest.raises(TypeError, match="expected int or float, got str"):
            Capability.from_dict(kwargs)

    def test_nan_expiry_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["expires_at"] = float("nan")
        with pytest.raises(ValueError, match="NaN is not allowed"):
            Capability(**kwargs)
        with pytest.raises(ValueError, match="NaN is not allowed"):
            Capability.from_dict(kwargs)

    def test_positive_infinity_expiry_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["expires_at"] = float("inf")
        with pytest.raises(ValueError, match="infinity is not allowed"):
            Capability(**kwargs)
        with pytest.raises(ValueError, match="infinity is not allowed"):
            Capability.from_dict(kwargs)

    def test_negative_infinity_expiry_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["expires_at"] = float("-inf")
        with pytest.raises(ValueError, match="infinity is not allowed"):
            Capability(**kwargs)
        with pytest.raises(ValueError, match="infinity is not allowed"):
            Capability.from_dict(kwargs)

    def test_missing_expiry_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["expires_at"] = None
        with pytest.raises(TypeError, match="expires_at cannot be None"):
            Capability(**kwargs)

        del kwargs["expires_at"]
        with pytest.raises(TypeError):
            Capability(**kwargs)
        with pytest.raises(TypeError, match="expires_at cannot be None"):
            Capability.from_dict(kwargs)

    def test_structural_validity_distinct_from_runtime_expiration(self):
        """A capability with an expiry in the past is structurally valid, but is_expired evaluates True."""
        kwargs = _valid_capability_kwargs()
        kwargs["created_at"] = 100.0
        kwargs["expires_at"] = 200.0
        past_cap = Capability(**kwargs)
        assert past_cap.expires_at == 200.0
        # Runtime evaluation shows expired at now=300
        assert past_cap.is_expired(current_time=300.0) is True
        # Runtime evaluation shows not expired at now=150
        assert past_cap.is_expired(current_time=150.0) is False


class TestCapabilityContractBindingRepresentation:
    """Verifies clear distinction between genuinely unbound (None) and bound contract representations."""

    def test_unbound_contract_represented_by_none(self):
        kwargs = _valid_capability_kwargs()
        kwargs["contract_id"] = None
        cap = Capability(**kwargs)
        assert cap.contract_id is None
        assert cap.to_dict()["contract_id"] is None

        roundtrip = Capability.from_dict(cap.to_dict())
        assert roundtrip.contract_id is None

    def test_bound_contract_id_preserved_exactly(self):
        kwargs = _valid_capability_kwargs()
        kwargs["contract_id"] = "TASK-CONTRACT-SEC-99"
        cap = Capability(**kwargs)
        assert cap.contract_id == "TASK-CONTRACT-SEC-99"
        assert cap.to_dict()["contract_id"] == "TASK-CONTRACT-SEC-99"

        roundtrip = Capability.from_dict(cap.to_dict())
        assert roundtrip.contract_id == "TASK-CONTRACT-SEC-99"

    def test_empty_or_whitespace_contract_id_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["contract_id"] = ""
        with pytest.raises(ValueError, match="contract_id: cannot be empty or whitespace-only"):
            Capability(**kwargs)
        with pytest.raises(ValueError, match="contract_id: cannot be empty or whitespace-only"):
            Capability.from_dict(kwargs)

        kwargs["contract_id"] = "   \t  "
        with pytest.raises(ValueError, match="contract_id: cannot be empty or whitespace-only"):
            Capability(**kwargs)
        with pytest.raises(ValueError, match="contract_id: cannot be empty or whitespace-only"):
            Capability.from_dict(kwargs)

    def test_invalid_contract_id_type_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["contract_id"] = 99999
        with pytest.raises(TypeError, match="expected str, got int"):
            Capability(**kwargs)
        with pytest.raises(TypeError, match="expected str, got int"):
            Capability.from_dict(kwargs)


class TestCapabilityRequiredSuccessEvidenceValidation:
    """Verifies that required_success_evidence input is strictly validated."""

    def test_invalid_required_success_evidence_type_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["required_success_evidence"] = "should_not_be_a_string"
        with pytest.raises(TypeError, match="expected collection"):
            Capability(**kwargs)
        with pytest.raises(TypeError, match="expected collection"):
            Capability.from_dict(kwargs)

    def test_empty_or_non_string_element_in_evidence_rejected(self):
        kwargs = _valid_capability_kwargs()
        kwargs["required_success_evidence"] = {"valid_key", ""}
        with pytest.raises(ValueError, match="elements must be nonempty strings"):
            Capability(**kwargs)
        with pytest.raises(ValueError, match="elements must be nonempty strings"):
            Capability.from_dict(kwargs)

        kwargs["required_success_evidence"] = {"valid_key", 123}
        with pytest.raises(ValueError, match="elements must be nonempty strings"):
            Capability(**kwargs)
        with pytest.raises(ValueError, match="elements must be nonempty strings"):
            Capability.from_dict(kwargs)


class TestAuthorityPolicyTenantEnforcement:
    """Verifies tenant identity resolution, combinations, and precedence rules."""

    def test_combo1_policy_tenant_absent_authority_tenant_configured(self):
        """Combination 1: Policy tenant absent, authority tenant configured -> authority tenant used."""
        policy = Policy(
            policy_id="pol-no-tenant",
            allowed_operations={"read_file"},
            allowed_resources={"/data"},
            tenant_domain=None
        )
        test_idp = ExternalTestIdentityAuthority(issuer_id="TestIdP_Authority")
        verifier = PrincipalVerifier(trusted_public_keys={"TestIdP_Authority": test_idp.public_key})
        p_assert = test_idp.issue_principal("operator_alice")
        authority = AuthorizationAuthority(default_policy=policy, principal_provider=verifier, tenant_domain="authority.configured.domain")
        cap, reason = authority.evaluate_and_issue_capability(
            action_name="read_file",
            target="/data",
            canonical_request_digest="b" * 64,
            principal_id=p_assert
        )
        assert cap is not None
        assert reason == "AUTHORIZATION_GRANTED"
        assert cap.tenant_domain == "authority.configured.domain"

    def test_combo2_policy_tenant_valid_authority_tenant_configured_different(self):
        """Combination 2: Policy tenant valid, authority tenant configured with different value -> policy tenant takes precedence."""
        policy = Policy(
            policy_id="pol-with-tenant",
            allowed_operations={"read_file"},
            allowed_resources={"/data"},
            tenant_domain="policy.specific.domain"
        )
        test_idp = ExternalTestIdentityAuthority(issuer_id="TestIdP_Authority")
        verifier = PrincipalVerifier(trusted_public_keys={"TestIdP_Authority": test_idp.public_key})
        p_assert = test_idp.issue_principal("operator_alice")
        authority = AuthorizationAuthority(default_policy=policy, principal_provider=verifier, tenant_domain="authority.base.domain")
        cap, reason = authority.evaluate_and_issue_capability(
            action_name="read_file",
            target="/data",
            canonical_request_digest="b" * 64,
            principal_id=p_assert
        )
        assert cap is not None
        assert reason == "AUTHORIZATION_GRANTED"
        assert cap.tenant_domain == "policy.specific.domain"

    def test_combo3_policy_tenant_explicitly_empty_or_whitespace_fails_closed(self):
        """Combination 3: Policy tenant explicitly empty or whitespace -> fails closed, does NOT fall back to authority tenant."""
        policy_empty = Policy(
            policy_id="pol-empty-tenant",
            allowed_operations={"read_file"},
            allowed_resources={"/data"},
            tenant_domain=""
        )
        authority = AuthorizationAuthority(default_policy=policy_empty, tenant_domain="authority.fallback.domain")
        cap, reason = authority.evaluate_and_issue_capability(
            action_name="read_file",
            target="/data",
            canonical_request_digest="b" * 64
        )
        assert cap is None
        assert reason == "AUTHORIZATION_DENIED_INVALID_POLICY_TENANT_DOMAIN"

        policy_ws = Policy(
            policy_id="pol-ws-tenant",
            allowed_operations={"read_file"},
            allowed_resources={"/data"},
            tenant_domain="   \t  "
        )
        cap_ws, reason_ws = authority.evaluate_and_issue_capability(
            action_name="read_file",
            target="/data",
            canonical_request_digest="b" * 64,
            policy=policy_ws
        )
        assert cap_ws is None
        assert reason_ws == "AUTHORIZATION_DENIED_INVALID_POLICY_TENANT_DOMAIN"

    def test_combo4_neither_source_configured_fails_closed(self):
        """Combination 4: Neither policy nor authority tenant configured -> fails closed."""
        policy = Policy(
            policy_id="pol-no-tenant",
            allowed_operations={"read_file"},
            allowed_resources={"/data"},
            tenant_domain=None
        )
        authority = AuthorizationAuthority(default_policy=policy, tenant_domain=None)
        cap, reason = authority.evaluate_and_issue_capability(
            action_name="read_file",
            target="/data",
            canonical_request_digest="b" * 64
        )
        assert cap is None
        assert reason == "AUTHORIZATION_DENIED_MISSING_TENANT_DOMAIN"


class TestFileStoreRoundtripAndLegacyFailClosed:
    """Verifies FileAuthorizationStore persistence round-trip and legacy record fail-closed rejection."""

    def test_roundtrip_preserves_tenant_policy_contract_identity(self, tmp_path):
        store_path = str(tmp_path / "auth_store.jsonl")
        store = FileAuthorizationStore(store_path=store_path)

        kwargs = _valid_capability_kwargs()
        kwargs["tenant_domain"] = "tenant.persistence.domain"
        kwargs["policy_id"] = "pol.persisted.v1"
        kwargs["contract_id"] = "CONTRACT-PERSIST-10"
        cap = Capability(**kwargs)

        store.register_capability(cap)

        # Retrieve through new instance reading from disk
        store2 = FileAuthorizationStore(store_path=store_path)
        retrieved = store2.get_capability(cap.token_id)
        assert retrieved is not None
        assert isinstance(retrieved, Capability)
        assert retrieved.tenant_domain == "tenant.persistence.domain"
        assert retrieved.policy_id == "pol.persisted.v1"
        assert retrieved.contract_id == "CONTRACT-PERSIST-10"
        assert retrieved.token_id == cap.token_id

    def test_legacy_persisted_record_missing_tenant_fails_closed(self, tmp_path):
        store_path = str(tmp_path / "legacy_store.jsonl")
        store = FileAuthorizationStore(store_path=store_path)

        # Write legacy record without tenant_domain into the store file
        legacy_data = {
            "token_id": "AUTH-LEGACY-001",
            "principal_id": "user_legacy",
            "correlation_id": "c1",
            "request_id": "r1",
            "action_name": "legacy_op",
            "target": "/legacy",
            "canonical_request_digest": "c" * 64,
            "executor_id": "default_executor",
            "policy_version": "1.0.0",
            "created_at": 1000.0,
            "expires_at": 1300.0
            # missing tenant_domain and policy_id
        }

        journal_entry = {
            "type": "REGISTER_CAPABILITY",
            "token_id": "AUTH-LEGACY-001",
            "data": legacy_data,
            "timestamp": time.time()
        }

        import json
        with open(store_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(journal_entry) + "\n")

        # Deserializing via get_capability on store with fail-closed deserialization must raise TypeError/ValueError
        store2 = FileAuthorizationStore(store_path=store_path)
        with pytest.raises(TypeError, match="tenant_domain cannot be None"):
            store2.get_capability("AUTH-LEGACY-001")
