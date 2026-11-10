from tests.unit.test_sec01_sec03_remediation import ExternalTestIdentityAuthority
from epistemicos.authorization import PrincipalVerifier
import tempfile
from unittest.mock import MagicMock
import pytest

from epistemicos.authorization import AuthorizationAuthority, Policy
from epistemicos.core import EpistemicOrchestrator
from epistemicos.gates import GateAction, GateResult
from epistemicos.provenance import LocalProvenanceStore, TrustedExecutionBoundary


class TestCoreCoverageOrchestratorEnforcement:
    """Tests for edge cases and failure paths in EpistemicOrchestrator."""

    def test_provenance_store_failure_on_missing_action_or_target(self):
        """Tests that when action or target is missing and store.record_event raises,
        the failure message is captured and execution halts fail-closed."""
        with tempfile.NamedTemporaryFile() as tf_audit:
            mock_store = MagicMock(spec=LocalProvenanceStore)
            boundary = TrustedExecutionBoundary(provenance_store=mock_store)
            orch = EpistemicOrchestrator(
                audit_log_path=tf_audit.name, execution_boundary=boundary
            )
            orch.gates = []

            def side_effect(event):
                if event.event_type == "ACTION_PROPOSED":
                    return None
                raise OSError("Prov write failed")

            mock_store.record_event.side_effect = side_effect

            payload = {"policy_id": "pol-1", "task": "test"}

            # 1. Missing action_name (lines 441-442)
            ctx_no_action = {
                "actual_executable": lambda: None,
                "correlation_id": "c1",
                "request_id": "r1",
            }
            res_no_action = orch.process_submission(
                raw_payload=payload, context=ctx_no_action
            )
            assert res_no_action["status"] == "HALTED"
            assert res_no_action["execution_status"] == "DENIED"
            assert "Missing or ambiguous action_name" in res_no_action["reason"]
            msg_frag = "(Provenance recording failed: Prov write failed)"
            assert msg_frag in res_no_action["reason"]

            # 2. Missing target (lines 482-483)
            ctx_no_target = {
                "actual_executable": lambda: None,
                "action_name": "test_act",
                "correlation_id": "c2",
                "request_id": "r2",
            }
            res_no_target = orch.process_submission(
                raw_payload=payload, context=ctx_no_target
            )
            assert res_no_target["status"] == "HALTED"
            assert res_no_target["execution_status"] == "DENIED"
            assert "Missing or ambiguous target resource" in res_no_target["reason"]
            assert msg_frag in res_no_target["reason"]

    def test_authorization_granted_provenance_write_failure(self):
        """Tests lines 660-673: Pre-execution authorization provenance recording failure halts."""
        with tempfile.NamedTemporaryFile() as tf_audit, tempfile.NamedTemporaryFile() as tf_prov:
            store = LocalProvenanceStore(log_path=tf_prov.name)
            policy = Policy(
                policy_id="pol",
                allowed_operations={"read_file"},
                allowed_resources={"data.txt"},
                tenant_domain="test_tenant",
            )
            test_idp = ExternalTestIdentityAuthority(issuer_id="TestIdP_Core")
            verifier = PrincipalVerifier(trusted_public_keys={"TestIdP_Core": test_idp.public_key})
            auth_p = test_idp.issue_principal("operator_core")
            authority = AuthorizationAuthority(principal_provider=verifier, tenant_domain="test_tenant", default_policy=policy)
            boundary = TrustedExecutionBoundary(
                provenance_store=store, authority=authority
            )
            orch = EpistemicOrchestrator(
                audit_log_path=tf_audit.name,
                execution_boundary=boundary,
                authority=authority,
            )
            orch.gates = []

            original_record = store.record_event

            def fail_on_grant(event):
                if event.event_type == "AUTHORIZATION_GRANTED":
                    raise OSError("Provenance grant event disk write failed")
                return original_record(event)

            store.record_event = fail_on_grant

            payload = {"policy_id": "pol", "task": "read"}
            ctx = {
                "actual_executable": lambda: "read_success",
                "action_name": "read_file",
                "target": "data.txt",
                "correlation_id": "corr-grant-fail",
                "request_id": "req-grant-fail",
                "authenticated_principal": auth_p,
            }
            res = orch.process_submission(raw_payload=payload, context=ctx)
            assert res["status"] == "HALTED"
            assert res["execution_status"] == "AUTHORIZED_NOT_EXECUTED"
            assert res["gate"] == "TrustedGovernanceIssuer"
            expected_err = (
                "Pre-execution authorization provenance recording failed: "
                "Provenance grant event disk write failed"
            )
            assert expected_err in res["reason"]

    def test_missing_authorization_granted_record_integrity_check(self):
        """Tests lines 713-725: No matching AUTHORIZATION_GRANTED record in provenance store."""
        with tempfile.NamedTemporaryFile() as tf_audit, tempfile.NamedTemporaryFile() as tf_prov:
            store = LocalProvenanceStore(log_path=tf_prov.name)
            policy = Policy(
                policy_id="pol",
                allowed_operations={"read_file"},
                allowed_resources={"data.txt"},
                tenant_domain="test_tenant",
            )
            test_idp = ExternalTestIdentityAuthority(issuer_id="TestIdP_Core")
            verifier = PrincipalVerifier(trusted_public_keys={"TestIdP_Core": test_idp.public_key})
            auth_p = test_idp.issue_principal("operator_core")
            authority = AuthorizationAuthority(principal_provider=verifier, tenant_domain="test_tenant", default_policy=policy)
            boundary = TrustedExecutionBoundary(
                provenance_store=store, authority=authority
            )
            orch = EpistemicOrchestrator(
                audit_log_path=tf_audit.name,
                execution_boundary=boundary,
                authority=authority,
            )
            orch.gates = []

            original_record = store.record_event

            def swallow_grant(event):
                if event.event_type == "AUTHORIZATION_GRANTED":
                    return
                return original_record(event)

            store.record_event = swallow_grant

            payload = {"policy_id": "pol", "task": "read"}
            ctx = {
                "actual_executable": lambda: "read_success",
                "action_name": "read_file",
                "target": "data.txt",
                "correlation_id": "corr-missing-grant",
                "request_id": "req-missing-grant",
                "authenticated_principal": auth_p,
            }
            res = orch.process_submission(raw_payload=payload, context=ctx)
            assert res["status"] == "HALTED"
            assert res["execution_status"] == "DENIED"
            assert res["gate"] == "TrustedExecutionBoundary"
            assert "No matching AUTHORIZATION_GRANTED record found" in res["reason"]

    def test_execution_boundary_unexpected_exception(self):
        """Tests lines 851-866: Unexpected exception during execute_protected_action."""
        with tempfile.NamedTemporaryFile() as tf_audit, tempfile.NamedTemporaryFile() as tf_prov:
            store = LocalProvenanceStore(log_path=tf_prov.name)
            policy = Policy(
                policy_id="pol",
                allowed_operations={"read_file"},
                allowed_resources={"data.txt"},
                tenant_domain="test_tenant",
            )
            test_idp = ExternalTestIdentityAuthority(issuer_id="TestIdP_Core")
            verifier = PrincipalVerifier(trusted_public_keys={"TestIdP_Core": test_idp.public_key})
            auth_p = test_idp.issue_principal("operator_core")
            authority = AuthorizationAuthority(principal_provider=verifier, tenant_domain="test_tenant", default_policy=policy)
            boundary = TrustedExecutionBoundary(
                provenance_store=store, authority=authority
            )
            orch = EpistemicOrchestrator(
                audit_log_path=tf_audit.name,
                execution_boundary=boundary,
                authority=authority,
            )
            orch.gates = []

            def crash_boundary(*args, **kwargs):
                raise RuntimeError("Hardware boundary fault")

            boundary.execute_protected_action = crash_boundary

            payload = {"policy_id": "pol", "task": "read"}
            ctx = {
                "actual_executable": lambda: "read_success",
                "action_name": "read_file",
                "target": "data.txt",
                "correlation_id": "corr-boundary-crash",
                "request_id": "req-boundary-crash",
                "authenticated_principal": auth_p,
            }
            res = orch.process_submission(raw_payload=payload, context=ctx)
            assert res["status"] == "HALTED"
            assert res["execution_status"] == "EXECUTION_FAILED"
            assert res["gate"] == "TrustedExecutionBoundary"
            expected_msg = (
                "TrustedExecutionBoundary Enforcement Failed: Hardware boundary fault"
            )
            assert expected_msg in res["reason"]
            assert res["vectors_revoked"] >= 1

    def test_policy_scope_synthesis_and_requestor_validation(self):
        """Tests dynamic policy scope synthesis from gate objects."""
        with tempfile.NamedTemporaryFile() as tf_audit, tempfile.NamedTemporaryFile() as tf_prov:
            store = LocalProvenanceStore(log_path=tf_prov.name)
            test_idp = ExternalTestIdentityAuthority(issuer_id="TestIdP_Core")
            verifier = PrincipalVerifier(trusted_public_keys={"TestIdP_Core": test_idp.public_key})
            auth_p = test_idp.issue_principal("operator_core")
            authority = AuthorizationAuthority(principal_provider=verifier, tenant_domain="test_tenant")
            boundary = TrustedExecutionBoundary(
                provenance_store=store, authority=authority
            )
            orch = EpistemicOrchestrator(
                audit_log_path=tf_audit.name,
                execution_boundary=boundary,
                authority=authority,
            )

            payload = {"policy_id": "pol", "task": "read"}

            # 1. Scope implementing .to_dict() (line 534)
            class ScopeToDict:
                def to_dict(self):
                    return {
                        "allowed_operations": ["read_file"],
                        "allowed_resources": ["data.txt"],
                        "tenant_domain": "test_tenant",
                    }

            class GateToDict:
                def __init__(self):
                    self.trusted_scope = ScopeToDict()

                def evaluate(self, payload, context):
                    return GateResult(
                        action=GateAction.ALLOW, status="ALLOWED", gate_name="GateToDict"
                    )

            orch.gates = [GateToDict()]
            ctx = {
                "actual_executable": lambda: "ok",
                "action_name": "read_file",
                "target": "data.txt",
                "correlation_id": "c1",
                "request_id": "r1",
                "authenticated_principal": auth_p,
            }
            res1 = orch.process_submission(raw_payload=payload, context=ctx)
            assert res1["status"] == "ALLOWED"

            # 2. Scope implementing .__dict__ (line 536)
            class ScopeDictObj:
                def __init__(self):
                    self.allowed_operations = ["read_file"]
                    self.allowed_resources = ["data.txt"]

            class GateDictObj:
                def __init__(self):
                    self.trusted_scope = ScopeDictObj()

                def evaluate(self, payload, context):
                    return GateResult(
                        action=GateAction.ALLOW, status="ALLOWED", gate_name="GateDictObj"
                    )

            orch.gates = [GateDictObj()]
            res2 = orch.process_submission(raw_payload=payload, context=ctx)
            assert res2["status"] == "ALLOWED"

            # 3. Scope without allowed_resources (line 547)
            class ScopeNoRes:
                def to_dict(self):
                    return {"allowed_operations": ["read_file"]}

            class GateNoRes:
                def __init__(self):
                    self.trusted_scope = ScopeNoRes()

                def evaluate(self, payload, context):
                    return GateResult(
                        action=GateAction.ALLOW, status="ALLOWED", gate_name="GateNoRes"
                    )

            orch.gates = [GateNoRes()]
            res3 = orch.process_submission(raw_payload=payload, context=ctx)
            assert res3["status"] == "HALTED"
            assert "AUTHORIZATION_DENIED_TARGET_NOT_ALLOWED" in res3["reason"]

            # 4. Gate with trusted_operations dictionary (line 554)
            class GateTrustedOps:
                def __init__(self):
                    self.trusted_scope = None
                    self.trusted_operations = {"read_file": True}

                def evaluate(self, payload, context):
                    return GateResult(
                        action=GateAction.ALLOW, status="ALLOWED", gate_name="GateTrustedOps"
                    )

            orch.gates = [GateTrustedOps()]
            res4 = orch.process_submission(raw_payload=payload, context=ctx)
            assert res4["status"] == "HALTED"
            assert "AUTHORIZATION_DENIED_TARGET_NOT_ALLOWED" in res4["reason"]

            # 5. Empty gate scope -> active_policy = None (line 564)
            class GateEmpty:
                def __init__(self):
                    self.trusted_scope = "non-dict-scalar"

                def evaluate(self, payload, context):
                    return GateResult(
                        action=GateAction.ALLOW, status="ALLOWED", gate_name="GateEmpty"
                    )

            orch.gates = [GateEmpty()]
            res5 = orch.process_submission(raw_payload=payload, context=ctx)
            assert res5["status"] == "HALTED"
            assert "AUTHORIZATION_DENIED_NO_TRUSTED_POLICY" in res5["reason"]

            # 6. Requestor ID validation without wildcard principal (lines 576-579)
            orch.gates = [GateDictObj()]
            ctx6 = {k: v for k, v in ctx.items() if k != "authenticated_principal"}
            ctx6["requestor_id"] = "unverified_principal"
            res6 = orch.process_submission(
                raw_payload=payload,
                context=ctx6,
            )
            assert res6["status"] == "HALTED"
            err_substr = (
                "Plain string or unverified context cannot satisfy principal authentication"
            )
            assert err_substr in res6["reason"]

    def test_execution_outcome_unknown_fallback_cleanup_status(self):
        """Tests line 788: EXECUTION_OUTCOME_UNKNOWN cleanup status fallback branch."""
        with tempfile.NamedTemporaryFile() as tf_audit, tempfile.NamedTemporaryFile() as tf_prov:
            store = LocalProvenanceStore(log_path=tf_prov.name)
            policy = Policy(
                policy_id="pol",
                allowed_operations={"read_file"},
                allowed_resources={"data.txt"},
                tenant_domain="test_tenant",
            )
            test_idp = ExternalTestIdentityAuthority(issuer_id="TestIdP_Core")
            verifier = PrincipalVerifier(trusted_public_keys={"TestIdP_Core": test_idp.public_key})
            auth_p = test_idp.issue_principal("operator_core")
            authority = AuthorizationAuthority(principal_provider=verifier, tenant_domain="test_tenant", default_policy=policy)
            boundary = TrustedExecutionBoundary(
                provenance_store=store, authority=authority
            )
            orch = EpistemicOrchestrator(
                audit_log_path=tf_audit.name,
                execution_boundary=boundary,
                authority=authority,
            )
            orch.gates = []

            # Mock execute_protected_action to return EXECUTION_OUTCOME_UNKNOWN
            def outcome_unknown(*args, **kwargs):
                return {
                    "status": "EXECUTION_OUTCOME_UNKNOWN",
                    "reason": "Terminal audit log write failed",
                }

            boundary.execute_protected_action = outcome_unknown

            # Simulate condition for line 788:
            # initial_staged > 0, actual_revoked == 0, pending == 0
            orch.vector_manager.get_staged_count = MagicMock(return_value=2)
            orch.vector_manager.revoke_trajectory = MagicMock(return_value=[])
            orch.vector_manager.get_outstanding_vectors = MagicMock(return_value=[])

            payload = {"policy_id": "pol", "task": "read"}
            ctx = {
                "actual_executable": lambda: "read_success",
                "action_name": "read_file",
                "target": "data.txt",
                "correlation_id": "corr-unknown-outcome",
                "request_id": "req-unknown-outcome",
                "authenticated_principal": auth_p,
            }
            res = orch.process_submission(raw_payload=payload, context=ctx)
            assert res["status"] == "RECONCILIATION_REQUIRED"
            assert res["vector_cleanup"]["status"] == "PENDING_RECONCILIATION"
            assert res["vector_cleanup"]["vectors_purged"] == 0
            assert res["vector_cleanup"]["vectors_pending"] == 0

    def test_restricted_principals_validation(self):
        """Tests line 577: Claimed requestor_id with restricted policy principals."""
        with tempfile.NamedTemporaryFile() as tf_audit, tempfile.NamedTemporaryFile() as tf_prov:
            store = LocalProvenanceStore(log_path=tf_prov.name)
            policy = Policy(
                policy_id="pol",
                allowed_operations={"read_file"},
                allowed_resources={"data.txt"},
                tenant_domain="test_tenant",
                allowed_principals={"admin"},
            )
            authority = AuthorizationAuthority(default_policy=policy)
            boundary = TrustedExecutionBoundary(
                provenance_store=store, authority=authority
            )
            orch = EpistemicOrchestrator(
                audit_log_path=tf_audit.name,
                execution_boundary=boundary,
                authority=authority,
            )
            orch.gates = []

            payload = {"policy_id": "pol", "task": "read"}
            ctx = {
                "actual_executable": lambda: "ok",
                "action_name": "read_file",
                "target": "data.txt",
                "correlation_id": "c1",
                "request_id": "r1",
                "requestor_id": "admin",
            }
            res = orch.process_submission(raw_payload=payload, context=ctx)
            assert res["status"] == "HALTED"
            assert res["execution_status"] == "DENIED"
            denied_msg = "AUTHORIZATION_DENIED_AUTHENTICATED_PRINCIPAL_REQUIRED"
            assert denied_msg in res["reason"]

    def test_invalid_boundary_response_fails_closed(self):
        """Tests that invalid boundary responses (non-dict, empty dict, missing status,
        null status, unknown status, non-string status) fail closed and never report
        ALLOWED or EXECUTED."""
        with tempfile.NamedTemporaryFile() as tf_audit, tempfile.NamedTemporaryFile() as tf_prov:
            store = LocalProvenanceStore(log_path=tf_prov.name)
            policy_star = Policy(
                policy_id="pol_star",
                allowed_operations={"read_file"},
                allowed_resources={"data.txt"},
                allowed_principals={"*"},
                tenant_domain="test_tenant",
            )
            test_idp = ExternalTestIdentityAuthority(issuer_id="TestIdP_Core")
            verifier = PrincipalVerifier(trusted_public_keys={"TestIdP_Core": test_idp.public_key})
            auth_p = test_idp.issue_principal("operator_core")
            authority = AuthorizationAuthority(principal_provider=verifier, tenant_domain="test_tenant", default_policy=policy_star)
            boundary = TrustedExecutionBoundary(
                provenance_store=store, authority=authority
            )
            orch = EpistemicOrchestrator(
                audit_log_path=tf_audit.name,
                execution_boundary=boundary,
                authority=authority,
            )
            orch.gates = []

            # 1. Non-dictionary responses
            invalid_types = [
                "raw_string_outcome",
                None,
                12345,
                ["invalid", "list"],
                True,
            ]
            for invalid_val in invalid_types:
                boundary.execute_protected_action = lambda *args, **kwargs: invalid_val
                ctx = {
                    "actual_executable": lambda: "ok",
                    "action_name": "read_file",
                    "target": "data.txt",
                    "correlation_id": "corr-invalid-boundary",
                    "request_id": "req-invalid-boundary",
                "authenticated_principal": auth_p,
                }
                res = orch.process_submission(
                    raw_payload={"policy_id": "pol_star", "task": "read"}, context=ctx
                )
                assert res["status"] == "HALTED"
                assert res["execution_status"] == "EXECUTION_FAILED"
                assert res["gate"] == "TrustedExecutionBoundary"
                assert "Invalid execution boundary response type" in res["reason"]
                assert res["vectors_revoked"] >= 1

            # 2. Dictionary responses with invalid/missing/null/unknown/non-string status
            class HostileEqualsSuccess:
                def __eq__(self, other):
                    return True

            invalid_dict_outcomes = [
                {},
                {"result": "ok"},  # missing status
                {"status": None},  # null status
                {"status": "GARBAGE"},  # unknown status
                {"status": 123},  # non-string status
                {"status": False},  # boolean status
                {"status": HostileEqualsSuccess()},  # hostile equality duck-typing
            ]
            for invalid_dict in invalid_dict_outcomes:
                boundary.execute_protected_action = lambda *args, **kwargs: invalid_dict
                ctx = {
                    "actual_executable": lambda: "ok",
                    "action_name": "read_file",
                    "target": "data.txt",
                    "correlation_id": "corr-invalid-dict-status",
                    "request_id": "req-invalid-dict-status",
                "authenticated_principal": auth_p,
                }
                res = orch.process_submission(
                    raw_payload={"policy_id": "pol_star", "task": "read"}, context=ctx
                )
                assert res["status"] == "HALTED"
                assert res["execution_status"] == "EXECUTION_FAILED"
                assert res["gate"] == "TrustedExecutionBoundary"
                assert "Invalid execution boundary response status" in res["reason"]
                assert res["vectors_revoked"] >= 1

            # 3. Positive control: genuine SUCCESS response succeeds
            valid_success = {"status": "SUCCESS", "result": "computed_val"}
            boundary.execute_protected_action = lambda *args, **kwargs: valid_success
            ctx_success = {
                "actual_executable": lambda: "ok",
                "action_name": "read_file",
                "target": "data.txt",
                "correlation_id": "corr-valid-success",
                "request_id": "req-valid-success",
                "authenticated_principal": auth_p,
            }
            res_success = orch.process_submission(
                raw_payload={"policy_id": "pol_star", "task": "read"}, context=ctx_success
            )
            assert res_success["status"] == "ALLOWED"
            assert res_success["execution_status"] == "EXECUTED"
            assert res_success["execution_outcome"] == valid_success

            # 4. Positive control: genuine UNVERIFIED_SUCCESS response halts with evidence failure
            valid_unverified = {
                "status": "UNVERIFIED_SUCCESS",
                "reason": "Missing required signature evidence",
            }
            boundary.execute_protected_action = lambda *args, **kwargs: valid_unverified
            ctx_unverified = {
                "actual_executable": lambda: "ok",
                "action_name": "read_file",
                "target": "data.txt",
                "correlation_id": "corr-valid-unverified",
                "request_id": "req-valid-unverified",
                "authenticated_principal": auth_p,
            }
            res_unverified = orch.process_submission(
                raw_payload={"policy_id": "pol_star", "task": "read"}, context=ctx_unverified
            )
            assert res_unverified["status"] == "HALTED"
            assert res_unverified["execution_status"] == "UNVERIFIED_SUCCESS"
            assert res_unverified["gate"] == "TrustedExecutionBoundary"
            assert "Execution boundary verification failed" in res_unverified["reason"]
            assert res_unverified["execution_outcome"] == valid_unverified
            assert res_unverified["vectors_revoked"] >= 0


def test_orchestrator_hmac_key_resolution_fail_closed(monkeypatch, tmp_path):
    """
    Verifies fail-closed environment variable resolution for HMAC keys in EpistemicOrchestrator.
    Explicit empty string environment variables must raise ValueError rather than silently
    falling back to unkeyed None.
    """
    audit_file = str(tmp_path / "audit_hmac_test.jsonl")

    # 1. Explicit empty string for EPISTEMICOS_AUDIT_HMAC_KEY -> ValueError
    monkeypatch.setenv("EPISTEMICOS_AUDIT_HMAC_KEY", "")
    monkeypatch.delenv("EPISTEMICOS_PROVENANCE_HMAC_KEY", raising=False)
    with pytest.raises(ValueError, match="hmac_key cannot be empty"):
        EpistemicOrchestrator(audit_log_path=audit_file)

    # 2. Explicit empty string for EPISTEMICOS_PROVENANCE_HMAC_KEY -> ValueError
    monkeypatch.delenv("EPISTEMICOS_AUDIT_HMAC_KEY", raising=False)
    monkeypatch.setenv("EPISTEMICOS_PROVENANCE_HMAC_KEY", "")
    with pytest.raises(ValueError, match="hmac_key cannot be empty"):
        EpistemicOrchestrator(audit_log_path=audit_file)

    # 3. Valid non-empty environment variables -> loaded as bytes and configured
    monkeypatch.setenv("EPISTEMICOS_AUDIT_HMAC_KEY", "secret_audit_key_123")
    monkeypatch.setenv("EPISTEMICOS_PROVENANCE_HMAC_KEY", "secret_prov_key_456")
    orch_keyed = EpistemicOrchestrator(audit_log_path=audit_file)
    assert orch_keyed.audit_logger.hmac_key == b"secret_audit_key_123"
    assert orch_keyed.execution_boundary.store.hmac_key == b"secret_prov_key_456"

    # 4. Unset environment variables -> default to None (unkeyed mode)
    monkeypatch.delenv("EPISTEMICOS_AUDIT_HMAC_KEY", raising=False)
    monkeypatch.delenv("EPISTEMICOS_PROVENANCE_HMAC_KEY", raising=False)
    orch_unkeyed = EpistemicOrchestrator(audit_log_path=audit_file)
    assert orch_keyed.audit_logger.hmac_key is not None
    assert orch_unkeyed.audit_logger.hmac_key is None
    assert orch_unkeyed.execution_boundary.store.hmac_key is None
