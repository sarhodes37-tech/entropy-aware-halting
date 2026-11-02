"""
Unit test suite for epistemicos.action_policy module.
Validates ActionPolicy evaluation, ActionRequest, PolicyDecision,
and related action policy and side-effect engine functionality.
"""

import time
import pytest
from epistemicos.action_policy import (
    ActionCategory,
    ActionPolicy,
    ActionRequest,
    ActionRegistry,
    PolicyDecision,
    RegisteredActionDefinition,
    SideEffectPolicyEngine,
    TypedHumanApprovalRecord,
)


class TestActionPolicyEvaluate:
    """Test suite for ActionPolicy.evaluate and related authorization behavior."""

    def test_evaluate_allowed_action(self):
        """Validates that an action in allowed_actions produces an allowed PolicyDecision."""
        policy = ActionPolicy(allowed_actions={"read_data", "query_status"})
        request = ActionRequest(action="read_data", resource="/data/metrics")
        decision = policy.evaluate(request)

        assert isinstance(decision, PolicyDecision)
        assert decision.allowed is True
        assert decision.reason == "Allowed by default"

    def test_evaluate_denied_action_not_allowed(self):
        """Validates that an action not in allowed_actions produces a denied PolicyDecision."""
        policy = ActionPolicy(allowed_actions={"read_data"})
        request = ActionRequest(action="delete_db", resource="/data/primary")
        decision = policy.evaluate(request)

        assert isinstance(decision, PolicyDecision)
        assert decision.allowed is False
        assert decision.reason == "Action not explicitly allowed"

    def test_evaluate_default_empty_allowed_actions(self):
        """Validates default initialization of ActionPolicy with None/empty allowed_actions."""
        policy_default = ActionPolicy()
        assert policy_default.allowed_actions == set()

        request = ActionRequest(action="any_action")
        decision = policy_default.evaluate(request)
        assert decision.allowed is False
        assert decision.reason == "Action not explicitly allowed"

    def test_evaluate_explicit_empty_allowed_actions(self):
        """Validates ActionPolicy initialized with an empty set denies actions."""
        policy = ActionPolicy(allowed_actions=set())
        request = ActionRequest(action="any_action")
        decision = policy.evaluate(request)
        assert decision.allowed is False
        assert decision.reason == "Action not explicitly allowed"

    def test_evaluate_case_sensitivity(self):
        """Validates exact case sensitivity of action matching."""
        policy = ActionPolicy(allowed_actions={"read_file"})
        request_upper = ActionRequest(action="READ_FILE")
        decision = policy.evaluate(request_upper)
        assert decision.allowed is False
        assert decision.reason == "Action not explicitly allowed"

    def test_action_request_fields_preservation(self):
        """Validates that ActionRequest preserves action, resource, and context fields."""
        ctx = {"user_id": "usr_123", "role": "auditor"}
        req = ActionRequest(action="inspect_log", resource="/var/log/audit.log", context=ctx)
        assert req.action == "inspect_log"
        assert req.resource == "/var/log/audit.log"
        assert req.context == ctx

    def test_action_request_default_fields(self):
        """Validates default values for optional ActionRequest fields."""
        req = ActionRequest(action="status")
        assert req.action == "status"
        assert req.resource is None
        assert req.context is None

    def test_policy_decision_dataclass_fields(self):
        """Validates PolicyDecision attribute assignment and equality."""
        dec1 = PolicyDecision(allowed=True, reason="Allowed by default")
        dec2 = PolicyDecision(allowed=True, reason="Allowed by default")
        dec3 = PolicyDecision(allowed=False, reason="Action not explicitly allowed")

        assert dec1.allowed is True
        assert dec1.reason == "Allowed by default"
        assert dec1 == dec2
        assert dec1 != dec3


class TestActionPolicyEdgeCasesAndEngine:
    """Additional unit tests ensuring comprehensive coverage of action_policy.py."""

    def test_action_registry_custom_actions_and_lookup(self):
        """Validates custom actions registration, lookup, and fallback classification."""
        custom_action = RegisteredActionDefinition(
            operation_id="custom_analytics",
            category=ActionCategory.READ_ONLY_LOCAL,
            description="Custom local analytics read",
            requires_human_approval=False,
            allowed_resources={"*"},
            is_externally_consequential=False,
        )
        registry = ActionRegistry(custom_actions={"custom_analytics": custom_action})
        assert registry.lookup_action("custom_analytics") == custom_action
        assert registry.classify_action("custom_analytics") == ActionCategory.READ_ONLY_LOCAL

        # Fallback to STATE_MUTATION for unknown action
        assert registry.classify_action("completely_unknown_op") == ActionCategory.STATE_MUTATION

    def test_compute_canonical_digest_variants(self):
        """Validates compute_canonical_digest with bytes, str, dict, and non-serializable object."""
        engine = SideEffectPolicyEngine(signing_secret="TEST_SECRET")

        # Bytes
        d_bytes = engine.compute_canonical_digest(b"test_payload")
        assert isinstance(d_bytes, str) and len(d_bytes) == 64

        # String
        d_str = engine.compute_canonical_digest("test_payload")
        assert d_bytes == d_str

        # Dict JSON serializable
        d_dict = engine.compute_canonical_digest({"b": 2, "a": 1})
        d_dict2 = engine.compute_canonical_digest({"a": 1, "b": 2})
        assert d_dict == d_dict2  # sort_keys ensures identical hash

        # Object causing json dumps fallback (e.g. object with circular ref or custom type)
        from unittest.mock import patch
        with patch("json.dumps", side_effect=TypeError("cannot serialize")):
            d_fallback = engine.compute_canonical_digest({"key": "val"})
            assert isinstance(d_fallback, str) and len(d_fallback) == 64

    def test_compute_approval_signature_missing_secret(self):
        """Validates ValueError when compute_approval_signature has no signing secret."""
        engine = SideEffectPolicyEngine(signing_secret=None)
        engine.signing_secret = None
        with pytest.raises(ValueError, match="No signing secret configured"):
            engine.compute_approval_signature(("a", "b", "c"))

    def test_verify_approval_record_invalid_record(self):
        """Validates rejection of non-TypedHumanApprovalRecord input."""
        engine = SideEffectPolicyEngine(signing_secret="SECRET")
        valid, msg = engine.verify_approval_record(
            record=None,  # type: ignore
            expected_operation_id="op",
            expected_target="tgt",
            expected_payload={},
            expected_task_id="tsk",
        )
        assert valid is False
        assert msg == "Invalid or missing approval record"

    def test_verify_approval_record_missing_secret(self):
        """Validates rejection when engine has no signing secret."""
        engine = SideEffectPolicyEngine(signing_secret=None)
        engine.signing_secret = None
        record = TypedHumanApprovalRecord(
            approval_id="A1",
            operation_id="op",
            target_resource="tgt",
            canonical_args_digest="digest",
            task_id="tsk",
            policy_version="1.0.0",
            approved_by_principal="admin",
            timestamp="2026-01-01T00:00:00Z",
            signature="sig",
        )
        valid, msg = engine.verify_approval_record(
            record=record,
            expected_operation_id="op",
            expected_target="tgt",
            expected_payload={},
            expected_task_id="tsk",
        )
        assert valid is False
        assert msg == "No signing secret configured for approval verification"

    def test_verify_approval_record_mismatches(self):
        """Validates individual mismatch checks in verify_approval_record."""
        secret = "TEST_SECRET"
        engine = SideEffectPolicyEngine(signing_secret=secret)
        payload = {"param": "val"}
        digest = engine.compute_canonical_digest(payload)

        base_kwargs = {
            "approval_id": "APP_1",
            "operation_id": "op_test",
            "target_resource": "res_target",
            "canonical_args_digest": digest,
            "task_id": "task_1",
            "policy_version": "1.0.0",
            "approved_by_principal": "admin",
            "timestamp": "2026-01-01T00:00:00Z",
        }
        sig = engine.compute_approval_signature((
            base_kwargs["approval_id"],
            base_kwargs["operation_id"],
            base_kwargs["target_resource"],
            base_kwargs["canonical_args_digest"],
            base_kwargs["task_id"],
            base_kwargs["policy_version"],
            base_kwargs["approved_by_principal"],
        ))
        record = TypedHumanApprovalRecord(signature=sig, **base_kwargs)

        # 1. Operation mismatch
        valid, msg = engine.verify_approval_record(
            record=record,
            expected_operation_id="different_op",
            expected_target="res_target",
            expected_payload=payload,
            expected_task_id="task_1",
        )
        assert valid is False
        assert "Approval operation mismatch" in msg

        # 2. Target mismatch
        valid, msg = engine.verify_approval_record(
            record=record,
            expected_operation_id="op_test",
            expected_target="different_target",
            expected_payload=payload,
            expected_task_id="task_1",
        )
        assert valid is False
        assert "Approval target mismatch" in msg

        # 3. Payload digest mismatch
        valid, msg = engine.verify_approval_record(
            record=record,
            expected_operation_id="op_test",
            expected_target="res_target",
            expected_payload={"different": "payload"},
            expected_task_id="task_1",
        )
        assert valid is False
        assert "Approval payload digest mismatch" in msg

        # 4. Task mismatch
        valid, msg = engine.verify_approval_record(
            record=record,
            expected_operation_id="op_test",
            expected_target="res_target",
            expected_payload=payload,
            expected_task_id="different_task",
        )
        assert valid is False
        assert "Approval task mismatch" in msg

        # 5. Policy version mismatch
        valid, msg = engine.verify_approval_record(
            record=record,
            expected_operation_id="op_test",
            expected_target="res_target",
            expected_payload=payload,
            expected_task_id="task_1",
            expected_policy_version="2.0.0",
        )
        assert valid is False
        assert "Approval policy version mismatch" in msg

        # 6. Bad signature
        bad_sig_record = TypedHumanApprovalRecord(signature="invalid_sig", **base_kwargs)
        valid, msg = engine.verify_approval_record(
            record=bad_sig_record,
            expected_operation_id="op_test",
            expected_target="res_target",
            expected_payload=payload,
            expected_task_id="task_1",
        )
        assert valid is False
        assert "Approval signature verification failed" in msg

    def test_violation_counts_tracking(self):
        """Validates violation count tracking on correlation IDs."""
        engine = SideEffectPolicyEngine(signing_secret="TEST_SECRET")
        assert engine.get_violation_count("corr_xyz") == 0
        assert engine.record_scope_violation("corr_xyz") == 1
        assert engine.record_scope_violation("corr_xyz") == 2
        assert engine.get_violation_count("corr_xyz") == 2
