"""
Unit test suite for epistemicos.action_policy module.
Validates ActionPolicy evaluation, ActionRequest, PolicyDecision,
and related action policy and side-effect engine security invariants.
"""

import pytest
from epistemicos import ActionPolicy, ActionRequest
from epistemicos.action_policy import (
    PolicyDecision,
    SideEffectPolicyEngine,
    TypedHumanApprovalRecord,
)


class TestActionPolicySecurityContract:
    """
    Test suite for ActionPolicy.evaluate verifying behavioral invariants,
    failure modes, and documentation of the preliminary action allowlist contract.
    """

    def test_public_package_imports(self):
        """Validates that ActionRequest, ActionPolicy, and ActionPolicyDecision are exposed at package root."""
        from epistemicos import ActionPolicy as RootActionPolicy
        from epistemicos import ActionRequest as RootActionRequest
        from epistemicos import ActionPolicyDecision as RootActionPolicyDecision

        assert RootActionPolicy is ActionPolicy
        assert RootActionRequest is ActionRequest
        assert RootActionPolicyDecision is PolicyDecision

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

    def test_evaluate_same_action_different_resources(self):
        """
        Validates the security contract that ActionPolicy is strictly an action-name allowlist.
        Both requests with the same allowed action against two different resources (one public,
        one sensitive) are allowed at this preliminary filter stage. Comprehensive resource-level
        scoping and path restrictions must be enforced downstream by SideEffectPolicyEngine
        or TrustedExecutionBoundary.
        """
        policy = ActionPolicy(allowed_actions={"read_file"})
        req_public = ActionRequest(action="read_file", resource="/public/readme.txt")
        req_secret = ActionRequest(action="read_file", resource="/etc/shadow")

        dec_public = policy.evaluate(req_public)
        dec_secret = policy.evaluate(req_secret)

        # Under the action-name-only contract, both evaluate to allowed:
        assert dec_public.allowed is True
        assert dec_secret.allowed is True
        assert dec_public.reason == "Allowed by default"
        assert dec_secret.reason == "Allowed by default"

    def test_evaluate_context_preservation_and_intentional_omission(self):
        """
        Validates that ActionRequest preserves context metadata, but ActionPolicy intentionally
        does not use context to grant or deny access (contract is action-name-only).
        """
        policy = ActionPolicy(allowed_actions={"read_file"})
        ctx_admin = {"role": "admin", "privileged": True}
        ctx_unauth = {"role": "guest", "privileged": False}

        req_admin = ActionRequest(action="read_file", resource="/data", context=ctx_admin)
        req_guest = ActionRequest(action="read_file", resource="/data", context=ctx_unauth)
        req_denied_admin = ActionRequest(action="delete_db", resource="/data", context=ctx_admin)

        assert req_admin.context == ctx_admin
        assert req_guest.context == ctx_unauth

        # Context does not alter ActionPolicy evaluation:
        assert policy.evaluate(req_admin).allowed is True
        assert policy.evaluate(req_guest).allowed is True
        assert policy.evaluate(req_denied_admin).allowed is False

    def test_evaluate_missing_empty_and_malformed_actions(self):
        """Validates fail-closed denial for missing, empty, or non-string action values."""
        policy = ActionPolicy(allowed_actions={"", "   ", "read_file"})

        # Empty string
        dec_empty = policy.evaluate(ActionRequest(action=""))
        assert dec_empty.allowed is False
        assert dec_empty.reason == "Action not explicitly allowed"

        # None as action
        dec_none = policy.evaluate(ActionRequest(action=None))  # type: ignore
        assert dec_none.allowed is False
        assert dec_none.reason == "Action not explicitly allowed"

        # Non-string action type
        dec_int = policy.evaluate(ActionRequest(action=12345))  # type: ignore
        assert dec_int.allowed is False
        assert dec_int.reason == "Action not explicitly allowed"

    def test_evaluate_invalid_request_type(self):
        """Validates that passing a non-ActionRequest object raises TypeError."""
        policy = ActionPolicy(allowed_actions={"read_file"})

        with pytest.raises(TypeError, match="Expected ActionRequest instance"):
            policy.evaluate("read_file")  # type: ignore

        with pytest.raises(TypeError, match="Expected ActionRequest instance"):
            policy.evaluate({"action": "read_file"})  # type: ignore

    def test_evaluate_mutation_of_caller_allowed_actions_set(self):
        """Validates that mutating the caller's set after initialization does not alter policy state."""
        caller_set = {"read_data"}
        policy = ActionPolicy(allowed_actions=caller_set)

        # Mutate caller set after policy initialization
        caller_set.add("delete_db")

        # Action added to caller_set should still be denied by the policy
        assert policy.evaluate(ActionRequest(action="delete_db")).allowed is False
        assert "delete_db" not in policy.allowed_actions

    def test_independent_policy_instances(self):
        """Validates that distinct ActionPolicy instances have independent, non-shared state."""
        pol1 = ActionPolicy(allowed_actions={"action_a"})
        pol2 = ActionPolicy(allowed_actions={"action_b"})

        req_a = ActionRequest(action="action_a")
        req_b = ActionRequest(action="action_b")

        assert pol1.evaluate(req_a).allowed is True
        assert pol1.evaluate(req_b).allowed is False

        assert pol2.evaluate(req_a).allowed is False
        assert pol2.evaluate(req_b).allowed is True

    def test_evaluate_default_and_explicit_empty_allowed_actions(self):
        """Validates default initialization of ActionPolicy with None or empty set denies all actions."""
        policy_default = ActionPolicy()
        assert policy_default.allowed_actions == set()
        assert policy_default.evaluate(ActionRequest(action="any_action")).allowed is False

        policy_explicit_empty = ActionPolicy(allowed_actions=set())
        assert policy_explicit_empty.evaluate(ActionRequest(action="any_action")).allowed is False

    def test_evaluate_case_sensitivity(self):
        """Validates exact case sensitivity of action matching."""
        policy = ActionPolicy(allowed_actions={"read_file"})
        assert policy.evaluate(ActionRequest(action="READ_FILE")).allowed is False
        assert policy.evaluate(ActionRequest(action="read_file")).allowed is True

    def test_policy_decision_dataclass_equality(self):
        """Validates PolicyDecision attribute assignment and equality."""
        dec1 = PolicyDecision(allowed=True, reason="Allowed by default")
        dec2 = PolicyDecision(allowed=True, reason="Allowed by default")
        dec3 = PolicyDecision(allowed=False, reason="Action not explicitly allowed")

        assert dec1.allowed is True
        assert dec1.reason == "Allowed by default"
        assert dec1 == dec2
        assert dec1 != dec3


class TestSideEffectPolicyEngineInvariants:
    """
    Focused unit tests for SideEffectPolicyEngine security invariants,
    avoiding duplicate coverage already asserted in test_phase2_egress_controls.py.
    """

    @pytest.mark.parametrize(
        "field_name, tampered_val",
        [
            ("approval_id", "APP-TAMPERED-999"),
            ("operation_id", "delete_db"),
            ("target_resource", "https://registry.npmjs.org/tampered-pkg"),
            ("canonical_args_digest", "0000000000000000000000000000000000000000000000000000000000000000"),
            ("task_id", "TASK-TAMPERED-999"),
            ("policy_version", "2.0.0"),
            ("approved_by_principal", "attacker_principal"),
            ("expires_at", 1700000500.0),
        ],
    )
    def test_signature_binds_every_signed_field_individually(self, field_name, tampered_val):
        """
        Validates that TypedHumanApprovalRecord HMAC signature binds every single signed field.
        Tampering with each individual signed field while updating the corresponding expectation
        bypasses the initial field-equality checks and isolates failure to signature verification.
        """
        secret = "TEST_SECRET"
        engine = SideEffectPolicyEngine(signing_secret=secret)
        payload = {"op": "publish"}
        digest = engine.compute_canonical_digest(payload)
        base_expires_at = 1700000000.0

        base_fields = {
            "approval_id": "APP-FIELD-1",
            "operation_id": "package_publish",
            "target_resource": "https://registry.npmjs.org/pkg",
            "canonical_args_digest": digest,
            "task_id": "TASK-FIELD-1",
            "policy_version": "1.0.0",
            "approved_by_principal": "security_admin",
            "timestamp": "2026-01-01T00:00:00Z",
            "expires_at": base_expires_at,
        }

        # Baseline valid signature computed across all 8 fields including expires_at
        valid_sig = engine.compute_approval_signature((
            base_fields["approval_id"],
            base_fields["operation_id"],
            base_fields["target_resource"],
            base_fields["canonical_args_digest"],
            base_fields["task_id"],
            base_fields["policy_version"],
            base_fields["approved_by_principal"],
            str(base_fields["expires_at"]),
        ))

        # Baseline verification passes
        valid_rec = TypedHumanApprovalRecord(signature=valid_sig, **base_fields)
        ok, msg = engine.verify_approval_record(
            record=valid_rec,
            expected_operation_id=base_fields["operation_id"],
            expected_target=base_fields["target_resource"],
            expected_payload=payload,
            expected_task_id=base_fields["task_id"],
            expected_policy_version=base_fields["policy_version"],
            current_time=1699999000.0,
        )
        assert ok is True, f"Baseline verification failed: {msg}"

        # Tamper with exactly one field
        tampered_fields = dict(base_fields)
        tampered_fields[field_name] = tampered_val
        tampered_rec = TypedHumanApprovalRecord(signature=valid_sig, **tampered_fields)

        # Align expected arguments so field-mismatch checks pass and the check reaches signature verification
        exp_op = tampered_fields["operation_id"]
        exp_target = tampered_fields["target_resource"]
        exp_task = tampered_fields["task_id"]
        exp_version = tampered_fields["policy_version"]
        eval_payload = payload

        if field_name == "canonical_args_digest":
            eval_payload = b"tampered_payload_matching_digest"
            from unittest.mock import patch
            with patch.object(engine, "compute_canonical_digest", return_value=tampered_val):
                ok_tampered, msg_tampered = engine.verify_approval_record(
                    record=tampered_rec,
                    expected_operation_id=exp_op,
                    expected_target=exp_target,
                    expected_payload=eval_payload,
                    expected_task_id=exp_task,
                    expected_policy_version=exp_version,
                    current_time=1699999000.0,
                )
        else:
            ok_tampered, msg_tampered = engine.verify_approval_record(
                record=tampered_rec,
                expected_operation_id=exp_op,
                expected_target=exp_target,
                expected_payload=eval_payload,
                expected_task_id=exp_task,
                expected_policy_version=exp_version,
                current_time=1699999000.0,
            )

        assert ok_tampered is False
        assert msg_tampered == "Approval signature verification failed", (
            f"Expected signature verification failure for tampered field '{field_name}', got '{msg_tampered}'"
        )

    @pytest.mark.parametrize("is_expiring", [False, True])
    def test_timestamp_is_not_signed_and_modification_preserves_signature(self, is_expiring):
        """
        Explicitly documents and tests the current behavioral invariant that `timestamp` is NOT
        included in the HMAC signature tuple (both for expiring and non-expiring records).
        Modifying `record.timestamp` does not invalidate the HMAC signature.
        """
        secret = "TEST_SECRET"
        engine = SideEffectPolicyEngine(signing_secret=secret)
        payload = {"op": "test"}
        digest = engine.compute_canonical_digest(payload)
        expires_at = 1700000000.0 if is_expiring else None

        base_fields = {
            "approval_id": "APP-TIME-1",
            "operation_id": "local_read",
            "target_resource": "/data",
            "canonical_args_digest": digest,
            "task_id": "TASK-TIME-1",
            "policy_version": "1.0.0",
            "approved_by_principal": "auditor",
            "timestamp": "2026-01-01T00:00:00Z",
            "expires_at": expires_at,
        }

        if is_expiring:
            sig_tuple = (
                base_fields["approval_id"],
                base_fields["operation_id"],
                base_fields["target_resource"],
                base_fields["canonical_args_digest"],
                base_fields["task_id"],
                base_fields["policy_version"],
                base_fields["approved_by_principal"],
                str(expires_at),
            )
        else:
            sig_tuple = (
                base_fields["approval_id"],
                base_fields["operation_id"],
                base_fields["target_resource"],
                base_fields["canonical_args_digest"],
                base_fields["task_id"],
                base_fields["policy_version"],
                base_fields["approved_by_principal"],
            )

        valid_sig = engine.compute_approval_signature(sig_tuple)

        # Modifying timestamp to a completely different timestamp
        modified_rec = TypedHumanApprovalRecord(
            signature=valid_sig,
            timestamp="2099-12-31T23:59:59Z",
            approval_id=base_fields["approval_id"],
            operation_id=base_fields["operation_id"],
            target_resource=base_fields["target_resource"],
            canonical_args_digest=base_fields["canonical_args_digest"],
            task_id=base_fields["task_id"],
            policy_version=base_fields["policy_version"],
            approved_by_principal=base_fields["approved_by_principal"],
            expires_at=expires_at,
        )

        ok, msg = engine.verify_approval_record(
            record=modified_rec,
            expected_operation_id=base_fields["operation_id"],
            expected_target=base_fields["target_resource"],
            expected_payload=payload,
            expected_task_id=base_fields["task_id"],
            expected_policy_version=base_fields["policy_version"],
            current_time=1699999000.0 if is_expiring else None,
        )
        # Demonstrates that timestamp is currently unsigned and does not invalidate verification
        assert ok is True
        assert msg == "Approval record validated"

    def test_expired_approval_record_with_explicit_timestamp(self):
        """Validates that expired TypedHumanApprovalRecord fails closed even with a valid signature."""
        secret = "TEST_SECRET"
        engine = SideEffectPolicyEngine(signing_secret=secret)
        payload = {"data": "test"}
        digest = engine.compute_canonical_digest(payload)
        expires_at = 1700000000.0

        sig = engine.compute_approval_signature((
            "APP-EXP-1", "package_publish", "https://registry.npmjs.org",
            digest, "TASK-EXP", "1.0.0", "admin", str(expires_at)
        ))

        record = TypedHumanApprovalRecord(
            approval_id="APP-EXP-1",
            operation_id="package_publish",
            target_resource="https://registry.npmjs.org",
            canonical_args_digest=digest,
            task_id="TASK-EXP",
            policy_version="1.0.0",
            approved_by_principal="admin",
            timestamp="2026-01-01T00:00:00Z",
            signature=sig,
            expires_at=expires_at,
        )

        # Verification at time > expires_at must fail
        valid, msg = engine.verify_approval_record(
            record=record,
            expected_operation_id="package_publish",
            expected_target="https://registry.npmjs.org",
            expected_payload=payload,
            expected_task_id="TASK-EXP",
            current_time=expires_at + 10.0,
        )
        assert valid is False
        assert "Approval record expired" in msg

    def test_unregistered_action_fails_closed(self):
        """Validates that unregistered actions fail closed with scope violation recording."""
        engine = SideEffectPolicyEngine(signing_secret="TEST_SECRET")
        allowed, reason = engine.evaluate_side_effect_authorization(
            operation_id="completely_unregistered_action",
            target_resource="http://example.com",
            payload={},
            task_id="TASK-1",
            correlation_id="CORR-UNREG-1",
        )
        assert allowed is False
        assert "is unregistered" in reason
        assert engine.get_violation_count("CORR-UNREG-1") == 1

    def test_canonical_digest_fallback_behavior_and_limitation(self):
        """
        Documents and asserts the current behavior of the json.dumps fallback in compute_canonical_digest.

        ARCHITECTURAL NOTE:
        When json.dumps raises an exception, the engine falls back to `str(payload).encode("utf-8")`.
        This produces a valid SHA-256 hash, but `str()` serialization is NOT canonical across
        different object formats or memory addresses (e.g. object default reprs). This test
        confirms the current fallback behavior without endorsing it as collision-resistant canonicalization.
        """
        engine = SideEffectPolicyEngine(signing_secret="TEST_SECRET")
        from unittest.mock import patch

        with patch("json.dumps", side_effect=TypeError("Simulation of non-serializable object")):
            fallback_digest = engine.compute_canonical_digest({"unserializable": True})
            assert isinstance(fallback_digest, str)
            assert len(fallback_digest) == 64
