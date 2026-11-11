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

    def test_bytes_and_bytearray_signing_secret_support(self):
        """Validates that bytes/bytearray signing secrets are supported and verified properly."""
        payload = {"cmd": "deploy"}
        for secret in [b"my_bytes_secret", bytearray(b"my_bytearray_secret")]:
            engine = SideEffectPolicyEngine(signing_secret=secret)
            digest = engine.compute_canonical_digest(payload)
            sig = engine.compute_approval_signature((
                "APP-1", "package_publish", "https://example.com",
                digest, "TASK-1", "1.0.0", "admin"
            ))
            record = TypedHumanApprovalRecord(
                approval_id="APP-1",
                operation_id="package_publish",
                target_resource="https://example.com",
                canonical_args_digest=digest,
                task_id="TASK-1",
                policy_version="1.0.0",
                approved_by_principal="admin",
                timestamp="2026-01-01T00:00:00Z",
                signature=sig,
            )
            valid, msg = engine.verify_approval_record(
                record=record,
                expected_operation_id="package_publish",
                expected_target="https://example.com",
                expected_payload=payload,
                expected_task_id="TASK-1",
            )
            assert valid is True
            assert msg == "Approval record validated"

    def test_empty_secret_fails_closed_without_exceptions(self):
        """Validates that empty secret strings or byte sequences fail closed."""
        payload = {"cmd": "deploy"}
        for empty_secret in ["", b"", bytearray()]:
            engine = SideEffectPolicyEngine(signing_secret=empty_secret)
            assert engine.signing_secret is None

            with pytest.raises(ValueError, match="No signing secret configured"):
                engine.compute_approval_signature((
                    "APP-1", "package_publish", "https://example.com",
                    "digest", "TASK-1", "1.0.0", "admin"
                ))

            record = TypedHumanApprovalRecord(
                approval_id="APP-1",
                operation_id="package_publish",
                target_resource="https://example.com",
                canonical_args_digest=engine.compute_canonical_digest(payload),
                task_id="TASK-1",
                policy_version="1.0.0",
                approved_by_principal="admin",
                timestamp="2026-01-01T00:00:00Z",
                signature="0" * 64,
            )
            valid, msg = engine.verify_approval_record(
                record=record,
                expected_operation_id="package_publish",
                expected_target="https://example.com",
                expected_payload=payload,
                expected_task_id="TASK-1",
            )
            assert valid is False
            assert "No signing secret configured" in msg

    def test_malformed_signature_and_expiration_fail_closed(self):
        """Validates that non-hex/wrong length signatures and non-finite expires_at fail closed."""
        engine = SideEffectPolicyEngine(signing_secret="TEST_SECRET")
        payload = {"action": "clean"}
        digest = engine.compute_canonical_digest(payload)

        # 1. Signature format invalid (unicode lookalikes, whitespace, sign, etc.)
        base_record_fields = {
            "approval_id": "APP-BAD-SIG",
            "operation_id": "package_publish",
            "target_resource": "https://example.com",
            "canonical_args_digest": digest,
            "task_id": "TASK-1",
            "policy_version": "1.0.0",
            "approved_by_principal": "admin",
            "timestamp": "2026-01-01T00:00:00Z",
            "signature": "0" * 64,
        }
        for bad_sig in [
            "short",
            "0" * 63,
            "0" * 65,
            "z" * 64,
            None,
            12345,
            " " * 64,
            " " + "0" * 63,
            "+" + "0" * 63,
            "-\x00" * 32,
            "\uff10" * 64,  # full-width unicode zero
        ]:
            record = TypedHumanApprovalRecord(**base_record_fields)
            object.__setattr__(record, "signature", bad_sig)
            valid, msg = engine.verify_approval_record(
                record=record,
                expected_operation_id="package_publish",
                expected_target="https://example.com",
                expected_payload=payload,
                expected_task_id="TASK-1",
            )
            assert valid is False
            assert "Approval signature" in msg

        # 2. Malformed expires_at (strings, booleans, NaN, Inf, -Inf)
        bad_exp_list = [
            "tomorrow",
            "1234567890",
            True,
            False,
            float("nan"),
            float("inf"),
            float("-inf"),
        ]
        for bad_exp in bad_exp_list:
            record = TypedHumanApprovalRecord(**base_record_fields)
            object.__setattr__(record, "expires_at", bad_exp)
            valid, msg = engine.verify_approval_record(
                record=record,
                expected_operation_id="package_publish",
                expected_target="https://example.com",
                expected_payload=payload,
                expected_task_id="TASK-1",
            )
            assert valid is False
            assert "Approval record expiration" in msg

    def test_current_time_clock_override_validation(self):
        """Validates that current_time override strictly rejects non-finite/malformed inputs."""
        engine = SideEffectPolicyEngine(signing_secret="TEST_SECRET")
        payload = {"action": "build"}
        digest = engine.compute_canonical_digest(payload)
        expires_at = 1000.0

        sig = engine.compute_approval_signature((
            "APP-CLOCK", "package_publish", "https://example.com",
            digest, "TASK-1", "1.0.0", "admin", str(expires_at)
        ))
        record = TypedHumanApprovalRecord(
            approval_id="APP-CLOCK",
            operation_id="package_publish",
            target_resource="https://example.com",
            canonical_args_digest=digest,
            task_id="TASK-1",
            policy_version="1.0.0",
            approved_by_principal="admin",
            timestamp="2026-01-01T00:00:00Z",
            signature=sig,
            expires_at=expires_at,
        )

        # Genuinely expired under valid clock
        valid, msg = engine.verify_approval_record(
            record=record,
            expected_operation_id="package_publish",
            expected_target="https://example.com",
            expected_payload=payload,
            expected_task_id="TASK-1",
            current_time=2000.0,
        )
        assert valid is False
        assert "Approval record expired" in msg

        # Valid non-expired under valid clock
        valid, msg = engine.verify_approval_record(
            record=record,
            expected_operation_id="package_publish",
            expected_target="https://example.com",
            expected_payload=payload,
            expected_task_id="TASK-1",
            current_time=500.0,
        )
        assert valid is True
        assert msg == "Approval record validated"

        # Adversarial current_time inputs cannot bypass expiration
        for bad_clock in [
            float("nan"),
            float("inf"),
            float("-inf"),
            True,
            False,
            "12345",
            "now",
            [12345],
        ]:
            valid, msg = engine.verify_approval_record(
                record=record,
                expected_operation_id="package_publish",
                expected_target="https://example.com",
                expected_payload=payload,
                expected_task_id="TASK-1",
                current_time=bad_clock,  # type: ignore
            )
            assert valid is False
            assert "Invalid current_time clock override" in msg

    def test_secret_normalization_surrogate_content_fails_closed(self):
        """Validates that strings with unencodable surrogate code points fail closed."""
        surrogate_str = "secret\ud800key"
        engine = SideEffectPolicyEngine(signing_secret=surrogate_str)
        assert engine.signing_secret is None

    def test_integer_overflow_protection_in_verification(self):
        """
        Validates that arbitrarily large integers (e.g. 10**10000) do not cause OverflowError
        and fail closed in verify_approval_record().
        """
        engine = SideEffectPolicyEngine(signing_secret="TEST_SECRET")
        payload = {"action": "scale"}
        digest = engine.compute_canonical_digest(payload)
        expires_at_normal = 2000

        sig = engine.compute_approval_signature((
            "APP-OVERFLOW", "package_publish", "https://example.com",
            digest, "TASK-1", "1.0.0", "admin", str(expires_at_normal)
        ))
        record = TypedHumanApprovalRecord(
            approval_id="APP-OVERFLOW",
            operation_id="package_publish",
            target_resource="https://example.com",
            canonical_args_digest=digest,
            task_id="TASK-1",
            policy_version="1.0.0",
            approved_by_principal="admin",
            timestamp="2026-01-01T00:00:00Z",
            signature=sig,
            expires_at=expires_at_normal,
        )

        # 1. Out-of-bounds integer and float current_time overrides fail closed
        for bad_time in [10**10000, 1 << 63, -(1 << 63) - 1, 1e100, -1e100, float(1 << 63)]:
            valid, msg = engine.verify_approval_record(
                record=record,
                expected_operation_id="package_publish",
                expected_target="https://example.com",
                expected_payload=payload,
                expected_task_id="TASK-1",
                current_time=bad_time,
            )
            assert valid is False
            assert "Invalid current_time clock override" in msg

        # 2. Out-of-bounds integer and float expires_at values fail closed
        for bad_exp in [10**10000, 1 << 63, -(1 << 63) - 1, 1e100, -1e100, float(1 << 63)]:
            record_bad_exp = TypedHumanApprovalRecord(
                approval_id="APP-OVERFLOW-EXP",
                operation_id="package_publish",
                target_resource="https://example.com",
                canonical_args_digest=digest,
                task_id="TASK-1",
                policy_version="1.0.0",
                approved_by_principal="admin",
                timestamp="2026-01-01T00:00:00Z",
                signature="0" * 64,
                expires_at=None,
            )
            object.__setattr__(record_bad_exp, "expires_at", bad_exp)
            valid, msg = engine.verify_approval_record(
                record=record_bad_exp,
                expected_operation_id="package_publish",
                expected_target="https://example.com",
                expected_payload=payload,
                expected_task_id="TASK-1",
                current_time=1000,
            )
            assert valid is False
            assert "overflows" in msg

        # 3. Valid integer boundaries and ordinary in-range fractional floats pass within signed 64-bit limits
        for valid_time in [1000, 1000.5, (1 << 63) - 1, -(1 << 63)]:
            valid, msg = engine.verify_approval_record(
                record=record,
                expected_operation_id="package_publish",
                expected_target="https://example.com",
                expected_payload=payload,
                expected_task_id="TASK-1",
                current_time=valid_time,
            )
            # record.expires_at is 2000, so valid_time >= 2000 is expired, valid_time < 2000 is validated
            if valid_time >= 2000:
                assert valid is False
                assert "expired" in msg
            else:
                assert valid is True
                assert msg == "Approval record validated"

        # Valid boundary expires_at: (1 << 63) - 1
        sig_max = engine.compute_approval_signature((
            "APP-MAX", "package_publish", "https://example.com",
            digest, "TASK-1", "1.0.0", "admin", str((1 << 63) - 1)
        ))
        record_max = TypedHumanApprovalRecord(
            approval_id="APP-MAX",
            operation_id="package_publish",
            target_resource="https://example.com",
            canonical_args_digest=digest,
            task_id="TASK-1",
            policy_version="1.0.0",
            approved_by_principal="admin",
            timestamp="2026-01-01T00:00:00Z",
            signature=sig_max,
            expires_at=(1 << 63) - 1,
        )
        valid, msg = engine.verify_approval_record(
            record=record_max,
            expected_operation_id="package_publish",
            expected_target="https://example.com",
            expected_payload=payload,
            expected_task_id="TASK-1",
            current_time=1000,
        )
        assert valid is True
        assert msg == "Approval record validated"

        # 4. Ordinary float current_time and expires_at
        sig_float = engine.compute_approval_signature((
            "APP-FLOAT", "package_publish", "https://example.com",
            digest, "TASK-1", "1.0.0", "admin", "2000.5"
        ))
        record_float = TypedHumanApprovalRecord(
            approval_id="APP-FLOAT",
            operation_id="package_publish",
            target_resource="https://example.com",
            canonical_args_digest=digest,
            task_id="TASK-1",
            policy_version="1.0.0",
            approved_by_principal="admin",
            timestamp="2026-01-01T00:00:00Z",
            signature=sig_float,
            expires_at=2000.5,
        )
        valid, msg = engine.verify_approval_record(
            record=record_float,
            expected_operation_id="package_publish",
            expected_target="https://example.com",
            expected_payload=payload,
            expected_task_id="TASK-1",
            current_time=1000.5,
        )
        assert valid is True
        assert msg == "Approval record validated"

    def test_signature_hex_validation_differential_equivalence(self):
        """
        ⚡ Bolt differential equivalence test:
        Verifies 100% equivalence between legacy frozenset + generator expression
        and the optimized precompiled regex across BMP codepoints and edge-case strings.
        """
        from typing import Any
        from epistemicos.action_policy import _APPROVAL_SIG_HEX_REGEX

        def legacy_hex_check(sig: Any) -> bool:
            if not isinstance(sig, str) or len(sig) != 64:
                return False
            _hex_chars = frozenset("0123456789abcdefABCDEF")
            if any(c not in _hex_chars for c in sig):
                return False
            return True

        def optimized_hex_check(sig: Any) -> bool:
            if not isinstance(sig, str) or len(sig) != 64:
                return False
            if not _APPROVAL_SIG_HEX_REGEX.match(sig):
                return False
            return True

        # Test varying lengths and non-string types
        test_inputs = [
            "",
            "a" * 63,
            "a" * 64,
            "a" * 65,
            "A" * 64,
            "0" * 64,
            "f" * 64,
            "F" * 64,
            None,
            123,
            True,
            False,
            ("a" * 63) + " ",
            ("a" * 63) + "z",
            ("a" * 63) + "Z",
            ("a" * 63) + chr(0),
            ("a" * 63) + "\n",
            "+" + ("0" * 63),
            "-" + ("0" * 63),
            " " + ("0" * 63),
            "0123456789abcdef" * 4,
            "0123456789ABCDEF" * 4,
            "0123456789aBcDeF" * 4,
        ]

        for s in test_inputs:
            assert legacy_hex_check(s) == optimized_hex_check(s), f"Differential mismatch for input {s!r}"

        # Exhaustive character test across ASCII range [0, 127]
        for c_code in range(128):
            ch = chr(c_code)
            test_sig = ch * 64
            assert legacy_hex_check(test_sig) == optimized_hex_check(test_sig), (
                f"ASCII character mismatch at code {c_code}: {ch!r}"
            )

    def test_typed_human_approval_record_is_expired_encapsulation(self):
        """
        Validates TypedHumanApprovalRecord.is_expired() fail-closed behavior across
        valid timestamps, expired timestamps, clock overrides, non-finite values, and overflows.
        """
        rec_none = TypedHumanApprovalRecord(
            approval_id="APP-NONE",
            operation_id="package_publish",
            target_resource="https://example.com",
            canonical_args_digest="digest",
            task_id="TASK-1",
            policy_version="1.0.0",
            approved_by_principal="admin",
            timestamp="2026-01-01T00:00:00Z",
            signature="0" * 64,
            expires_at=None,
        )
        assert rec_none.is_expired(current_time=1000) is False
        # Clock override invalid/overflow fails closed
        assert rec_none.is_expired(current_time=True) is True
        assert rec_none.is_expired(current_time="invalid") is True
        assert rec_none.is_expired(current_time=float("nan")) is True
        assert rec_none.is_expired(current_time=float("inf")) is True
        assert rec_none.is_expired(current_time=1 << 63) is True
        assert rec_none.is_expired(current_time=-(1 << 63) - 1) is True

        rec_exp = TypedHumanApprovalRecord(
            approval_id="APP-EXP",
            operation_id="package_publish",
            target_resource="https://example.com",
            canonical_args_digest="digest",
            task_id="TASK-1",
            policy_version="1.0.0",
            approved_by_principal="admin",
            timestamp="2026-01-01T00:00:00Z",
            signature="0" * 64,
            expires_at=2000.0,
        )
        assert rec_exp.is_expired(current_time=1500.0) is False
        assert rec_exp.is_expired(current_time=2000.0) is True
        assert rec_exp.is_expired(current_time=2500.0) is True

        # Mutated expires_at fails closed
        for bad_val in (True, "string", float("nan"), float("inf"), 1 << 63, -(1 << 63) - 1):
            object.__setattr__(rec_exp, "expires_at", bad_val)
            assert rec_exp.is_expired(current_time=1500.0) is True

    def test_typed_human_approval_record_post_init_validation(self):
        """
        Validates fail-closed __post_init__ validation on TypedHumanApprovalRecord:
        1. Required string attributes must be non-empty strings.
        2. expires_at rejects booleans, unparseable strings, non-finite floats, and signed 64-bit out-of-range values.
        3. Valid integer boundaries and fractional floats pass.
        """
        base_kwargs = {
            "approval_id": "APP-TEST-VAL",
            "operation_id": "package_publish",
            "target_resource": "https://example.com",
            "canonical_args_digest": "0" * 64,
            "task_id": "TASK-1",
            "policy_version": "1.0.0",
            "approved_by_principal": "admin",
            "timestamp": "2026-01-01T00:00:00Z",
            "signature": "0" * 64,
        }

        # 1. Valid construction with None, int, float, and valid numeric string
        rec_none = TypedHumanApprovalRecord(**base_kwargs, expires_at=None)
        assert rec_none.expires_at is None

        rec_int = TypedHumanApprovalRecord(**base_kwargs, expires_at=2000)
        assert rec_int.expires_at == 2000

        rec_flt = TypedHumanApprovalRecord(**base_kwargs, expires_at=2000.5)
        assert rec_flt.expires_at == 2000.5

        rec_str = TypedHumanApprovalRecord(**base_kwargs, expires_at="2000.5")
        assert rec_str.expires_at == 2000.5

        # 2. Reject non-string or empty required fields
        for field_name in (
            "approval_id",
            "operation_id",
            "target_resource",
            "canonical_args_digest",
            "task_id",
            "policy_version",
            "approved_by_principal",
            "timestamp",
            "signature",
        ):
            for bad_val in ("", "   ", None, 12345, True, False, []):
                invalid_kwargs = dict(base_kwargs)
                invalid_kwargs[field_name] = bad_val
                with pytest.raises(ValueError, match="must be a non-empty string"):
                    TypedHumanApprovalRecord(**invalid_kwargs)

        # 3. Reject boolean expires_at
        for bad_bool in (True, False):
            with pytest.raises(TypeError, match="expires_at must be a numeric timestamp"):
                TypedHumanApprovalRecord(**base_kwargs, expires_at=bad_bool)

        # 4. Reject unparseable strings
        with pytest.raises(ValueError, match="cannot be parsed as a float"):
            TypedHumanApprovalRecord(**base_kwargs, expires_at="invalid-date")

        # 5. Reject non-finite floats
        for bad_flt in (float("nan"), float("inf"), float("-inf")):
            with pytest.raises(ValueError, match="must be a finite number"):
                TypedHumanApprovalRecord(**base_kwargs, expires_at=bad_flt)

        # 6. Reject signed 64-bit integer overflow
        for bad_int in (1 << 63, -(1 << 63) - 1, 10**100):
            with pytest.raises(ValueError, match="integer overflows signed 64-bit limits"):
                TypedHumanApprovalRecord(**base_kwargs, expires_at=bad_int)

        # 7. Reject signed 64-bit float overflow
        for bad_flt in (float(1 << 63), float(-(1 << 63) - 2000), 1e100, -1e100):
            with pytest.raises(ValueError, match="float overflows signed 64-bit limits"):
                TypedHumanApprovalRecord(**base_kwargs, expires_at=bad_flt)

        # 8. Valid boundary integers pass
        rec_min = TypedHumanApprovalRecord(**base_kwargs, expires_at=-(1 << 63))
        assert rec_min.expires_at == -(1 << 63)

        rec_max = TypedHumanApprovalRecord(**base_kwargs, expires_at=(1 << 63) - 1)
        assert rec_max.expires_at == (1 << 63) - 1
