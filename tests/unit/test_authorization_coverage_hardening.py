"""
Comprehensive behavior-driven regression tests hardening epistemicos/authorization.py.

Covers security invariants:
1. Principal authentication and identity verification (PEM/hex/base64 parsing, point decoding,
   pure Ed25519 fallback, assertion validation).
2. Capability issuance, registration, verification, and revocation.
3. Target canonicalization, URL authority checks, and malformed-target rejection.
4. Fencing-token monotonicity, generation allocation, and stale/future rejection.
5. Replay prevention and single-use capability behavior.
6. Persistent authorization state, journal integrity, corrupted records recovery,
   and flock error handling.
7. Concurrency, locking, and atomic competing operations using synchronization primitives.
8. Expiration, clock skew, and temporal validity.
9. Failure handling, malformed inputs, and exception paths.
"""

import base64
import copy
import json
import threading
import time
import pytest
from unittest.mock import patch, MagicMock

import epistemicos.authorization as auth
from epistemicos.authorization import (
    HumanApprovalRecord,
    TrustedTaskContract,
    Policy,
    InMemoryAuthorizationStore,
    FileAuthorizationStore,
    Capability,
    CapabilityRegistry,
    AuthorizationAuthority,
    ExecutorRegistry,
    AuthenticatedPrincipal,
    PrincipalVerifier,
    canonicalize_fencing_scope,
    normalize_target_scope,
    get_callable_identity,
    verify_ed25519_signature,
    _ed25519_verify_pure,
    MAX_TARGET_INPUT_LEN,
)
from tests.unit.test_sec01_sec03_remediation import (
    ExternalTestIdentityAuthority,
    _ed25519_sign,
)


def make_test_cap(
    token_id="tok-1",
    principal_id="principal-1",
    correlation_id="corr-1",
    request_id="req-1",
    action_name="read",
    target="/res",
    canonical_request_digest="digest-1",
    executor_id="exec-1",
    policy_version="1.0.0",
    created_at=None,
    expires_at=None,
    task_id="task-1",
    contract_version="1.0.0",
    fencing_token=1,
    scope_key=None,
    human_approval=None,
):
    if created_at is None:
        created_at = time.time()
    if expires_at is None:
        expires_at = created_at + 300.0
    if scope_key is None:
        scope_key = canonicalize_fencing_scope(task_id, target)
    return Capability(
        token_id=token_id,
        principal_id=principal_id,
        correlation_id=correlation_id,
        request_id=request_id,
        action_name=action_name,
        target=target,
        canonical_request_digest=canonical_request_digest,
        executor_id=executor_id,
        policy_version=policy_version,
        created_at=created_at,
        expires_at=expires_at,
        task_id=task_id,
        contract_version=contract_version,
        fencing_token=fencing_token,
        scope_key=scope_key,
        human_approval=human_approval,
    )


class TestHumanApprovalAndContractInvariants:
    def test_human_approval_expiry_edge_cases(self):
        secret = b"test-secret-32-bytes-long-key!!"
        rec = HumanApprovalRecord(
            approval_id="app-1",
            approver_id="admin",
            action_name="deploy",
            target="prod",
            action_digest="abc",
            request_id="req-1",
            expires_at="1234567890.5",
        )
        rec.sign(secret)

        assert rec.verify_signature(secret, current_time=1234567800.0) is True
        assert rec.verify_signature(secret, current_time=1234567900.0) is False

        rec_inf = HumanApprovalRecord(
            approval_id="app-2",
            approver_id="admin",
            action_name="deploy",
            target="prod",
            action_digest="abc",
            request_id="req-2",
            expires_at=1000.0,
        )
        rec_inf.sign(secret)
        rec_inf.expires_at = "inf"
        assert rec_inf.verify_signature(secret) is False

        rec_nan = HumanApprovalRecord(
            approval_id="app-3",
            approver_id="admin",
            action_name="deploy",
            target="prod",
            action_digest="abc",
            request_id="req-3",
            expires_at=1000.0,
        )
        rec_nan.sign(secret)
        rec_nan.expires_at = "not-a-number"
        assert rec_nan.verify_signature(secret) is False

    def test_human_approval_signing_secret_and_signature_security(self):
        rec = HumanApprovalRecord(
            approval_id="app-sec-1",
            approver_id="admin",
            action_name="deploy",
            target="prod",
            action_digest="abc",
            request_id="req-sec-1",
        )
        # 1. sign() rejects non-bytes or empty signing secret
        with pytest.raises(TypeError, match="signing_secret must be bytes or bytearray"):
            rec.sign(None)
        with pytest.raises(TypeError, match="signing_secret must be bytes or bytearray"):
            rec.sign("string-secret")
        with pytest.raises(ValueError, match="signing_secret cannot be empty"):
            rec.sign(b"")
        with pytest.raises(ValueError, match="signing_secret cannot be empty"):
            rec.sign(bytearray())

        valid_secret = b"valid-secret-key-32-bytes-long!"
        rec.sign(valid_secret)
        assert rec.verify_signature(valid_secret) is True

        # 2. verify_signature() fails closed on empty or non-bytes keys
        assert rec.verify_signature(b"") is False
        assert rec.verify_signature(bytearray()) is False
        assert rec.verify_signature(None) is False
        assert rec.verify_signature("string-secret") is False
        assert rec.verify_signature(12345) is False

        # 3. verify_signature() fails closed on invalid signature formats
        rec_tampered = copy.deepcopy(rec)
        rec_tampered.signature = "x" * 64  # non-hex
        assert rec_tampered.verify_signature(valid_secret) is False

        rec_tampered.signature = "abc"  # too short
        assert rec_tampered.verify_signature(valid_secret) is False

        rec_tampered.signature = ""  # empty
        assert rec_tampered.verify_signature(valid_secret) is False

        rec_tampered.signature = None  # None
        assert rec_tampered.verify_signature(valid_secret) is False

    def test_human_approval_from_input_validation(self):
        data_missing = {
            "approval_id": "app-1",
            "action_name": "deploy",
            "target": "prod",
            "action_digest": "abc",
            "request_id": "req-1",
        }
        assert HumanApprovalRecord.from_input(data_missing) is None
        assert HumanApprovalRecord.from_input(12345) is None

        data_inf = {
            "approval_id": "app-1",
            "approver_id": "admin",
            "action_name": "deploy",
            "target": "prod",
            "action_digest": "abc",
            "request_id": "req-1",
            "expires_at": "inf",
        }
        assert HumanApprovalRecord.from_input(data_inf) is None

        data_neg = copy.deepcopy(data_inf)
        data_neg["expires_at"] = -10.0
        assert HumanApprovalRecord.from_input(data_neg) is None

        data_invalid_str = copy.deepcopy(data_inf)
        data_invalid_str["expires_at"] = "invalid"
        assert HumanApprovalRecord.from_input(data_invalid_str) is None

        data_valid = {
            "approval_id": "app-1",
            "approver_id": "admin",
            "action_name": "deploy",
            "target": "prod",
            "action_digest": "abc",
            "request_id": "req-1",
            "expires_at": 2000000000.0,
            "policy_version": "1.1.0",
            "task_id": "task-xyz",
            "signature": "sig-hex",
        }
        rec = HumanApprovalRecord.from_input(data_valid)
        assert rec is not None
        assert rec.approval_id == "app-1"
        assert rec.task_id == "task-xyz"
        assert rec.policy_version == "1.1.0"

    def test_trusted_task_contract_invariants(self):
        contract = TrustedTaskContract(
            task_id="task-1",
            permitted_actions={"read", "write"},
            resource_scope={"db://cluster-1/*"},
            explicit_prohibitions={"delete"},
            prohibited_resources={"*"},
            expires_at=1000.0,
        )
        secret = b"test-secret-32-bytes-long-key!!"
        contract.sign(secret)
        assert contract.verify_signature(secret, current_time=2000.0) is False
        assert contract.verify_signature(secret, current_time=500.0) is True

        assert contract.is_action_prohibited("read", "db://cluster-1/users") is True
        assert contract.is_action_permitted("read", "db://cluster-1/users") is False

    def test_trusted_task_contract_signing_secret_and_signature_security(self):
        contract = TrustedTaskContract(
            task_id="task-sec-1",
            permitted_actions={"read"},
            resource_scope={"target-1"},
        )
        # 1. sign() rejects non-bytes or empty signing secret
        with pytest.raises(TypeError, match="signing_secret must be bytes or bytearray"):
            contract.sign(None)
        with pytest.raises(TypeError, match="signing_secret must be bytes or bytearray"):
            contract.sign("string-secret")
        with pytest.raises(ValueError, match="signing_secret cannot be empty"):
            contract.sign(b"")
        with pytest.raises(ValueError, match="signing_secret cannot be empty"):
            contract.sign(bytearray())

        valid_secret = b"valid-contract-secret-key-32b!!"
        contract.sign(valid_secret)
        assert contract.verify_signature(valid_secret) is True

        # 2. verify_signature() fails closed on empty or non-bytes keys
        assert contract.verify_signature(b"") is False
        assert contract.verify_signature(bytearray()) is False
        assert contract.verify_signature(None) is False
        assert contract.verify_signature("string-secret") is False
        assert contract.verify_signature(99999) is False

        # 3. verify_signature() fails closed on invalid signature formats
        contract_tampered = copy.deepcopy(contract)
        contract_tampered.signature = "y" * 64  # non-hex
        assert contract_tampered.verify_signature(valid_secret) is False

        contract_tampered.signature = "deadbeef"  # too short
        assert contract_tampered.verify_signature(valid_secret) is False

        contract_tampered.signature = ""
        assert contract_tampered.verify_signature(valid_secret) is False

        contract_tampered.signature = None
        assert contract_tampered.verify_signature(valid_secret) is False

        contract_scoped = TrustedTaskContract(
            task_id="task-2",
            permitted_actions={"read"},
            resource_scope={"target-a"},
            explicit_prohibitions=set(),
            prohibited_resources=set(),
        )
        assert contract_scoped.is_action_permitted("read", "target-b") is False

        c_dict = contract_scoped.to_dict()
        assert c_dict["task_id"] == "task-2"
        assert "target-a" in c_dict["resource_scope"]
        assert c_dict["contract_digest"] == contract_scoped.compute_contract_digest()

        restored = TrustedTaskContract.from_dict(c_dict)
        assert restored.task_id == contract_scoped.task_id
        assert restored.permitted_actions == contract_scoped.permitted_actions
        assert restored.resource_scope == contract_scoped.resource_scope


class TestTargetCanonicalizationAndPolicyInvariants:
    def test_normalize_target_scope_boundaries(self):
        with pytest.raises(ValueError, match="Target resource must be a non-empty string"):
            normalize_target_scope(None)
        with pytest.raises(ValueError, match="Target resource must be a non-empty string"):
            normalize_target_scope(12345)

        long_target = "a" * (MAX_TARGET_INPUT_LEN + 1)
        with pytest.raises(ValueError, match="exceeds maximum input length"):
            normalize_target_scope(long_target)

        with pytest.raises(ValueError, match="unencoded whitespace or control characters"):
            normalize_target_scope("http://example.com/a b")
        with pytest.raises(ValueError, match="unencoded whitespace or control characters"):
            normalize_target_scope("http://example.com/a\nb")

        with pytest.raises(ValueError, match="decoded whitespace or control characters"):
            normalize_target_scope("http://exa%20mple.com/path")

        assert normalize_target_scope("http://example.com") == "target:example.com:/"

        with pytest.raises(ValueError, match="decoded control characters or NUL"):
            normalize_target_scope("http://example.com/api%00bad")
        with pytest.raises(ValueError, match="decoded control characters or NUL"):
            normalize_target_scope("http://example.com/api%0Abad")

        assert normalize_target_scope("/users/../users/admin") == "target::/users/admin"
        assert normalize_target_scope("/api?param=1") == "target::/api"
        assert normalize_target_scope("/") == "target::/"

    def test_policy_filtering(self):
        policy = Policy(
            policy_id="pol-1",
            allowed_operations={"read", "query"},
            allowed_resources={"db://main/tbl", "db://main/*"},
            allowed_executors={"exec1", "exec2"},
        )
        assert policy.is_operation_allowed("drop_table") is False
        assert policy.is_operation_allowed("write") is False
        assert policy.is_operation_allowed("read") is True

        assert policy.is_target_allowed("db://other/tbl") is False
        assert policy.is_target_allowed("db://main/tbl") is True

        assert policy.is_executor_allowed("exec1") is True
        assert policy.is_executor_allowed("unauthorized_exec") is False

        wildcard_policy = Policy(
            policy_id="pol-wild",
            allowed_operations={"*"},
            allowed_resources={"*"},
            allowed_principals={"*"},
            allowed_executors={"*"},
        )
        assert wildcard_policy.is_operation_allowed("any_op") is True
        assert wildcard_policy.is_target_allowed("any_target") is True
        assert wildcard_policy.is_principal_allowed("any_p") is True
        assert wildcard_policy.is_executor_allowed("any_exec") is True

        empty_policy = Policy(
            policy_id="pol-empty",
            allowed_operations=set(),
            allowed_resources=set(),
            allowed_principals=set(),
            allowed_executors=set(),
        )
        assert empty_policy.is_operation_allowed("any_op") is False
        assert empty_policy.is_target_allowed("any_target") is False
        assert empty_policy.is_principal_allowed("any_p") is False
        assert empty_policy.is_executor_allowed("any_exec") is False


class TestAuthorizationStoresInvariants:
    def test_in_memory_store_fencing_and_revocation(self):
        scope_canonical = canonicalize_fencing_scope("task-1", "/res")
        store = InMemoryAuthorizationStore()
        token1 = store.allocate_fencing_token(scope_canonical)
        assert token1 == 1
        token2 = store.allocate_fencing_token(scope_canonical)
        assert token2 == 2

        cap = make_test_cap(
            token_id="tok-mem-1",
            task_id="task-1",
            target="/res",
            action_name="read",
            fencing_token=2,
            scope_key=scope_canonical,
        )
        bad_cap = copy.deepcopy(cap)
        bad_cap.scope_key = "spoofed_scope"
        with pytest.raises(ValueError, match="Capability scope_key mismatch"):
            store.issue_and_register_capability(bad_cap, lambda c: "sig")
        with pytest.raises(ValueError, match="Capability scope_key mismatch"):
            store.register_capability(bad_cap)

        store.register_capability(cap)

        ok, reason = store.consume_capability(
            "tok-mem-1",
            expected_fencing_token=999,
        )
        assert ok is False
        assert "CAPABILITY_CONSUMPTION_FAILED_FENCING_TOKEN_MISMATCH" in reason

        store.allocate_fencing_token(scope_canonical)
        ok, reason = store.consume_capability(
            "tok-mem-1",
            expected_fencing_token=2,
        )
        assert ok is False
        assert "CAPABILITY_CONSUMPTION_FAILED_STALE_FENCING_TOKEN" in reason

        cap_future = make_test_cap(
            token_id="tok-mem-future",
            task_id="task-1",
            target="/res",
            action_name="read",
            fencing_token=10,
            scope_key=scope_canonical,
        )
        store._capabilities[cap_future.token_id] = cap_future
        ok, reason = store.consume_capability(
            "tok-mem-future",
            expected_fencing_token=10,
        )
        assert ok is False
        assert "CAPABILITY_CONSUMPTION_FAILED_FUTURE_FENCING_TOKEN" in reason

        ok, reason = store.consume_capability("unknown-tok")
        assert ok is False
        assert reason == "CAPABILITY_CONSUMPTION_FAILED_UNKNOWN_TOKEN"

        ok, msg = store.revoke_capability("tok-mem-future")
        assert ok is True
        assert msg == "CAPABILITY_REVOKED_SUCCESSFULLY"
        ok, msg = store.revoke_capability("tok-mem-future")
        assert ok is True
        assert msg == "CAPABILITY_ALREADY_REVOKED"

        ok, reason = store.consume_capability("tok-mem-future")
        assert ok is False
        assert reason == "CAPABILITY_CONSUMPTION_FAILED_REVOKED"

        cap_consume = make_test_cap(
            token_id="tok-to-consume",
            task_id="task-1",
            target="/res",
            action_name="read",
            fencing_token=4,
            scope_key=scope_canonical,
        )
        store.allocate_fencing_token(scope_canonical)
        store.register_capability(cap_consume)
        ok, reason = store.consume_capability("tok-to-consume")
        assert ok is True
        ok, msg = store.revoke_capability("tok-to-consume")
        assert ok is False
        assert msg == "CAPABILITY_REVOCATION_REJECTED_ALREADY_CONSUMED"

    def test_file_authorization_store_fencing_and_journal_integrity(self, tmp_path):
        journal_path = tmp_path / "auth_journal.jsonl"
        store = FileAuthorizationStore(store_path=str(journal_path), fail_closed=True)
        scope_canonical = canonicalize_fencing_scope("file-task", "/db")

        token1 = store.allocate_fencing_token(scope_canonical)
        assert token1 == 1
        token2 = store.allocate_fencing_token(scope_canonical)
        assert token2 == 2

        approval_rec = HumanApprovalRecord(
            approval_id="app-f-1",
            approver_id="admin",
            action_name="query",
            target="/db",
            action_digest="dig",
            request_id="req-1",
        )

        cap = make_test_cap(
            token_id="cap-file-1",
            task_id="file-task",
            target="/db",
            action_name="query",
            fencing_token=2,
            scope_key=scope_canonical,
            human_approval=approval_rec,
        )
        bad_cap = copy.deepcopy(cap)
        bad_cap.scope_key = "tampered_scope"
        with pytest.raises(ValueError, match="Capability scope_key mismatch"):
            store.issue_and_register_capability(bad_cap, lambda c: "sig")
        with pytest.raises(ValueError, match="Capability scope_key mismatch"):
            store.register_capability(bad_cap)

        store.register_capability(cap)

        fetched = store.get_capability("cap-file-1")
        assert fetched is not None
        assert fetched.token_id == "cap-file-1"
        assert fetched.human_approval is not None
        assert fetched.human_approval.approval_id == "app-f-1"

        assert store.is_approval_consumed("app-f-1") is False

        ok, reason = store.consume_capability("cap-file-1", expected_fencing_token=999)
        assert ok is False
        assert "CAPABILITY_CONSUMPTION_FAILED_FENCING_TOKEN_MISMATCH" in reason

        store.allocate_fencing_token(scope_canonical)
        ok, reason = store.consume_capability("cap-file-1", expected_fencing_token=2)
        assert ok is False
        assert "CAPABILITY_CONSUMPTION_FAILED_STALE_FENCING_TOKEN" in reason

        cap_future = make_test_cap(
            token_id="cap-file-future",
            task_id="file-task",
            target="/db",
            action_name="query",
            fencing_token=10,
            scope_key=scope_canonical,
        )
        rec_future = {
            "type": "REGISTER_CAPABILITY",
            "token_id": "cap-file-future",
            "data": cap_future.to_dict(),
            "timestamp": time.time(),
        }
        with open(journal_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec_future) + "\n")

        ok, reason = store.consume_capability("cap-file-future", expected_fencing_token=10)
        assert ok is False
        assert "CAPABILITY_CONSUMPTION_FAILED_FUTURE_FENCING_TOKEN" in reason

        ok, reason = store.consume_capability("nonexistent-token")
        assert ok is False
        assert reason == "CAPABILITY_CONSUMPTION_FAILED_UNKNOWN_TOKEN"

        store.allocate_fencing_token(scope_canonical)
        store.allocate_fencing_token(scope_canonical)
        cap_valid = make_test_cap(
            token_id="cap-file-valid",
            task_id="file-task",
            target="/db",
            action_name="query",
            fencing_token=5,
            scope_key=scope_canonical,
            human_approval=approval_rec,
        )
        store.register_capability(cap_valid)
        ok, reason = store.consume_capability("cap-file-valid", expected_fencing_token=5)
        assert ok is True
        assert store.is_consumed("cap-file-valid") is True
        assert store.is_approval_consumed("app-f-1") is True

        ok, reason = store.consume_capability("cap-file-valid", expected_fencing_token=5)
        assert ok is False
        assert reason == "CAPABILITY_CONSUMPTION_FAILED_ALREADY_CONSUMED"

        cap_replay_app = make_test_cap(
            token_id="cap-file-replay-app",
            task_id="file-task",
            target="/db",
            action_name="query",
            fencing_token=6,
            scope_key=scope_canonical,
            human_approval=approval_rec,
        )
        store.allocate_fencing_token(scope_canonical)
        store.register_capability(cap_replay_app)
        ok, reason = store.consume_capability("cap-file-replay-app", expected_fencing_token=6)
        assert ok is False
        assert reason == "CAPABILITY_CONSUMPTION_FAILED_APPROVAL_REPLAYED"

        ok, msg = store.revoke_capability("cap-file-replay-app")
        assert ok is True
        assert msg == "CAPABILITY_REVOKED_SUCCESSFULLY"
        ok, msg = store.revoke_capability("cap-file-replay-app")
        assert ok is True
        assert msg == "CAPABILITY_ALREADY_REVOKED"

        ok, msg = store.revoke_capability("cap-file-valid")
        assert ok is False
        assert msg == "CAPABILITY_REVOCATION_REJECTED_ALREADY_CONSUMED"

    def test_file_authorization_store_corrupted_journal_recovery(self, tmp_path):
        journal_path = tmp_path / "corrupted_journal.jsonl"
        store_fail_closed = FileAuthorizationStore(store_path=str(journal_path), fail_closed=True)
        store_fail_open = FileAuthorizationStore(store_path=str(journal_path), fail_closed=False)

        journal_path.write_text("not json\n", encoding="utf-8")
        with pytest.raises(RuntimeError):
            store_fail_closed.get_scope_fencing_token("s1")
        assert store_fail_open.get_scope_fencing_token("s1") == 0

        corrupt_issue = json.dumps({"type": "ISSUE_CAPABILITY", "capability": "not-a-dict"}) + "\n"
        journal_path.write_text(corrupt_issue, encoding="utf-8")
        with pytest.raises(RuntimeError, match="Corrupted ISSUE_CAPABILITY"):
            store_fail_closed.get_scope_fencing_token("s1")
        assert store_fail_open.get_scope_fencing_token("s1") == 0

        corrupt_reg = json.dumps({"type": "REGISTER_CAPABILITY"}) + "\n"
        journal_path.write_text(corrupt_reg, encoding="utf-8")
        with pytest.raises(RuntimeError, match="Corrupted REGISTER_CAPABILITY"):
            store_fail_closed.get_scope_fencing_token("s1")
        assert store_fail_open.get_scope_fencing_token("s1") == 0

        corrupt_consume = json.dumps({"type": "CONSUME"}) + "\n"
        journal_path.write_text(corrupt_consume, encoding="utf-8")
        with pytest.raises(RuntimeError, match="Corrupted CONSUME"):
            store_fail_closed.get_scope_fencing_token("s1")
        assert store_fail_open.get_scope_fencing_token("s1") == 0

        corrupt_revoke = json.dumps({"type": "REVOKE"}) + "\n"
        journal_path.write_text(corrupt_revoke, encoding="utf-8")
        with pytest.raises(RuntimeError, match="Corrupted REVOKE"):
            store_fail_closed.get_scope_fencing_token("s1")
        assert store_fail_open.get_scope_fencing_token("s1") == 0

        corrupt_fence = json.dumps({"type": "FENCE", "scope_key": "s1"}) + "\n"
        journal_path.write_text(corrupt_fence, encoding="utf-8")
        with pytest.raises(RuntimeError, match="Corrupted FENCE"):
            store_fail_closed.get_scope_fencing_token("s1")
        assert store_fail_open.get_scope_fencing_token("s1") == 0

        corrupt_unknown = json.dumps({"type": "UNKNOWN_ACTION"}) + "\n"
        journal_path.write_text(corrupt_unknown, encoding="utf-8")
        with pytest.raises(RuntimeError, match="Unknown or ambiguous record type"):
            store_fail_closed.get_scope_fencing_token("s1")
        assert store_fail_open.get_scope_fencing_token("s1") == 0

    def test_file_authorization_store_flock_and_persistence_exceptions(self, tmp_path):
        journal_path = tmp_path / "flock_journal.jsonl"
        store = FileAuthorizationStore(store_path=str(journal_path), fail_closed=True)

        with patch("fcntl.flock", side_effect=OSError("Lock busy")):
            with pytest.raises(RuntimeError, match="Failed to acquire interprocess flock"):
                store._acquire_flock()

        store._lock_file = open(store.lock_path, "a+")
        store._lock_depth = 1
        with patch("fcntl.flock", side_effect=OSError("Unlock failed")):
            with pytest.raises(RuntimeError, match="Failed to release interprocess flock"):
                store._release_flock()

        class DictObj:
            def to_dict(self):
                return {"field": "val"}

        store._append_record_under_lock({"sets": {"a", "b"}, "obj": DictObj()})
        with pytest.raises(RuntimeError, match="Authoritative storage failure: unable to persist"):
            store._append_record_under_lock({"unserializable": object()})


class TestEd25519PureVerificationFallback:
    def test_ed25519_rfc8032_known_answer_test_vectors(self):
        """Verifies published RFC 8032 known-answer test vectors (Section 7.1)."""
        # RFC 8032 Test Vector 1:
        # pk: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
        # msg: "" (empty message)
        pk1 = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        msg1 = b""
        sig1 = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        assert _ed25519_verify_pure(sig1, msg1, pk1) is True
        assert verify_ed25519_signature(sig1, msg1, pk1) is True

        # Tampered message / signature rejection on published vector
        assert _ed25519_verify_pure(sig1, b"tampered_payload", pk1) is False
        assert verify_ed25519_signature(sig1, b"tampered_payload", pk1) is False
        bad_sig1 = bytearray(sig1)
        bad_sig1[0] ^= 0x01
        assert _ed25519_verify_pure(bytes(bad_sig1), msg1, pk1) is False
        assert verify_ed25519_signature(bytes(bad_sig1), msg1, pk1) is False

        # RFC 8032 Test Vector 2:
        # pk: 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
        # msg: 0x72 (single byte 0x72, ASCII 'r')
        pk2 = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        msg2 = bytes.fromhex("72")
        sig2 = bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )
        assert _ed25519_verify_pure(sig2, msg2, pk2) is True
        assert verify_ed25519_signature(sig2, msg2, pk2) is True

    def test_ed25519_pure_and_fallback_dispatch(self):
        """Verifies pure-Python and libcrypto fallback with locally generated signatures."""
        idp = ExternalTestIdentityAuthority()
        msg_bytes = b"authoritative test message"
        pk_bytes = idp.public_key
        sig_bytes = _ed25519_sign(msg_bytes, idp.private_seed, pk_bytes)

        assert _ed25519_verify_pure(sig_bytes, msg_bytes, pk_bytes) is True
        assert _ed25519_verify_pure(sig_bytes, b"tampered", pk_bytes) is False
        assert _ed25519_verify_pure(b"short", msg_bytes, pk_bytes) is False
        assert _ed25519_verify_pure(sig_bytes, msg_bytes, b"short") is False

        bad_s_sig = sig_bytes[:32] + (2**253).to_bytes(32, "little")
        assert _ed25519_verify_pure(bad_s_sig, msg_bytes, pk_bytes) is False

        bad_point_sig = (b"\xff" * 32) + sig_bytes[32:]
        assert _ed25519_verify_pure(bad_point_sig, msg_bytes, pk_bytes) is False

        assert verify_ed25519_signature(sig_bytes, msg_bytes, pk_bytes) is True
        assert verify_ed25519_signature(b"bad", msg_bytes, pk_bytes) is False

        with patch.object(auth, "_HAS_LIBCRYPTO", False):
            assert verify_ed25519_signature(sig_bytes, msg_bytes, pk_bytes) is True
            assert verify_ed25519_signature(sig_bytes, b"bad", pk_bytes) is False

        if auth._HAS_LIBCRYPTO:
            with patch.object(auth._libcrypto, "EVP_DigestVerifyInit", return_value=0):
                assert verify_ed25519_signature(sig_bytes, msg_bytes, pk_bytes) is False
            with patch.object(auth._libcrypto, "EVP_PKEY_new_raw_public_key", return_value=None):
                assert verify_ed25519_signature(sig_bytes, msg_bytes, pk_bytes) is True


class TestPrincipalVerifierAndAssertionInvariants:
    def test_authenticated_principal_validation(self):
        with pytest.raises(ValueError, match="principal_id must be a non-empty string"):
            AuthenticatedPrincipal(
                principal_id="", issuer_id="iss-1", signature="sig", timestamp=time.time()
            )
        with pytest.raises(ValueError, match="issuer_id must be a non-empty string"):
            AuthenticatedPrincipal(
                principal_id="p1", issuer_id="", signature="sig", timestamp=time.time()
            )
        with pytest.raises(ValueError, match="signature must be a non-empty string"):
            AuthenticatedPrincipal(
                principal_id="p1", issuer_id="iss-1", signature="", timestamp=time.time()
            )

    def test_principal_verifier_key_formats_and_immutability(self, monkeypatch):
        idp = ExternalTestIdentityAuthority()
        pk_bytes = idp.public_key

        spki_prefix = bytes.fromhex("302a300506032b6570032100")
        pem_der = base64.b64encode(spki_prefix + pk_bytes).decode("ascii")
        pem_key = f"-----BEGIN PUBLIC KEY-----\n{pem_der}\n-----END PUBLIC KEY-----"

        verifier_pem = PrincipalVerifier(trusted_public_keys={"iss-pem": pem_key})
        assert verifier_pem.has_trusted_issuers() is True
        assert verifier_pem._trusted_public_keys["iss-pem"] == pk_bytes

        b64_key = base64.b64encode(pk_bytes).decode("ascii")
        verifier_b64 = PrincipalVerifier(trusted_public_keys={"iss-b64": b64_key})
        assert verifier_b64._trusted_public_keys["iss-b64"] == pk_bytes

        monkeypatch.setenv("EPISTEMICOS_IDP_ISSUER", "iss-env")
        monkeypatch.setenv("EPISTEMICOS_IDP_PUBLIC_KEY", pk_bytes.hex())
        verifier_env = PrincipalVerifier()
        assert "iss-env" in verifier_env._trusted_public_keys

        with pytest.raises(ValueError, match="issuer_id must be a non-empty string"):
            PrincipalVerifier(trusted_public_keys={"": pk_bytes})
        with pytest.raises(TypeError, match="public_key must be bytes or str"):
            PrincipalVerifier(trusted_public_keys={"iss": 12345})
        with pytest.raises(ValueError, match="Ed25519 public key must be exactly 32 bytes"):
            PrincipalVerifier(trusted_public_keys={"iss": b"short"})

        with pytest.raises(PermissionError, match="immutable and cannot be reassigned"):
            verifier_pem._trusted_public_keys = {}
        with pytest.raises(PermissionError, match="cannot be deleted"):
            del verifier_pem._trusted_public_keys
        with pytest.raises(PermissionError, match="immutable and cannot be reassigned"):
            verifier_pem.clock_skew_seconds = 100.0
        with pytest.raises(PermissionError, match="cannot be deleted"):
            del verifier_pem.clock_skew_seconds

    def test_principal_verifier_assertion_verification(self):
        idp = ExternalTestIdentityAuthority()
        verifier = PrincipalVerifier(trusted_public_keys={"trusted-iss": idp.public_key})

        ok, reason, p = verifier.verify_principal("just-a-string")
        assert ok is False
        assert "not a valid AuthenticatedPrincipal assertion" in reason

        bad_p = MagicMock(spec=AuthenticatedPrincipal)
        bad_p.principal_id = "user1"
        bad_p.issuer_id = "trusted-iss"
        bad_p.signature = None
        ok, reason, p = verifier.verify_principal(bad_p)
        assert ok is False
        assert "Missing or invalid signature" in reason

        bad_enc = AuthenticatedPrincipal(
            principal_id="user1",
            issuer_id="trusted-iss",
            signature="!!!not-valid-base64-or-hex!!!",
            timestamp=time.time(),
        )
        ok, reason, p = verifier.verify_principal(bad_enc)
        assert ok is False
        assert "Invalid signature encoding" in reason

        bad_len = AuthenticatedPrincipal(
            principal_id="user1",
            issuer_id="trusted-iss",
            signature=bytes(30).hex(),
            timestamp=time.time(),
        )
        ok, reason, p = verifier.verify_principal(bad_len)
        assert ok is False
        assert "Invalid signature length" in reason


class TestCapabilityRegistryPersistenceAndDenialInvariants:
    def test_capability_registry_initialization_and_poisoning(self, tmp_path):
        with pytest.raises(ValueError, match="denial_log_path is required when fail_closed"):
            CapabilityRegistry(denial_log_path=None, fail_closed_persistence=True)

        log_path = tmp_path / "denial.log"
        reg = CapabilityRegistry(denial_log_path=str(log_path), fail_closed_persistence=True)

        reg._is_poisoned = True
        with pytest.raises(RuntimeError, match="poisoned state"):
            reg._check_poisoned()
        with pytest.raises(RuntimeError, match="poisoned state"):
            with reg.lock_registry():
                pass

    def test_capability_registry_denial_log_parsing_and_corruption(self, tmp_path):
        log_path = tmp_path / "corrupted_denials.log"
        valid_denial = {
            "task_id": "task-1",
            "action_name": "delete",
            "target": "/secure/db",
            "reason": "Explicit denial",
            "status": "ACTIVE",
        }
        corrupted_line = "not a valid json entry\n"
        empty_line = "\n"

        log_path.write_text(
            corrupted_line + empty_line + json.dumps(valid_denial) + "\n",
            encoding="utf-8"
        )

        with pytest.raises(RuntimeError, match="Failed to load persistent denial log"):
            CapabilityRegistry(denial_log_path=str(log_path), fail_closed_persistence=True)

        reg_open = CapabilityRegistry(denial_log_path=str(log_path), fail_closed_persistence=False)
        is_denied, reason = reg_open.check_denial("task-1", "delete", "/secure/db")
        assert is_denied is True
        assert "Explicit denial" in reason["reason"]

    def test_capability_registry_flock_failures_in_denials(self, tmp_path):
        log_path = tmp_path / "flock_denial.log"
        reg = CapabilityRegistry(denial_log_path=str(log_path), fail_closed_persistence=True)

        with patch("fcntl.flock", side_effect=OSError("Lock error")):
            with pytest.raises(RuntimeError, match="unable to acquire interprocess file lock"):
                with reg.lock_registry():
                    pass

    def test_clear_denial_with_approval_validation(self, tmp_path):
        log_path = tmp_path / "clear_denials.log"
        reg = CapabilityRegistry(denial_log_path=str(log_path), fail_closed_persistence=False)

        ok, msg = reg.clear_denial_with_approval(
            task_id="t1",
            action_name="read",
            target="/res",
            reauthorization_record="invalid-record",
            signing_secret=b"sec",
        )
        assert ok is False
        assert msg == "Invalid or missing reauthorization record"

    def test_capability_registry_persistence_failures_in_clear_denial(self, tmp_path):
        """Verifies fail-open persistence failure handling in clear_denial_with_approval."""
        log_path = tmp_path / "denial_readonly.log"
        log_path.write_text("", encoding="utf-8")

        reg = CapabilityRegistry(denial_log_path=str(log_path), fail_closed_persistence=False)

        app_rec = HumanApprovalRecord(
            approval_id="app-clear-1",
            approver_id="admin",
            action_name="CLEAR_DENIAL",
            target="CLEAR_DENIAL",
            action_digest="dig",
            request_id="req-1",
            task_id="t1",
        )
        app_rec.sign(b"sec")

        with patch("builtins.open", side_effect=OSError("Disk full")):
            ok, msg = reg.clear_denial_with_approval(
                task_id="t1",
                action_name="read",
                target="/res",
                reauthorization_record=app_rec,
                signing_secret=b"sec",
            )
            assert ok is False
            assert "Denial persistence failure" in msg


class TestAuthorizationAuthorityIssuanceAndVerificationInvariants:
    def test_authority_production_configuration_validation(self, monkeypatch):
        monkeypatch.setenv("EPISTEMICOS_ENV", "production")
        with pytest.raises(ValueError, match="EPISTEMICOS_APPROVAL_SECRET must be explicitly set"):
            AuthorizationAuthority(approval_signing_secret=None)

        with pytest.raises(ValueError, match="EPISTEMICOS_CONTRACT_SECRET must be explicitly set"):
            AuthorizationAuthority(
                approval_signing_secret=b"app-sec", contract_signing_secret=None
            )

    def test_authority_privileged_principal_and_unallowed_principal(self):
        policy = Policy(
            policy_id="p_priv",
            allowed_operations={"read"},
            allowed_resources={"*"},
            allowed_principals={"trusted_service"},
        )
        authority = AuthorizationAuthority(default_policy=policy)

        cap, reason = authority.evaluate_and_issue_capability(
            task_id="t1",
            principal_id="unauthenticated_raw_string",
            action_name="read",
            target="/res",
            canonical_request_digest="dig1",
            executor_id="exec1",
        )
        assert cap is None
        assert "AUTHORIZATION_DENIED_AUTHENTICATED_PRINCIPAL_REQUIRED" in reason

        mock_provider = MagicMock()
        mock_provider.verify_principal.return_value = (True, "Valid", "unauthorized_principal")
        auth_disallowed = AuthorizationAuthority(
            default_policy=policy,
            principal_provider=mock_provider,
        )
        auth_p = AuthenticatedPrincipal(
            principal_id="unauthorized_principal",
            issuer_id="iss1",
            signature="sig",
            timestamp=time.time(),
        )
        cap2, reason2 = auth_disallowed.evaluate_and_issue_capability(
            task_id="t1",
            principal_id=auth_p,
            action_name="read",
            target="/res",
            canonical_request_digest="dig1",
            executor_id="exec1",
        )
        assert cap2 is None
        assert "AUTHORIZATION_DENIED_PRINCIPAL_NOT_ALLOWED:unauthorized_principal" in reason2

    def test_authority_clear_denial_format_validation(self):
        authority = AuthorizationAuthority()
        ok, msg = authority.clear_denial_with_approval(
            task_id="t1",
            action_name="read",
            target="/res",
            reauthorization_record="invalid_format_string",
        )
        assert ok is False
        assert msg == "Invalid reauthorization record format"

    def test_authority_missing_identity_provider(self):
        authority = AuthorizationAuthority(
            default_policy=Policy(
                policy_id="p1", allowed_operations={"read"}, allowed_resources={"*"}
            ),
            principal_provider=None,
        )
        auth_p = AuthenticatedPrincipal(
            principal_id="privileged_agent",
            issuer_id="iss-1",
            signature="hex",
            timestamp=time.time(),
        )
        cap, reason = authority.evaluate_and_issue_capability(
            task_id="t1",
            principal_id=auth_p,
            action_name="read",
            target="/res",
            canonical_request_digest="req_digest_1",
            executor_id="exec-1",
        )
        assert cap is None
        assert "AUTHORIZATION_DENIED_NO_IDENTITY_PROVIDER_CONFIGURED" in reason

        dummy_cap = make_test_cap(
            token_id="tok1",
            task_id="t1",
            target="/res",
            action_name="read",
            canonical_request_digest="req_digest_1",
            executor_id="exec-1",
            principal_id="privileged_agent",
        )
        authority.registry.register_capability(dummy_cap)

        ok, v_reason, c = authority.verify_capability(
            token_id="tok1",
            principal_id=auth_p,
            action_name="read",
            target="/res",
            canonical_request_digest="req_digest_1",
            executor_id="exec-1",
        )
        assert ok is False
        assert "CAPABILITY_VERIFICATION_FAILED_NO_IDENTITY_PROVIDER" in v_reason

    def test_authority_principal_authentication_failure(self):
        mock_provider = MagicMock()
        mock_provider.verify_principal.return_value = (False, "Signature forgery detected", None)

        authority = AuthorizationAuthority(
            default_policy=Policy(
                policy_id="p1", allowed_operations={"read"}, allowed_resources={"*"}
            ),
            principal_provider=mock_provider,
        )
        auth_p = AuthenticatedPrincipal(
            principal_id="privileged_agent",
            issuer_id="iss-1",
            signature="hex",
            timestamp=time.time(),
        )
        cap, reason = authority.evaluate_and_issue_capability(
            task_id="t1",
            principal_id=auth_p,
            action_name="read",
            target="/res",
            canonical_request_digest="req_digest_1",
            executor_id="exec-1",
        )
        assert cap is None
        assert "AUTHORIZATION_DENIED_PRINCIPAL_AUTHENTICATION_FAILED" in reason

        reg_cap = make_test_cap(
            token_id="tok-p-fail",
            task_id="t1",
            target="/res",
            action_name="read",
            canonical_request_digest="req_digest_1",
            executor_id="exec-1",
            principal_id="privileged_agent",
        )
        authority.registry.register_capability(reg_cap)

        ok, v_reason, c = authority.verify_capability(
            token_id="tok-p-fail",
            principal_id=auth_p,
            action_name="read",
            target="/res",
            canonical_request_digest="req_digest_1",
            executor_id="exec-1",
        )
        assert ok is False
        assert "CAPABILITY_VERIFICATION_FAILED_PRINCIPAL_AUTHENTICATION_FAILED" in v_reason

    def test_authority_invalid_principal_types(self):
        authority = AuthorizationAuthority(
            default_policy=Policy(
                policy_id="p1", allowed_operations={"read"}, allowed_resources={"*"}
            ),
        )
        cap, reason = authority.evaluate_and_issue_capability(
            task_id="t1",
            principal_id=12345,
            action_name="read",
            target="/res",
            canonical_request_digest="req_digest_1",
            executor_id="exec-1",
        )
        assert cap is None
        assert reason == "AUTHORIZATION_DENIED_INVALID_PRINCIPAL_TYPE"

    def test_authority_malformed_task_contract_dict(self):
        authority = AuthorizationAuthority(
            default_policy=Policy(
                policy_id="p1", allowed_operations={"read"}, allowed_resources={"*"}
            ),
        )
        cap, reason = authority.evaluate_and_issue_capability(
            task_id="t1",
            principal_id="agent1",
            action_name="read",
            target="/res",
            canonical_request_digest="req_digest_1",
            executor_id="exec-1",
            task_contract={"malformed": "contract"},
        )
        assert cap is None
        assert reason == "AUTHORIZATION_DENIED_MALFORMED_TASK_CONTRACT"

    def test_authority_expired_task_contract(self):
        authority = AuthorizationAuthority(
            default_policy=Policy(
                policy_id="p1", allowed_operations={"read"}, allowed_resources={"*"}
            ),
        )
        contract = TrustedTaskContract(
            task_id="t1",
            permitted_actions={"read"},
            resource_scope={"*"},
            expires_at=1000.0,
        )
        contract.sign(authority.contract_signing_secret)

        with patch.object(contract, "verify_signature", return_value=True):
            cap, reason = authority.evaluate_and_issue_capability(
                task_id="t1",
                principal_id="agent1",
                action_name="read",
                target="/res",
                canonical_request_digest="req_digest_1",
                executor_id="exec-1",
                task_contract=contract,
                current_time=2000.0,
            )
            assert cap is None
            assert reason == "AUTHORIZATION_DENIED_EXPIRED_TASK_CONTRACT"

    def test_authority_executor_not_allowed(self):
        authority = AuthorizationAuthority(
            default_policy=Policy(
                policy_id="p1",
                allowed_operations={"read"},
                allowed_resources={"*"},
                allowed_executors={"exec_allowed"},
            ),
        )
        cap, reason = authority.evaluate_and_issue_capability(
            task_id="t1",
            principal_id="agent1",
            action_name="read",
            target="/res",
            canonical_request_digest="req_digest_1",
            executor_id="exec_disallowed",
        )
        assert cap is None
        assert "AUTHORIZATION_DENIED_EXECUTOR_NOT_ALLOWED:exec_disallowed" in reason

    def test_authority_human_approval_digest_and_request_mismatches(self):
        secret = b"test-approval-secret-key-32b!!"
        idp = ExternalTestIdentityAuthority(issuer_id="CoverageTestIdP")
        verifier = PrincipalVerifier(trusted_public_keys={"CoverageTestIdP": idp.public_key})
        authority = AuthorizationAuthority(
            default_policy=Policy(
                policy_id="p1",
                allowed_operations={"drop_table"},
                allowed_resources={"*"},
                required_human_approval_operations={"drop_table"},
            ),
            approval_signing_secret=secret,
            principal_provider=verifier,
        )
        contract = TrustedTaskContract(
            task_id="t1",
            permitted_actions={"drop_table"},
            resource_scope={"*"},
            approval_requirements=["drop_table"],
        )
        contract.sign(authority.contract_signing_secret)

        assertion = idp.issue_principal("sec-admin")
        approval_record = HumanApprovalRecord(
            approval_id="app-1",
            approver_id="sec-admin",
            action_name="drop_table",
            target="/db/tbl",
            action_digest="correct_digest",
            request_id="req-expected",
            task_id="t1",
            requesting_principal="agent1",
            policy_version="1.0.0",
            approver_assertion=assertion,
        )
        approval_record.sign(secret)

        cap_valid, r_valid = authority.evaluate_and_issue_capability(
            task_id="t1",
            principal_id="agent1",
            action_name="drop_table",
            target="/db/tbl",
            canonical_request_digest="correct_digest",
            request_id="req-expected",
            task_contract=contract,
            human_approval_input=approval_record,
            executor_id="exec-1",
        )
        assert cap_valid is not None
        assert r_valid == "AUTHORIZATION_GRANTED"
        assert cap_valid.action_name == "drop_table"

        cap_bad_dig, r_bad_dig = authority.evaluate_and_issue_capability(
            task_id="t1",
            principal_id="agent1",
            action_name="drop_table",
            target="/db/tbl",
            canonical_request_digest="different_digest",
            request_id="req-expected",
            task_contract=contract,
            human_approval_input=approval_record,
            executor_id="exec-1",
        )
        assert cap_bad_dig is None
        assert r_bad_dig == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_DIGEST_MISMATCH"

        cap_bad_req, r_bad_req = authority.evaluate_and_issue_capability(
            task_id="t1",
            principal_id="agent1",
            action_name="drop_table",
            target="/db/tbl",
            canonical_request_digest="correct_digest",
            request_id="req-different",
            task_contract=contract,
            human_approval_input=approval_record,
            executor_id="exec-1",
        )
        assert cap_bad_req is None
        assert r_bad_req == "AUTHORIZATION_DENIED_HUMAN_APPROVAL_REQUEST_ID_MISMATCH"

    def test_authority_verification_contract_version_and_future_token(self):
        authority = AuthorizationAuthority(
            default_policy=Policy(
                policy_id="p1", allowed_operations={"read"}, allowed_resources={"*"}
            ),
        )

        cap_baseline = make_test_cap(
            token_id="tok-ver-base",
            task_id="t1",
            target="/res",
            action_name="read",
            canonical_request_digest="req_digest_1",
            executor_id="exec-1",
            principal_id="agent1",
            contract_version="1.0.0",
            fencing_token=1,
        )
        authority.registry.storage.allocate_fencing_token(cap_baseline.scope_key)
        authority.registry.register_capability(cap_baseline)

        ok_base, r_base, c_base = authority.verify_capability(
            token_id="tok-ver-base",
            principal_id="agent1",
            action_name="read",
            target="/res",
            canonical_request_digest="req_digest_1",
            executor_id="exec-1",
            contract_version="1.0.0",
        )
        assert ok_base is True
        assert r_base == "CAPABILITY_VERIFIED"
        assert c_base is not None

        ok_ver, reason_ver, c_ver = authority.verify_capability(
            token_id="tok-ver-base",
            principal_id="agent1",
            action_name="read",
            target="/res",
            canonical_request_digest="req_digest_1",
            executor_id="exec-1",
            contract_version="2.0.0",
        )
        assert ok_ver is False
        assert "CAPABILITY_VERIFICATION_FAILED_CONTRACT_VERSION_MISMATCH" in reason_ver

        cap_future = make_test_cap(
            token_id="tok-ver-future",
            task_id="t1",
            target="/res",
            action_name="read",
            canonical_request_digest="req_digest_1",
            executor_id="exec-1",
            principal_id="agent1",
            contract_version="1.0.0",
            fencing_token=10,
        )
        cap_future.signature = authority.registry.sign_capability(cap_future)
        authority.registry.storage._capabilities[cap_future.token_id] = cap_future

        ok_fut, reason_fut, c_fut = authority.verify_capability(
            token_id="tok-ver-future",
            principal_id="agent1",
            action_name="read",
            target="/res",
            canonical_request_digest="req_digest_1",
            executor_id="exec-1",
            contract_version="1.0.0",
        )
        assert ok_fut is False
        assert "CAPABILITY_VERIFICATION_FAILED_FUTURE_FENCING_TOKEN" in reason_fut

    def test_authority_delattr_immutability(self):
        authority = AuthorizationAuthority(
            default_policy=Policy(
                policy_id="p1", allowed_operations={"read"}, allowed_resources={"*"}
            ),
        )
        with pytest.raises(PermissionError, match="cannot be deleted"):
            del authority._principal_provider


class TestExecutorRegistryAndCallableIdentity:
    def test_callable_identity_resolution(self):
        def sample_func():
            pass

        assert "sample_func" in get_callable_identity(sample_func)
        assert get_callable_identity("already_string") == "already_string"
        assert get_callable_identity(None) == "default_executor"

        class NoName:
            pass

        obj = NoName()
        assert "NoName" in get_callable_identity(obj)

    def test_executor_registry_initialization_mapping(self):
        def exec1():
            return None

        registry1 = ExecutorRegistry({"exec1": exec1})
        assert registry1.contains("exec1") is True

        registry2 = ExecutorRegistry(registry1)
        assert registry2.contains("exec1") is True


class TestAuthorizationConcurrencyAndDeterminism:
    def test_concurrent_single_use_capability_consumption(self):
        """Deterministically proves that competing threads cannot replay a single-use capability."""
        store = InMemoryAuthorizationStore()
        token_id = "tok-concurrent-single-use"
        scope = canonicalize_fencing_scope("concurrent-task", "/resource")
        store.allocate_fencing_token(scope)

        cap = make_test_cap(
            token_id=token_id,
            task_id="concurrent-task",
            target="/resource",
            action_name="write",
            fencing_token=1,
            scope_key=scope,
        )
        store.register_capability(cap)

        num_threads = 8
        barrier = threading.Barrier(num_threads)
        results = []
        lock = threading.Lock()
        exceptions = []

        def worker():
            try:
                barrier.wait(timeout=5.0)
                ok, reason = store.consume_capability(token_id, expected_fencing_token=1)
                with lock:
                    results.append((ok, reason))
            except Exception as e:
                with lock:
                    exceptions.append(e)

        threads = [threading.Thread(target=worker, daemon=False) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)
            assert not t.is_alive(), (
                f"Worker thread {t.name} did not terminate within bounded timeout"
            )

        assert len(exceptions) == 0, f"Worker thread exceptions: {exceptions}"
        assert len(results) == num_threads

        successes = [r for r in results if r[0] is True]
        failures = [r for r in results if r[0] is False]

        assert len(successes) == 1
        assert len(failures) == num_threads - 1
        assert all("ALREADY_CONSUMED" in r[1] for r in failures)

    def test_capability_registry_signing_secret_validation_and_env_loading(self, monkeypatch):
        # 1. Non-bytes/bytearray key raises TypeError
        with pytest.raises(TypeError, match="signing_secret must be bytes or bytearray"):
            CapabilityRegistry(signing_secret="string-key")

        with pytest.raises(TypeError, match="signing_secret must be bytes or bytearray"):
            CapabilityRegistry(signing_secret=12345)

        # 2. Empty bytes/bytearray key raises ValueError
        with pytest.raises(ValueError, match="signing_secret cannot be empty"):
            CapabilityRegistry(signing_secret=b"")

        with pytest.raises(ValueError, match="signing_secret cannot be empty"):
            CapabilityRegistry(signing_secret=bytearray())

        # 3. Valid bytearray converts to immutable bytes
        sec_ba = bytearray(b"secure_test_key_32_bytes_long_ok")
        reg_ba = CapabilityRegistry(signing_secret=sec_ba)
        assert reg_ba.signing_secret == b"secure_test_key_32_bytes_long_ok"
        sec_ba[0] = ord(b"X")
        assert reg_ba.signing_secret == b"secure_test_key_32_bytes_long_ok"

        # 4. Environment variable handling:
        # 4a. Unset env var -> falls back to generating random ephemeral 32-byte key
        monkeypatch.delenv("EPISTEMICOS_CAP_SECRET", raising=False)
        reg_unset = CapabilityRegistry()
        assert isinstance(reg_unset.signing_secret, bytes)
        assert len(reg_unset.signing_secret) == 32

        # 4b. Explicit empty string env var -> raises ValueError
        monkeypatch.setenv("EPISTEMICOS_CAP_SECRET", "")
        with pytest.raises(ValueError, match="signing_secret cannot be empty"):
            CapabilityRegistry()

        # 4c. Valid env var -> loads correctly
        monkeypatch.setenv("EPISTEMICOS_CAP_SECRET", "custom_env_cap_secret")
        reg_env = CapabilityRegistry()
        assert reg_env.signing_secret == b"custom_env_cap_secret"

        # 4d. Explicit constructor arg takes precedence over env var
        reg_override = CapabilityRegistry(signing_secret=b"override_secret_val")
        assert reg_override.signing_secret == b"override_secret_val"

        # 5. Neither provided (arg=None, env=unset) -> random key generation backwards-compatible
        monkeypatch.delenv("EPISTEMICOS_CAP_SECRET", raising=False)
        reg_rand1 = CapabilityRegistry(signing_secret=None)
        reg_rand2 = CapabilityRegistry(signing_secret=None)
        assert isinstance(reg_rand1.signing_secret, bytes) and len(reg_rand1.signing_secret) == 32
        assert isinstance(reg_rand2.signing_secret, bytes) and len(reg_rand2.signing_secret) == 32
        assert reg_rand1.signing_secret != reg_rand2.signing_secret

    def test_authority_signing_secret_validation_and_falsy_key_rejection(self, monkeypatch):
        """
        Validates fail-closed handling and strict typing for approval_signing_secret
        and contract_signing_secret in AuthorizationAuthority.
        """
        monkeypatch.delenv("EPISTEMICOS_APPROVAL_SECRET", raising=False)
        monkeypatch.delenv("EPISTEMICOS_CONTRACT_SECRET", raising=False)
        monkeypatch.delenv("EPISTEMICOS_ENV", raising=False)
        monkeypatch.delenv("ENVIRONMENT", raising=False)

        # 1. Non-bytes types raise TypeError
        for invalid_secret in [12345, "string_key", {"key": "val"}, [1, 2, 3], True]:
            with pytest.raises(
                TypeError, match="approval_signing_secret must be bytes or bytearray"
            ):
                AuthorizationAuthority(approval_signing_secret=invalid_secret)

            with pytest.raises(
                TypeError, match="contract_signing_secret must be bytes or bytearray"
            ):
                AuthorizationAuthority(contract_signing_secret=invalid_secret)

        # 2. Empty bytes or bytearray raise ValueError
        for empty_sec in [b"", bytearray(b"")]:
            with pytest.raises(ValueError, match="approval_signing_secret cannot be empty"):
                AuthorizationAuthority(approval_signing_secret=empty_sec)

            with pytest.raises(ValueError, match="contract_signing_secret cannot be empty"):
                AuthorizationAuthority(contract_signing_secret=empty_sec)

        # 3. Valid bytearray converts to immutable bytes
        app_ba = bytearray(b"approval_test_secret_key_32_bytes")
        con_ba = bytearray(b"contract_test_secret_key_32_bytes")
        auth_ba = AuthorizationAuthority(
            approval_signing_secret=app_ba, contract_signing_secret=con_ba
        )
        assert auth_ba.approval_signing_secret == b"approval_test_secret_key_32_bytes"
        assert auth_ba.contract_signing_secret == b"contract_test_secret_key_32_bytes"
        app_ba[0] = ord(b"Z")
        con_ba[0] = ord(b"W")
        assert auth_ba.approval_signing_secret == b"approval_test_secret_key_32_bytes"
        assert auth_ba.contract_signing_secret == b"contract_test_secret_key_32_bytes"

        # 4. Explicit empty string env var -> raises ValueError
        monkeypatch.setenv("EPISTEMICOS_APPROVAL_SECRET", "")
        with pytest.raises(ValueError, match="approval_signing_secret cannot be empty"):
            AuthorizationAuthority()

        monkeypatch.delenv("EPISTEMICOS_APPROVAL_SECRET", raising=False)
        monkeypatch.setenv("EPISTEMICOS_CONTRACT_SECRET", "")
        with pytest.raises(ValueError, match="contract_signing_secret cannot be empty"):
            AuthorizationAuthority()

        # 5. Valid env var -> loads correctly
        monkeypatch.setenv("EPISTEMICOS_APPROVAL_SECRET", "env_approval_secret_value")
        monkeypatch.setenv("EPISTEMICOS_CONTRACT_SECRET", "env_contract_secret_value")
        auth_env = AuthorizationAuthority()
        assert auth_env.approval_signing_secret == b"env_approval_secret_value"
        assert auth_env.contract_signing_secret == b"env_contract_secret_value"

        # 6. Explicit constructor arg takes precedence over env var
        auth_override = AuthorizationAuthority(
            approval_signing_secret=b"override_approval",
            contract_signing_secret=b"override_contract",
        )
        assert auth_override.approval_signing_secret == b"override_approval"
        assert auth_override.contract_signing_secret == b"override_contract"

        # 7. Default ephemeral generation when unset
        monkeypatch.delenv("EPISTEMICOS_APPROVAL_SECRET", raising=False)
        monkeypatch.delenv("EPISTEMICOS_CONTRACT_SECRET", raising=False)
        auth_rand1 = AuthorizationAuthority()
        auth_rand2 = AuthorizationAuthority()
        assert (
            isinstance(auth_rand1.approval_signing_secret, bytes)
            and len(auth_rand1.approval_signing_secret) == 32
        )
        assert (
            isinstance(auth_rand1.contract_signing_secret, bytes)
            and len(auth_rand1.contract_signing_secret) == 32
        )
        assert auth_rand1.approval_signing_secret != auth_rand2.approval_signing_secret
        assert auth_rand1.contract_signing_secret != auth_rand2.contract_signing_secret


class TestAuthenticatedPrincipalNumericHardening:
    """Tests for fail-closed timestamp and expiration numeric validation."""

    def test_authenticated_principal_timestamp_validation(self):
        # 1. Non-numeric or boolean timestamp rejected
        with pytest.raises(TypeError, match="timestamp must be a numeric timestamp"):
            AuthenticatedPrincipal("alice", "idp", True, "00" * 64)

        with pytest.raises(TypeError, match="timestamp must be a numeric timestamp"):
            AuthenticatedPrincipal("alice", "idp", "12345", "00" * 64)

        # 2. Non-finite float timestamp rejected
        with pytest.raises(ValueError, match="timestamp must be a finite number"):
            AuthenticatedPrincipal("alice", "idp", float("nan"), "00" * 64)

        with pytest.raises(ValueError, match="timestamp must be a finite number"):
            AuthenticatedPrincipal("alice", "idp", float("inf"), "00" * 64)

        # 3. 64-bit integer overflow rejected
        with pytest.raises(ValueError, match="timestamp integer overflows 64-bit limits"):
            AuthenticatedPrincipal("alice", "idp", 10**100, "00" * 64)

        # 4. Valid int and float timestamp accepted
        p_int = AuthenticatedPrincipal("alice", "idp", 1700000000, "00" * 64)
        assert p_int.timestamp == 1700000000
        p_flt = AuthenticatedPrincipal("alice", "idp", 1700000000.5, "00" * 64)
        assert p_flt.timestamp == 1700000000.5

    def test_authenticated_principal_expires_at_validation(self):
        # 1. Non-numeric or boolean expires_at rejected
        with pytest.raises(TypeError, match="expires_at must be a numeric timestamp"):
            AuthenticatedPrincipal("alice", "idp", 1000.0, "00" * 64, expires_at=False)

        with pytest.raises(TypeError, match="expires_at must be a numeric timestamp"):
            AuthenticatedPrincipal("alice", "idp", 1000.0, "00" * 64, expires_at="invalid")

        # 2. Non-finite float expires_at rejected
        with pytest.raises(ValueError, match="expires_at must be a finite number"):
            AuthenticatedPrincipal("alice", "idp", 1000.0, "00" * 64, expires_at=float("nan"))

        with pytest.raises(ValueError, match="expires_at must be a finite number"):
            AuthenticatedPrincipal("alice", "idp", 1000.0, "00" * 64, expires_at=float("inf"))

        # 3. 64-bit integer overflow rejected
        with pytest.raises(ValueError, match="expires_at integer overflows 64-bit limits"):
            AuthenticatedPrincipal("alice", "idp", 1000.0, "00" * 64, expires_at=10**100)

        # 4. Valid int and float expires_at accepted
        p_int = AuthenticatedPrincipal("alice", "idp", 1000.0, "00" * 64, expires_at=2000)
        assert p_int.expires_at == 2000
        p_flt = AuthenticatedPrincipal("alice", "idp", 1000.0, "00" * 64, expires_at=2000.5)
        assert p_flt.expires_at == 2000.5

    def test_principal_verifier_clock_override_and_expiration_fail_closed(self):
        verifier = PrincipalVerifier({"idp": b"\x00" * 32})
        p = AuthenticatedPrincipal("alice", "idp", 1000.0, "00" * 64, expires_at=2000.0)

        # 1. Boolean current_time fails closed
        valid, reason, pid = verifier.verify_principal(p, current_time=True)
        assert not valid
        assert "Invalid current_time clock override" in reason

        # 2. Non-numeric current_time fails closed
        valid, reason, pid = verifier.verify_principal(p, current_time="not-a-number")
        assert not valid
        assert "Invalid current_time clock override" in reason

        # 3. Non-finite float current_time fails closed
        valid, reason, pid = verifier.verify_principal(p, current_time=float("nan"))
        assert not valid
        assert "Invalid current_time clock override" in reason

        # 4. Overflowing current_time fails closed
        valid, reason, pid = verifier.verify_principal(p, current_time=10**100)
        assert not valid
        assert "Invalid current_time clock override" in reason

    def test_compute_signature_payload_defensive_validation_on_bypassed_mutation(self):
        p = AuthenticatedPrincipal("alice", "idp", 1000.0, "00" * 64, expires_at=2000.0)

        # Mutate timestamp via object.__setattr__ to bypass frozen dataclass
        object.__setattr__(p, "timestamp", True)
        with pytest.raises(TypeError, match="timestamp must be a numeric timestamp"):
            p.compute_signature_payload()

        object.__setattr__(p, "timestamp", float("nan"))
        with pytest.raises(ValueError, match="timestamp must be a finite number"):
            p.compute_signature_payload()

        object.__setattr__(p, "timestamp", 10**100)
        with pytest.raises(ValueError, match="timestamp integer overflows 64-bit limits"):
            p.compute_signature_payload()

        # Restore valid timestamp, mutate expires_at
        object.__setattr__(p, "timestamp", 1000.0)
        object.__setattr__(p, "expires_at", False)
        with pytest.raises(TypeError, match="expires_at must be a numeric timestamp"):
            p.compute_signature_payload()

        object.__setattr__(p, "expires_at", float("inf"))
        with pytest.raises(ValueError, match="expires_at must be a finite number"):
            p.compute_signature_payload()

        object.__setattr__(p, "expires_at", 10**100)
        with pytest.raises(ValueError, match="expires_at integer overflows 64-bit limits"):
            p.compute_signature_payload()

    def test_principal_verifier_timestamp_runtime_validation_fails_closed(self):
        verifier = PrincipalVerifier({"idp": b"\x00" * 32})
        p = AuthenticatedPrincipal("alice", "idp", 1000.0, "00" * 64, expires_at=2000.0)

        # 1. Boolean timestamp fails closed
        object.__setattr__(p, "timestamp", True)
        valid, reason, pid = verifier.verify_principal(p)
        assert not valid
        assert "Principal assertion has invalid non-numeric timestamp" in reason

        # 2. Non-numeric string timestamp fails closed
        object.__setattr__(p, "timestamp", "not-a-number")
        valid, reason, pid = verifier.verify_principal(p)
        assert not valid
        assert "Principal assertion has invalid non-numeric timestamp" in reason

        # 3. Non-finite NaN float timestamp fails closed
        object.__setattr__(p, "timestamp", float("nan"))
        valid, reason, pid = verifier.verify_principal(p)
        assert not valid
        assert "Principal assertion timestamp is non-finite or overflows limits" in reason

        # 4. Non-finite Inf float timestamp fails closed
        object.__setattr__(p, "timestamp", float("inf"))
        valid, reason, pid = verifier.verify_principal(p)
        assert not valid
        assert "Principal assertion timestamp is non-finite or overflows limits" in reason

        # 5. Overflowing integer timestamp fails closed
        object.__setattr__(p, "timestamp", 10**100)
        valid, reason, pid = verifier.verify_principal(p)
        assert not valid
        assert "Principal assertion timestamp integer overflows 64-bit limits" in reason
