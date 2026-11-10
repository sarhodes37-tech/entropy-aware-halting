import pytest
import math
import uuid
import time
import tempfile
import os
import concurrent.futures
from epistemicos.authorization import (
    InMemoryAuthorizationStore,
    FileAuthorizationStore,
    Capability,
    CapabilityRegistry,
    HumanApprovalRecord,
    AuthorizationAuthority,
    Policy,
    PrincipalVerifier,
    _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN
)
from tests.unit.test_sec01_sec03_remediation import ExternalTestIdentityAuthority
from epistemicos.provenance import (
    TrustedExecutionBoundary,
    LocalProvenanceStore,
    ExecutionContext
)
from epistemicos.core import EpistemicOrchestrator
from epistemicos.gates import PermissionGate


def make_test_capability(token_id="AUTH-CAP-STEP4-01", approval_id=None, expires_at=2000000000.0, canonical_request_digest="a"*64):
    approval = None
    if approval_id is not None:
        approval = HumanApprovalRecord(
            approval_id=approval_id,
            approver_id="ciso_carol",
            action_name="read_secret",
            target="/secrets/key",
            action_digest=canonical_request_digest,
            request_id="REQ-STEP4-01",
            requesting_principal="agent_operator",
            tenant_domain="tenant-corp"
        )
    return Capability(
        token_id=token_id,
        principal_id="agent_operator",
        correlation_id="CORR-STEP4-01",
        request_id="REQ-STEP4-01",
        action_name="read_secret",
        target="/secrets/key",
        canonical_request_digest="a" * 64,
        executor_id="default_executor",
        policy_version="1.0.0",
        created_at=100.0,
        expires_at=expires_at,
        tenant_domain="tenant-corp",
        policy_id="pol-corp",
        human_approval=approval,
        authorization_basis="HUMAN_APPROVED" if approval else "AUTONOMOUS",
        _trusted_issuance_token=_TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN
    )


class TestTimestampValidationInMemoryStore:
    """Verifies finite numeric timestamp validation in InMemoryAuthorizationStore."""

    @pytest.mark.parametrize("invalid_ts", [
        float("nan"),
        float("inf"),
        float("-inf"),
        "12345.0",
        None,
        True,
        False,
        [123],
        {"ts": 123}
    ])
    def test_inmemory_rejects_non_finite_or_non_numeric_timestamp(self, invalid_ts):
        store = InMemoryAuthorizationStore()
        cap = make_test_capability(token_id="CAP-MEM-01", approval_id="APP-MEM-01")
        store.register_capability(cap)

        initial_seq = store._seq

        ok, reason, rec = store.consume_token_and_record_dispatch(
            token_id="CAP-MEM-01",
            attempt_id="ATT-MEM-01",
            dispatched_executor_id="default_executor",
            started_at=invalid_ts
        )

        assert ok is False
        assert reason == "CAPABILITY_CONSUMPTION_FAILED_INVALID_TIMESTAMP"
        assert rec is None

        # State must NOT be mutated
        assert store._seq == initial_seq
        assert "CAP-MEM-01" not in store._consumed_tokens
        assert "APP-MEM-01" not in store._consumed_approvals
        assert "ATT-MEM-01" not in store._execution_attempts
        assert "CAP-MEM-01" not in store._token_to_attempts

    def test_inmemory_accepts_valid_finite_timestamps_including_zero(self):
        store = InMemoryAuthorizationStore()
        cap1 = make_test_capability(token_id="CAP-MEM-ZERO", approval_id="APP-MEM-ZERO")
        store.register_capability(cap1)

        # 0 is a valid numeric timestamp
        ok, reason, rec = store.consume_token_and_record_dispatch(
            token_id="CAP-MEM-ZERO",
            attempt_id="ATT-MEM-ZERO",
            dispatched_executor_id="default_executor",
            started_at=0
        )
        assert ok is True
        assert reason == "DISPATCH_RECORDED_SUCCESSFULLY"
        assert rec["started_at"] == 0.0
        assert store._seq == 1
        assert "CAP-MEM-ZERO" in store._consumed_tokens
        assert "APP-MEM-ZERO" in store._consumed_approvals

        # Valid normal timestamp (e.g. 1700000000.5)
        cap2 = make_test_capability(token_id="CAP-MEM-NORM", approval_id="APP-MEM-NORM")
        store.register_capability(cap2)
        ok2, reason2, rec2 = store.consume_token_and_record_dispatch(
            token_id="CAP-MEM-NORM",
            attempt_id="ATT-MEM-NORM",
            dispatched_executor_id="default_executor",
            started_at=1700000000.5
        )
        assert ok2 is True
        assert rec2["started_at"] == 1700000000.5
        assert store._seq == 2


class TestTimestampValidationFileStore:
    """Verifies finite numeric timestamp validation in FileAuthorizationStore."""

    @pytest.mark.parametrize("invalid_ts", [
        float("nan"),
        float("inf"),
        float("-inf"),
        "12345.0",
        None,
        True,
        False,
        [123],
        {"ts": 123}
    ])
    def test_filestore_rejects_non_finite_or_non_numeric_timestamp(self, invalid_ts):
        with tempfile.NamedTemporaryFile(suffix=".jsonl") as f:
            store = FileAuthorizationStore(f.name)
            cap = make_test_capability(token_id="CAP-FILE-01", approval_id="APP-FILE-01")
            store.register_capability(cap)

            # Sync to get exact sequence from initial disk registrations
            store._sync_from_disk(acquire_lock=False)
            initial_seq = store._seq

            ok, reason, rec = store.consume_token_and_record_dispatch(
                token_id="CAP-FILE-01",
                attempt_id="ATT-FILE-01",
                dispatched_executor_id="default_executor",
                started_at=invalid_ts
            )

            assert ok is False
            assert reason == "CAPABILITY_CONSUMPTION_FAILED_INVALID_TIMESTAMP"
            assert rec is None

            # State and sequence must NOT be mutated
            assert store._seq == initial_seq
            assert "CAP-FILE-01" not in store._consumed_tokens
            assert "APP-FILE-01" not in store._consumed_approvals
            assert "ATT-FILE-01" not in store._execution_attempts

            # File must not contain a CONSUME_AND_DISPATCH record
            with open(f.name, "r", encoding="utf-8") as jf:
                lines = [line.strip() for line in jf if line.strip()]
                for l in lines:
                    assert "CONSUME_AND_DISPATCH" not in l

    def test_filestore_accepts_valid_finite_timestamps_including_zero(self):
        with tempfile.NamedTemporaryFile(suffix=".jsonl") as f:
            store = FileAuthorizationStore(f.name)
            cap1 = make_test_capability(token_id="CAP-FILE-ZERO", approval_id="APP-FILE-ZERO")
            store.register_capability(cap1)
            store._sync_from_disk(acquire_lock=False)
            initial_seq = store._seq

            # 0 is a valid numeric timestamp
            ok, reason, rec = store.consume_token_and_record_dispatch(
                token_id="CAP-FILE-ZERO",
                attempt_id="ATT-FILE-ZERO",
                dispatched_executor_id="default_executor",
                started_at=0
            )
            assert ok is True
            assert reason == "DISPATCH_RECORDED_SUCCESSFULLY"
            assert rec["started_at"] == 0.0
            assert store._seq == initial_seq + 1
            assert "CAP-FILE-ZERO" in store._consumed_tokens
            assert "APP-FILE-ZERO" in store._consumed_approvals

            # Valid normal timestamp (e.g. 1700000000.5)
            cap2 = make_test_capability(token_id="CAP-FILE-NORM", approval_id="APP-FILE-NORM")
            store.register_capability(cap2)
            store._sync_from_disk(acquire_lock=False)
            seq_before_norm = store._seq
            ok2, reason2, rec2 = store.consume_token_and_record_dispatch(
                token_id="CAP-FILE-NORM",
                attempt_id="ATT-FILE-NORM",
                dispatched_executor_id="default_executor",
                started_at=1700000000.5
            )
            assert ok2 is True
            assert rec2["started_at"] == 1700000000.5
            assert store._seq == seq_before_norm + 1


class TestOrchestratorAuthorityTenantEnforcement:
    """Verifies that EpistemicOrchestrator enforces authority tenant configuration and fails closed on missing tenant."""

    def test_orchestrator_fails_closed_when_authority_tenant_domain_missing(self):
        """When authority has no configured tenant_domain, orchestrator must fail closed and issue no capability."""
        authority = AuthorizationAuthority(tenant_domain=None)
        with tempfile.NamedTemporaryFile(suffix=".jsonl") as prov_file, tempfile.NamedTemporaryFile(suffix=".jsonl") as audit_file:
            prov_store = LocalProvenanceStore(prov_file.name)
            boundary = TrustedExecutionBoundary(provenance_store=prov_store, authority=authority)
            orch = EpistemicOrchestrator(
                authority=authority,
                execution_boundary=boundary,
                audit_log_path=audit_file.name
            )
            gate = PermissionGate(trusted_scope={"allowed_operations": ["read_data"], "allowed_resources": ["/data/test"]})
            orch.gates = [gate]

            def read_exec():
                return {"data": "secure_content"}
            authority.register_executor("read_exec", read_exec)

            res = orch.process_submission(
                raw_payload={"policy_id": "pol", "task": "read"},
                context={
                    "actual_executable": read_exec,
                    "action_name": "read_data",
                    "target": "/data/test",
                    "correlation_id": "c-no-tenant",
                    "request_id": "r-no-tenant",
                    "executor_func": "read_exec"
                }
            )

            assert res["status"] == "HALTED"
            assert res["execution_status"] == "DENIED"
            assert "AUTHORIZATION_DENIED_MISSING_TENANT_DOMAIN" in res["reason"]

            # Verify no capability was issued or recorded
            assert len(authority.registry._capabilities) == 0

            # Verify provenance event was recorded with DENIED
            corr_events = prov_store.get_events_for_correlation("c-no-tenant")
            denied_events = [e for e in corr_events if e.event_type == "AUTHORIZATION_DENIED"]
            assert len(denied_events) >= 1
            assert denied_events[0].decision == "DENIED"

    def test_orchestrator_fails_closed_when_authority_tenant_domain_empty_or_whitespace(self):
        """Empty or whitespace-only tenant_domain must fail closed."""
        authority = AuthorizationAuthority(tenant_domain="   ")
        with tempfile.NamedTemporaryFile(suffix=".jsonl") as prov_file, tempfile.NamedTemporaryFile(suffix=".jsonl") as audit_file:
            prov_store = LocalProvenanceStore(prov_file.name)
            boundary = TrustedExecutionBoundary(provenance_store=prov_store, authority=authority)
            orch = EpistemicOrchestrator(
                authority=authority,
                execution_boundary=boundary,
                audit_log_path=audit_file.name
            )
            gate = PermissionGate(trusted_scope={"allowed_operations": ["read_data"], "allowed_resources": ["/data/test"]})
            orch.gates = [gate]

            def read_exec():
                return {"data": "secure_content"}
            authority.register_executor("read_exec", read_exec)

            res = orch.process_submission(
                raw_payload={"policy_id": "pol", "task": "read"},
                context={
                    "actual_executable": read_exec,
                    "action_name": "read_data",
                    "target": "/data/test",
                    "correlation_id": "c-whitespace-tenant",
                    "request_id": "r-whitespace-tenant",
                    "executor_func": "read_exec"
                }
            )

            assert res["status"] == "HALTED"
            assert res["execution_status"] == "DENIED"
            assert "AUTHORIZATION_DENIED_MISSING_TENANT_DOMAIN" in res["reason"]
            assert len(authority.registry._capabilities) == 0
            corr_events = prov_store.get_events_for_correlation("c-whitespace-tenant")
            denied_events = [e for e in corr_events if e.event_type == "AUTHORIZATION_DENIED"]
            assert len(denied_events) >= 1
            assert denied_events[0].decision == "DENIED"

    def test_orchestrator_succeeds_when_authority_tenant_domain_validly_configured(self):
        """When authority has a valid configured tenant_domain, synthesized policy adopts it cleanly."""
        test_idp = ExternalTestIdentityAuthority(issuer_id="TestIdP_Authority")
        verifier = PrincipalVerifier(trusted_public_keys={"TestIdP_Authority": test_idp.public_key})
        p_assert = test_idp.issue_principal("operator_alice")
        authority = AuthorizationAuthority(principal_provider=verifier, tenant_domain="defense.corp.internal")
        with tempfile.NamedTemporaryFile(suffix=".jsonl") as prov_file, tempfile.NamedTemporaryFile(suffix=".jsonl") as audit_file:
            prov_store = LocalProvenanceStore(prov_file.name)
            boundary = TrustedExecutionBoundary(provenance_store=prov_store, authority=authority)
            orch = EpistemicOrchestrator(
                authority=authority,
                execution_boundary=boundary,
                audit_log_path=audit_file.name
            )
            gate = PermissionGate(trusted_scope={"allowed_operations": ["read_data"], "allowed_resources": ["/data/test"]})
            orch.gates = [gate]

            def read_exec():
                return {"data": "secure_content"}
            authority.register_executor("read_exec", read_exec)

            res = orch.process_submission(
                raw_payload={"policy_id": "pol", "task": "read"},
                context={
                    "actual_executable": read_exec,
                    "action_name": "read_data",
                    "target": "/data/test",
                    "correlation_id": "c-valid-tenant",
                    "request_id": "r-valid-tenant",
                    "executor_func": "read_exec",
                    "authenticated_principal": p_assert
                }
            )

            # Execution succeeds cleanly
            assert res["status"] == "ALLOWED"
            assert res["execution_status"] == "EXECUTED"
            assert res["execution_outcome"]["status"] == "SUCCESS"

            # Verify issued capability adopted authority tenant and server_trusted_scope
            issued_caps = list(authority.registry._capabilities.values())
            assert len(issued_caps) == 1
            assert issued_caps[0].tenant_domain == "defense.corp.internal"
            assert issued_caps[0].policy_id == "server_trusted_scope"


class TestApprovalConsumptionConcurrencyAndAtomicity:
    """Verifies atomic approval consumption and crash semantics under Step 4."""

    def test_approval_consumed_with_capability_atomically(self):
        store = InMemoryAuthorizationStore()
        cap = make_test_capability(token_id="CAP-ATOM-01", approval_id="APP-ATOM-01")
        store.register_capability(cap)

        assert not store.is_consumed("CAP-ATOM-01")
        assert not store.is_approval_consumed("APP-ATOM-01")

        ok, reason, rec = store.consume_token_and_record_dispatch(
            token_id="CAP-ATOM-01",
            attempt_id="ATT-ATOM-01",
            dispatched_executor_id="default_executor",
            started_at=1000.0
        )
        assert ok is True
        assert reason == "DISPATCH_RECORDED_SUCCESSFULLY"

        assert store.is_consumed("CAP-ATOM-01")
        assert store.is_approval_consumed("APP-ATOM-01")

    def test_approval_replay_rejected_under_different_capability(self):
        """Once an approval is consumed, another capability presenting the same approval cannot dispatch."""
        store = InMemoryAuthorizationStore()
        cap1 = make_test_capability(token_id="CAP-REPLAY-01", approval_id="APP-REPLAY-SHARED")
        cap2 = make_test_capability(token_id="CAP-REPLAY-02", approval_id="APP-REPLAY-SHARED")
        store.register_capability(cap1)
        store.register_capability(cap2)

        ok1, reason1, _ = store.consume_token_and_record_dispatch(
            token_id="CAP-REPLAY-01",
            attempt_id="ATT-REPLAY-01",
            dispatched_executor_id="default_executor",
            started_at=1000.0
        )
        assert ok1 is True

        # Second capability replay with the same approval must fail closed
        ok2, reason2, _ = store.consume_token_and_record_dispatch(
            token_id="CAP-REPLAY-02",
            attempt_id="ATT-REPLAY-02",
            dispatched_executor_id="default_executor",
            started_at=1001.0
        )
        assert ok2 is False
        assert "APPROVAL_REPLAYED" in reason2

    def test_concurrent_approval_consumption_only_one_wins(self):
        """Simulate concurrent threads racing to consume the same approval token."""
        store = InMemoryAuthorizationStore()
        cap = make_test_capability(token_id="CAP-CONCURR-01", approval_id="APP-CONCURR-01")
        store.register_capability(cap)

        results = []

        def worker(thread_idx):
            return store.consume_token_and_record_dispatch(
                token_id="CAP-CONCURR-01",
                attempt_id=f"ATT-CONCURR-{thread_idx}",
                dispatched_executor_id="default_executor",
                started_at=1000.0 + thread_idx
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futs = [executor.submit(worker, i) for i in range(8)]
            for f in concurrent.futures.as_completed(futs):
                results.append(f.result())

        successes = [r for r in results if r[0] is True]
        failures = [r for r in results if r[0] is False]

        assert len(successes) == 1
        assert len(failures) == 7
        assert store._seq == 1


class TestAuthorizationBasisDispatchEnforcement:
    """Verifies that InMemoryAuthorizationStore and FileAuthorizationStore enforce authorization_basis invariants at dispatch."""

    def test_human_approved_missing_approval_record_rejected(self):
        # InMemory
        mem_store = InMemoryAuthorizationStore()
        cap_mem = make_test_capability(token_id="CAP-MEM-NO-APP", approval_id=None)
        # Force authorization_basis to HUMAN_APPROVED while human_approval is None
        object.__setattr__(cap_mem, "authorization_basis", "HUMAN_APPROVED")
        mem_store.register_capability(cap_mem)
        seq0 = mem_store._seq

        ok, reason, _ = mem_store.consume_token_and_record_dispatch(
            token_id="CAP-MEM-NO-APP",
            attempt_id="ATT-1",
            dispatched_executor_id="exec1",
            started_at=100.0
        )
        assert ok is False
        assert reason == "CAPABILITY_CONSUMPTION_FAILED_MISSING_APPROVAL_RECORD"
        assert mem_store._seq == seq0
        assert "CAP-MEM-NO-APP" not in mem_store._consumed_tokens
        assert "ATT-1" not in mem_store._execution_attempts

        # FileStore
        with tempfile.NamedTemporaryFile(suffix=".jsonl") as f:
            fstore = FileAuthorizationStore(f.name)
            cap_f = make_test_capability(token_id="CAP-FILE-NO-APP", approval_id=None)
            object.__setattr__(cap_f, "authorization_basis", "HUMAN_APPROVED")
            fstore.register_capability(cap_f)
            fstore._sync_from_disk(acquire_lock=False)
            seq_f0 = fstore._seq

            ok_f, reason_f, _ = fstore.consume_token_and_record_dispatch(
                token_id="CAP-FILE-NO-APP",
                attempt_id="ATT-1",
                dispatched_executor_id="exec1",
                started_at=100.0
            )
            assert ok_f is False
            assert reason_f == "CAPABILITY_CONSUMPTION_FAILED_MISSING_APPROVAL_RECORD"
            assert fstore._seq == seq_f0
            assert "CAP-FILE-NO-APP" not in fstore._consumed_tokens
            assert "ATT-1" not in fstore._execution_attempts

    def test_human_approved_empty_or_whitespace_approval_id_rejected(self):
        for bad_id, expected_reason in [
            ("", "CAPABILITY_CONSUMPTION_FAILED_EMPTY_APPROVAL_ID"),
            ("  APP-TRIM-LEFT", "CAPABILITY_CONSUMPTION_FAILED_MALFORMED_APPROVAL_ID_WHITESPACE"),
            ("APP-TRIM-RIGHT  ", "CAPABILITY_CONSUMPTION_FAILED_MALFORMED_APPROVAL_ID_WHITESPACE"),
            ("  APP-TRIM-BOTH  ", "CAPABILITY_CONSUMPTION_FAILED_MALFORMED_APPROVAL_ID_WHITESPACE"),
        ]:
            # InMemory
            mem_store = InMemoryAuthorizationStore()
            cap_mem = make_test_capability(token_id=f"CAP-MEM-{uuid.uuid4()}", approval_id=bad_id)
            object.__setattr__(cap_mem, "authorization_basis", "HUMAN_APPROVED")
            mem_store.register_capability(cap_mem)
            seq0 = mem_store._seq

            ok, reason, _ = mem_store.consume_token_and_record_dispatch(
                token_id=cap_mem.token_id,
                attempt_id="ATT-1",
                dispatched_executor_id="exec1",
                started_at=100.0
            )
            assert ok is False
            assert reason == expected_reason
            assert mem_store._seq == seq0
            assert cap_mem.token_id not in mem_store._consumed_tokens

            # FileStore
            with tempfile.NamedTemporaryFile(suffix=".jsonl") as f:
                fstore = FileAuthorizationStore(f.name)
                cap_f = make_test_capability(token_id=f"CAP-FILE-{uuid.uuid4()}", approval_id=bad_id)
                object.__setattr__(cap_f, "authorization_basis", "HUMAN_APPROVED")
                fstore.register_capability(cap_f)
                fstore._sync_from_disk(acquire_lock=False)
                seq_f0 = fstore._seq

                ok_f, reason_f, _ = fstore.consume_token_and_record_dispatch(
                    token_id=cap_f.token_id,
                    attempt_id="ATT-1",
                    dispatched_executor_id="exec1",
                    started_at=100.0
                )
                assert ok_f is False
                assert reason_f == expected_reason
                assert fstore._seq == seq_f0
                assert cap_f.token_id not in fstore._consumed_tokens

    def test_autonomous_with_attached_approval_rejected(self):
        # InMemory
        mem_store = InMemoryAuthorizationStore()
        # Cap has human_approval object, but basis is AUTONOMOUS
        cap_mem = make_test_capability(token_id="CAP-MEM-INCONSISTENT", approval_id="APP-INCONSISTENT")
        object.__setattr__(cap_mem, "authorization_basis", "AUTONOMOUS")
        mem_store.register_capability(cap_mem)
        seq0 = mem_store._seq

        ok, reason, _ = mem_store.consume_token_and_record_dispatch(
            token_id="CAP-MEM-INCONSISTENT",
            attempt_id="ATT-1",
            dispatched_executor_id="exec1",
            started_at=100.0
        )
        assert ok is False
        assert reason == "CAPABILITY_CONSUMPTION_FAILED_INCONSISTENT_AUTONOMOUS_APPROVAL"
        assert mem_store._seq == seq0
        assert "CAP-MEM-INCONSISTENT" not in mem_store._consumed_tokens
        assert "APP-INCONSISTENT" not in mem_store._consumed_approvals

        # FileStore
        with tempfile.NamedTemporaryFile(suffix=".jsonl") as f:
            fstore = FileAuthorizationStore(f.name)
            cap_f = make_test_capability(token_id="CAP-FILE-INCONSISTENT", approval_id="APP-FILE-INCONSISTENT")
            object.__setattr__(cap_f, "authorization_basis", "AUTONOMOUS")
            fstore.register_capability(cap_f)
            fstore._sync_from_disk(acquire_lock=False)
            seq_f0 = fstore._seq

            ok_f, reason_f, _ = fstore.consume_token_and_record_dispatch(
                token_id="CAP-FILE-INCONSISTENT",
                attempt_id="ATT-1",
                dispatched_executor_id="exec1",
                started_at=100.0
            )
            assert ok_f is False
            assert reason_f == "CAPABILITY_CONSUMPTION_FAILED_INCONSISTENT_AUTONOMOUS_APPROVAL"
            assert fstore._seq == seq_f0
            assert "CAP-FILE-INCONSISTENT" not in fstore._consumed_tokens
            assert "APP-FILE-INCONSISTENT" not in fstore._consumed_approvals

    def test_missing_or_unknown_authorization_basis_rejected(self):
        for bad_basis in [None, "", "INVALID_BASIS", "DELEGATED", 123]:
            # InMemory
            mem_store = InMemoryAuthorizationStore()
            cap_mem = make_test_capability(token_id=f"CAP-MEM-{uuid.uuid4()}", approval_id=None)
            object.__setattr__(cap_mem, "authorization_basis", bad_basis)
            mem_store.register_capability(cap_mem)
            seq0 = mem_store._seq

            ok, reason, _ = mem_store.consume_token_and_record_dispatch(
                token_id=cap_mem.token_id,
                attempt_id="ATT-1",
                dispatched_executor_id="exec1",
                started_at=100.0
            )
            assert ok is False
            assert "CAPABILITY_CONSUMPTION_FAILED_INVALID_AUTHORIZATION_BASIS" in reason
            assert mem_store._seq == seq0
            assert cap_mem.token_id not in mem_store._consumed_tokens

            # FileStore
            with tempfile.NamedTemporaryFile(suffix=".jsonl") as f:
                fstore = FileAuthorizationStore(f.name)
                cap_f = make_test_capability(token_id=f"CAP-FILE-{uuid.uuid4()}", approval_id=None)
                object.__setattr__(cap_f, "authorization_basis", bad_basis)
                fstore.register_capability(cap_f)
                fstore._sync_from_disk(acquire_lock=False)
                seq_f0 = fstore._seq

                ok_f, reason_f, _ = fstore.consume_token_and_record_dispatch(
                    token_id=cap_f.token_id,
                    attempt_id="ATT-1",
                    dispatched_executor_id="exec1",
                    started_at=100.0
                )
                assert ok_f is False
                assert "CAPABILITY_CONSUMPTION_FAILED_INVALID_AUTHORIZATION_BASIS" in reason_f
                assert fstore._seq == seq_f0
                assert cap_f.token_id not in fstore._consumed_tokens

    def test_valid_autonomous_dispatch_consumes_only_capability(self):
        # InMemory
        mem_store = InMemoryAuthorizationStore()
        cap_mem = make_test_capability(token_id="CAP-MEM-AUTO-OK", approval_id=None)
        mem_store.register_capability(cap_mem)
        seq0 = mem_store._seq

        ok, reason, rec = mem_store.consume_token_and_record_dispatch(
            token_id="CAP-MEM-AUTO-OK",
            attempt_id="ATT-AUTO-1",
            dispatched_executor_id="exec1",
            started_at=100.0
        )
        assert ok is True
        assert reason == "DISPATCH_RECORDED_SUCCESSFULLY"
        assert mem_store._seq == seq0 + 1
        assert "CAP-MEM-AUTO-OK" in mem_store._consumed_tokens
        assert len(mem_store._consumed_approvals) == 0

        # FileStore
        with tempfile.NamedTemporaryFile(suffix=".jsonl") as f:
            fstore = FileAuthorizationStore(f.name)
            cap_f = make_test_capability(token_id="CAP-FILE-AUTO-OK", approval_id=None)
            fstore.register_capability(cap_f)
            fstore._sync_from_disk(acquire_lock=False)
            seq_f0 = fstore._seq

            ok_f, reason_f, rec_f = fstore.consume_token_and_record_dispatch(
                token_id="CAP-FILE-AUTO-OK",
                attempt_id="ATT-AUTO-1",
                dispatched_executor_id="exec1",
                started_at=100.0
            )
            assert ok_f is True
            assert reason_f == "DISPATCH_RECORDED_SUCCESSFULLY"
            assert fstore._seq == seq_f0 + 1
            assert "CAP-FILE-AUTO-OK" in fstore._consumed_tokens
            assert len(fstore._consumed_approvals) == 0

    def test_valid_human_approved_dispatch_consumes_capability_and_approval_atomically(self):
        # InMemory
        mem_store = InMemoryAuthorizationStore()
        cap_mem = make_test_capability(token_id="CAP-MEM-HA-OK", approval_id="APP-MEM-HA-OK")
        mem_store.register_capability(cap_mem)
        seq0 = mem_store._seq

        ok, reason, rec = mem_store.consume_token_and_record_dispatch(
            token_id="CAP-MEM-HA-OK",
            attempt_id="ATT-HA-1",
            dispatched_executor_id="exec1",
            started_at=100.0
        )
        assert ok is True
        assert reason == "DISPATCH_RECORDED_SUCCESSFULLY"
        assert mem_store._seq == seq0 + 1
        assert "CAP-MEM-HA-OK" in mem_store._consumed_tokens
        assert "APP-MEM-HA-OK" in mem_store._consumed_approvals

        # FileStore
        with tempfile.NamedTemporaryFile(suffix=".jsonl") as f:
            fstore = FileAuthorizationStore(f.name)
            cap_f = make_test_capability(token_id="CAP-FILE-HA-OK", approval_id="APP-FILE-HA-OK")
            fstore.register_capability(cap_f)
            fstore._sync_from_disk(acquire_lock=False)
            seq_f0 = fstore._seq

            ok_f, reason_f, rec_f = fstore.consume_token_and_record_dispatch(
                token_id="CAP-FILE-HA-OK",
                attempt_id="ATT-HA-1",
                dispatched_executor_id="exec1",
                started_at=100.0
            )
            assert ok_f is True
            assert reason_f == "DISPATCH_RECORDED_SUCCESSFULLY"
            assert fstore._seq == seq_f0 + 1
            assert "CAP-FILE-HA-OK" in fstore._consumed_tokens
            assert "APP-FILE-HA-OK" in fstore._consumed_approvals

    def test_execution_boundary_rejects_unverified_approval_shaped_object(self):
        """Verify that TrustedExecutionBoundary fails closed and does NOT dispatch when capability has an unverified approval record."""
        authority = AuthorizationAuthority(tenant_domain="tenant-corp")
        with tempfile.NamedTemporaryFile(suffix=".jsonl") as prov_file:
            prov_store = LocalProvenanceStore(prov_file.name)
            boundary = TrustedExecutionBoundary(provenance_store=prov_store, authority=authority)

            # Construct capability with forged/unverified approval record
            unverified_app = HumanApprovalRecord(
                approval_id="APP-FORGED-01",
                approver_id="attacker",
                action_name="read_secret",
                target="/secrets/key",
                action_digest="a" * 64,
                request_id="REQ-STEP4-01",
                requesting_principal="agent_operator",
                tenant_domain="tenant-corp"
            )
            def dummy_exec():
                return {"data": "exposed"}
            from epistemicos.authorization import get_callable_identity, canonicalize_fencing_scope
            exec_id = get_callable_identity(dummy_exec)
            authority.register_executor(exec_id, dummy_exec)

            payload = {"data": "test"}
            payload_digest = boundary.compute_canonical_digest(payload)

            cap = make_test_capability(token_id="CAP-FORGED-APP", approval_id=None)
            object.__setattr__(cap, "human_approval", unverified_app)
            object.__setattr__(cap, "authorization_basis", "HUMAN_APPROVED")
            unverified_app.action_digest = payload_digest
            object.__setattr__(cap, "executor_id", exec_id)
            object.__setattr__(cap, "canonical_request_digest", payload_digest)
            cap.scope_key = canonicalize_fencing_scope(cap.task_id, cap.target)
            cap.fencing_token = 1
            cap.signature = authority.registry._sign_capability_internal(cap, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)
            authority.registry.register_capability(cap)

            with pytest.raises(PermissionError) as exc_info:
                boundary.execute_protected_action(
                    action_name="read_secret",
                    target="/secrets/key",
                    request_payload=payload,
                    correlation_id="CORR-STEP4-01",
                    request_id="REQ-STEP4-01",
                    authorization_token_id="CAP-FORGED-APP",
                    authorized_digest=payload_digest,
                    authorization_granted=True,
                    executor_func=dummy_exec
                )

            assert "HUMAN_APPROVAL_SIGNATURE_INVALID" in str(exc_info.value)
            # Assert capability and approval were NOT consumed
            assert not authority.registry.is_consumed("CAP-FORGED-APP")
            assert not authority.registry.is_approval_consumed("APP-FORGED-01")


class TestTrustedCapabilityRestorationAndRegistrationBypass:
    """Adversarial tests for forged deserialization, arbitrary registration bypass, and journal restoration."""

    def test_from_dict_cannot_create_trusted_capability_from_serialized_basis(self):
        """Ordinary Capability.from_dict() must reject serialized authorization_basis without trust token."""
        for basis in ["AUTONOMOUS", "HUMAN_APPROVED"]:
            data = {
                "token_id": f"CAP-FORGED-{basis}",
                "principal_id": "attacker",
                "correlation_id": "c1",
                "request_id": "r1",
                "action_name": "transfer_funds",
                "target": "/accounts/drain",
                "canonical_request_digest": "f" * 64,
                "executor_id": "evil_exec",
                "policy_version": "1.0.0",
                "created_at": 100.0,
                "expires_at": 200.0,
                "tenant_domain": "corp.finance",
                "policy_id": "pol-finance",
                "authorization_basis": basis
            }
            with pytest.raises(ValueError, match="Caller authorization_basis selection prohibited"):
                Capability.from_dict(data)

    def test_restore_from_storage_rejects_unauthorized_token(self):
        """Capability._restore_from_storage() must fail closed if trust_token is not _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN."""
        data = {
            "token_id": "CAP-RESTORE-UNAUTH",
            "principal_id": "attacker",
            "correlation_id": "c1",
            "request_id": "r1",
            "action_name": "transfer_funds",
            "target": "/accounts/drain",
            "canonical_request_digest": "f" * 64,
            "executor_id": "evil_exec",
            "policy_version": "1.0.0",
            "created_at": 100.0,
            "expires_at": 200.0,
            "tenant_domain": "corp.finance",
            "policy_id": "pol-finance",
            "authorization_basis": "AUTONOMOUS"
        }
        with pytest.raises(PermissionError, match="Unauthorized invocation of _restore_from_storage"):
            Capability._restore_from_storage(data, trust_token="caller_fabricated_token")

    def test_arbitrary_capability_registration_bypass_closed(self):
        """CapabilityRegistry.register_capability() must reject unsigned or forged capabilities."""
        reg = CapabilityRegistry()
        cap_unsigned = Capability(
            token_id="CAP-ATTACK-01",
            principal_id="attacker",
            correlation_id="c1",
            request_id="r1",
            action_name="wipe_db",
            target="/db/prod",
            canonical_request_digest="0" * 64,
            executor_id="exec1",
            policy_version="1.0.0",
            created_at=100.0,
            expires_at=200.0,
            tenant_domain="corp.finance",
            policy_id="pol-finance"
        )
        # 1. Unsigned capability cannot be registered through public register_capability
        with pytest.raises(PermissionError, match="Registration rejected: capability must bear a valid authority signature"):
            reg.register_capability(cap_unsigned)

        # 2. Forged signature cannot be registered
        cap_unsigned.signature = "bad_signature" * 4
        with pytest.raises(PermissionError, match="Registration rejected: capability must bear a valid authority signature"):
            reg.register_capability(cap_unsigned)

        # Confirm store never received the forged capability
        assert reg.get_capability("CAP-ATTACK-01") is None

    def test_legitimate_authority_issuance_and_file_store_restoration(self):
        """Legitimate authority-issued capability persists to journal and is restored correctly via _restore_from_storage."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl") as f:
            file_store = FileAuthorizationStore(f.name)
            reg = CapabilityRegistry(storage_backend=file_store)
            policy = Policy(
                policy_id="pol-corp",
                allowed_operations={"read_metrics"},
                allowed_resources={"/metrics/health"},
                tenant_domain="defense.corp"
            )
            test_idp = ExternalTestIdentityAuthority(issuer_id="TestIdP_Authority")
            verifier = PrincipalVerifier(trusted_public_keys={"TestIdP_Authority": test_idp.public_key})
            p_assert = test_idp.issue_principal("operator_alice")
            authority = AuthorizationAuthority(
                default_policy=policy,
                registry=reg,
                principal_provider=verifier,
                tenant_domain="defense.corp"
            )
            cap, reason = authority.evaluate_and_issue_capability(
                action_name="read_metrics",
                target="/metrics/health",
                canonical_request_digest="b" * 64,
                principal_id=p_assert
            )
            assert cap is not None
            assert reason == "AUTHORIZATION_GRANTED"
            assert cap.authorization_basis == "AUTONOMOUS"

            # Create new file store instance pointing to same journal to test on-disk restoration
            new_store = FileAuthorizationStore(f.name)
            restored = new_store.get_capability(cap.token_id)
            assert restored is not None
            assert isinstance(restored, Capability)
            assert restored.token_id == cap.token_id
            assert restored.authorization_basis == "AUTONOMOUS"
            assert restored.signature == cap.signature
            # Verify signature matches
            assert reg._verify_capability_signature(restored) is True

    def test_legitimate_human_approved_issuance_and_restoration(self):
        """Legitimate human-approved capability retains approval and verifies after file-store restoration."""
        test_idp = ExternalTestIdentityAuthority(issuer_id="TestIdP_Authority")
        verifier = PrincipalVerifier(trusted_public_keys={"TestIdP_Authority": test_idp.public_key})
        ciso_ast = test_idp.issue_principal("ciso_carol")
        agent_ast = test_idp.issue_principal("agent_op")

        with tempfile.NamedTemporaryFile(suffix=".jsonl") as f:
            file_store = FileAuthorizationStore(f.name)
            reg = CapabilityRegistry(storage_backend=file_store)
            policy = Policy(
                policy_id="pol-corp-ha",
                allowed_operations={"deploy_firmware"},
                allowed_resources={"/cluster/primary"},
                required_human_approval_operations={"deploy_firmware"},
                allowed_approvers={"ciso_carol"},
                tenant_domain="defense.corp"
            )
            authority = AuthorizationAuthority(
                default_policy=policy,
                registry=reg,
                principal_provider=verifier,
                tenant_domain="defense.corp"
            )

            req_digest = "c" * 64
            req_id = "REQ-HA-RESTORE-1"
            corr_id = "CORR-HA-RESTORE-1"

            approval = HumanApprovalRecord(
                approval_id="APP-HA-RESTORE-1",
                approver_id="ciso_carol",
                action_name="deploy_firmware",
                target="/cluster/primary",
                action_digest=req_digest,
                request_id=req_id,
                requesting_principal="agent_op",
                approver_assertion=ciso_ast,
                tenant_domain="defense.corp"
            )
            approval.sign(authority.approval_signing_secret)

            authority.register_executor("default_executor", lambda: None)

            cap, reason = authority.evaluate_and_issue_capability(
                action_name="deploy_firmware",
                target="/cluster/primary",
                canonical_request_digest=req_digest,
                principal_id=agent_ast,
                correlation_id=corr_id,
                request_id=req_id,
                human_approval_input=approval
            )
            assert cap is not None
            assert reason == "AUTHORIZATION_GRANTED"
            assert cap.authorization_basis == "HUMAN_APPROVED"

            # Reopen from disk
            new_store = FileAuthorizationStore(f.name)
            restored = new_store.get_capability(cap.token_id)
            assert restored is not None
            assert restored.authorization_basis == "HUMAN_APPROVED"
            assert restored.human_approval is not None
            assert restored.human_approval.approval_id == "APP-HA-RESTORE-1"

            # Independent verification of restored capability
            ok, v_reason, _ = authority.verify_capability(
                token_id=restored.token_id,
                action_name="deploy_firmware",
                target="/cluster/primary",
                canonical_request_digest=req_digest,
                executor_id="default_executor",
                principal_id=agent_ast,
                correlation_id=corr_id,
                request_id=req_id
            )
            assert ok is True
            assert v_reason == "CAPABILITY_VERIFIED"


class TestTrustedIssuanceBoundaryHardening:
    """
    Adversarial tests proving:
    - No public registry API can sign an arbitrary capability.
    - CapabilityRegistry._sign_capability_internal rejects omitted or invalid issuance tokens.
    - CapabilityRegistry.register_capability rejects unsigned or forged caller-created capabilities.
    - Capability._restore_from_storage strictly fails with TypeError when trust_token is omitted.
    - Capability._restore_from_storage strictly fails with PermissionError when trust_token is invalid.
    - Legitimate issued capabilities persist, restore, and verify cleanly.
    """

    def test_no_public_registry_api_can_sign_arbitrary_capability(self):
        """Verify that sign_capability does not exist on CapabilityRegistry instances or class."""
        reg = CapabilityRegistry()
        assert not hasattr(reg, "sign_capability")
        assert not hasattr(CapabilityRegistry, "sign_capability")

    def test_sign_capability_internal_strictly_requires_trusted_token(self):
        """_sign_capability_internal must reject omitted, wrong, or forged issuance tokens."""
        reg = CapabilityRegistry()
        cap = make_test_capability(token_id="CAP-TAMPER-SIGN")

        # Wrong token raises PermissionError
        for invalid_token in [None, "forged_token", 12345, object(), object()]:
            with pytest.raises(PermissionError, match="Direct capability signing is restricted to trusted authority issuance"):
                reg._sign_capability_internal(cap, invalid_token)

        # Omission of required token raises TypeError
        with pytest.raises(TypeError):
            reg._sign_capability_internal(cap)

    def test_arbitrary_caller_created_capabilities_cannot_be_registered(self):
        """register_capability strictly rejects unsigned or forged caller-created capabilities."""
        reg = CapabilityRegistry()
        cap = make_test_capability(token_id="CAP-FORGED-REG")

        # Unsigned
        object.__setattr__(cap, "signature", None)
        with pytest.raises(PermissionError, match="capability must bear a valid authority signature"):
            reg.register_capability(cap)

        # Forged signature
        object.__setattr__(cap, "signature", "a" * 64)
        with pytest.raises(PermissionError, match="capability must bear a valid authority signature"):
            reg.register_capability(cap)

    def test_capability_restore_from_storage_strictly_requires_trust_token(self):
        """Capability._restore_from_storage has no default and strictly requires _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN."""
        cap = make_test_capability(token_id="CAP-RESTORE-TEST")
        cap_dict = cap.to_dict()

        # Omitted token raises TypeError (not taking default)
        with pytest.raises(TypeError, match="missing 1 required positional argument: .trust_token."):
            Capability._restore_from_storage(cap_dict)

        # Invalid tokens raise PermissionError
        for bad_tok in [None, "unauthorized", 999, object(), False]:
            with pytest.raises(PermissionError, match="Unauthorized invocation of _restore_from_storage"):
                Capability._restore_from_storage(cap_dict, bad_tok)

        # Legitimate token succeeds
        restored = Capability._restore_from_storage(cap_dict, _TRUSTED_AUTHORITY_ASSIGNMENT_TOKEN)
        assert restored is not None
        assert restored.token_id == "CAP-RESTORE-TEST"


class TestStorageBackendEncapsulation:
    """
    Adversarial acceptance tests demonstrating:
    - The ordinary registry interface does not expose unrestricted backend registration.
    - Public registry APIs cannot register arbitrary unsigned or forged capabilities.
    - Callers cannot supply arbitrary signing callbacks through an exposed registry operation.
    - Legitimate issuance still allocates fencing tokens, signs capabilities, and persists them.
    - File-backed restoration and atomic dispatch continue to work.
    """

    def test_ordinary_registry_interface_does_not_expose_storage(self):
        """Verify that self.storage is not exposed as a public attribute on CapabilityRegistry."""
        reg = CapabilityRegistry()
        assert not hasattr(reg, "storage")
        assert not hasattr(CapabilityRegistry, "storage")

    def test_callers_cannot_supply_arbitrary_signing_callbacks_through_registry(self):
        """CapabilityRegistry.issue_and_register_capability strictly takes only (cap), rejecting caller signing callbacks."""
        import inspect
        reg = CapabilityRegistry()
        sig = inspect.signature(reg.issue_and_register_capability)
        param_names = list(sig.parameters.keys())
        assert param_names == ["cap"]

        cap = make_test_capability(token_id="CAP-TAMPER-CALLBACK")
        forged_signer = lambda c: "forged_signature_by_attacker"

        with pytest.raises(TypeError):
            reg.issue_and_register_capability(cap, forged_signer)

    def test_public_registry_apis_cannot_register_arbitrary_unsigned_or_forged_capabilities(self):
        """CapabilityRegistry.register_capability rejects unsigned or forged caller-created capabilities."""
        reg = CapabilityRegistry()
        cap = make_test_capability(token_id="CAP-RAW-ATTEMPT")

        # Unsigned
        object.__setattr__(cap, "signature", None)
        with pytest.raises(PermissionError, match="capability must bear a valid authority signature prior to storage registration"):
            reg.register_capability(cap)

        # Forged signature
        object.__setattr__(cap, "signature", "b" * 64)
        with pytest.raises(PermissionError, match="capability must bear a valid authority signature prior to storage registration"):
            reg.register_capability(cap)

    def test_legitimate_issuance_allocates_fencing_tokens_signs_and_persists(self):
        """Legitimate authority-mediated issuance allocates monotonic fencing tokens, signs, and persists."""
        authority = AuthorizationAuthority(tenant_domain="encapsulated.corp")
        pol = Policy(
            policy_id="encap-pol",
            allowed_operations={"deploy_service"},
            allowed_resources={"/svc/web"},
            tenant_domain="encapsulated.corp"
        )
        authority.default_policy = pol

        cap, reason = authority.evaluate_and_issue_capability(
            action_name="deploy_service",
            target="/svc/web",
            canonical_request_digest="f" * 64,
            principal_id="admin_op",
            correlation_id="corr-encap-01",
            request_id="req-encap-01",
            task_id="TASK-ENCAP-01"
        )
        assert cap is not None
        assert reason == "AUTHORIZATION_GRANTED"
        assert cap.fencing_token == 1
        assert cap.signature is not None

        # Verify capability is persisted in registry and independently verifiable
        stored_cap = authority.registry.get_capability(cap.token_id)
        assert stored_cap is not None
        assert stored_cap.token_id == cap.token_id
        assert stored_cap.signature == cap.signature

        ok, v_reason, _ = authority.verify_capability(
            token_id=cap.token_id,
            action_name="deploy_service",
            target="/svc/web",
            canonical_request_digest="f" * 64,
            executor_id="default_executor",
            principal_id="admin_op",
            correlation_id="corr-encap-01",
            request_id="req-encap-01",
            task_id="TASK-ENCAP-01"
        )
        assert ok is True
        assert v_reason == "CAPABILITY_VERIFIED"
