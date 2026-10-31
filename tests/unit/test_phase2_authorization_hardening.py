"""
Adversarial and Concurrency Test Suite for EpistemicOS P0.2 Execution Boundary Hardening.

Verifies:
1. Two independent authority/boundary instances attempt to consume the same capability: exactly one succeeds.
2. Cross-instance revocation: Revocation via Instance A is observed and rejected on Instance B.
3. Linearization of consumption racing with revocation: well-defined outcomes, no invalid states.
4. Monotonic fencing: stale fencing tokens rejected after newer token is issued for scope.
5. Delayed operation carrying stale fencing token rejected at FencedResource boundary.
6. Downstream resource lacking fencing cannot protect against delayed execution (documented boundary limit).
7. Backend failure fail-closed: unwriteable/corrupt backend fails closed and never authorizes.
8. Process restart/reconstruction: state remains consumed or revoked across independent instances.
9. Multi-process concurrency: independent processes allocating fencing tokens and consuming capabilities without collision.
"""

import os
import json
import time
import uuid
import pytest
import multiprocessing
from unittest.mock import MagicMock

from epistemicos.authorization import (
    AuthorizationAuthority,
    CapabilityRegistry,
    FileAuthorizationStore,
    InMemoryAuthorizationStore,
    Policy,
    Capability,
    HumanApprovalRecord,
    canonicalize_fencing_scope,
)
from epistemicos.provenance import (
    TrustedExecutionBoundary,
    LocalProvenanceStore,
    ExecutionContext,
    FencedResource,
)


def test_independent_instances_single_use_consumption(tmp_path):
    """
    Two independent authority/boundary instances sharing a FileAuthorizationStore
    attempt to consume the same capability: exactly one succeeds.
    """
    store_path = str(tmp_path / "auth_store.jsonl")
    shared_store = FileAuthorizationStore(store_path=store_path)

    # Authority A and Boundary A
    reg_a = CapabilityRegistry(storage_backend=shared_store, denial_log_path=str(tmp_path / "denials_a.jsonl"))
    auth_a = AuthorizationAuthority(registry=reg_a)
    prov_a = LocalProvenanceStore(log_path=str(tmp_path / "prov_a.jsonl"))
    boundary_a = TrustedExecutionBoundary(provenance_store=prov_a, authority=auth_a)

    # Authority B and Boundary B (completely separate instance sharing backend)
    reg_b = CapabilityRegistry(
        signing_secret=reg_a.signing_secret,
        storage_backend=FileAuthorizationStore(store_path=store_path),
        denial_log_path=str(tmp_path / "denials_b.jsonl")
    )
    auth_b = AuthorizationAuthority(registry=reg_b)
    prov_b = LocalProvenanceStore(log_path=str(tmp_path / "prov_b.jsonl"))
    boundary_b = TrustedExecutionBoundary(provenance_store=prov_b, authority=auth_b)

    payload = {"data": "shared_resource_test"}
    digest = boundary_a.compute_canonical_digest(payload)
    callback_a = MagicMock(return_value={"status": "EXEC_A"})
    callback_b = MagicMock(return_value={"status": "EXEC_B"})

    policy = Policy(policy_id="p1", allowed_operations={"operate"}, allowed_resources={"/res1"})
    auth_a.default_policy = policy
    auth_b.default_policy = policy

    auth_a.register_executor("operate", callback_a)
    auth_b.register_executor("operate", callback_b)

    # Issue capability from Instance A
    cap, reason = auth_a.evaluate_and_issue_capability("operate", "/res1", digest, executor_id=callback_a)
    assert cap is not None
    assert reason == "AUTHORIZATION_GRANTED"

    # Consume on Boundary A
    res_a = boundary_a.execute_protected_action(
        action_name="operate",
        target="/res1",
        request_payload=payload,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        executor_func=callback_a
    )
    assert res_a["status"] == "SUCCESS"
    assert callback_a.call_count == 1

    # Attempt to consume the SAME token on Boundary B: MUST FAIL CLOSED (already consumed)
    with pytest.raises(PermissionError, match="has already been consumed"):
        boundary_b.execute_protected_action(
            action_name="operate",
            target="/res1",
            request_payload=payload,
            authorization_token_id=cap.token_id,
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=callback_b
        )

    assert callback_b.call_count == 0


def test_cross_instance_revocation_observed(tmp_path):
    """
    Revocation through instance A is observed and rejected on instance B.
    """
    store_path = str(tmp_path / "auth_store.jsonl")
    shared_store = FileAuthorizationStore(store_path=store_path)

    reg_a = CapabilityRegistry(storage_backend=shared_store, denial_log_path=str(tmp_path / "denials_a.jsonl"))
    auth_a = AuthorizationAuthority(registry=reg_a)

    reg_b = CapabilityRegistry(
        signing_secret=reg_a.signing_secret,
        storage_backend=FileAuthorizationStore(store_path=store_path),
        denial_log_path=str(tmp_path / "denials_b.jsonl")
    )
    auth_b = AuthorizationAuthority(registry=reg_b)
    boundary_b = TrustedExecutionBoundary(
        provenance_store=LocalProvenanceStore(log_path=str(tmp_path / "prov_b.jsonl")),
        authority=auth_b
    )

    payload = {"data": "revocation_test"}
    digest = boundary_b.compute_canonical_digest(payload)
    callback = MagicMock()

    policy = Policy(policy_id="p1", allowed_operations={"operate"}, allowed_resources={"/res1"})
    auth_a.default_policy = policy
    auth_b.default_policy = policy
    auth_b.register_executor("operate", callback)

    # Issue capability on A
    cap, _ = auth_a.evaluate_and_issue_capability("operate", "/res1", digest, executor_id=callback)
    assert cap is not None

    # Revoke on A
    rev_ok, rev_msg = reg_a.revoke_token(cap.token_id, reason="Security audit halt")
    assert rev_ok is True

    # Attempt verification and execution on B
    valid, v_reason, _ = auth_b.verify_capability(
        token_id=cap.token_id,
        action_name="operate",
        target="/res1",
        canonical_request_digest=digest,
        executor_id="operate"
    )
    assert valid is False
    assert "REVOKED_TOKEN" in v_reason

    # Execution on Boundary B must be rejected
    with pytest.raises(PermissionError, match="REVOKED_TOKEN"):
        boundary_b.execute_protected_action(
            action_name="operate",
            target="/res1",
            request_payload=payload,
            authorization_token_id=cap.token_id,
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=callback
        )

    assert callback.call_count == 0


def test_consumption_racing_with_revocation(tmp_path):
    """
    Consumption racing with revocation produces only documented linearization outcomes:
    - Either revocation linearizes first -> consumption fails.
    - Or consumption linearizes first -> revocation fails to prevent that execution.
    Never both or inconsistent state.
    """
    store_path = str(tmp_path / "auth_store.jsonl")
    store = FileAuthorizationStore(store_path=store_path)

    # Create dummy capability
    cap = Capability(
        token_id="RACE-TOKEN-1",
        principal_id="p1",
        correlation_id="c1",
        request_id="r1",
        action_name="act",
        target="/tgt",
        canonical_request_digest="d",
        executor_id="e",
        policy_version="1.0",
        created_at=time.time(),
        expires_at=time.time() + 100,
        fencing_token=1,
        scope_key="task:__GLOBAL__|target::/tgt"
    )
    store.register_capability(cap)

    # Test 1: Revocation before consumption
    rev_ok, _ = store.revoke_capability("RACE-TOKEN-1", "revocation race")
    assert rev_ok is True
    consume_ok, consume_reason = store.consume_capability("RACE-TOKEN-1")
    assert consume_ok is False
    assert "REVOKED" in consume_reason

    # Test 2: Consumption before revocation
    cap2 = Capability(
        token_id="RACE-TOKEN-2",
        principal_id="p1",
        correlation_id="c2",
        request_id="r2",
        action_name="act",
        target="/tgt",
        canonical_request_digest="d",
        executor_id="e",
        policy_version="1.0",
        created_at=time.time(),
        expires_at=time.time() + 100,
        fencing_token=1,
        scope_key="task:__GLOBAL__|target::/tgt"
    )
    store.register_capability(cap2)

    c_ok, _ = store.consume_capability("RACE-TOKEN-2")
    assert c_ok is True
    r_ok, r_msg = store.revoke_capability("RACE-TOKEN-2", "late revocation")
    assert r_ok is False
    assert "ALREADY_CONSUMED" in r_msg


def test_monotonic_fencing_stale_generation_rejected(tmp_path):
    """
    Monotonic fencing: A capability with an older fencing token is rejected
    after a newer generation becomes authoritative for that scope.
    """
    store_path = str(tmp_path / "auth_store.jsonl")
    shared_store = FileAuthorizationStore(store_path=store_path)
    reg = CapabilityRegistry(storage_backend=shared_store, denial_log_path=str(tmp_path / "denials.jsonl"))
    auth = AuthorizationAuthority(registry=reg)
    boundary = TrustedExecutionBoundary(
        provenance_store=LocalProvenanceStore(log_path=str(tmp_path / "prov.jsonl")),
        authority=auth
    )

    policy = Policy(policy_id="p1", allowed_operations={"mutate"}, allowed_resources={"/database"})
    auth.default_policy = policy
    callback = MagicMock(return_value={"status": "OK"})
    auth.register_executor("mutate", callback)

    payload = {"data": "val"}
    digest = boundary.compute_canonical_digest(payload)

    # 1. Issue Cap 1 (fencing token generation 1)
    cap1, _ = auth.evaluate_and_issue_capability(
        "mutate", "/database", digest, executor_id=callback, task_id="task_A"
    )
    assert cap1.fencing_token == 1
    assert cap1.scope_key == "task:task_A|target::/database"

    # 2. Issue Cap 2 for the same scope (fencing token generation 2)
    cap2, _ = auth.evaluate_and_issue_capability(
        "mutate", "/database", digest, executor_id=callback, task_id="task_A"
    )
    assert cap2.fencing_token == 2
    assert cap2.scope_key == "task:task_A|target::/database"

    # Authority and Boundary should now reject Cap 1 because its generation (1) is stale (< 2)
    valid, reason, _ = auth.verify_capability(
        token_id=cap1.token_id,
        action_name="mutate",
        target="/database",
        canonical_request_digest=digest,
        executor_id=auth.registry.get_capability(cap1.token_id).executor_id,
        task_id="task_A"
    )
    assert valid is False
    assert "STALE_FENCING_TOKEN" in reason

    with pytest.raises(PermissionError, match="STALE_FENCING_TOKEN"):
        boundary.execute_protected_action(
            action_name="mutate",
            target="/database",
            request_payload=payload,
            authorization_token_id=cap1.token_id,
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=callback,
            context=ExecutionContext(
                correlation_id=cap1.correlation_id,
                request_id=cap1.request_id,
                authorization_token_id=cap1.token_id,
                authorized_digest=digest,
                fencing_token=cap1.fencing_token,
                task_id="task_A"
            )
        )

    assert callback.call_count == 0

    # Cap 2 is current and must execute successfully
    res2 = boundary.execute_protected_action(
        action_name="mutate",
        target="/database",
        request_payload=payload,
        authorization_token_id=cap2.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        executor_func=callback,
        context=ExecutionContext(
            correlation_id=cap2.correlation_id,
            request_id=cap2.request_id,
            authorization_token_id=cap2.token_id,
            authorized_digest=digest,
            fencing_token=cap2.fencing_token,
            task_id="task_A"
        )
    )
    assert res2["status"] == "SUCCESS"
    assert callback.call_count == 1


import threading

class MockFencedDatabase:
    """
    Mock downstream resource implementing atomic resource-side fencing validation.
    Maintains independent high-water marks per scope_key, ensuring cross-scope isolation.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self.scope_watermarks: dict[str, int] = {}
        self.operations = []

    def __call__(self, *args, **kwargs):
        return self.validate_and_execute(0, "default_scope", *args, **kwargs)

    def validate_and_execute(self, fencing_token: int, scope_key: str, *args, **kwargs):
        with self._lock:
            current_hwm = self.scope_watermarks.get(scope_key, 0)
            if fencing_token < current_hwm:
                raise PermissionError(
                    f"Resource boundary violation for {scope_key}: Stale fencing token {fencing_token} < current {current_hwm}"
                )
            self.scope_watermarks[scope_key] = fencing_token
            self.operations.append((scope_key, fencing_token))
            return {"status": "APPLIED", "scope_key": scope_key, "generation": fencing_token}


def test_downstream_resource_fencing_enforcement(tmp_path):
    """
    A delayed operation carrying a stale fencing token is rejected at the protected resource boundary
    when the downstream resource implements fencing validation.
    """
    resource = MockFencedDatabase()
    assert isinstance(resource, FencedResource)

    store = FileAuthorizationStore(store_path=str(tmp_path / "auth.jsonl"))
    reg = CapabilityRegistry(storage_backend=store, denial_log_path=str(tmp_path / "denial.jsonl"))
    auth = AuthorizationAuthority(registry=reg)
    boundary = TrustedExecutionBoundary(
        provenance_store=LocalProvenanceStore(log_path=str(tmp_path / "prov.jsonl")),
        authority=auth
    )

    policy = Policy(policy_id="p_db", allowed_operations={"write"}, allowed_resources={"/db/table"})
    auth.default_policy = policy
    auth.register_executor("write", resource)

    payload = {"query": "UPDATE balance"}
    digest = boundary.compute_canonical_digest(payload)

    # Operation 1: Gen 1 on task_A
    cap1, _ = auth.evaluate_and_issue_capability("write", "/db/table", digest, executor_id=resource, task_id="task_A")
    res1 = boundary.execute_protected_action(
        action_name="write",
        target="/db/table",
        request_payload=payload,
        authorization_token_id=cap1.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        executor_func=resource
    )
    assert res1["status"] == "SUCCESS"
    assert resource.scope_watermarks[cap1.scope_key] == 1

    # Operation 2: Gen 2 on task_A
    cap2, _ = auth.evaluate_and_issue_capability("write", "/db/table", digest, executor_id=resource, task_id="task_A")
    res2 = boundary.execute_protected_action(
        action_name="write",
        target="/db/table",
        request_payload=payload,
        authorization_token_id=cap2.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        executor_func=resource
    )
    assert res2["status"] == "SUCCESS"
    assert resource.scope_watermarks[cap2.scope_key] == 2

    # Delayed execution simulation: an old request tries to call validate_and_execute with Gen 1 for task_A scope
    with pytest.raises(PermissionError, match="Stale fencing token 1 < current 2"):
        resource.validate_and_execute(1, cap1.scope_key)

    # Independent scope isolation test: task_B targeting the same resource receives Gen 1 and executes without interference
    cap3, _ = auth.evaluate_and_issue_capability("write", "/db/table", digest, executor_id=resource, task_id="task_B")
    assert cap3.fencing_token == 1
    assert cap3.scope_key != cap1.scope_key
    res3 = boundary.execute_protected_action(
        action_name="write",
        target="/db/table",
        request_payload=payload,
        authorization_token_id=cap3.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        executor_func=resource
    )
    assert res3["status"] == "SUCCESS"
    assert resource.scope_watermarks[cap3.scope_key] == 1


def test_unfenced_resource_demonstrates_documented_limitation(tmp_path):
    """
    Demonstrates the documented boundary limit: if a downstream resource does NOT validate fencing tokens,
    an arbitrary delayed network operation cannot be rejected at the resource layer alone.
    """
    class LegacyDatabase:
        def __init__(self):
            self.applied_count = 0
        def execute(self):
            self.applied_count += 1
            return "APPLIED"

    legacy_db = LegacyDatabase()
    assert not isinstance(legacy_db, FencedResource)

    # Because LegacyDatabase does not validate fencing generations, direct invocation executes
    res = legacy_db.execute()
    assert res == "APPLIED"
    assert legacy_db.applied_count == 1


def test_backend_failure_fails_closed(tmp_path):
    """
    Storage / backend failure (corrupted journal, unparseable json, or lock failure)
    fails closed immediately and never authorizes execution.
    """
    store_file = tmp_path / "corrupted_store.jsonl"
    with open(store_file, "w", encoding="utf-8") as f:
        f.write('{"type": "INIT"}\n')
        f.write('THIS_IS_CORRUPTED_JSON_DATA_LINE\n')

    # Instantiating or reading must fail closed
    with pytest.raises(RuntimeError, match="Corrupted or ambiguous authorization journal"):
        FileAuthorizationStore(store_path=str(store_file), fail_closed=True)


def test_restart_reconstruction_preserves_revocation_and_consumption(tmp_path):
    """
    Restart/reconstruction of registry and boundary instances does not silently
    restore revoked or consumed authorization state.
    """
    store_path = str(tmp_path / "auth_store.jsonl")
    store = FileAuthorizationStore(store_path=store_path)
    reg = CapabilityRegistry(storage_backend=store, denial_log_path=str(tmp_path / "denials.jsonl"))
    auth = AuthorizationAuthority(registry=reg)

    policy = Policy(policy_id="p1", allowed_operations={"op"}, allowed_resources={"/res"})
    auth.default_policy = policy
    callback = MagicMock(return_value={"status": "OK"})
    auth.register_executor("op", callback)

    boundary = TrustedExecutionBoundary(
        provenance_store=LocalProvenanceStore(log_path=str(tmp_path / "prov.jsonl")),
        authority=auth
    )

    # 1. Issue and consume token 1
    payload1 = {"d": 1}
    d1 = boundary.compute_canonical_digest(payload1)
    cap1, _ = auth.evaluate_and_issue_capability("op", "/res", d1, executor_id=callback)
    boundary.execute_protected_action("op", "/res", payload1, authorization_token_id=cap1.token_id, authorized_digest=d1, authorization_granted=True, executor_func=callback)

    # 2. Issue and revoke token 2
    payload2 = {"d": 2}
    d2 = boundary.compute_canonical_digest(payload2)
    cap2, _ = auth.evaluate_and_issue_capability("op", "/res", d2, executor_id=callback)
    reg.revoke_token(cap2.token_id, "test audit revoke")

    # Reconstruct new independent authority/registry from disk (simulating service restart)
    new_store = FileAuthorizationStore(store_path=store_path)
    new_reg = CapabilityRegistry(
        signing_secret=reg.signing_secret,
        storage_backend=new_store,
        denial_log_path=str(tmp_path / "denials.jsonl")
    )
    new_auth = AuthorizationAuthority(registry=new_reg, default_policy=policy)
    new_boundary = TrustedExecutionBoundary(
        provenance_store=LocalProvenanceStore(log_path=str(tmp_path / "prov2.jsonl")),
        authority=new_auth
    )
    new_auth.register_executor("op", callback)

    # Verify token 1 remains CONSUMED
    assert new_reg.is_consumed(cap1.token_id) is True
    with pytest.raises(PermissionError, match="has already been consumed"):
        new_boundary.execute_protected_action("op", "/res", payload1, authorization_token_id=cap1.token_id, authorized_digest=d1, authorization_granted=True, executor_func=callback)

    # Verify token 2 remains REVOKED
    assert new_reg.is_revoked(cap2.token_id) is True
    with pytest.raises(PermissionError, match="REVOKED_TOKEN"):
        new_boundary.execute_protected_action("op", "/res", payload2, authorization_token_id=cap2.token_id, authorized_digest=d2, authorization_granted=True, executor_func=callback)


def _worker_fence_allocation(store_path: str, scope_key: str, results_queue: multiprocessing.Queue):
    """Worker process allocating fencing tokens in parallel."""
    store = FileAuthorizationStore(store_path=store_path)
    for _ in range(5):
        token = store.allocate_fencing_token(scope_key)
        results_queue.put(token)


def test_cross_process_monotonic_fencing_allocation(tmp_path):
    """
    Two independent processes sharing the same FileAuthorizationStore allocate fencing tokens simultaneously.
    Asserts no duplicate or regressing values.
    """
    store_path = str(tmp_path / "shared_auth.jsonl")
    # Initialize store
    _ = FileAuthorizationStore(store_path=store_path)

    queue = multiprocessing.Queue()
    scope = "task:concurrent_task|target::/shared_db"

    p1 = multiprocessing.Process(target=_worker_fence_allocation, args=(store_path, scope, queue))
    p2 = multiprocessing.Process(target=_worker_fence_allocation, args=(store_path, scope, queue))

    p1.start()
    p2.start()

    p1.join(timeout=10)
    p2.join(timeout=10)

    assert p1.exitcode == 0
    assert p2.exitcode == 0

    allocated = []
    while not queue.empty():
        allocated.append(queue.get())

    assert len(allocated) == 10
    # Values must be exactly 1 through 10 with NO duplicates
    assert sorted(allocated) == list(range(1, 11))


def _worker_concurrent_issuance(store_path: str, signing_secret: bytes, scope_key: str, results_queue: multiprocessing.Queue):
    """Worker process issuing capabilities concurrently."""
    store = FileAuthorizationStore(store_path=store_path)
    reg = CapabilityRegistry(signing_secret=signing_secret, storage_backend=store)
    auth = AuthorizationAuthority(registry=reg, default_policy=Policy(policy_id="p", allowed_operations={"op"}, allowed_resources={"/res"}))
    for i in range(5):
        cap, reason = auth.evaluate_and_issue_capability("op", "/res", f"digest_{i}", task_id="multi_proc_task")
        if cap:
            results_queue.put((cap.token_id, cap.fencing_token))


def test_cross_process_concurrent_capability_issuance(tmp_path):
    """
    Two independent processes sharing a FileAuthorizationStore issue capabilities concurrently for the same scope.
    Verifies that all issued capabilities receive strictly unique, monotonically increasing generations
    and all registered capabilities are persisted without corruption.
    """
    store_path = str(tmp_path / "concurrent_issuance.jsonl")
    shared_store = FileAuthorizationStore(store_path=store_path)
    signing_secret = b"CONCURRENT_SIGNING_SECRET_12345"

    queue = multiprocessing.Queue()
    scope = "task:multi_proc_task|target::/res"

    p1 = multiprocessing.Process(target=_worker_concurrent_issuance, args=(store_path, signing_secret, scope, queue))
    p2 = multiprocessing.Process(target=_worker_concurrent_issuance, args=(store_path, signing_secret, scope, queue))

    p1.start()
    p2.start()
    p1.join(timeout=10)
    p2.join(timeout=10)

    assert p1.exitcode == 0
    assert p2.exitcode == 0

    issued = []
    while not queue.empty():
        issued.append(queue.get())

    assert len(issued) == 10
    tokens = [tok for tok, fence in issued]
    fences = [fence for tok, fence in issued]

    # All token IDs must be unique
    assert len(set(tokens)) == 10
    # All fencing generations must be unique and strictly sequential 1..10
    assert sorted(fences) == list(range(1, 11))


def _worker_compete_consumption(store_path: str, token_id: str, results_queue: multiprocessing.Queue):
    """Worker process attempting to consume a single-use token."""
    store = FileAuthorizationStore(store_path=store_path)
    ok, reason = store.consume_capability(token_id)
    results_queue.put((ok, reason))


def test_cross_process_concurrent_consumption_race(tmp_path):
    """
    Two independent processes race to consume the same capability simultaneously.
    Asserts that exactly one succeeds and one receives ALREADY_CONSUMED.
    """
    store_path = str(tmp_path / "compete_consume.jsonl")
    store = FileAuthorizationStore(store_path=store_path)
    reg = CapabilityRegistry(storage_backend=store)
    auth = AuthorizationAuthority(registry=reg, default_policy=Policy(policy_id="p", allowed_operations={"op"}, allowed_resources={"/res"}))

    cap, _ = auth.evaluate_and_issue_capability("op", "/res", "d_race")
    assert cap is not None

    queue = multiprocessing.Queue()
    p1 = multiprocessing.Process(target=_worker_compete_consumption, args=(store_path, cap.token_id, queue))
    p2 = multiprocessing.Process(target=_worker_compete_consumption, args=(store_path, cap.token_id, queue))

    p1.start()
    p2.start()
    p1.join(timeout=10)
    p2.join(timeout=10)

    assert p1.exitcode == 0
    assert p2.exitcode == 0

    outcomes = []
    while not queue.empty():
        outcomes.append(queue.get())

    successes = [ok for ok, r in outcomes if ok is True]
    failures = [r for ok, r in outcomes if ok is False]

    assert len(successes) == 1
    assert len(failures) == 1
    assert "ALREADY_CONSUMED" in failures[0]


def test_crash_recovery_journal_atomicity(tmp_path):
    """
    Crash recovery & journal atomicity:
    1. Single-event ISSUE_CAPABILITY reconstructs both capability registration and fencing generation.
    2. A partially written/truncated journal line triggers fail-closed error upon restart.
    3. State cannot be loaded partially or ambiguously.
    """
    store_path = str(tmp_path / "crash_store.jsonl")
    store = FileAuthorizationStore(store_path=store_path)
    reg = CapabilityRegistry(storage_backend=store)
    auth = AuthorizationAuthority(registry=reg, default_policy=Policy(policy_id="p", allowed_operations={"op"}, allowed_resources={"/res"}))

    cap, _ = auth.evaluate_and_issue_capability("op", "/res", "d_crash", task_id="crash_task")
    assert cap is not None
    assert cap.fencing_token == 1

    # Verify normal restart reconstruction
    store_restarted = FileAuthorizationStore(store_path=store_path)
    assert store_restarted.get_scope_fencing_token(cap.scope_key) == 1
    reconstructed_cap = store_restarted.get_capability(cap.token_id)
    assert reconstructed_cap is not None
    assert reconstructed_cap.token_id == cap.token_id
    assert reconstructed_cap.fencing_token == 1

    # Simulate crash during journal append resulting in a truncated line
    with open(store_path, "a", encoding="utf-8") as f:
        f.write('{"type": "ISSUE_CAPABILITY", "token_id": "PARTIAL_TRUNCATED_RECORD", "scope_key": "task:crash|target::/res"')  # missing closing brace

    # Reopening after crash with truncated journal MUST fail closed
    with pytest.raises(RuntimeError, match="Corrupted or ambiguous authorization journal"):
        FileAuthorizationStore(store_path=store_path, fail_closed=True)
