"""
Adversarial and Concurrency Test Suite for EpistemicOS P0.2 Execution Boundary Hardening.

Verifies:
1. Two independent authority/boundary instances attempt to consume the same capability: exactly one succeeds.
2. Cross-instance revocation: Revocation via Instance A is observed and rejected on Instance B.
3. Linearization of consumption racing with revocation under concurrent thread contention.
4. Monotonic fencing: stale fencing tokens rejected after newer token is issued for scope.
5. Delayed operation carrying stale fencing token rejected at FencedResource boundary with atomic operation execution.
6. Downstream resource lacking fencing cannot protect against delayed execution (documented boundary limit).
7. Backend failure fail-closed: unwriteable/corrupt backend fails closed and never authorizes.
8. Process restart/reconstruction: state remains consumed or revoked across independent instances.
9. Multi-process concurrency: independent processes allocating fencing tokens, issuing capabilities, and competing for single-use consumption.
10. Atomic resource-side fencing: concurrent delayed operations cannot apply after newer generations have been committed.
"""

import os
import json
import time
import uuid
import pytest
import threading
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


class MockFencedDatabase:
    """
    Mock downstream resource implementing atomic resource-side fencing validation
    and consequential state application inside the resource's atomic boundary.
    Maintains independent high-water marks and state per scope_key.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self.scope_watermarks: dict[str, int] = {}
        self.scope_state: dict[str, list] = {}
        self.operations = []

    def __call__(self, *args, **kwargs):
        return self.validate_and_execute(0, "default_scope", None, *args, **kwargs)

    def validate_and_execute(
        self,
        fencing_token: int,
        scope_key: str,
        operation_payload: dict = None,
        *args,
        **kwargs
    ):
        with self._lock:
            current_hwm = self.scope_watermarks.get(scope_key, 0)
            if fencing_token < current_hwm:
                raise PermissionError(
                    f"Resource boundary violation for {scope_key}: Stale fencing token {fencing_token} < current {current_hwm}"
                )
            self.scope_watermarks[scope_key] = fencing_token
            # Consequential operation executed inside atomic boundary
            applied_record = {
                "scope_key": scope_key,
                "generation": fencing_token,
                "payload": operation_payload
            }
            if scope_key not in self.scope_state:
                self.scope_state[scope_key] = []
            self.scope_state[scope_key].append(applied_record)
            self.operations.append(applied_record)
            return {"status": "APPLIED", "scope_key": scope_key, "generation": fencing_token, "applied_data": operation_payload}


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


def test_concurrent_consumption_racing_with_revocation(tmp_path):
    """
    Concurrent consumption racing with revocation under thread synchronization:
    Synchronized via threading.Barrier to enter critical section concurrently.
    Verifies that the linearization point in authoritative storage produces strictly valid outcomes:
    - If revocation linearizes first: consumption fails closed (REVOKED).
    - If consumption linearizes first: revocation fails (ALREADY_CONSUMED).
    Never an invalid or unrecorded intermediate state.
    """
    store_path = str(tmp_path / "auth_race.jsonl")
    store = FileAuthorizationStore(store_path=store_path)

    cap = Capability(
        token_id="CONC-RACE-TOKEN",
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

    barrier = threading.Barrier(2)
    results = {}

    def consume_worker():
        barrier.wait()
        results["consume"] = store.consume_capability("CONC-RACE-TOKEN")

    def revoke_worker():
        barrier.wait()
        results["revoke"] = store.revoke_capability("CONC-RACE-TOKEN", reason="race halt")

    t1 = threading.Thread(target=consume_worker)
    t2 = threading.Thread(target=revoke_worker)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    c_ok, c_reason = results["consume"]
    r_ok, r_reason = results["revoke"]

    # Linearization semantics check:
    # Exactly one operation can win the race to commit state transition.
    if c_ok:
        # Consumption won: revocation must report ALREADY_CONSUMED
        assert r_ok is False
        assert "ALREADY_CONSUMED" in r_reason
    else:
        # Revocation won: consumption must report REVOKED
        assert r_ok is True
        assert "REVOKED" in c_reason


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
    cap1_stored = auth.registry.get_capability(cap1.token_id)
    valid, reason, _ = auth.verify_capability(
        token_id=cap1.token_id,
        action_name="mutate",
        target="/database",
        canonical_request_digest=digest,
        executor_id=cap1_stored.executor_id,
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


def test_downstream_resource_fencing_operation_contract(tmp_path):
    """
    Downstream resource operation contract:
    1. Passes authorized operation_payload directly into atomic resource boundary.
    2. Consequential operation is performed and recorded atomically alongside generation update.
    3. Rejects stale delayed operations for the scope.
    4. Independent scopes maintain separate high-water marks and state without cross-scope collision.
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

    payload_a1 = {"balance_delta": +100}
    digest_a1 = boundary.compute_canonical_digest(payload_a1)

    # Operation 1: Gen 1 on task_A
    cap1, _ = auth.evaluate_and_issue_capability("write", "/db/table", digest_a1, executor_id=resource, task_id="task_A")
    res1 = boundary.execute_protected_action(
        action_name="write",
        target="/db/table",
        request_payload=payload_a1,
        authorization_token_id=cap1.token_id,
        authorized_digest=digest_a1,
        authorization_granted=True,
        executor_func=resource
    )
    assert res1["status"] == "SUCCESS"
    assert resource.scope_watermarks[cap1.scope_key] == 1
    assert resource.scope_state[cap1.scope_key][0]["payload"] == payload_a1

    # Operation 2: Gen 2 on task_A
    payload_a2 = {"balance_delta": -50}
    digest_a2 = boundary.compute_canonical_digest(payload_a2)
    cap2, _ = auth.evaluate_and_issue_capability("write", "/db/table", digest_a2, executor_id=resource, task_id="task_A")
    res2 = boundary.execute_protected_action(
        action_name="write",
        target="/db/table",
        request_payload=payload_a2,
        authorization_token_id=cap2.token_id,
        authorized_digest=digest_a2,
        authorization_granted=True,
        executor_func=resource
    )
    assert res2["status"] == "SUCCESS"
    assert resource.scope_watermarks[cap2.scope_key] == 2
    assert resource.scope_state[cap2.scope_key][1]["payload"] == payload_a2

    # Delayed execution attempt: stale token (Gen 1) targeting task_A scope is rejected
    with pytest.raises(PermissionError, match="Stale fencing token 1 < current 2"):
        resource.validate_and_execute(1, cap1.scope_key, {"balance_delta": +999})

    # Independent scope isolation test: task_B targeting same resource receives Gen 1 and executes without interference
    payload_b = {"balance_delta": +500}
    digest_b = boundary.compute_canonical_digest(payload_b)
    cap3, _ = auth.evaluate_and_issue_capability("write", "/db/table", digest_b, executor_id=resource, task_id="task_B")
    assert cap3.fencing_token == 1
    assert cap3.scope_key != cap1.scope_key
    res3 = boundary.execute_protected_action(
        action_name="write",
        target="/db/table",
        request_payload=payload_b,
        authorization_token_id=cap3.token_id,
        authorized_digest=digest_b,
        authorization_granted=True,
        executor_func=resource
    )
    assert res3["status"] == "SUCCESS"
    assert resource.scope_watermarks[cap3.scope_key] == 1
    assert resource.scope_state[cap3.scope_key][0]["payload"] == payload_b


def test_concurrent_competing_delayed_resource_operations():
    """
    Atomic resource-side fencing: once generation 2 has been accepted by the resource,
    a delayed generation-1 operation must never execute, regardless of thread interleaving.

    Deterministic Ordering:
    1. Commit generation 2 to the resource.
    2. Release a delayed generation-1 operation from a barrier.
    3. Assert it raises PermissionError.
    4. Assert the resource's operation history contains no generation-1 operation after generation 2.
    """
    resource = MockFencedDatabase()
    scope = "task:concurrent_ops|target::/shared_db"

    # 1. Commit generation 2 to the resource
    res_gen2 = resource.validate_and_execute(2, scope, {"data": "authoritative_op_gen2"})
    assert res_gen2["status"] == "APPLIED"
    assert resource.scope_watermarks[scope] == 2

    # 2. Coordinate release of a delayed generation-1 worker thread via barrier
    barrier = threading.Barrier(2)
    delayed_results = {}

    def delayed_op_worker():
        barrier.wait()
        try:
            delayed_results["result"] = resource.validate_and_execute(1, scope, {"data": "stale_delayed_op_gen1"})
        except Exception as e:
            delayed_results["error"] = e

    delayed_thread = threading.Thread(target=delayed_op_worker)
    delayed_thread.start()

    # Release worker from barrier
    barrier.wait()
    delayed_thread.join(timeout=5)

    # 3. Assert it raises PermissionError with Stale fencing token message
    assert "error" in delayed_results
    assert isinstance(delayed_results["error"], PermissionError)
    assert "Stale fencing token 1 < current 2" in str(delayed_results["error"])

    # 4. Assert the resource operation history contains strictly the gen 2 operation, and no gen 1 operation
    applied_generations = [op["generation"] for op in resource.operations if op["scope_key"] == scope]
    assert applied_generations == [2]
    applied_state_gens = [st["generation"] for st in resource.scope_state.get(scope, [])]
    assert applied_state_gens == [2]


def test_unfenced_resource_demonstrates_documented_limitation():
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

    with pytest.raises(RuntimeError, match="Corrupted or ambiguous authorization journal"):
        FileAuthorizationStore(store_path=str(store_file), fail_closed=True)


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
        f.write('{"type": "ISSUE_CAPABILITY", "token_id": "PARTIAL_TRUNCATED_RECORD", "scope_key": "task:crash|target::/res"')

    # Reopening after crash with truncated journal MUST fail closed
    with pytest.raises(RuntimeError, match="Corrupted or ambiguous authorization journal"):
        FileAuthorizationStore(store_path=store_path, fail_closed=True)


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


def _worker_concurrent_issuance(store_path: str, signing_secret: bytes, barrier, results_queue, num_ops: int):
    """Worker process issuing capabilities concurrently under process barrier synchronization."""
    store = FileAuthorizationStore(store_path=store_path)
    reg = CapabilityRegistry(signing_secret=signing_secret, storage_backend=store)
    auth = AuthorizationAuthority(registry=reg, default_policy=Policy(policy_id="p", allowed_operations={"op"}, allowed_resources={"/res"}))
    barrier.wait()
    for i in range(num_ops):
        cap, _ = auth.evaluate_and_issue_capability("op", "/res", f"digest_{os.getpid()}_{i}", task_id="multi_proc_task")
        if cap:
            results_queue.put((cap.token_id, cap.fencing_token))


def test_cross_process_concurrent_capability_issuance(tmp_path):
    """
    Two independent processes sharing a FileAuthorizationStore issue capabilities concurrently for the same scope.
    Uses multiprocessing.Barrier for synchronized entry.
    Verifies that all issued capabilities receive strictly unique, monotonically increasing generations
    and all registered capabilities are persisted without corruption.
    """
    store_path = str(tmp_path / "concurrent_issuance.jsonl")
    _ = FileAuthorizationStore(store_path=store_path)
    signing_secret = b"CONCURRENT_SIGNING_SECRET_12345"

    barrier = multiprocessing.Barrier(2)
    queue = multiprocessing.Queue()
    num_per_worker = 5

    p1 = multiprocessing.Process(target=_worker_concurrent_issuance, args=(store_path, signing_secret, barrier, queue, num_per_worker))
    p2 = multiprocessing.Process(target=_worker_concurrent_issuance, args=(store_path, signing_secret, barrier, queue, num_per_worker))

    p1.start()
    p2.start()

    issued = [queue.get() for _ in range(num_per_worker * 2)]
    p1.join(timeout=10)
    p2.join(timeout=10)

    assert p1.exitcode == 0
    assert p2.exitcode == 0

    tokens = [tok for tok, fence in issued]
    fences = [fence for tok, fence in issued]

    assert len(set(tokens)) == num_per_worker * 2
    assert sorted(fences) == list(range(1, (num_per_worker * 2) + 1))


def _worker_compete_consumption(store_path: str, token_id: str, barrier, results_queue):
    """Worker process attempting to consume a single-use token under barrier synchronization."""
    store = FileAuthorizationStore(store_path=store_path)
    barrier.wait()
    ok, reason = store.consume_capability(token_id)
    results_queue.put((ok, reason))


def test_cross_process_concurrent_consumption_race(tmp_path):
    """
    Two independent processes race to consume the same capability simultaneously under Barrier synchronization.
    Asserts that exactly one succeeds and one receives ALREADY_CONSUMED.
    """
    store_path = str(tmp_path / "compete_consume.jsonl")
    store = FileAuthorizationStore(store_path=store_path)
    reg = CapabilityRegistry(storage_backend=store)
    auth = AuthorizationAuthority(registry=reg, default_policy=Policy(policy_id="p", allowed_operations={"op"}, allowed_resources={"/res"}))

    cap, _ = auth.evaluate_and_issue_capability("op", "/res", "d_race")
    assert cap is not None

    barrier = multiprocessing.Barrier(2)
    queue = multiprocessing.Queue()
    p1 = multiprocessing.Process(target=_worker_compete_consumption, args=(store_path, cap.token_id, barrier, queue))
    p2 = multiprocessing.Process(target=_worker_compete_consumption, args=(store_path, cap.token_id, barrier, queue))

    p1.start()
    p2.start()

    outcomes = [queue.get() for _ in range(2)]
    p1.join(timeout=10)
    p2.join(timeout=10)

    assert p1.exitcode == 0
    assert p2.exitcode == 0

    successes = [ok for ok, r in outcomes if ok is True]
    failures = [r for ok, r in outcomes if ok is False]

    assert len(successes) == 1
    assert len(failures) == 1
    assert "ALREADY_CONSUMED" in failures[0]


def test_capability_timestamp_validation_and_fail_closed_expiration():
    """
    Validates that Capability enforces strict numeric validation within signed 64-bit bounds
    on created_at and expires_at during initialization, and fails closed during is_expired().
    """
    base_kwargs = {
        "token_id": "tok-hardening-1",
        "principal_id": "principal_1",
        "correlation_id": "corr_1",
        "request_id": "req_1",
        "action_name": "op",
        "target": "/resource",
        "canonical_request_digest": "digest_123",
        "executor_id": "default_executor",
        "policy_version": "1.0.0",
        "created_at": 1000.0,
        "expires_at": 2000.0,
    }

    # 1. Normal construction and valid expiration evaluation
    cap = Capability(**base_kwargs)
    assert cap.is_expired(current_time=1500.0) is False
    assert cap.is_expired(current_time=2000.0) is True
    assert cap.is_expired(current_time=2500.0) is True

    # 2. Reject non-numeric and boolean types during construction
    for bad_ts in (True, False, "1000.0", None, [], {}):
        with pytest.raises(TypeError, match="must be a numeric timestamp"):
            Capability(**{**base_kwargs, "created_at": bad_ts})
        with pytest.raises(TypeError, match="must be a numeric timestamp"):
            Capability(**{**base_kwargs, "expires_at": bad_ts})

    # 3. Reject non-finite floats during construction
    for bad_float in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError, match="must be a finite number"):
            Capability(**{**base_kwargs, "created_at": bad_float})
        with pytest.raises(ValueError, match="must be a finite number"):
            Capability(**{**base_kwargs, "expires_at": bad_float})

    # 4. Reject signed 64-bit out-of-range integers and floats
    out_of_bounds_ints = [-(1 << 63) - 1, 1 << 63, 10**100]
    for bad_int in out_of_bounds_ints:
        with pytest.raises(ValueError, match="integer overflows signed 64-bit limits"):
            Capability(**{**base_kwargs, "created_at": bad_int})
        with pytest.raises(ValueError, match="integer overflows signed 64-bit limits"):
            Capability(**{**base_kwargs, "expires_at": bad_int})

    out_of_bounds_floats = [float(-(1 << 63) - 2000), float(1 << 63), 1e100]
    for bad_flt in out_of_bounds_floats:
        with pytest.raises(ValueError, match="float overflows signed 64-bit limits"):
            Capability(**{**base_kwargs, "created_at": bad_flt})
        with pytest.raises(ValueError, match="float overflows signed 64-bit limits"):
            Capability(**{**base_kwargs, "expires_at": bad_flt})

    # 5. Fail-closed expiration evaluation when expires_at is mutated post-construction
    test_cap = Capability(**base_kwargs)
    for bad_val in (float("nan"), float("inf"), float("-inf"), True, False, "invalid", 1 << 63, -(1 << 63) - 1):
        test_cap.expires_at = bad_val
        assert test_cap.is_expired(current_time=1500.0) is True

    # 6. Fail-closed expiration evaluation on invalid current_time clock overrides
    valid_cap = Capability(**base_kwargs)
    for bad_clock in (float("nan"), float("inf"), float("-inf"), True, False, "1500.0", 1 << 63, -(1 << 63) - 1, float(1 << 63)):
        assert valid_cap.is_expired(current_time=bad_clock) is True


def test_human_approval_record_signed_64bit_timestamp_hardening():
    """
    Validates fail-closed timestamp and expiration boundary enforcement on HumanApprovalRecord:
    1. Construction rejects boolean, non-numeric, non-finite floats (NaN, ±Inf), and signed 64-bit overflowing integers/floats.
    2. Construction parses and validates valid string timestamps within bounds.
    3. is_expired() and verify_signature() fail closed when expires_at is mutated post-construction or clock overrides are invalid/out-of-bounds.
    4. from_input() rejects non-finite or out-of-bounds expires_at.
    """
    secret = b"test-secret-key-32-bytes-long!!"
    base_kwargs = {
        "approval_id": "app-test-hardened-1",
        "approver_id": "admin_alice",
        "action_name": "database:drop_table",
        "target": "prod_db",
        "action_digest": "sha256_dummy_digest",
        "request_id": "req-999",
        "expires_at": 2000.0,
    }

    # 1. Normal construction and valid expiration evaluation
    app_rec = HumanApprovalRecord(**base_kwargs)
    app_rec.sign(secret)
    assert app_rec.is_expired(current_time=1500.0) is False
    assert app_rec.verify_signature(secret, current_time=1500.0) is True
    assert app_rec.is_expired(current_time=2000.0) is True
    assert app_rec.verify_signature(secret, current_time=2000.0) is False
    assert app_rec.is_expired(current_time=2500.0) is True
    assert app_rec.verify_signature(secret, current_time=2500.0) is False

    # 2. Reject boolean types during construction
    for bad_ts in (True, False):
        with pytest.raises(TypeError, match="must be a numeric timestamp"):
            HumanApprovalRecord(**{**base_kwargs, "expires_at": bad_ts})

    # 3. Reject non-finite floats during construction
    for bad_float in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError, match="must be a finite number"):
            HumanApprovalRecord(**{**base_kwargs, "expires_at": bad_float})

    # 4. Reject unparseable strings during construction
    with pytest.raises(ValueError, match="cannot be parsed as a float"):
        HumanApprovalRecord(**{**base_kwargs, "expires_at": "not-a-number"})

    # 5. Reject signed 64-bit out-of-range integers and floats
    out_of_bounds_ints = [-(1 << 63) - 1, 1 << 63, 10**100]
    for bad_int in out_of_bounds_ints:
        with pytest.raises(ValueError, match="integer overflows signed 64-bit limits"):
            HumanApprovalRecord(**{**base_kwargs, "expires_at": bad_int})

    out_of_bounds_floats = [float(-(1 << 63) - 2000), float(1 << 63), 1e100]
    for bad_flt in out_of_bounds_floats:
        with pytest.raises(ValueError, match="float overflows signed 64-bit limits"):
            HumanApprovalRecord(**{**base_kwargs, "expires_at": bad_flt})

    # 6. Fail-closed expiration evaluation when expires_at is mutated post-construction
    test_rec = HumanApprovalRecord(**base_kwargs)
    test_rec.sign(secret)
    for bad_val in (float("nan"), float("inf"), float("-inf"), True, False, "invalid", 1 << 63, -(1 << 63) - 1):
        test_rec.expires_at = bad_val
        assert test_rec.is_expired(current_time=1500.0) is True
        assert test_rec.verify_signature(secret, current_time=1500.0) is False

    # 7. Fail-closed expiration evaluation on invalid current_time clock overrides
    valid_rec = HumanApprovalRecord(**base_kwargs)
    valid_rec.sign(secret)
    for bad_clock in (float("nan"), float("inf"), float("-inf"), True, False, "1500.0", 1 << 63, -(1 << 63) - 1, float(1 << 63)):
        assert valid_rec.is_expired(current_time=bad_clock) is True
        assert valid_rec.verify_signature(secret, current_time=bad_clock) is False

    # 8. Unexpired record with expires_at=None also fails closed on invalid clock overrides
    no_exp_rec = HumanApprovalRecord(**{**base_kwargs, "expires_at": None})
    no_exp_rec.sign(secret)
    assert no_exp_rec.is_expired() is False
    assert no_exp_rec.verify_signature(secret) is True
    for bad_clock in (float("nan"), float("inf"), float("-inf"), True, False, "1500.0", 1 << 63, -(1 << 63) - 1):
        assert no_exp_rec.is_expired(current_time=bad_clock) is True
        assert no_exp_rec.verify_signature(secret, current_time=bad_clock) is False

    # 9. HumanApprovalRecord.from_input rejects out-of-bounds or non-finite values
    dict_payload = {
        "approval_id": "app-from-input",
        "approver_id": "admin",
        "action_name": "op",
        "target": "tgt",
        "action_digest": "dig",
        "request_id": "req-1",
    }
    assert HumanApprovalRecord.from_input({**dict_payload, "expires_at": float("inf")}) is None
    assert HumanApprovalRecord.from_input({**dict_payload, "expires_at": float("nan")}) is None
    assert HumanApprovalRecord.from_input({**dict_payload, "expires_at": 1 << 63}) is None
    assert HumanApprovalRecord.from_input({**dict_payload, "expires_at": True}) is None
    valid_parsed = HumanApprovalRecord.from_input({**dict_payload, "expires_at": 2000.0})
    assert valid_parsed is not None
    assert valid_parsed.expires_at == 2000.0


def test_capability_consumption_and_historical_verification_temporal_validation(tmp_path):
    """
    Verifies fail-closed temporal validation in consume_token_and_record_dispatch and verify_historical_capability
    against non-finite floats, booleans, out-of-range bounds, and expired timestamps.
    """
    store_path = str(tmp_path / "auth_store.jsonl")
    denial_log = str(tmp_path / "denial.jsonl")
    backend = FileAuthorizationStore(store_path)
    registry = CapabilityRegistry(storage_backend=backend, denial_log_path=denial_log)
    authority = AuthorizationAuthority(registry=registry)

    # Issue a valid capability with expires_at = 1000.0
    cap = Capability(
        token_id="token-temporal-test-1",
        principal_id="principal-1",
        correlation_id="corr-1",
        request_id="req-1",
        action_name="read_secret",
        target="db/secrets",
        canonical_request_digest="digest-1234",
        executor_id="exec-1",
        policy_version="1.0.0",
        created_at=500.0,
        expires_at=1000.0,
    )
    authority.registry.register_capability(cap)

    # 1. consume_token_and_record_dispatch with non-numeric, boolean, non-finite, out-of-bounds, or expired started_at
    bad_started_ats = [
        float("nan"),
        float("inf"),
        float("-inf"),
        True,
        False,
        "500.0",
        1 << 63,
        -(1 << 63) - 1,
        1000.0,  # started_at == expires_at is expired
        1500.0,  # started_at > expires_at is expired
    ]
    for idx, bad_ts in enumerate(bad_started_ats):
        attempt_id = f"attempt-bad-{idx}"
        ok, reason, _ = authority.registry.consume_token_and_record_dispatch(
            token_id="token-temporal-test-1",
            attempt_id=attempt_id,
            dispatched_executor_id="exec-1",
            started_at=bad_ts,
        )
        assert ok is False
        assert reason == "CAPABILITY_CONSUMPTION_FAILED_EXPIRED_TOKEN"

    # Token must not have been consumed by the failed attempts
    assert authority.registry.is_consumed("token-temporal-test-1") is False

    # 2. consume_token_and_record_dispatch succeeds with valid finite started_at < expires_at
    ok, reason, rec = authority.registry.consume_token_and_record_dispatch(
        token_id="token-temporal-test-1",
        attempt_id="attempt-good-1",
        dispatched_executor_id="exec-1",
        started_at=750.0,
        dispatch_metadata={"principal_id": "principal-1"},
    )
    assert ok is True
    assert authority.registry.is_consumed("token-temporal-test-1") is True

    # 3. verify_historical_capability with non-numeric, boolean, non-finite, out-of-bounds, or expired execution_start_time
    for bad_exec_time in bad_started_ats:
        valid, reason, _, _ = authority.verify_historical_capability(
            token_id="token-temporal-test-1",
            action_name="read_secret",
            target="db/secrets",
            canonical_request_digest="digest-1234",
            execution_attempt_id="attempt-good-1",
            dispatched_executor_id="exec-1",
            execution_start_time=bad_exec_time,
            principal_id="principal-1",
        )
        assert valid is False
        assert "HISTORICAL_VERIFICATION_FAILED_EXPIRED_BEFORE_EXECUTION" in reason

    # 4. verify_historical_capability succeeds with valid execution_start_time < expires_at
    valid, reason, _, _ = authority.verify_historical_capability(
        token_id="token-temporal-test-1",
        action_name="read_secret",
        target="db/secrets",
        canonical_request_digest="digest-1234",
        execution_attempt_id="attempt-good-1",
        dispatched_executor_id="exec-1",
        execution_start_time=750.0,
        principal_id="principal-1",
    )
    assert valid is True
    assert reason == "HISTORICAL_CAPABILITY_VERIFIED"
