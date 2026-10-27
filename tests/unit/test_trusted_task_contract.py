"""
Unit, Adversarial, and Security Invariant Tests for EpistemicOS TrustedTaskContract.
Verifies contract integrity, prohibition precedence, approval binding, denial preservation,
delegation isolation, success evidence requirements, and audit trail reconciliation.
"""

import os
import time
import uuid
import pytest
from typing import Dict, Any, List

import epistemicos.provenance
from epistemicos.authorization import (
    TrustedTaskContract,
    AuthorizationAuthority,
    CapabilityRegistry,
    Policy,
    HumanApprovalRecord
)
from epistemicos.provenance import (
    TrustedExecutionBoundary,
    LocalProvenanceStore,
    ExecutionContext,
    ProvenanceReconciler,
    ProvenanceEventType,
    ProvenanceSource,
    ProvenanceEvent
)
from epistemicos.core import EpistemicOrchestrator


def dummy_executor():
    return {"status": "ok", "evidence_key": "valid_proof_123"}


def bad_executor():
    return {"status": "ok", "wrong_key": "no_proof"}


def test_contract_integrity_and_signature():
    secret = b"trusted_contract_signing_secret_32b"
    contract = TrustedTaskContract(
        task_id="TASK-INT-01",
        contract_version="1.0.0",
        permitted_actions={"local_read", "execute_cmd"},
        resource_scope={"/tmp/allowed"},
        explicit_prohibitions={"delete_file"},
        prohibited_resources={"/etc/shadow"}
    )
    sig = contract.sign(secret)
    assert sig is not None
    assert contract.verify_signature(secret) is True

    # Tamper with contract action
    contract.permitted_actions.add("admin_shell")
    assert contract.verify_signature(secret) is False


def test_contract_signature_verification_enforced_in_authority():
    authority = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"})
    )

    contract = TrustedTaskContract(
        task_id="TASK-AUTH-SIG",
        permitted_actions={"read_table"},
        resource_scope={"/db/users"}
    )

    # 1. Unsigned contract fails
    cap1, reason1 = authority.evaluate_and_issue_capability(
        action_name="read_table",
        target="/db/users",
        canonical_request_digest="dig1",
        task_contract=contract
    )
    assert cap1 is None
    assert reason1 == "AUTHORIZATION_DENIED_CONTRACT_SIGNATURE_INVALID"

    # 2. Forged signature fails
    contract.sign(b"wrong_untrusted_secret")
    cap2, reason2 = authority.evaluate_and_issue_capability(
        action_name="read_table",
        target="/db/users",
        canonical_request_digest="dig1",
        task_contract=contract
    )
    assert cap2 is None
    assert reason2 == "AUTHORIZATION_DENIED_CONTRACT_SIGNATURE_INVALID"

    # 3. Validly signed contract succeeds
    contract.sign(authority.contract_signing_secret)
    cap3, reason3 = authority.evaluate_and_issue_capability(
        action_name="read_table",
        target="/db/users",
        canonical_request_digest="dig1",
        task_contract=contract
    )
    assert cap3 is not None
    assert reason3 == "AUTHORIZATION_GRANTED"


def test_explicit_prohibition_precedence_over_broad_permissions():
    authority = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"})
    )

    contract = TrustedTaskContract(
        task_id="TASK-PROHIB-01",
        permitted_actions={"*"},
        resource_scope={"*"},
        explicit_prohibitions={"delete_database"},
        prohibited_resources={"/db/production"}
    )
    contract.sign(authority.contract_signing_secret)

    # Permitted action allowed
    cap, reason = authority.evaluate_and_issue_capability(
        action_name="read_table",
        target="/db/users",
        canonical_request_digest="dig1",
        task_contract=contract
    )
    assert cap is not None
    assert reason == "AUTHORIZATION_GRANTED"

    # Explicitly prohibited action denied despite broad permissions
    contract_p1 = TrustedTaskContract(
        task_id="TASK-PROHIB-01",
        permitted_actions={"*"},
        resource_scope={"*"},
        explicit_prohibitions={"delete_database"},
        prohibited_resources={"/db/production"}
    )
    contract_p1.sign(authority.contract_signing_secret)

    cap2, reason2 = authority.evaluate_and_issue_capability(
        action_name="delete_database",
        target="/db/users",
        canonical_request_digest="dig2",
        task_contract=contract_p1
    )
    assert cap2 is None
    assert "CONTRACT_EXPLICIT_PROHIBITION" in reason2

    # Prohibited resource denied
    contract_p2 = TrustedTaskContract(
        task_id="TASK-PROHIB-01",
        permitted_actions={"*"},
        resource_scope={"*"},
        explicit_prohibitions={"delete_database"},
        prohibited_resources={"/db/production"}
    )
    contract_p2.sign(authority.contract_signing_secret)

    cap3, reason3 = authority.evaluate_and_issue_capability(
        action_name="read_table",
        target="/db/production",
        canonical_request_digest="dig3",
        task_contract=contract_p2
    )
    assert cap3 is None
    assert "CONTRACT_EXPLICIT_PROHIBITION" in reason3


def test_durable_denial_preservation_across_retries_and_routes(tmp_path):
    log_file = tmp_path / "prov.jsonl"
    denial_log = tmp_path / "denials.jsonl"
    store = LocalProvenanceStore(log_path=str(log_file))
    registry = CapabilityRegistry(denial_log_path=str(denial_log))
    authority = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"local_read"}, allowed_resources={"/app/data"}),
        registry=registry
    )

    contract = TrustedTaskContract(
        task_id="TASK-DENIAL-01",
        permitted_actions={"local_read"},
        resource_scope={"/app/data"}
    )
    contract.sign(authority.contract_signing_secret)

    # Initial attempt for forbidden operation 'write_file' -> DENIED by contract scope check and recorded
    cap1, reason1 = authority.evaluate_and_issue_capability(
        action_name="write_file",
        target="/app/data",
        canonical_request_digest="digest_1",
        task_contract=contract
    )
    assert cap1 is None
    assert "CONTRACT_SCOPE_VIOLATION" in reason1

    # Now, present a newly signed contract for the SAME task_id that permits 'write_file'.
    # Because TASK-DENIAL-01 had a denial recorded under this task_id, action, and target,
    # the durable denial registry MUST actively block the retry!
    contract_permissive = TrustedTaskContract(
        task_id="TASK-DENIAL-01",
        permitted_actions={"local_read", "write_file"},
        resource_scope={"/app/data"}
    )
    contract_permissive.sign(authority.contract_signing_secret)

    cap2, reason2 = authority.evaluate_and_issue_capability(
        action_name="write_file",
        target="/app/data",
        canonical_request_digest="digest_alt_route",
        task_contract=contract_permissive
    )
    assert cap2 is None
    assert "DURABLE_DENIAL_ACTIVE" in reason2


def test_denial_persistence_failure_handling(tmp_path):
    unwritable_path = tmp_path / "non_existent_dir" / "readonly" / "denial.jsonl"
    registry = CapabilityRegistry(denial_log_path=str(unwritable_path), fail_closed_persistence=True)

    # Create invalid directory to trigger write failure
    os.makedirs(tmp_path / "non_existent_dir", mode=0o444, exist_ok=True)

    with pytest.raises(RuntimeError) as exc_info:
        registry.record_denial("TASK-FAIL-PERSIST", "delete", "/path", "Forbidden")
    assert "Denial persistence failure" in str(exc_info.value) or "Lock registry failure" in str(exc_info.value)


def test_denial_continuity_across_version_updates_and_explicit_reauthorization(tmp_path):
    denial_log = tmp_path / "denials_ver.jsonl"
    registry = CapabilityRegistry(denial_log_path=str(denial_log))
    authority = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"}),
        registry=registry
    )

    contract_v1 = TrustedTaskContract(
        task_id="TASK-VER-01",
        contract_version="1.0.0",
        explicit_prohibitions={"mutate_state"}
    )
    contract_v1.sign(authority.contract_signing_secret)

    # Initial attempt -> DENIED
    cap1, reason1 = authority.evaluate_and_issue_capability(
        action_name="mutate_state",
        target="/state",
        canonical_request_digest="dig1",
        task_contract=contract_v1
    )
    assert cap1 is None
    assert "CONTRACT_EXPLICIT_PROHIBITION" in reason1

    # Retry under updated contract_version '2.0.0' without reauthorization -> STILL DENIED
    contract_v2 = TrustedTaskContract(
        task_id="TASK-VER-01",
        contract_version="2.0.0",
        permitted_actions={"mutate_state"},
        resource_scope={"/state"}
    )
    contract_v2.sign(authority.contract_signing_secret)

    cap2, reason2 = authority.evaluate_and_issue_capability(
        action_name="mutate_state",
        target="/state",
        canonical_request_digest="dig2",
        task_contract=contract_v2
    )
    assert cap2 is None
    assert "DURABLE_DENIAL_ACTIVE" in reason2

    # 1. Ordinary action approval cannot clear denial
    ordinary_app = HumanApprovalRecord(
        approval_id="APP-ORD-01",
        approver_id="security_admin",
        action_name="mutate_state",
        target="/state",
        action_digest="dig3",
        request_id="REQ-CLEAR-01",
        task_id="TASK-VER-01"
    )
    ordinary_app.sign(authority.approval_signing_secret)

    cleared_ord, msg_ord = authority.clear_denial_with_approval("TASK-VER-01", "mutate_state", "/state", ordinary_app)
    assert cleared_ord is False
    assert "cannot be repurposed" in msg_ord

    # 2. Unsigned clearance approval fails
    clearance_app = HumanApprovalRecord(
        approval_id="APP-CLEAR-01",
        approver_id="security_admin",
        action_name="CLEAR_DENIAL:mutate_state",
        target="/state",
        action_digest="dig3",
        request_id="REQ-CLEAR-01",
        task_id="TASK-VER-01"
    )
    cleared_unsigned, msg_unsigned = authority.clear_denial_with_approval("TASK-VER-01", "mutate_state", "/state", clearance_app)
    assert cleared_unsigned is False
    assert "verification failed" in msg_unsigned

    # 3. Forged clearance signature fails
    clearance_app.sign(b"wrong_secret")
    cleared_forged, msg_forged = authority.clear_denial_with_approval("TASK-VER-01", "mutate_state", "/state", clearance_app)
    assert cleared_forged is False
    assert "verification failed" in msg_forged

    # 4. Properly signed clearance approval succeeds!
    clearance_app.sign(authority.approval_signing_secret)
    cleared, msg_success = authority.clear_denial_with_approval("TASK-VER-01", "mutate_state", "/state", clearance_app)
    assert cleared is True
    assert "successfully cleared" in msg_success

    # 5. Replaying the clearance approval fails
    cleared_replay, msg_replay = authority.clear_denial_with_approval("TASK-VER-01", "mutate_state", "/state", clearance_app)
    assert cleared_replay is False
    assert "already consumed" in msg_replay

    # Retry after explicit reauthorization -> GRANTED
    action_app = HumanApprovalRecord(
        approval_id="APP-ACTION-01",
        approver_id="security_admin",
        action_name="mutate_state",
        target="/state",
        action_digest="dig3",
        request_id="REQ-MUT-01"
    )
    action_app.sign(authority.approval_signing_secret)
    cap3, reason3 = authority.evaluate_and_issue_capability(
        action_name="mutate_state",
        target="/state",
        canonical_request_digest="dig3",
        request_id="REQ-MUT-01",
        task_contract=contract_v2,
        human_approval_input=action_app
    )
    assert cap3 is not None
    assert reason3 == "AUTHORIZATION_GRANTED"


def test_multi_instance_denial_synchronization(tmp_path):
    denial_log = tmp_path / "shared_denials.jsonl"
    registry_a = CapabilityRegistry(denial_log_path=str(denial_log))
    registry_b = CapabilityRegistry(denial_log_path=str(denial_log))

    # Instance A records denial
    registry_a.record_denial("TASK-SHARED-1", "drop_db", "/prod", "Prohibited by A")

    # Instance B queries denial -> must re-sync from shared persistent log and detect ACTIVE denial!
    is_denied, record = registry_b.check_denial("TASK-SHARED-1", "drop_db", "/prod")
    assert is_denied is True
    assert record["reason"] == "Prohibited by A"


def test_corrupted_denial_log_line_fails_closed(tmp_path):
    denial_log = tmp_path / "corrupted_denials.jsonl"
    with open(denial_log, "w", encoding="utf-8") as f:
        f.write('{"task_id": "T1", "action_name": "op", "target": "/res", "status": "ACTIVE"}\n')
        f.write('INVALID_CORRUPTED_JSON_LINE\n')

    with pytest.raises(RuntimeError) as exc_info:
        CapabilityRegistry(denial_log_path=str(denial_log), fail_closed_persistence=True)
    assert "Failed to load persistent denial log" in str(exc_info.value) or "Failed to parse" in str(exc_info.value)


def test_clearance_approval_replay_prevention_preserved_on_persistent_reload(tmp_path):
    denial_log = tmp_path / "clearance_reload.jsonl"
    registry1 = CapabilityRegistry(denial_log_path=str(denial_log))
    authority = AuthorizationAuthority(registry=registry1)

    registry1.record_denial("TASK-RELOAD-1", "write_file", "/target", "Initial denial")

    clearance_app = HumanApprovalRecord(
        approval_id="APP-CLEAR-RELOAD",
        approver_id="security_admin",
        action_name="CLEAR_DENIAL:write_file",
        target="/target",
        action_digest="dig1",
        request_id="REQ-CLEAR-01",
        task_id="TASK-RELOAD-1"
    )
    clearance_app.sign(authority.approval_signing_secret)

    cleared, _ = authority.clear_denial_with_approval("TASK-RELOAD-1", "write_file", "/target", clearance_app)
    assert cleared is True

    # Now instantiate a NEW registry instance reading the same persistent log
    registry2 = CapabilityRegistry(denial_log_path=str(denial_log))
    authority2 = AuthorizationAuthority(registry=registry2)

    # Attempting to reuse the consumed clearance approval in registry2 MUST fail due to replay prevention!
    cleared_again, msg = registry2.clear_denial_with_approval(
        task_id="TASK-RELOAD-1",
        action_name="write_file",
        target="/target",
        reauthorization_record=clearance_app,
        signing_secret=authority.approval_signing_secret
    )
    assert cleared_again is False
    assert "already consumed" in msg


def test_clearance_approval_mismatched_target_rejected(tmp_path):
    denial_log = tmp_path / "clearance_target.jsonl"
    registry = CapabilityRegistry(denial_log_path=str(denial_log))
    authority = AuthorizationAuthority(registry=registry)

    registry.record_denial("TASK-TARGET-1", "drop_db", "/prod_db", "Prohibited target")

    # Clearance approval issued for /dev_db instead of /prod_db
    clearance_app = HumanApprovalRecord(
        approval_id="APP-CLEAR-TARGET",
        approver_id="security_admin",
        action_name="CLEAR_DENIAL",
        target="/dev_db",
        action_digest="dig1",
        request_id="REQ-CLEAR-02",
        task_id="TASK-TARGET-1"
    )
    clearance_app.sign(authority.approval_signing_secret)

    cleared, msg = authority.clear_denial_with_approval("TASK-TARGET-1", "drop_db", "/prod_db", clearance_app)
    assert cleared is False
    assert "does not match" in msg


def test_clearance_approval_mismatched_task_id_rejected(tmp_path):
    denial_log = tmp_path / "clearance_taskid.jsonl"
    registry = CapabilityRegistry(denial_log_path=str(denial_log))
    authority = AuthorizationAuthority(registry=registry)

    registry.record_denial("TASK-ORIGINAL-01", "write_file", "/target", "Initial denial")

    # Clearance approval explicitly bound to TASK-OTHER-02
    clearance_app = HumanApprovalRecord(
        approval_id="APP-CLEAR-TASK-DIFF",
        approver_id="security_admin",
        action_name="CLEAR_DENIAL:write_file",
        target="/target",
        action_digest="dig1",
        request_id="REQ-CLEAR-03",
        task_id="TASK-OTHER-02"
    )
    clearance_app.sign(authority.approval_signing_secret)

    cleared, msg = authority.clear_denial_with_approval("TASK-ORIGINAL-01", "write_file", "/target", clearance_app)
    assert cleared is False
    assert "task_id mismatch" in msg


def test_clearance_approval_missing_task_id_rejected(tmp_path):
    denial_log = tmp_path / "clearance_no_taskid.jsonl"
    registry = CapabilityRegistry(denial_log_path=str(denial_log))
    authority = AuthorizationAuthority(registry=registry)

    registry.record_denial("TASK-NEED-ID", "write_file", "/target", "Initial denial")

    # Clearance approval without task_id
    clearance_app = HumanApprovalRecord(
        approval_id="APP-CLEAR-NO-TASKID",
        approver_id="security_admin",
        action_name="CLEAR_DENIAL:write_file",
        target="/target",
        action_digest="dig1",
        request_id="REQ-CLEAR-04",
        task_id=None
    )
    clearance_app.sign(authority.approval_signing_secret)

    cleared, msg = authority.clear_denial_with_approval("TASK-NEED-ID", "write_file", "/target", clearance_app)
    assert cleared is False
    assert "missing required task_id" in msg


def test_unsupported_fcntl_fails_closed(tmp_path):
    denial_log = tmp_path / "nofcntl_denials.jsonl"
    from unittest.mock import patch
    with patch.dict("sys.modules", {"fcntl": None}):
        registry = CapabilityRegistry(denial_log_path=str(denial_log), fail_closed_persistence=True)
        with pytest.raises(RuntimeError) as exc_info:
            with registry.lock_registry():
                pass
        assert "unsupported on this operating system" in str(exc_info.value)


def test_concurrent_authorization_and_clearance_no_deadlock(tmp_path):
    import concurrent.futures
    denial_log = tmp_path / "concurrent_auth.jsonl"
    registry = CapabilityRegistry(denial_log_path=str(denial_log))
    authority = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"}),
        registry=registry
    )

    contract = TrustedTaskContract(task_id="TASK-CONCUR-01", permitted_actions={"read_data"}, resource_scope={"/data"})
    contract.sign(authority.contract_signing_secret)

    def worker_auth(i: int):
        cap, reason = authority.evaluate_and_issue_capability(
            action_name="read_data",
            target="/data",
            canonical_request_digest=f"dig_{i}",
            task_contract=contract,
            task_id="TASK-CONCUR-01"
        )
        return cap, reason

    # Submit 20 concurrent authorization tasks to worker pool with timeout = 5 seconds to assert zero deadlock
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(worker_auth, i) for i in range(20)]
        results = [f.result(timeout=5.0) for f in futures]

    assert len(results) == 20
    for cap, reason in results:
        assert cap is not None
        assert reason == "AUTHORIZATION_GRANTED"


def _proc_record_denial(log_path, result_queue):
    try:
        reg = CapabilityRegistry(denial_log_path=log_path)
        reg.record_denial("TASK-MP-01", "write_file", "/target", "Denial by process B")
        result_queue.put(("SUCCESS", None))
    except Exception as e:
        result_queue.put(("ERROR", str(e)))


def test_multiprocess_denial_check_and_record_race(tmp_path):
    import multiprocessing
    denial_log = str(tmp_path / "mp_denial_log.jsonl")

    reg_a = CapabilityRegistry(denial_log_path=denial_log)
    authority_a = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"}),
        registry=reg_a
    )

    contract = TrustedTaskContract(task_id="TASK-MP-01", permitted_actions={"write_file"}, resource_scope={"/target"})
    contract.sign(authority_a.contract_signing_secret)

    # Initial check -> allowed
    cap1, _ = authority_a.evaluate_and_issue_capability(
        action_name="write_file", target="/target", canonical_request_digest="d1", task_contract=contract
    )
    assert cap1 is not None

    # Spawn Process B to record denial concurrently
    q = multiprocessing.Queue()
    proc_b = multiprocessing.Process(target=_proc_record_denial, args=(denial_log, q))
    proc_b.start()
    proc_b.join(timeout=5.0)

    status, err = q.get(timeout=2.0)
    assert status == "SUCCESS", f"Process B failed: {err}"

    # Subsequent check by Process A MUST observe Process B's durable denial and fail closed!
    cap2, reason2 = authority_a.evaluate_and_issue_capability(
        action_name="write_file", target="/target", canonical_request_digest="d2", task_contract=contract
    )
    assert cap2 is None
    assert "DURABLE_DENIAL_ACTIVE" in reason2


def _proc_clear_denial(log_path, signing_secret, reauth_dict, result_queue):
    try:
        reg = CapabilityRegistry(denial_log_path=log_path)
        rec = HumanApprovalRecord.from_input(reauth_dict)
        cleared, msg = reg.clear_denial_with_approval(
            task_id="TASK-MP-CLEAR",
            action_name="delete_data",
            target="/database",
            reauthorization_record=rec,
            signing_secret=signing_secret
        )
        result_queue.put((cleared, msg))
    except Exception as e:
        result_queue.put((False, f"EXCEPTION: {str(e)}"))


def test_multiprocess_concurrent_clearance(tmp_path):
    import multiprocessing
    denial_log = str(tmp_path / "mp_clearance_log.jsonl")

    reg_main = CapabilityRegistry(denial_log_path=denial_log)
    authority_main = AuthorizationAuthority(registry=reg_main)

    reg_main.record_denial("TASK-MP-CLEAR", "delete_data", "/database", "Initial denial")

    clearance_app = HumanApprovalRecord(
        approval_id="APP-CLEAR-MP-01",
        approver_id="security_admin",
        action_name="CLEAR_DENIAL:delete_data",
        target="/database",
        action_digest="dig1",
        request_id="REQ-CLEAR-MP",
        task_id="TASK-MP-CLEAR"
    )
    clearance_app.sign(authority_main.approval_signing_secret)
    reauth_dict = clearance_app.to_dict()

    q1 = multiprocessing.Queue()
    q2 = multiprocessing.Queue()

    sec = authority_main.approval_signing_secret

    p1 = multiprocessing.Process(target=_proc_clear_denial, args=(denial_log, sec, reauth_dict, q1))
    p2 = multiprocessing.Process(target=_proc_clear_denial, args=(denial_log, sec, reauth_dict, q2))

    p1.start()
    p2.start()

    p1.join(timeout=5.0)
    p2.join(timeout=5.0)

    res1, msg1 = q1.get(timeout=2.0)
    res2, msg2 = q2.get(timeout=2.0)

    # Exactly ONE process succeeds, the other process fails with replay error!
    assert (res1 is True and res2 is False) or (res1 is False and res2 is True)
    failed_msg = msg2 if res1 is True else msg1
    assert "already consumed" in failed_msg


def _proc_record_and_signal(log_path, event_started, event_done, result_q):
    try:
        event_started.wait(timeout=5.0)
        reg = CapabilityRegistry(denial_log_path=log_path)
        reg.record_denial("TASK-INTERLEAVE-01", "write_file", "/target", "Interleaved denial")
        event_done.set()
        result_q.put(("SUCCESS", None))
    except Exception as e:
        result_q.put(("ERROR", str(e)))


def test_multiprocess_interprocess_lock_serialization(tmp_path):
    import multiprocessing
    denial_log = str(tmp_path / "interleave_denial_log.jsonl")

    reg_a = CapabilityRegistry(denial_log_path=denial_log)
    authority_a = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"}),
        registry=reg_a
    )

    contract = TrustedTaskContract(task_id="TASK-INTERLEAVE-01", permitted_actions={"write_file"}, resource_scope={"/target"})
    contract.sign(authority_a.contract_signing_secret)

    ev_start = multiprocessing.Event()
    ev_done = multiprocessing.Event()
    q = multiprocessing.Queue()

    proc_b = multiprocessing.Process(target=_proc_record_and_signal, args=(denial_log, ev_start, ev_done, q))
    proc_b.start()

    # Process A enters lock_registry() first
    with reg_a.lock_registry():
        ev_start.set()
        # Process B tries to call record_denial() in background, but MUST block because reg_a holds lock_registry()
        time.sleep(0.1)
        assert ev_done.is_set() is False, "Process B should be blocked waiting for lock_registry()"

    # Process A releases lock -> Process B acquires lock and completes write
    proc_b.join(timeout=5.0)
    status_b, err_b = q.get(timeout=2.0)
    assert status_b == "SUCCESS", f"Process B error: {err_b}"
    assert ev_done.is_set() is True

    # Process A's subsequent capability check re-syncs and observes Process B's recorded denial
    cap, reason = authority_a.evaluate_and_issue_capability(
        action_name="write_file", target="/target", canonical_request_digest="d_interleave", task_contract=contract
    )
    assert cap is None
    assert "DURABLE_DENIAL_ACTIVE" in reason


def _proc_record_denial_event(log_path, ev_checked, ev_denied, q):
    try:
        ev_checked.wait(timeout=5.0)
        reg = CapabilityRegistry(denial_log_path=log_path)
        reg.record_denial("TASK-RACE-01", "write_file", "/target", "Denial by process B during pause")
        ev_denied.set()
        q.put(("SUCCESS", None))
    except Exception as e:
        q.put(("ERROR", str(e)))


def test_multiprocess_deterministic_denial_interleaving_race(tmp_path):
    import multiprocessing
    denial_log = str(tmp_path / "race_denial_log.jsonl")

    reg_a = CapabilityRegistry(denial_log_path=denial_log)
    authority_a = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"*"}, allowed_resources={"*"}),
        registry=reg_a
    )

    contract = TrustedTaskContract(task_id="TASK-RACE-01", permitted_actions={"write_file"}, resource_scope={"/target"})
    contract.sign(authority_a.contract_signing_secret)

    event_a_checked = multiprocessing.Event()
    event_b_denied = multiprocessing.Event()
    result_q = multiprocessing.Queue()

    proc_b = multiprocessing.Process(
        target=_proc_record_denial_event,
        args=(denial_log, event_a_checked, event_b_denied, result_q)
    )
    proc_b.start()

    # Pre-issuance hook on Authority A: yields file lock, signals Process B to record denial and waits until B completes
    def hook():
        event_a_checked.set()
        event_b_denied.wait(timeout=5.0)

    authority_a._pre_issuance_hook = hook

    cap, reason = authority_a.evaluate_and_issue_capability(
        action_name="write_file",
        target="/target",
        canonical_request_digest="d_race",
        task_contract=contract,
        task_id="TASK-RACE-01"
    )

    proc_b.join(timeout=5.0)
    status_b, err_b = result_q.get(timeout=2.0)
    assert status_b == "SUCCESS", f"Process B error: {err_b}"

    # Assert Process A was DENIED and NO capability was issued despite starting authorization before Process B recorded denial!
    assert cap is None
    assert "DURABLE_DENIAL_ACTIVE" in reason


def test_rollback_truncation_failure_injection_handling(tmp_path):
    from unittest.mock import patch
    denial_log = str(tmp_path / "trunc_fail.jsonl")
    registry = CapabilityRegistry(denial_log_path=denial_log, fail_closed_persistence=True)

    original_open = open
    def mock_open_with_faulty_truncate(*args, **kwargs):
        f = original_open(*args, **kwargs)
        if len(args) > 1 and "a+" in args[1]:
            def faulty_truncate(pos=None):
                raise OSError("Truncate error")
            f.truncate = faulty_truncate
        return f

    with patch("os.fsync", side_effect=OSError("Disk fsync error")):
        with patch("builtins.open", side_effect=mock_open_with_faulty_truncate):
            with pytest.raises(RuntimeError) as exc:
                registry.record_denial("TASK-TRUNC-FAIL", "write_file", "/target", "Initial denial")
            assert "rollback truncation failure" in str(exc.value)


def test_persistence_failure_injection_write_flush_fsync(tmp_path):
    import io
    from unittest.mock import patch
    denial_log = str(tmp_path / "fail_inj.jsonl")
    registry = CapabilityRegistry(denial_log_path=denial_log, fail_closed_persistence=True)

    # 1. Write failure
    with patch("json.dumps", side_effect=IOError("Write failed")):
        with pytest.raises(RuntimeError) as exc1:
            registry.record_denial("TASK-INJ-1", "write_file", "/target", "Reason")
        assert "Denial persistence failure" in str(exc1.value) or "Write failed" in str(exc1.value)

    # 2. Flush failure
    original_open = open
    def mock_open_with_faulty_flush(*args, **kwargs):
        f = original_open(*args, **kwargs)
        if len(args) > 1 and "a" in args[1]:
            def faulty_flush():
                raise IOError("Flush failed")
            f.flush = faulty_flush
        return f

    with patch("builtins.open", side_effect=mock_open_with_faulty_flush):
        with pytest.raises(RuntimeError) as exc2:
            registry.record_denial("TASK-INJ-2", "write_file", "/target", "Reason")
        assert "Denial persistence failure" in str(exc2.value) or "Flush failed" in str(exc2.value)

    # 3. fsync failure & reloaded registry state reconciliation
    authority = AuthorizationAuthority(registry=registry)
    app = HumanApprovalRecord(
        approval_id="APP-FSYNC-FAIL",
        approver_id="admin",
        action_name="CLEAR_DENIAL:write_file",
        target="/target",
        action_digest="dig",
        request_id="req",
        task_id="TASK-INJ-3"
    )
    app.sign(authority.approval_signing_secret)

    registry.record_denial("TASK-INJ-3", "write_file", "/target", "Initial denial")

    with patch("os.fsync", side_effect=OSError("Disk full fsync error")):
        with pytest.raises(RuntimeError) as exc3:
            registry.clear_denial_with_approval("TASK-INJ-3", "write_file", "/target", app, authority.approval_signing_secret)
        assert "Denial persistence failure" in str(exc3.value) or "Disk full fsync error" in str(exc3.value)

    # Reloaded registry from disk MUST reflect active denial and unconsumed approval
    reloaded_registry = CapabilityRegistry(denial_log_path=denial_log)
    is_denied, record = reloaded_registry.check_denial("TASK-INJ-3", "write_file", "/target")
    assert is_denied is True
    assert reloaded_registry.is_approval_consumed("APP-FSYNC-FAIL") is False


def test_production_configuration_enforcement(monkeypatch):
    monkeypatch.setenv("EPISTEMICOS_ENV", "production")

    # Missing secrets raises ValueError
    with pytest.raises(ValueError) as exc:
        AuthorizationAuthority()
    assert "EPISTEMICOS_APPROVAL_SECRET" in str(exc.value)

    monkeypatch.setenv("EPISTEMICOS_APPROVAL_SECRET", "prod_app_secret_123")
    monkeypatch.setenv("EPISTEMICOS_CONTRACT_SECRET", "prod_contract_secret_123")

    # Explicitly trying to disable task contracts in production mode raises ValueError
    with pytest.raises(ValueError) as exc2:
        AuthorizationAuthority(require_task_contract=False)
    assert "cannot be disabled in production mode" in str(exc2.value)

    # Valid production initialization succeeds
    auth = AuthorizationAuthority()
    assert auth.is_production is True
    assert auth.require_task_contract is True


def test_contract_required_execution_mode():
    authority = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"read"}, allowed_resources={"/data"}),
        require_task_contract=True
    )

    # Calling without task contract fails closed
    cap, reason = authority.evaluate_and_issue_capability(
        action_name="read",
        target="/data",
        canonical_request_digest="dig"
    )
    assert cap is None
    assert reason == "AUTHORIZATION_DENIED_CONTRACT_REQUIRED"


def test_null_and_empty_evidence_validation(tmp_path):
    log_file = tmp_path / "prov_null.jsonl"
    store = LocalProvenanceStore(log_path=str(log_file))
    authority = AuthorizationAuthority(
        default_policy=Policy(policy_id="p1", allowed_operations={"run"}, allowed_resources={"/res"})
    )
    boundary = TrustedExecutionBoundary(provenance_store=store, authority=authority)

    def null_evidence_executor():
        return {"status": "ok", "proof": None}

    def empty_evidence_executor():
        return {"status": "ok", "proof": ""}

    boundary.authority.register_executor("null_exec", null_evidence_executor)
    boundary.authority.register_executor("empty_exec", empty_evidence_executor)

    req_payload = {"cmd": "test"}
    d = boundary.compute_canonical_digest(req_payload)

    corr1 = str(uuid.uuid4())
    cap1, _ = authority.evaluate_and_issue_capability(action_name="run", target="/res", canonical_request_digest=d, executor_id=null_evidence_executor, correlation_id=corr1)
    ctx1 = ExecutionContext(correlation_id=corr1, request_id=cap1.request_id, authorization_token_id=cap1.token_id, authorized_digest=d, required_success_evidence={"proof"})
    res1 = boundary.execute_protected_action(action_name="run", target="/res", request_payload=req_payload, executor_func=null_evidence_executor, context=ctx1)
    assert res1["status"] == "UNVERIFIED_SUCCESS"

    corr2 = str(uuid.uuid4())
    cap2, _ = authority.evaluate_and_issue_capability(action_name="run", target="/res", canonical_request_digest=d, executor_id=empty_evidence_executor, correlation_id=corr2)
    ctx2 = ExecutionContext(correlation_id=corr2, request_id=cap2.request_id, authorization_token_id=cap2.token_id, authorized_digest=d, required_success_evidence={"proof"})
    res2 = boundary.execute_protected_action(action_name="run", target="/res", request_payload=req_payload, executor_func=empty_evidence_executor, context=ctx2)
    assert res2["status"] == "UNVERIFIED_SUCCESS"


def test_end_to_end_adversarial_side_effect_isolation(tmp_path):
    audit_file = tmp_path / "audit_adv.jsonl"
    orchestrator = EpistemicOrchestrator(audit_log_path=str(audit_file))
    orchestrator.authority.require_task_contract = True
    authority = orchestrator.authority
    contract_secret = authority.contract_signing_secret

    side_effect_counter = [0]

    def side_effecting_executor():
        side_effect_counter[0] += 1
        return {"status": "ok", "evidence_key": "valid_proof_999"}

    authority.register_executor("side_effect_exec", side_effecting_executor)
    authority.default_policy = Policy(policy_id="p1", allowed_operations={"consequential_op"}, allowed_resources={"/target"})

    # Attack 1: Omitted contract when required -> Callback NOT executed
    res1 = orchestrator.process_submission(
        raw_payload={"policy_id": "p1"},
        context={"action_name": "consequential_op", "target": "/target", "actual_executable": side_effecting_executor}
    )
    assert res1["status"] == "HALTED"
    assert side_effect_counter[0] == 0

    # Attack 2: Tampered contract signature -> Callback NOT executed
    contract_forged = TrustedTaskContract(task_id="TASK-ADV-1", permitted_actions={"consequential_op"}, resource_scope={"/target"})
    contract_forged.sign(b"forged_key")

    res2 = orchestrator.process_submission(
        raw_payload={"policy_id": "p1"},
        context={"action_name": "consequential_op", "target": "/target", "actual_executable": side_effecting_executor, "task_contract": contract_forged}
    )
    assert res2["status"] == "HALTED"
    assert side_effect_counter[0] == 0

    # Attack 3: Task identity substitution -> Callback NOT executed
    contract_valid = TrustedTaskContract(task_id="TASK-ORIGINAL", permitted_actions={"consequential_op"}, resource_scope={"/target"})
    contract_valid.sign(contract_secret)

    res3 = orchestrator.process_submission(
        raw_payload={"policy_id": "p1"},
        context={"action_name": "consequential_op", "target": "/target", "actual_executable": side_effecting_executor, "task_contract": contract_valid, "task_id": "TASK-SUBSTITUTE"}
    )
    assert res3["status"] == "HALTED"
    assert side_effect_counter[0] == 0

    # Valid execution -> Callback executed exactly ONCE
    contract_valid_e2e = TrustedTaskContract(task_id="TASK-LEGIT", permitted_actions={"consequential_op"}, resource_scope={"/target"}, success_evidence_requirements={"evidence_key"})
    contract_valid_e2e.sign(contract_secret)

    res_valid = orchestrator.process_submission(
        raw_payload={"policy_id": "p1"},
        context={"action_name": "consequential_op", "target": "/target", "actual_executable": side_effecting_executor, "task_contract": contract_valid_e2e}
    )
    assert res_valid["status"] == "ALLOWED"
    assert side_effect_counter[0] == 1
