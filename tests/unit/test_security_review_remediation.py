"""
Unit Tests for Security Hardening and Fail-Closed Control Plane Invariants.
Addresses issues identified during initial code review and PR follow-up audit.
"""

import uuid
import pytest
import threading
from unittest.mock import patch, MagicMock

from epistemicos.provenance import (
    TrustedExecutionBoundary,
    LocalProvenanceStore,
    ExecutionContext,
    ProvenanceEvent,
    ProvenanceEventType,
)
from epistemicos.core import EpistemicOrchestrator
from epistemicos.gates import Gate, GateResult, GateAction


def test_trusted_execution_boundary_denies_omitted_or_false_authorization(tmp_path):
    log_file = str(tmp_path / "prov_auth.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"action": "delete_all"}
    digest = boundary.compute_canonical_digest(payload)

    # 1. Reject omitted authorization_granted (None)
    with pytest.raises(PermissionError, match="Authorization was not granted"):
        boundary.execute_protected_action(
            action_name="DELETE",
            target="db-prod",
            request_payload=payload,
            correlation_id="c1",
            request_id="r1",
            authorization_token_id="tok1",
            authorized_digest=digest,
            authorization_granted=None,
            executor_func=lambda: "deleted"
        )

    # 2. Reject explicit authorization_granted=False
    with pytest.raises(PermissionError, match="Authorization was not granted"):
        boundary.execute_protected_action(
            action_name="DELETE",
            target="db-prod",
            request_payload=payload,
            correlation_id="c1",
            request_id="r1",
            authorization_token_id="tok1",
            authorized_digest=digest,
            authorization_granted=False,
            executor_func=lambda: "deleted"
        )


def test_trusted_execution_boundary_validates_token_id_and_digest(tmp_path):
    log_file = str(tmp_path / "prov_val.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"data": "test"}
    digest = boundary.compute_canonical_digest(payload)

    # 1. None token ID
    with pytest.raises(PermissionError, match="Missing or invalid authorization token ID"):
        boundary.execute_protected_action(
            action_name="READ",
            target="resource",
            request_payload=payload,
            authorization_token_id=None,
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=lambda: True
        )

    # 2. Empty string token ID
    with pytest.raises(PermissionError, match="Missing or invalid authorization token ID"):
        boundary.execute_protected_action(
            action_name="READ",
            target="resource",
            request_payload=payload,
            authorization_token_id="  ",
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=lambda: True
        )

    # 3. None digest
    with pytest.raises(PermissionError, match="Missing or invalid authorized digest"):
        boundary.execute_protected_action(
            action_name="READ",
            target="resource",
            request_payload=payload,
            authorization_token_id="tok-valid",
            authorized_digest=None,
            authorization_granted=True,
            executor_func=lambda: True
        )

    # 4. Empty string digest
    with pytest.raises(PermissionError, match="Missing or invalid authorized digest"):
        boundary.execute_protected_action(
            action_name="READ",
            target="resource",
            request_payload=payload,
            authorization_token_id="tok-valid",
            authorized_digest="",
            authorization_granted=True,
            executor_func=lambda: True
        )


def test_authorized_digest_mismatch_and_payload_mutation(tmp_path):
    log_file = str(tmp_path / "prov_mismatch.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    boundary = TrustedExecutionBoundary(provenance_store=store)

    original_payload = {"amount": 100, "recipient": "user-A", "api_key": "sk-secret-1"}
    authorized_digest = boundary.compute_canonical_digest(original_payload)

    # 1. Completely wrong authorized_digest
    with pytest.raises(ValueError, match="digest changed"):
        boundary.execute_protected_action(
            action_name="TRANSFER",
            target="bank-api",
            request_payload=original_payload,
            authorization_token_id="tok-mismatch-1",
            authorized_digest="0000000000000000000000000000000000000000000000000000000000000000",
            authorization_granted=True,
            executor_func=lambda: "transferred"
        )

    # 2. Payload modified after authorization (amount tampered)
    tampered_payload_amount = {"amount": 10000, "recipient": "user-A", "api_key": "sk-secret-1"}
    with pytest.raises(ValueError, match="digest changed"):
        boundary.execute_protected_action(
            action_name="TRANSFER",
            target="bank-api",
            request_payload=tampered_payload_amount,
            authorization_token_id="tok-mismatch-2",
            authorized_digest=authorized_digest,
            authorization_granted=True,
            executor_func=lambda: "transferred"
        )

    # 3. Payload modified after authorization (security-relevant sensitive credential tampered)
    tampered_payload_credential = {"amount": 100, "recipient": "user-A", "api_key": "sk-secret-TAMPERED"}
    with pytest.raises(ValueError, match="digest changed"):
        boundary.execute_protected_action(
            action_name="TRANSFER",
            target="bank-api",
            request_payload=tampered_payload_credential,
            authorization_token_id="tok-mismatch-3",
            authorized_digest=authorized_digest,
            authorization_granted=True,
            executor_func=lambda: "transferred"
        )


def test_non_callable_executor_rejected_before_side_effects(tmp_path):
    log_file = str(tmp_path / "prov_noncallable.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"cmd": "run"}
    digest = boundary.compute_canonical_digest(payload)
    token_id = "tok-noncallable"

    # Reject non-callable executor
    with pytest.raises(ValueError, match="executor_func must be a callable object"):
        boundary.execute_protected_action(
            action_name="RUN",
            target="worker",
            request_payload=payload,
            authorization_token_id=token_id,
            authorized_digest=digest,
            authorization_granted=True,
            executor_func="not_a_callable"
        )

    # Token must NOT be consumed
    assert token_id not in boundary._consumed_tokens

    # Provenance store must NOT have an EXECUTION_STARTED event
    events = store.get_events_for_correlation("corr-id-none")
    assert len(events) == 0


def test_concurrent_competing_attempts_barrier(tmp_path):
    from epistemicos.authorization import Policy
    log_file = str(tmp_path / "prov_concurrent.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"op": "UNIQUE_TRANSACTION"}
    digest = boundary.compute_canonical_digest(payload)

    policy = Policy(policy_id="p1", allowed_operations={"PAYMENT"}, allowed_resources={"gateway"})
    cap, _ = boundary.authority.evaluate_and_issue_capability("PAYMENT", "gateway", digest, correlation_id="corr-conc", request_id="req-conc", executor_id="<lambda>", policy=policy)
    token_id = cap.token_id

    num_threads = 5
    barrier = threading.Barrier(num_threads)
    executions = []
    results = []
    errors = []

    def competing_worker():
        barrier.wait()  # Synchronize all threads to execute concurrently
        try:
            res = boundary.execute_protected_action(
                action_name="PAYMENT",
                target="gateway",
                request_payload=payload,
                correlation_id="corr-conc",
                request_id="req-conc",
                authorization_token_id=token_id,
                authorized_digest=digest,
                authorization_granted=True,
                executor_func=lambda: (executions.append(1), "PAID")[1]
            )
            results.append(res)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=competing_worker) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Assert exactly 1 thread reached executor and succeeded, and all 4 other threads failed
    assert len(executions) == 1
    assert len(results) == 1
    assert len(errors) == num_threads - 1
    assert all(isinstance(err, PermissionError) and ("already been consumed" in str(err) or "REPLAY" in str(err)) for err in errors)


def test_failure_to_record_execution_started_prevents_executor(tmp_path):
    from epistemicos.authorization import Policy
    mock_store = MagicMock()
    mock_store.record_event.side_effect = RuntimeError("Disk I/O error during EXECUTION_STARTED")
    boundary = TrustedExecutionBoundary(provenance_store=mock_store)

    payload = {"action": "mutate"}
    digest = boundary.compute_canonical_digest(payload)
    executed = []

    def executor():
        executed.append(True)
        return "mutated"

    policy = Policy(policy_id="p1", allowed_operations={"MUTATE"}, allowed_resources={"db"})
    cap, _ = boundary.authority.evaluate_and_issue_capability("MUTATE", "db", digest, executor_id=executor, policy=policy)

    with pytest.raises(RuntimeError, match="Disk I/O error during EXECUTION_STARTED"):
        boundary.execute_protected_action(
            action_name="MUTATE",
            target="db",
            request_payload=payload,
            authorization_token_id=cap.token_id,
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=executor
        )

    # Executor must NEVER be invoked if recording EXECUTION_STARTED fails
    assert len(executed) == 0


def test_failure_to_record_terminal_outcome(tmp_path):
    from epistemicos.authorization import Policy
    mock_store = MagicMock()
    # First call (EXECUTION_STARTED) succeeds; second call (EXECUTION_SUCCEEDED) fails
    mock_store.record_event.side_effect = [{"status": "OK"}, RuntimeError("Disk full during EXECUTION_SUCCEEDED")]
    boundary = TrustedExecutionBoundary(provenance_store=mock_store)

    payload = {"action": "transfer"}
    digest = boundary.compute_canonical_digest(payload)
    executed = []

    def executor():
        executed.append(True)
        return "transferred_500_usd"

    policy = Policy(policy_id="p1", allowed_operations={"TRANSFER"}, allowed_resources={"bank"})
    cap, _ = boundary.authority.evaluate_and_issue_capability("TRANSFER", "bank", digest, executor_id=executor, policy=policy)

    res = boundary.execute_protected_action(
        action_name="TRANSFER",
        target="bank",
        request_payload=payload,
        authorization_token_id=cap.token_id,
        authorized_digest=digest,
        authorization_granted=True,
        executor_func=executor
    )

    # Execution completed but terminal audit event recording failed -> EXECUTION_OUTCOME_UNKNOWN reported
    assert res["status"] == "EXECUTION_OUTCOME_UNKNOWN"
    assert res["recovery_required"] is True
    assert len(executed) == 1


def test_replay_attempt_after_successful_token_consumption(tmp_path):
    from epistemicos.authorization import Policy
    log_file = str(tmp_path / "prov_replay.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"action": "withdraw"}
    digest = boundary.compute_canonical_digest(payload)

    policy = Policy(policy_id="p1", allowed_operations={"WITHDRAW"}, allowed_resources={"atm"})
    cap, _ = boundary.authority.evaluate_and_issue_capability("WITHDRAW", "atm", digest, executor_id="<lambda>", policy=policy)
    token_id = cap.token_id

    # First attempt succeeds
    res1 = boundary.execute_protected_action(
        action_name="WITHDRAW",
        target="atm",
        request_payload=payload,
        authorization_token_id=token_id,
        authorized_digest=digest,
        authorization_granted=True,
        executor_func=lambda: "dispensed_100"
    )
    assert res1["status"] == "SUCCESS"

    # Replay attempt fails closed with PermissionError
    with pytest.raises(PermissionError, match="already been consumed"):
        boundary.execute_protected_action(
            action_name="WITHDRAW",
            target="atm",
            request_payload=payload,
            authorization_token_id=token_id,
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=lambda: "dispensed_100_again"
        )


def test_orchestrator_fail_closed_contract_on_gate_anomalies():
    orchestrator = EpistemicOrchestrator()

    # 1. Gate raises an exception
    class ExceptionGate(Gate):
        def evaluate(self, payload, context):
            raise RuntimeError("Gate internal crash")

    orch_exc = EpistemicOrchestrator()
    orch_exc.register_gate(ExceptionGate())
    res_exc = orch_exc.process_submission({"policy_id": "P1", "fleet_data": {}}, {"token_count": 1})
    assert res_exc["status"] == "HALTED"
    assert "Gate Execution Failure" in res_exc["reason"]

    # 2. Gate returns None
    class NoneGate(Gate):
        def evaluate(self, payload, context):
            return None

    orch_none = EpistemicOrchestrator()
    orch_none.register_gate(NoneGate())
    res_none = orch_none.process_submission({"policy_id": "P1", "fleet_data": {}}, {"token_count": 1})
    assert res_none["status"] == "HALTED"
    assert "Returned None" in res_none["reason"]

    # 3. Gate returns unknown action
    class UnknownActionGate(Gate):
        def evaluate(self, payload, context):
            res = GateResult(status="HALTED", gate_name="UnknownActionGate")
            res.action = "INVALID_ACTION_CODE"
            return res

    orch_unknown = EpistemicOrchestrator()
    orch_unknown.register_gate(UnknownActionGate())
    res_unknown = orch_unknown.process_submission({"policy_id": "P1", "fleet_data": {}}, {"token_count": 1})
    assert res_unknown["status"] == "HALTED"
    assert "Invalid or Unknown Action" in res_unknown["reason"]

    # 4. Gate returns ALLOW with passed=False
    class ContradictoryGate(Gate):
        def evaluate(self, payload, context):
            class CustomResult:
                action = GateAction.ALLOW
                passed = False
                gate_name = "ContradictoryGate"
            return CustomResult()

    orch_contra = EpistemicOrchestrator()
    orch_contra.register_gate(ContradictoryGate())
    res_contra = orch_contra.process_submission({"policy_id": "P1", "fleet_data": {}}, {"token_count": 1})
    assert res_contra["status"] == "HALTED"
    assert "Contradiction" in res_contra["reason"]
