"""
Unit Tests for Security Hardening and Fail-Closed Control Plane Invariants.
Addresses issues identified during initial code review.
"""

import uuid
import pytest
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


def test_trusted_execution_boundary_validates_executor_func(tmp_path):
    log_file = str(tmp_path / "prov_exec.jsonl")
    store = LocalProvenanceStore(log_path=log_file)
    boundary = TrustedExecutionBoundary(provenance_store=store)

    payload = {"cmd": "run"}
    digest = boundary.compute_canonical_digest(payload)

    # None executor_func
    with pytest.raises(ValueError, match="executor_func must be a callable object"):
        boundary.execute_protected_action(
            action_name="RUN",
            target="worker",
            request_payload=payload,
            authorization_token_id="tok-1",
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=None
        )

    # Non-callable executor_func
    with pytest.raises(ValueError, match="executor_func must be a callable object"):
        boundary.execute_protected_action(
            action_name="RUN",
            target="worker",
            request_payload=payload,
            authorization_token_id="tok-1",
            authorized_digest=digest,
            authorization_granted=True,
            executor_func="not_a_function"
        )


def test_trusted_execution_boundary_audit_failure_prevents_execution(tmp_path):
    mock_store = MagicMock()
    mock_store.record_event.side_effect = RuntimeError("Audit log disk full")
    boundary = TrustedExecutionBoundary(provenance_store=mock_store)

    payload = {"action": "mutate"}
    digest = boundary.compute_canonical_digest(payload)
    executed = []

    def executor():
        executed.append(True)
        return "done"

    # Audit failure during EXECUTION_STARTED must raise RuntimeError and prevent executor execution
    with pytest.raises(RuntimeError, match="Audit log disk full"):
        boundary.execute_protected_action(
            action_name="MUTATE",
            target="db",
            request_payload=payload,
            authorization_token_id="tok-audit-fail",
            authorized_digest=digest,
            authorization_granted=True,
            executor_func=executor
        )

    assert len(executed) == 0


def test_orchestrator_fail_closed_contract_on_gate_anomalies():
    orchestrator = EpistemicOrchestrator()

    # 1. Gate returns None
    class NoneGate(Gate):
        def evaluate(self, payload, context):
            return None

    orch_none = EpistemicOrchestrator()
    orch_none.register_gate(NoneGate())
    res_none = orch_none.process_submission({"policy_id": "P1", "fleet_data": {}}, {"token_count": 1})
    assert res_none["status"] == "HALTED"
    assert "Returned None" in res_none["reason"]

    # 2. Gate returns unknown action
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

    # 3. Gate returns ALLOW with passed=False
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
