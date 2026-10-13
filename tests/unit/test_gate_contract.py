"""
Contract tests for independent control-plane governance gates interface.
Verifies input contracts, decision taxonomy, evidence reporting, versioned configs,
cost bounds, fail-closed behavior, indeterminate safety, explicit gate ordering,
and audit event generation.
"""

import pytest
from epistemicos.gates import (
    GateDecision,
    GateInput,
    GateConfig,
    GateOutcome,
    ControlPlaneGate,
    PermissionGate,
    EntropyGate,
    TriangulationGate,
    CryptoAttestationGate,
    GateAction,
    GateResult
)
from epistemicos.core import EpistemicOrchestrator


def test_gate_decision_enum_taxonomy():
    """Validates the structured decision enum values."""
    assert GateDecision.ALLOW.value == "ALLOW"
    assert GateDecision.DENY.value == "DENY"
    assert GateDecision.HALT.value == "HALT"
    assert GateDecision.INDETERMINATE.value == "INDETERMINATE"


def test_gate_input_contract():
    """Validates typed gate input structure and payload access."""
    gi = GateInput(
        payload={"policy_id": "POL-123"},
        context={"token_logprobs": [-0.1, -0.2]},
        operation_id="update_db",
        requestor_id="usr-99",
        attempt_number=1
    )
    assert gi.payload == {"policy_id": "POL-123"}
    assert gi.operation_id == "update_db"
    assert gi.attempt_number == 1


def test_gate_config_versioning():
    """Validates versioned configuration attributes."""
    cfg = GateConfig(version="1.0.0", max_execution_cost_ms=50.0)
    assert cfg.version == "1.0.0"
    assert cfg.enabled is True
    assert cfg.max_execution_cost_ms == 50.0


def test_gate_outcome_audit_event_generation():
    """Validates machine-readable audit event representation and backward compatibility."""
    outcome = GateOutcome(
        decision=GateDecision.DENY,
        reason_code="UNAUTHORIZED_OPERATION",
        gate_name="PermissionGate",
        gate_version="1.0.0",
        evidence={"operation": "drop_table"},
        latency_ms=1.2,
        cost_estimate_ms=2.0
    )

    audit_event = outcome.to_audit_event()
    assert audit_event["gate_name"] == "PermissionGate"
    assert audit_event["gate_version"] == "1.0.0"
    assert audit_event["decision"] == "DENY"
    assert audit_event["reason_code"] == "UNAUTHORIZED_OPERATION"
    assert audit_event["evidence"] == {"operation": "drop_table"}
    assert "timestamp" in audit_event

    # Check compatibility bridge with GateResult
    compat_res = outcome.to_gate_result()
    assert compat_res.action == GateAction.HALT
    assert compat_res.passed is False
    assert compat_res.reason == "UNAUTHORIZED_OPERATION"


def test_indeterminate_cannot_become_allow():
    """Ensures INDETERMINATE result is not treated as ALLOW by check helpers."""
    outcome = GateOutcome(
        decision=GateDecision.INDETERMINATE,
        reason_code="MISSING_TELEMETRY",
        gate_name="TriangulationGate"
    )

    assert outcome.passed is False
    assert outcome.decision != GateDecision.ALLOW
    compat = outcome.to_gate_result()
    assert compat.passed is False


class FailingSecurityGate(ControlPlaneGate):
    def __init__(self, is_critical=True):
        super().__init__(config=GateConfig(version="1.0.0", is_critical=is_critical))

    def evaluate_contract(self, gate_input: GateInput) -> GateOutcome:
        raise RuntimeError("Cryptographic verification service unreachable")


def test_fail_closed_on_security_critical_gate_exception():
    """Ensures security-critical gate exceptions fail closed (DENY/HALT)."""
    gate = FailingSecurityGate(is_critical=True)
    gi = GateInput(payload={}, context={})
    outcome = gate.evaluate_safe(gi)

    assert outcome.decision == GateDecision.HALT
    assert outcome.reason_code == "GATE_EXECUTION_ERROR"
    assert "Cryptographic verification service unreachable" in outcome.evidence.get("error", "")


def test_explicit_gate_ordering_in_orchestrator():
    """Ensures gate execution ordering is explicit, deterministic, and testable."""
    orchestrator = EpistemicOrchestrator()
    gate_names = [getattr(g, "gate_name", g.__class__.__name__) for g in orchestrator.gates]
    assert gate_names == ["PermissionGate", "EntropyGate", "TriangulationGate"]


def test_retry_composition_does_not_bypass_permissions():
    """Ensures gate composition enforces permissions on retries (attempt_number > 1)."""
    gate = PermissionGate(allowed_actions=["read_only"])
    gi_retry = GateInput(
        payload={"scope": {"allowed_operations": ["read_only"]}},
        context={"proposed_actions": [{"op": "write_db", "node": "db"}]},
        attempt_number=2
    )

    outcome = gate.evaluate_contract(gi_retry)
    assert outcome.decision in (GateDecision.DENY, GateDecision.HALT)
    assert outcome.passed is False


def test_orchestrator_failing_gate_fails_closed(tmp_path):
    """Verifies that an unhandled exception in a gate causes EpistemicOrchestrator to fail closed."""
    log_file = str(tmp_path / "test_audit.jsonl")
    orchestrator = EpistemicOrchestrator(audit_log_path=log_file)

    class BrokenGate(ControlPlaneGate):
        def evaluate_contract(self, gate_input: GateInput) -> GateOutcome:
            raise RuntimeError("Database connection lost")

    orchestrator.register_gate(BrokenGate())
    res = orchestrator.process_submission(
        raw_payload={"policy_id": "POL-ERR-TEST"},
        context={}
    )

    assert res["status"] == "HALTED"
    assert "GATE_EXECUTION_ERROR" in res["reason"] or "Database connection lost" in res["reason"]
