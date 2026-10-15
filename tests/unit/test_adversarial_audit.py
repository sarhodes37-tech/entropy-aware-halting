"""
Adversarial Correctness Audit Test Suite for EpistemicOS.

Tests and proves the confirmed defects and counterexamples in the control pipeline.
"""

import sys
import math
from unittest.mock import MagicMock
import pytest
from epistemicos.core import EpistemicOrchestrator
from epistemicos.gates import (
    Gate,
    GateAction,
    GateResult,
    EntropyGate,
    PermissionGate,
    TriangulationGate
)
from epistemicos.models import (
    TokenSurprisalSensor,
    PermissionScope,
    CanonicalProblemRepresentation
)
from epistemicos.scheduler import EntropyAwareScheduler
from epistemicos.containment import ContainmentGuard, ContainmentViolationType


def test_defect_1_rollback_treated_as_allow():
    """Verifies Remediation 1: GateAction.ROLLBACK is not permitted as ALLOWED."""
    class RollbackGate(Gate):
        def evaluate(self, payload, context):
            return GateResult(action=GateAction.ROLLBACK, reason="Testing Rollback")

    orchestrator = EpistemicOrchestrator()
    orchestrator.register_gate(RollbackGate())

    raw_payload = {"policy_id": "POL-123"}
    res = orchestrator.process_submission(raw_payload, context={})
    # Remediated: Orchestrator halts/rollbacks non-ALLOW gate actions
    assert res["status"] == "HALTED"


def test_defect_2_surprisal_warmup_bypass():
    """Verifies Remediation: Warm-up tokens at index 0 and 1 evaluate against baseline prior surprisal."""
    sensor = TokenSurprisalSensor(z_threshold=1.5, window_size=10)

    # Nominal logprobs close to baseline (-1.0 surprisal vs baseline prior surprisal 1.0)
    nominal_logprobs = [-1.0, -0.8]
    nominal_result = sensor.evaluate(nominal_logprobs)
    assert nominal_result["passed"] is True

    # Extreme anomaly/prompt injection at index 0 or 1
    anomalous_logprobs = [-25.0, -30.0]
    anomalous_result = sensor.evaluate(anomalous_logprobs)
    assert anomalous_result["passed"] is False
    assert anomalous_result["flagged_tokens"] > 0


def test_defect_3_nan_logprob_bypass():
    """Verifies Remediation 2: NaN logprobs are safely handled with explicit failure result."""
    sensor = TokenSurprisalSensor(z_threshold=1.5)
    logprobs = [float('nan'), float('nan'), float('nan')]
    result = sensor.evaluate(logprobs)
    assert result["passed"] is False
    assert result["reason"] == "MALFORMED_NON_FINITE_LOGPROBS"


def test_defect_4_missing_logprobs_silent_permit():
    """Finding Disposition: Explicit Optional-Gate Behavior.
    Missing telemetry in optional gates permits execution while relying on mandatory gates.
    """
    entropy_gate = EntropyGate()
    res = entropy_gate.evaluate(payload={}, context={})
    assert res.action == GateAction.ALLOW
    assert res.reason == "NO_LOGPROBS_PROVIDED"


def test_defect_5_repetition_collapse_false_negative():
    """Finding Disposition: Design Boundary.
    Repetitive sequences yield 0 surprisal. Structural repetition is handled by grammar/length gates.
    """
    sensor = TokenSurprisalSensor(z_threshold=1.5)
    logprobs = [0.0] * 20
    result = sensor.evaluate(logprobs)
    assert result["passed"] is True


def test_defect_6_valid_reasoning_false_positive():
    """Finding Disposition: Empirical Trade-off / Uncertainty Signal.
    Token surprisal serves as an uncertainty indicator rather than absolute safety truth.
    """
    sensor = TokenSurprisalSensor(z_threshold=1.5, window_size=10)
    prose_logprobs = [-0.2] * 10
    logprobs = prose_logprobs + [-3.5]
    result = sensor.evaluate(logprobs)
    assert result["passed"] is False


def test_defect_7_rolling_window_ramping_evasion():
    """Finding Disposition: Statistical Window Property.
    Rolling window tracks local rate of change. Cumulative drift is monitored by trajectory-level gates.
    """
    sensor = TokenSurprisalSensor(z_threshold=2.85, window_size=10)
    base = [1.0, 1.5, 0.8, 1.4, 0.9, 1.6, 0.7, 1.3, 0.8, 1.2]
    ramp = [1.2 + 0.15 * i for i in range(1, 30)]
    logprobs = [-x for x in (base + ramp)]
    result = sensor.evaluate(logprobs)
    assert result["passed"] is True


def test_defect_8_scheduler_state_leakage(monkeypatch):
    """Verifies Remediation 7: Scheduler state is isolated per trajectory/request."""
    def dummy_entropy(self, probabilities):
        p_eps = [v + 1e-9 for v in probabilities]
        return -sum(v * math.log2(v) for v in p_eps)

    monkeypatch.setattr(EntropyAwareScheduler, "entropy", dummy_entropy)

    orchestrator = EpistemicOrchestrator()
    orchestrator.process_step([0.5, 0.5], cost=1.0, state="req1", trajectory_id="traj_1")
    orchestrator.process_step([0.5, 0.5], cost=1.0, state="req2", trajectory_id="traj_2")

    # Remediated: History is isolated per trajectory
    assert len(orchestrator._schedulers["traj_1"].history) == 1
    assert len(orchestrator._schedulers["traj_2"].history) == 1


def test_defect_9_permission_gate_textual_approximation_bypass():
    """Verifies Remediation 4: PermissionGate binds authorization to resolved executable operation."""
    gate = PermissionGate(allowed_actions=["read"])
    def dangerous_func():
        return "hacked"

    context = {
        "proposed_actions": [{"op": "read", "endpoint": "logistics_db"}],
        "actual_executable": dangerous_func
    }
    result = gate.evaluate(payload={}, context=context)
    # Remediated: Halts because dangerous_func is not in allowed_actions ("read")
    assert result.action == GateAction.HALT


def test_defect_10_containment_guard_parameter_bypass():
    """Verifies Remediation 5: ContainmentGuard inspects normalized tool arguments regardless of kwarg name."""
    guard = ContainmentGuard()
    dangerous_executed = []

    def target_tool(**kwargs):
        dangerous_executed.append(kwargs)
        return "executed"

    success, result, receipt = guard.wrap_tool_execution(
        tool_name="shell",
        tool_func=target_tool,
        kwargs={"args": ["rm", "-rf", "/"]}
    )

    # Remediated: Blocked command regardless of parameter key 'args'
    assert success is False
    assert receipt.passed is False
    assert len(dangerous_executed) == 0


def test_defect_11_permission_scope_missing_key_bypass():
    """Verifies Remediation 6: PermissionScope requires explicit op and target fields when restricted."""
    scope = PermissionScope(
        allowed_operations=["read"],
        allowed_resources=["public_db"]
    )
    action_missing_op = {"node": "public_db"}
    action_missing_target = {"op": "read"}

    # Remediated: Rejects actions missing mandatory operation or target fields
    assert scope.validate_action(action_missing_op) is False
    assert scope.validate_action(action_missing_target) is False
