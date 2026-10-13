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
    """Proves Defect 1: GateAction.ROLLBACK is ignored by orchestrator and permitted."""
    class RollbackGate(Gate):
        def evaluate(self, payload, context):
            return GateResult(action=GateAction.ROLLBACK, reason="Testing Rollback")

    orchestrator = EpistemicOrchestrator()
    orchestrator.register_gate(RollbackGate())

    raw_payload = {"policy_id": "POL-123"}
    res = orchestrator.process_submission(raw_payload, context={})
    # Defect: Orchestrator returns ALLOWED instead of HALTED for GateAction.ROLLBACK
    assert res["status"] == "ALLOWED", "Demonstrated defect: ROLLBACK was permitted as ALLOWED"


def test_defect_2_surprisal_warmup_bypass():
    """Proves Defect 2: Tokens at index 0 and 1 unconditionally bypass surprisal checks."""
    sensor = TokenSurprisalSensor(z_threshold=1.5, window_size=10)
    # Extremely surprising logprobs at index 0 and 1
    logprobs = [-25.0, -30.0]
    result = sensor.evaluate(logprobs)
    # Defect: Anomaly at token 0/1 is completely ignored
    assert result["passed"] is True
    assert result["flagged_tokens"] == 0
    assert result["max_z_score"] == 0.0


def test_defect_3_nan_logprob_bypass():
    """Proves Defect 3: NaN logprobs pass surprisal and scheduler checks without flagging."""
    sensor = TokenSurprisalSensor(z_threshold=1.5)
    logprobs = [float('nan'), float('nan'), float('nan')]
    result = sensor.evaluate(logprobs)
    # Defect: NaN comparisons evaluate to False, flagging 0 tokens
    assert result["passed"] is True
    assert result["flagged_tokens"] == 0


def test_defect_4_missing_logprobs_silent_permit():
    """Proves Defect 4: Missing logprobs/telemetry silently return GateAction.ALLOW."""
    entropy_gate = EntropyGate()
    res = entropy_gate.evaluate(payload={}, context={})
    assert res.action == GateAction.ALLOW
    assert res.reason == "NO_LOGPROBS_PROVIDED"

    tri_gate = TriangulationGate()
    res_tri = tri_gate.evaluate(payload={}, context={})
    assert res_tri.action == GateAction.ALLOW


def test_defect_5_repetition_collapse_false_negative():
    """Proves Defect 5: Repetitive token collapse (e.g. 'the the the...') produces Z-score 0."""
    sensor = TokenSurprisalSensor(z_threshold=1.5)
    # Highly predictable repeated tokens with logprob 0.0
    logprobs = [0.0] * 20
    result = sensor.evaluate(logprobs)
    # Defect: Repetition collapse is passed as 100% normal
    assert result["passed"] is True
    assert result["max_z_score"] == 0.0


def test_defect_6_valid_reasoning_false_positive():
    """Proves Defect 6: Benign transition from prose to code triggers false positive halt."""
    sensor = TokenSurprisalSensor(z_threshold=1.5, window_size=10)
    # Baseline prose with steady low surprisal
    prose_logprobs = [-0.2] * 10
    # Syntax shift token (e.g. 'def', '\\frac', '{') with higher surprisal -3.5
    logprobs = prose_logprobs + [-3.5]
    result = sensor.evaluate(logprobs)
    # Defect: Valid reasoning syntax shift is falsely flagged as anomalous
    assert result["passed"] is False
    assert result["flagged_tokens"] >= 1


def test_defect_7_rolling_window_ramping_evasion():
    """Proves Defect 7: Smoothly ramping surprisal evades rolling window Z-score detection."""
    sensor = TokenSurprisalSensor(z_threshold=2.85, window_size=10)
    base = [1.0, 1.5, 0.8, 1.4, 0.9, 1.6, 0.7, 1.3, 0.8, 1.2]
    ramp = [1.2 + 0.15 * i for i in range(1, 30)]
    logprobs = [-x for x in (base + ramp)]
    result = sensor.evaluate(logprobs)
    # Defect: Huge final surprisal (5.55 vs initial 1.0) is never flagged
    assert result["passed"] is True
    assert result["flagged_tokens"] == 0
    assert result["max_z_score"] < 2.0


def test_defect_8_scheduler_state_leakage(monkeypatch):
    """Proves Defect 8: Scheduler state leaks across independent requests in orchestrator."""
    def dummy_entropy(self, probabilities):
        p_eps = [v + 1e-9 for v in probabilities]
        return -sum(v * math.log2(v) for v in p_eps)

    monkeypatch.setattr(EntropyAwareScheduler, "entropy", dummy_entropy)

    orchestrator = EpistemicOrchestrator()
    # Request 1 step
    orchestrator.process_step([0.5, 0.5], cost=1.0, state="req1")
    assert len(orchestrator.scheduler.history) == 1

    # Request 2 step (independent request)
    orchestrator.process_step([0.5, 0.5], cost=1.0, state="req2")
    # Defect: History accumulated to 2 instead of resetting for independent request
    assert len(orchestrator.scheduler.history) == 2


def test_defect_9_permission_gate_textual_approximation_bypass():
    """Proves Defect 9: PermissionGate inspects metadata keys rather than actual executable action."""
    gate = PermissionGate(allowed_actions=["read"])
    # Action dictionary claims op is 'read', but executable action in context is dangerous
    context = {
        "proposed_actions": [{"op": "read", "endpoint": "logistics_db"}],
        "actual_executable": lambda: __import__("os").system("echo hacked")
    }
    result = gate.evaluate(payload={}, context=context)
    # Defect: Allowed because metadata op=='read' matches, ignoring actual executable
    assert result.action == GateAction.ALLOW


def test_defect_10_containment_guard_parameter_bypass():
    """Proves Defect 10: ContainmentGuard skips checks if parameter names differ from expected keys."""
    guard = ContainmentGuard()
    dangerous_executed = []

    def target_tool(**kwargs):
        dangerous_executed.append(kwargs)
        return "executed"

    # Uses 'args' instead of 'command' or 'script'
    success, result, receipt = guard.wrap_tool_execution(
        tool_name="shell",
        tool_func=target_tool,
        kwargs={"args": ["rm", "-rf", "/"]}
    )

    # Defect: Bypassed command check because key was 'args' instead of 'command'
    assert success is True
    assert receipt.passed is True
    assert len(dangerous_executed) == 1


def test_defect_11_permission_scope_missing_key_bypass():
    """Proves Defect 11: PermissionScope validates action as True when op or target is None/missing."""
    scope = PermissionScope(
        allowed_operations=["read"],
        allowed_resources=["public_db"]
    )
    # Action on allowed_resources ('public_db') but missing 'op' (unauthorized mutation)
    action_missing_op = {"node": "public_db"}
    # Action with allowed 'op' ('read') but missing 'target'/'node' (unauthorized resource)
    action_missing_target = {"op": "read"}

    # Defect: Returns True (valid) even though operations and resources are restricted
    assert scope.validate_action(action_missing_op) is True
    assert scope.validate_action(action_missing_target) is True
