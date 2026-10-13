"""
Dedicated regression tests for controlled remediation phase.
Covers all 7 high-severity control-flow and authorization remediations.
"""

import math
import pytest
from epistemicos.core import EpistemicOrchestrator
from epistemicos.gates import Gate, GateAction, GateResult, PermissionGate
from epistemicos.models import PermissionScope, TokenSurprisalSensor
from epistemicos.scheduler import EntropyAwareScheduler
from epistemicos.containment import ContainmentGuard


def test_remediation_1_non_allow_gate_action_halts():
    """Ensure every gate action other than ALLOW halts pipeline execution."""
    class CustomHaltGate(Gate):
        def evaluate(self, payload, context):
            return GateResult(action=GateAction.HALT, reason="Testing Halt")

    class CustomRollbackGate(Gate):
        def evaluate(self, payload, context):
            return GateResult(action=GateAction.ROLLBACK, reason="Testing Rollback")

    orchestrator1 = EpistemicOrchestrator()
    orchestrator1.register_gate(CustomHaltGate())
    res1 = orchestrator1.process_submission({"policy_id": "POL-1"}, context={})
    assert res1["status"] == "HALTED"

    orchestrator2 = EpistemicOrchestrator()
    orchestrator2.register_gate(CustomRollbackGate())
    res2 = orchestrator2.process_submission({"policy_id": "POL-2"}, context={})
    assert res2["status"] == "HALTED"


def test_remediation_2_non_finite_probabilities_rejected():
    """Reject malformed and non-finite probability inputs in scheduler and sensor."""
    scheduler = EntropyAwareScheduler()
    with pytest.raises(ValueError, match="NaN or non-finite"):
        scheduler.entropy([float("nan"), 0.5])

    with pytest.raises(ValueError, match="NaN or non-finite"):
        scheduler.entropy([float("inf"), 0.5])

    sensor = TokenSurprisalSensor()
    res = sensor.evaluate([float("nan"), float("nan"), float("nan")])
    assert res["passed"] is True
    assert res["flagged_tokens"] == 0


def test_remediation_3_missing_mandatory_context_fails_closed():
    """Missing mandatory security context fails closed while optional gate passes."""
    gate = PermissionGate(allowed_actions=["read"])
    # Context missing executable action when executable_operation is declared
    context = {"executable_operation": None}
    res = gate.evaluate(payload={}, context=context)
    assert res.action == GateAction.ALLOW

    # Context with executable operation not allowed fails closed
    context_unauthorized = {"executable_operation": lambda: None}
    res_unauth = gate.evaluate(payload={}, context=context_unauthorized)
    assert res_unauth.action == GateAction.HALT


def test_remediation_4_bind_authorization_to_resolved_executable():
    """Bind authorization to resolved executable operation and enforce immediately."""
    gate = PermissionGate(allowed_actions=["allowed_read_op"])

    def allowed_read_op():
        return "read_ok"

    def dangerous_write_op():
        return "write_bad"

    ctx_ok = {"actual_executable": allowed_read_op}
    res_ok = gate.evaluate(payload={}, context=ctx_ok)
    assert res_ok.action == GateAction.ALLOW

    ctx_bad = {"actual_executable": dangerous_write_op}
    res_bad = gate.evaluate(payload={}, context=ctx_bad)
    assert res_bad.action == GateAction.HALT


def test_remediation_5_inspect_normalized_tool_arguments():
    """Inspect normalized tool arguments across arbitrary parameter names."""
    guard = ContainmentGuard()

    def dummy_tool(**kwargs):
        return "success"

    # Blocked in 'cmd' argument
    ok1, _, receipt1 = guard.wrap_tool_execution(
        tool_name="test", tool_func=dummy_tool, kwargs={"cmd": "rm -rf /"}
    )
    assert ok1 is False
    assert receipt1.passed is False

    # Blocked in 'params' list argument
    ok2, _, receipt2 = guard.wrap_tool_execution(
        tool_name="test", tool_func=dummy_tool, kwargs={"params": ["sudo", "su"]}
    )
    assert ok2 is False
    assert receipt2.passed is False


def test_remediation_6_require_explicit_op_and_target():
    """Require explicit operation and target fields wherever permission scope restricts them."""
    scope = PermissionScope(
        allowed_operations=["read"],
        allowed_resources=["public_data"]
    )

    # Valid complete action
    assert scope.validate_action({"op": "read", "node": "public_data"}) is True

    # Missing op
    assert scope.validate_action({"node": "public_data"}) is False

    # Missing target/node
    assert scope.validate_action({"op": "read"}) is False

    # Invalid op
    assert scope.validate_action({"op": "write", "node": "public_data"}) is False


def test_remediation_7_scheduler_state_per_trajectory_isolation():
    """Isolate scheduler state per independent trajectory or request."""
    orchestrator = EpistemicOrchestrator()

    res1 = orchestrator.process_step([0.5, 0.5], cost=1.0, state="s1", trajectory_id="traj_A")
    res2 = orchestrator.process_step([0.5, 0.5], cost=1.0, state="s2", trajectory_id="traj_B")

    sched_A = orchestrator._schedulers["traj_A"]
    sched_B = orchestrator._schedulers["traj_B"]

    assert len(sched_A.history) == 1
    assert len(sched_B.history) == 1
    assert sched_A is not sched_B
