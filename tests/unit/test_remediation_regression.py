"""
Comprehensive regression test suite for PR #170 review feedback.
Verifies all 5 specific concerns and asserts execution path behavior.
"""

import math
import concurrent.futures
import pytest
from epistemicos.core import EpistemicOrchestrator
from epistemicos.gates import GateAction, PermissionGate, EntropyGate
from epistemicos.models import TokenSurprisalSensor
from epistemicos.containment import ContainmentGuard
from epistemicos.scheduler import EntropyAwareScheduler


# =============================================================================
# CONCERN 1: EpistemicOrchestrator.process_step & Scheduler Isolation
# =============================================================================

def test_orchestrator_process_step_sequential_isolation():
    """Sequential test proving independent trajectories maintain isolated step counts, utility, and state."""
    orchestrator = EpistemicOrchestrator()

    # Trajectory A step 1 & 2
    res_a1 = orchestrator.process_step([0.5, 0.5], cost=1.0, state="A1", trajectory_id="traj_A")
    res_a2 = orchestrator.process_step([0.4, 0.6], cost=1.0, state="A2", trajectory_id="traj_A")

    # Trajectory B step 1 (interleaved)
    res_b1 = orchestrator.process_step([0.8, 0.2], cost=5.0, state="B1", trajectory_id="traj_B")

    sched_a = orchestrator._schedulers["traj_A"]
    sched_b = orchestrator._schedulers["traj_B"]

    assert len(sched_a.history) == 2
    assert len(sched_b.history) == 1
    assert sched_a.best_state == "A1" or sched_a.best_state == "A2"
    assert sched_b.best_state == "B1"
    assert res_a2.termination_step == 1
    assert res_b1.termination_step == 0


def test_orchestrator_process_step_concurrent_isolation():
    """Concurrent multi-threaded test proving parallel requests cannot affect each other's scheduler state."""
    orchestrator = EpistemicOrchestrator()

    def run_trajectory(traj_id):
        results = []
        for i in range(5):
            res = orchestrator.process_step([0.5, 0.5], cost=1.0, state=f"{traj_id}_{i}", trajectory_id=traj_id)
            results.append(res)
        return traj_id, results

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(run_trajectory, f"concurrent_traj_{k}") for k in range(10)]
        done_results = [f.result() for f in concurrent.futures.as_completed(futures)]

    for traj_id, results in done_results:
        sched = orchestrator._schedulers[traj_id]
        assert len(sched.history) == 5
        assert sched.history[0].state == f"{traj_id}_0"
        assert sched.history[4].state == f"{traj_id}_4"


# =============================================================================
# CONCERN 2: TokenSurprisalSensor & Explicit Validation Failures
# =============================================================================

def test_token_surprisal_sensor_nan_inf_malformed_raises_and_halts():
    """Proves compute_z_scores raises ValueError on malformed inputs and EntropyGate halts."""
    sensor = TokenSurprisalSensor()

    with pytest.raises(ValueError, match="non-finite logprob"):
        sensor.compute_z_scores([float("nan"), -1.0])

    with pytest.raises(ValueError, match="non-finite logprob"):
        sensor.compute_z_scores([float("inf"), -1.0])

    with pytest.raises(ValueError, match="Malformed or non-finite logprob"):
        sensor.compute_z_scores(["bad_string", -1.0])

    gate = EntropyGate()

    # NaN logprobs halt the pipeline
    res_nan = gate.evaluate(payload={}, context={"token_logprobs": [float("nan"), -1.0]})
    assert res_nan.action == GateAction.HALT
    assert "non-finite logprob" in res_nan.reason.lower()

    # Malformed string logprobs halt the pipeline
    res_malformed = gate.evaluate(payload={}, context={"token_logprobs": ["invalid"]})
    assert res_malformed.action == GateAction.HALT


# =============================================================================
# CONCERN 3: PermissionGate & Trusted Operation Registry
# =============================================================================

def test_permission_gate_trusted_operation_registry_substitution_defense():
    """Proves PermissionGate rejects spoofed/substituted callables using trusted operation registry."""
    executed = []

    def genuine_op():
        executed.append("genuine")
        return "genuine_result"

    def malicious_op():
        executed.append("malicious")
        return "pwned"

    registry = {"read_user_profile": genuine_op}
    gate = PermissionGate(allowed_actions=["read_user_profile"], trusted_operations=registry)

    # Authorized genuine operation passes
    ctx_genuine = {
        "requested_operation_id": "read_user_profile",
        "actual_executable": genuine_op
    }
    res_genuine = gate.evaluate(payload={}, context=ctx_genuine)
    assert res_genuine.action == GateAction.ALLOW

    if res_genuine.action == GateAction.ALLOW:
        ctx_genuine["actual_executable"]()
    assert executed == ["genuine"]

    # Substituted/spoofed function for registered operation ID is rejected
    ctx_substituted = {
        "requested_operation_id": "read_user_profile",
        "actual_executable": malicious_op
    }
    res_sub = gate.evaluate(payload={}, context=ctx_substituted)
    assert res_sub.action == GateAction.HALT
    assert "substituted executable detected" in res_sub.reason

    # Unregistered operation ID is rejected
    ctx_unregistered = {
        "requested_operation_id": "delete_all",
        "actual_executable": malicious_op
    }
    res_unreg = gate.evaluate(payload={}, context=ctx_unregistered)
    assert res_unreg.action == GateAction.HALT


# =============================================================================
# CONCERN 4: ContainmentGuard Argument Shapes & Egress/Command Normalization
# =============================================================================

def test_containment_guard_positional_and_nested_argument_shapes():
    """Proves ContainmentGuard inspects positional args, kwargs, and nested containers."""
    executed_args = []

    def mock_tool(*args, **kwargs):
        executed_args.append((args, kwargs))
        return "ok"

    guard = ContainmentGuard()

    # 1. Positional argument command injection blocked
    ok1, _, receipt1 = guard.wrap_tool_execution(
        tool_name="shell",
        tool_func=mock_tool,
        args=("rm -rf /",),
        kwargs={}
    )
    assert ok1 is False
    assert receipt1.passed is False

    # 2. Nested dictionary in positional arguments blocked
    ok2, _, receipt2 = guard.wrap_tool_execution(
        tool_name="shell",
        tool_func=mock_tool,
        args=({"config": {"exec": "sudo su"}},),
        kwargs={}
    )
    assert ok2 is False
    assert receipt2.passed is False

    # 3. Nested list in kwargs url egress blocked
    ok3, _, receipt3 = guard.wrap_tool_execution(
        tool_name="fetch",
        tool_func=mock_tool,
        args=(),
        kwargs={"endpoints": ["http://127.0.0.1/admin"]}
    )
    assert ok3 is False
    assert receipt3.passed is False

    # Safe positional and keyword execution succeeds and executes
    ok_safe, result, receipt_safe = guard.wrap_tool_execution(
        tool_name="safe_tool",
        tool_func=mock_tool,
        args=("safe_arg",),
        kwargs={"mode": "read"}
    )
    assert ok_safe is True
    assert receipt_safe.passed is True
    assert len(executed_args) == 1


# =============================================================================
# CONCERN 5: EntropyAwareScheduler.entropy Input Contract & Strict Validation
# =============================================================================

def test_entropy_aware_scheduler_input_contract():
    """Proves EntropyAwareScheduler.entropy strictly validates distribution constraints."""
    scheduler = EntropyAwareScheduler()

    # 1. Reject 2D shape
    with pytest.raises(ValueError, match="1D distribution"):
        scheduler.entropy([[0.5, 0.5], [0.5, 0.5]])

    # 2. Reject empty sequence
    with pytest.raises(ValueError, match="cannot be empty"):
        scheduler.entropy([])

    # 3. Reject NaN
    with pytest.raises(ValueError, match="NaN or non-finite"):
        scheduler.entropy([float("nan"), 0.5])

    # 4. Reject Infinity
    with pytest.raises(ValueError, match="NaN or non-finite"):
        scheduler.entropy([float("inf"), 0.5])

    # 5. Reject Negative probabilities
    with pytest.raises(ValueError, match="negative values"):
        scheduler.entropy([-0.1, 1.1])

    # 6. Reject zero / non-positive sum
    with pytest.raises(ValueError, match="positive finite value"):
        scheduler.entropy([0.0, 0.0])

    # Valid distribution calculates correct Shannon entropy without epsilon distortion
    # For fair coin [0.5, 0.5], H = -2 * (0.5 * log2(0.5)) = 1.0 bit
    h = scheduler.entropy([0.5, 0.5])
    assert math.isclose(h, 1.0)

    # Handles zero probabilities using 0 * log(0) = 0 limit
    h_zero = scheduler.entropy([1.0, 0.0])
    assert math.isclose(h_zero, 0.0)
