"""
Unit tests for epistemicos/semantic_adapter.py.

Covering:
- DualUncertaintyStepMetrics serialization
- SemanticSchedulerAdapter initialization and validation
- Cost and v_decision boundary conditions
- Trajectory key resolution logic
- Isolated trajectory step execution and metrics computation
- Multi-step semantic uncertainty delta & eta calculations
- Skipping invalid semantic results when calculating previous valid entropy
- Resetting specific trajectory vs all trajectories
- Telemetry summary filtering and flattening
"""

import math
import pytest

from epistemicos.scheduler import EntropyAwareScheduler, StepMetrics, DecisionResult
from epistemicos.semantic_uncertainty import (
    SemanticUncertaintyEstimator,
    SemanticUncertaintyResult,
    SemanticUncertaintyStatus,
)
from epistemicos.semantic_adapter import (
    DualUncertaintyStepMetrics,
    SemanticSchedulerAdapter,
)


def test_dual_uncertainty_step_metrics_to_dict():
    """Verifies that DualUncertaintyStepMetrics correctly serializes all fields to a dict."""
    token_metrics = StepMetrics(
        step_index=0,
        entropy=0.8,
        delta_h=0.2,
        eta=1.5,
        utility=10.0,
        utility_gain=2.0,
        state="s0"
    )
    sem_result = SemanticUncertaintyResult(
        semantic_entropy_bits=1.0,
        normalized_semantic_entropy=0.5,
        semantic_disagreement=0.5,
        decision_sensitive_disagreement=0.0,
        resolver_ambiguity=0.0,
        status=SemanticUncertaintyStatus.VALID,
        candidates_analyzed=2,
        num_clusters=2,
        cluster_distribution=[]
    )
    metrics = DualUncertaintyStepMetrics(
        step_index=0,
        token_metrics=token_metrics,
        semantic_result=sem_result,
        delta_h_sem=0.5,
        eta_sem=2.5,
        semantic_utility=15.0,
        cost=2.0
    )

    d = metrics.to_dict()
    assert d["step_index"] == 0
    assert d["token_entropy"] == 0.8
    assert d["token_delta_h"] == 0.2
    assert d["token_eta"] == 1.5
    assert d["token_utility"] == 10.0
    assert d["semantic_entropy_bits"] == 1.0
    assert d["semantic_normalized_entropy"] == 0.5
    assert d["semantic_disagreement"] == 0.5
    assert d["decision_sensitive_disagreement"] == 0.0
    assert d["delta_h_sem"] == 0.5
    assert d["eta_sem"] == 2.5
    assert d["semantic_utility"] == 15.0
    assert d["cost"] == 2.0
    assert d["status"] == "VALID"
    assert d["candidates_analyzed"] == 2
    assert d["num_clusters"] == 2


def test_adapter_init_validation():
    """Verifies parameter validation for v_decision during initialization."""
    invalid_values = [0.0, -10.0, float("nan"), float("inf"), float("-inf"), "invalid", None]
    for val in invalid_values:
        with pytest.raises(ValueError, match="v_decision must be a positive finite number"):
            SemanticSchedulerAdapter(v_decision=val)

    # Valid values
    adapter = SemanticSchedulerAdapter(v_decision=50.0)
    assert adapter.v_decision == 50.0

    adapter_int = SemanticSchedulerAdapter(v_decision=100)
    assert adapter_int.v_decision == 100.0


def test_adapter_custom_scheduler_and_estimator():
    """Verifies initialization with custom scheduler and estimator."""
    custom_scheduler = EntropyAwareScheduler(value_of_information=200.0)
    custom_estimator = SemanticUncertaintyEstimator()
    adapter = SemanticSchedulerAdapter(
        scheduler=custom_scheduler,
        estimator=custom_estimator,
        v_decision=200.0
    )
    assert adapter._base_scheduler.V == 200.0
    assert adapter.estimator is custom_estimator


def test_get_trajectory_key_resolution():
    """Verifies trajectory key resolution priority logic."""
    adapter = SemanticSchedulerAdapter()

    # 1. Explicit trajectory_id takes top precedence
    key = adapter._get_trajectory_key("traj_123", "state_abc")
    assert key == "traj_123"

    # 2. Non-empty string state used if trajectory_id is None
    key = adapter._get_trajectory_key(None, "state_abc")
    assert key == "state_abc"

    # 3. Fallback to default_trajectory for empty/whitespace state or non-string state
    assert adapter._get_trajectory_key(None, "") == "default_trajectory"
    assert adapter._get_trajectory_key(None, "   ") == "default_trajectory"
    assert adapter._get_trajectory_key(None, None) == "default_trajectory"
    assert adapter._get_trajectory_key(None, {"key": "val"}) == "default_trajectory"
    assert adapter._get_trajectory_key(None, 42) == "default_trajectory"


def test_step_cost_validation():
    """Verifies cost parameter validation during step execution."""
    adapter = SemanticSchedulerAdapter()
    invalid_costs = [0.0, -1.0, float("nan"), float("inf"), float("-inf"), "invalid", None]
    for cost in invalid_costs:
        with pytest.raises(ValueError, match="Cost must be a positive finite number"):
            adapter.step([0.5, 0.5], ["Cand A", "Cand B"], cost=cost, state="s1")


def test_step_single_step_valid():
    """Verifies a single step execution with valid semantic candidates."""
    adapter = SemanticSchedulerAdapter(v_decision=100.0)
    candidates = ["The system is online.", "The system is offline."]

    dec, sem, metric = adapter.step(
        token_probabilities=[0.5, 0.5],
        candidates=candidates,
        cost=10.0,
        state="step1",
        trajectory_id="traj_single"
    )

    assert isinstance(dec, DecisionResult)
    assert isinstance(sem, SemanticUncertaintyResult)
    assert isinstance(metric, DualUncertaintyStepMetrics)

    # Initial valid step has delta_h_sem = 0.0 and eta_sem = 0.0
    assert metric.delta_h_sem == 0.0
    assert metric.eta_sem == 0.0
    # Utility = v_decision * (init_h - current_h) - total_cost = 100.0 * (1.0 - 1.0) - 10.0 = -10.0
    assert pytest.approx(metric.semantic_utility, 1e-4) == -10.0


def test_step_multi_step_delta_and_eta_computation():
    """Verifies multi-step delta_h_sem, eta_sem, and semantic_utility calculation."""
    adapter = SemanticSchedulerAdapter(v_decision=100.0)

    # Step 1: 2 distinct clusters -> H_sem = 1.0
    cand_step1 = ["The request is approved.", "The request is denied."]
    _, _, m1 = adapter.step([0.5, 0.5], cand_step1, cost=10.0, state="s1", trajectory_id="t1")
    assert m1.semantic_result.semantic_entropy_bits == 1.0
    assert m1.delta_h_sem == 0.0
    assert m1.eta_sem == 0.0

    # Step 2: 1 cluster -> H_sem = 0.0
    cand_step2 = ["The request is approved.", "Request is approved."]
    _, _, m2 = adapter.step([1.0, 0.0], cand_step2, cost=5.0, state="s2", trajectory_id="t1")
    assert m2.semantic_result.semantic_entropy_bits == 0.0
    # delta_h_sem = 1.0 - 0.0 = 1.0
    assert m2.delta_h_sem == 1.0
    # eta_sem = (1.0 * 100.0) / 5.0 = 20.0
    assert pytest.approx(m2.eta_sem, 1e-4) == 20.0
    # semantic_utility = 100.0 * (1.0 - 0.0) - (10.0 + 5.0) = 85.0
    assert pytest.approx(m2.semantic_utility, 1e-4) == 85.0


def test_step_with_invalid_semantic_result():
    """Verifies that non-VALID semantic status results in None for delta_h_sem, eta_sem, and utility."""
    adapter = SemanticSchedulerAdapter(v_decision=100.0)

    # Single candidate input -> INSUFFICIENT_EVIDENCE
    cand = ["Single candidate"]
    _, sem, metric = adapter.step([1.0], cand, cost=10.0, state="s1", trajectory_id="t1")

    assert sem.status == SemanticUncertaintyStatus.INSUFFICIENT_EVIDENCE
    assert metric.delta_h_sem is None
    assert metric.eta_sem is None
    assert metric.semantic_utility is None


def test_step_skips_invalid_previous_step_when_computing_delta():
    """Verifies that step searching for previous valid entropy skips invalid intermediate steps."""
    adapter = SemanticSchedulerAdapter(v_decision=100.0)

    # Step 1: Valid candidates (H = 1.0)
    adapter.step([0.5, 0.5], ["Approved", "Denied"], cost=10.0, state="s1", trajectory_id="t_skip")

    # Step 2: Invalid candidates (single candidate -> INSUFFICIENT_EVIDENCE)
    adapter.step([1.0], ["Single candidate"], cost=5.0, state="s2", trajectory_id="t_skip")

    # Step 3: Valid candidates (H = 0.0)
    _, _, m3 = adapter.step([1.0, 0.0], ["Approved", "Approved!"], cost=5.0, state="s3", trajectory_id="t_skip")

    assert m3.semantic_result.status == SemanticUncertaintyStatus.VALID
    # Delta should be calculated relative to Step 1 (H = 1.0), skipping Step 2
    assert m3.delta_h_sem == 1.0
    assert pytest.approx(m3.eta_sem, 1e-4) == (1.0 * 100.0) / 5.0


def test_decision_context_passed_to_estimator():
    """Verifies decision_context parameter is correctly passed to the estimator."""
    class ContextRecorderEstimator(SemanticUncertaintyEstimator):
        def __init__(self):
            super().__init__()
            self.last_context = None

        def estimate(self, candidates, decision_context=None):
            self.last_context = decision_context
            return super().estimate(candidates, decision_context=decision_context)

    estimator = ContextRecorderEstimator()
    adapter = SemanticSchedulerAdapter(estimator=estimator)

    context_data = {"criticality": "high", "action_space": ["ALLOW", "DENY"]}
    adapter.step([0.5, 0.5], ["A", "B"], cost=10.0, state="s1", decision_context=context_data)

    assert estimator.last_context == context_data


def test_interleaved_trajectories_isolation():
    """Verifies complete state isolation between interleaved trajectories."""
    adapter = SemanticSchedulerAdapter(v_decision=100.0)

    # Trajectory 1 Step 1
    adapter.step([0.5, 0.5], ["A", "B"], cost=10.0, state="s1", trajectory_id="t1")

    # Trajectory 2 Step 1
    adapter.step([1.0, 0.0], ["X", "X"], cost=10.0, state="s1", trajectory_id="t2")

    # Trajectory 1 Step 2
    _, _, m1_2 = adapter.step([1.0, 0.0], ["A", "A"], cost=5.0, state="s2", trajectory_id="t1")

    # Trajectory 2 Step 2
    _, _, m2_2 = adapter.step([0.5, 0.5], ["X", "Y"], cost=5.0, state="s2", trajectory_id="t2")

    assert m1_2.delta_h_sem == 1.0  # From 1.0 in t1 s1 to 0.0 in t1 s2
    assert m2_2.delta_h_sem == -1.0  # From 0.0 in t2 s1 to 1.0 in t2 s2


def test_reset_functionality():
    """Verifies reset clearing individual trajectories or all trajectories."""
    adapter = SemanticSchedulerAdapter(v_decision=100.0)

    adapter.step([0.5, 0.5], ["A", "B"], cost=10.0, state="s1", trajectory_id="t1")
    adapter.step([0.5, 0.5], ["X", "Y"], cost=10.0, state="s1", trajectory_id="t2")

    assert len(adapter._schedulers) == 2
    assert len(adapter._histories) == 2

    # Reset non-existent trajectory does nothing
    adapter.reset("non_existent")
    assert len(adapter._schedulers) == 2

    # Reset t1
    adapter.reset("t1")
    assert "t1" not in adapter._schedulers
    assert "t2" in adapter._schedulers
    assert len(adapter.get_telemetry_summary("t1")) == 0
    assert len(adapter.get_telemetry_summary("t2")) == 1

    # Reset all
    adapter.reset()
    assert len(adapter._schedulers) == 0
    assert len(adapter._histories) == 0
    assert len(adapter.get_telemetry_summary()) == 0


def test_get_telemetry_summary():
    """Verifies get_telemetry_summary filtering and flattening outputs."""
    adapter = SemanticSchedulerAdapter(v_decision=100.0)

    adapter.step([0.5, 0.5], ["A", "B"], cost=10.0, state="s1", trajectory_id="t1")
    adapter.step([1.0, 0.0], ["A", "A"], cost=5.0, state="s2", trajectory_id="t1")
    adapter.step([0.5, 0.5], ["X", "Y"], cost=10.0, state="s1", trajectory_id="t2")

    t1_summary = adapter.get_telemetry_summary("t1")
    assert len(t1_summary) == 2
    assert t1_summary[0]["step_index"] == 0
    assert t1_summary[1]["step_index"] == 1

    t2_summary = adapter.get_telemetry_summary("t2")
    assert len(t2_summary) == 1

    all_summary = adapter.get_telemetry_summary()
    assert len(all_summary) == 3

    empty_summary = adapter.get_telemetry_summary("unknown_traj")
    assert empty_summary == []
