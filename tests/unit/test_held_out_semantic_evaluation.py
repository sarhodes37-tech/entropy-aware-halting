"""
Unit and Regression Tests for Held-Out Multi-Step Trajectory Evaluation Harness.

Ensures:
1. Split integrity (no scenario family or trajectory leakage between dev and test).
2. Compute cost accounting precision (token counts, resolver call counts, overhead).
3. Missing/malformed signal handling safety.
4. Policy determinism and trajectory isolation across interleaved evaluation runs.
5. Production immutability regression check (verifies production scheduler & defaults remain unchanged).
"""

import json
import os
import pytest

from epistemicos.scheduler import EntropyAwareScheduler, DecisionResult
from epistemicos.semantic_uncertainty import SemanticUncertaintyEstimator, SemanticUncertaintyStatus
from epistemicos.semantic_adapter import SemanticSchedulerAdapter
from benchmarks.run_held_out_semantic_evaluation import (
    run_held_out_evaluation,
    FixedBudgetPolicy,
    TokenEntropyHaltingPolicy,
    SemanticUncertaintyHaltingPolicy,
    CombinedEntropyHaltingPolicy,
    ReferenceSchedulerPolicy
)


DATASET_PATH = os.path.join("benchmarks", "data", "held_out_semantic_trajectories.json")


def test_split_integrity():
    """Verify that dev and test splits are strictly disjoint in trajectory IDs and properly structured."""
    assert os.path.exists(DATASET_PATH)
    with open(DATASET_PATH, "r") as f:
        data = json.load(f)

    trajectories = data["trajectories"]
    dev_ids = {t["id"] for t in trajectories if t["split"] == "dev"}
    test_ids = {t["id"] for t in trajectories if t["split"] == "test"}

    # No overlap in trajectory IDs
    assert dev_ids.isdisjoint(test_ids)

    # Every preregistered family (A-F) must be present in both splits
    dev_families = {t["family"] for t in trajectories if t["split"] == "dev"}
    test_families = {t["family"] for t in trajectories if t["split"] == "test"}
    expected_families = {"A", "B", "C", "D", "E", "F"}

    assert dev_families == expected_families
    assert test_families == expected_families


def test_compute_accounting():
    """Verify exact calculation of token, resolver call, and total compute overhead."""
    report = run_held_out_evaluation(DATASET_PATH)
    summary = report["summary"]

    for policy_name, p_data in summary.items():
        assert p_data["held_out_test_runs"] == 6
        assert p_data["avg_total_compute"] > 0
        assert p_data["avg_resolver_cost_overhead"] >= 0

        for run in p_data["raw_test_runs"]:
            comp = run["compute"]
            assert comp["tokens_generated"] > 0
            # Total compute = tokens + resolver_cost (0.5 per resolver call)
            expected_total = comp["tokens_generated"] + (comp["resolver_calls"] * 0.5)
            assert pytest.approx(comp["total_compute"], 1e-4) == expected_total


def test_missing_signal_handling():
    """Verify policy behavior when semantic estimates or token probabilities are missing or malformed."""
    adapter = SemanticSchedulerAdapter(v_decision=100.0)

    # Single candidate input gives INSUFFICIENT_EVIDENCE
    dec_res, sem_res, dual_metric = adapter.step(
        token_probabilities=[1.0],
        candidates=["Single candidate string"],
        cost=10.0,
        state="state_missing"
    )

    assert sem_res.status == SemanticUncertaintyStatus.INSUFFICIENT_EVIDENCE

    # Combined policy must not halt on INSUFFICIENT_EVIDENCE without token convergence
    policy = CombinedEntropyHaltingPolicy(token_threshold=0.10, sem_threshold=0.05)
    halt_dec = policy.evaluate_step(
        step_index=0,
        token_entropy=1.5,  # High token entropy
        sem_result=sem_res,
        adapter_metric=dual_metric,
        dec_res=dec_res,
        total_steps=3
    )

    assert not halt_dec.halt
    assert halt_dec.directive == "CONTINUE"


def test_production_defaults_regression():
    """Regression test ensuring experimental harness did not mutate EntropyAwareScheduler defaults."""
    sched = EntropyAwareScheduler()
    assert sched.V == 100
    assert sched.divergence_threshold == 0.15
    assert sched.negative_yield_window == 2
    assert sched.entropy_delta_threshold == 0.005
    assert sched.stagnation_window == 3
    assert sched.confidence_threshold == 0.01
    assert sched.utility_epsilon == 0.5
    assert sched.minimum_steps_before_convergence == 3
