"""
Unit tests for Semantic Uncertainty Estimator and Semantic Scheduler Adapter.

Phase 5 Synthetic & Adversarial Test Suite covering:
1. Paraphrase invariance
2. Negation sensitivity & double negation
3. Quantity, unit, actor, conditional, and temporal sensitivity
4. Competing hypotheses
5. Confident shared error
6. Single-candidate limitation
7. Malformed and insufficient inputs
8. Resolver ambiguity & unresolved comparisons
9. Decision-sensitive disagreement
10. Duplicate candidate multiplicity & probability aggregation semantics
11. Controlled Paraphrase Multiplicity vs Evidence Accumulation Test
12. Interleaved Trajectories Isolation Test
13. Adapter cost, v_decision, and state safety validation
14. Report verification test for benchmarks/run_semantic_evaluation.py
"""

import json
import math
import os
import pytest

from epistemicos.semantic_uncertainty import (
    SemanticUncertaintyEstimator,
    SemanticUncertaintyStatus,
    Candidate,
    ExactAndNormalizedResolver,
    SemanticResolver,
    SemanticComparisonResult
)
from epistemicos.semantic_adapter import SemanticSchedulerAdapter
from epistemicos.scheduler import EntropyAwareScheduler
from benchmarks.run_semantic_evaluation import run_evaluation


# Scenario 1: Paraphrase invariance
def test_scenario_1_paraphrase_invariance():
    """Multiple phrasings expressing the same conclusion should produce 1 cluster and zero entropy."""
    estimator = SemanticUncertaintyEstimator()
    candidates = [
        "The system execution succeeded with zero errors.",
        "System execution succeeded with zero errors",
        "The system execution succeeded with zero errors!",
        "system execution succeeded with zero errors"
    ]
    res = estimator.estimate(candidates)
    assert res.status == SemanticUncertaintyStatus.VALID
    assert res.num_clusters == 1
    assert res.semantic_entropy_bits == 0.0
    assert res.normalized_semantic_entropy == 0.0
    assert res.semantic_disagreement == 0.0


# Scenario 2: Negation sensitivity & Double Negation
def test_scenario_2_negation_sensitivity():
    """Positive and negative versions of a claim must not be collapsed into the same cluster."""
    estimator = SemanticUncertaintyEstimator()
    candidates = [
        "The request was authorized by the security policy.",
        "The request was not authorized by the security policy."
    ]
    res = estimator.estimate(candidates)
    assert res.status == SemanticUncertaintyStatus.VALID
    assert res.num_clusters == 2
    assert res.semantic_entropy_bits == 1.0  # 1 bit for 2 uniform clusters
    assert res.semantic_disagreement == 1.0


def test_double_negation_simplification():
    """'not unauthorized' should simplify to 'authorized' and be clustered as equivalent."""
    estimator = SemanticUncertaintyEstimator()
    candidates = [
        "The user is authorized to proceed.",
        "The user is not unauthorized to proceed."
    ]
    res = estimator.estimate(candidates)
    assert res.status == SemanticUncertaintyStatus.VALID
    assert res.num_clusters == 1
    assert res.semantic_entropy_bits == 0.0


# Scenario 3: Quantity, Unit, Actor, Conditional, and Temporal Sensitivity
def test_scenario_3_quantity_and_unit_sensitivity():
    """Changes to material numbers, entities, or currency units must be separated into distinct clusters."""
    estimator = SemanticUncertaintyEstimator()
    candidates = [
        "Transfer $500 USD to account 12345.",
        "Transfer $500 EUR to account 12345.",
        "Transfer $5000 USD to account 12345."
    ]
    res = estimator.estimate(candidates)
    assert res.status == SemanticUncertaintyStatus.VALID
    assert res.num_clusters == 3
    assert res.semantic_disagreement == 1.0


def test_actor_role_swap_sensitivity():
    """Actor swaps ('Alice paid Bob' vs 'Bob paid Alice') must be detected as distinct conclusions."""
    estimator = SemanticUncertaintyEstimator()
    candidates = [
        "Alice transferred $100 to Bob.",
        "Bob transferred $100 to Alice."
    ]
    res = estimator.estimate(candidates)
    assert res.status == SemanticUncertaintyStatus.VALID
    assert res.num_clusters == 2
    assert res.semantic_disagreement == 1.0


def test_conditional_and_temporal_sensitivity():
    """Conditional ('approved if verified') and temporal ('valid before 2024') discrepancies must be separated."""
    estimator = SemanticUncertaintyEstimator()

    # Conditionals
    res_cond = estimator.estimate(["The refund is approved.", "The refund is approved if verified."])
    assert res_cond.num_clusters == 2

    # Temporal
    res_temp = estimator.estimate(["Access granted before midnight.", "Access granted after midnight."])
    assert res_temp.num_clusters == 2


# Scenario 4: Competing hypotheses
def test_scenario_4_competing_hypotheses():
    """Genuinely different conclusions produce non-zero semantic cluster entropy."""
    estimator = SemanticUncertaintyEstimator()
    candidates = [
        {"text": "Diagnosis is influenza type A", "probability": 0.5},
        {"text": "Diagnosis is acute bacterial pneumonia", "probability": 0.5}
    ]
    res = estimator.estimate(candidates)
    assert res.status == SemanticUncertaintyStatus.VALID
    assert res.num_clusters == 2
    assert res.semantic_entropy_bits == 1.0
    assert res.normalized_semantic_entropy == 1.0


# Scenario 5: Confident shared error
def test_scenario_5_confident_shared_error():
    """
    Repeated agreement on an incorrect answer produces LOW semantic uncertainty,
    demonstrating that low semantic entropy DOES NOT equal factual correctness.
    """
    estimator = SemanticUncertaintyEstimator()
    false_candidates = [
        "The capital of Australia is Sydney.",
        "The capital city of Australia is Sydney.",
        "Sydney is the capital of Australia."
    ]
    res = estimator.estimate(false_candidates)
    assert res.status == SemanticUncertaintyStatus.VALID
    assert res.num_clusters == 1
    assert res.semantic_entropy_bits == 0.0
    assert res.factual_correctness is None
    assert res.evidence_sufficiency is None


# Scenario 6: Single-candidate limitation
def test_scenario_6_single_candidate_limitation():
    """One candidate must produce INSUFFICIENT_EVIDENCE status, not validated convergence."""
    estimator = SemanticUncertaintyEstimator()
    candidates = ["The server response time was 42ms."]
    res = estimator.estimate(candidates)
    assert res.status == SemanticUncertaintyStatus.INSUFFICIENT_EVIDENCE
    assert res.candidates_analyzed == 1
    assert res.num_clusters == 1


# Scenario 7: Malformed and insufficient inputs
def test_scenario_7_malformed_inputs():
    """Empty inputs, NaN probabilities, or non-string elements return MALFORMED_INPUT status safely."""
    estimator = SemanticUncertaintyEstimator()

    assert estimator.estimate([]).status == SemanticUncertaintyStatus.MALFORMED_INPUT
    assert estimator.estimate([{"text": "A", "probability": float("nan")}, {"text": "B", "probability": 0.5}]).status == SemanticUncertaintyStatus.MALFORMED_INPUT
    assert estimator.estimate([{"text": "A", "probability": -0.1}, {"text": "B", "probability": 0.5}]).status == SemanticUncertaintyStatus.MALFORMED_INPUT
    assert estimator.estimate(["", "Valid text"]).status == SemanticUncertaintyStatus.MALFORMED_INPUT


# Scenario 8: Resolver ambiguity
class AmbiguousResolver(SemanticResolver):
    """Custom resolver simulating high ambiguity / low confidence comparisons."""
    def resolve(self, candidate_a: Candidate, candidate_b: Candidate) -> SemanticComparisonResult:
        return SemanticComparisonResult(
            is_equivalent=False,
            similarity_score=0.5,
            resolver_confidence=0.3
        )


def test_scenario_8_resolver_ambiguity():
    """Uncertain semantic comparisons produce UNRESOLVED_COMPARISON status rather than false precision."""
    estimator = SemanticUncertaintyEstimator(resolver=AmbiguousResolver())
    candidates = ["Quantum state alpha", "Quantum state beta"]
    res = estimator.estimate(candidates)
    assert res.status == SemanticUncertaintyStatus.UNRESOLVED_COMPARISON
    assert res.resolver_ambiguity > 0.4


# Scenario 9: Decision-sensitive disagreement
def test_scenario_9_decision_sensitive_disagreement():
    """Semantically different candidates that imply different downstream actions are flagged."""
    estimator = SemanticUncertaintyEstimator()

    candidates = [
        Candidate(text="Database load is high.", action="SCALE_UP"),
        Candidate(text="Database load is normal.", action="NO_ACTION")
    ]
    res = estimator.estimate(candidates)
    assert res.status == SemanticUncertaintyStatus.VALID
    assert res.decision_sensitive_disagreement == 1.0


# Controlled Paraphrase Multiplicity vs Evidence Accumulation Test
def test_controlled_paraphrase_multiplicity_vs_evidence():
    """
    Directly verifies whether the estimator distinguishes paraphrase multiplicity
    (adding more phrasings of hypothesis A) from evidence accumulation (increasing A's probability).
    """
    estimator = SemanticUncertaintyEstimator()

    # 1. Equal Baseline Support: Hypothesis A (p=0.5) vs Hypothesis B (p=0.5)
    base_candidates = [
        {"text": "Diagnosis is Influenza Type A", "probability": 0.5},
        {"text": "Diagnosis is Acute Bacterial Pneumonia", "probability": 0.5}
    ]
    res_base = estimator.estimate(base_candidates)
    assert res_base.num_clusters == 2
    assert res_base.semantic_entropy_bits == 1.0
    cluster_a_prob_base = res_base.cluster_distribution[0].probability
    assert pytest.approx(cluster_a_prob_base, 1e-4) == 0.5

    # 2. Paraphrase Multiplicity: Splitting Hypothesis A's 0.5 mass across 2 paraphrases
    paraphrased_candidates = [
        {"text": "Diagnosis is Influenza Type A", "probability": 0.25},
        {"text": "Diagnosis is Type A Influenza", "probability": 0.25},
        {"text": "Diagnosis is Acute Bacterial Pneumonia", "probability": 0.50}
    ]
    res_para = estimator.estimate(paraphrased_candidates)
    assert res_para.num_clusters == 2
    # Cluster A's aggregated mass remains 0.25 + 0.25 = 0.50, and semantic entropy remains exactly 1.0 bit!
    assert pytest.approx(res_para.semantic_entropy_bits, 1e-4) == 1.0
    cluster_a_prob_para = [c.probability for c in res_para.cluster_distribution if "Influenza" in c.representative_text][0]
    assert pytest.approx(cluster_a_prob_para, 1e-4) == 0.50

    # 3. Genuine Evidence Accumulation: Evidence for Hypothesis A increases (p=0.8), Hypothesis B drops (p=0.2)
    evidence_candidates = [
        {"text": "Diagnosis is Influenza Type A", "probability": 0.80},
        {"text": "Diagnosis is Acute Bacterial Pneumonia", "probability": 0.20}
    ]
    res_evid = estimator.estimate(evidence_candidates)
    assert res_evid.num_clusters == 2
    # Semantic entropy decreases from 1.0 bit to ~0.72 bits as evidence accumulates for A!
    assert res_evid.semantic_entropy_bits < 0.80
    expected_entropy = -0.8 * math.log2(0.8) - 0.2 * math.log2(0.2)
    assert pytest.approx(res_evid.semantic_entropy_bits, 1e-4) == expected_entropy


# Interleaved Trajectories Isolation Test
def test_interleaved_trajectories_isolation():
    """Verifies that SemanticSchedulerAdapter maintains isolated states for interleaved trajectory IDs."""
    adapter = SemanticSchedulerAdapter(v_decision=100.0)

    # Step 1 on Trajectory 1
    cand_t1_s1 = ["Approve transaction $10", "Deny transaction $10"]
    _, sem_t1_s1, metric_t1_s1 = adapter.step([0.5, 0.5], cand_t1_s1, cost=10.0, state="s1", trajectory_id="traj_1")
    assert sem_t1_s1.semantic_entropy_bits == 1.0
    assert metric_t1_s1.delta_h_sem == 0.0

    # Interleaved Step 1 on Trajectory 2
    cand_t2_s1 = ["Approve transaction $100", "Approve transaction $100"]
    _, sem_t2_s1, metric_t2_s1 = adapter.step([1.0, 0.0], cand_t2_s1, cost=10.0, state="s1", trajectory_id="traj_2")
    assert sem_t2_s1.semantic_entropy_bits == 0.0
    assert metric_t2_s1.delta_h_sem == 0.0

    # Step 2 on Trajectory 1 (delta_h_sem must be computed relative to Trajectory 1 Step 1, NOT Trajectory 2!)
    cand_t1_s2 = ["Approve transaction $10", "Approve transaction $10"]
    _, sem_t1_s2, metric_t1_s2 = adapter.step([1.0, 0.0], cand_t1_s2, cost=5.0, state="s2", trajectory_id="traj_1")
    assert sem_t1_s2.semantic_entropy_bits == 0.0
    # delta_h_sem = 1.0 (from traj_1 s1) - 0.0 = 1.0
    assert metric_t1_s2.delta_h_sem == 1.0
    assert pytest.approx(metric_t1_s2.eta_sem, 1e-4) == 20.0

    # Step 2 on Trajectory 2
    cand_t2_s2 = ["Approve transaction $100", "Deny transaction $100"]
    _, sem_t2_s2, metric_t2_s2 = adapter.step([0.5, 0.5], cand_t2_s2, cost=5.0, state="s2", trajectory_id="traj_2")
    assert sem_t2_s2.semantic_entropy_bits == 1.0
    # delta_h_sem = 0.0 (from traj_2 s1) - 1.0 = -1.0
    assert metric_t2_s2.delta_h_sem == -1.0


# Adapter cost & v_decision validation & invalid state safety
def test_adapter_validation_and_safety():
    adapter = SemanticSchedulerAdapter(v_decision=100.0)

    # Invalid cost raises ValueError
    with pytest.raises(ValueError, match="Cost must be a positive finite number"):
        adapter.step([0.5, 0.5], ["A", "B"], cost=0.0, state="s1")

    with pytest.raises(ValueError, match="Cost must be a positive finite number"):
        adapter.step([0.5, 0.5], ["A", "B"], cost=-5.0, state="s1")

    with pytest.raises(ValueError, match="v_decision must be a positive finite number"):
        SemanticSchedulerAdapter(v_decision=0.0)

    # Single candidate input (status = INSUFFICIENT_EVIDENCE) sets eta_sem to None
    dec, sem, metric = adapter.step([1.0], ["Single"], cost=10.0, state="s1")
    assert sem.status == SemanticUncertaintyStatus.INSUFFICIENT_EVIDENCE
    assert metric.eta_sem is None
    assert metric.semantic_utility is None


# Evaluation Harness Report Verification
def test_evaluation_harness_report_structure():
    """Verifies that run_evaluation() outputs valid, non-hardcoded report structure."""
    report = run_evaluation()
    assert report["harness_type"] == "SYNTHETIC_CONCEPTUAL_DEMONSTRATION"
    assert len(report["eval_scenarios"]) == 5
    assert len(report["measured_empirical_findings"]) == 5

    # Check scenario 1 measured findings
    scen1 = report["eval_scenarios"][0]
    assert scen1["signals"]["synthetic_token_entropy_bits"] == 2.0
    assert scen1["signals"]["semantic_entropy_bits"] == 0.0
