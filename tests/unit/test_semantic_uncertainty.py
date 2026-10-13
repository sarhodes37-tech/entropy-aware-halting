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
11. Adapter cost, v_decision, and state safety validation
12. Report verification test for benchmarks/run_semantic_evaluation.py
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


# Duplicate candidate multiplicity & probability aggregation semantics
def test_duplicate_candidate_probability_aggregation():
    """Repeated candidates aggregate their sample probabilities into the single semantic cluster."""
    estimator = SemanticUncertaintyEstimator()
    candidates = [
        {"text": "Result A", "probability": 0.3},
        {"text": "Result A", "probability": 0.3},
        {"text": "Result B", "probability": 0.4}
    ]
    res = estimator.estimate(candidates)
    assert res.status == SemanticUncertaintyStatus.VALID
    assert res.num_clusters == 2
    # Cluster 0 ("Result A") should have aggregated mass 0.3 + 0.3 = 0.6
    # Cluster 1 ("Result B") should have mass 0.4
    cluster_a = [c for c in res.cluster_distribution if "Result A" in c.representative_text][0]
    assert pytest.approx(cluster_a.probability, 1e-4) == 0.6


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
    assert len(report["measured_empirical_findings"]) == 4

    # Check scenario 1 measured findings
    scen1 = report["eval_scenarios"][0]
    assert scen1["signals"]["synthetic_token_entropy_bits"] == 2.0
    assert scen1["signals"]["semantic_entropy_bits"] == 0.0
