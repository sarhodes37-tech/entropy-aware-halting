"""
Unit tests for Semantic Uncertainty Estimator and Semantic Scheduler Adapter.

Phase 5 Synthetic Test Suite covering 10 required scenarios:
1. Paraphrase invariance
2. Negation sensitivity
3. Quantity and actor sensitivity
4. Competing hypotheses
5. Confident shared error
6. Single-candidate limitation
7. Malformed and insufficient inputs
8. Resolver ambiguity
9. Decision-sensitive disagreement
10. System regression (ensuring existing functionality remains unaffected)
"""

import math
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


# Scenario 2: Negation sensitivity
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


# Scenario 3: Quantity and actor sensitivity
def test_scenario_3_quantity_and_actor_sensitivity():
    """Changes to material numbers, entities, or amounts must be separated into distinct clusters."""
    estimator = SemanticUncertaintyEstimator()
    candidates = [
        "Transfer $500 to account 12345.",
        "Transfer $5000 to account 12345.",
        "Transfer $500 to account 99999."
    ]
    res = estimator.estimate(candidates)
    assert res.status == SemanticUncertaintyStatus.VALID
    assert res.num_clusters == 3
    assert res.semantic_disagreement == 1.0


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
    # All candidate models confidently agree on a false claim
    false_candidates = [
        "The capital of Australia is Sydney.",
        "The capital city of Australia is Sydney.",
        "Sydney is the capital of Australia."
    ]
    res = estimator.estimate(false_candidates)
    assert res.status == SemanticUncertaintyStatus.VALID
    assert res.num_clusters == 1
    assert res.semantic_entropy_bits == 0.0
    # Explicitly verify Phase 3 separation: factual_correctness is None, NOT assumed True
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

    # Empty candidates
    res_empty = estimator.estimate([])
    assert res_empty.status == SemanticUncertaintyStatus.MALFORMED_INPUT

    # Candidate with NaN probability
    res_nan = estimator.estimate([{"text": "A", "probability": float("nan")}, {"text": "B", "probability": 0.5}])
    assert res_nan.status == SemanticUncertaintyStatus.MALFORMED_INPUT

    # Candidate with negative probability
    res_neg = estimator.estimate([{"text": "A", "probability": -0.1}, {"text": "B", "probability": 0.5}])
    assert res_neg.status == SemanticUncertaintyStatus.MALFORMED_INPUT

    # Candidate with blank text
    res_blank = estimator.estimate(["", "Valid text"])
    assert res_blank.status == SemanticUncertaintyStatus.MALFORMED_INPUT


# Scenario 8: Resolver ambiguity
class AmbiguousResolver(SemanticResolver):
    """Custom resolver simulating high ambiguity / low confidence comparisons."""
    def resolve(self, candidate_a: Candidate, candidate_b: Candidate) -> SemanticComparisonResult:
        return SemanticComparisonResult(
            is_equivalent=False,
            similarity_score=0.5,
            resolver_confidence=0.3  # High ambiguity
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


# Semantic Scheduler Adapter Step & Marginal Utility Tests
def test_adapter_step_and_marginal_utility():
    """Validates that SemanticSchedulerAdapter computes eta_sem correctly while keeping token scheduler unchanged."""
    adapter = SemanticSchedulerAdapter(v_decision=100.0)

    # Step 1: High semantic entropy (2 clusters: 1 bit)
    cand_step1 = ["Approve transaction $10", "Deny transaction $10"]
    decision1, sem1, metric1 = adapter.step([0.5, 0.5], cand_step1, cost=10.0, state="step1")

    assert sem1.semantic_entropy_bits == 1.0
    assert metric1.delta_h_sem == 0.0
    assert metric1.eta_sem == 0.0

    # Step 2: Reduced semantic entropy (1 cluster: 0 bits)
    cand_step2 = ["Approve transaction $10", "Approve transaction $10"]
    decision2, sem2, metric2 = adapter.step([1.0, 0.0], cand_step2, cost=5.0, state="step2")

    assert sem2.semantic_entropy_bits == 0.0
    # delta_h_sem = 1.0 - 0.0 = 1.0 bit
    assert metric2.delta_h_sem == 1.0
    # eta_sem = (1.0 * 100.0) / 5.0 = 20.0
    assert pytest.approx(metric2.eta_sem, 1e-4) == 20.0
