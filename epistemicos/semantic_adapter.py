"""
Semantic Scheduler Adapter for EpistemicOS.

Phase 4 Integration Path:
Design an experimental adapter that makes semantic uncertainty available alongside
existing token-level entropy measurements without modifying default production behavior.

Computes semantic marginal information utility:
    eta_sem,t = (delta_H_sem,t * V_decision) / C_t
where delta_H_sem,t = H_sem,t-1 - H_sem,t (positive value represents uncertainty reduction).

Does not add token entropy and semantic entropy together, nor alter existing halting thresholds.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from epistemicos.scheduler import EntropyAwareScheduler, StepMetrics, DecisionResult
from epistemicos.semantic_uncertainty import (
    SemanticUncertaintyEstimator,
    SemanticUncertaintyResult,
    SemanticUncertaintyStatus,
    Candidate
)


@dataclass
class DualUncertaintyStepMetrics:
    """Combines token-level StepMetrics and SemanticUncertaintyResult for step-wise evaluation."""
    step_index: int
    token_metrics: StepMetrics
    semantic_result: SemanticUncertaintyResult
    delta_h_sem: float
    eta_sem: float
    semantic_utility: float
    cost: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_index": self.step_index,
            "token_entropy": self.token_metrics.entropy,
            "token_delta_h": self.token_metrics.delta_h,
            "token_eta": self.token_metrics.eta,
            "token_utility": self.token_metrics.utility,
            "semantic_entropy_bits": self.semantic_result.semantic_entropy_bits,
            "semantic_normalized_entropy": self.semantic_result.normalized_semantic_entropy,
            "semantic_disagreement": self.semantic_result.semantic_disagreement,
            "decision_sensitive_disagreement": self.semantic_result.decision_sensitive_disagreement,
            "delta_h_sem": self.delta_h_sem,
            "eta_sem": self.eta_sem,
            "semantic_utility": self.semantic_utility,
            "cost": self.cost,
            "status": self.semantic_result.status.value,
            "candidates_analyzed": self.semantic_result.candidates_analyzed,
            "num_clusters": self.semantic_result.num_clusters,
        }


class SemanticSchedulerAdapter:
    """
    Experimental evaluation wrapper around EntropyAwareScheduler and SemanticUncertaintyEstimator.

    Preserves default production behavior of EntropyAwareScheduler while recording parallel
    semantic uncertainty signals and calculating semantic marginal utility.
    """

    def __init__(
        self,
        scheduler: Optional[EntropyAwareScheduler] = None,
        estimator: Optional[SemanticUncertaintyEstimator] = None,
        v_decision: float = 100.0
    ):
        if v_decision <= 0.0:
            raise ValueError("v_decision must be positive")
        self.scheduler = scheduler or EntropyAwareScheduler()
        self.estimator = estimator or SemanticUncertaintyEstimator()
        self.v_decision = v_decision

        self.dual_history: List[DualUncertaintyStepMetrics] = []
        self.initial_semantic_entropy: Optional[float] = None

    def step(
        self,
        token_probabilities: Any,
        candidates: Sequence[Union[str, Dict[str, Any], Candidate]],
        cost: float,
        state: Any,
        decision_context: Optional[Dict[str, Any]] = None
    ) -> Tuple[DecisionResult, SemanticUncertaintyResult, DualUncertaintyStepMetrics]:
        """
        Executes a scheduler step. Default halting directive is strictly derived from token-level scheduler.
        """
        # Execute token scheduler step (leaves production halting logic untouched)
        decision_result = self.scheduler.step(token_probabilities, cost, state)
        token_step_metrics = self.scheduler.history[-1]

        # Compute semantic uncertainty
        sem_result = self.estimator.estimate(candidates, decision_context=decision_context)

        step_idx = len(self.dual_history)
        current_h_sem = sem_result.semantic_entropy_bits

        # Compute delta_h_sem and eta_sem
        delta_h_sem = 0.0
        eta_sem = 0.0
        semantic_utility = 0.0

        if current_h_sem is not None:
            if self.initial_semantic_entropy is None and sem_result.status == SemanticUncertaintyStatus.VALID:
                self.initial_semantic_entropy = current_h_sem

            if step_idx > 0 and self.dual_history[-1].semantic_result.semantic_entropy_bits is not None:
                prev_h_sem = self.dual_history[-1].semantic_result.semantic_entropy_bits
                delta_h_sem = prev_h_sem - current_h_sem

                if cost > 0.0:
                    # Sign convention: positive delta_h_sem -> reduction in uncertainty -> positive eta_sem
                    eta_sem = (delta_h_sem * self.v_decision) / cost

            if self.initial_semantic_entropy is not None:
                semantic_utility = self.v_decision * (self.initial_semantic_entropy - current_h_sem) - self.scheduler.total_cost

        dual_metric = DualUncertaintyStepMetrics(
            step_index=step_idx,
            token_metrics=token_step_metrics,
            semantic_result=sem_result,
            delta_h_sem=delta_h_sem,
            eta_sem=eta_sem,
            semantic_utility=semantic_utility,
            cost=cost
        )
        self.dual_history.append(dual_metric)

        return decision_result, sem_result, dual_metric

    def get_telemetry_summary(self) -> List[Dict[str, Any]]:
        return [m.to_dict() for m in self.dual_history]
