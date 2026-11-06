"""
Semantic Scheduler Adapter for EpistemicOS.

Phase 4 Integration Path:
Design an experimental adapter that makes semantic uncertainty available alongside
existing token-level entropy measurements without modifying default production behavior.

Computes semantic marginal information utility:
    eta_sem,t = (delta_H_sem,t * V_decision) / C_t
where delta_H_sem,t = H_sem,t-1 - H_sem,t (positive value represents uncertainty reduction).

Trajectory Isolation:
- Manages per-trajectory state (_schedulers, _histories, _initial_entropies) to prevent
  cross-request or cross-scenario state contamination.
- Provides reset() method to clear trajectory history.
"""

import math
import uuid
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
    delta_h_sem: Optional[float]
    eta_sem: Optional[float]
    semantic_utility: Optional[float]
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
        if not isinstance(v_decision, (int, float)) or math.isnan(v_decision) or math.isinf(v_decision) or v_decision <= 0.0:
            raise ValueError("v_decision must be a positive finite number")
        self._base_scheduler = scheduler or EntropyAwareScheduler()
        self.estimator = estimator or SemanticUncertaintyEstimator()
        self.v_decision = float(v_decision)

        self._schedulers: Dict[str, EntropyAwareScheduler] = {}
        self._histories: Dict[str, List[DualUncertaintyStepMetrics]] = {}
        self._initial_entropies: Dict[str, Optional[float]] = {}

    def reset(self, trajectory_id: Optional[str] = None) -> None:
        """Clears state for a specific trajectory or all trajectories."""
        if trajectory_id is not None:
            self._schedulers.pop(trajectory_id, None)
            self._histories.pop(trajectory_id, None)
            self._initial_entropies.pop(trajectory_id, None)
        else:
            self._schedulers.clear()
            self._histories.clear()
            self._initial_entropies.clear()

    def _get_trajectory_key(self, trajectory_id: Optional[str], state: Any) -> str:
        if trajectory_id:
            return trajectory_id
        if isinstance(state, str) and state.strip():
            return state
        return "default_trajectory"

    def step(
        self,
        token_probabilities: Any,
        candidates: Sequence[Union[str, Dict[str, Any], Candidate]],
        cost: float,
        state: Any,
        decision_context: Optional[Dict[str, Any]] = None,
        trajectory_id: Optional[str] = None
    ) -> Tuple[DecisionResult, SemanticUncertaintyResult, DualUncertaintyStepMetrics]:
        """
        Executes a scheduler step. Default halting directive is strictly derived from token-level scheduler.
        """
        if not isinstance(cost, (int, float)) or math.isnan(cost) or math.isinf(cost) or cost <= 0.0:
            raise ValueError("Cost must be a positive finite number")

        traj_key = self._get_trajectory_key(trajectory_id, state)

        # Isolated scheduler per trajectory
        if traj_key not in self._schedulers:
            self._schedulers[traj_key] = EntropyAwareScheduler(
                value_of_information=self._base_scheduler.V,
                divergence_threshold=self._base_scheduler.divergence_threshold,
                negative_yield_window=self._base_scheduler.negative_yield_window,
                entropy_delta_threshold=self._base_scheduler.entropy_delta_threshold,
                stagnation_window=self._base_scheduler.stagnation_window,
                confidence_threshold=self._base_scheduler.confidence_threshold,
                utility_epsilon=self._base_scheduler.utility_epsilon,
                minimum_steps_before_convergence=self._base_scheduler.minimum_steps_before_convergence
            )
            self._histories[traj_key] = []
            self._initial_entropies[traj_key] = None

        target_scheduler = self._schedulers[traj_key]
        history = self._histories[traj_key]

        # Execute token scheduler step
        decision_result = target_scheduler.step(token_probabilities, cost, state)
        token_step_metrics = target_scheduler.history[-1]

        # Compute semantic uncertainty
        sem_result = self.estimator.estimate(candidates, decision_context=decision_context)

        step_idx = len(history)
        current_h_sem = sem_result.semantic_entropy_bits

        delta_h_sem: Optional[float] = None
        eta_sem: Optional[float] = None
        semantic_utility: Optional[float] = None

        if sem_result.status == SemanticUncertaintyStatus.VALID and current_h_sem is not None:
            if self._initial_entropies[traj_key] is None:
                self._initial_entropies[traj_key] = current_h_sem

            # Find previous valid step in this trajectory for delta_h_sem calculation
            prev_valid = None
            for prev_m in reversed(history):
                if prev_m.semantic_result.status == SemanticUncertaintyStatus.VALID and prev_m.semantic_result.semantic_entropy_bits is not None:
                    prev_valid = prev_m
                    break

            if prev_valid is not None and prev_valid.semantic_result.semantic_entropy_bits is not None:
                delta_h_sem = prev_valid.semantic_result.semantic_entropy_bits - current_h_sem
                # Sign convention: positive delta_h_sem -> reduction in uncertainty -> positive eta_sem
                eta_sem = (delta_h_sem * self.v_decision) / cost
            else:
                delta_h_sem = 0.0
                eta_sem = 0.0

            init_h = self._initial_entropies[traj_key]
            if init_h is not None:
                semantic_utility = self.v_decision * (init_h - current_h_sem) - target_scheduler.total_cost

        dual_metric = DualUncertaintyStepMetrics(
            step_index=step_idx,
            token_metrics=token_step_metrics,
            semantic_result=sem_result,
            delta_h_sem=delta_h_sem,
            eta_sem=eta_sem,
            semantic_utility=semantic_utility,
            cost=cost
        )
        history.append(dual_metric)

        return decision_result, sem_result, dual_metric

    def get_telemetry_summary(self, trajectory_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if trajectory_id is not None:
            return [m.to_dict() for m in self._histories.get(trajectory_id, [])]
        # Return flattened summary of all histories
        all_metrics = []
        for traj_history in self._histories.values():
            all_metrics.extend([m.to_dict() for m in traj_history])
        return all_metrics
