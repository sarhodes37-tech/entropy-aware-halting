"""
Held-Out Multi-Step Trajectory Evaluation Harness for Semantic Uncertainty Halting.

Executes 5 explicitly named halting policy conditions across preregistered multi-step trajectory
scenario families (A-F), tracking detailed compute costs (tokens, steps, resolver calls, overhead),
evaluating decision quality, premature halting, and unnecessary continuation rates, and computing
bootstrap 95% confidence intervals (B=1000) and Quality vs Compute curve statistics.
"""

import math
import json
import os
import random
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Sequence

from epistemicos.scheduler import EntropyAwareScheduler, DecisionResult
from epistemicos.semantic_uncertainty import (
    SemanticUncertaintyEstimator,
    SemanticUncertaintyResult,
    SemanticUncertaintyStatus,
    Candidate
)
from epistemicos.semantic_adapter import SemanticSchedulerAdapter


@dataclass
class PolicyHaltingDecision:
    halt: bool
    directive: str
    step_halted: int
    reason: str


class HaltingPolicy:
    """Abstract Base Class for Halting Policies in the Evaluation Harness."""
    name: str

    def evaluate_step(
        self,
        step_index: int,
        token_entropy: float,
        sem_result: SemanticUncertaintyResult,
        adapter_metric: Any,
        dec_res: DecisionResult,
        total_steps: int
    ) -> PolicyHaltingDecision:
        raise NotImplementedError


class FixedBudgetPolicy(HaltingPolicy):
    """Condition 1: Fixed-Budget Baseline - Continues until budget is exhausted."""

    def __init__(self, max_steps: int = 4):
        self.name = "1. Fixed-Budget Baseline"
        self.max_steps = max_steps

    def evaluate_step(
        self,
        step_index: int,
        token_entropy: float,
        sem_result: SemanticUncertaintyResult,
        adapter_metric: Any,
        dec_res: DecisionResult,
        total_steps: int
    ) -> PolicyHaltingDecision:
        if step_index >= self.max_steps - 1 or step_index >= total_steps - 1:
            return PolicyHaltingDecision(True, "BUDGET_EXHAUSTED", step_index, "Reached max step budget")
        return PolicyHaltingDecision(False, "CONTINUE", step_index, "Budget remains")


class TokenEntropyHaltingPolicy(HaltingPolicy):
    """Condition 2: Token-Entropy Halting - Uses token entropy alone."""

    def __init__(self, threshold: float = 0.10):
        self.name = "2. Token-Entropy Halting"
        self.threshold = threshold

    def evaluate_step(
        self,
        step_index: int,
        token_entropy: float,
        sem_result: SemanticUncertaintyResult,
        adapter_metric: Any,
        dec_res: DecisionResult,
        total_steps: int
    ) -> PolicyHaltingDecision:
        if token_entropy < self.threshold:
            return PolicyHaltingDecision(True, "TOKEN_ENTROPY_CONVERGENCE", step_index, f"Token entropy {token_entropy:.4f} < {self.threshold}")
        if step_index >= total_steps - 1:
            return PolicyHaltingDecision(True, "MAX_STEPS_REACHED", step_index, "Trajectory ended")
        return PolicyHaltingDecision(False, "CONTINUE", step_index, "Token entropy above threshold")


class SemanticUncertaintyHaltingPolicy(HaltingPolicy):
    """Condition 3: Semantic-Uncertainty Halting - Uses semantic uncertainty alone."""

    def __init__(self, sem_entropy_threshold: float = 0.05):
        self.name = "3. Semantic-Uncertainty Halting"
        self.threshold = sem_entropy_threshold

    def evaluate_step(
        self,
        step_index: int,
        token_entropy: float,
        sem_result: SemanticUncertaintyResult,
        adapter_metric: Any,
        dec_res: DecisionResult,
        total_steps: int
    ) -> PolicyHaltingDecision:
        if sem_result.status == SemanticUncertaintyStatus.VALID:
            if sem_result.normalized_semantic_entropy is not None and sem_result.normalized_semantic_entropy <= self.threshold:
                return PolicyHaltingDecision(True, "SEMANTIC_CONVERGENCE", step_index, f"Normalized semantic entropy {sem_result.normalized_semantic_entropy:.4f} <= {self.threshold}")
        if step_index >= total_steps - 1:
            return PolicyHaltingDecision(True, "MAX_STEPS_REACHED", step_index, "Trajectory ended")
        return PolicyHaltingDecision(False, "CONTINUE", step_index, "Semantic uncertainty above threshold")


class CombinedEntropyHaltingPolicy(HaltingPolicy):
    """Condition 4: Combined Policy - Uses both signals with a joint decision rule."""

    def __init__(self, token_threshold: float = 0.10, sem_threshold: float = 0.05):
        self.name = "4. Combined Policy"
        self.token_threshold = token_threshold
        self.sem_threshold = sem_threshold

    def evaluate_step(
        self,
        step_index: int,
        token_entropy: float,
        sem_result: SemanticUncertaintyResult,
        adapter_metric: Any,
        dec_res: DecisionResult,
        total_steps: int
    ) -> PolicyHaltingDecision:
        if sem_result.status == SemanticUncertaintyStatus.VALID:
            norm_sem = sem_result.normalized_semantic_entropy
            # Dual convergence rule or decision-sensitive disagreement resolution
            if norm_sem is not None and norm_sem <= self.sem_threshold and token_entropy < self.token_threshold:
                return PolicyHaltingDecision(True, "DUAL_CONVERGENCE", step_index, "Both token and semantic entropy converged")
            if step_index >= 1 and sem_result.decision_sensitive_disagreement == 0.0 and norm_sem == 0.0:
                return PolicyHaltingDecision(True, "DECISION_CONSENSUS", step_index, "Zero decision-sensitive disagreement achieved")
        if step_index >= total_steps - 1:
            return PolicyHaltingDecision(True, "MAX_STEPS_REACHED", step_index, "Trajectory ended")
        return PolicyHaltingDecision(False, "CONTINUE", step_index, "Signals continue")


class ReferenceSchedulerPolicy(HaltingPolicy):
    """Condition 5: Reference Condition - Production EntropyAwareScheduler decision result."""

    def __init__(self):
        self.name = "5. Reference Scheduler Policy"

    def evaluate_step(
        self,
        step_index: int,
        token_entropy: float,
        sem_result: SemanticUncertaintyResult,
        adapter_metric: Any,
        dec_res: DecisionResult,
        total_steps: int
    ) -> PolicyHaltingDecision:
        # Use actual production scheduler halt decision from adapter.step()
        if dec_res.halt:
            return PolicyHaltingDecision(True, dec_res.directive, step_index, f"Production scheduler directive: {dec_res.directive}")
        if step_index >= total_steps - 1:
            return PolicyHaltingDecision(True, "MAX_STEPS_REACHED", step_index, "Trajectory ended")
        return PolicyHaltingDecision(False, "CONTINUE", step_index, "Reference scheduler continuing")


def compute_bootstrap_ci(scores: List[float], num_samples: int = 1000, ci_level: float = 0.95, seed: int = 42) -> Tuple[float, float]:
    """Computes bootstrap confidence interval over scenario quality scores."""
    if not scores:
        return 0.0, 0.0
    rng = random.Random(seed)
    n = len(scores)
    means = []
    for _ in range(num_samples):
        sample = [rng.choice(scores) for _ in range(n)]
        means.append(sum(sample) / n)
    means.sort()
    lower_idx = int((1.0 - ci_level) / 2.0 * num_samples)
    upper_idx = int((1.0 - (1.0 - ci_level) / 2.0) * num_samples) - 1
    return means[lower_idx], means[min(upper_idx, num_samples - 1)]


def run_held_out_evaluation(dataset_path: str) -> Dict[str, Any]:
    with open(dataset_path, "r") as f:
        data = json.load(f)

    trajectories = data["trajectories"]

    policies: List[HaltingPolicy] = [
        FixedBudgetPolicy(max_steps=4),
        TokenEntropyHaltingPolicy(threshold=0.10),
        SemanticUncertaintyHaltingPolicy(sem_entropy_threshold=0.05),
        CombinedEntropyHaltingPolicy(token_threshold=0.10, sem_threshold=0.05),
        ReferenceSchedulerPolicy()
    ]

    policy_results = {p.name: [] for p in policies}

    for traj in trajectories:
        traj_id = traj["id"]
        split = traj["split"]
        family = traj["family"]
        family_name = traj["family_name"]
        ground_truth = traj["ground_truth"]
        steps = traj["steps"]
        total_steps = len(steps)

        # Pre-compute step signals to ensure exact signal matching across policies
        step_records = []
        adapter = SemanticSchedulerAdapter(v_decision=100.0)

        for step_data in steps:
            s_idx = step_data["step_index"]
            cands = step_data["candidates"]
            probs = [c.get("probability", 1.0 / len(cands)) for c in cands]
            if not probs or None in probs:
                probs = [1.0 / len(cands)] * len(cands)

            # Compute logprobs entropy if present or probs entropy
            if "token_logprobs" in step_data:
                lps = step_data["token_logprobs"]
                unnorm = [math.exp(lp) for lp in lps]
                sum_u = sum(unnorm)
                tok_probs = [u / sum_u for u in unnorm]
            else:
                tok_probs = probs

            dec_res, sem_res, dual_metric = adapter.step(
                token_probabilities=tok_probs,
                candidates=cands,
                cost=10.0,
                state=f"{traj_id}_s{s_idx}",
                trajectory_id=traj_id
            )

            # Record compute accounting
            tokens_gen = step_data.get("tokens_generated", 10)
            num_cands = len(cands)
            resolver_calls = (num_cands * (num_cands - 1)) // 2 if num_cands > 1 else 0
            resolver_overhead = resolver_calls * 0.5  # Standardized resolver cost units

            step_records.append({
                "step_index": s_idx,
                "token_entropy": dual_metric.token_metrics.entropy,
                "sem_result": sem_res,
                "dual_metric": dual_metric,
                "dec_res": dec_res,
                "tokens_generated": tokens_gen,
                "resolver_calls": resolver_calls,
                "resolver_overhead": resolver_overhead,
                "step_cost": tokens_gen + resolver_overhead
            })

        # Evaluate each policy on this trajectory
        for policy in policies:
            halted_step = total_steps - 1
            final_decision = None

            accum_tokens = 0
            accum_resolver_calls = 0
            accum_resolver_cost = 0.0
            accum_total_compute = 0.0

            for record in step_records:
                s_idx = record["step_index"]
                accum_tokens += record["tokens_generated"]
                accum_resolver_calls += record["resolver_calls"]
                accum_resolver_cost += record["resolver_overhead"]
                accum_total_compute += record["step_cost"]

                halt_dec = policy.evaluate_step(
                    step_index=s_idx,
                    token_entropy=record["token_entropy"],
                    sem_result=record["sem_result"],
                    adapter_metric=record["dual_metric"],
                    dec_res=record["dec_res"],
                    total_steps=total_steps
                )

                if halt_dec.halt:
                    halted_step = s_idx
                    final_decision = halt_dec
                    break

            if final_decision is None:
                halted_step = total_steps - 1
                final_decision = PolicyHaltingDecision(True, "END_OF_TRAJECTORY", halted_step, "Reached trajectory end")

            # Score Decision Quality against Ground Truth
            optimal_step = ground_truth["optimal_step"]
            is_correct_step = (halted_step == optimal_step) or (halted_step >= optimal_step and ground_truth["optimal_action"] == "HALT")

            # Premature halting & unnecessary continuation
            premature_halt = (halted_step < optimal_step)
            unnecessary_continuation = (halted_step > optimal_step)

            # Quality Score Q in [0, 1]
            if premature_halt:
                quality_score = 0.2
            elif is_correct_step or halted_step == optimal_step:
                quality_score = 1.0
            else:
                quality_score = max(0.0, 1.0 - 0.25 * (halted_step - optimal_step))

            policy_results[policy.name].append({
                "trajectory_id": traj_id,
                "split": split,
                "family": family,
                "family_name": family_name,
                "halted_step": halted_step,
                "optimal_step": optimal_step,
                "quality_score": quality_score,
                "premature_halt": premature_halt,
                "unnecessary_continuation": unnecessary_continuation,
                "directive": final_decision.directive,
                "reason": final_decision.reason,
                "compute": {
                    "tokens_generated": accum_tokens,
                    "resolver_calls": accum_resolver_calls,
                    "resolver_cost": accum_resolver_cost,
                    "total_compute": accum_total_compute
                }
            })

    # Summary Statistics per Policy and per Family
    summary_by_policy = {}
    for p_name, p_runs in policy_results.items():
        # Filter test split for primary held-out claims
        test_runs = [r for r in p_runs if r["split"] == "test"]

        scores = [r["quality_score"] for r in test_runs]
        avg_quality = sum(scores) / len(scores) if scores else 0.0
        ci_lower, ci_upper = compute_bootstrap_ci(scores, num_samples=1000)

        premature_rate = sum(1 for r in test_runs if r["premature_halt"]) / len(test_runs) if test_runs else 0.0
        unnecessary_rate = sum(1 for r in test_runs if r["unnecessary_continuation"]) / len(test_runs) if test_runs else 0.0
        avg_compute = sum(r["compute"]["total_compute"] for r in test_runs) / len(test_runs) if test_runs else 0.0
        avg_resolver_cost = sum(r["compute"]["resolver_cost"] for r in test_runs) / len(test_runs) if test_runs else 0.0

        # Family breakdown
        family_breakdown = {}
        for r in test_runs:
            fam = r["family"]
            if fam not in family_breakdown:
                family_breakdown[fam] = {"quality_sum": 0.0, "count": 0, "compute_sum": 0.0}
            family_breakdown[fam]["quality_sum"] += r["quality_score"]
            family_breakdown[fam]["compute_sum"] += r["compute"]["total_compute"]
            family_breakdown[fam]["count"] += 1

        fam_stats = {
            f: {
                "avg_quality": d["quality_sum"] / d["count"],
                "avg_compute": d["compute_sum"] / d["count"]
            }
            for f, d in family_breakdown.items()
        }

        summary_by_policy[p_name] = {
            "held_out_test_runs": len(test_runs),
            "avg_decision_quality": avg_quality,
            "bootstrap_95_ci": [ci_lower, ci_upper],
            "premature_halting_rate": premature_rate,
            "unnecessary_continuation_rate": unnecessary_rate,
            "avg_total_compute": avg_compute,
            "avg_resolver_cost_overhead": avg_resolver_cost,
            "family_breakdown": fam_stats,
            "raw_test_runs": test_runs
        }

    return {
        "title": "Held-Out Evaluation Report: Semantic Uncertainty for Adaptive Halting",
        "dataset_version": data["metadata"]["version"],
        "policies_evaluated": list(summary_by_policy.keys()),
        "summary": summary_by_policy
    }


def main():
    ds_path = os.path.join("benchmarks", "data", "held_out_semantic_trajectories.json")
    report = run_held_out_evaluation(ds_path)

    os.makedirs("results", exist_ok=True)
    out_json = os.path.join("results", "held_out_semantic_evaluation_report.json")
    with open(out_json, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Evaluation complete. Results saved to {out_json}")


if __name__ == "__main__":
    main()
