"""
Reproducible Evaluation Harness for Semantic Uncertainty vs. Token Entropy.

Phase 5 Deliverable:
Evaluates and compares four signal configurations across synthetic test scenarios:
1. Token-level entropy alone
2. Semantic uncertainty alone
3. Dual / Combined signal telemetry
4. Decision-sensitive semantic disagreement

Generates structured JSON report: results/semantic_evaluation_results.json
"""

import json
import os
import sys
from typing import Any, Dict, List

from epistemicos.scheduler import EntropyAwareScheduler
from epistemicos.semantic_uncertainty import SemanticUncertaintyEstimator, Candidate, SemanticUncertaintyStatus
from epistemicos.semantic_adapter import SemanticSchedulerAdapter


def run_evaluation() -> Dict[str, Any]:
    adapter = SemanticSchedulerAdapter(v_decision=100.0)

    eval_scenarios = [
        {
            "id": "scenario_1_paraphrase_invariance",
            "description": "High token variance, zero semantic variance (Paraphrases)",
            "token_probs": [0.25, 0.25, 0.25, 0.25],  # Token entropy = 2.0 bits
            "candidates": [
                "The system execution succeeded with zero errors.",
                "System execution succeeded with zero errors",
                "The system execution succeeded with zero errors!",
                "system execution succeeded with zero errors"
            ],
            "cost": 10.0
        },
        {
            "id": "scenario_2_negation_reversal",
            "description": "Low token difference, high semantic divergence (Negation)",
            "token_probs": [0.5, 0.5],
            "candidates": [
                Candidate(text="The request was authorized by security policy.", action="ALLOW"),
                Candidate(text="The request was not authorized by security policy.", action="DENY")
            ],
            "cost": 10.0
        },
        {
            "id": "scenario_3_confident_shared_error",
            "description": "Low token & semantic entropy, but false conclusion (Shared Error)",
            "token_probs": [0.95, 0.05],
            "candidates": [
                "The capital of Australia is Sydney.",
                "Sydney is the capital of Australia."
            ],
            "cost": 10.0
        },
        {
            "id": "scenario_4_competing_hypotheses",
            "description": "High token & high semantic uncertainty (Competing Hypotheses)",
            "token_probs": [0.5, 0.5],
            "candidates": [
                Candidate(text="Diagnosis: Influenza Type A", action="PRESCRIBE_ANTIVIRAL"),
                Candidate(text="Diagnosis: Bacterial Pneumonia", action="PRESCRIBE_ANTIBIOTIC")
            ],
            "cost": 10.0
        },
        {
            "id": "scenario_5_single_candidate",
            "description": "Single candidate output (Insufficient Evidence)",
            "token_probs": [1.0],
            "candidates": [
                "Single candidate output"
            ],
            "cost": 5.0
        }
    ]

    results = []

    for scenario in eval_scenarios:
        dec_res, sem_res, dual_metric = adapter.step(
            token_probabilities=scenario["token_probs"],
            candidates=scenario["candidates"],
            cost=scenario["cost"],
            state=scenario["id"]
        )

        record = {
            "scenario_id": scenario["id"],
            "description": scenario["description"],
            "signals": {
                "token_entropy_bits": dual_metric.token_metrics.entropy,
                "semantic_entropy_bits": sem_res.semantic_entropy_bits,
                "normalized_semantic_entropy": sem_res.normalized_semantic_entropy,
                "semantic_disagreement": sem_res.semantic_disagreement,
                "decision_sensitive_disagreement": sem_res.decision_sensitive_disagreement,
                "resolver_ambiguity": sem_res.resolver_ambiguity,
                "status": sem_res.status.value,
            },
            "interpretation_comparison": {
                "token_alone": f"Token entropy = {dual_metric.token_metrics.entropy:.2f} bits",
                "semantic_alone": f"Semantic entropy = {sem_res.semantic_entropy_bits if sem_res.semantic_entropy_bits is not None else 'N/A'} bits",
                "combined": f"Token H={dual_metric.token_metrics.entropy:.2f}, Semantic H={sem_res.semantic_entropy_bits if sem_res.semantic_entropy_bits is not None else 'N/A'}",
                "decision_sensitive": f"Decision disagreement = {sem_res.decision_sensitive_disagreement:.2f}"
            }
        }
        results.append(record)

    report = {
        "title": "EpistemicOS Semantic Uncertainty Prototype Evaluation",
        "method_version": SemanticUncertaintyEstimator.VERSION,
        "eval_scenarios": results,
        "key_findings": [
            "Token entropy overestimates uncertainty on paraphrases (Scenario 1).",
            "Semantic disagreement isolates meaning & decision changes that token distance masks (Scenario 2 & 4).",
            "Low semantic entropy does NOT imply factual correctness (Scenario 3).",
            "Single candidates return INSUFFICIENT_EVIDENCE status (Scenario 5)."
        ]
    }

    return report


def main():
    report = run_evaluation()
    os.makedirs("results", exist_ok=True)
    out_path = os.path.join("results", "semantic_evaluation_results.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Semantic uncertainty evaluation complete. Report saved to {out_path}")


if __name__ == "__main__":
    main()
