"""
Synthetic Demonstration Harness for Semantic Uncertainty vs. Token-Level Signals.

Phase 5 Deliverable & PR Feedback Refinements:
- Demonstrates semantic uncertainty calculation across controlled synthetic test scenarios.
- Explicitly labeled as a Synthetic Conceptual Demonstration, NOT a benchmark of general predictive performance on model logs.
- Dynamically derives findings directly from measured outputs.
- Clearly distinguishes synthetic next-token entropy inputs from actual model-derived token entropy distributions.

Generates report: results/semantic_evaluation_results.json
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
            "description": "High synthetic token entropy, zero semantic variance (Paraphrases)",
            "token_probs": [0.25, 0.25, 0.25, 0.25],  # Synthetic token entropy = 2.0 bits
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
            "description": "Low synthetic token & semantic entropy, but false conclusion (Shared Error)",
            "token_probs": [0.95, 0.05],
            "candidates": [
                "The capital of Australia is Sydney.",
                "Sydney is the capital of Australia."
            ],
            "cost": 10.0
        },
        {
            "id": "scenario_4_competing_hypotheses",
            "description": "High synthetic token & high semantic uncertainty (Competing Hypotheses)",
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
    measured_findings = []

    for scenario in eval_scenarios:
        scen_id = scenario["id"]
        dec_res, sem_res, dual_metric = adapter.step(
            token_probabilities=scenario["token_probs"],
            candidates=scenario["candidates"],
            cost=scenario["cost"],
            state=scen_id,
            trajectory_id=scen_id
        )

        tok_h = dual_metric.token_metrics.entropy
        sem_h = sem_res.semantic_entropy_bits

        record = {
            "scenario_id": scen_id,
            "description": scenario["description"],
            "signals": {
                "synthetic_token_entropy_bits": tok_h,
                "semantic_entropy_bits": sem_h,
                "normalized_semantic_entropy": sem_res.normalized_semantic_entropy,
                "semantic_disagreement": sem_res.semantic_disagreement,
                "decision_sensitive_disagreement": sem_res.decision_sensitive_disagreement,
                "resolver_ambiguity": sem_res.resolver_ambiguity,
                "status": sem_res.status.value,
                "num_clusters": sem_res.num_clusters,
                "candidates_analyzed": sem_res.candidates_analyzed
            },
            "interpretation": {
                "token_vs_semantic_gap": (tok_h - sem_h) if (tok_h is not None and sem_h is not None) else None,
                "decision_impact": sem_res.decision_sensitive_disagreement > 0.0
            }
        }
        results.append(record)

        # Dynamically build empirical findings from measured values
        if scen_id == "scenario_1_paraphrase_invariance":
            measured_findings.append(
                f"Measured Scenario 1: Synthetic token entropy was {tok_h:.2f} bits, "
                f"while measured semantic entropy was {sem_h:.2f} bits across {sem_res.num_clusters} cluster(s)."
            )
        elif scen_id == "scenario_2_negation_reversal":
            measured_findings.append(
                f"Measured Scenario 2: High decision-sensitive disagreement ({sem_res.decision_sensitive_disagreement:.2f}) "
                f"was detected despite low lexical difference."
            )
        elif scen_id == "scenario_3_confident_shared_error":
            measured_findings.append(
                f"Measured Scenario 3: Measured semantic entropy was {sem_h:.2f} bits, "
                f"while factual_correctness remained explicitly {sem_res.factual_correctness} (unassumed)."
            )
        elif scen_id == "scenario_5_single_candidate":
            measured_findings.append(
                f"Measured Scenario 5: Single candidate input returned status '{sem_res.status.value}'."
            )

    report = {
        "title": "EpistemicOS Semantic Uncertainty Prototype Synthetic Demonstration",
        "harness_type": "SYNTHETIC_CONCEPTUAL_DEMONSTRATION",
        "method_version": SemanticUncertaintyEstimator.VERSION,
        "disclaimer": "This report evaluates synthetic candidate distributions to demonstrate signal dynamics. It is NOT a benchmark of general predictive accuracy or empirical error detection on LLM outputs.",
        "eval_scenarios": results,
        "measured_empirical_findings": measured_findings
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
