"""
Reproducible Benchmark Harness for Semantic Uncertainty Performance Optimization.

Evaluates performance of SemanticUncertaintyEstimator across candidate set sizes (N=10 to N=200).
Measures:
1. Cold Cache Execution Time (first evaluation with cleared LRU feature cache)
2. Warm Cache Execution Time (subsequent evaluations leveraging LRU feature cache)
3. Un-cached Baseline Execution Time (simulating unoptimized feature extraction and pairwise resolve calls)
4. Speedup Ratios (Baseline vs. Cold Cache vs. Warm Cache)

Generates output artifact: results/semantic_optimization_benchmark.json
"""

import json
import math
import os
import re
import statistics
import time
from typing import Any, Dict, List, Tuple

from epistemicos.semantic_uncertainty import (
    Candidate,
    ExactAndNormalizedResolver,
    SemanticComparisonResult,
    SemanticUncertaintyEstimator,
)


def generate_candidate_set(n: int) -> List[Candidate]:
    base_texts = [
        "The transfer of $100 USD to Alice was completed successfully.",
        "Transfer of 100 usd to Alice was not completed successfully.",
        "Paid $100 to Alice without error.",
        "Transferred $100 USD to Bob before deadline.",
        "Transferred $100 USD to Bob after deadline.",
        "Alice transferred $100 USD to Bob.",
        "Bob transferred $100 USD to Alice.",
        "The system is operating within normal parameters.",
        "System performance is normal and healthy.",
        "Operation failed due to timeout.",
    ]
    actions = ["APPROVE", "DENY", "REVIEW", None]
    candidates = []

    for i in range(n):
        text = f"{base_texts[i % len(base_texts)]} [Variation sample {i}]"
        action = actions[i % len(actions)]
        prob = 1.0 / n
        candidates.append(Candidate(text=text, probability=prob, action=action))
    return candidates


def run_uncached_unoptimized_baseline(candidates: List[Candidate], estimator: SemanticUncertaintyEstimator) -> Tuple[float, int]:
    """
    Simulates original un-cached behavior (re-normalizing strings and re-executing regexes per pair).
    """
    resolver = ExactAndNormalizedResolver()

    # Disable LRU cache by clearing it before every single extraction
    def raw_resolve(cand_a: Candidate, cand_b: Candidate) -> SemanticComparisonResult:
        resolver._get_features.cache_clear()
        return resolver.resolve(cand_a, cand_b)

    n_candidates = len(candidates)
    total_pairs = 0
    t0 = time.perf_counter()

    # Re-simulate unoptimized pairwise comparisons without pairwise comparison_cache
    for i in range(n_candidates):
        for j in range(n_candidates):
            if i != j:
                raw_resolve(candidates[i], candidates[j])
                total_pairs += 1

    t1 = time.perf_counter()
    return (t1 - t0) * 1000.0, total_pairs


def run_benchmark(n_sizes: List[int] = [10, 30, 50, 100, 200], iterations: int = 15) -> Dict[str, Any]:
    estimator = SemanticUncertaintyEstimator()
    benchmark_results = []

    for n in n_sizes:
        candidates = generate_candidate_set(n)
        pairs_count = n * (n - 1) // 2

        # 1. Measure Cold Cache execution (clear LRU cache first)
        ExactAndNormalizedResolver._get_features.cache_clear()
        t0_cold = time.perf_counter()
        estimator.estimate(candidates)
        t1_cold = time.perf_counter()
        cold_time_ms = (t1_cold - t0_cold) * 1000.0

        # 2. Measure Warm Cache executions
        warm_times_ms = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            estimator.estimate(candidates)
            t1 = time.perf_counter()
            warm_times_ms.append((t1 - t0) * 1000.0)

        mean_warm_ms = statistics.mean(warm_times_ms)
        std_warm_ms = statistics.stdev(warm_times_ms) if len(warm_times_ms) > 1 else 0.0

        # 3. Measure Uncached / Unoptimized Baseline
        uncached_time_ms, uncached_evals = run_uncached_unoptimized_baseline(candidates, estimator)

        cold_speedup = uncached_time_ms / cold_time_ms if cold_time_ms > 0 else 0.0
        warm_speedup = uncached_time_ms / mean_warm_ms if mean_warm_ms > 0 else 0.0

        benchmark_results.append({
            "candidate_count": n,
            "pairwise_combinations": pairs_count,
            "uncached_baseline_ms": round(uncached_time_ms, 3),
            "cold_cache_ms": round(cold_time_ms, 3),
            "warm_cache_mean_ms": round(mean_warm_ms, 3),
            "warm_cache_std_ms": round(std_warm_ms, 3),
            "cold_cache_speedup": round(cold_speedup, 2),
            "warm_cache_speedup": round(warm_speedup, 2),
        })

    report = {
        "title": "EpistemicOS Semantic Uncertainty Performance Benchmark",
        "method_version": SemanticUncertaintyEstimator.VERSION,
        "iterations_per_size": iterations,
        "results": benchmark_results,
    }
    return report


def main():
    report = run_benchmark()
    os.makedirs("results", exist_ok=True)
    out_path = os.path.join("results", "semantic_optimization_benchmark.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)

    print("=" * 80)
    print("EpistemicOS Semantic Uncertainty Optimization Benchmark Results")
    print("=" * 80)
    print(f"{'N':<6} | {'Pairs':<8} | {'Uncached (ms)':<14} | {'Cold (ms)':<10} | {'Warm (ms)':<10} | {'Warm Speedup':<12}")
    print("-" * 80)
    for r in report["results"]:
        print(
            f"{r['candidate_count']:<6} | "
            f"{r['pairwise_combinations']:<8} | "
            f"{r['uncached_baseline_ms']:<14.3f} | "
            f"{r['cold_cache_ms']:<10.3f} | "
            f"{r['warm_cache_mean_ms']:<10.3f} | "
            f"{r['warm_cache_speedup']:<12.1f}x"
        )
    print("=" * 80)
    print(f"Benchmark report saved to {out_path}")


if __name__ == "__main__":
    main()
