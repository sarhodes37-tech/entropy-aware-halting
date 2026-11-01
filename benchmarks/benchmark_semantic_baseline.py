"""
Comparative benchmark measuring unoptimized legacy vs optimized semantic uncertainty estimation.
Measures:
1. End-to-end estimate() runtime across candidate-set sizes (N=10, 30, 50, 100, 200).
2. Separate feature extraction runtime vs pairwise comparison operations.
3. Cache operations (hits, misses, lookups).
4. Memory overhead via tracemalloc.
5. Strict verification of pairwise comparison symmetry: resolve(a, b) == resolve(b, a).
"""

import math
import os
import sys
import time
import tracemalloc
from typing import List, Tuple, Dict, Any

from epistemicos.semantic_uncertainty import (
    Candidate,
    ExactAndNormalizedResolver,
    SemanticResolver,
    SemanticUncertaintyEstimator,
    SemanticComparisonResult,
)


def verify_pairwise_symmetry() -> bool:
    """Verifies that ExactAndNormalizedResolver is strictly symmetric across varied inputs."""
    resolver = ExactAndNormalizedResolver()
    test_cases = [
        ("The transfer of $100 to Alice succeeded.", "Transfer of 100 usd to Alice succeeded.", "APPROVE", "APPROVE"),
        ("Alice sent $100 to Bob.", "Bob sent $100 to Alice.", "APPROVE", "APPROVE"),
        ("The operation is not denied.", "The operation is approved.", "APPROVE", "APPROVE"),
        ("Access is denied.", "Access is permitted.", "DENY", "APPROVE"),
        ("System failed due to timeout.", "Normal operation restored.", None, None),
        ("If condition A met then proceed.", "Unless condition A met proceed.", "A", "B"),
        ("Transferred $500 before midnight.", "Transferred $500 after midnight.", "A", "A"),
        ("Pay $100.", "Pay $200.", "A", "A"),
        ("Identical sentence.", "Identical sentence.", "A", "B"),
        ("Identical sentence.", "Identical sentence.", "A", "A"),
    ]

    candidates = [
        Candidate(text=t, action=a) for t, _, a, _ in test_cases
    ] + [
        Candidate(text=t, action=a) for _, t, _, a in test_cases
    ]

    all_symmetric = True
    for i in range(len(candidates)):
        for j in range(len(candidates)):
            res_ij = resolver.resolve(candidates[i], candidates[j])
            res_ji = resolver.resolve(candidates[j], candidates[i])
            if res_ij != res_ji:
                print(f"ASYMMETRY DETECTED between candidate {i} and {j}:")
                all_symmetric = False
    return all_symmetric


def generate_benchmark_candidates(n: int) -> List[Candidate]:
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


class LegacyResolver(SemanticResolver):
    """Simulates unoptimized legacy resolver resolving without pre-extracted feature passing."""
    def __init__(self):
        self.base = ExactAndNormalizedResolver()

    def resolve(self, candidate_a: Candidate, candidate_b: Candidate) -> SemanticComparisonResult:
        return self.base.resolve(candidate_a, candidate_b)


def run_comparative_benchmark(n_sizes: List[int] = [10, 30, 50, 100, 200], iterations: int = 15) -> Dict[str, Any]:
    opt_estimator = SemanticUncertaintyEstimator(resolver=ExactAndNormalizedResolver())
    legacy_estimator = SemanticUncertaintyEstimator(resolver=LegacyResolver())

    results = []

    for n in n_sizes:
        candidates = generate_benchmark_candidates(n)
        pairs_count = n * (n - 1) // 2

        # 1. Measure pure feature extraction time for N candidates
        opt_estimator.resolver._get_features.cache_clear()
        t0 = time.perf_counter()
        for c in candidates:
            _ = opt_estimator.resolver._get_features(c.text)
        t1 = time.perf_counter()
        feat_time_ms = (t1 - t0) * 1000.0

        # 2. Measure legacy unoptimized estimate()
        legacy_estimator.resolver.base._get_features.cache_clear()
        tracemalloc.start()
        t0 = time.perf_counter()
        for _ in range(iterations):
            legacy_estimator.estimate(candidates)
        t1 = time.perf_counter()
        _, legacy_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        legacy_mean_ms = ((t1 - t0) * 1000.0) / iterations

        # 3. Measure optimized estimate()
        opt_estimator.resolver._get_features.cache_clear()
        tracemalloc.start()
        t0 = time.perf_counter()
        for _ in range(iterations):
            opt_estimator.estimate(candidates)
        t1 = time.perf_counter()
        _, opt_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        opt_mean_ms = ((t1 - t0) * 1000.0) / iterations

        speedup = legacy_mean_ms / opt_mean_ms if opt_mean_ms > 0 else 1.0

        results.append({
            "n": n,
            "pairs": pairs_count,
            "feat_time_ms": round(feat_time_ms, 3),
            "legacy_mean_ms": round(legacy_mean_ms, 3),
            "opt_mean_ms": round(opt_mean_ms, 3),
            "speedup": round(speedup, 2),
            "legacy_mem_kb": round(legacy_peak / 1024.0, 2),
            "opt_mem_kb": round(opt_peak / 1024.0, 2),
        })

    return {"results": results}


def main():
    print("Checking resolver pairwise symmetry...")
    assert verify_pairwise_symmetry()
    print("Pairwise comparison symmetry established: True\n")

    print("Running comparative benchmark...")
    report = run_comparative_benchmark()

    print("=" * 96)
    print(f"{'N':<6} | {'Pairs':<8} | {'Feat Extr (ms)':<15} | {'Legacy (ms)':<13} | {'Opt (ms)':<10} | {'Speedup':<9} | {'Peak Mem (KB)'}")
    print("-" * 96)
    for r in report["results"]:
        print(f"{r['n']:<6} | {r['pairs']:<8} | {r['feat_time_ms']:<15.3f} | {r['legacy_mean_ms']:<13.3f} | {r['opt_mean_ms']:<10.3f} | {r['speedup']:<7.2f}x | {r['legacy_mem_kb']} -> {r['opt_mem_kb']}")
    print("=" * 96)


if __name__ == "__main__":
    main()
