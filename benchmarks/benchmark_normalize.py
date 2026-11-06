"""
Reproducible Empirical Benchmark for ExactAndNormalizedResolver Feature Extraction Optimizations.

Addresses PR #368 review criteria:
1. Baseline vs PR comparison: Exact pre-PR baseline logic vs fast-path guarded implementation.
2. Separate measurement conditions: Strictly separates Cold-Cache and Warm-Cache evaluations.
3. Defined workloads:
   - Clean conversational text (no negations, no numbers/currencies)
   - Negation-heavy text (not, no, never, cannot, double negations)
   - Quantity/unit-heavy text (currencies, numbers, units, percentages)
   - Mixed realistic enterprise inputs
4. Statistical reporting:
   - Sample count, p50, p95, p99, mean, stddev, min, max, delta, speedup
   - Distinguishes per-candidate latency from per-batch and complete estimate() latency.
5. Saves machine-readable results to results/semantic_feature_benchmark_results.json
"""

import functools
import json
import os
import platform
import statistics
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Tuple

from epistemicos.semantic_uncertainty import (
    ExactAndNormalizedResolver,
    SemanticUncertaintyEstimator,
)

RESULTS_PATH = Path("results/semantic_feature_benchmark_results.json")


def baseline_unoptimized_get_features(
    text: str
) -> Tuple[
    str,
    Tuple[str, ...],
    FrozenSet[str],
    Tuple[str, ...],
    FrozenSet[str],
    FrozenSet[str],
    FrozenSet[str],
    FrozenSet[str]
]:
    """Exact pre-PR implementation of _get_features without trigger guards."""
    clean = text.strip().lower()
    for pattern, replacement in ExactAndNormalizedResolver.DOUBLE_NEGATION_PATTERNS:
        clean = pattern.sub(replacement, clean)
    clean = ExactAndNormalizedResolver.CLEAN_PUNCTUATION_PATTERN.sub("", clean)
    norm = " ".join(clean.split())
    tokens = tuple(norm.split())
    token_set = frozenset(tokens)

    matches = ExactAndNormalizedResolver.QUANTITY_UNIT_PATTERN.findall(text.lower())
    units = tuple(m.strip() for m in matches if m.strip())

    negs = token_set & ExactAndNormalizedResolver.NEGATION_WORDS
    conds = token_set & ExactAndNormalizedResolver.CONDITIONAL_WORDS
    temps = token_set & ExactAndNormalizedResolver.TEMPORAL_WORDS
    dirs = token_set & ExactAndNormalizedResolver.DIRECTIONAL_KEYWORDS

    return norm, tokens, token_set, units, negs, conds, temps, dirs


class BaselineExactAndNormalizedResolver(ExactAndNormalizedResolver):
    @staticmethod
    @functools.lru_cache(maxsize=4096)
    def _get_features(text: str):
        return baseline_unoptimized_get_features(text)


# Workload Definitions (10 unique strings per workload, covering varied lengths and semantics)
WORKLOAD_CLEAN_TEXTS = [
    "Please summarize the quarterly logistics analysis.",
    "System status normal and healthy.",
    "The user requested documentation for deploying services across regions.",
    "The quick brown fox jumps over the lazy dog in the green meadow.",
    "Explain difference between Bayesian and frequentist inference.",
    "Calculate gradient descent update rule for a linear model.",
    "Write a function that calculates the nth Fibonacci sequence value.",
    "What are the best practices for structuring microservices in python?",
    "Architectural decisions must prioritize security and determinism.",
    "Database replication completed without replica lag across zones."
]

WORKLOAD_NEGATION_TEXTS = [
    "This request is not unauthorized and should be processed immediately.",
    "The document is not invalid according to section four of policy.",
    "Statement one is not false, but statement two is not correct.",
    "Access was not denied for user admin.",
    "It is not impossible to complete this task on time.",
    "The output was not incorrect during validation checks.",
    "User rejected the proposed plan and will not proceed.",
    "The transaction cannot complete and was never approved.",
    "Neither proposal was accepted nor was the exception granted.",
    "Permission was denied because principal identity was false."
]

WORKLOAD_QUANTITY_TEXTS = [
    "Customer transfer of $100 USD completed successfully.",
    "Billing statement reflects 250 EUR fee and 50 percent discount.",
    "Total weight exceeded 15.5 kg and measured 34.2 lbs.",
    "Payment gateway charged 5000 JPY to merchant account.",
    "Direct wire transfer of 1200 GBP processed via clearinghouse.",
    "The account balance is 450 dollars with 10 percent interest.",
    "Invoice amount is 300 euros with 0.05 percent late fee.",
    "Transaction volume increased by 25 percent to 1000000 USD.",
    "Shipment volume measured 45.8 kg in container 89.",
    "Refund requested for $75.50 USD after delivery failure."
]

WORKLOAD_MIXED_TEXTS = [
    "The transfer of $100 USD to Alice was not unauthorized.",
    "Transfer of 100 usd to Bob was not completed successfully.",
    "Paid $100 to Charlie without error or delay.",
    "Transferred $100 USD to David before deadline with 5 percent fee.",
    "Transferred $100 USD to Eve after deadline with 10 percent penalty.",
    "Alice transferred 50 EUR to Bob and statement is not false.",
    "Bob transferred 50 EUR to Alice and access was not denied.",
    "The system is operating within normal parameters with 0 errors.",
    "Operation failed due to timeout after 30 seconds wait.",
    "Financial state mutation of $500 USD was approved by principal."
]

WORKLOADS = {
    "clean_conversational": WORKLOAD_CLEAN_TEXTS,
    "negation_heavy": WORKLOAD_NEGATION_TEXTS,
    "quantity_unit_heavy": WORKLOAD_QUANTITY_TEXTS,
    "mixed_realistic": WORKLOAD_MIXED_TEXTS,
}


def get_environment_info() -> Dict[str, Any]:
    commit_sha = "unknown"
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        )
        commit_sha = res.stdout.strip()
    except Exception:
        pass

    return {
        "commit_sha": commit_sha,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or "x86_64",
        "cpu_count": os.cpu_count() or 1,
    }


def compute_statistics(values: List[float]) -> Dict[str, float]:
    if not values:
        return {}
    s = sorted(values)
    n = len(s)
    p50_idx = int(0.50 * n)
    p95_idx = int(0.95 * n)
    p99_idx = int(0.99 * n)

    return {
        "samples": n,
        "mean": round(statistics.mean(values), 4),
        "stddev": round(statistics.stdev(values), 4) if n > 1 else 0.0,
        "median_p50": round(s[min(p50_idx, n - 1)], 4),
        "p95": round(s[min(p95_idx, n - 1)], 4),
        "p99": round(s[min(p99_idx, n - 1)], 4),
        "min": round(s[0], 4),
        "max": round(s[-1], 4),
    }


def run_feature_extraction_benchmarks(
    repetitions: int = 25, calls_per_rep: int = 1000
) -> Dict[str, Any]:
    """
    Evaluates isolated _get_features extraction across workloads.
    Separates:
    - Cold-Cache: invoking un-cached kernel logic directly (wrapped function)
    - Warm-Cache: invoking cached @lru_cache kernel with pre-warmed entries
    """
    results = {}

    for w_name, texts in WORKLOADS.items():
        # Assert strict output equivalence
        for text in texts:
            base_out = baseline_unoptimized_get_features(text)
            opt_out = ExactAndNormalizedResolver._get_features(text)
            assert base_out == opt_out, f"Mismatch in {w_name} on '{text}'"

        # 1. COLD-CACHE (Direct un-cached function calls)
        base_cold_times = []
        opt_cold_times = []

        for rep in range(repetitions):
            if rep % 2 == 0:
                t0 = time.perf_counter()
                for _ in range(calls_per_rep):
                    for t in texts:
                        baseline_unoptimized_get_features(t)
                t1 = time.perf_counter()
                base_cold_times.append((t1 - t0) * 1000.0)

                t0 = time.perf_counter()
                for _ in range(calls_per_rep):
                    for t in texts:
                        ExactAndNormalizedResolver._get_features.__wrapped__(t)
                t1 = time.perf_counter()
                opt_cold_times.append((t1 - t0) * 1000.0)
            else:
                t0 = time.perf_counter()
                for _ in range(calls_per_rep):
                    for t in texts:
                        ExactAndNormalizedResolver._get_features.__wrapped__(t)
                t1 = time.perf_counter()
                opt_cold_times.append((t1 - t0) * 1000.0)

                t0 = time.perf_counter()
                for _ in range(calls_per_rep):
                    for t in texts:
                        baseline_unoptimized_get_features(t)
                t1 = time.perf_counter()
                base_cold_times.append((t1 - t0) * 1000.0)

        total_calls_per_rep = len(texts) * calls_per_rep
        base_cold_us_per_call = [(t / total_calls_per_rep) * 1000.0 for t in base_cold_times]
        opt_cold_us_per_call = [(t / total_calls_per_rep) * 1000.0 for t in opt_cold_times]

        stats_base_cold = compute_statistics(base_cold_us_per_call)
        stats_opt_cold = compute_statistics(opt_cold_us_per_call)
        speedup_cold = stats_base_cold["median_p50"] / (stats_opt_cold["median_p50"] or 1e-6)
        reduction_cold = (
            1.0 - (stats_opt_cold["median_p50"] / stats_base_cold["median_p50"])
        ) * 100.0

        # 2. WARM-CACHE (Cached function calls)
        # Pre-warm caches
        for t in texts:
            BaselineExactAndNormalizedResolver._get_features(t)
            ExactAndNormalizedResolver._get_features(t)

        base_warm_times = []
        opt_warm_times = []

        for rep in range(repetitions):
            if rep % 2 == 0:
                t0 = time.perf_counter()
                for _ in range(calls_per_rep * 5):
                    for t in texts:
                        BaselineExactAndNormalizedResolver._get_features(t)
                t1 = time.perf_counter()
                base_warm_times.append((t1 - t0) * 1000.0)

                t0 = time.perf_counter()
                for _ in range(calls_per_rep * 5):
                    for t in texts:
                        ExactAndNormalizedResolver._get_features(t)
                t1 = time.perf_counter()
                opt_warm_times.append((t1 - t0) * 1000.0)
            else:
                t0 = time.perf_counter()
                for _ in range(calls_per_rep * 5):
                    for t in texts:
                        ExactAndNormalizedResolver._get_features(t)
                t1 = time.perf_counter()
                opt_warm_times.append((t1 - t0) * 1000.0)

                t0 = time.perf_counter()
                for _ in range(calls_per_rep * 5):
                    for t in texts:
                        BaselineExactAndNormalizedResolver._get_features(t)
                t1 = time.perf_counter()
                base_warm_times.append((t1 - t0) * 1000.0)

        total_warm_calls_per_rep = len(texts) * calls_per_rep * 5
        base_warm_us_per_call = [(t / total_warm_calls_per_rep) * 1000.0 for t in base_warm_times]
        opt_warm_us_per_call = [(t / total_warm_calls_per_rep) * 1000.0 for t in opt_warm_times]

        stats_base_warm = compute_statistics(base_warm_us_per_call)
        stats_opt_warm = compute_statistics(opt_warm_us_per_call)
        speedup_warm = stats_base_warm["median_p50"] / (stats_opt_warm["median_p50"] or 1e-6)

        results[w_name] = {
            "unique_inputs": len(texts),
            "input_lengths": [len(t) for t in texts],
            "cold_cache_us_per_eval": {
                "baseline": stats_base_cold,
                "optimized": stats_opt_cold,
                "speedup_ratio": round(speedup_cold, 2),
                "latency_reduction_pct": round(reduction_cold, 1),
            },
            "warm_cache_us_per_eval": {
                "baseline": stats_base_warm,
                "optimized": stats_opt_warm,
                "speedup_ratio": round(speedup_warm, 2),
            }
        }

        print(
            f"  [{w_name}] Cold Eval: Base p50={stats_base_cold['median_p50']:.2f}µs, "
            f"Opt p50={stats_opt_cold['median_p50']:.2f}µs | "
            f"Speedup: {speedup_cold:.2f}x ({reduction_cold:.1f}% reduction) | "
            f"Warm: Base={stats_base_warm['median_p50']:.3f}µs, "
            f"Opt={stats_opt_warm['median_p50']:.3f}µs"
        )

    return results


def run_end_to_end_estimate_benchmarks(
    candidate_counts: List[int] = [6, 12, 24], batches_per_count: int = 30
) -> Dict[str, Any]:
    """
    Evaluates full end-to-end SemanticUncertaintyEstimator.estimate() calls.
    Tests cold-cache batch evaluation by clearing the LRU cache before each batch of candidates.
    """
    print("\n--- Part 2: End-to-End estimate() Cold-Cache Candidate Batches ---")
    est_base = SemanticUncertaintyEstimator(resolver=BaselineExactAndNormalizedResolver())
    est_opt = SemanticUncertaintyEstimator(resolver=ExactAndNormalizedResolver())

    results = {}

    for k in candidate_counts:
        batches = [
            [
                f"Candidate option {i} analyzing proposal outcome variation for batch {b}"
                for i in range(k)
            ]
            for b in range(batches_per_count)
        ]

        # Verify equivalence
        for b in batches:
            res_b = est_base.estimate(b)
            res_o = est_opt.estimate(b)
            assert res_b.to_dict() == res_o.to_dict(), f"estimate() output mismatch on size {k}"

        base_batch_ms = []
        opt_batch_ms = []
        trials = 20

        for rep in range(trials):
            if rep % 2 == 0:
                t0 = time.perf_counter()
                for b in batches:
                    BaselineExactAndNormalizedResolver._get_features.cache_clear()
                    est_base.estimate(b)
                t1 = time.perf_counter()
                base_batch_ms.append(((t1 - t0) / batches_per_count) * 1000.0)

                t0 = time.perf_counter()
                for b in batches:
                    ExactAndNormalizedResolver._get_features.cache_clear()
                    est_opt.estimate(b)
                t1 = time.perf_counter()
                opt_batch_ms.append(((t1 - t0) / batches_per_count) * 1000.0)
            else:
                t0 = time.perf_counter()
                for b in batches:
                    ExactAndNormalizedResolver._get_features.cache_clear()
                    est_opt.estimate(b)
                t1 = time.perf_counter()
                opt_batch_ms.append(((t1 - t0) / batches_per_count) * 1000.0)

                t0 = time.perf_counter()
                for b in batches:
                    BaselineExactAndNormalizedResolver._get_features.cache_clear()
                    est_base.estimate(b)
                t1 = time.perf_counter()
                base_batch_ms.append(((t1 - t0) / batches_per_count) * 1000.0)

        stats_base = compute_statistics(base_batch_ms)
        stats_opt = compute_statistics(opt_batch_ms)
        speedup = stats_base["median_p50"] / (stats_opt["median_p50"] or 1e-6)
        reduction = (1.0 - (stats_opt["median_p50"] / stats_base["median_p50"])) * 100.0

        results[f"candidates_{k}"] = {
            "candidate_count": k,
            "batches_evaluated": batches_per_count,
            "cold_cache_batch_latency_ms": {
                "baseline": stats_base,
                "optimized": stats_opt,
                "speedup_ratio": round(speedup, 2),
                "latency_reduction_pct": round(reduction, 1),
            }
        }

        print(
            f"  [Candidates K={k:2d}] Cold Batch Latency: "
            f"Base p50={stats_base['median_p50']:.3f}ms, "
            f"Opt p50={stats_opt['median_p50']:.3f}ms | "
            f"Speedup: {speedup:.2f}x ({reduction:.1f}% reduction)"
        )

    return results


def main():
    env_info = get_environment_info()
    print("=" * 80)
    print("ExactAndNormalizedResolver Feature Extraction Empirical Benchmark Harness")
    print("=" * 80)
    print(f"Commit SHA     : {env_info['commit_sha']}")
    print(f"Python Runtime : {env_info['python_version']} on {env_info['platform']}")
    print(f"CPU Hardware   : {env_info['cpu_count']} cores ({env_info['processor']})")
    print("=" * 80)

    feat_results = run_feature_extraction_benchmarks(repetitions=25, calls_per_rep=1000)
    e2e_results = run_end_to_end_estimate_benchmarks(
        candidate_counts=[6, 12, 24], batches_per_count=30
    )

    full_report = {
        "benchmark_title": "EpistemicOS Semantic Feature Extraction Optimization Benchmark",
        "environment": env_info,
        "methodology": {
            "repetitions": 25,
            "alternating_order": True,
            "metrics": ["mean", "stddev", "median_p50", "p95", "p99", "min", "max"],
            "cache_separation": "Cold-cache (isolated kernel calls) vs warm-cache (pre-warmed LRU)",
        },
        "feature_extraction_workloads": feat_results,
        "end_to_end_estimate_batches": e2e_results,
    }

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)

    print("\n" + "=" * 80)
    print(f"✓ Empirical benchmark successfully completed. Saved results to: {RESULTS_PATH}")
    print("=" * 80)


if __name__ == "__main__":
    main()
