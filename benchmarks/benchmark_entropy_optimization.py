#!/usr/bin/env python3
"""
⚡ Bolt Benchmark: EntropyAwareScheduler.entropy() Optimization

Benchmarks baseline vs optimized implementation across sequence lengths K = 2..128.
Measures:
- Latency across distribution profiles (uniform, skewed, deterministic)
- Type parsing (native floats vs custom numeric types with __float__)
- Validation overhead vs entropy-calculation loop overhead
- Statistical metrics: Median, P95, Mean, StdDev, Speedup Ratio, Delta
Outputs machine-readable benchmark JSON to results/entropy_optimization_benchmark_results.json.
"""

import json
import math
import os
import platform
import random
import statistics
import subprocess
import time
from typing import Any, Dict, List


def baseline_entropy(probabilities: Any) -> float:
    """Legacy unoptimized entropy implementation."""
    if hasattr(probabilities, "ndim") and getattr(probabilities, "ndim", 1) != 1:
        raise ValueError("Probabilities must be a 1D distribution sequence")

    try:
        p_clean = []
        total_sum = 0.0
        for v in probabilities:
            if isinstance(v, (list, tuple, dict, set)):
                raise ValueError("Probabilities must be a 1D distribution sequence")
            fval = float(v)
            if math.isnan(fval) or math.isinf(fval):
                raise ValueError("Probabilities cannot contain NaN or non-finite values")
            if fval < 0.0:
                raise ValueError("Probabilities cannot contain negative values")
            total_sum += fval
            p_clean.append(fval)
    except (TypeError, ValueError) as e:
        msg = str(e)
        if "NaN or non-finite" in msg or "negative values" in msg or "1D distribution" in msg:
            raise e
        item = v if "v" in locals() else probabilities
        raise ValueError(f"Invalid probability sequence or values: {item}") from e

    if not p_clean:
        raise ValueError("Probabilities sequence cannot be empty")

    if total_sum <= 0.0 or math.isnan(total_sum) or math.isinf(total_sum):
        raise ValueError("Probabilities must sum to a positive finite value")

    h = 0.0
    for p in p_clean:
        p_norm = p / total_sum
        if p_norm > 0.0:
            h -= p_norm * math.log2(p_norm)
    return h


class CustomNumber:
    """Custom numeric object with __float__."""
    def __init__(self, val: float):
        self.val = val

    def __float__(self) -> float:
        return float(self.val)


def get_git_info() -> Dict[str, Any]:
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip()
    except Exception:
        commit = "unknown"
    return {"commit": commit}


def percentile(data: List[float], p: float) -> float:
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_data[int(k)]
    d0 = sorted_data[int(f)] * (c - k)
    d1 = sorted_data[int(c)] * (k - f)
    return d0 + d1


def run_paired_benchmark(
    fn_baseline,
    fn_optimized,
    test_inputs: List[Any],
    num_trials: int = 40,
    calls_per_trial: int = 500
) -> Dict[str, Any]:
    # Warmup
    for _ in range(5):
        for inp in test_inputs:
            fn_baseline(inp)
            fn_optimized(inp)

    times_baseline: List[float] = []
    times_optimized: List[float] = []

    for trial in range(num_trials):
        if trial % 2 == 0:
            t0 = time.perf_counter()
            for _ in range(calls_per_trial):
                for inp in test_inputs:
                    fn_baseline(inp)
            t_base = ((time.perf_counter() - t0) * 1e6) / (calls_per_trial * len(test_inputs))

            t0 = time.perf_counter()
            for _ in range(calls_per_trial):
                for inp in test_inputs:
                    fn_optimized(inp)
            t_opt = ((time.perf_counter() - t0) * 1e6) / (calls_per_trial * len(test_inputs))
        else:
            t0 = time.perf_counter()
            for _ in range(calls_per_trial):
                for inp in test_inputs:
                    fn_optimized(inp)
            t_opt = ((time.perf_counter() - t0) * 1e6) / (calls_per_trial * len(test_inputs))

            t0 = time.perf_counter()
            for _ in range(calls_per_trial):
                for inp in test_inputs:
                    fn_baseline(inp)
            t_base = ((time.perf_counter() - t0) * 1e6) / (calls_per_trial * len(test_inputs))

        times_baseline.append(t_base)
        times_optimized.append(t_opt)

    med_base = percentile(times_baseline, 50)
    med_opt = percentile(times_optimized, 50)
    p95_base = percentile(times_baseline, 95)
    p95_opt = percentile(times_optimized, 95)
    mean_base = statistics.mean(times_baseline)
    mean_opt = statistics.mean(times_optimized)
    std_base = statistics.stdev(times_baseline)
    std_opt = statistics.stdev(times_optimized)

    speedup = med_base / med_opt if med_opt > 0 else 1.0
    reduction_pct = ((med_base - med_opt) / med_base * 100.0) if med_base > 0 else 0.0

    return {
        "median_baseline_us": round(med_base, 3),
        "median_optimized_us": round(med_opt, 3),
        "p95_baseline_us": round(p95_base, 3),
        "p95_optimized_us": round(p95_opt, 3),
        "mean_baseline_us": round(mean_base, 3),
        "mean_optimized_us": round(mean_opt, 3),
        "std_baseline_us": round(std_base, 3),
        "std_optimized_us": round(std_opt, 3),
        "speedup_ratio": round(speedup, 2),
        "latency_reduction_pct": round(reduction_pct, 1),
    }


def main():
    from epistemicos.scheduler import EntropyAwareScheduler

    scheduler = EntropyAwareScheduler()
    fn_opt = scheduler.entropy
    fn_base = baseline_entropy

    git_info = get_git_info()
    os.makedirs("results", exist_ok=True)

    header = "=" * 80
    print(header)
    print("⚡ BOLT BENCHMARK: EntropyAwareScheduler.entropy() Optimization")
    print(f"Commit:  {git_info['commit']}")
    print(f"Python:  {platform.python_version()} on {platform.system()}-{platform.machine()}")
    print("Method:  Paired alternating trials (N=40 trials x 500 calls/trial)")
    print(header)

    results: Dict[str, Any] = {
        "metadata": {
            "commit": git_info["commit"],
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "k_sweep": {},
        "distribution_profiles": {},
        "type_profiles": {},
    }

    # 1. K-Sweep (Uniform Distributions K = 2, 4, 8, 16, 32, 64, 128)
    print("\n--- Workload 1: Sequence Length Scaling (Uniform Distributions K=2..128) ---")
    fmt = "{:<5} | {:<10} | {:<10} | {:<10} | {:<10} | {:<8} | {:<14}"
    print(fmt.format("K", "Base Med", "Opt Med", "Base p95", "Opt p95", "Speedup", "Reduction"))
    print("-" * 80)

    for k in [2, 4, 8, 16, 32, 64, 128]:
        test_inputs = [[1.0 / k] * k]
        # Verify equivalence first
        assert abs(fn_base(test_inputs[0]) - fn_opt(test_inputs[0])) < 1e-12
        stats = run_paired_benchmark(fn_base, fn_opt, test_inputs)
        results["k_sweep"][f"K={k}"] = stats
        print(fmt.format(
            k,
            f"{stats['median_baseline_us']:.3f} µs",
            f"{stats['median_optimized_us']:.3f} µs",
            f"{stats['p95_baseline_us']:.3f} µs",
            f"{stats['p95_optimized_us']:.3f} µs",
            f"{stats['speedup_ratio']:.2f}x",
            f"-{stats['latency_reduction_pct']:.1f}%",
        ))

    # 2. Distribution Characteristics (Fixed K=32)
    print("\n--- Workload 2: Distribution Characteristics (Fixed K=32) ---")
    print(fmt.format(
        "Profile", "Base Med", "Opt Med", "Base p95", "Opt p95", "Speedup", "Reduction"
    ))
    print("-" * 80)

    profiles = {
        "Uniform": [1.0 / 32] * 32,
        "Skewed": [1.0] + [1e-12] * 31,
        "Deterministic": [1.0] + [0.0] * 31,
        "Random": [random.Random(42).uniform(0.01, 10.0) for _ in range(32)],
        "Extreme-Scale": [1e100] * 32,
    }

    for name, p in profiles.items():
        assert abs(fn_base(p) - fn_opt(p)) < 1e-12
        stats = run_paired_benchmark(fn_base, fn_opt, [p])
        results["distribution_profiles"][name] = stats
        print(fmt.format(
            name,
            f"{stats['median_baseline_us']:.3f} µs",
            f"{stats['median_optimized_us']:.3f} µs",
            f"{stats['p95_baseline_us']:.3f} µs",
            f"{stats['p95_optimized_us']:.3f} µs",
            f"{stats['speedup_ratio']:.2f}x",
            f"-{stats['latency_reduction_pct']:.1f}%",
        ))

    # 3. Input Types (Fixed K=16)
    print("\n--- Workload 3: Input Types & Type Fast-Pathing (Fixed K=16) ---")
    print(fmt.format(
        "Type", "Base Med", "Opt Med", "Base p95", "Opt p95", "Speedup", "Reduction"
    ))
    print("-" * 80)

    type_inputs = {
        "Native Float": [float(i + 1) for i in range(16)],
        "Native Int": [int(i + 1) for i in range(16)],
        "Custom Numeric": [CustomNumber(float(i + 1)) for i in range(16)],
    }

    for name, p in type_inputs.items():
        assert abs(fn_base(p) - fn_opt(p)) < 1e-12
        stats = run_paired_benchmark(fn_base, fn_opt, [p])
        results["type_profiles"][name] = stats
        print(fmt.format(
            name,
            f"{stats['median_baseline_us']:.3f} µs",
            f"{stats['median_optimized_us']:.3f} µs",
            f"{stats['p95_baseline_us']:.3f} µs",
            f"{stats['p95_optimized_us']:.3f} µs",
            f"{stats['speedup_ratio']:.2f}x",
            f"-{stats['latency_reduction_pct']:.1f}%",
        ))

    out_file = "results/entropy_optimization_benchmark_results.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)

    print(header)
    print(f"✓ Benchmark results written to {out_file}")
    print(header)


if __name__ == "__main__":
    main()
