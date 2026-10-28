"""
Benchmark script measuring performance of TokenSurprisalSensor.evaluate
comparing the original vs optimized implementations for both malformed (non-finite)
and normal finite input paths over repeated runs.
"""

import time
import math
import statistics
from typing import List, Dict, Any
from epistemicos.models import TokenSurprisalSensor


def original_evaluate(sensor: TokenSurprisalSensor, logprobs: List[float], z_scores: List[float]) -> Dict[str, Any]:
    """Original implementation of non-finite evaluation in evaluate()."""
    if any(not math.isfinite(z) for z in z_scores):
        non_finite_count = sum(1 for z in z_scores if not math.isfinite(z))
        sanitized_z_scores = [z if math.isfinite(z) else None for z in z_scores]
        return {
            "passed": False,
            "reason": "MALFORMED_NON_FINITE_LOGPROBS",
            "error": f"Derived Z-scores contain {non_finite_count} non-finite value(s)",
            "max_z_score": 0.0,
            "flagged_tokens": len(logprobs) if logprobs else 1,
            "token_z_scores": sanitized_z_scores
        }

    flagged_count = 0
    for i, z in enumerate(z_scores):
        lp = float(logprobs[i])
        surprisal = -lp
        is_z_anomaly = z > sensor.z_threshold
        is_ceiling_anomaly = (
            sensor.max_surprisal_ceiling is not None
            and surprisal > sensor.max_surprisal_ceiling
        )
        if is_z_anomaly or is_ceiling_anomaly:
            flagged_count += 1

    max_z = float(max(z_scores)) if z_scores else 0.0

    return {
        "passed": flagged_count == 0,
        "max_z_score": max_z,
        "flagged_tokens": flagged_count,
        "token_z_scores": z_scores
    }


def optimized_evaluate(sensor: TokenSurprisalSensor, logprobs: List[float], z_scores: List[float]) -> Dict[str, Any]:
    """Optimized implementation of non-finite evaluation in evaluate()."""
    isfinite = math.isfinite
    if any(not isfinite(z) for z in z_scores):
        sanitized_z_scores = [z if isfinite(z) else None for z in z_scores]
        non_finite_count = sanitized_z_scores.count(None)
        return {
            "passed": False,
            "reason": "MALFORMED_NON_FINITE_LOGPROBS",
            "error": f"Derived Z-scores contain {non_finite_count} non-finite value(s)",
            "max_z_score": 0.0,
            "flagged_tokens": len(logprobs) if logprobs else 1,
            "token_z_scores": sanitized_z_scores
        }

    flagged_count = 0
    for i, z in enumerate(z_scores):
        lp = float(logprobs[i])
        surprisal = -lp
        is_z_anomaly = z > sensor.z_threshold
        is_ceiling_anomaly = (
            sensor.max_surprisal_ceiling is not None
            and surprisal > sensor.max_surprisal_ceiling
        )
        if is_z_anomaly or is_ceiling_anomaly:
            flagged_count += 1

    max_z = float(max(z_scores)) if z_scores else 0.0

    return {
        "passed": flagged_count == 0,
        "max_z_score": max_z,
        "flagged_tokens": flagged_count,
        "token_z_scores": z_scores
    }


def run_benchmark():
    sensor = TokenSurprisalSensor()

    scenarios = {
        "Malformed (Small, 10 items, 20% non-finite)": (
            [-0.5] * 10,
            [1.0, float('nan'), 2.5, float('inf'), 3.0, 1.2, 0.5, 0.0, -1.0, 2.0]
        ),
        "Malformed (Medium, 100 items, 10% non-finite)": (
            [-0.5] * 100,
            [float('nan') if i % 10 == 0 else float(i) for i in range(100)]
        ),
        "Malformed (Large, 10k items, 10% non-finite)": (
            [-0.5] * 10000,
            [float('nan') if i % 10 == 0 else float(i) for i in range(10000)]
        ),
        "Normal Finite (Small, 10 items)": (
            [-0.5] * 10,
            [float(i) * 0.1 for i in range(10)]
        ),
        "Normal Finite (Medium, 100 items)": (
            [-0.5] * 100,
            [float(i) * 0.1 for i in range(100)]
        ),
        "Normal Finite (Large, 10k items)": (
            [-0.5] * 10000,
            [float(i) * 0.1 for i in range(10000)]
        ),
    }

    warmup_runs = 100
    measurement_runs = 5
    iters_per_run = 1000

    print("=" * 80)
    print(" TOKEN SURPRISAL SENSOR EVALUATE BENCHMARK REPORT")
    print("=" * 80)

    for name, (logprobs, z_scores) in scenarios.items():
        # Correctness check
        res_orig = original_evaluate(sensor, logprobs, z_scores)
        res_opt = optimized_evaluate(sensor, logprobs, z_scores)
        assert res_orig == res_opt, f"Mismatch in {name}"

        # Warmup
        for _ in range(warmup_runs):
            original_evaluate(sensor, logprobs, z_scores)
            optimized_evaluate(sensor, logprobs, z_scores)

        # Measure Original across repeated runs
        orig_run_times = []
        for _ in range(measurement_runs):
            t0 = time.perf_counter()
            for _ in range(iters_per_run):
                original_evaluate(sensor, logprobs, z_scores)
            t1 = time.perf_counter()
            orig_run_times.append((t1 - t0) * 1000.0 / iters_per_run) # ms per single call

        # Measure Optimized across repeated runs
        opt_run_times = []
        for _ in range(measurement_runs):
            t0 = time.perf_counter()
            for _ in range(iters_per_run):
                optimized_evaluate(sensor, logprobs, z_scores)
            t1 = time.perf_counter()
            opt_run_times.append((t1 - t0) * 1000.0 / iters_per_run) # ms per single call

        avg_orig = statistics.mean(orig_run_times)
        avg_opt = statistics.mean(opt_run_times)
        std_orig = statistics.stdev(orig_run_times)
        std_opt = statistics.stdev(opt_run_times)

        diff_ms = avg_orig - avg_opt
        speedup = avg_orig / avg_opt if avg_opt > 0 else 1.0
        pct_improvement = (diff_ms / avg_orig) * 100.0 if avg_orig > 0 else 0.0

        print(f"\nScenario: {name}")
        print(f"  Original Impl  : {avg_orig * 1000:.3f} µs/op (± {std_orig * 1000:.3f} µs)")
        print(f"  Optimized Impl : {avg_opt * 1000:.3f} µs/op (± {std_opt * 1000:.3f} µs)")
        print(f"  Speedup        : {speedup:.2f}x ({pct_improvement:.1f}% reduction in execution time)")

    print("=" * 80)

if __name__ == "__main__":
    run_benchmark()
