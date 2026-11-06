"""
Benchmark script measuring performance of TokenSurprisalSensor.evaluate
comparing the original pre-PR multi-pass implementation vs the exact new
single-pass streaming implementation across representative sequence lengths.

Covers:
1. Isolated post-processing comparison (given pre-computed z_scores and logprobs)
2. Full end-to-end evaluate() comparison (including compute_z_scores)
"""

import time
import math
import statistics
from typing import List, Dict, Any, Tuple
from epistemicos.models import TokenSurprisalSensor


def original_post_process(
    sensor: TokenSurprisalSensor, logprobs: List[float], z_scores: List[float]
) -> Dict[str, Any]:
    """Exact pre-PR multi-pass post-processing implementation."""
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


def original_evaluate(sensor: TokenSurprisalSensor, logprobs: List[float]) -> Dict[str, Any]:
    """Exact pre-PR full evaluate() implementation."""
    try:
        z_scores = sensor.compute_z_scores(logprobs)
    except ValueError as e:
        return {
            "passed": False,
            "reason": "MALFORMED_NON_FINITE_LOGPROBS",
            "error": str(e),
            "max_z_score": 0.0,
            "flagged_tokens": len(logprobs) if logprobs else 1,
            "token_z_scores": []
        }

    return original_post_process(sensor, logprobs, z_scores)


def optimized_post_process(
    sensor: TokenSurprisalSensor, logprobs: List[float], z_scores: List[float]
) -> Dict[str, Any]:
    """Exact new single-pass streaming post-processing implementation."""
    if not z_scores:
        return {
            "passed": True,
            "max_z_score": 0.0,
            "flagged_tokens": 0,
            "token_z_scores": []
        }

    isfinite = math.isfinite
    z_threshold = sensor.z_threshold
    ceiling = sensor.max_surprisal_ceiling
    has_ceiling = ceiling is not None

    flagged_count = 0
    max_z = float("-inf")
    has_non_finite = False

    for i, z in enumerate(z_scores):
        if not isfinite(z):
            has_non_finite = True
            break
        if z > max_z:
            max_z = z
        lp = float(logprobs[i])
        surprisal = -lp
        is_z_anomaly = z > z_threshold
        is_ceiling_anomaly = has_ceiling and surprisal > ceiling
        if is_z_anomaly or is_ceiling_anomaly:
            flagged_count += 1

    if has_non_finite:
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

    return {
        "passed": flagged_count == 0,
        "max_z_score": float(max_z),
        "flagged_tokens": flagged_count,
        "token_z_scores": z_scores
    }


def optimized_evaluate(sensor: TokenSurprisalSensor, logprobs: List[float]) -> Dict[str, Any]:
    """Uses sensor.evaluate() directly which runs the new single-pass implementation."""
    return sensor.evaluate(logprobs)


def _compute_stats(times_us: List[float]) -> Dict[str, float]:
    sorted_times = sorted(times_us)
    p95_idx = int(math.ceil(0.95 * len(sorted_times))) - 1
    return {
        "mean": statistics.mean(times_us),
        "median": statistics.median(times_us),
        "std": statistics.stdev(times_us) if len(times_us) > 1 else 0.0,
        "min": sorted_times[0],
        "max": sorted_times[-1],
        "p95": sorted_times[p95_idx]
    }


def run_benchmark():
    sensor = TokenSurprisalSensor()

    scenarios: Dict[str, Tuple[List[float], List[float]]] = {
        "Normal Finite (N=10)": (
            [-0.5 * (1 + (i % 5)) for i in range(10)],
            sensor.compute_z_scores([-0.5 * (1 + (i % 5)) for i in range(10)])
        ),
        "Normal Finite (N=50)": (
            [-0.5 * (1 + (i % 5)) for i in range(50)],
            sensor.compute_z_scores([-0.5 * (1 + (i % 5)) for i in range(50)])
        ),
        "Normal Finite (N=100)": (
            [-0.5 * (1 + (i % 5)) for i in range(100)],
            sensor.compute_z_scores([-0.5 * (1 + (i % 5)) for i in range(100)])
        ),
        "Normal Finite (N=1000)": (
            [-0.5 * (1 + (i % 5)) for i in range(1000)],
            sensor.compute_z_scores([-0.5 * (1 + (i % 5)) for i in range(1000)])
        ),
        "Anomaly Present (N=100)": (
            [-0.5 * (1 + (i % 5)) if i != 50 else -15.0 for i in range(100)],
            sensor.compute_z_scores(
                [-0.5 * (1 + (i % 5)) if i != 50 else -15.0 for i in range(100)]
            )
        ),
        "Malformed Non-Finite (N=100, 10% NaN)": (
            [-0.5] * 100,
            [float('nan') if i % 10 == 0 else float(i) * 0.1 for i in range(100)]
        ),
    }

    warmup_runs = 25
    measurement_trials = 100
    iters_per_trial = 500

    print("=" * 135)
    print(" TOKEN SURPRISAL SENSOR: PRE-PR MULTI-PASS VS NEW SINGLE-PASS BENCHMARK")
    print(f" Trials: {measurement_trials} paired alternating runs | Warmups: {warmup_runs} | "
          f"Percentile estimator: Nearest-rank (sorted[ceil(0.95*N)-1])")
    print("=" * 135)

    hdr = (
        f"{'Scenario':<34} | {'Orig Med (p95) ±Std µs':<27} | {'Opt Med (p95) ±Std µs':<27} | "
        f"{'Speedup':<8} | {'Latency Reduction':<18}"
    )

    # 1. Post-Processing Benchmark (Isolated)
    print("\n--- PART 1: Isolated Post-Processing (Kernel Microbenchmark) ---")
    print(hdr)
    print("-" * len(hdr))

    for name, (logprobs, z_scores) in scenarios.items():
        # Verify equivalence
        res_orig = original_post_process(sensor, logprobs, z_scores)
        res_opt = optimized_post_process(sensor, logprobs, z_scores)
        assert res_orig == res_opt, f"Equivalence mismatch in post-process for {name}"

        # Warmup
        for _ in range(warmup_runs):
            original_post_process(sensor, logprobs, z_scores)
            optimized_post_process(sensor, logprobs, z_scores)

        orig_trials = []
        opt_trials = []
        iters = iters_per_trial if len(z_scores) <= 100 else 100

        for trial in range(measurement_trials):
            if trial % 2 == 0:
                t0 = time.perf_counter()
                for _ in range(iters):
                    original_post_process(sensor, logprobs, z_scores)
                t1 = time.perf_counter()
                orig_trials.append((t1 - t0) * 1e6 / iters)

                t0 = time.perf_counter()
                for _ in range(iters):
                    optimized_post_process(sensor, logprobs, z_scores)
                t1 = time.perf_counter()
                opt_trials.append((t1 - t0) * 1e6 / iters)
            else:
                t0 = time.perf_counter()
                for _ in range(iters):
                    optimized_post_process(sensor, logprobs, z_scores)
                t1 = time.perf_counter()
                opt_trials.append((t1 - t0) * 1e6 / iters)

                t0 = time.perf_counter()
                for _ in range(iters):
                    original_post_process(sensor, logprobs, z_scores)
                t1 = time.perf_counter()
                orig_trials.append((t1 - t0) * 1e6 / iters)

        orig_stats = _compute_stats(orig_trials)
        opt_stats = _compute_stats(opt_trials)
        med_orig = orig_stats["median"]
        p95_orig = orig_stats["p95"]
        std_orig = orig_stats["std"]
        med_opt = opt_stats["median"]
        p95_opt = opt_stats["p95"]
        std_opt = opt_stats["std"]
        speedup = med_orig / med_opt if med_opt > 0 else 1.0
        pct_reduction = ((med_orig - med_opt) / med_orig) * 100.0 if med_orig > 0 else 0.0

        orig_str = f"{med_orig:6.3f} ({p95_orig:6.3f}) ±{std_orig:4.2f}"
        opt_str = f"{med_opt:6.3f} ({p95_opt:6.3f}) ±{std_opt:4.2f}"
        print(
            f"{name:<34} | {orig_str:<27} | {opt_str:<27} | {speedup:5.2f}x  | "
            f"{pct_reduction:5.1f}%"
        )

    # 2. End-to-End evaluate() Benchmark
    print("\n--- PART 2: Full evaluate() End-to-End Pipeline ---")
    print(hdr)
    print("-" * len(hdr))

    e2e_scenarios = {
        "Normal Finite (N=10)": [-0.5 * (1 + (i % 5)) for i in range(10)],
        "Normal Finite (N=50)": [-0.5 * (1 + (i % 5)) for i in range(50)],
        "Normal Finite (N=100)": [-0.5 * (1 + (i % 5)) for i in range(100)],
        "Normal Finite (N=1000)": [-0.5 * (1 + (i % 5)) for i in range(1000)],
        "Anomaly Present (N=100)": [
            -0.5 * (1 + (i % 5)) if i != 50 else -15.0 for i in range(100)
        ],
    }

    for name, logprobs in e2e_scenarios.items():
        # Verify equivalence
        res_orig = original_evaluate(sensor, logprobs)
        res_opt = optimized_evaluate(sensor, logprobs)
        assert res_orig == res_opt, f"Equivalence mismatch in evaluate for {name}"

        # Warmup
        for _ in range(warmup_runs):
            original_evaluate(sensor, logprobs)
            optimized_evaluate(sensor, logprobs)

        orig_trials = []
        opt_trials = []
        iters = 200 if len(logprobs) <= 100 else 50

        for trial in range(measurement_trials):
            if trial % 2 == 0:
                t0 = time.perf_counter()
                for _ in range(iters):
                    original_evaluate(sensor, logprobs)
                t1 = time.perf_counter()
                orig_trials.append((t1 - t0) * 1e6 / iters)

                t0 = time.perf_counter()
                for _ in range(iters):
                    optimized_evaluate(sensor, logprobs)
                t1 = time.perf_counter()
                opt_trials.append((t1 - t0) * 1e6 / iters)
            else:
                t0 = time.perf_counter()
                for _ in range(iters):
                    optimized_evaluate(sensor, logprobs)
                t1 = time.perf_counter()
                opt_trials.append((t1 - t0) * 1e6 / iters)

                t0 = time.perf_counter()
                for _ in range(iters):
                    original_evaluate(sensor, logprobs)
                t1 = time.perf_counter()
                orig_trials.append((t1 - t0) * 1e6 / iters)

        orig_stats = _compute_stats(orig_trials)
        opt_stats = _compute_stats(opt_trials)
        med_orig = orig_stats["median"]
        p95_orig = orig_stats["p95"]
        std_orig = orig_stats["std"]
        med_opt = opt_stats["median"]
        p95_opt = opt_stats["p95"]
        std_opt = opt_stats["std"]
        speedup = med_orig / med_opt if med_opt > 0 else 1.0
        pct_reduction = ((med_orig - med_opt) / med_orig) * 100.0 if med_orig > 0 else 0.0

        orig_str = f"{med_orig:6.3f} ({p95_orig:6.3f}) ±{std_orig:4.2f}"
        opt_str = f"{med_opt:6.3f} ({p95_opt:6.3f}) ±{std_opt:4.2f}"
        print(
            f"{name:<34} | {orig_str:<27} | {opt_str:<27} | {speedup:5.2f}x  | "
            f"{pct_reduction:5.1f}%"
        )

    print("=" * len(hdr))


if __name__ == "__main__":
    run_benchmark()
