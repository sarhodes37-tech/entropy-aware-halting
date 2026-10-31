"""
EpistemicOS TokenSurprisalSensor Benchmark Suite.

Independent, reproducible, same-process benchmark comparing the optimized implementation
against the pre-PR reference implementation.
Uses interleaved/randomized execution order across identical workloads.
Measures both compute_z_scores() and evaluate() independently and reports
per-run measurements, median, mean, and dispersion alongside Python and hardware metadata.
"""

import sys
import time
import math
import random
import statistics
import platform
import os
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

from epistemicos.models import TokenSurprisalSensor
from tests.unit.test_models import _pre_pr_compute_z_scores


def pre_pr_evaluate(sensor: TokenSurprisalSensor, logprobs):
    try:
        z_scores = _pre_pr_compute_z_scores(sensor, logprobs)
    except ValueError as e:
        return {
            "passed": False,
            "reason": "MALFORMED_NON_FINITE_LOGPROBS",
            "error": str(e),
            "max_z_score": 0.0,
            "flagged_tokens": len(logprobs) if logprobs else 1,
            "token_z_scores": []
        }

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


def run_benchmark(num_runs: int = 10, calls_per_run: int = 1000):
    env_info = {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or "x86_64",
        "cpu_count": os.cpu_count() or 1,
    }

    sensor = TokenSurprisalSensor()
    workload = [-0.1, -0.2, -0.15, -0.12, -0.18, -0.11, -0.25, -0.14, -0.19, -0.10] * 50

    # Warmup
    for _ in range(100):
        _pre_pr_compute_z_scores(sensor, workload)
        sensor.compute_z_scores(workload)
        pre_pr_evaluate(sensor, workload)
        sensor.evaluate(workload)

    rng = random.Random(42)

    ref_compute_runs = []
    opt_compute_runs = []
    ref_eval_runs = []
    opt_eval_runs = []

    for _ in range(num_runs):
        order = ["ref", "opt"]
        rng.shuffle(order)

        measurements = {}
        for impl in order:
            if impl == "ref":
                t0 = time.perf_counter()
                for _ in range(calls_per_run):
                    _pre_pr_compute_z_scores(sensor, workload)
                t1 = time.perf_counter()
                measurements["ref_compute"] = t1 - t0

                t0 = time.perf_counter()
                for _ in range(calls_per_run):
                    pre_pr_evaluate(sensor, workload)
                t1 = time.perf_counter()
                measurements["ref_eval"] = t1 - t0
            else:
                t0 = time.perf_counter()
                for _ in range(calls_per_run):
                    sensor.compute_z_scores(workload)
                t1 = time.perf_counter()
                measurements["opt_compute"] = t1 - t0

                t0 = time.perf_counter()
                for _ in range(calls_per_run):
                    sensor.evaluate(workload)
                t1 = time.perf_counter()
                measurements["opt_eval"] = t1 - t0

        ref_compute_runs.append(measurements["ref_compute"])
        opt_compute_runs.append(measurements["opt_compute"])
        ref_eval_runs.append(measurements["ref_eval"])
        opt_eval_runs.append(measurements["opt_eval"])

    compute_speedup = statistics.median(ref_compute_runs) / statistics.median(opt_compute_runs)
    eval_speedup = statistics.median(ref_eval_runs) / statistics.median(opt_eval_runs)

    print("=================================================================")
    print("EpistemicOS TokenSurprisalSensor Benchmark Results")
    print("=================================================================")
    print(f"Python: {env_info['python_version']} on {env_info['platform']}")
    print(f"CPUs: {env_info['cpu_count']} ({env_info['processor']})")
    print(f"Repetitions: {num_runs} runs x {calls_per_run} calls (500 tokens/call)")
    print("-----------------------------------------------------------------")
    print("1. compute_z_scores():")
    print(f"  Ref runs (s): {[round(x, 4) for x in ref_compute_runs]}")
    print(f"  Opt runs (s): {[round(x, 4) for x in opt_compute_runs]}")
    print(f"  Ref Median: {statistics.median(ref_compute_runs):.4f}s | Mean: {statistics.mean(ref_compute_runs):.4f}s | Stdev: {statistics.stdev(ref_compute_runs):.4f}s")
    print(f"  Opt Median: {statistics.median(opt_compute_runs):.4f}s | Mean: {statistics.mean(opt_compute_runs):.4f}s | Stdev: {statistics.stdev(opt_compute_runs):.4f}s")
    print(f"  Median Speedup: {compute_speedup:.2f}x (Latency delta: -{(1.0 - 1.0/compute_speedup)*100:.1f}%)")
    print("-----------------------------------------------------------------")
    print("2. evaluate():")
    print(f"  Ref runs (s): {[round(x, 4) for x in ref_eval_runs]}")
    print(f"  Opt runs (s): {[round(x, 4) for x in opt_eval_runs]}")
    print(f"  Ref Median: {statistics.median(ref_eval_runs):.4f}s | Mean: {statistics.mean(ref_eval_runs):.4f}s | Stdev: {statistics.stdev(ref_eval_runs):.4f}s")
    print(f"  Opt Median: {statistics.median(opt_eval_runs):.4f}s | Mean: {statistics.mean(opt_eval_runs):.4f}s | Stdev: {statistics.stdev(opt_eval_runs):.4f}s")
    print(f"  Median Speedup: {eval_speedup:.2f}x (Latency delta: -{(1.0 - 1.0/eval_speedup)*100:.1f}%)")
    print("=================================================================")


if __name__ == "__main__":
    run_benchmark()
