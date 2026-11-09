#!/usr/bin/env python3
"""
⚡ BOLT: Isolated Benchmark for Approval Signature Format Validation.

Directly benchmarks and compares the original Python generator any() character scans
against the module-level precompiled C-level regular expression format check.

Workloads evaluated:
1. Isolated Predicate: 64-character valid hex signature
2. Isolated Predicate: 64-character invalid hex (invalid character at end)
3. Isolated Predicate: 64-character invalid hex (invalid character at start)
4. Isolated Predicate: 64-character whitespace / non-hex chars
"""

import os
import platform
import statistics
import subprocess
import time
from typing import Any, Dict, List, Tuple

from epistemicos.action_policy import _APPROVAL_SIG_HEX_REGEX


def original_signature_format_check(sig: Any) -> bool:
    """Original signature format validation before optimization."""
    if not isinstance(sig, str) or len(sig) != 64:
        return False
    _HEX_CHARS = frozenset("0123456789abcdefABCDEF")
    if any(c not in _HEX_CHARS for c in sig):
        return False
    return True


def optimized_signature_format_check(sig: Any) -> bool:
    """Optimized signature format validation using precompiled regex."""
    if not isinstance(sig, str) or len(sig) != 64:
        return False
    if not _APPROVAL_SIG_HEX_REGEX.match(sig):
        return False
    return True


def get_git_commit_sha() -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True
        )
        return res.stdout.strip()
    except Exception:
        return "UNKNOWN_SHA"


def compute_percentiles(data: List[float]) -> Tuple[float, float, float, float]:
    sorted_data = sorted(data)
    n = len(sorted_data)
    mean_val = statistics.mean(sorted_data)
    median_val = statistics.median(sorted_data)
    p95_idx = int(0.95 * (n - 1))
    p95_val = sorted_data[p95_idx]
    std_val = statistics.stdev(sorted_data) if n > 1 else 0.0
    return mean_val, median_val, p95_val, std_val


def benchmark_predicate(
    name: str,
    inputs: List[str],
    iterations_per_trial: int = 1000,
    trial_count: int = 25
) -> Dict[str, Any]:
    total_ops = len(inputs) * iterations_per_trial
    orig_times = []
    opt_times = []

    for trial in range(trial_count):
        if trial % 2 == 0:
            # Original first
            t0 = time.perf_counter()
            for _ in range(iterations_per_trial):
                for s in inputs:
                    original_signature_format_check(s)
            t_orig = time.perf_counter() - t0

            # Optimized second
            t0 = time.perf_counter()
            for _ in range(iterations_per_trial):
                for s in inputs:
                    optimized_signature_format_check(s)
            t_opt = time.perf_counter() - t0
        else:
            # Optimized first
            t0 = time.perf_counter()
            for _ in range(iterations_per_trial):
                for s in inputs:
                    optimized_signature_format_check(s)
            t_opt = time.perf_counter() - t0

            # Original second
            t0 = time.perf_counter()
            for _ in range(iterations_per_trial):
                for s in inputs:
                    original_signature_format_check(s)
            t_orig = time.perf_counter() - t0

        orig_times.append(t_orig)
        opt_times.append(t_opt)

    o_mean, o_med, o_p95, o_std = compute_percentiles(orig_times)
    p_mean, p_med, p_p95, p_std = compute_percentiles(opt_times)

    speedup_median = o_med / p_med if p_med > 0 else 1.0
    speedup_mean = o_mean / p_mean if p_mean > 0 else 1.0

    o_us_med = (o_med / total_ops) * 1e6
    o_us_p95 = (o_p95 / total_ops) * 1e6
    p_us_med = (p_med / total_ops) * 1e6
    p_us_p95 = (p_p95 / total_ops) * 1e6

    reduction_pct = ((o_med - p_med) / o_med) * 100.0 if o_med > 0 else 0.0

    return {
        "workload": name,
        "sample_count": len(inputs),
        "total_evaluations_per_trial": total_ops,
        "trials": trial_count,
        "original": {
            "median_sec": o_med,
            "p95_sec": o_p95,
            "us_per_op_median": o_us_med,
            "us_per_op_p95": o_us_p95,
        },
        "optimized": {
            "median_sec": p_med,
            "p95_sec": p_p95,
            "us_per_op_median": p_us_med,
            "us_per_op_p95": p_us_p95,
        },
        "speedup_median": round(speedup_median, 2),
        "speedup_mean": round(speedup_mean, 2),
        "latency_reduction_pct": round(reduction_pct, 1),
    }


def main():
    print("=" * 78)
    print("⚡ BOLT: Isolated Benchmark (Approval Signature Validation)")
    print("=" * 78)

    env = {
        "commit_sha": get_git_commit_sha(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "cpu_count": os.cpu_count() or 1,
    }
    print(f"Commit:  {env['commit_sha']}")
    print(f"Python:  {env['python_version']} on {env['platform']} (CPUs: {env['cpu_count']})")
    print("-" * 78)

    # Workloads:
    valid_sigs = [
        "a" * 64,
        "0" * 64,
        "f" * 64,
        "A" * 64,
        "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF",
        "4a5b6c7d8e9f00112233445566778899aabbccddeeff00112233445566778899",
    ]

    invalid_end = [
        ("a" * 63) + "z",
        ("0" * 63) + " ",
        ("f" * 63) + "\x00",
        ("A" * 63) + "!",
    ]

    invalid_start = [
        "z" + ("a" * 63),
        " " + ("0" * 63),
        "\x00" + ("f" * 63),
        "+" + ("A" * 63),
    ]

    invalid_misc = [
        " " * 64,
        "z" * 64,
        "\x00" * 64,
        "0123456789abcdef" * 3 + "xyz!",
    ]

    workloads = [
        ("1. Valid 64-char Hex Signatures", valid_sigs, 2000),
        ("2. Malformed: Invalid Char at End", invalid_end, 2000),
        ("3. Malformed: Invalid Char at Start", invalid_start, 2000),
        ("4. Malformed: Non-Hex Characters", invalid_misc, 2000),
    ]

    for title, inputs, iters in workloads:
        res = benchmark_predicate(title, inputs, iterations_per_trial=iters, trial_count=25)
        print(f"\n📊 {res['workload']}:")
        print(f"  Samples: {res['sample_count']} | Ops/trial: {res['total_evaluations_per_trial']} | Trials: {res['trials']}")
        print(f"  Original:  median={res['original']['us_per_op_median']:.3f} µs/op, p95={res['original']['us_per_op_p95']:.3f} µs/op")
        print(f"  Optimized: median={res['optimized']['us_per_op_median']:.3f} µs/op, p95={res['optimized']['us_per_op_p95']:.3f} µs/op")
        print(f"  ⚡ Speedup: {res['speedup_median']:.2f}x (median), {res['speedup_mean']:.2f}x (mean) | Latency reduction: {res['latency_reduction_pct']}%")

    print("\n" + "=" * 78)


if __name__ == "__main__":
    main()
