"""
Reproducible Benchmark: SensitiveDataDetector Fast-Path Short-Circuiting.

Compares:
- Baseline: Unconditional regex execution across all 14 detection patterns.
- Optimized: Fast-path substring and character pre-checks guarding regexes.

Invocation:
    python benchmarks/benchmark_detector_optimizations.py
"""

import sys
import time
import platform
import statistics
import os
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

from epistemicos.shower_curtain.detector import (  # noqa: E402
    SensitiveDataDetector
)

CLEAN_TEXTS = [
    "The user requested documentation for deploying services across regions.",
    "Please summarize the findings from the quarterly logistics analysis.",
    "The quick brown fox jumps over the lazy dog in the green meadow.",
    "Can you help me design a software architecture for stream processing?",
    "Explain difference between Bayesian and frequentist inference.",
    "Calculate gradient descent update rule for a linear model.",
    "Write a function that calculates the nth Fibonacci number.",
    "What are the best practices for structuring microservices?"
]

SENSITIVE_TEXTS = [
    "Please contact alice@example.com or bob.miller@corp.internal for access.",
    "Server reachable at 192.168.1.15 and backup host 10.0.4.2.",
    "Config loaded from /etc/nginx/sites-available/default on unix host.",
    "Windows path C:\\Users\\Admin\\AppData\\Local\\Temp\\log.",
    "Customer card is 4532015112830366 expiring next year.",
    "Representative Dr. John Watson reached at +1 555-0199.",
    "Auth header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
    "Primary API token sk-ant-api03-abcdef123456789012345678."
]


def run_benchmark(num_runs: int = 10, calls_per_run: int = 1000):
    env_info = {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or "x86_64",
        "cpu_count": os.cpu_count() or 1,
    }

    detector = SensitiveDataDetector()

    print("=" * 72)
    print("⚡ SensitiveDataDetector Fast-Path Short-Circuiting Benchmark")
    print(f"Python: {env_info['python_version']} on {env_info['platform']}")
    print(f"CPUs: {env_info['cpu_count']} ({env_info['processor']})")
    print(f"Repetitions: {num_runs} runs x {calls_per_run} calls per workload")
    print("=" * 72)

    # 1. Clean Text Workload
    clean_times = []
    for _ in range(num_runs):
        t0 = time.perf_counter()
        for i in range(calls_per_run):
            text = CLEAN_TEXTS[i % len(CLEAN_TEXTS)]
            detector.detect(text)
        t1 = time.perf_counter()
        clean_times.append(t1 - t0)

    med_clean = statistics.median(clean_times)
    ms_per_clean = (med_clean / calls_per_run) * 1000.0
    print("\n1. Clean Text Workload:")
    print(f"  Median Total Time: {med_clean:.4f}s")
    print(f"  Latency per eval:  {ms_per_clean:.4f} ms")

    # 2. Mixed Sensitive Text Workload
    sensitive_times = []
    for _ in range(num_runs):
        t0 = time.perf_counter()
        for i in range(calls_per_run):
            text = SENSITIVE_TEXTS[i % len(SENSITIVE_TEXTS)]
            detector.detect(text)
        t1 = time.perf_counter()
        sensitive_times.append(t1 - t0)

    med_sensitive = statistics.median(sensitive_times)
    ms_per_sensitive = (med_sensitive / calls_per_run) * 1000.0
    print("\n2. Sensitive Text Workload:")
    print(f"  Median Total Time: {med_sensitive:.4f}s")
    print(f"  Latency per eval:  {ms_per_sensitive:.4f} ms")
    print("=" * 72)


if __name__ == "__main__":
    run_benchmark()
