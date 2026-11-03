"""
Empirical Benchmark Harness for ContainmentGuard Candidate Detection & Host Normalization.
"""

import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Imports from epistemicos after sys.path configuration
from epistemicos.containment import (  # noqa: E402
    ContainmentGuard,
    normalize_destination_host,
    _cached_normalize_destination_host,
    parse_url_authority_structure,
)

RESULTS_PATH = REPO_ROOT / "results" / "containment_optimization_benchmark_results.json"


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


def get_environment_info() -> Dict[str, Any]:
    return {
        "commit_sha": get_git_commit_sha(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or "x86_64",
        "cpu_count": os.cpu_count() or 1,
    }


def _unoptimized_normalize_destination_host(target_url_or_host: str) -> str:
    """Pre-PR baseline: uncached direct authority parsing."""
    res = parse_url_authority_structure(target_url_or_host)
    return res["normalized_host"]


def _unoptimized_is_candidate_destination(curr: str, key_context: str = "") -> bool:
    """Pre-PR baseline: unconditional authority parsing without trigger-character guard."""
    import ipaddress
    import re
    from epistemicos.containment import parse_ip_numeric

    if not curr or not isinstance(curr, str):
        return False
    s = curr.strip()
    if not s:
        return False

    norm = _unoptimized_normalize_destination_host(s)
    if not norm:
        return False

    if "://" in s or s.startswith("//") or s.startswith(("http://", "https://", "ftp://")):
        return True

    if "/" in s or ":" in s:
        return True

    try:
        ipaddress.ip_address(norm)
        return True
    except ValueError:
        pass

    if parse_ip_numeric(s) is not None:
        return True

    if re.search(r"\.[a-zA-Z]{2,}$", norm):
        ignored = (
            ".py", ".txt", ".json", ".md", ".sh", ".csv",
            ".log", ".yaml", ".yml", ".html", ".css", ".js", ".png", ".jpg", ".pdf"
        )
        if not norm.endswith(ignored):
            return True

    return False


def compute_metrics(trials: List[float]) -> Dict[str, float]:
    sorted_trials = sorted(trials)
    n = len(sorted_trials)
    p50 = statistics.median(sorted_trials)
    p95_idx = int(round(0.95 * (n - 1)))
    p95 = sorted_trials[min(p95_idx, n - 1)]
    mean_val = statistics.mean(sorted_trials)
    stdev_val = statistics.stdev(sorted_trials) if n > 1 else 0.0
    return {
        "mean_ms": round(mean_val, 4),
        "median_ms": round(p50, 4),
        "p95_ms": round(p95, 4),
        "stdev_ms": round(stdev_val, 4),
    }


def run_candidate_benchmarks(repetitions: int = 30) -> Dict[str, Any]:
    print(f"\n--- Part 1: Candidate Destination Inspection ({repetitions} trials) ---")

    benign_items = [
        "policy_id", "POL-2026-BENIGN", "applicant", "Acme Logistics LLC", "fleet_size",
        "25", "region", "US-EAST", "vehicle_count", "operating_radius_miles", "150.0",
        "loss_modifier", "1.0", "primary_metric", "100.0", "read", "api_call", "logistics_db",
        "status", "NORMAL", "description", "Standard fleet risk policy evaluation"
    ] * 50

    destination_items = [
        "https://api.github.com/repos/org/repo/issues",
        "http://localhost:8080/v1/telemetry",
        "192.168.1.1:9000",
        "10.0.0.1",
        "2130706433",
        "0x7f000001",
        "api.stripe.com",
        "subdomain.example.org",
        "/api/v1/auth/token",
        "ftp://backup.internal.lan/archive",
        "script.py",
        "document.pdf",
        "non_destination_field"
    ] * 80

    for item in benign_items + destination_items:
        unopt_res = _unoptimized_is_candidate_destination(item)
        opt_res = ContainmentGuard._is_candidate_destination(item)
        assert unopt_res == opt_res, f"Boolean mismatch on {item!r}: {unopt_res} != {opt_res}"
    print("✓ 100% Boolean equivalence confirmed across all candidate destination test inputs.")

    results = {}
    workload_specs = [("benign_heavy", benign_items), ("destination_heavy", destination_items)]

    for workload_name, items in workload_specs:
        unopt_trials = []
        opt_trials = []

        for rep in range(repetitions):
            if rep % 2 == 0:
                t0 = time.perf_counter_ns()
                for s in items:
                    _ = _unoptimized_is_candidate_destination(s)
                t1 = time.perf_counter_ns()
                unopt_trials.append((t1 - t0) / 1e6)

                t0 = time.perf_counter_ns()
                for s in items:
                    _ = ContainmentGuard._is_candidate_destination(s)
                t1 = time.perf_counter_ns()
                opt_trials.append((t1 - t0) / 1e6)
            else:
                t0 = time.perf_counter_ns()
                for s in items:
                    _ = ContainmentGuard._is_candidate_destination(s)
                t1 = time.perf_counter_ns()
                opt_trials.append((t1 - t0) / 1e6)

                t0 = time.perf_counter_ns()
                for s in items:
                    _ = _unoptimized_is_candidate_destination(s)
                t1 = time.perf_counter_ns()
                unopt_trials.append((t1 - t0) / 1e6)

        unopt_metrics = compute_metrics(unopt_trials)
        opt_metrics = compute_metrics(opt_trials)
        speedup = unopt_metrics["median_ms"] / (opt_metrics["median_ms"] or 1e-6)

        results[workload_name] = {
            "items_per_eval": len(items),
            "unoptimized": unopt_metrics,
            "optimized": opt_metrics,
            "speedup_ratio_median": round(speedup, 2),
        }
        print(
            f"  [{workload_name}] Base: p50={unopt_metrics['median_ms']}ms, "
            f"p95={unopt_metrics['p95_ms']}ms | Opt: p50={opt_metrics['median_ms']}ms, "
            f"p95={opt_metrics['p95_ms']}ms | Speedup: {speedup:.2f}x"
        )

    return results


def run_normalization_cache_benchmarks(repetitions: int = 30) -> Dict[str, Any]:
    print(f"\n--- Part 2: Normalization Cache ({repetitions} trials) ---")

    repeated_inputs = [
        "https://api.github.com:443",
        "http://localhost:8080/path",
        "https://example.com/api/v1",
        "192.168.1.1",
        "10.0.0.1:80",
        "applicant",
        "US-EAST",
        "logistics_db",
    ] * 200

    mixed_inputs = [
        f"https://api-{i % 10}.example.com/endpoint/{i % 5}" for i in range(100)
    ] + [
        f"service-{i % 8}:8080" for i in range(100)
    ] + [
        f"field_key_{i % 20}" for i in range(100)
    ]
    mixed_inputs = mixed_inputs * 5

    high_card_inputs = [f"https://sub-{i}.domain-unique-{i}.org/resource" for i in range(6000)]
    results = {}

    # 1. Repeated Endpoints
    unopt_repeated = []
    opt_repeated = []
    _cached_normalize_destination_host.cache_clear()
    t0 = time.perf_counter_ns()
    for s in repeated_inputs:
        _ = normalize_destination_host(s)
    t1 = time.perf_counter_ns()
    cold_repeated_ms = (t1 - t0) / 1e6

    for rep in range(repetitions):
        if rep % 2 == 0:
            t0 = time.perf_counter_ns()
            for s in repeated_inputs:
                _ = _unoptimized_normalize_destination_host(s)
            t1 = time.perf_counter_ns()
            unopt_repeated.append((t1 - t0) / 1e6)

            t0 = time.perf_counter_ns()
            for s in repeated_inputs:
                _ = normalize_destination_host(s)
            t1 = time.perf_counter_ns()
            opt_repeated.append((t1 - t0) / 1e6)
        else:
            t0 = time.perf_counter_ns()
            for s in repeated_inputs:
                _ = normalize_destination_host(s)
            t1 = time.perf_counter_ns()
            opt_repeated.append((t1 - t0) / 1e6)

            t0 = time.perf_counter_ns()
            for s in repeated_inputs:
                _ = _unoptimized_normalize_destination_host(s)
            t1 = time.perf_counter_ns()
            unopt_repeated.append((t1 - t0) / 1e6)

    cache_info_rep = _cached_normalize_destination_host.cache_info()
    rep_unopt_metrics = compute_metrics(unopt_repeated)
    rep_opt_metrics = compute_metrics(opt_repeated)
    speedup_rep = rep_unopt_metrics["median_ms"] / (rep_opt_metrics["median_ms"] or 1e-6)

    results["repeated_endpoints"] = {
        "calls_per_eval": len(repeated_inputs),
        "cold_cache_ms": round(cold_repeated_ms, 4),
        "unoptimized": rep_unopt_metrics,
        "optimized_warm": rep_opt_metrics,
        "speedup_ratio_median": round(speedup_rep, 2),
        "cache_stats": {
            "hits": cache_info_rep.hits,
            "misses": cache_info_rep.misses,
            "maxsize": cache_info_rep.maxsize,
            "currsize": cache_info_rep.currsize,
        }
    }
    print(
        f"  [repeated_endpoints] Cold: {cold_repeated_ms:.2f}ms | Base: "
        f"p50={rep_unopt_metrics['median_ms']}ms | Warm: p50={rep_opt_metrics['median_ms']}ms | "
        f"Speedup: {speedup_rep:.2f}x | Hits: {cache_info_rep.hits}"
    )

    # 2. Mixed Realistic
    _cached_normalize_destination_host.cache_clear()
    unopt_mixed = []
    opt_mixed = []
    for rep in range(repetitions):
        if rep % 2 == 0:
            t0 = time.perf_counter_ns()
            for s in mixed_inputs:
                _ = _unoptimized_normalize_destination_host(s)
            t1 = time.perf_counter_ns()
            unopt_mixed.append((t1 - t0) / 1e6)

            t0 = time.perf_counter_ns()
            for s in mixed_inputs:
                _ = normalize_destination_host(s)
            t1 = time.perf_counter_ns()
            opt_mixed.append((t1 - t0) / 1e6)
        else:
            t0 = time.perf_counter_ns()
            for s in mixed_inputs:
                _ = normalize_destination_host(s)
            t1 = time.perf_counter_ns()
            opt_mixed.append((t1 - t0) / 1e6)

            t0 = time.perf_counter_ns()
            for s in mixed_inputs:
                _ = _unoptimized_normalize_destination_host(s)
            t1 = time.perf_counter_ns()
            unopt_mixed.append((t1 - t0) / 1e6)

    cache_info_mixed = _cached_normalize_destination_host.cache_info()
    mixed_unopt_metrics = compute_metrics(unopt_mixed)
    mixed_opt_metrics = compute_metrics(opt_mixed)
    speedup_mixed = mixed_unopt_metrics["median_ms"] / (mixed_opt_metrics["median_ms"] or 1e-6)

    results["mixed_realistic"] = {
        "calls_per_eval": len(mixed_inputs),
        "unoptimized": mixed_unopt_metrics,
        "optimized_warm": mixed_opt_metrics,
        "speedup_ratio_median": round(speedup_mixed, 2),
        "cache_stats": {
            "hits": cache_info_mixed.hits,
            "misses": cache_info_mixed.misses,
            "maxsize": cache_info_mixed.maxsize,
            "currsize": cache_info_mixed.currsize,
        }
    }
    print(
        f"  [mixed_realistic] Base: p50={mixed_unopt_metrics['median_ms']}ms | Warm: "
        f"p50={mixed_opt_metrics['median_ms']}ms | Speedup: {speedup_mixed:.2f}x | "
        f"Hits: {cache_info_mixed.hits}, Misses: {cache_info_mixed.misses}"
    )

    # 3. High-Cardinality Churn (6,000 distinct items exceeding 4,096 capacity)
    _cached_normalize_destination_host.cache_clear()
    unopt_high = []
    opt_high = []
    for rep in range(10):
        if rep % 2 == 0:
            t0 = time.perf_counter_ns()
            for s in high_card_inputs:
                _ = _unoptimized_normalize_destination_host(s)
            t1 = time.perf_counter_ns()
            unopt_high.append((t1 - t0) / 1e6)

            t0 = time.perf_counter_ns()
            for s in high_card_inputs:
                _ = normalize_destination_host(s)
            t1 = time.perf_counter_ns()
            opt_high.append((t1 - t0) / 1e6)
        else:
            t0 = time.perf_counter_ns()
            for s in high_card_inputs:
                _ = normalize_destination_host(s)
            t1 = time.perf_counter_ns()
            opt_high.append((t1 - t0) / 1e6)

            t0 = time.perf_counter_ns()
            for s in high_card_inputs:
                _ = _unoptimized_normalize_destination_host(s)
            t1 = time.perf_counter_ns()
            unopt_high.append((t1 - t0) / 1e6)

    cache_info_high = _cached_normalize_destination_host.cache_info()
    high_unopt_metrics = compute_metrics(unopt_high)
    high_opt_metrics = compute_metrics(opt_high)
    evictions = max(0, cache_info_high.misses - cache_info_high.currsize)

    results["high_cardinality_churn"] = {
        "calls_per_eval": len(high_card_inputs),
        "unoptimized": high_unopt_metrics,
        "optimized": high_opt_metrics,
        "cache_stats": {
            "hits": cache_info_high.hits,
            "misses": cache_info_high.misses,
            "maxsize": cache_info_high.maxsize,
            "currsize": cache_info_high.currsize,
            "evictions_detected": evictions,
        }
    }
    print(
        f"  [high_cardinality_churn] Base: p50={high_unopt_metrics['median_ms']}ms | Cached: "
        f"p50={high_opt_metrics['median_ms']}ms | Cache: {cache_info_high.currsize}/"
        f"{cache_info_high.maxsize}, Evictions: {evictions}"
    )

    return results


def main():
    env_info = get_environment_info()
    print("=" * 80)
    print(" ContainmentGuard Candidate Detection & Host Normalization Empirical Benchmark")
    print("=" * 80)
    print(f"Git Commit SHA : {env_info['commit_sha']}")
    print(f"Python Runtime : {env_info['python_version']} on {env_info['platform']}")
    print(f"CPU Hardware   : {env_info['cpu_count']} cores ({env_info['processor']})")

    candidate_results = run_candidate_benchmarks(repetitions=30)
    cache_results = run_normalization_cache_benchmarks(repetitions=30)

    final_results = {
        "environment": env_info,
        "candidate_destination_inspection": candidate_results,
        "normalization_cache": cache_results,
        "methodology": {
            "repetitions": 30,
            "alternating_order": True,
            "metrics": ["mean_ms", "median_ms (p50)", "p95_ms", "stdev_ms"],
            "command": "python benchmarks/benchmark_containment_optimizations.py",
        }
    }

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(final_results, f, indent=2)

    print(f"\n✓ Empirical benchmark complete. Machine-readable JSON saved to: {RESULTS_PATH}")


if __name__ == "__main__":
    main()
