"""
Empirical Benchmark Harness for normalize_target_scope Bounded Memoization Optimization.

Measures latency, throughput, and cache metrics between uncached baseline and cached implementations
across 4 workload profiles with rigorous cache-state control:
1. Repetitive Endpoints: 100% recurrent targets (steady-state warm cache).
2. Mixed Real-World Workload (Cold & Steady): 80% recurrent / 20% genuinely novel targets per trial.
   Reports cache hits, misses, current size, cold-start vs steady-state latency (mean, median, p95).
3. High-Cardinality Churn: 100% unique targets measuring cold cache miss overhead.
4. Large Targets (> 512 characters): cache bypass measuring zero regression.

Outputs empirical benchmark results to results/target_scope_benchmark_results.json.
"""

import json
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import time
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

from epistemicos.authorization import (  # noqa: E402
    normalize_target_scope,
    _normalize_target_scope_impl,
    _cached_normalize_target_scope,
)

RESULTS_PATH = REPO_ROOT / "results" / "target_scope_benchmark_results.json"


def get_git_commit_sha() -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True
        )
        base_sha = res.stdout.strip()
        status_res = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True
        )
        if status_res.stdout.strip():
            return f"{base_sha} (working-tree dirty)"
        return base_sha
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


def compute_percentiles(data: List[float]) -> Tuple[float, float, float, float]:
    """Returns (mean, median, p95, std_dev) for a list of measurements."""
    sorted_data = sorted(data)
    n = len(sorted_data)
    mean_val = statistics.mean(sorted_data)
    median_val = statistics.median(sorted_data)
    p95_idx = int(0.95 * (n - 1))
    p95_val = sorted_data[p95_idx]
    std_val = statistics.stdev(sorted_data) if n > 1 else 0.0
    return mean_val, median_val, p95_val, std_val


def run_benchmark_trial(
    func,
    targets: List[str],
    iterations: int = 1000
) -> float:
    """Executes a benchmark run over a list of targets and returns elapsed seconds."""
    t0 = time.perf_counter()
    for _ in range(iterations):
        for t in targets:
            func(t)
    return time.perf_counter() - t0


def run_mixed_workload_trial(
    func,
    sequence: List[str]
) -> float:
    """Executes an exact sequence of targets for mixed workload trials."""
    t0 = time.perf_counter()
    for t in sequence:
        func(t)
    return time.perf_counter() - t0


def main():
    print("=" * 75)
    print("⚡ BOLT: normalize_target_scope Bounded Memoization Benchmark (Methodology v2)")
    print("=" * 75)

    env_info = get_environment_info()
    print(f"Commit:  {env_info['commit_sha']}")
    print(f"Python:  {env_info['python_version']} on {env_info['platform']}")
    print(f"CPUs:    {env_info['cpu_count']}")
    print("-" * 75)

    recurrent_targets = [
        "http://localhost:8080/api/v1/auth",
        "http://localhost:8080/api/v1/users",
        "/db/accounts/balance",
        "/db/transactions/pending",
        "/files/secure/contract.pdf",
        "/files/audit/ledger.json",
        "https://api.external.com/v2/webhooks?sig=abc",
        "https://api.external.com/v2/status",
        "/services/payment/gateway",
        "/services/notification/dispatch",
    ]

    # Pre-verification pass for equivalence (runs in isolation and clears cache)
    _cached_normalize_target_scope.cache_clear()
    for t in recurrent_targets:
        assert _normalize_target_scope_impl(t) == normalize_target_scope(t)
    # Clear cache immediately so verification does not leak into timed trials!
    _cached_normalize_target_scope.cache_clear()
    assert _cached_normalize_target_scope.cache_info().currsize == 0

    results: Dict[str, Any] = {
        "environment": env_info,
        "profiles": {},
    }
    trials_count = 20

    # =========================================================================
    # 1. PROFILE: Recurrent Endpoints (100% recurrent, steady-state warm cache)
    # =========================================================================
    p1_iters = 2000
    p1_total_ops = len(recurrent_targets) * p1_iters
    p1_uncached_times = []
    p1_cached_times = []

    for trial in range(trials_count):
        if trial % 2 == 0:
            t_u = run_benchmark_trial(_normalize_target_scope_impl, recurrent_targets, p1_iters)
            for t in recurrent_targets:
                normalize_target_scope(t)
            t_c = run_benchmark_trial(normalize_target_scope, recurrent_targets, p1_iters)
        else:
            for t in recurrent_targets:
                normalize_target_scope(t)
            t_c = run_benchmark_trial(normalize_target_scope, recurrent_targets, p1_iters)
            t_u = run_benchmark_trial(_normalize_target_scope_impl, recurrent_targets, p1_iters)

        p1_uncached_times.append(t_u)
        p1_cached_times.append(t_c)

    p1_u_mean, p1_u_med, p1_u_p95, p1_u_std = compute_percentiles(p1_uncached_times)
    p1_c_mean, p1_c_med, p1_c_p95, p1_c_std = compute_percentiles(p1_cached_times)

    speedup_mean = p1_u_mean / p1_c_mean if p1_c_mean > 0 else 1.0
    speedup_med = p1_u_med / p1_c_med if p1_c_med > 0 else 1.0

    results["profiles"]["profile_recurrent_endpoints"] = {
        "description": "100% recurrent targets (warm cache / steady-state)",
        "total_ops_per_trial": p1_total_ops,
        "trials": trials_count,
        "uncached": {
            "mean_sec": round(p1_u_mean, 6),
            "median_sec": round(p1_u_med, 6),
            "p95_sec": round(p1_u_p95, 6),
            "std_sec": round(p1_u_std, 6),
            "us_per_op_mean": round((p1_u_mean / p1_total_ops) * 1e6, 4),
            "us_per_op_median": round((p1_u_med / p1_total_ops) * 1e6, 4),
            "us_per_op_p95": round((p1_u_p95 / p1_total_ops) * 1e6, 4),
        },
        "cached": {
            "mean_sec": round(p1_c_mean, 6),
            "median_sec": round(p1_c_med, 6),
            "p95_sec": round(p1_c_p95, 6),
            "std_sec": round(p1_c_std, 6),
            "us_per_op_mean": round((p1_c_mean / p1_total_ops) * 1e6, 4),
            "us_per_op_median": round((p1_c_med / p1_total_ops) * 1e6, 4),
            "us_per_op_p95": round((p1_c_p95 / p1_total_ops) * 1e6, 4),
        },
        "speedup_ratio_mean": round(speedup_mean, 2),
        "speedup_ratio_median": round(speedup_med, 2),
    }

    print("\n📊 1. Profile: Recurrent Endpoints (100% recurrent, warm cache):")
    print(f"  Uncached: mean={p1_u_mean*1e3:.2f}ms ({(p1_u_mean/p1_total_ops)*1e6:.3f} µs/op), "
          f"med={p1_u_med*1e3:.2f}ms, p95={p1_u_p95*1e3:.2f}ms")
    print(f"  Cached:   mean={p1_c_mean*1e3:.2f}ms ({(p1_c_mean/p1_total_ops)*1e6:.3f} µs/op), "
          f"med={p1_c_med*1e3:.2f}ms, p95={p1_c_p95*1e3:.2f}ms")
    print(f"  ⚡ Speedup: {speedup_mean:.2f}x (mean), {speedup_med:.2f}x (median)")

    # =========================================================================
    # 2. PROFILE: Mixed Workload (80% recurrent / 20% genuinely novel per trial)
    # =========================================================================
    mixed_ops = 5000
    n_recurrent = int(0.80 * mixed_ops)  # 4000 ops
    n_novel = mixed_ops - n_recurrent    # 1000 ops

    cold_uncached_times = []
    cold_cached_times = []
    cold_cache_stats = []

    steady_uncached_times = []
    steady_cached_times = []
    steady_cache_stats = []

    rng = random.Random(42)

    for trial in range(trials_count):
        novel_targets = [
            f"/endpoint/novel/t{trial}_item_{i}_{rng.randint(10000, 99999)}"
            for i in range(n_novel)
        ]
        recurrent_pool = [rng.choice(recurrent_targets) for _ in range(n_recurrent)]
        mixed_sequence = recurrent_pool + novel_targets
        rng.shuffle(mixed_sequence)

        # (a) Cold-start trial
        if trial % 2 == 0:
            t_u = run_mixed_workload_trial(_normalize_target_scope_impl, mixed_sequence)
            _cached_normalize_target_scope.cache_clear()
            info_before = _cached_normalize_target_scope.cache_info()
            t_c = run_mixed_workload_trial(normalize_target_scope, mixed_sequence)
            info_after = _cached_normalize_target_scope.cache_info()
        else:
            _cached_normalize_target_scope.cache_clear()
            info_before = _cached_normalize_target_scope.cache_info()
            t_c = run_mixed_workload_trial(normalize_target_scope, mixed_sequence)
            info_after = _cached_normalize_target_scope.cache_info()
            t_u = run_mixed_workload_trial(_normalize_target_scope_impl, mixed_sequence)

        cold_uncached_times.append(t_u)
        cold_cached_times.append(t_c)
        cold_cache_stats.append({
            "hits": info_after.hits - info_before.hits,
            "misses": info_after.misses - info_before.misses,
            "currsize": info_after.currsize,
            "maxsize": info_after.maxsize,
        })

        # (b) Steady-state trial (recurrent pre-warmed, novel fresh)
        steady_novel = [
            f"/endpoint/steady/t{trial}_item_{i}_{rng.randint(10000, 99999)}"
            for i in range(n_novel)
        ]
        steady_sequence = recurrent_pool + steady_novel
        rng.shuffle(steady_sequence)

        _cached_normalize_target_scope.cache_clear()
        for t in recurrent_targets:
            normalize_target_scope(t)

        if trial % 2 == 0:
            t_u_st = run_mixed_workload_trial(_normalize_target_scope_impl, steady_sequence)
            info_before_st = _cached_normalize_target_scope.cache_info()
            t_c_st = run_mixed_workload_trial(normalize_target_scope, steady_sequence)
            info_after_st = _cached_normalize_target_scope.cache_info()
        else:
            info_before_st = _cached_normalize_target_scope.cache_info()
            t_c_st = run_mixed_workload_trial(normalize_target_scope, steady_sequence)
            info_after_st = _cached_normalize_target_scope.cache_info()
            t_u_st = run_mixed_workload_trial(_normalize_target_scope_impl, steady_sequence)

        steady_uncached_times.append(t_u_st)
        steady_cached_times.append(t_c_st)
        steady_cache_stats.append({
            "hits": info_after_st.hits - info_before_st.hits,
            "misses": info_after_st.misses - info_before_st.misses,
            "currsize": info_after_st.currsize,
            "maxsize": info_after_st.maxsize,
        })

    c_u_mean, c_u_med, c_u_p95, c_u_std = compute_percentiles(cold_uncached_times)
    c_c_mean, c_c_med, c_c_p95, c_c_std = compute_percentiles(cold_cached_times)
    c_speedup_mean = c_u_mean / c_c_mean if c_c_mean > 0 else 1.0
    c_speedup_med = c_u_med / c_c_med if c_c_med > 0 else 1.0

    s_u_mean, s_u_med, s_u_p95, s_u_std = compute_percentiles(steady_uncached_times)
    s_c_mean, s_c_med, s_c_p95, s_c_std = compute_percentiles(steady_cached_times)
    s_speedup_mean = s_u_mean / s_c_mean if s_c_mean > 0 else 1.0
    s_speedup_med = s_u_med / s_c_med if s_c_med > 0 else 1.0

    avg_cold_hits = statistics.mean([s["hits"] for s in cold_cache_stats])
    avg_cold_misses = statistics.mean([s["misses"] for s in cold_cache_stats])
    avg_steady_hits = statistics.mean([s["hits"] for s in steady_cache_stats])
    avg_steady_misses = statistics.mean([s["misses"] for s in steady_cache_stats])

    results["profiles"]["profile_mixed_workload_cold_start"] = {
        "description": "80% recurrent / 20% novel targets (Cold Start: cache empty)",
        "total_ops_per_trial": mixed_ops,
        "trials": trials_count,
        "recurrent_ops": n_recurrent,
        "novel_ops": n_novel,
        "cache_metrics": {
            "mean_hits": round(avg_cold_hits, 1),
            "mean_misses": round(avg_cold_misses, 1),
            "mean_hit_ratio": round(avg_cold_hits / mixed_ops, 4),
            "mean_final_currsize": round(
                statistics.mean([s["currsize"] for s in cold_cache_stats]), 1
            ),
            "maxsize": 4096,
        },
        "uncached": {
            "mean_sec": round(c_u_mean, 6),
            "median_sec": round(c_u_med, 6),
            "p95_sec": round(c_u_p95, 6),
            "std_sec": round(c_u_std, 6),
            "us_per_op_mean": round((c_u_mean / mixed_ops) * 1e6, 4),
            "us_per_op_median": round((c_u_med / mixed_ops) * 1e6, 4),
            "us_per_op_p95": round((c_u_p95 / mixed_ops) * 1e6, 4),
        },
        "cached": {
            "mean_sec": round(c_c_mean, 6),
            "median_sec": round(c_c_med, 6),
            "p95_sec": round(c_c_p95, 6),
            "std_sec": round(c_c_std, 6),
            "us_per_op_mean": round((c_c_mean / mixed_ops) * 1e6, 4),
            "us_per_op_median": round((c_c_med / mixed_ops) * 1e6, 4),
            "us_per_op_p95": round((c_c_p95 / mixed_ops) * 1e6, 4),
        },
        "speedup_ratio_mean": round(c_speedup_mean, 2),
        "speedup_ratio_median": round(c_speedup_med, 2),
    }

    results["profiles"]["profile_mixed_workload_steady_state"] = {
        "description": "80% recurrent / 20% novel targets (Steady State: recurrent pre-warmed)",
        "total_ops_per_trial": mixed_ops,
        "trials": trials_count,
        "recurrent_ops": n_recurrent,
        "novel_ops": n_novel,
        "cache_metrics": {
            "mean_hits": round(avg_steady_hits, 1),
            "mean_misses": round(avg_steady_misses, 1),
            "mean_hit_ratio": round(avg_steady_hits / mixed_ops, 4),
            "mean_final_currsize": round(
                statistics.mean([s["currsize"] for s in steady_cache_stats]), 1
            ),
            "maxsize": 4096,
        },
        "uncached": {
            "mean_sec": round(s_u_mean, 6),
            "median_sec": round(s_u_med, 6),
            "p95_sec": round(s_u_p95, 6),
            "std_sec": round(s_u_std, 6),
            "us_per_op_mean": round((s_u_mean / mixed_ops) * 1e6, 4),
            "us_per_op_median": round((s_u_med / mixed_ops) * 1e6, 4),
            "us_per_op_p95": round((s_u_p95 / mixed_ops) * 1e6, 4),
        },
        "cached": {
            "mean_sec": round(s_c_mean, 6),
            "median_sec": round(s_c_med, 6),
            "p95_sec": round(s_c_p95, 6),
            "std_sec": round(s_c_std, 6),
            "us_per_op_mean": round((s_c_mean / mixed_ops) * 1e6, 4),
            "us_per_op_median": round((s_c_med / mixed_ops) * 1e6, 4),
            "us_per_op_p95": round((s_c_p95 / mixed_ops) * 1e6, 4),
        },
        "speedup_ratio_mean": round(s_speedup_mean, 2),
        "speedup_ratio_median": round(s_speedup_med, 2),
    }

    print("\n📊 2a. Profile: Mixed Workload (Cold Start: 80% recurrent / 20% novel):")
    print(f"  Cache Stats: hits={avg_cold_hits:.0f}, misses={avg_cold_misses:.0f} "
          f"(hit ratio: {avg_cold_hits/mixed_ops*100:.1f}%)")
    print(f"  Uncached: mean={c_u_mean*1e3:.2f}ms ({(c_u_mean/mixed_ops)*1e6:.3f} µs/op), "
          f"med={c_u_med*1e3:.2f}ms, p95={c_u_p95*1e3:.2f}ms")
    print(f"  Cached:   mean={c_c_mean*1e3:.2f}ms ({(c_c_mean/mixed_ops)*1e6:.3f} µs/op), "
          f"med={c_c_med*1e3:.2f}ms, p95={c_c_p95*1e3:.2f}ms")
    print(f"  ⚡ Speedup: {c_speedup_mean:.2f}x (mean), {c_speedup_med:.2f}x (median)")

    print("\n📊 2b. Profile: Mixed Workload (Steady State: recurrent pre-warmed, novel fresh):")
    print(f"  Cache Stats: hits={avg_steady_hits:.0f}, misses={avg_steady_misses:.0f} "
          f"(hit ratio: {avg_steady_hits/mixed_ops*100:.1f}%)")
    print(f"  Uncached: mean={s_u_mean*1e3:.2f}ms ({(s_u_mean/mixed_ops)*1e6:.3f} µs/op), "
          f"med={s_u_med*1e3:.2f}ms, p95={s_u_p95*1e3:.2f}ms")
    print(f"  Cached:   mean={s_c_mean*1e3:.2f}ms ({(s_c_mean/mixed_ops)*1e6:.3f} µs/op), "
          f"med={s_c_med*1e3:.2f}ms, p95={s_c_p95*1e3:.2f}ms")
    print(f"  ⚡ Speedup: {s_speedup_mean:.2f}x (mean), {s_speedup_med:.2f}x (median)")

    # =========================================================================
    # 3. PROFILE: Large Targets > 512 chars (Cache Bypass / Zero Regression)
    # =========================================================================
    long_targets = ["/" + ("segment/" * 70) + f"target_{i}" for i in range(10)]
    for lt in long_targets:
        assert len(lt) > 512
    p3_iters = 200
    p3_total_ops = len(long_targets) * p3_iters
    p3_uncached_times = []
    p3_cached_times = []

    for trial in range(trials_count):
        if trial % 2 == 0:
            t_u = run_benchmark_trial(_normalize_target_scope_impl, long_targets, p3_iters)
            t_c = run_benchmark_trial(normalize_target_scope, long_targets, p3_iters)
        else:
            t_c = run_benchmark_trial(normalize_target_scope, long_targets, p3_iters)
            t_u = run_benchmark_trial(_normalize_target_scope_impl, long_targets, p3_iters)
        p3_uncached_times.append(t_u)
        p3_cached_times.append(t_c)

    p3_u_mean, p3_u_med, p3_u_p95, p3_u_std = compute_percentiles(p3_uncached_times)
    p3_c_mean, p3_c_med, p3_c_p95, p3_c_std = compute_percentiles(p3_cached_times)
    p3_speedup_mean = p3_u_mean / p3_c_mean if p3_c_mean > 0 else 1.0
    p3_speedup_med = p3_u_med / p3_c_med if p3_c_med > 0 else 1.0

    results["profiles"]["profile_cache_bypass_long_targets"] = {
        "description": "Targets > 512 chars (Cache Bypass / Zero Regression)",
        "total_ops_per_trial": p3_total_ops,
        "trials": trials_count,
        "uncached": {
            "mean_sec": round(p3_u_mean, 6),
            "median_sec": round(p3_u_med, 6),
            "p95_sec": round(p3_u_p95, 6),
            "std_sec": round(p3_u_std, 6),
            "us_per_op_mean": round((p3_u_mean / p3_total_ops) * 1e6, 4),
            "us_per_op_median": round((p3_u_med / p3_total_ops) * 1e6, 4),
            "us_per_op_p95": round((p3_u_p95 / p3_total_ops) * 1e6, 4),
        },
        "cached": {
            "mean_sec": round(p3_c_mean, 6),
            "median_sec": round(p3_c_med, 6),
            "p95_sec": round(p3_c_p95, 6),
            "std_sec": round(p3_c_std, 6),
            "us_per_op_mean": round((p3_c_mean / p3_total_ops) * 1e6, 4),
            "us_per_op_median": round((p3_c_med / p3_total_ops) * 1e6, 4),
            "us_per_op_p95": round((p3_c_p95 / p3_total_ops) * 1e6, 4),
        },
        "speedup_ratio_mean": round(p3_speedup_mean, 2),
        "speedup_ratio_median": round(p3_speedup_med, 2),
    }

    print("\n📊 3. Profile: Large Targets > 512 chars (Cache Bypass / Zero Regression):")
    print(f"  Uncached: mean={p3_u_mean*1e3:.2f}ms ({(p3_u_mean/p3_total_ops)*1e6:.3f} µs/op), "
          f"med={p3_u_med*1e3:.2f}ms, p95={p3_u_p95*1e3:.2f}ms")
    print(f"  Cached:   mean={p3_c_mean*1e3:.2f}ms ({(p3_c_mean/p3_total_ops)*1e6:.3f} µs/op), "
          f"med={p3_c_med*1e3:.2f}ms, p95={p3_c_p95*1e3:.2f}ms")
    print(f"  ⚡ Speedup: {p3_speedup_mean:.2f}x (mean), {p3_speedup_med:.2f}x (median)")

    # =========================================================================
    # 4. PROFILE: High Cardinality Churn (100% unique targets, cold cache)
    # =========================================================================
    churn_ops = 5000
    churn_u_times = []
    churn_c_times = []

    for trial in range(trials_count):
        churn_targets = [
            f"/endpoint/churn/t{trial}_{i}_{rng.randint(1000, 9999)}"
            for i in range(churn_ops)
        ]
        if trial % 2 == 0:
            t_u = run_mixed_workload_trial(_normalize_target_scope_impl, churn_targets)
            _cached_normalize_target_scope.cache_clear()
            t_c = run_mixed_workload_trial(normalize_target_scope, churn_targets)
        else:
            _cached_normalize_target_scope.cache_clear()
            t_c = run_mixed_workload_trial(normalize_target_scope, churn_targets)
            t_u = run_mixed_workload_trial(_normalize_target_scope_impl, churn_targets)
        churn_u_times.append(t_u)
        churn_c_times.append(t_c)

    ch_u_mean, ch_u_med, ch_u_p95, ch_u_std = compute_percentiles(churn_u_times)
    ch_c_mean, ch_c_med, ch_c_p95, ch_c_std = compute_percentiles(churn_c_times)
    ch_speedup_mean = ch_u_mean / ch_c_mean if ch_c_mean > 0 else 1.0
    ch_speedup_med = ch_u_med / ch_c_med if ch_c_med > 0 else 1.0

    results["profiles"]["profile_high_cardinality_churn"] = {
        "description": "100% unique targets (Cold Cache Churn Overhead Test)",
        "total_ops_per_trial": churn_ops,
        "trials": trials_count,
        "uncached": {
            "mean_sec": round(ch_u_mean, 6),
            "median_sec": round(ch_u_med, 6),
            "p95_sec": round(ch_u_p95, 6),
            "std_sec": round(ch_u_std, 6),
            "us_per_op_mean": round((ch_u_mean / churn_ops) * 1e6, 4),
            "us_per_op_median": round((ch_u_med / churn_ops) * 1e6, 4),
            "us_per_op_p95": round((ch_u_p95 / churn_ops) * 1e6, 4),
        },
        "cached": {
            "mean_sec": round(ch_c_mean, 6),
            "median_sec": round(ch_c_med, 6),
            "p95_sec": round(ch_c_p95, 6),
            "std_sec": round(ch_c_std, 6),
            "us_per_op_mean": round((ch_c_mean / churn_ops) * 1e6, 4),
            "us_per_op_median": round((ch_c_med / churn_ops) * 1e6, 4),
            "us_per_op_p95": round((ch_c_p95 / churn_ops) * 1e6, 4),
        },
        "speedup_ratio_mean": round(ch_speedup_mean, 2),
        "speedup_ratio_median": round(ch_speedup_med, 2),
    }

    print("\n📊 4. Profile: High Cardinality Churn (100% unique targets, cold cache):")
    print(f"  Uncached: mean={ch_u_mean*1e3:.2f}ms ({(ch_u_mean/churn_ops)*1e6:.3f} µs/op), "
          f"med={ch_u_med*1e3:.2f}ms, p95={ch_u_p95*1e3:.2f}ms")
    print(f"  Cached:   mean={ch_c_mean*1e3:.2f}ms ({(ch_c_mean/churn_ops)*1e6:.3f} µs/op), "
          f"med={ch_c_med*1e3:.2f}ms, p95={ch_c_p95*1e3:.2f}ms")
    print(f"  ⚡ Ratio:   {ch_speedup_mean:.2f}x (mean), {ch_speedup_med:.2f}x (median)")

    # Save structured results
    os.makedirs(RESULTS_PATH.parent, exist_ok=True)
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 75)
    print(f"✅ Benchmark results written to {RESULTS_PATH}")
    print("=" * 75)


if __name__ == "__main__":
    main()
