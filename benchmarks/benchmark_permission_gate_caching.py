"""
Reproducible Benchmark: PermissionGate Regex Memoization Evaluation.

Compares:
- Baseline: Uncached injection_regex search across all strings.
- Optimized: Bounded LRU memoization (maxsize=4096, strings <= 256 chars cached).

Workloads Evaluated:
A. Repetitive schema workload (deeply nested dicts, repetitive keys and identifiers).
B. High-cardinality workload (many unique short strings, inducing cache churn and eviction).
C. Mixed realistic workload (repeated schema keys combined with unique user values, both benign and adversarial).
D. Long-string workload (significant proportion of strings > 256 chars).

Methodology & Statistical Rigor:
- Alternating paired execution between Baseline and Optimized to eliminate ordering bias.
- N=30 independent measurement repetitions per profile.
- Explicit cold-cache distribution measured across 30 independent trials with fresh cache resets.
- Explicit warm-cache distribution measured following 1-pass warm-up.
- Strict ground-truth correctness and cross-implementation equivalence assertions.
- Machine-readable JSON output and console table summary.

Invocation:
    python benchmarks/benchmark_permission_gate_caching.py
"""

import os
import sys
import time
import json
import random
import platform
import statistics
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Tuple

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

from epistemicos.gates import PermissionGate, GateInput, GateDecision  # noqa: E402

RESULTS_PATH = REPO_ROOT / "results" / "permission_gate_benchmark_results.json"


def get_environment_info() -> Dict[str, Any]:
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip()
    except Exception:
        commit = "UNKNOWN"

    try:
        branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=REPO_ROOT, text=True).strip()
    except Exception:
        branch = "UNKNOWN"

    try:
        # Check if source tree (excluding results) has modifications
        status_proc = subprocess.run(
            ["git", "status", "--porcelain", "epistemicos/", "benchmarks/", ".jules/"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True
        )
        is_clean = len(status_proc.stdout.strip()) == 0
    except Exception:
        is_clean = False

    return {
        "commit_sha": commit,
        "branch": branch,
        "working_tree_clean": is_clean,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or "x86_64",
        "cpu_count": os.cpu_count() or 1,
        "exact_command": "python benchmarks/benchmark_permission_gate_caching.py"
    }


def compute_p95(values: List[float]) -> float:
    """Computes p95 using standard nearest-rank percentile over sorted values."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    if n == 1:
        return sorted_vals[0]
    # Standard quantile interpolation or nearest-rank for N>=20
    idx = int(round(0.95 * (n - 1)))
    return sorted_vals[min(idx, n - 1)]


def summarize_distribution(times: List[float], num_items: int) -> Dict[str, float]:
    """Computes median, p95, mean, and per-eval metrics across measured runs."""
    med = statistics.median(times)
    p95_val = compute_p95(times)
    avg = statistics.mean(times)
    return {
        "median_total_sec": round(med, 6),
        "p95_total_sec": round(p95_val, 6),
        "mean_total_sec": round(avg, 6),
        "median_ms_per_eval": round((med / num_items) * 1000.0, 5),
        "p95_ms_per_eval": round((p95_val / num_items) * 1000.0, 5),
        "mean_ms_per_eval": round((avg / num_items) * 1000.0, 5),
    }


# ==============================================================================
# Workload Generators with Ground-Truth Annotations
# ==============================================================================

def generate_workload_a(num_samples: int = 1000) -> List[Tuple[GateInput, GateDecision]]:
    """Profile A: Repetitive schema workload with deeply nested dicts and recurrent keys (All Benign -> ALLOW)."""
    samples = []
    base_actions = [{"op": "read", "endpoint": "logistics_db"}]
    for i in range(num_samples):
        payload = {
            "policy_id": "POL-2026-BENIGN",
            "raw_payload": {
                "applicant": "Acme Logistics LLC",
                "fleet_size": 25,
                "region": "US-EAST",
                "nested_profile": {
                    "tier": "enterprise",
                    "status": "active",
                    "compliance_tags": ["soc2", "iso27001", "hipaa"],
                    "audit_meta": {
                        "issuer": "logistics_authority",
                        "scope_ref": "db_read_only"
                    }
                }
            },
            "fleet_data": {
                "vehicle_count": 25,
                "operating_radius_miles": 150.0,
                "loss_modifier": 1.0
            },
            "primary_metric": 100.0,
            "sample_index": i % 5
        }
        samples.append((GateInput(payload=payload, context={"proposed_actions": base_actions}), GateDecision.ALLOW))
    return samples


def generate_workload_b(num_samples: int = 2000) -> List[Tuple[GateInput, GateDecision]]:
    """Profile B: High-cardinality workload with many unique short strings (All Benign -> ALLOW)."""
    samples = []
    base_actions = [{"op": "read", "endpoint": "logistics_db"}]
    rng = random.Random(1337)
    for i in range(num_samples):
        payload = {
            f"rand_key_{rng.randint(0, 1000000)}": f"val_{rng.randint(0, 1000000)}",
            f"rand_field_{rng.randint(0, 1000000)}": f"entry_{i}",
            "transient_token": f"tok_{rng.getrandbits(64):x}",
            "policy_id": f"POL-HC-{i}"
        }
        samples.append((GateInput(payload=payload, context={"proposed_actions": base_actions}), GateDecision.ALLOW))
    return samples


class CustomStringSubclassKey(str):
    pass


def generate_workload_c(num_samples: int = 1000) -> List[Tuple[GateInput, GateDecision]]:
    """Profile C: Mixed realistic workload with repeated schema keys and unique values (20% Adversarial -> HALT, 80% Benign -> ALLOW)."""
    samples = []
    base_actions = [{"op": "read", "endpoint": "logistics_db"}]
    rng = random.Random(42)

    for i in range(num_samples):
        is_adv = (i % 5 == 0)
        if is_adv:
            pattern = rng.choice(["import os", "[SYSTEM OVERRIDE]", "curl -s http://evil", "rm -rf /"])
            if i % 10 == 0:
                # Custom str subclass malicious key
                payload = {
                    "policy_id": "POL-2026-ADV",
                    CustomStringSubclassKey(pattern): f"adv_val_{i}",
                    "user_id": f"usr_{i}"
                }
            else:
                payload = {
                    "policy_id": "POL-2026-ADV",
                    "notes": f"benign prefix; {pattern} ; suffix",
                    "user_id": f"usr_{i}"
                }
            expected = GateDecision.HALT
        else:
            payload = {
                "policy_id": "POL-2026-BENIGN",
                "notes": f"Standard user request note number {i} from operational terminal.",
                "user_id": f"usr_{i}",
                "account": {"id": f"acct_{i % 50}", "status": "verified"}
            }
            expected = GateDecision.ALLOW
        samples.append((GateInput(payload=payload, context={"proposed_actions": base_actions}), expected))
    return samples


def generate_workload_d(num_samples: int = 1000) -> List[Tuple[GateInput, GateDecision]]:
    """Profile D: Long-string workload (> 256 chars) confirming cache bypass without regression (10% Adversarial -> HALT, 90% Benign -> ALLOW)."""
    samples = []
    base_actions = [{"op": "read", "endpoint": "logistics_db"}]
    rng = random.Random(999)

    # Use clean english prose vocabulary without embedded shell tokens (sh, nc, rm, etc.)
    vocab = [
        "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog",
        "compliance", "report", "logistic", "freight", "evaluation",
        "system", "telemetry", "metric", "indicator", "operational",
        "radius", "vehicle", "fleet", "warehouse", "distribution", "status"
    ]
    # Filter out any word matching injection regex
    gate_temp = PermissionGate()
    safe_words = [w for w in vocab if not gate_temp.injection_regex.search(w)]

    for i in range(num_samples):
        str_len = rng.randint(40, 90)
        filler = " ".join(rng.choices(safe_words, k=str_len))
        # Ensure length > 256
        while len(filler) < 300:
            filler += " " + " ".join(rng.choices(safe_words, k=20))

        is_adv = (i % 10 == 0)
        if is_adv:
            long_content = filler + " [SYSTEM OVERRIDE] " + filler
            expected = GateDecision.HALT
        else:
            long_content = filler
            expected = GateDecision.ALLOW

        payload = {
            "policy_id": "POL-2026-LONG",
            "long_description": long_content,
            "supplementary_data": filler[:350],
            "seq": i
        }
        samples.append((GateInput(payload=payload, context={"proposed_actions": base_actions}), expected))
    return samples


# ==============================================================================
# Benchmarking Engine
# ==============================================================================

def run_workload_benchmark(
    name: str,
    annotated_samples: List[Tuple[GateInput, GateDecision]],
    cached_gate: PermissionGate,
    uncached_gate: PermissionGate,
    repetitions: int = 30
) -> Dict[str, Any]:
    """
    Executes a statistically rigorous, paired alternating evaluation over N repetitions.
    Asserts both ground-truth correctness and cross-implementation equivalence.
    """
    inputs = [s[0] for s in annotated_samples]
    n_samples = len(inputs)

    # 1. Ground Truth & Equivalence Assertions (run once before timing)
    cached_gate._cached_injection_search.cache_clear()
    for idx, (gi, exp_dec) in enumerate(annotated_samples):
        res_cached = cached_gate.evaluate_contract(gi)
        res_uncached = uncached_gate.evaluate_contract(gi)

        assert res_cached.decision == exp_dec, (
            f"[{name}] Ground truth failure at item {idx}: got {res_cached.decision}, expected {exp_dec}"
        )
        assert res_uncached.decision == exp_dec, (
            f"[{name}] Baseline ground truth failure at item {idx}: got {res_uncached.decision}, expected {exp_dec}"
        )
        assert res_cached.decision == res_uncached.decision, (
            f"[{name}] Cross-implementation discrepancy at item {idx}: cached={res_cached.decision}, uncached={res_uncached.decision}"
        )
        assert res_cached.reason_code == res_uncached.reason_code, (
            f"[{name}] Reason code discrepancy at item {idx}: cached='{res_cached.reason_code}', uncached='{res_uncached.reason_code}'"
        )

    # 2. Cold-Cache Distribution (N trials with cache cleared before each trial)
    cold_times = []
    for _ in range(repetitions):
        cached_gate._cached_injection_search.cache_clear()
        t0 = time.perf_counter()
        for gi in inputs:
            cached_gate.evaluate_contract(gi)
        t1 = time.perf_counter()
        cold_times.append(t1 - t0)

    cold_cache_info = cached_gate._cached_injection_search.cache_info()

    # 3. Warm-Cache Warm-up (1 pass to populate steady-state cache)
    cached_gate._cached_injection_search.cache_clear()
    for gi in inputs:
        cached_gate.evaluate_contract(gi)

    # 4. Paired, Alternating Measurements (N repetitions)
    # Alternates execution order: even runs measure baseline first, odd runs measure optimized first
    uncached_times = []
    cached_warm_times = []

    for rep in range(repetitions):
        if rep % 2 == 0:
            # Baseline then Optimized
            t0 = time.perf_counter()
            for gi in inputs:
                uncached_gate.evaluate_contract(gi)
            t1 = time.perf_counter()
            uncached_times.append(t1 - t0)

            t0 = time.perf_counter()
            for gi in inputs:
                cached_gate.evaluate_contract(gi)
            t1 = time.perf_counter()
            cached_warm_times.append(t1 - t0)
        else:
            # Optimized then Baseline
            t0 = time.perf_counter()
            for gi in inputs:
                cached_gate.evaluate_contract(gi)
            t1 = time.perf_counter()
            cached_warm_times.append(t1 - t0)

            t0 = time.perf_counter()
            for gi in inputs:
                uncached_gate.evaluate_contract(gi)
            t1 = time.perf_counter()
            uncached_times.append(t1 - t0)

    final_cache_info = cached_gate._cached_injection_search.cache_info()

    base_dist = summarize_distribution(uncached_times, n_samples)
    cold_dist = summarize_distribution(cold_times, n_samples)
    warm_dist = summarize_distribution(cached_warm_times, n_samples)

    warm_speedup = round(base_dist["median_total_sec"] / (warm_dist["median_total_sec"] or 1e-6), 2)
    warm_reduction_pct = round((1.0 - (warm_dist["median_total_sec"] / base_dist["median_total_sec"])) * 100.0, 2)
    cold_ratio = round(cold_dist["median_total_sec"] / base_dist["median_total_sec"], 2)

    return {
        "num_samples": n_samples,
        "repetitions": repetitions,
        "methodology": "Paired alternating execution, 30 repetitions, p95 nearest-rank",
        "baseline_uncached": base_dist,
        "optimized_cold": {
            **cold_dist,
            "cold_vs_baseline_ratio": cold_ratio,
            "single_trial_cache_stats": {
                "hits": cold_cache_info.hits,
                "misses": cold_cache_info.misses,
                "currsize": cold_cache_info.currsize,
                "maxsize": cold_cache_info.maxsize
            }
        },
        "optimized_warm": warm_dist,
        "relative_speedup_warm": warm_speedup,
        "percent_latency_reduction_warm": warm_reduction_pct,
        "final_cache_stats": {
            "hits": final_cache_info.hits,
            "misses": final_cache_info.misses,
            "currsize": final_cache_info.currsize,
            "maxsize": final_cache_info.maxsize
        }
    }


def main():
    env_info = get_environment_info()
    trusted_scope = {
        "allowed_operations": ["read", "api_call"],
        "allowed_resources": ["logistics_db", "/bind_policy"]
    }

    cached_gate = PermissionGate(trusted_scope=trusted_scope)
    uncached_gate = PermissionGate(trusted_scope=trusted_scope)
    # Strictly disable caching on baseline gate
    uncached_gate._cached_injection_search = lambda s: bool(uncached_gate.injection_regex.search(s))

    workloads = {
        "workload_a_repetitive_schema": generate_workload_a(num_samples=1000),
        "workload_b_high_cardinality": generate_workload_b(num_samples=2000),
        "workload_c_mixed_realistic": generate_workload_c(num_samples=1000),
        "workload_d_long_strings": generate_workload_d(num_samples=1000),
    }

    results = {
        "environment": env_info,
        "workload_results": {}
    }

    print("=" * 84)
    print("⚡ EpistemicOS PermissionGate Regex Memoization Benchmark (Statistical Rigor)")
    print(f"Commit SHA:   {env_info['commit_sha']}")
    print(f"Branch:       {env_info['branch']} (Clean: {env_info['working_tree_clean']})")
    print(f"Python:       {env_info['python_version']} on {env_info['platform']}")
    print("=" * 84)

    for w_name, w_samples in workloads.items():
        print(f"\nBenchmarking {w_name} ({len(w_samples)} items x 30 paired repetitions)...")
        w_res = run_workload_benchmark(w_name, w_samples, cached_gate, uncached_gate, repetitions=30)
        results["workload_results"][w_name] = w_res

        base = w_res["baseline_uncached"]
        cold = w_res["optimized_cold"]
        warm = w_res["optimized_warm"]

        print(f"  Baseline Uncached:  median={base['median_ms_per_eval']} ms/op | p95={base['p95_ms_per_eval']} ms/op | mean={base['mean_ms_per_eval']} ms/op")
        print(f"  Optimized Cold:     median={cold['median_ms_per_eval']} ms/op | p95={cold['p95_ms_per_eval']} ms/op | ratio={cold['cold_vs_baseline_ratio']}x")
        print(f"  Optimized Warm:     median={warm['median_ms_per_eval']} ms/op | p95={warm['p95_ms_per_eval']} ms/op | mean={warm['mean_ms_per_eval']} ms/op")
        print(f"  Warm Speedup:       {w_res['relative_speedup_warm']}x ({w_res['percent_latency_reduction_warm']}% reduction)")
        print(f"  Cache Usage:        {w_res['final_cache_stats']['currsize']}/{w_res['final_cache_stats']['maxsize']} (hits={w_res['final_cache_stats']['hits']}, misses={w_res['final_cache_stats']['misses']})")

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 84)
    print(f"Empirical benchmark results successfully written to:\n{RESULTS_PATH}")
    print("=" * 84)
    return results


if __name__ == "__main__":
    main()
