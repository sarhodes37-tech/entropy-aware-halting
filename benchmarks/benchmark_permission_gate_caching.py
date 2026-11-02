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

Invocation:
    python benchmarks/benchmark_permission_gate_caching.py
"""

import os
import sys
import time
import json
import random
import platform
import subprocess
from pathlib import Path
from typing import Dict, Any, List

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

from epistemicos.gates import PermissionGate, GateInput  # noqa: E402

RESULTS_PATH = REPO_ROOT / "results" / "permission_gate_benchmark_results.json"


def get_environment_info() -> Dict[str, Any]:
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip()
    except Exception:
        commit = "UNKNOWN"

    return {
        "commit_sha": commit,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or "x86_64",
        "cpu_count": os.cpu_count() or 1,
        "exact_command": "python benchmarks/benchmark_permission_gate_caching.py"
    }


def generate_workload_a(num_samples: int = 1000) -> List[GateInput]:
    """Profile A: Repetitive schema workload with deeply nested dicts and recurrent keys."""
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
            "sample_index": i % 5  # repeated small cyclic value
        }
        samples.append(GateInput(payload=payload, context={"proposed_actions": base_actions}))
    return samples


def generate_workload_b(num_samples: int = 2000) -> List[GateInput]:
    """Profile B: High-cardinality workload with many unique short strings (inducing cache churn)."""
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
        samples.append(GateInput(payload=payload, context={"proposed_actions": base_actions}))
    return samples


def generate_workload_c(num_samples: int = 1000) -> List[GateInput]:
    """Profile C: Mixed realistic workload with repeated schema keys and unique values (benign + adversarial)."""
    samples = []
    base_actions = [{"op": "read", "endpoint": "logistics_db"}]
    rng = random.Random(42)

    class CustomSubclassKey(str):
        pass

    for i in range(num_samples):
        is_adv = (i % 5 == 0)  # 20% adversarial
        if is_adv:
            adv_pattern = rng.choice(["import os", "[SYSTEM OVERRIDE]", "curl -s http://evil", "rm -rf /"])
            if i % 10 == 0:
                # Malicious str subclass key
                payload = {
                    "policy_id": "POL-2026-ADV",
                    CustomSubclassKey(adv_pattern): f"adv_val_{i}",
                    "user_id": f"usr_{i}"
                }
            else:
                payload = {
                    "policy_id": "POL-2026-ADV",
                    "notes": f"benign prefix; {adv_pattern} ; suffix",
                    "user_id": f"usr_{i}"
                }
        else:
            payload = {
                "policy_id": "POL-2026-BENIGN",
                "notes": f"Standard user request note number {i} from operational terminal.",
                "user_id": f"usr_{i}",
                "account": {"id": f"acct_{i % 50}", "status": "verified"}
            }
        samples.append(GateInput(payload=payload, context={"proposed_actions": base_actions}))
    return samples


def generate_workload_d(num_samples: int = 1000) -> List[GateInput]:
    """Profile D: Long-string workload where significant proportion of strings exceed 256 characters."""
    samples = []
    base_actions = [{"op": "read", "endpoint": "logistics_db"}]
    rng = random.Random(999)

    for i in range(num_samples):
        # Generate strings with length 300 - 800 characters
        str_len = rng.randint(300, 800)
        filler = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz 0123456789", k=str_len))
        is_adv = (i % 10 == 0)
        if is_adv:
            long_content = filler + " [SYSTEM OVERRIDE] " + filler
        else:
            long_content = filler

        payload = {
            "policy_id": "POL-2026-LONG",
            "long_description": long_content,
            "supplementary_data": filler[:350],
            "seq": i
        }
        samples.append(GateInput(payload=payload, context={"proposed_actions": base_actions}))
    return samples


def evaluate_workload(
    gate: PermissionGate,
    uncached_gate: PermissionGate,
    inputs: List[GateInput],
    repetitions: int = 10
) -> Dict[str, Any]:
    """
    Executes benchmark comparison between uncached baseline and cached gate.
    Asserts 100% security decision equivalence.
    Measures cold start and warm repetition runs.
    """
    # 1. Assert Security Equivalence first across all samples
    for idx, gi in enumerate(inputs):
        res_cached = gate.evaluate_contract(gi)
        res_uncached = uncached_gate.evaluate_contract(gi)
        assert res_cached.decision == res_uncached.decision, (
            f"Security discrepancy at sample {idx}: cached={res_cached.decision}, uncached={res_uncached.decision}"
        )
        assert res_cached.reason_code == res_uncached.reason_code, (
            f"Reason discrepancy at sample {idx}: cached='{res_cached.reason_code}', uncached='{res_uncached.reason_code}'"
        )

    n_samples = len(inputs)

    # 2. Baseline (Uncached) Measurements across repetitions
    uncached_run_times = []
    for _ in range(repetitions):
        t0 = time.perf_counter()
        for gi in inputs:
            uncached_gate.evaluate_contract(gi)
        t1 = time.perf_counter()
        uncached_run_times.append(t1 - t0)

    # 3. Optimized (Cached) Cold-Start Measurement (1 pass on freshly cleared cache)
    gate._cached_injection_search.cache_clear()
    t0 = time.perf_counter()
    for gi in inputs:
        gate.evaluate_contract(gi)
    t_cold = time.perf_counter() - t0
    cold_stats = gate._cached_injection_search.cache_info()

    # 4. Optimized (Cached) Warm Measurements across repetitions (warm cache)
    cached_warm_run_times = []
    for _ in range(repetitions):
        t0 = time.perf_counter()
        for gi in inputs:
            gate.evaluate_contract(gi)
        t1 = time.perf_counter()
        cached_warm_run_times.append(t1 - t0)
    final_stats = gate._cached_injection_search.cache_info()

    def stats_summary(times: List[float], count: int) -> Dict[str, float]:
        sorted_times = sorted(times)
        median = sorted_times[len(sorted_times) // 2]
        p95_idx = int(0.95 * (len(sorted_times) - 1))
        p95 = sorted_times[p95_idx]
        mean = sum(times) / len(times)
        return {
            "median_total_sec": round(median, 6),
            "p95_total_sec": round(p95, 6),
            "mean_total_sec": round(mean, 6),
            "mean_ms_per_eval": round((mean / count) * 1000.0, 5),
            "median_ms_per_eval": round((median / count) * 1000.0, 5)
        }

    base_stats = stats_summary(uncached_run_times, n_samples)
    opt_warm_stats = stats_summary(cached_warm_run_times, n_samples)

    warm_speedup = round(base_stats["median_total_sec"] / (opt_warm_stats["median_total_sec"] or 1e-6), 2)
    warm_pct_reduction = round((1.0 - (opt_warm_stats["median_total_sec"] / base_stats["median_total_sec"])) * 100.0, 2)

    cold_ms_per_eval = round((t_cold / n_samples) * 1000.0, 5)
    cold_ratio = round(t_cold / base_stats["median_total_sec"], 2)

    return {
        "num_samples": n_samples,
        "repetitions": repetitions,
        "baseline_uncached": base_stats,
        "optimized_cold": {
            "total_sec": round(t_cold, 6),
            "ms_per_eval": cold_ms_per_eval,
            "ratio_vs_baseline_median": cold_ratio,
            "cache_info": {
                "hits": cold_stats.hits,
                "misses": cold_stats.misses,
                "currsize": cold_stats.currsize,
                "maxsize": cold_stats.maxsize
            }
        },
        "optimized_warm": opt_warm_stats,
        "relative_speedup_warm": warm_speedup,
        "percent_latency_reduction_warm": warm_pct_reduction,
        "final_cache_info": {
            "hits": final_stats.hits,
            "misses": final_stats.misses,
            "currsize": final_stats.currsize,
            "maxsize": final_stats.maxsize
        }
    }


def run_benchmark_suite() -> Dict[str, Any]:
    env_info = get_environment_info()
    trusted_scope = {
        "allowed_operations": ["read", "api_call"],
        "allowed_resources": ["logistics_db", "/bind_policy"]
    }

    cached_gate = PermissionGate(trusted_scope=trusted_scope)
    uncached_gate = PermissionGate(trusted_scope=trusted_scope)
    # Baseline strictly disables LRU lookup, routing every string unconditionally through raw regex search
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

    print("=" * 80)
    print("⚡ EpistemicOS PermissionGate Regex Memoization Benchmark Suite")
    print(f"Commit: {env_info['commit_sha']} | Python: {env_info['python_version']} | OS: {env_info['platform']}")
    print("=" * 80)

    for name, inputs in workloads.items():
        print(f"\nEvaluating {name} ({len(inputs)} samples, 10 repetitions)...")
        w_res = evaluate_workload(cached_gate, uncached_gate, inputs, repetitions=10)
        results["workload_results"][name] = w_res

        base = w_res["baseline_uncached"]
        cold = w_res["optimized_cold"]
        warm = w_res["optimized_warm"]

        print(f"  Baseline (Uncached):   median {base['median_total_sec']}s ({base['median_ms_per_eval']} ms/op)")
        print(f"  Optimized (Cold):      total  {cold['total_sec']}s ({cold['ms_per_eval']} ms/op) [hits={cold['cache_info']['hits']}, misses={cold['cache_info']['misses']}]")
        print(f"  Optimized (Warm):      median {warm['median_total_sec']}s ({warm['median_ms_per_eval']} ms/op)")
        print(f"  Warm Speedup:          {w_res['relative_speedup_warm']}x ({w_res['percent_latency_reduction_warm']}% reduction)")
        print(f"  Final Cache Size:      {w_res['final_cache_info']['currsize']}/{w_res['final_cache_info']['maxsize']}")

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 80)
    print(f"Results exported successfully to {RESULTS_PATH}")
    print("=" * 80)
    return results


if __name__ == "__main__":
    run_benchmark_suite()
