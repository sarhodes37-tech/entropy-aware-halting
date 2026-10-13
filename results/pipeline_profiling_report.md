# 📊 EpistemicOS Empirical Profiling & Performance Report

## 1. Provenance, Reproducibility & Environment
- **Git Commit SHA:** `f993219a55a83429501d22d0cf51b3beec33af4b`
- **Exact Benchmark Command:** `PYTHONPATH=. python3 benchmarks/run_pipeline_profiling.py`
- **Statistical Model:** Run-level Student's t-distribution ($N=10$ runs, $df=9$, $t_{0.025}=2.262$)
- **Interleaved Execution:** Interleaved randomized workload sequence to eliminate order bias.
- **Repetitions:** 10 runs x 200 iterations/run
- **Python Runtime:** Version 3.12.13 on Linux-6.8.0-x86_64-with-glibc2.39
- **Hardware Profile:** 4 CPUs (x86_64)
- **PyTorch/CUDA Acceleration:** CUDA Available = `False` (PyTorch Version: `N/A`)

---

## 2. Per-Gate & Component Latency Breakdown
*All measurements reported in milliseconds calculated at the run level across $N=10$ independent run observations (with 95% Student's t-CI).*

| Component / Gate | Mean (ms) | Mean 95% CI | p50 (ms) | p95 Mean (ms) | p95 95% CI | p99 Mean (ms) | p99 95% CI | StdDev |
|---|---|---|---|---|---|---|---|---|
| **CPR Schema Validation** | 0.3731 | ±0.0648 | 0.2137 | 0.9712 | ±0.1967 | 1.2461 | ±0.405 | 0.0907 |
| **Permission Gate** | 1.4432 | ±0.2017 | 0.3894 | 3.8317 | ±0.7832 | 4.5447 | ±1.3605 | 0.282 |
| **Entropy Gate** | 1.7414 | ±0.2627 | 0.3616 | 4.9363 | ±1.1723 | 5.898 | ±1.9419 | 0.3672 |
| **Triangulation Gate** | 0.0448 | ±0.0076 | 0.0383 | 0.0762 | ±0.0183 | 0.1114 | ±0.0418 | 0.0107 |
| **Crypto Attestation Gate** | 0.0288 | ±0.0049 | 0.0262 | 0.0428 | ±0.0153 | 0.0771 | ±0.0196 | 0.0069 |
| **Audit Trail Persistence** | 0.6277 | ±0.1084 | 0.6049 | 0.8787 | ±0.2496 | 1.0011 | ±0.3114 | 0.1515 |
| **Total End-to-End Pipeline** | 4.07 | ±0.6149 | 1.7956 | 12.1701 | ±2.3606 | 14.8513 | ±4.7448 | 0.8597 |

> **Note on Percentile Sample Variance:** Per-run p95 and p99 estimates are computed over $M=200$ samples per run. While p50 and p95 estimates are statistically stable across runs, p99 estimates exhibit higher natural sampling dispersion due to tail latency events (e.g. garbage collection or OS context switches).

---

## 3. Workload Latency Comparison
| Workload | Mean Latency (ms) | Mean 95% CI | p50 (ms) | p95 Mean (ms) | p95 95% CI | p99 Mean (ms) |
|---|---|---|---|---|---|---|
| **Benign Payload** | 0.4969 | ±0.0066 | 0.4932 | 0.5833 | ±0.0117 | 0.633 |
| **Adversarial Payload** | 0.4849 | ±0.0026 | 0.4828 | 0.5766 | ±0.0084 | 0.6224 |
| **Malformed Payload** | 0.2164 | ±0.0043 | 0.2059 | 0.2995 | ±0.0129 | 0.344 |
| **High-Volume Payload** | 3.6656 | ±0.0211 | 3.6467 | 3.8212 | ±0.0515 | 4.0801 |

---

## 4. Concurrent Workload Throughput
| Threads | QPS Mean (req/sec) | QPS 95% CI | p50 QPS | StdDev QPS | Raw Per-Run QPS Means |
|---|---|---|---|---|---|
| **1 Thread** | **456.6578 req/s** | ±26.9834 | 456.6578 | 37.7229 | `[483.4283, 484.174, 468.0087, 447.1632, 453.1174, 355.3104, 468.3821, 466.0504, 481.0353, 459.9083]` |
| **2 Threads** | **406.6686 req/s** | ±12.2882 | 406.6686 | 17.1789 | `[364.1326, 409.5089, 397.5322, 422.7812, 421.3263, 401.3716, 413.7082, 403.691, 418.3261, 414.3074]` |
| **4 Threads** | **382.9343 req/s** | ±7.2692 | 382.9343 | 10.1623 | `[377.1615, 392.0798, 363.427, 377.8061, 383.3837, 388.5664, 396.5815, 388.2381, 389.7743, 372.3242]` |
| **8 Threads** | **338.5664 req/s** | ±54.8201 | 338.5664 | 76.6386 | `[378.0233, 395.6275, 383.3487, 359.9341, 238.7125, 162.5976, 334.1401, 381.4218, 377.0203, 374.8386]` |

---

## 5. Cold-Start vs. Steady-State & Resource Allocations
- **Cold-Start Latency Mean:** `0.8633 ms` (±0.1498)
- **Steady-State Mean Latency:** `0.5168 ms` (±0.016)
- **Cold-Start Overhead Ratio:** `1.67x`
- **CPU Process Execution Time:** `30.0944 seconds`
- **Current Heap Allocation:** `0.7333 MB`
- **Peak Heap Allocation:** `0.814 MB`

---

## 6. Audit Logging & False-Positive Halt Recovery Overhead
- **In-Memory Receipt Generation:** `1.1532 ms/call` (p95: `1.1532 ms`)
- **Audit File Persistence (JSONL + HMAC Chain + flock):** `0.6277 ms/call` (p95: `0.8787 ms`)
- **Allowed Submission Latency:** `0.4969 ms`
- **Halted Submission Latency:** `0.5136 ms` (includes vector revocation + audit HALT record)
- **False-Positive Halt + Recovery Retry Loop:** `1.0484 ms` (2x pipeline pass overhead)

---

## 7. Performance Evidence & Verification Summary
Profiling identified CPU hotspots in `PermissionGate._deep_regex_inspection`, `TokenSurprisalSensor.compute_z_scores`, and schema validation error logging.
1. **Empty-Object Short-Circuiting:** Fast-path check `if not obj: return False` in `_deep_regex_inspection` reduced redundant stack/DFS allocations for empty payloads/actions.
2. **Fast-Path Type Checking:** Replaced per-element `try...except` exception wrapping in `compute_z_scores` with `type(lp) in (float, int)`, removing exception frame setup costs while preserving exact exception types and error messages.
3. **Pre-Allocated Redaction Sets:** Replaced per-call set construction in `CanonicalProblemRepresentation.mask_egress_payload` with module-level `DEFAULT_REDACTION_KEYS`.
4. **Equivalence & Security Guarantees:** 100% decision and exception equivalence, audit-chain cryptographic integrity (`verify_chain_integrity()`), and multi-threaded scheduler state isolation verified via `tests/unit/test_equivalence.py`.
