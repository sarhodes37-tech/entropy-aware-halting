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
| **CPR Schema Validation** | 0.299 | ±0.0017 | 0.1557 | 0.7665 | ±0.0082 | 0.8194 | ±0.0167 | 0.0024 |
| **Permission Gate** | 1.2841 | ±0.0034 | 0.3255 | 3.2871 | ±0.0118 | 3.4079 | ±0.0637 | 0.0048 |
| **Entropy Gate** | 1.528 | ±0.0044 | 0.2953 | 4.1063 | ±0.0131 | 4.2765 | ±0.1411 | 0.0062 |
| **Triangulation Gate** | 0.0363 | ±0.0002 | 0.0316 | 0.0569 | ±0.0066 | 0.0794 | ±0.0035 | 0.0003 |
| **Crypto Attestation Gate** | 0.0231 | ±0.0002 | 0.0215 | 0.0286 | ±0.0004 | 0.06 | ±0.0024 | 0.0002 |
| **Audit Trail Persistence** | 0.5041 | ±0.0159 | 0.4925 | 0.5707 | ±0.0109 | 0.6261 | ±0.0268 | 0.0222 |
| **Total End-to-End Pipeline** | 3.4574 | ±0.0084 | 1.5252 | 10.1249 | ±0.0335 | 10.4112 | ±0.1524 | 0.0118 |

> **Note on Percentile Sample Variance:** Per-run p95 and p99 estimates are computed over $M=200$ samples per run. While p50 and p95 estimates are statistically stable across runs, p99 estimates exhibit higher natural sampling dispersion due to tail latency events (e.g. garbage collection or OS context switches).

---

## 3. Workload Latency & Programmatic Paired Analysis
| Workload | Mean Latency (ms) | Mean 95% CI | p50 (ms) | p95 Mean (ms) | p95 95% CI | p99 Mean (ms) |
|---|---|---|---|---|---|---|
| **Benign Payload** | 0.4811 | ±0.0064 | 0.4836 | 0.5447 | ±0.015 | 0.585 |
| **Adversarial Payload** | 0.4694 | ±0.0102 | 0.4728 | 0.5244 | ±0.0114 | 0.5721 |
| **Malformed Payload** | 0.1994 | ±0.0013 | 0.1887 | 0.2551 | ±0.0022 | 0.275 |
| **High-Volume Payload** | 3.4928 | ±0.0173 | 3.4769 | 3.6339 | ±0.0844 | 3.8525 |

### Programmatic Paired t-Test: Malformed-Payload Latency
- **Paired Mean Difference (d_bar):** `-0.0988 ms` (-27.4% latency drop)
- **Paired Sample StdDev (s_d):** `0.0018 ms`
- **Standard Error (SE):** `0.0006 ms`
- **Paired t-Statistic:** `-170.8989` (df=9, p < 0.0001)
- **95% Paired Student's t-CI:** `[-0.1001, -0.0975] ms`

---

## 4. Concurrent Workload Throughput & Programmatic Paired Analysis
| Threads | QPS Mean (req/sec) | QPS 95% CI | p50 QPS | StdDev QPS | Raw Per-Run QPS Means |
|---|---|---|---|---|---|
| **1 Thread** | **489.2244 req/s** | ±5.1236 | 489.2244 | 7.1623 | `[483.8898, 496.9434, 493.8725, 483.5822, 489.9195, 474.0738, 496.681, 489.5006, 488.7058, 495.0755]` |
| **2 Threads** | **453.54 req/s** | ±3.6481 | 453.54 | 5.0997 | `[443.0121, 455.7922, 451.8679, 457.3694, 457.3137, 454.5375, 459.8283, 456.3997, 447.7277, 451.5513]` |
| **4 Threads** | **416.8028 req/s** | ±2.7199 | 416.8028 | 3.8022 | `[413.7052, 419.5722, 413.8151, 422.296, 418.7058, 418.8156, 416.6835, 408.8031, 417.7593, 417.8726]` |
| **8 Threads** | **416.4183 req/s** | ±2.4415 | 416.4183 | 3.413 | `[417.6717, 416.3806, 415.0581, 419.2681, 418.1227, 417.797, 416.3539, 407.3234, 418.3113, 417.8963]` |

### Programmatic Paired t-Test: 1-Thread Throughput Gain
- **Paired Differences (d_i):** `[42.6898, 48.4434, 54.7725, 40.7822, 54.3195, 113.9738, 51.381, 47.7006, 39.6058, 56.8755]` req/s
- **Mean Paired Difference (d_bar):** `+55.0544 req/s` (+5.18%)
- **Paired Sample StdDev (s_d):** `21.556 req/s`
- **Standard Error (SE):** `6.8166 req/s`
- **Paired t-Statistic:** `8.0765` (df=9, p = 0.0005)
- **95% Paired Student's t-CI:** `[39.6342, 70.4746] req/s`

---

## 5. Cold-Start vs. Steady-State & Resource Allocations
- **Cold-Start Latency Mean:** `0.7921 ms` (±0.1425)
- **Steady-State Mean Latency:** `0.4864 ms` (±0.0077)
- **Cold-Start Overhead Ratio:** `1.63x`
- **CPU Process Execution Time:** `25.6836 seconds`
- **Current Heap Allocation:** `0.7325 MB`
- **Peak Heap Allocation:** `0.8132 MB`

---

## 6. Audit Logging & False-Positive Halt Recovery Overhead
- **In-Memory Receipt Generation:** `1.0923 ms/call` (p95: `1.0923 ms`)
- **Audit File Persistence (JSONL + HMAC Chain + flock):** `0.5041 ms/call` (p95: `0.5707 ms`)
- **Allowed Submission Latency:** `0.4811 ms`
- **Halted Submission Latency:** `0.4705 ms` (includes vector revocation + audit HALT record)
- **False-Positive Halt + Recovery Retry Loop:** `0.9513 ms` (2x pipeline pass overhead)

---

## 7. Performance Evidence & Verification Summary
Profiling identified CPU hotspots in `PermissionGate._deep_regex_inspection`, `TokenSurprisalSensor.compute_z_scores`, and schema validation error logging.
1. **Empty-Object Short-Circuiting:** Fast-path check `if not obj: return False` in `_deep_regex_inspection` reduced redundant stack/DFS allocations for empty payloads/actions.
2. **Fast-Path Type Checking:** Replaced per-element `try...except` exception wrapping in `compute_z_scores` with `type(lp) in (float, int)`, removing exception frame setup costs while preserving exact exception types and error messages.
3. **Pre-Allocated Redaction Sets:** Replaced per-call set construction in `CanonicalProblemRepresentation.mask_egress_payload` with module-level `DEFAULT_REDACTION_KEYS`.
4. **Equivalence & Security Guarantees:** 100% decision and exception equivalence, audit-chain cryptographic integrity (`verify_chain_integrity()`), and multi-threaded scheduler state isolation verified via `tests/unit/test_equivalence.py`.
