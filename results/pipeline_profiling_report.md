# 📊 EpistemicOS Empirical Profiling & Performance Report

## 1. Provenance, Reproducibility & Environment
- **Git Commit SHA:** `f993219a55a83429501d22d0cf51b3beec33af4b`
- **Exact Benchmark Command:** `PYTHONPATH=. python3 benchmarks/run_pipeline_profiling.py`
- **Statistical Model:** Run-level Student's t-distribution ($N=10$ runs, $df=9$, $t_{0.025}=2.262$)
- **Repetitions:** 10 runs x 200 iterations/run
- **Python Runtime:** Version 3.12.13 on Linux-6.8.0-x86_64-with-glibc2.39
- **Hardware Profile:** 4 CPUs (x86_64)
- **PyTorch/CUDA Acceleration:** CUDA Available = `False` (PyTorch Version: `N/A`)

---

## 2. Per-Gate & Component Latency Breakdown
*All measurements reported in milliseconds calculated at the run level across $N=10$ independent run observations (with 95% Student's t-CI).*

| Component / Gate | Mean (ms) | Mean 95% CI | p50 (ms) | p95 Mean (ms) | p95 95% CI | p99 Mean (ms) | p99 95% CI | StdDev |
|---|---|---|---|---|---|---|---|---|
| **CPR Schema Validation** | 0.354 | ±0.0296 | 0.2132 | 0.9294 | ±0.2048 | 1.1329 | ±0.3585 | 0.0414 |
| **Permission Gate** | 1.4259 | ±0.1378 | 0.3461 | 4.1368 | ±1.0549 | 4.962 | ±1.7185 | 0.1927 |
| **Entropy Gate** | 1.7122 | ±0.1623 | 0.3225 | 5.2292 | ±1.255 | 6.3195 | ±2.0025 | 0.2269 |
| **Triangulation Gate** | 0.0443 | ±0.0036 | 0.0346 | 0.0813 | ±0.0141 | 0.1303 | ±0.0362 | 0.005 |
| **Crypto Attestation Gate** | 0.0295 | ±0.0036 | 0.0237 | 0.0468 | ±0.0103 | 0.0981 | ±0.032 | 0.0051 |
| **Audit Trail Persistence** | 0.6234 | ±0.0384 | 0.5631 | 0.9504 | ±0.165 | 1.3195 | ±0.4018 | 0.0537 |
| **Total End-to-End Pipeline** | 4.0243 | ±0.322 | 1.6476 | 13.09 | ±2.8625 | 15.6328 | ±4.902 | 0.4501 |

---

## 3. Workload Latency Comparison
| Workload | Mean Latency (ms) | Mean 95% CI | p50 (ms) | p95 Mean (ms) | p95 95% CI | p99 Mean (ms) |
|---|---|---|---|---|---|---|
| **Benign Payload** | 0.5053 | ±0.0051 | 0.4988 | 0.6092 | ±0.0125 | 0.7343 |
| **Adversarial Payload** | 0.6101 | ±0.1072 | 0.5551 | 0.9443 | ±0.3052 | 1.2866 |
| **Malformed Payload** | 0.2252 | ±0.0038 | 0.213 | 0.318 | ±0.0106 | 0.3883 |
| **High-Volume Payload** | 3.9966 | ±0.3956 | 3.7629 | 5.2946 | ±2.2404 | 6.0242 |

---

## 4. Concurrent Workload Throughput
| Threads | QPS Mean (req/sec) | QPS 95% CI | p50 QPS | StdDev QPS |
|---|---|---|---|---|
| **1 Thread** | **447.751 req/s** | ±10.3987 | 447.751 | 14.5374 |
| **2 Threads** | **400.7014 req/s** | ±10.5175 | 400.7014 | 14.7034 |
| **4 Threads** | **384.4804 req/s** | ±10.0719 | 384.4804 | 14.0806 |
| **8 Threads** | **388.9043 req/s** | ±7.1425 | 388.9043 | 9.9853 |

---

## 5. Cold-Start vs. Steady-State & Resource Allocations
- **Cold-Start Latency Mean:** `1.4248 ms` (±0.5721)
- **Steady-State Mean Latency:** `0.5151 ms` (±0.019)
- **Cold-Start Overhead Ratio:** `2.77x`
- **CPU Process Execution Time:** `29.6145 seconds`
- **Current Heap Allocation:** `0.7362 MB`
- **Peak Heap Allocation:** `0.8103 MB`

---

## 6. Audit Logging & False-Positive Halt Recovery Overhead
- **In-Memory Receipt Generation:** `1.1405 ms/call` (p95: `1.1405 ms`)
- **Audit File Persistence (JSONL + HMAC Chain + flock):** `0.6234 ms/call` (p95: `0.9504 ms`)
- **Allowed Submission Latency:** `0.5053 ms`
- **Halted Submission Latency:** `0.5008 ms` (includes vector revocation + audit HALT record)
- **False-Positive Halt + Recovery Retry Loop:** `1.0259 ms` (2x pipeline pass overhead)

---

## 7. Performance Evidence & Verification Summary
Profiling identified CPU hotspots in `PermissionGate._deep_regex_inspection`, `TokenSurprisalSensor.compute_z_scores`, and schema validation error logging.
1. **Empty-Object Short-Circuiting:** Fast-path check `if not obj: return False` in `_deep_regex_inspection` reduced redundant stack/DFS allocations for empty payloads/actions.
2. **Fast-Path Type Checking:** Replaced per-element `try...except` exception wrapping in `compute_z_scores` with `type(lp) in (float, int)`, removing exception frame setup costs while preserving exact exception types and error messages.
3. **Pre-Allocated Redaction Sets:** Replaced per-call set construction in `CanonicalProblemRepresentation.mask_egress_payload` with module-level `DEFAULT_REDACTION_KEYS`.
4. **Equivalence & Security Guarantees:** 100% decision and exception equivalence, audit-chain cryptographic integrity (`verify_chain_integrity()`), and multi-threaded scheduler state isolation verified via `tests/unit/test_equivalence.py`.
