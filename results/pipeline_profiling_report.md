# 📊 EpistemicOS Empirical Profiling & Performance Report

## 1. Provenance, Reproducibility & Environment
- **Git Commit SHA:** `f993219a55a83429501d22d0cf51b3beec33af4b`
- **Exact Benchmark Command:** `PYTHONPATH=. python3 benchmarks/run_pipeline_profiling.py`
- **Repetitions:** 10 runs x 200 iterations/run
- **Python Runtime:** Version 3.12.13 on Linux-6.8.0-x86_64-with-glibc2.39
- **Hardware Profile:** 4 CPUs (x86_64)
- **PyTorch/CUDA Acceleration:** CUDA Available = `False` (PyTorch Version: `N/A`)

---

## 2. Per-Gate & Component Latency Breakdown
*All measurements reported in milliseconds across 10 repetitions (with 95% confidence intervals).*

| Component / Gate | Mean (ms) | 95% CI Margin | p50 (ms) | p95 (ms) | p99 (ms) | StdDev |
|---|---|---|---|---|---|---|
| **CPR Schema Validation** | 0.3293 | ±0.0086 | 0.1926 | 0.7992 | 1.2543 | 0.2766 |
| **Permission Gate** | 1.3466 | ±0.0535 | 0.327 | 3.3961 | 5.1431 | 1.4937 |
| **Entropy Gate** | 1.6115 | ±0.0691 | 0.3046 | 4.2433 | 6.5801 | 1.9297 |
| **Triangulation Gate** | 0.0386 | ±0.0005 | 0.0311 | 0.0702 | 0.0998 | 0.0148 |
| **Crypto Attestation Gate** | 0.0247 | ±0.0003 | 0.0213 | 0.041 | 0.0709 | 0.0096 |
| **Audit Trail Persistence** | 0.5657 | ±0.0046 | 0.5332 | 0.7978 | 1.0595 | 0.128 |
| **Total End-to-End Pipeline** | 3.7695 | ±0.1329 | 1.5776 | 10.7596 | 16.5176 | 4.2895 |

---

## 3. Workload Latency Comparison
| Workload | Mean Latency (ms) | 95% CI Margin | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|
| **Benign Payload** | 0.5048 | ±0.0048 | 0.4965 | 0.6067 | 0.6819 |
| **Adversarial Payload** | 0.4946 | ±0.0026 | 0.4888 | 0.6019 | 0.6757 |
| **Malformed Payload** | 0.2276 | ±0.0041 | 0.2172 | 0.3032 | 0.365 |
| **High-Volume Payload** | 3.6861 | ±0.0089 | 3.6531 | 3.9064 | 4.1972 |

---

## 4. Concurrent Workload Throughput
| Threads | QPS Mean (req/sec) | 95% CI Margin | p50 QPS | StdDev QPS |
|---|---|---|---|---|
| **1 Thread** | **466.3758 req/s** | ±6.0615 | 462.1854 | 9.7796 |
| **2 Threads** | **410.5913 req/s** | ±9.6665 | 414.0859 | 15.5961 |
| **4 Threads** | **395.4759 req/s** | ±3.4699 | 397.7432 | 5.5984 |
| **8 Threads** | **383.6319 req/s** | ±8.003 | 390.0418 | 12.9121 |

---

## 5. Cold-Start vs. Steady-State & Resource Allocations
- **Cold-Start Latency Mean:** `1.3517 ms` (±0.1889)
- **Steady-State Mean Latency:** `0.5141 ms` (±0.0035)
- **Cold-Start Overhead Ratio:** `2.63x`
- **CPU Process Execution Time:** `27.6537 seconds`
- **Current Heap Allocation:** `0.7492 MB`
- **Peak Heap Allocation:** `0.8232 MB`

---

## 6. Audit Logging & False-Positive Halt Recovery Overhead
- **In-Memory Receipt Generation:** `1.1743 ms/call` (p95: `2.1826 ms`)
- **Audit File Persistence (JSONL + HMAC Chain + flock):** `0.5657 ms/call` (p95: `0.7978 ms`)
- **Allowed Submission Latency:** `0.5048 ms`
- **Halted Submission Latency:** `0.5242 ms` (includes vector revocation + audit HALT record)
- **False-Positive Halt + Recovery Retry Loop:** `1.0641 ms` (2x pipeline pass overhead)

---

## 7. Performance Evidence & Verification Summary
Profiling identified CPU bottlenecks in `PermissionGate._deep_regex_inspection`, `TokenSurprisalSensor.compute_z_scores`, and schema validation error logging.
1. **Empty-Object Short-Circuiting:** Fast-path check `if not obj: return False` in `_deep_regex_inspection` reduced redundant stack/DFS allocations for empty payloads/actions.
2. **Fast-Path Type Checking:** Replaced per-element `try...except` exception wrapping in `compute_z_scores` with `type(lp) in (float, int)`, removing exception frame setup costs while preserving exact exception types and error messages.
3. **Pre-Allocated Redaction Sets:** Replaced per-call set construction in `CanonicalProblemRepresentation.mask_egress_payload` with module-level `DEFAULT_REDACTION_KEYS`.
4. **Equivalence & Safety Guarantees:** 100% decision and exception equivalence verified via `tests/unit/test_equivalence.py`.
