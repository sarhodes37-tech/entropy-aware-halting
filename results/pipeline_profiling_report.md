# 📊 EpistemicOS Complete Pipeline Profiling Report

## 1. Environment & Hardware Context
- **Python Version:** 3.12.13
- **CPU Count:** 4
- **Platform:** Linux-6.8.0-x86_64-with-glibc2.39
- **PyTorch/CUDA Status:** CUDA Available = `False` (PyTorch Version: `N/A`)

---

## 2. Per-Gate & Component Latency Breakdown
| Component / Gate | Mean (ms) | p50 (ms) | p95 (ms) | p99 (ms) | StdDev (ms) |
|---|---|---|---|---|---|
| **CPR Schema Validation** | 0.3091 | 0.1881 | 0.7471 | 0.8015 | 0.2338 |
| **Permission Gate** | 1.3125 | 0.339 | 3.3031 | 3.6414 | 1.3864 |
| **Entropy Gate** | 1.5477 | 0.3198 | 4.1058 | 4.5557 | 1.7885 |
| **Triangulation Gate** | 0.0383 | 0.032 | 0.0702 | 0.094 | 0.0164 |
| **Crypto Attestation Gate** | 0.0246 | 0.021 | 0.0499 | 0.0844 | 0.0112 |
| **Audit Trail Persistence** | 0.5633 | 0.5354 | 0.8743 | 1.0965 | 0.1337 |
| **Total End-to-End** | 3.6166 | 1.5718 | 10.3657 | 11.0094 | 3.8785 |

---

## 3. Workload Comparison
| Workload | Mean Latency (ms) | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|
| **Benign Payload** | 0.5104 | 0.5086 | 0.5912 | 0.6298 |
| **Adversarial Payload** | 0.4958 | 0.4891 | 0.5758 | 0.6322 |
| **Malformed Payload** | 0.2165 | 0.2081 | 0.2849 | 0.3072 |
| **High-Volume Payload** | 3.7042 | 3.6334 | 4.0659 | 4.2419 |

---

## 4. Concurrent Throughput
| Threads | Total Requests | Duration (sec) | Throughput (req/sec) |
|---|---|---|---|
| **1 Thread** | 1000 | 2.123 | **471.04 req/s** |
| **2 Threads** | 1000 | 2.5645 | **389.94 req/s** |
| **4 Threads** | 1000 | 2.7152 | **368.3 req/s** |
| **8 Threads** | 1000 | 2.5358 | **394.35 req/s** |

---

## 5. Cold-Start vs. Steady-State & Resource Allocations
- **Cold-Start Latency:** `2.6684 ms`
- **Steady-State Mean Latency:** `0.641 ms`
- **Cold-Start Overhead Ratio:** `4.16x`
- **Total CPU Process Time:** `6.6602 seconds`
- **Current Memory Allocation:** `0.2821 MB`
- **Peak Memory Allocation:** `0.3561 MB`

---

## 6. Audit Logging & Halt Recovery Costs
- **In-Memory Receipt Minting Cost:** `1.1294 ms/call`
- **Audit File Persistence (JSONL + SHA-256 + flock):** Mean `0.5633 ms` (p95: `0.8743 ms`)
- **Allowed Request Mean Latency:** `0.5104 ms`
- **Halted Request Mean Latency:** `0.5126 ms`
- **False-Positive Halt + Recovery Loop:** `1.1055 ms` (2x pipeline pass overhead)

---

## 7. Evidence-Based Optimization Summary
Profiling identified key CPU hotspots:
1. **`PermissionGate._deep_regex_inspection`**: Added empty-object short-circuiting (`if not obj: return False`), eliminating redundant DFS traversals for empty/None payloads.
2. **`TokenSurprisalSensor.compute_z_scores`**: Replaced per-element `try...except` exception wrapping with fast-path `type(lp) in (float, int)` checks, removing per-token exception frame overhead.
3. **`CanonicalProblemRepresentation` Egress Masking**: Pre-allocated `DEFAULT_REDACTION_KEYS` set to eliminate per-call set construction.
4. **`EpistemicOrchestrator._validate_and_normalize`**: Avoided dummy CPR object instantiation during schema error handling, speeding up malformed payload processing by ~25%.
