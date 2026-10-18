# EpistemicOS Four-Layer Evidence Architecture Specification

**Version:** 1.0.0
**Date:** 2026-03-30
**Status:** SPECIFICATION / PHASE 1

---

## 1. Objective and Core Directives

The objective of the EpistemicOS Evidence Architecture is to establish reproducible, independently evaluable security claims across four distinct, uncollapsed layers. Rather than maximizing a single headline benchmark score, this architecture provides rigorous CI enforcement for security-invariant violations, dataset integrity, and documented metric regressions.

---

## 2. Machine-Readable Status Semantics

All evaluation components, test harnesses, and evidence aggregators must emit explicit, standardized status codes defined centrally:

| Status Code | Definition | Security Implication |
|---|---|---|
| `PASS` | Security invariant holds, expected outcome observed, zero unmediated side effects. | Fully verified under tested conditions. |
| `FAIL` | Security invariant violated, unauthorized side effect executed, or regression threshold exceeded. | Critical security failure; blocks CI merge. |
| `PARTIAL` | Component-level defense succeeded, but end-to-end transitive enforcement is unintegrated. | Known architectural defense gap (e.g., GAP-03). |
| `UNTESTED` | Test path or integration unavailable in current architecture. | Execution boundary not exercised. |
| `BLOCKED_BY_ARCHITECTURE` | Feature or path intentionally restricted or unsupported by system model. | Structural design constraint. |
| `INCONCLUSIVE` | Trial produced ambiguous execution telemetry or stochastic variance without explicit outcome. | Requires further investigation or additional trials. |

---

## 3. Four Distinct Evidence Layers

```
+-----------------------------------------------------------------------------------+
|                        EPISTEMICOS EVIDENCE ARCHITECTURE                          |
+-----------------------------------------------------------------------------------+
|  LAYER A: Deterministic Regression                                                 |
|  - Invariant assertion unit tests (pytest tests/unit/, tests/e2e_security/)        |
|  - Explicit expected outcome per case, zero silent failures                         |
+-----------------------------------------------------------------------------------+
|  LAYER B: Actual Execution-Boundary Integration                                    |
|  - Incident Lab 7-scenario evaluation harness (benchmarks/run_incident_lab.py)    |
|  - Real EpistemicOrchestrator, TrustedExecutionBoundary, LocalProvenanceStore    |
|  - Zero manually seeded grants, full accounting of decisions vs boundary admission|
+-----------------------------------------------------------------------------------+
|  LAYER C: Live-Agent Red-Team                                                      |
|  - Synthetic multi-step red-team simulator (benchmarks/run_live_agent_redteam.py)  |
|  - Multi-turn injections, indirect egress, credential misuse, multi-agent cascades |
|  - Zero external network access, isolated local simulators                         |
+-----------------------------------------------------------------------------------+
|  LAYER D: Performance & Cost Benchmarks                                            |
|  - Stratified N=100 evaluation suite (benchmarks/run_full_benchmark.py)           |
|  - Latency percentiles, token usage, Wilson 95% CIs, McNemar paired statistical tests|
|  - Strictly decoupled from binary security invariant pass/fail evaluation          |
+-----------------------------------------------------------------------------------+
```

### Layer A: Deterministic Regression
- **Purpose:** Prevent known security regressions and enforce fundamental code invariants.
- **Scope:** Unit and property-based tests for `PermissionGate`, `EntropyGate`, `ShowerCurtainGate`, `ContainmentGuard`, `TrustedExecutionBoundary`, and `LocalProvenanceStore`.
- **Requirements:**
  - Standard `pytest` suite execution (`tests/unit/`, `tests/e2e_security/`).
  - Direct assertions on security invariants (e.g. rejection of scope bypasses, malformed logprobs, unauthorized token consumption).
  - Explicit machine-readable assertion outputs.

### Layer B: Actual Execution-Boundary Integration
- **Purpose:** Demonstrate that security controls govern real protected operations through the core orchestrator and trusted execution boundary.
- **Scope:** 7 Incident Lab real-world scenarios (`Case1GitHub` through `Case7Fleet`).
- **Requirements:**
  - Execute through `EpistemicOrchestrator` and `TrustedExecutionBoundary`.
  - Obtain authorization strictly through server-controlled issuance paths; **zero manually seeded `AUTHORIZATION_GRANTED` events**.
  - Measure governance decision, boundary admission, callback invocation, task completion, and audit evidence independently.
  - Distinguish component-level gating from end-to-end containment (`PARTIAL` status for GAP-03/GAP-04).

### Layer C: Live-Agent Red-Team
- **Purpose:** Evaluate multi-step, stochastic agent bypass attempts against isolated synthetic targets.
- **Scope:** Multi-turn adversarial prompt injections, indirect egress attempts, credential misuse vectors, and multi-agent cascades (`benchmarks/run_live_agent_redteam.py`).
- **Requirements:**
  - Strictly isolated synthetic local resources (local mock webhooks, mock DBs, synthetic credentials).
  - **Zero external network access** or real credentials.
  - Record attempted attack vectors, blocked attempts, unauthorized actions, completed side effects, and inconclusive runs.
  - Preserve exact test prompts, execution seeds, tool permissions, and model parameters.

### Layer D: Performance & Cost Benchmarks
- **Purpose:** Quantify the operational overhead, latency, token consumption, and statistical reliability of security controls.
- **Scope:** N=100 stratified held-out benchmark dataset (`benchmarks/run_full_benchmark.py`).
- **Requirements:**
  - Measure Latency (P50, P95, Mean), Token Consumption, Accuracy, Precision, Recall, FPR, FNR, Wilson 95% Confidence Intervals, and McNemar paired statistical comparisons.
  - Keep performance scoring strictly separated from binary Layer A/B security invariant checks (a performance improvement can never compensate for a security breach).

---

## 4. Evidence Reporting & CI Integration

The evidence pipeline aggregates all four layers into a single canonical artifact: `results/four_layer_evidence.json` and human-readable `docs/security/four_layer_evidence_report.md`.

### Reproducibility Metadata Requirements:
Every generated evidence artifact must record:
1. Evaluated Git commit hash.
2. Working tree status (`CLEAN` or `DIRTY`).
3. SHA-256 digest of the frozen evaluation dataset (`benchmarks/data/eval_set.jsonl`).
4. Exact execution timestamp, environment parameters, and Python version.
