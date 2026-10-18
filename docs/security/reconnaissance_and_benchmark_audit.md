# EpistemicOS Repository Reconnaissance & Benchmark Audit Report

**Date:** 2026-03-30
**Author:** Jules (Security Evaluation Infrastructure Lead)
**Status:** COMPLETED AUDIT / PHASE 0

---

## 1. Executive Summary

This audit evaluates the security evaluation infrastructure of EpistemicOS prior to establishing a four-layer evidence foundation. The primary objective is to verify that security claims reported by benchmark harnesses correspond to observable production execution paths, that ground-truth labels and metric calculations are statistically sound, and that no single headline score masks component-level gaps or unmediated execution boundaries.

---

## 2. Benchmark Suite Inventory & Execution Path Audit

The repository contains several evaluation and benchmark entry points:

| Entry Point | Target Evaluation Area | Execution Path Type | Primary Output Artifacts |
|---|---|---|---|
| `benchmarks/run_full_benchmark.py` | N=100 Stratified Synthetic Baseline & Ablation | `EpistemicOrchestrator.process_submission()` | `results/ablation_table.json`, `results/per_case_results.json`, `results/ablation_summary.md` |
| `benchmarks/run_incident_lab.py` | 7 Incident-Derived Real Scenario Investigations | Core Orchestrator + Permission Gate + Containment + Boundary | `results/incident_lab_results.json`, `docs/security/incident_lab_report.md` |
| `benchmarks/run_e2e_security_evaluation.py` | End-to-End Security Evidence & Provenance Reconciliation | Orchestrator + ProvenanceReconciler | `results/security_evidence.json`, `docs/security/e2e_security_evidence_report.md` |
| `benchmarks/test_layer2_benchmarks.py` | Token Bloat, HumanEval & IFEval JSON Constraints | Pytest Harness / Helper Functions | Pytest execution results |
| `benchmarks/test_layer3_benchmarks.py` | Commercial Underwriting Rationalization & Pressure | Pytest Harness / Helper Functions | Pytest execution results |
| `benchmarks/test_layer4_benchmarks.py` | Adversarial Injection & Schema Validation | Core Orchestrator + Gate Contracts | Pytest execution results |

### Key Execution Path Observations:
1. **Production Orchestrator Execution:** Both `run_full_benchmark.py` and `run_incident_lab.py` invoke `EpistemicOrchestrator` directly rather than mocking gate responses.
2. **Provenance Grant Semantics:** `run_incident_lab.py` and `run_e2e_security_evaluation.py` adhere strictly to dynamic provenance checks without seeding fake `AUTHORIZATION_GRANTED` events.
3. **Helper vs. Boundary Separation:** Component-level checks (e.g. `ContainmentGuard` or `ShowerCurtainGate` in isolation) are distinguished in Incident Lab reports via explicit labels like `PARTIAL_GATING_DEFENSE` or `COMPONENT_LEVEL_FLEET_EVIDENCE` (addressing GAP-03 and GAP-04).

---

## 3. N=100 Benchmark Dataset Audit (`benchmarks/data/eval_set.jsonl`)

An exhaustive audit of the 100 evaluation cases in `benchmarks/data/eval_set.jsonl` was conducted:

### 3.1 Cryptographic Digest & Dataset Integrity
- **SHA-256 Digest:** `f4e31381a922c1143769ccb887c4841e4a14fedec6eef6569d40eed2956ce873`
- **Total Case Count:** $N = 100$
- **Expected Outcome Distribution:**
  - `ALLOW` (Benign Controls): 35 cases ($35\%$)
  - `ROLLBACK` (Adversarial Truncation): 40 cases ($40\%$)
  - `HALT` (Deterministic Interception): 25 cases ($25\%$)
  - **Total Benign ($N_{\text{benign}}$):** 35
  - **Total Adversarial ($N_{\text{adv}}$):** 65

### 3.2 Scenario Family Breakdown
1. Commercial Underwriting & Operations ($N=20$)
2. Cyber, Shell & DB Threat Vectors ($N=15$)
3. Multi-Turn & Obfuscated Prompt Injections ($N=15$)
4. Impossible Paradoxes & Introspection ($N=15$)
5. High-Noise Benign Controls ($N=15$)
6. Unauthorized Operations & Boundary Failures ($N=10$)
7. Gate Exceptions & Edge Cases ($N=10$)

### 3.3 Label Sanity & Denominator Verification
- **Label Audit:** Every case's `expected_action` matches its `is_adversarial` flag (`ALLOW` $\iff$ `is_adversarial: false`; `ROLLBACK`/`HALT` $\iff$ `is_adversarial: true`). Zero label mismatches were detected.
- **Metric Calculations:** Precision, Recall, FPR, FNR, Wilson 95% CIs, and McNemar paired tests in `run_full_benchmark.py` accurately handle zero-denominator boundary conditions by returning `"N/A"` or $0.0\%$ appropriately.
- **Observed Baseline Performance:**
  - Ungated Generation: Accuracy $35.0\%$, Recall $0.0\%$, FNR $100.0\%$
  - Entropy-Only Gating: Accuracy $90.0\%$, Recall $84.62\%$, FPR $0.0\%$
  - Permission-Only Gating: Accuracy $68.0\%$, Recall $50.77\%$, FPR $0.0\%$
  - Combined Gating: Accuracy $100.0\%$, Recall $100.0\%$, FPR $0.0\%$, FNR $0.0\%$

---

## 4. Confirmed Defects & Implementation Gaps

1. **Lack of Distinct Four-Layer Architecture:**
   Previously, benchmark outputs reported a single aggregate score (`ablation_table.json`), blending deterministic unit tests, execution boundary tests, and performance metrics into one headline metric.
2. **Missing Live-Agent Red-Team Layer (Layer C):**
   There was no dedicated, reproducible harness for evaluating multi-step stochastic agent red-team bypass attempts against isolated synthetic targets.
3. **Absence of Frozen Dataset Manifest Enforcement:**
   Benchmark scripts loaded `eval_set.jsonl` without verifying its SHA-256 digest against an immutable manifest prior to execution.
4. **CI Enforcement Gaps:**
   CI workflows (`ci.yml` and `security_bench.yml`) verified that `ablation_table.json` existed and sample count $> 0$, but did not enforce zero security invariant violations, dataset digest matches, or documented metric regression thresholds.
5. **Architectural Gap Tracking:**
   Incident Lab correctly identifies architectural limitations (e.g. GAP-03: lack of transitive network egress enforcement on allowed operations; GAP-04: multi-tenant fleet isolation rely on orchestrator process boundary), but these gaps were not prominently surfaced in CI reporting.

---

## 5. Reusable Infrastructure & Implementation Strategy

### Reusable Assets:
- `EpistemicOrchestrator` and gate implementations (`PermissionGate`, `EntropyGate`, `TriangulationGate`, `ShowerCurtainGate`, `ContainmentGuard`, `TrustedExecutionBoundary`).
- N=100 dataset (`benchmarks/data/eval_set.jsonl`) and Preregistration commitments (`docs/PREREGISTRATION.md`).
- McNemar test & Wilson score statistical helper functions in `benchmarks/run_full_benchmark.py`.
- Scenario fixtures and provenance reconciler in `tests/incident_lab/` and `benchmarks/run_incident_lab.py`.

### Proposed Implementation Sequence:
1. **Phase 1:** Document the formal Four-Layer Evidence Architecture in `docs/security/evidence_architecture.md`.
2. **Phase 2:** Freeze the evaluation dataset and publish `benchmarks/data/dataset_manifest.json` with cryptographic SHA-256 verification.
3. **Phase 3:** Construct the Layer C Live-Agent Red-Team simulator (`benchmarks/run_live_agent_redteam.py`) and consolidated report generator (`benchmarks/generate_evidence_report.py`).
4. **Phase 4:** Update CI workflows (`.github/workflows/ci.yml` and `.github/workflows/security_bench.yml`) to enforce security invariants, dataset integrity, and metric regressions.
5. **Phase 5:** Implement comprehensive unit tests (`tests/unit/test_evidence_architecture.py`) to verify the evidence pipeline.
