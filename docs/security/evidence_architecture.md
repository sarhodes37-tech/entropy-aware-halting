# EpistemicOS Four-Layer Evidence Architecture Specification

**Version:** 2.3.0
**Date:** 2026-10-30
**Status:** SPECIFICATION / PHASE 2

---

## 1. Objective and Core Directives

The objective of the EpistemicOS Evidence Architecture is to establish reproducible, commit-pinned, independently evaluable security claims across four distinct, uncollapsed layers. Rather than maximizing a single headline benchmark score, this architecture provides rigorous CI enforcement for security-invariant violations, dataset integrity, working-tree purity, and documented metric regressions.

---

## 2. Machine-Readable Status Semantics & CI Policy

All evaluation components, test harnesses, and evidence aggregators must emit explicit, standardized status codes defined centrally:

| Status Code | Definition | Security Implication | CI Workflow Enforcement |
|---|---|---|---|
| `PASS` | Security invariant holds, expected outcome observed, zero unmediated side effects. | Fully verified under tested conditions. | All CI jobs pass. |
| `FAIL` | Security invariant violated, unauthorized side effect executed, or regression threshold exceeded. | Critical security failure. | **Blocks all CI jobs** (PR CI and Release CI). |
| `PARTIAL` | Component-level defense succeeded, but end-to-end transitive enforcement is unintegrated (e.g. GAP-03). | Known architectural defense gap. | **Permitted on PR CI with warnings**, but **Blocks Release CI** (`--require-full-pass`). |
| `UNTESTED` | Test path or integration unavailable in current architecture. | Execution boundary not exercised. | Permitted on PR CI with warnings; **Blocks Release CI**. |
| `BLOCKED_BY_ARCHITECTURE` | Feature or path intentionally restricted or unsupported by system model. | Structural design constraint. | Documented constraint; requires explicit policy override. |
| `INCONCLUSIVE` | Trial produced ambiguous execution telemetry or stochastic variance without explicit outcome. | Requires further investigation. | Permitted on PR CI with warnings; **Blocks Release CI**. |

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
|  LAYER C: Deterministic Synthetic Adversarial Harness                              |
|  - Synthetic multi-step adversarial harness (benchmarks/run_live_agent_redteam.py)  |
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
  - Direct assertions on security invariants.
  - Explicit machine-readable assertion outputs.

### Layer B: Actual Execution-Boundary Integration
- **Purpose:** Demonstrate that security controls govern real protected operations through the core orchestrator and trusted execution boundary.
- **Scope:** 7 Incident Lab real-world scenarios (`Case1GitHub` through `Case7Fleet`).
- **Requirements:**
  - Execute through `EpistemicOrchestrator` and `TrustedExecutionBoundary`.
  - Obtain authorization strictly through server-controlled issuance paths; **zero manually seeded `AUTHORIZATION_GRANTED` events**.
  - Measure governance decision, boundary admission, callback invocation, task completion, and audit evidence independently.
  - Distinguish component-level gating from end-to-end containment (`PARTIAL` status for GAP-03/GAP-04).

### Layer C: Deterministic Synthetic Adversarial Harness
- **Purpose:** Evaluate synthetic multi-step adversarial vectors against isolated local targets.
- **Scope:** Multi-turn adversarial prompt injections, indirect egress attempts, credential misuse vectors, and multi-agent cascades (`benchmarks/run_live_agent_redteam.py`).
- **Requirements:**
  - Strictly isolated synthetic local resources (local mock webhooks, mock DBs, synthetic credentials).
  - **Zero external network access** or real credentials.
  - Record orchestrator decision, actual boundary admission, callback invocation, and observed side effects separately per trial.

### Layer D: Performance & Cost Benchmarks
- **Purpose:** Quantify operational overhead, latency, token consumption, and statistical reliability of security controls.
- **Scope:** N=100 stratified held-out benchmark dataset (`benchmarks/run_full_benchmark.py`).
- **Requirements:**
  - Measure Latency (P50, P95, Mean), Token Consumption, Accuracy, Precision, Recall, FPR, FNR, Wilson 95% Confidence Intervals, and McNemar paired statistical comparisons.
  - Keep performance scoring strictly separated from binary Layer A/B security invariant checks.

---

## 4. Evidence Reporting & CI Integration

The evidence pipeline aggregates all four layers into a single canonical artifact: `results/four_layer_evidence.json` and human-readable `docs/security/four_layer_evidence_report.md`.

### Environmental & Reproducibility Metadata Requirements
Every generated evidence artifact records:
1. `evaluated_git_commit`: Full 40-character Git SHA actually executed during evaluation.
2. `report_persistence_commit`: Later commit hash where report files were stored/committed.
3. `working_tree_status`: Pre-run working tree status (`CLEAN` or `DIRTY`).
4. `working_tree_digest`: SHA-256 digest covering tracked and untracked source inputs prior to report generation.
5. `evaluation_command`: Exact CLI invocation string.
6. `execution_environment_type`: `CI` vs `LOCAL` execution tag.
7. `python_version` & `operating_system`: Runtime host platform details.
8. `lockfile_sha256_digest`: SHA-256 digest of `requirements-full-lock.txt` / `requirements-test-lock.txt`.
9. `dataset_sha256_digest`: SHA-256 digest of `benchmarks/data/eval_set.jsonl` verified against trusted base ref.
10. `exit_code` & `exit_status`: Explicit process exit code (`0` for `SUCCESS`), reported separately from scenario pass rates.
11. `report_artifact_sha256`: SHA-256 digest of the final generated report artifact itself.

---

## 5. Commit-Pinned Reproduction & Bounded Security Claims

### Exact Reproduction Procedure
To independently reproduce security evidence against an explicit Git commit SHA:

```bash
# 1. Fetch and check out the target commit in a clean worktree
git checkout <TARGET_40_CHAR_COMMIT_SHA>
git status --porcelain -uall  # Must be clean!

# 2. Run consolidated evidence evaluation with commit pinning and clean-tree assertion
python3 -m benchmarks.generate_evidence_report --commit <TARGET_40_CHAR_COMMIT_SHA> --require-clean

# 3. Validate generated evidence artifact against cryptographic baseline and schema
python3 -m benchmarks.validate_evidence \
  --artifact results/four_layer_evidence.json \
  --expected-commit <TARGET_40_CHAR_COMMIT_SHA> \
  --require-clean-tree
```

### Separating Evaluated Source Revision from Report Persistence Revision
Generating evidence report files (`results/four_layer_evidence.json`, `docs/security/four_layer_evidence_report.md`) creates or modifies files in the working directory. To prevent contaminating the clean-tree assertion:

1. **Pre-Run Snapshot:** The evaluation harness records `evaluated_git_commit`, `working_tree_status`, and `working_tree_digest` *before* generating report outputs.
2. **Output Isolation:** Evaluation runners support `--output-dir <DIR>` to write report files into a separate location outside the evaluated source tree.
3. **Commit Distinction:** Reports record `evaluated_git_commit` (source revision evaluated) separately from `report_persistence_commit` (the later commit containing the committed report artifact).

### Relationship Between Local Persisted Reports and CI Artifacts
- **Locally Persisted Reports:** Local evaluation runs generate reports tagged with `execution_environment_type: "LOCAL"`. If uncommitted changes exist, the report records `working_tree_status: "DIRTY"` and refuses to claim clean reproducibility.
- **CI Artifacts:** GitHub Actions CI workflows run against a checked-out commit with `execution_environment_type: "CI"`. CI runs generate clean-tree verified evidence artifacts published as workflow build artifacts (`telemetry-results-3.11`).
- **Non-Equivalence:** Local report execution verifies control plane logic in a developer sandbox; it does not replace or stand in for independent CI verification.

### Bounded Security Claims (Non-Claims & Threat Model Boundaries)

**What Evidence Establishes:**
- Under the specific 7 Incident Lab scenarios, 5 synthetic adversarial vectors, and N=100 benchmark dataset, EpistemicOS control plane mechanics (`PermissionGate`, `EntropyGate`, `ShowerCurtainGate`, `TrustedExecutionBoundary`, `ContainmentGuard`) enforce the specified security invariants.
- Execution boundary calls strictly require single-use capability tokens bound to explicit `(operation, resource)` targets.
- Gating decisions and provenance events are recorded in tamper-evident audit logs.

**What Evidence Does NOT Establish:**
- Evidence does **NOT** prove resistance to arbitrary zero-day exploit primitives or unmodeled attack vectors.
- Evidence does **NOT** prove process isolation against a compromised Python host runtime or arbitrary code execution within the same process.
- Evidence does **NOT** replace operating system or hypervisor microVM sandboxing.
- Evidence does **NOT** guarantee 100% security recall on unobserved, real-world distribution shifts outside the tested benchmark suite.
