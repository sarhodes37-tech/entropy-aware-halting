# EpistemicOS: Deterministic Halting & Security Middleware for LLMs

EpistemicOS is an experimental low-latency security middleware designed to enforce deterministic halting, authorization policies, privacy controls, and execution governance for Large Language Model (LLM) workflows. It intercepts structural collapse, N-gram loops, epistemic hallucinations, unauthorized tool-calling vectors, and sensitive data leakage prior to execution within configured control plane boundaries.

---

## 🏛 System Architecture & Control Plane Implementation

### Control Plane Architecture Diagram

![EpistemicOS Control Plane Architecture](docs/figures/control_plane.svg)

*Figure 1 — EpistemicOS Control Plane Architecture: Workloads route through ordered governance gates before reaching the trusted execution boundary. Any gate violation triggers an immediate fail-closed halt, revokes execution vectors, and commits an audit receipt to the tamper-evident hash chain.*

---

### Shower Curtain Privacy Architecture

![Shower Curtain Privacy Boundary](docs/figures/shower_curtain_boundary.svg)

*Figure 2 — Shower Curtain Privacy Boundary: Local data sanitization, session-scoped pseudonym mapping, egress fail-closed policy enforcement, and inbound response inspection.*

The **Shower Curtain** subsystem forms a local-first privacy boundary mediating interaction between client applications and external inference providers:

* **Local Trust Boundary:** Sensitive PII, financial data, and authentication credentials remain within the local client perimeter.
* **Multi-Stage Processing:** Ingress workloads pass through deterministic detection (Stage A), classification and policy evaluation (Stage B), local pseudonym mapping (Stage C), context minimization (Stage D), and serialized egress gate inspection (Stage E).
* **Session Pseudonyms & Zero Credential Leakage:** Reversible pseudonyms replace identifiable entities within isolated session scopes. Credentials and secrets are strictly redacted or blocked and cannot be rehydrated inbound.
* **Fail-Closed Egress Enforcement:** Egress payloads are serialized and inspected prior to provider transmission. Unsanitized sensitive data or policy violations trigger immediate execution halts.

For detailed architecture specifications and security guarantees, see [`docs/SHOWER_CURTAIN_ARCHITECTURE.md`](docs/SHOWER_CURTAIN_ARCHITECTURE.md).

---

### EpistemicOS Observatory Control Room

![EpistemicOS Observatory Interface](docs/figures/observatory-concept.png)

*Figure 3 — EpistemicOS Observatory Control Room: Real-time telemetry monitoring, audit verification, and execution trace exploration interface. Depicted metrics, timestamps, and benchmark results are an illustrative design concept and do not represent live system telemetry.*

---

## 🔒 Control Plane Mechanics & Architectural Invariants

### Architectural Responsibility Separation

EpistemicOS strictly decouples three distinct control-plane responsibilities:

1. **Reasoning & Halting (`EntropyGate` / `EntropyAwareScheduler`):** Estimates token surprisal ($h = -\log p$) and semantic uncertainty to determine whether further model computation is useful or collapsing into repetitive/hallucinatory states. *Halting evaluates computational utility; it never grants authorization.*
2. **Policy & Authorization Gate (`PermissionGate`):** Enforces static and dynamic authorization contracts. Verifies that requested tool operations (`op`) and resource targets (`node`/`endpoint`) match authenticated trusted scopes (`trusted_scope`). *Authorization evaluates policy compliance; high model confidence or utility cannot override an authorization failure.*
3. **Execution Enforcement (`TrustedExecutionBoundary` & `ContainmentGuard`):** Mediates actual operation dispatching. `TrustedExecutionBoundary` enforces explicit authorization tokens (`authorization_granted=True`), single-use token consumption, and callback verification, while `ContainmentGuard` inspects shell commands and outbound network URIs against restricted patterns. *Enforcement ensures that denied requests cannot trigger side effects.*

### Fail-Closed Handling & Exception Policy

* **Ordered Fail-Closed Gates:** Gates evaluate sequentially (`ShowerCurtainGate` $\rightarrow$ `EntropyGate` $\rightarrow$ `PermissionGate` $\rightarrow$ `TriangulationGate`). The first gate that returns `GateDecision.HALT` or `GateDecision.DENY` immediately halts the pipeline without evaluating remaining gates.
* **Malformed Inputs & Exceptions:** If a payload lacks required action contract attributes (such as missing `op` or `endpoint`), or if a gate encounters an unhandled exception, `EpistemicOrchestrator` catches the error and defaults to `GateDecision.HALT` with a reason code describing the failure.
* **Audit & Receipt Binding:** Every gate outcome—whether allowed or halted—is cryptographically bound to the input hash and recorded in `TamperEvidentAuditTrail` via a SHA-256 entry hash chain. Receipt minting uses SHA-256 digests by default, or symmetric HMAC-SHA256 signatures when configured with a trusted secret key.

### Core Architectural Invariants

The control plane is designed around five core invariants:

1. **Authorization Non-Overridability:** High information utility, low token surprisal, or high LLM confidence cannot override a `PermissionGate` denial. Authorization is a non-compensatory constraint.
2. **No Unsanitized Alternative Execution Paths:** Within the orchestrator pipeline, execution callbacks (`actual_executable`) are mediated through `TrustedExecutionBoundary.execute_protected_action()`. Direct invocation or unauthenticated fallback routes are rejected.
3. **Action-Resource Binding:** Authorization is granted specifically to a `(operation, resource)` tuple extracted via `_extract_action_details()`. Granting permission for an operation on resource $A$ does not grant permission for the same operation on resource $B$.
4. **Execution Prevention on Denial:** A gate denial immediately halts pipeline execution. Gate outcomes are enforced prior to execution, not merely logged post-hoc.
5. **Accurate Outcome Reporting:** Final pipeline status reporting reflects actual execution outcomes. A session where execution was denied or halted will never return `ALLOWED` status.

### Tested vs. Unverified Properties & Security Limitations

* **Enforced & Verified in Code:** Test coverage in `tests/unit/test_gates.py`, `tests/unit/test_provenance.py`, and `tests/unit/test_permission_gate_regression.py` confirms fail-closed behavior on missing fields, single-use token consumption, strict scope matching, and execution suppression upon gate denial.
* **Limitations & Unverified Assumptions:**
  * *Application-Level vs. OS Sandbox:* `ContainmentGuard` provides application-level regex parameter inspection for shell commands and network URIs; it does not replace operating system or kernel-level hardware sandbox isolation.
  * *Audit Chain Tamper Detection:* `TamperEvidentAuditTrail` detects log insertion, deletion, or modification at read time via hash chain verification, but does not prevent root-level host file deletion unless backed by external write-once storage (WORM).
  * *Synthetic Benchmark Generalization:* Evaluated performance on `benchmarks/data/eval_set.jsonl` demonstrates control-plane logic correctness under fixed test scenarios, but does not substitute for production threat modeling across arbitrary real-world LLM workloads.

---

## 🛠 Authorization Scope & Resource Extraction Refinement

### Defect Analysis & Research Impact

An audit identified an issue in authorization resource resolution where nested action structures (such as API call payloads with embedded endpoints) were unparsed during resource scope checks. Valid nested tool calls failed resource matching and were falsely halted as unauthorized actions.

On the $N = 100$ benchmark evaluation dataset, this defect caused **35 benign control cases** (20 in *Commercial Underwriting & Operations* and 15 in *High-Noise Benign Controls*) to be incorrectly halted, yielding a **35.0% false positive rate (FPR)** and reducing Combined Gating accuracy to **65.0%**.

### Technical Resolution & Benchmark Restoration

Resource extraction in `PermissionGate` was refined to evaluate resource targets consistently across top-level, nested, and object-wrapped action representations without altering security contracts.

Following this refinement:
* All 35 false-positive halts on benign workloads were eliminated (**0.0% Benign FPR**).
* Combined Gating accuracy was restored to **100.0%** across the $N=100$ evaluation set.
* Strict fail-closed defense against unauthorized operations, missing parameters, and malformed actions was preserved.

Detailed root-cause analysis, internal code paths, and regression test suite specifications are documented in [`docs/audit_guarantees.md`](docs/audit_guarantees.md) and verified in [`tests/unit/test_permission_gate_regression.py`](tests/unit/test_permission_gate_regression.py).

---

## 📊 Measured Benchmark Results

The benchmark suite evaluates EpistemicOS on a stratified held-out evaluation dataset ($N = 100$) across 6 baseline conditions. Benchmark metrics reflect actual measured predictions and outcomes.

### Benchmark Ground-Truth & Metric Definitions

* **Evaluated Dataset:** $N = 100$ stratified cases (`benchmarks/data/eval_set.jsonl`).
  * **Ground-Truth Positive Class (Adversarial / Malicious / Unauthorized):** 65 cases expecting `ROLLBACK` (or `HALT`).
  * **Ground-Truth Negative Class (Benign Controls / Authorized Operations):** 35 cases expecting `COMMIT` (or `ALLOW`).
* **Positive Prediction:** System produces a `ROLLBACK` / `HALT` decision (intercepting execution).
* **Negative Prediction:** System produces a `COMMIT` / `ALLOW` decision (permitting execution).
* **Metric Formulations:**
  * **Accuracy:** $\frac{\mathrm{TC} + \mathrm{TR}}{N}$ where $\mathrm{TC}$ = True Commit (Benign Allowed) and $\mathrm{TR}$ = True Rollback (Adversarial Halted).
  * **Precision:** $\frac{\mathrm{TR}}{\mathrm{TR} + \mathrm{FR}}$ (Percentage of halted cases that were truly adversarial).
  * **Recall (Adversarial Recall):** $\frac{\mathrm{TR}}{\mathrm{TR} + \mathrm{FC}}$ (Percentage of adversarial cases correctly halted).
  * **Specificity:** $\frac{\mathrm{TC}}{\mathrm{TC} + \mathrm{FR}}$ (Percentage of benign cases correctly allowed).
  * **Benign False Positive Rate (FPR):** $\frac{\mathrm{FR}}{\mathrm{TC} + \mathrm{FR}}$ (Percentage of benign cases incorrectly blocked).
  * **Security False Negative Rate (FNR):** $\frac{\mathrm{FC}}{\mathrm{TR} + \mathrm{FC}}$ (Percentage of adversarial cases incorrectly permitted).
  * **Confidence Intervals:** Computed using Wilson score interval at 95% confidence level ($z = 1.96$).
  * **Undefined Metrics:** Indicated as `N/A` when the denominator is zero (e.g., Precision when 0 cases are halted).

---

### Primary Verified Post-Fix N = 100 Benchmark Results

*Source Artifact:* `results/ablation_table.json` | *Generated via:* `python3 -m benchmarks.run_full_benchmark`

| Baseline Condition | Sample Count | Accuracy (95% CI) | Precision | Recall | Specificity | False Positives (Benign Blocked) | False Negatives (Security Bypass) | Avg Latency (ms) | Total Tokens |
|---|---|---|---|---|---|---|---|---|---|
| **Ungated Generation** | 100 | 35.0% [26.36%, 44.75%] | N/A | 0.0% | 100.0% | 0 | 65 | 4.23 ms | 2000 |
| **Entropy-Only Gating** | 100 | 90.0% [82.56%, 94.48%] | 100.0% | 84.62% | 100.0% | 0 | 10 | 9.09 ms | 2000 |
| **Permission-Only Gating** | 100 | 71.0% [61.46%, 78.99%] | 100.0% | 55.38% | 100.0% | 0 | 29 | 13.31 ms | 2000 |
| **Combined Gating** | 100 | **100.0%** [96.30%, 100.0%] | **100.0%** | **100.0%** | **100.0%** | **0** | **0** | **18.06 ms** | **2000** |
| **Active Execution-Gated Recovery** | 100 | 71.0% [61.46%, 78.99%] | 100.0% | 55.38% | 100.0% | 0 | 29 | 49.31 ms | 4020 |
| **Compute-Matched Baseline** | 100 | 35.0% [26.36%, 44.75%] | N/A | 0.0% | 100.0% | 0 | 65 | 105.12 ms | 6000 |

---

### Scenario Family Breakdown (Combined Gating, Post-Fix N = 100)

| Scenario Family | Ground-Truth Cases | Accuracy (%) | Adversarial Recall (%) | Benign FPR (%) | Interception Vector |
|---|---|---|---|---|---|
| **Commercial Underwriting & Operations** | 20 (Benign) | 100.0% | N/A | 0.0% | Valid nested endpoint scope matched |
| **Cyber, Shell & DB Threat Vectors** | 15 (Adversarial) | 100.0% | 100.0% | N/A | Intercepted by `PermissionGate` |
| **Multi-Turn & Obfuscated Prompt Injections** | 15 (Adversarial) | 100.0% | 100.0% | N/A | Intercepted by `EntropyGate` & `PermissionGate` |
| **Impossible Paradoxes & Introspection** | 15 (Adversarial) | 100.0% | 100.0% | N/A | Intercepted by `EntropyGate` (High surprisal) |
| **High-Noise Benign Controls** | 15 (Benign) | 100.0% | N/A | 0.0% | Valid scope & low surprisal passed |
| **Unauthorized Operations & Boundary Failures** | 10 (Adversarial) | 100.0% | 100.0% | N/A | Intercepted by `PermissionGate` |
| **Gate Exceptions & Edge Cases** | 10 (Adversarial) | 100.0% | 100.0% | N/A | Fail-closed on malformed contract |

---

### Paired Inferential Comparisons (McNemar's Test)

Paired case-level McNemar test with continuity correction ($N=100$ paired observations):

| Comparison | Discordant A+/B- | Discordant A-/B+ | $\chi^2$ Statistic | $p$-value | Statistical Significance ($\alpha=0.05$) |
|---|---|---|---|---|---|
| **Combined Gating vs. Ungated Generation** | 65 | 0 | 63.02 | $< 0.0001$ | **Statistically Significant** |
| **Combined Gating vs. Compute-Matched Baseline** | 65 | 0 | 63.02 | $< 0.0001$ | **Statistically Significant** |
| **Entropy-Only Gating vs. Ungated Generation** | 55 | 0 | 53.02 | $< 0.0001$ | **Statistically Significant** |
| **Permission-Only Gating vs. Ungated Generation** | 36 | 0 | 34.03 | $< 0.0001$ | **Statistically Significant** |
| **Combined Gating vs. Active Recovery** | 29 | 0 | 27.03 | $< 0.0001$ | **Statistically Significant** |

---

### Historical Pre-Fix N = 100 Baseline Results (PermissionGate Defect)

To document the impact of the `PermissionGate` nested-resource extraction fix, the pre-fix benchmark figures are preserved below. In the pre-fix state, nested endpoint structures in benign cases were unparsed, triggering false resource denials.

| Baseline Condition | Sample Count | Accuracy (95% CI) | Precision | Recall | False Positives (Benign Blocked) | False Negatives (Security Bypass) | Primary Failure Cause |
|---|---|---|---|---|---|---|---|
| **Ungated Generation** | 100 | 35.0% [26.36%, 44.75%] | N/A | 0.0% | 0 | 65 | No security gates |
| **Entropy-Only Gating** | 100 | 90.0% [82.56%, 94.48%] | 100.0% | 84.62% | 0 | 10 | Misses static authorization rules |
| **Permission-Only (Pre-Fix)** | 100 | 50.0% [40.38%, 59.62%] | 58.82% | 76.92% | **35** | 15 | **Nested endpoint unparsed (Bug)** |
| **Combined Gating (Pre-Fix)** | 100 | 65.0% [55.25%, 73.64%] | 65.00% | 100.0% | **35** | 0 | **Nested endpoint unparsed (Bug)** |
| **Compute-Matched Baseline** | 100 | 35.0% [26.36%, 44.75%] | N/A | 0.0% | 0 | 65 | Pure compute without gating |

---

### Benchmark Interpretation & Key Findings

1. **Orthogonal Security Coverage:** `EntropyGate` and `PermissionGate` address complementary threat vectors. `EntropyGate` intercepts hallucinatory collapse, prompt injections, and introspective paradoxes (84.62% recall independently), while `PermissionGate` blocks explicit unauthorized tool calls and shell vectors (55.38% recall independently).
2. **Combined Defense Synergies:** Combined Gating achieves 100.0% accuracy across the evaluated $N=100$ benchmark dataset (`benchmarks/data/eval_set.jsonl`) because every adversarial vector in the evaluation set is intercepted by at least one gate, while benign requests satisfy both scope and surprisal criteria. This result is explicitly scoped to the current evaluation dataset and does not represent universal security or 100% interception on arbitrary, unseen real-world LLM workloads.
3. **Compute Matching vs. Security Gating:** Allocating additional retry compute without governance gates (`Compute-Matched Baseline`, 6000 tokens) provides 0.0% security improvement over single-pass ungated generation, proving that safety requires deterministic middleware filtering rather than sampling budget.

---

### Benchmark Reproducibility & Commands

To independently run the benchmark runner and regenerate all machine-readable artifacts:

```bash
# 1. Execute full benchmark suite
python3 -m benchmarks.run_full_benchmark

# 2. Inspect generated output files
cat results/ablation_summary.md
cat results/ablation_table.json
```

---

## 🚀 Quickstart & Requirements

### Package Requirements
* **Python 3.10+**
* **Core Dependencies:** `pydantic>=2.0.0`
* **Optional Extras:** `.[ml,test]` for PyTorch, Transformers, and Pytest harnesses.

### Installation

```bash
git clone https://github.com/sarhodes37-tech/entropy-aware-halting.git
cd entropy-aware-halting
pip install -e .[test]
```

---

## 🧪 Verified Execution & Verification Commands

### Run Unit & Integration Test Suite

```bash
pytest tests/
```

---

## 🔒 Security Hardening & Trust Boundaries

### Fail-Safe Model Loading Defaults
EpistemicOS enforces `trust_remote_code=False` by default across both `epistemicos.utils.get_model_and_tokenizer` and `epistemicos.get_model_and_tokenizer`. Custom remote code execution requires explicit opt-in (`trust_remote_code=True`).

### Trusted Authorization Scope Boundary
`PermissionGate` strictly isolates authorization scope resolution. Request-supplied or agent-controlled `scope` parameters in unauthenticated payloads are never treated as authoritative permissions. Authoritative scope must be injected via trusted gate configuration or authenticated context (`trusted_scope`).

### Tamper-Evident Audit Trail
All intercepted violations and sanitization events are logged cryptographically via SHA-256 chained entry hashes. PII and credentials are sanitized before log entry emission.
