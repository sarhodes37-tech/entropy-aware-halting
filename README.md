# EpistemicOS: Deterministic Halting & Security Middleware for LLMs

EpistemicOS is a low-latency security middleware designed to enforce deterministic halting, privacy invariants, and strict sandbox boundaries on Large Language Model (LLM) outputs. It intercepts structural collapse, N-gram loops, epistemic hallucinations, unauthorized tool-calling vectors, and sensitive data leakage before execution.

---

## 🏛 System Architecture & Trust Boundaries

### Control Plane Architecture

![EpistemicOS Control Plane Architecture](docs/figures/control_plane.svg)

*Figure A — EpistemicOS Control Plane: Input validation and CPR normalization route through ordered, fail-closed governance gates (Shower Curtain, Entropy-Aware Halting, and Permission Gate) before decision emission. Any gate violation halts execution, revokes active vectors, and logs a tamper-evident audit receipt.*

### Shower Curtain Privacy Boundary

![Shower Curtain Privacy Boundary](docs/figures/shower_curtain_boundary.svg)

*Figure B — Shower Curtain Privacy Boundary: Local context minimization, sensitive data detection, policy evaluation, and session pseudonym mapping ensure sensitive data never leaves the local boundary. Remote model responses undergo leak inspection before exact authorized session rehydration.*

---

## 📊 Measured Benchmark Results

The benchmark suite evaluates EpistemicOS on a held-out dataset across 6 baseline conditions. Benchmark metrics reflect actual measured predictions and outcomes rather than unit test pass statuses.

### Baseline Comparison (N = 10 Held-Out Evaluation Samples)

| Baseline Condition | Sample Count | Accuracy (95% CI) | False Positives (Benign Blocked) | False Negatives (Security Bypass) | Avg Latency (ms) | Total Tokens |
|---|---|---|---|---|---|---|
| **Ungated Generation** | 10 | 40.0% [16.82%, 68.73%] | 0 | 6 | 10.51 ms | 200 |
| **Entropy-Only Gating** | 10 | 100.0% [72.25%, 100.0%] | 0 | 0 | 10.87 ms | 200 |
| **Permission-Only Gating** | 10 | 50.0% [23.66%, 76.34%] | 3 | 2 | 11.18 ms | 200 |
| **Combined Gating** | 10 | 70.0% [39.68%, 89.22%] | 3 | 0 | 11.53 ms | 200 |
| **Active Execution-Gated Recovery** | 10 | 50.0% [23.66%, 76.34%] | 3 | 2 | 31.65 ms | 520 |
| **Compute-Matched Baseline** | 10 | 40.0% [16.82%, 68.73%] | 0 | 6 | 39.64 ms | 600 |

*Note: Confidence intervals are calculated using the Wilson score interval at a 95% confidence level. Current benchmark results reflect a 10-sample exploratory evaluation set; larger production evaluations should be performed per application domain.*

---

## 🚀 Quickstart & Requirements

### Package Requirements
* **Python 3.10+**
* **Dependencies:** `pydantic>=2.0.0` (required core dependency for model validation). Optional extras available for ML and testing (`.[ml,test]`).

### Installation

```bash
git clone https://github.com/sarhodes37-tech/entropy-aware-halting.git
cd entropy-aware-halting
pip install -e .[test]
```

---

## 🧪 Verified Execution & Verification Commands

### Run Unit Tests
To run the full unit and integration test suite:

```bash
pytest tests/
```

### Run Empirical Benchmark Suite
To execute the measured benchmark runner and regenerate machine-readable reports (`results/ablation_table.json`, `results/per_case_results.json`, and `results/ablation_summary.md`):

```bash
python3 -m benchmarks.run_full_benchmark
```

---

## 🔒 Security Hardening & Trust Boundaries

### Fail-Safe Model Loading Defaults
EpistemicOS enforces `trust_remote_code=False` by default across both `epistemicos.utils.get_model_and_tokenizer` and `epistemicos.get_model_and_tokenizer`. Custom remote code execution requires explicit opt-in (`trust_remote_code=True`).

### Trusted Authorization Scope Boundary
`PermissionGate` strictly isolates authorization scope resolution. Request-supplied or agent-controlled `scope` parameters in unauthenticated payloads are never treated as authoritative permissions. Authoritative scope must be injected via trusted gate configuration or authenticated context (`trusted_scope`).

### Tamper-Evident Audit Trail
All intercepted violations and sanitization events are logged cryptographically via SHA-256 chained entry hashes. PII and credentials are sanitized before log entry emission.
