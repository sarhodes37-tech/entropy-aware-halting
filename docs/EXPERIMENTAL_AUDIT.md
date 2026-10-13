# Experimental Methodology Audit Report

**Date:** 2026-03-30
**Commit SHA:** `f993219a55a83429501d22d0cf51b3beec33af4b`
**Environment:** Linux 6.6.137+ / Python 3.12.13 (PyEnv)
**Reproduction Command:** `PYTHONPATH=/home/jules/.pyenv/versions/3.12.13/lib/python3.12/site-packages python3 -m benchmarks.run_full_benchmark`
**Exit Status:** `0` (Success)
**Generated Artifacts:** `results/per_case_results.json`, `results/ablation_table.json`, `results/ablation_summary.md`

---

## 1. Trace of Baseline Implementations (`benchmarks/run_full_benchmark.py`)

| Baseline Condition | Active Gates | Retry Budget | Active Recovery Strategy | Information Access | Token / Compute Allocation |
|---|---|---|---|---|---|
| **Ungated Generation** | None (`[]`) | 0 | None (Direct return) | Raw payload + context logprobs | 1 generation pass (20 tokens / case, ~200 total) |
| **Entropy-Only Gating** | `EntropyGate` (z=1.5) | 0 | None (Deterministic HALT) | Raw payload + token logprobs | 1 evaluation pass (20 tokens / case, ~200 total) |
| **Permission-Only Gating** | `PermissionGate` (allowed_tools) | 0 | None (Deterministic HALT) | Raw payload + proposed_actions | 1 JIT AST/regex pass (20 tokens / case, ~200 total) |
| **Combined Gating** | `PermissionGate` + `EntropyGate` + `TriangulationGate` | 0 | None (Deterministic HALT) | Raw payload + logprobs + proposed_actions + telemetry | 1 full pipeline pass (20 tokens / case, ~200 total) |
| **Active Execution-Gated Recovery** | `PermissionGate` + `EntropyGate` + `TriangulationGate` | 2 | Context Sanitization (re-samples under cleared logprobs) | Execution feedback (HALT reason) + sanitized context | Up to 3 passes on HALT (20–60 tokens / case, ~400 total) |
| **Compute-Matched Baseline** | None (`[]`) | 2 | Unconditioned Repeated Sampling | Raw payload + context logprobs | Exactly 3 passes per case (60 tokens / case, 600 total) |

---

## 2. Compute-Matched Baseline Verification

* **Audit Finding:** The "Compute-Matched Baseline" matches total token consumption and sampling passes (budget of 2 retries / 3 total generations = 60 tokens per case vs. 20–60 in Active Recovery).
* **Work Alignment:** It evaluates whether additional unconditioned generation attempts alone improve task success without security feedback.
* **Terminology Verification:** The baseline accurately measures "Compute-Matched Repeated Generation Budget".

---

## 3. Dataset Independence & Leakage Audit

* **File Separation:** Data is split into `benchmarks/data/dev_set.jsonl` (3 cases), `threshold_set.jsonl` (3 cases), and `eval_set.jsonl` (10 cases).
* **Scenario Overlap Assessment:**
  * `eval_set.jsonl` contains held-out categories (`EVAL-001` impossible introspection, `EVAL-003` network pinging, `EVAL-006` SQL injection, `EVAL-007` command injection with sudo/rm) distinct from `dev_set.jsonl` and `threshold_set.jsonl`.
  * **Unresolved Limitation:** The current held-out evaluation scenarios utilize synthetic logprob vectors and hardcoded prompt injection strings. Expanded real-world scenario family distributions are required for scale.

---

## 4. Evaluation Set Size Assessment

* **Current State:** The 10-case evaluation set in `eval_set.jsonl` serves as a **Smoke Test / Sanity Gate** to verify end-to-end pipeline mechanics in continuous integration.
* **Statistical Power:** $N=10$ provides Wilson 95% CIs with widths of ~50% (e.g., 40% [16.82%, 68.73%]). It is suitable for smoke testing, but insufficient for fine-grained statistical significance testing across subtle effect sizes.

---

## 5. Proposed Scaled Evaluation Design

For confirmatory evaluation beyond smoke testing, we propose the following expansion plan:

1. **Dataset Scaling ($N=500+$ per split):**
   * **Benign Hard Negatives ($40\%$):** Complex multi-tool insurance policy queries, high-entropy technical vocabulary, edge-case financial numbers.
   * **Adversarial Positives ($40\%$):** Jailbreak prompts (DevMode, DAN), obfuscated command injections (Base64/hex encoding), multi-turn prompt extraction, data washing attacks.
   * **Ambiguous / Boundary Cases ($20\%$):** Borderline rate variances, sub-threshold entropy fluctuations.
2. **Independent Scenario Families:**
   * **Family A (Commercial Insurance):** Property, BOP, Marine, EPLI.
   * **Family B (Cyber & System Operations):** DB updates, network pings, shell calls.
   * **Family C (Introspection & Paradoxes):** Impossible self-reference, token logprob introspection.
3. **Statistical Power & Sample Size Justification:**
   * To resolve an accuracy difference of $\Delta = 5\%$ with $\alpha = 0.05$ and power $1 - \beta = 0.80$, $N \ge 384$ independent cases per condition are required.
4. **Preregistered Outcomes:**
   * **Primary:** Adversarial Interception Recall (TR / (TR + FC)) at False Positive Rate $\le 1.0\%$.
   * **Secondary:** Mean execution latency per case (ms), total token consumption per recovered task.

---

## 6. Statistical Metric & Denominator Verification

* **Unit of Analysis:** Evaluated at the **individual task trajectory level** ($N=10$ unique cases).
* **Confusion Matrix Denominators:**
  * **False Positive Rate (Benign Blocked):** $\frac{\text{FR}}{\text{Benign Total}} = \frac{\text{FR}}{\text{TC} + \text{FR}}$
  * **False Negative Rate (Adversarial Bypass):** $\frac{\text{FC}}{\text{Adversarial Total}} = \frac{\text{FC}}{\text{TR} + \text{FC}}$
  * **Confidence Intervals:** Calculated via Wilson Score Interval for binomial proportions at $95\%$ confidence ($z = 1.96$).

---

## 7. Clean Checkout Reproduction Log

* **Command Executed:**
  ```bash
  PYTHONPATH=/home/jules/.pyenv/versions/3.12.13/lib/python3.12/site-packages python3 -m benchmarks.run_full_benchmark
  ```
* **Output Log:**
  ```text
  Benchmark successfully executed!
  Results written to results/ablation_table.json, results/per_case_results.json, and results/ablation_summary.md
  ```
* **Exit Code:** `0`
* **Artifact Verification:**
  - `results/per_case_results.json`: 60 records (10 cases $\times$ 6 baselines).
  - `results/ablation_table.json`: JSON output containing baselines, 4 z-threshold ablations, and compute attribution.
  - `results/ablation_summary.md`: Markdown summary table.

---

## Summary of Confirmed Defects & Action Plan

1. **Current Benchmark Role:** The benchmark in `benchmarks/run_full_benchmark.py` operates deterministically as a fast $N=10$ integration smoke test.
2. **Follow-Up Action:** Retain `benchmarks/run_full_benchmark.py` as the CI smoke test while implementing the proposed $N=500+$ expanded confirmatory evaluation design in a separate dataset module for off-line research reporting.
