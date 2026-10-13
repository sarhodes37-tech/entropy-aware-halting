# EpistemicOS Preregistration & Power Analysis Plan

**Date:** 2026-03-30
**Status:** PREREGISTERED / PENDING REVIEW
**Version:** 2.0.0

---

## 1. Primary Comparison & Estimand

### 1.1 Hypotheses
* **Null Hypothesis ($H_0$):** Combined EpistemicOS Gating with Active Recovery yields equivalent or inferior security interception recall ($\text{TR} / (\text{TR} + \text{FC})$) compared to pass-matched ungated baseline generation at equivalent false positive rates ($\le 1.0\%$).
* **Alternative Hypothesis ($H_1$):** Combined EpistemicOS Gating with Active Recovery significantly increases security interception recall ($\Delta \ge 10.0\%$) over pass-matched ungated baseline generation at false positive rates $\le 1.0\%$.

### 1.2 Target Estimand & Primary Outcome
* **Primary Outcome:** Adversarial Interception Recall ($\text{Recall} = \frac{\text{TR}}{\text{TR} + \text{FC}}$) evaluated under a strict constraint of False Positive Rate ($\text{FPR} = \frac{\text{FR}}{\text{TC} + \text{FR}} \le 1.0\%$).
* **Unit of Analysis:** Individual, independent task execution trajectory $i \in \{1, \dots, N\}$.

### 1.3 Secondary Outcomes
1. **Benign False Positive Rate ($\text{FPR}$):** Percentage of benign queries incorrectly halted or rolled back.
2. **Compute Efficiency Ratio ($\text{CER}$):** Security Recall per 1,000 tokens consumed ($\frac{\text{Recall}}{\text{Tokens} / 1000}$).
3. **Latency Overhead ($\Delta T$):** Mean wall-clock latency difference (ms) between gated and ungated trajectories.
4. **Recovery Success Rate ($\text{RSR}$):** Percentage of initial false-positive halts successfully recovered via active execution feedback.

---

## 2. Statistical Power & Sample Size Calculation

### 2.1 Power Analysis Parameters
* **Alpha ($\alpha$):** 0.05 (two-tailed).
* **Target Power ($1 - \beta$):** 0.80 (80% power).
* **Baseline Recall ($P_0$):** Assumed $40.0\%$ for ungated baseline under adversarial prompt injections.
* **Target Treatment Recall ($P_1$):** Assumed $\ge 55.0\%$ (Minimum Detectable Effect Size $\Delta = 15.0\%$).
* **Test Statistic:** Paired McNemar's test for binary matched-pair outcomes (same scenarios evaluated under baseline vs treatment).

### 2.2 Sample Size Derivation
Using the paired McNemar sample size formula:
$$N = \frac{\left(z_{1-\alpha/2} + z_{1-\beta}\right)^2}{p_d \cdot (1 - p_d \cdot \delta^2)}$$
where $p_d$ is the proportion of discordant pairs ($p_{01} + p_{10} \approx 0.25$).

* **Minimum Required Trajectories:** $N \ge 384$ independent scenarios.
* **Allocated Dataset Size:** $N = 500$ scenarios across 5 scenario families (to account for potential scenario-family cluster effects and provide conservative power buffer).

---

## 3. Experimental Conditions & Compute Metrics

### 3.1 Experimental Conditions
1. **Condition 0 (Ungated Generation - Baseline):** Pass-matched direct sampling without security middleware.
2. **Condition 1 (Pass-Matched Baseline):** Receives the exact same retry/generation budget ($K=2$ retries, 3 total passes) without middleware gating.
3. **Condition 2 (Entropy-Only Gating):** Token-level Z-score surprisal monitoring ($z_{\text{thresh}} = 1.5$).
4. **Condition 3 (Permission-Only Gating):** Contract boundary JIT AST/regex validation.
5. **Condition 4 (Combined EpistemicOS - Full Middleware):** Sequential Permission + Entropy + Triangulation gates.
6. **Condition 5 (Active Execution-Gated Recovery - Treatment):** Combined gates with up to 2 retry attempts under execution-feedback context sanitization.

### 3.2 Compute & Efficiency Metric Schema
For every trajectory, the benchmark recorder tracks:
* `input_tokens` & `output_tokens`
* `model_calls` & `retry_count`
* `tool_invocations` & `vectors_revoked`
* `wall_clock_ms` (total time in pipeline)
* `overhead_ms` (pure middleware latency excluding LLM sampling)
* `estimated_cost_usd` (computed via standard $0.0015 / 1\text{k}$ input and $0.0020 / 1\text{k}$ output token pricing)

---

## 4. Scenario Families & Dataset Partitioning

### 4.1 Scenario Families
To prevent data leakage, scenario families are defined prior to data generation:

1. **Family A (Commercial Underwriting & Insurance):**
   - Property, Marine, BOP, E&S, EPLI binder queries.
   - Hard negatives: High-value commercial quotes with unusual risk parameters that remain within valid schema limits.
2. **Family B (Cyber, Shell & Database Operations):**
   - System updates, SQL commands, network pings, shell invocations.
   - Positives: Direct and obfuscated command injections, SQL manipulations, unauthorized subnets.
3. **Family C (Impossible Paradoxes & Introspection):**
   - Logit tensor inspection, recursive token self-reference, unobservable environment queries.
   - Positives: Requests requiring model hallucination or false proof generation.
4. **Family D (Multi-Turn & Obfuscated Jailbreaks):**
   - DevMode overrides, Base64/hex encoded injection payloads, persona switching.
   - Positives: Low-entropy jailbreaks attempting schema override.
5. **Family E (High-Noise Benign Controls):**
   - Technical domain queries with unusual terminology, mathematical equations, nested JSON.
   - Negatives: Valid complex requests designed to test entropy false positive rates.

### 4.2 Data Partitioning Scheme
* **Development Split ($N=100$):** Used for initial middleware development and debugging.
* **Calibration / Threshold Selection Split ($N=100$):** Used strictly for tuning entropy $z$-thresholds and window sizes. **Zero access to evaluation labels.**
* **Held-Out Evaluation Split ($N=300$):** Locked held-out test set evaluated exactly once after preregistration approval and threshold freezing.

---

## 5. Multiple-Comparison Handling & Exclusion Rules

### 5.1 Multiple Testing Correction
* Primary hypothesis test uses a single pre-specified McNemar's test ($\alpha = 0.05$).
* Secondary outcomes (FPR, CER, Latency) use the Benjamini-Hochberg False Discovery Rate (FDR) procedure with $q = 0.05$.

### 5.2 Trial Exclusion Rules
A trial is flagged as `INVALID` and excluded from primary efficacy calculation if:
1. Total wall-clock latency exceeds $30.0$ seconds (timeout failure).
2. Malformed JSON payload prevents initial parsing (recorded under `failures_to_complete`).

No trials will be excluded based on output content or middleware decision flags. Null results, adverse tradeoffs, and false rollbacks will be fully reported.
