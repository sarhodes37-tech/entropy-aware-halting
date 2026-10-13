# Preregistration Protocol: Held-Out Evaluation of Semantic Uncertainty for Adaptive Halting

**Version:** 1.0.0
**Date:** March 2026
**Status:** FROZEN BEFORE HELD-OUT RUN
**Target Domain:** Multi-Step Reasoning Trajectories with Meaning-Level Conclusion Clustered Signals

---

## 1. Objective & Research Questions

This experimental research protocol evaluates whether incorporating semantic uncertainty ($H_{\text{sem}}$) provides incremental halting value beyond next-token entropy ($H_{\text{token}}$) on multi-step reasoning trajectories.

### Primary Research Question
Does incorporating semantic uncertainty improve decision quality at comparable compute cost relative to token-entropy-only halting and baseline policies on held-out multi-step reasoning trajectories?

### Secondary Research Questions
1. How do candidate-level semantic cluster probabilities and token entropy signals behave across specific reasoning stress-test families?
2. What is the compute and latency overhead incurred by semantic resolution, and does its quality benefit exceed this cost?
3. How frequently do missing, invalid, or ambiguous semantic resolver outcomes occur, and how do policies handle them?

---

## 2. Hypotheses

- **$H_1$ (Primary):** Combined policy ($H_{\text{token}} + H_{\text{sem}}$) achieves higher decision quality than $H_{\text{token}}$-only halting at equivalent or lower compute budget on held-out multi-step trajectories.
- **$H_2$ (Paraphrase Invariance):** In scenarios with high syntactic variation but semantic consensus, $H_{\text{sem}}$ halting prevents premature halting or unnecessary continuation caused by token-entropy inflation.
- **$H_3$ (Confident Shared Error Limitation):** In scenarios where multiple generated reasoning steps converge on the same incorrect conclusion (confident shared error), $H_{\text{sem}}$ alone will exhibit low uncertainty and fail to halt early unless combined with step or budget bounds.

---

## 3. Scenario Construction & Split Integrity

The dataset consists of multi-step reasoning trajectories grouped into 6 preregistered stress-test families ($A$ through $F$).

### Scenario Families
- **Family A: Confident Shared Error** — Multiple candidate continuations converge on the same incorrect conclusion. (Measures whether low $H_{\text{sem}}$ is improperly treated as factual correctness).
- **Family B: Useful Uncertainty Increase** — New evidence introduces a relevant hypothesis/distinction, legitimately increasing semantic uncertainty. (Measures whether policy permits necessary exploration rather than halting on entropy spikes).
- **Family C: Semantic Stagnation** — Repeated reasoning steps rephrase existing points without adding new claims or distinctions. (Measures ability to halt unnecessary continuation).
- **Family D: Genuine Evidence Accumulation** — Independent, verifiable evidence updates shift cluster support toward the correct hypothesis. (Measures recognition of genuine convergence).
- **Family E: Decision-Sensitive Disagreement** — Candidates disagree on conclusions that alter downstream execution actions (`ALLOW`, `DENY`, `HALT`, `ROLLBACK`).
- **Family F: Resolver Ambiguity & Insufficient Evidence** — Semantic comparisons cannot be resolved with high confidence, or trajectory lacks sufficient candidates.

### Split Methodology (Leakage Prevention)
- **Split Unit:** Whole scenario family / problem domain. Splitting is strictly performed at the scenario family level, **never** randomly by individual paraphrase or trajectory instance.
- **Development Split (`dev`):** Used strictly for harness debugging, telemetry verification, and policy threshold calibration.
- **Held-Out Split (`test`):** Frozen and evaluated exactly once using pre-calibrated thresholds.

---

## 4. Evaluation Conditions (Policies)

1. **Condition 1: Fixed-Budget Baseline (`FixedBudgetPolicy`)**
   - Continues reasoning until a predefined maximum step or token compute budget $B_{\max}$ is reached.
2. **Condition 2: Token-Entropy Halting (`TokenEntropyHaltingPolicy`)**
   - Halts when token entropy $H_{\text{token}} < \theta_{\text{token}}$ or when token entropy delta stagnates ($\Delta H_{\text{token}} < \epsilon$).
3. **Condition 3: Semantic-Uncertainty Halting (`SemanticUncertaintyHaltingPolicy`)**
   - Halts when normalized semantic entropy $\bar{H}_{\text{sem}} < \theta_{\text{sem}}$ or when semantic disagreement $\le \delta_{\text{sem}}$.
4. **Condition 4: Combined Policy (`CombinedEntropyHaltingPolicy`)**
   - Halts when either $(H_{\text{token}} < \theta_{\text{token}} \land \bar{H}_{\text{sem}} < \theta_{\text{sem}})$ or decision-sensitive disagreement $= 0$ after $k \ge 2$ steps.
5. **Condition 5: Reference Scheduler Policy (`ReferenceSchedulerPolicy`)**
   - The default production `EntropyAwareScheduler` running strictly on token probabilities and utility yield.

---

## 5. Compute Matching Procedure

To ensure fair comparison, policies are evaluated under matched total compute accounting:
- **Compute Metrics Tracked:**
  - Total tokens generated ($T_{\text{gen}}$)
  - Reasoning steps taken ($N_{\text{steps}}$)
  - Semantic resolver calls ($N_{\text{resolver}}$)
  - Semantic resolution compute overhead ($C_{\text{resolver}}$)
  - Total cost $C_{\text{total}} = C_{\text{gen}} + C_{\text{resolver}}$
- **Compute Matching Method:**
  - Standardized unit costs: 1 token = 1.0 compute unit; 1 candidate pairwise resolution = 0.5 compute units.
  - Policies are evaluated across varying budget limits to construct **Decision Quality vs. Compute Cost Curves**.

---

## 6. Threshold Selection Procedure

- Policy thresholds ($\theta_{\text{token}}, \theta_{\text{sem}}, \epsilon$) are tuned using grid search **only** on the Development Split (`dev`).
- Once selected, thresholds are frozen in configuration before running the Held-Out Split (`test`).
- No held-out test data may be used to adjust policy parameters.

---

## 7. Statistical Unit, Analysis, and Uncertainty Intervals

- **Primary Statistical Unit:** Independent Scenario Family ($F_j$).
- **Primary Metrics:**
  - **Decision Quality Score ($Q \in [0, 1]$):** Scenario-specific ground truth accuracy / correctness of final chosen action.
  - **Premature Halting Rate ($R_{\text{premature}}$):** Halting before sufficient evidence accumulated.
  - **Unnecessary Continuation Rate ($R_{\text{unnecessary}}$):** Continuing execution after convergence reached.
- **Uncertainty Intervals:** 95% Confidence Intervals calculated via bootstrap resampling ($B=1000$) over scenario units.
- **Exclusion & Missing Data Criteria:**
  - Failed or malformed trajectories are recorded as failures ($Q=0$), not excluded.
  - Unresolved comparisons (`UNRESOLVED_COMPARISON`) or missing semantic estimates do **not** default to zero uncertainty or confident convergence.

---

## 8. Limitations and Criteria for Inconclusive Results

- **Probability Calibration Disclaimer:** Candidate cluster probabilities are conventional operational weights or sample frequencies, **not** calibrated model posterior beliefs.
- **Inconclusive Criteria:** If $95\%$ CIs for Decision Quality between Combined Policy and Token-Entropy Policy overlap significantly across held-out families, or if compute overhead of $H_{\text{sem}}$ eliminates any quality gain, the result shall be declared **inconclusive** or **null**.
