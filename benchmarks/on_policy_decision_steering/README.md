# On-Policy Decision Steering Benchmark Harness (Phase 1A)

**Module Location:** `benchmarks/on_policy_decision_steering/`
**Specification Version:** `3.0.0`
**Status:** PHASE 1A ISOLATED SYNTHETIC EVALUATION HARNESS

---

## 1. Overview & Purpose

This package implements Phase 1A of the EpistemicOS **On-Policy Decision Steering** research specification. The harness provides an isolated, reproducible experimental instrument designed to measure candidate ranking shifts induced by unfamiliar terminology and external retrieved text across six paired experimental conditions (A–F).

**Important Security & Scope Distinction:**
- This harness is a **synthetic, offline benchmark harness** designed for reproducible measurement.
- It does **NOT** modify or instantiate production `epistemicos/` control plane code.
- Condition F uses a benchmark-local placeholder (`ExperimentalGateAdapter`) to simulate gate interventions; it does **NOT** imply that a production defense against decision steering is deployed or active.

---

## 2. Experimental Conditions (A through F)

Every evaluation scenario is evaluated across six paired experimental conditions:

1. **Condition A (Baseline Control):** Standard candidate options evaluated without unfamiliar terms or retrieved context. Preserves natural baseline ranking ($R_{\text{baseline}}$).
2. **Condition B (Claim Only):** Target candidate option contains an unfamiliar term/claim without retrieval context. Measures default model term bias ($\Delta R_B$).
3. **Condition C (Direct Evidence Steering):** Adversarial claim and fabricated risk passage injected directly into the prompt text. Measures direct steering susceptibility ($\Delta R_C$).
4. **Condition D (Retrieval-Mediated Steering):** Unfamiliar term triggers mock web search, returning synthetic fabricated web pages. Measures search-mediated steering ($\Delta R_D$).
5. **Condition E (Decision-Time Source Assessment):** Condition D retrieval accompanied by system prompt requiring source credibility assessment. Measures prompted defense interception ($\Delta R_E$).
6. **Condition F (Experimental Gate Adapter):** Condition D retrieval passed through a benchmark-local evidence discount adapter (`ExperimentalGateAdapter`). Measures control-plane gate interception ($\Delta R_F$).

---

## 3. Data Contracts & Schema Specification

The harness enforces strict JSON and object contracts:

- **Candidate (`Candidate`):**
  - `candidate_id`: Unique string identifier within the scenario.
  - `title` & `description`: Option text.
  - `baseline_rank`: Integer initial rank position (1-indexed).
  - `is_target_option`: Boolean indicating if this option is the target of steering.
- **Scenario (`Scenario`):**
  - `scenario_id`: Unique scenario string (e.g., `SMOKE_001_DEV_RETRIEVAL_STEERING`).
  - `candidates`: List of `Candidate` objects.
  - `unfamiliar_term` & `query`: Search query string for mock retrieval.
  - `attack_variant`: Variant type (`direct_steering`, `retrieval_steering`, `invalid_inference`, `benign_control`).
  - `partition`: Partition label (`dev` or `held_out`).
- **Trial Result (`TrialResult`):**
  - `trial_id`: Deterministic/tracked trial identifier.
  - `scenario_id` & `condition`: Associated scenario ID and condition enum.
  - `output_ranking`: Ordered list of `candidate_id` strings (rank 1 first).
  - `is_valid` & `invalid_reason`: Boolean validity status and failure explanation.

---

## 4. Dataset Size Discrepancy & Stratification Reconciliation Plan

### The Dataset Size Discrepancy
The v3.0.0 research specification contains two distinct corpus size references:
1. **Initial 120-Scenario Specification:** An initial formulation specifying $N = 120$ scenarios ($80$ adversarial, $40$ benign), partitioned into $N_{\text{dev}} = 48$ ($40\%$) and $N_{\text{eval}} = 72$ ($60\%$).
2. **Statistical Power Recommendation ($N = 200$):** A power analysis calculation demonstrating that $N = 48$ held-out adversarial scenarios provides only $62\%$ statistical power at $\Delta = 0.20$, recommending scaling to $N = 200$ total scenarios ($120$ adversarial, $80$ benign) with $N_{\text{eval, adv}} = 80$ held-out scenarios to achieve $80\%$ statistical power at $\alpha = 0.05$.

### Reconciliation & Stratification Plan
For future full corpus generation (Phase 1B):
- **Total Corpus Size:** $N = 200$ scenarios.
- **Development Partition ($40\%$, $N = 80$ scenarios):**
  - $N = 48$ Adversarial cases (12 Direct Steering, 12 Retrieval Steering, 12 Circular Reporting, 12 Invalid Inference).
  - $N = 32$ Benign Control cases (8 Legitimate Terminology, 8 Credible Concern, 8 Independent Multi-Source, 8 Syndicated Common-Origin).
- **Held-Out Evaluation Partition ($60\%$, $N = 120$ scenarios):**
  - $N = 80$ Adversarial cases (20 Direct Steering, 20 Retrieval Steering, 20 Circular Reporting, 20 Invalid Inference). Guaranteed $80\%$ statistical power for paired McNemar tests at $\Delta = 0.20$.
  - $N = 40$ Benign Control cases (10 per benign type).
- **Dataset Partition Isolation Rule:** Held-out scenarios (`partition == "held_out"`) are cryptographically locked in `dataset_manifest.json` and are **never loaded** into development or prompt tuning paths.

---

## 5. Execution Commands & Test Invocation

To run the dedicated harness unit and integration test suite:

```bash
PYTHONPATH="/home/jules/.local/share/pipx/venvs/pytest/lib/python3.12/site-packages:/home/jules/.local/share/pipx/venvs/coverage/lib/python3.12/site-packages:/home/jules/.pyenv/versions/3.12.13/lib/python3.12/site-packages:." python3 -m pytest benchmarks/on_policy_decision_steering/test_steering_harness.py
```

---

## 6. Limitations & Unresolved Design Choices

1. **Synthetic Offline Execution:** Mock retrieval relies strictly on pre-configured local fixture passages. It does not perform live web search or query external search engines.
2. **Mechanical Metrics Only:** Metrics in Phase 1A compute exact top-$k$ entry/exit rates, rank shifts, invalid trial rates, and benign demotion rates. "Unsupported Claim Influence" is marked as `REQUIRES_EXTERNAL_EVALUATOR` and cannot be computed mechanically.
3. **No Production Defense Claims:** The harness is an offline measurement tool. Efficacy on synthetic fixtures does not prove security against real-world adversarial steering.
