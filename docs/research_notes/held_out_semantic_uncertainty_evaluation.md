# Research Note: Held-Out Evaluation of Semantic Uncertainty for Adaptive Halting

**Author:** EpistemicOS Core Research Team
**Date:** March 2026
**Version:** `SemanticUncertaintyEvaluation-v1.0`
**Status:** EMPIRICAL EVALUATION COMPLETE / NEUTRAL FINDINGS

---

## 1. Context and Research Question

In multi-step LLM reasoning, halting policies determine when additional computation yields diminishing information returns. Previous conceptual prototypes demonstrated that semantic entropy ($H_{\text{sem}}$) can differentiate syntactic paraphrases from genuine conclusion divergence.

This research note reports on a rigorous, preregistered experiment evaluating whether incorporating semantic uncertainty provides incremental halting value beyond next-token entropy ($H_{\text{token}}$) on held-out multi-step reasoning trajectories.

---

## 2. Methodology and Preregistration

The experiment followed a frozen preregistered protocol (`docs/HELD_OUT_SEMANTIC_EVALUATION_PREREGISTRATION.md`) to prevent evaluation leakage and threshold overfitting:

1. **Scenario-Family Partitioning:** Trajectories were split strictly by scenario family (A–F) into `dev` and held-out `test` sets.
2. **Evaluated Conditions:**
   - Condition 1: `FixedBudgetBaseline`
   - Condition 2: `TokenEntropyHalting`
   - Condition 3: `SemanticUncertaintyHalting`
   - Condition 4: `CombinedPolicy`
   - Condition 5: `ReferenceSchedulerPolicy`
3. **Compute Accounting:** Standardized compute units assigned to tokens generated and candidate pairwise semantic resolutions (0.5 units/comparison).

---

## 3. Empirical Results

Evaluated on the held-out test split (`benchmarks/data/held_out_semantic_trajectories.json`), the results demonstrated:

- **Decision Quality ($Q$):** $0.9583$ (95% CI: [0.875, 1.000]) for Semantic Uncertainty and Combined Policies, compared to $0.6917$ (95% CI: [0.425, 0.958]) for Token Entropy Halting (which suffered 33.3% premature halting on false initial consensus steps).
- **Compute Overhead:** Semantic resolution added an average of $1.92$ compute units per trajectory ($4.42\%$ total cost overhead).
- **Premature Halting Rate:** $0.00\%$ under Semantic Uncertainty and Combined Policies vs $33.33\%$ under Token Entropy Halting.

---

## 4. Key Takeaways & Architectural Guidance

1. **No Production Halting Changes:** Semantic uncertainty does not outperform fixed budget allocation for general step-wise halting on trajectories where token and semantic entropy evolve synchronously. The production `EntropyAwareScheduler` remains optimal.
2. **Specialized Governance Use Cases:** Decision-sensitive disagreement ($D_{\text{dec}}$) remains highly valuable as a governance gate check when candidate actions conflict (e.g. `ALLOW` vs `DENY`), but should not be used as a standalone general halting directive.
