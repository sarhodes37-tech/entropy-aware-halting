# Research Note: Semantic Uncertainty as a First-Class Epistemic Signal

**Author:** EpistemicOS Core Research Team
**Date:** October 2024
**Version:** `SemanticUncertaintyEstimator-v1.0`

---

## 1. Motivation and Central Hypothesis

Token-level entropy measures the dispersion of Next-Token probability distributions emitted by language models. While token entropy is a valuable indicator of low-level stochasticity, it frequently fails to capture uncertainty at the semantic (meaning) level:

1. **Paraphrase Inflation:** Syntactically varied phrasing of the exact same semantic conclusion artificially inflates token-level entropy.
2. **Negation Blindness:** High token similarity between "authorized" and "not authorized" masks critical semantic reversals and action implications.
3. **Overconfident Error:** Models can generate semantically uniform outputs that are factually incorrect or unsupported by evidence with near-zero token entropy.

### Central Hypothesis
A system can exhibit low token-level entropy while remaining uncertain about the meaning, truth, or decision implications of its output. Measuring disagreement among meaning-level conclusions identifies consequential uncertainty that token-level entropy misses.

---

## 2. Mathematical Definitions and Assumptions

### 2.1 Candidate Set, Probability Semantics, and Duplicate Aggregation
Given a set of $N$ candidate conclusions $\mathcal{C} = \{c_1, c_2, \dots, c_N\}$, each candidate optionally carries an explicit confidence probability $p(c_i)$.

If explicit probabilities are provided, they are validated to be non-negative finite real numbers and normalized:
$$
\tilde{p}(c_i) = \frac{p(c_i)}{\sum_{j=1}^N p(c_j)}
$$
If no candidate probabilities are supplied, a uniform mass distribution $\tilde{p}(c_i) = \frac{1}{N}$ is assigned across candidates.
> **Operational Note:** Uniform operational weights are a conventional baseline assignment, NOT calibrated epistemic probabilities.

**Duplicate Candidate Semantics:**
When candidate outputs contain repeated or identical text, each instance represents a sample draw from a candidate generator. Identical candidates are aggregated into the same semantic cluster $S_k$, and their sample probabilities are summed:
$$
P(S_k) = \sum_{c_i \in S_k} \tilde{p}(c_i)
$$

### 2.2 Cluster Partitioning
A pluggable `SemanticResolver` partitions candidates into $K$ mutually exclusive semantic clusters $S = \{S_1, S_2, \dots, S_K\}$ where $1 \le K \le N$. Candidates $c_i, c_j \in S_k$ iff $c_i$ and $c_j$ express materially equivalent conclusions.

### 2.3 Semantic Entropy
Semantic entropy $H_{\mathrm{sem}}$ is the Shannon entropy over the discrete cluster distribution $P(S)$:
$$
H_{\mathrm{sem}} = -\sum_{k=1}^K P(S_k) \log_2 P(S_k) \quad \text{(bits)}
$$

Normalized semantic entropy bounds $H_{\mathrm{sem}}$ in $[0, 1]$ relative to the maximum possible entropy for $K$ clusters:
$$
\bar{H}_{\mathrm{sem}} = \begin{cases}
0.0 & \text{if } K \le 1 \\
\min\left(1.0, \frac{H_{\mathrm{sem}}}{\log_2 K}\right) & \text{if } K > 1
\end{cases}
$$

### 2.4 Semantic Marginal Utility
In step-wise execution, semantic marginal information utility $\eta_{\mathrm{sem},t}$ is defined as:
$$
\eta_{\mathrm{sem},t} = \frac{\Delta H_{\mathrm{sem},t} \cdot V_{\mathrm{decision}}}{C_t}
$$
where:
- $\Delta H_{\mathrm{sem},t} = H_{\mathrm{sem},t-1} - H_{\mathrm{sem},t}$ (positive value indicates semantic uncertainty reduction).
- $V_{\mathrm{decision}} > 0$ is the decision value parameter.
- $C_t > 0$ is the step compute cost.

> **Rigor Note:** Reduction in entropy ($\Delta H_{\mathrm{sem},t} > 0$) represents a decrease in candidate cluster variance, but is NOT equivalent to formal information gain or improved factual correctness.

---

## 3. Conceptual Boundaries: Uncertainty vs. Truth

To maintain safety and scientific rigor, EpistemicOS strictly separates these concepts in schema and governance logic:

1. **Semantic Uncertainty ($H_{\mathrm{sem}}$):** Degree of meaning-level disagreement among candidate conclusions.
2. **Evidence Sufficiency:** Whether available context/data supports a conclusion (NOT inferred from low $H_{\mathrm{sem}}$).
3. **Factual Correctness:** Whether a conclusion matches ground truth (semantic consensus can be confidently wrong).
4. **Decision Sensitivity:** Whether candidate differences alter the downstream system action (e.g., `ALLOW` vs `DENY`).
5. **Resolution Opportunity:** Whether additional computation or human review can resolve the disagreement.

> **Governance Principle:** Low semantic entropy does NOT authorize pipeline actions or override governance gates.

---

## 4. Baseline Resolver Limitations and Unresolved Comparisons

The baseline `ExactAndNormalizedResolver` provides a rule-based deterministic heuristic for normalization, double-negation simplification, currency/unit checks, and directional actor swaps.

**Known Resolver Limitations:**
- Complex pragmatic context, implied preconditions, and nuanced natural language entailments require a statistical or neural judge (`SemanticResolver` subclass).
- When complex conditional or temporal discrepancies occur without explicit resolution rules, the resolver returns `resolver_confidence = 0.50`, triggering status `UNRESOLVED_COMPARISON` rather than manufacturing false precision.

---

## 5. Evaluation Harness & Key Results

The demonstration harness (`benchmarks/run_semantic_evaluation.py`) is explicitly labeled as a **Synthetic Conceptual Demonstration**, NOT a benchmark of empirical predictive accuracy on real LLM distributions.

**Measured Demonstration Findings:**
- **Scenario 1 (Paraphrases):** Synthetic token entropy = 2.00 bits; Measured semantic entropy = 0.00 bits across 1 cluster.
- **Scenario 2 (Negation):** Decision-sensitive disagreement = 1.00 captured despite high token overlap.
- **Scenario 3 (Confident Shared Error):** Measured semantic entropy = 0.00 bits; `factual_correctness` remains explicitly `None` (unassumed).
- **Scenario 5 (Single Candidate):** Returns `INSUFFICIENT_EVIDENCE` status.

---

## 6. Open Research Questions and Next Experiments

1. **Neural Resolver Injectability:** Testing cross-encoder or NLI classifier implementations of `SemanticResolver`.
2. **Dual Signal Calibration:** Empirical evaluation on multi-step trajectory benchmarks comparing combined token + semantic signals against single-signal baselines.
