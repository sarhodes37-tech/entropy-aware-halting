# Experimental Methodology & Limitations

This document outlines what the empirical validation and benchmark suite for EpistemicOS establishes, as well as explicit experimental boundaries and limitations.

## What the Experiments Establish

1. **Deterministic Security Interception**:
   - The PermissionGate and EntropyGate reliably intercept high-entropy anomalies, prompt overrides, and unauthorized state-mutating tool calls before execution.

2. **Active Execution-Gated Recovery**:
   - Pairing halting directives with active execution-gated recovery (resubmission under sanitized context) eliminates false positive rollbacks on benign borderline queries without lowering security boundaries against adversarial inputs.

3. **Compute Attribution**:
   - The compute-matched baseline demonstrates that additional compute budget alone (without active gating and feedback) does not prevent adversarial prompt injections or unauthorized system operations.

## Limitations & Scope Boundaries

1. **Synthetic / Simulated Logprob Distributions**:
   - The benchmarks utilize token-level logprob traces, simulated logits, and canonical representations. While these reflect real-world model outputs under high surprisal and prompt injections, performance under live API streams with non-deterministic provider sampling may vary slightly.

2. **Domain-Specific Schema Assumptions**:
   - The PermissionGate contract enforcement assumes well-defined schemas (e.g. CanonicalProblemRepresentation / Pydantic models). Unstructured, free-form text generations without explicit action boundaries require preliminary schema framing.

3. **Inference Latency Overhead**:
   - While the JIT pre-compiled regex and token surprisal calculations execute in sub-millisecond time ($< 0.5 \text{ ms}$), active execution-gated recovery incurs additional token generation latency when resubmitting queries.

4. **Adversarial Novelty**:
   - While negative controls and adversarial CTF cases test known injection vectors (e.g., system prompt overrides, command injections, data washing), zero-day adversarial jailbreaks that maintain artificially low surprisal and clean schema syntax may bypass entropy gates and require explicit permission gate updates.
