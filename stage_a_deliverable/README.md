# EpistemicOS Phase 0.4.2 — Stage A Implementation Reproducibility Guide

## Overview

This delivery package contains the complete, working, tested implementation of **EpistemicOS Phase 0.4.2 — Stage A (Authorization Integrity and Observable Execution)**.

### Scope & Invariants Delivered

1. **Stage A1 — Authorization Integrity & Effective-Policy Enforcement:**
   - **Capability Data Model & Hardened Metadata:**
     - Mandatory non-empty `tenant_domain`, `policy_id`, `policy_version`, and finite numeric `expires_at`.
     - Permissive defaults such as `default_policy` and `default_tenant` removed.
     - Deterministic UTF-8 JSON serialization (`json.dumps(payload_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')`).
     - **Cryptographically binds exactly 21 fields into the HMAC-SHA256 signature payload:**
       1. `token_id`
       2. `principal_id`
       3. `correlation_id`
       4. `request_id`
       5. `task_id`
       6. `action_name`
       7. `target`
       8. `canonical_request_digest`
       9. `executor_id`
       10. `tenant_domain`
       11. `policy_id`
       12. `policy_version`
       13. `contract_id`
       14. `contract_version`
       15. `contract_digest`
       16. `authorization_basis`
       17. `approval_binding_digest`
       18. `expires_at`
       19. `fencing_token`
       20. `scope_key`
       21. `issuer_id`
     - **Exclusion of `created_at` Rationale:** `created_at` is an informational local creation timestamp. It is intentionally excluded from signature binding to prevent sub-microsecond clock jitter or restoration drift from invalidating authentic capabilities across storage rehydration boundaries. Temporal validity is anchored by `expires_at` (strictly validated as finite float/int) and monotonic journal fencing sequence tokens (`fencing_token`).
   - **Authorization Basis Derivation (`AUTONOMOUS` vs `HUMAN_APPROVED`):**
     - Autonomous execution prohibited when effective policy or bound task contract requires approval (`approval_required = policy_requires_approval OR contract_requires_approval`).
     - Legitimate `HumanApprovalRecord` verified via `PrincipalVerifier` and Ed25519 identity assertions.
     - Single-use replay protection and wildcard approver restrictions enforced.
   - **Trusted Policy and Contract Resolution:**
     - Evaluated strictly against trusted authority state; caller-supplied overrides rejected.
   - **Atomic Approval Consumption & Fencing:**
     - Single-use approval tracking, monotonic sequence ordering, and atomicity in dispatch-intent recording.
   - **Identity Hardening:**
     - Permissive `"agent_default"` fallback eliminated. Unauthenticated `"agent_default"` strings strictly fail closed at issuance, boundary enforcement, and historical verification.

2. **Stage A2 — Observable Execution & Benchmark Hardening:**
   - **Observable Mock Executor (`benchmarks/run_full_benchmark.py`):**
     - Explicit scenario contracts defining action, target, read-only vs mutating, expected side effects, and permissions.
     - Fixture-state telemetry distinguishing callable invocation, mutation attempt, confirmed mutation, partial mutation, unknown outcome, and read-only completion.
     - Full execution-boundary traversal: `benchmark submission → orchestrator → trusted execution boundary → observable callable`.
     - Removed wildcard permissions in benchmarks.
     - Replaced condition name `Post-Halt Retry Control` with `Synthetic Token-Budget Control`.
     - Exact event-based reconciliation for dispatch intents and callable invocations.
   - **Corrected Metric & Statistical Calculations:**
     - F1-score maintains consistent 0.0–1.0 unit scale throughout calculation, JSON persistence, and Markdown reporting.
     - Exact two-tailed binomial McNemar test implemented for paired condition comparisons with discordant counts ($b$, $c$), method attribution, and scientific notation formatting for small $p$-values.
     - Verified threshold ablation sensitivity across decision boundaries ($Z \in [1.0, 1.5, 2.0, 2.85]$).

---

## Reproduction Instructions

### Prerequisites
- Python 3.11+ (Python 3.12 recommended)
- Dependencies installed: `pydantic>=2.0.0`, `cryptography>=41.0.0`, `pytest>=7.4.0`

### 1. Execute Unit & Acceptance Regression Suites

To run the complete Stage A acceptance and regression test suites:

```bash
PYTHONPATH=. python3 -m pytest -v \
  tests/unit/test_stage_a_step1.py \
  tests/unit/test_stage_a_step2.py \
  tests/unit/test_stage_a_step3.py \
  tests/unit/test_stage_a_step4.py \
  tests/unit/test_stage_a2_observable_execution.py \
  tests/unit/test_human_approval_provenance.py \
  tests/unit/test_authorization_coverage_hardening.py \
  tests/unit/test_evidence_authenticity_remediation.py \
  tests/unit/test_permission_gate_regression.py \
  tests/unit/test_core_coverage.py
```

### 2. Run the Full 6-Condition Benchmark Suite

To run the empirical benchmark across all 6 experimental conditions (600 cases total):

```bash
PYTHONPATH=. python3 benchmarks/run_full_benchmark.py
```

Outputs generated:
- `results/ablation_table.json`: Complete aggregate metrics and execution telemetry.
- `results/per_case_results.json`: Granular per-case telemetry across all 600 trials.
- `results/ablation_summary.md`: Formatted ablation tables and inferential McNemar statistics.

---

## Baseline Commit & Environment Info

- **Base Commit:** `d6e5f7d142d1396a84f509c31677c7263b652be8`
- **Branch:** `phase-0.4.2-stage-a-implementation`
