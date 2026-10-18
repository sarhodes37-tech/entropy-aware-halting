# EpistemicOS Dataset Provenance, Label Adjudication, and Integrity Specification

**Version:** 1.0.0-frozen
**Date:** 2026-03-30
**Status:** SPECIFICATION / PHASE 2

---

## 1. Overview & Dataset Separation

To guarantee that empirical benchmarks evaluate generalized security claims rather than overfitted threshold parameters, EpistemicOS enforces strict physical and operational separation between development/tuning data and frozen held-out evaluation datasets.

```
+------------------------------------------------------------------------------------+
|                         EPISTEMICOS DATASET SPLITS                                |
+------------------------------------------------------------------------------------+
|  DEV SET: benchmarks/data/dev_set.jsonl (N=50)                                     |
|  - Used for iterative gate design, prompt engineering, and feature exploration.    |
+------------------------------------------------------------------------------------+
|  THRESHOLD SET: benchmarks/data/threshold_set.jsonl (N=50)                         |
|  - Used exclusively for sliding window Z-score threshold selection (e.g. z=1.5).   |
+------------------------------------------------------------------------------------+
|  HELD-OUT EVAL SET: benchmarks/data/eval_set.jsonl (N=100)                         |
|  - Frozen, immutable held-out evaluation dataset.                                  |
|  - Cryptographic SHA-256 Digest: f4e31381a922c1143769ccb887c4841e4a14fedec6eef6569d40eed2956ce873 |
|  - FORBIDDEN from iterative tuning or threshold selection.                         |
+------------------------------------------------------------------------------------+
```

---

## 2. Label Adjudication & Ground Truth Criteria

Every evaluation case in `benchmarks/data/eval_set.jsonl` was constructed through dual-adjudicator consensus following the security criteria below:

### 2.1 Action Semantics & Classifications
- `ALLOW` (Benign Controls, $N=35$): Valid, policy-compliant requests formatted within expected statistical surprisal bounds. Ground truth expectation is pipeline completion and transaction commit.
- `ROLLBACK` (Adversarial Truncation, $N=40$): High-entropy prompt injections or malicious context manipulations triggering trajectory rollback without permanent halting.
- `HALT` (Deterministic Interception, $N=25$): Schema violations, scope mismatches, or prohibited system operations requiring immediate fail-closed pipeline halting.

### 2.2 Scenario Family Allocations ($N=100$)
1. **Commercial Underwriting & Operations ($N=20$):** BOP policy applications, driver MVR checks, filed rate variance bounds.
2. **Cyber, Shell & DB Threat Vectors ($N=15$):** Unrestricted SQL injections, shell command execution, DB drop table attempts.
3. **Multi-Turn & Obfuscated Prompt Injections ($N=15$):** DevMode overrides, role hijacking, encoded token bloat.
4. **Impossible Paradoxes & Introspection ($N=15$):** Self-referential logical loops designed to induce infinite tool invocation.
5. **High-Noise Benign Controls ($N=15$):** Complex enterprise JSON payloads with technical jargon that remain policy-compliant.
6. **Unauthorized Operations & Boundary Failures ($N=10$):** Unregistered tool dispatch attempts (e.g. unauthorized policy binder issuance).
7. **Gate Exceptions & Edge Cases ($N=10$):** Missing logprobs, non-finite Z-score edge cases, malformed structural payloads.

---

## 3. Cryptographic Digest, Dual-Lock Baseline, & Change Control

Dataset integrity is enforced through a **dual-lock verification model**:
1. Manifest Verification (`benchmarks/data/dataset_manifest.json`): Records dataset metadata and SHA-256 hash.
2. Code-Level Baseline Protection (`benchmarks/validate_evidence.py`): Hardcodes `FROZEN_BASELINE_DATASET_DIGEST = "f4e31381a922c1143769ccb887c4841e4a14fedec6eef6569d40eed2956ce873"`.

### Baseline Update Procedure
If the frozen evaluation dataset must be updated or re-versioned (e.g., v1.1.0-frozen release):
1. **Formal Review & Preregistration Amendment:** Submit a versioned amendment to `docs/PREREGISTRATION.md` documenting reasons for dataset modification or case additions.
2. **Re-compute SHA-256 Digest:** Generate the new SHA-256 digest of `benchmarks/data/eval_set.jsonl`.
3. **Synchronized Code & Manifest Update:** Simultaneously update `benchmarks/data/dataset_manifest.json` AND update `FROZEN_BASELINE_DATASET_DIGEST` in `benchmarks/validate_evidence.py`. Modifying `eval_set.jsonl` and `dataset_manifest.json` without updating `FROZEN_BASELINE_DATASET_DIGEST` will trigger an immediate CI baseline violation failure.

---

## 4. Run-Level Reproducibility Metadata

All consolidated evidence reports (`results/four_layer_evidence.json`) explicitly record:
1. `evaluated_git_commit`: The exact 40-character Git HEAD commit hash.
2. `working_tree_status`: `CLEAN` or `DIRTY`.
3. `working_tree_digest`: SHA-256 hash of uncommitted working tree file states.
4. `dataset_version`: `1.0.0-frozen`.
5. `dataset_sha256_digest`: Re-verified 64-character hex digest.
6. `dataset_digest_verified`: Boolean validation flag.
