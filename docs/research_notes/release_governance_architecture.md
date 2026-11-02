# EpistemicOS Change & Release Governance Architecture Specification

**Status:** Phase 0 Proof of Concept (Final Assurance Level Hardened)
**Subsystem:** `epistemicos/release/`
**Date:** May 2026
**Audience:** EpistemicOS Core Architecture & Safety Engineering

---

## 1. Executive Summary & Objective

EpistemicOS was initially conceived as an **in-process runtime execution governance system** (governing runtime tool execution via `TrustedExecutionBoundary`, capability checking via `AuthorizationAuthority`, and cryptographic provenance logging via `LocalProvenanceStore`).

This subsystem extends EpistemicOS into **Change & Release Governance**. The fundamental security property enforced is:

> **A release approval must authorize one exact, identifiable system configuration. Any material change to that configuration must strictly invalidate the previous approval.**

This implementation establishes an isolated subsystem under `epistemicos/release/` that formalizes:
1. Deterministic canonical release manifests and cryptographic SHA-256 digest calculation.
2. Cryptographic binding of verification evidence to exact release manifest digests, validating both evidence record integrity and actual artifact byte digests.
3. Complete evidence-scope binding for evaluator signatures (binding `evidence_id`, `manifest_digest`, `evidence_type`, `status`, `artifact_digest`, `evaluator_id`, `evaluator_issuer`, `evaluated_at_utc`, `evaluated_component_ids`, and `metadata`).
4. Mandatory evidence verification at the approval verification boundary: every referenced digest must correspond to an available verified record.
5. Required evidence completeness at the approval verification boundary: approvals must reference verified evidence satisfying every category in `manifest.required_evidence_types`; unreferenced records or partial category coverage strictly fail closed.
6. Evaluator signature verification is mandatory under the default policy; unsigned evidence is rejected unless explicit reduced-assurance mode is configured.
7. Explicit propagation of `AssuranceLevel` (`FULL_AUTHENTICATED` vs `REDUCED_ASSURANCE`) across both `evaluate_release_readiness()` (returning `ReleaseReadinessEvaluation`) and `verify_release_approval()` (returning `ReleaseApprovalVerificationResult`), ensuring reduced-assurance decisions are never represented as unqualified full authorizations.
8. Asymmetric Ed25519-signed release approvals bound to immutable manifest digests and verified via `PrincipalVerifier` (RFC 8032).
9. Monotonic, authoritative approval revocation via `ReleaseApprovalRevocationRegistry`, preventing resurrection attacks via in-memory or serialized object mutation.
10. Deterministic change detection and fail-closed evidence invalidation.
11. Fail-closed audit logging semantics for release authorization decisions, requiring a configured audit trail.

---

## 2. Architectural Boundaries & Trust Model

### 2.1 Cryptographic Distinction Matrix

| Operation | Mechanism | Security Claim Made | What It Does NOT Claim |
| :--- | :--- | :--- | :--- |
| **Manifest Hashing** | SHA-256 over canonical JSON | Exact byte/content identity of the release specification | Does NOT prove the referenced binaries or models are safe or authentic |
| **Evidence Record Integrity** | Manifest digest in `VerificationEvidenceRecord` | The test or benchmark record was generated for this specific manifest configuration | Does NOT guarantee the test suite is bug-free or covers all threat vectors |
| **Evidence Artifact Authenticity** | SHA-256 digest validation against actual artifact bytes & evaluator Ed25519 signature | Artifact byte content matches declared digest, originates from an authorized evaluator, and attests to exact component scope | Does NOT prove the test harness host OS was uncompromised |
| **Approval Signing** | Asymmetric RFC 8032 Ed25519 signature | An authorized human or cryptographic reviewer explicitly authorized this exact manifest digest | Does NOT prove the live deployment matches the signed artifact |
| **Effective Assurance Level** | `AssuranceLevel.FULL_AUTHENTICATED` vs `REDUCED_ASSURANCE` | Indicates whether all artifact bytes and evaluator signatures were verified or accepted under reduced policy | Does NOT eliminate the need to verify downstream deployment identity |
| **Authoritative Revocation** | `ReleaseApprovalRevocationRegistry` | Monotonically marks an approval ID as revoked, preventing resurrection by object mutation | Relies on registry persistence across restart boundaries (currently in-memory) |
| **Deployment Attestation** *(Deferred)* | Hardware TPM / enclave measurement | The running process memory matches the authorized binary | *Explicitly deferred to Phase 1 (not implemented in Phase 0)* |

### 2.2 Conceptual Subsystem Architecture

```
+-----------------------------------------------------------------------------------------+
|                                BUILD & RELEASE WORKFLOW                                  |
|                                                                                         |
|  +--------------------+     +---------------------+     +----------------------------+  |
|  | Component Artifacts|     | Verification Tests  |     | Authoritative Principal    |  |
|  | - Weights / Digest |     | - Security Audits   |     | - RFC 8032 Ed25519 Key     |  |
|  | - Config / Code    |     | - Clinical Benchmrk |     | - Human / Audit Signer     |  |
|  +---------+----------+     +----------+----------+     +--------------+-------------+  |
|            |                           |                               |                |
+------------|---------------------------|-------------------------------|----------------+
             |                           |                               |
             v                           v                               v
+-----------------------------------------------------------------------------------------+
|                         EPISTEMICOS RELEASE SUBSYSTEM (`epistemicos/release/`)          |
|                                                                                         |
|   +---------------------------------------------------------------------------------+   |
|   | 1. CANONICAL RELEASE MANIFEST (`ReleaseManifest`)                                |   |
|   |    - components: [{id, type, version, digest, config_digest}]                   |   |
|   |    - runtime_identity, policy_version, policy_digest, required_evidence_types   |   |
|   |    - Strict 64-hex SHA-256 input validation                                      |   |
|   |    => SHA-256 Digest: D_manifest                                                |   |
|   +---------------------------------------+-----------------------------------------+   |
|                                           |                                             |
|                                           v                                             |
|   +---------------------------------------------------------------------------------+   |
|   | 2. VERIFICATION EVIDENCE BINDING (`VerificationEvidenceRecord`)                 |   |
|   |    - manifest_digest == D_manifest (Exact match required)                       |   |
|   |    - status: PASS (Fails closed on FAIL, PARTIAL, or INCONCLUSIVE)              |   |
|   |    - artifact_digest validated against actual artifact bytes                     |   |
|   |    - Evaluator signature mandatory (RFC 8032 Ed25519 via PrincipalVerifier)     |   |
|   |    - Evaluator signature binds evaluated_component_ids and metadata             |   |
|   +---------------------------------------+-----------------------------------------+   |
|                                           |                                             |
|                                           v                                             |
|   +---------------------------------------------------------------------------------+   |
|   | 3. ASYMMETRIC APPROVAL VERIFICATION (`ReleaseApprovalRecord`)                   |   |
|   |    - manifest_digest == D_manifest                                              |   |
|   |    - approver_id in allowed_approvers allowlist                                 |   |
|   |    - Ed25519 signature verified via PrincipalVerifier (RFC 8032)                |   |
|   |    - Mandatory evidence records verified at approval boundary                   |   |
|   |    - Required evidence completeness enforced (no omitted categories)            |   |
|   |    - Effective AssuranceLevel communicated in ReleaseApprovalVerificationResult |   |
|   |    - Authoritative Revocation Registry check (anti-resurrection)                |   |
|   |    - Expiration & Policy Version consistency checks                             |   |
|   |    - Mandatory fail-closed audit logging (audit trail required)                 |   |
|   +---------------------------------------+-----------------------------------------+   |
|                                           |                                             |
|                                           v                                             |
|   +---------------------------------------------------------------------------------+   |
|   | 4. CHANGE IMPACT & EVIDENCE INVALIDATION (`EvidenceInvalidator`)                |   |
|   |    - Detects component additions, removals, mutations, or config changes        |   |
|   |    - Invalidates any evidence touching altered components                       |   |
|   |    - Rejects foreign/older manifest evidence for new release candidates         |   |
|   +---------------------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------------------+
```

---

## 3. Public API Assurance Level Contracts

### 3.1 Structured Return Types & Assurance Visibility
Both public entry points in `ReleaseGovernanceEngine` return structured result objects exposing the effective `AssuranceLevel`:
- `evaluate_release_readiness(manifest, evidence_records, artifact_bytes_provider) -> ReleaseReadinessEvaluation`:
  - `is_ready: bool`
  - `reason: str`
  - `verified_evidence_records: List[VerificationEvidenceRecord]`
  - `accepted_evidence_digests: List[str]`
  - `validation_results: List[EvidenceValidationResult]`
  - `effective_assurance_level: Optional[AssuranceLevel]` (`FULL_AUTHENTICATED`, `REDUCED_ASSURANCE`, or `None` on failure)

- `verify_release_approval(manifest, approval, evidence_records, artifact_bytes_provider, current_time) -> ReleaseApprovalVerificationResult`:
  - `is_verified: bool`
  - `reason: str`
  - `effective_assurance_level: Optional[AssuranceLevel]` (`FULL_AUTHENTICATED` or `REDUCED_ASSURANCE`)
  - `verified_evidence_count: int`
  - `validation_results: List[EvidenceValidationResult]`

### 3.2 Assurance Calculation Rules
1. `FULL_AUTHENTICATED` requires that EVERY evidence record referenced by the approval:
   - Had its raw artifact bytes retrieved and validated against `artifact_digest`.
   - Had its evaluator Ed25519 signature verified against a trusted `PrincipalVerifier` public key.
2. If any evidence record was verified without artifact bytes or without an evaluator signature (under an explicitly configured `require_artifact_bytes_verification=False` or `require_evaluator_signatures=False` engine mode), the overall effective assurance level is strictly set to `REDUCED_ASSURANCE`.
3. An approval verification can NEVER return `FULL_AUTHENTICATED` if any referenced evidence relied on reduced assurance.

---

## 4. Motivating Case: FDA Warning-Letter Scenario

### Change 1: New Machine-Learning Algorithm
- `diagnostic_model` digest changes from $D_1 \to D_2$.
- `EvidenceInvalidator` flags `ChangeCategory.MODEL_CHANGE`.
- Evidence covering `clinical_diagnostic_benchmark` bound to $D_1$ is marked **INVALIDATED**.
- Any previously signed approval bound to $D_1$ is strictly rejected for $D_2$.
- Requires a new benchmark run against $D_2$ and a new Ed25519 signature from a clinical reviewer.

### Change 2: Transition from Desktop Software to Web Architecture
- `runtime_identity` changes from `desktop-standalone-v1` to `web-gateway-v2`.
- `EvidenceInvalidator` detects `ChangeCategory.RUNTIME_CHANGE` and `ChangeCategory.COMPONENT_ADDED`.
- All local attack surface evidence is invalidated; network containment proofs must be rerun.

### Change 3: Technology Platform Migration
- Dependency lockfile or base runtime digest changes.
- Flagged as `ChangeCategory.DEPENDENCY_CHANGE` or `ChangeCategory.INFRASTRUCTURE_CHANGE`.
- Requires re-execution of core runtime regression suites.

---

## 5. Explicitly Deferred Capabilities & Trust Limitations

1. **Deployment Attestation:**
   - *Limitation:* Phase 0 verifies that a release candidate specification was approved in CI/CD. It does *not* prove that a live OS process running in a data center or edge device is executing that exact code.
   - *Future Work:* Integration with Sigstore/Cosign, TPM 2.0 measurements, or confidential container enclave quotes.

2. **Automated SBOM Discovery:**
   - *Limitation:* Components and dependency digests are supplied as inputs. EpistemicOS does not crawl container images or package managers in this layer.

3. **Generalized Dependency Graph & Dynamic Impact Scoring:**
   - *Limitation:* Impact analysis uses set-based component intersection. It does not compute transitive graph reachability.

4. **Revocation Persistence:**
   - *Limitation:* The revocation registry is currently in-memory and process-local. Monotonic disk journaling is deferred to Phase 1.
