# EpistemicOS Change & Release Governance Architecture Specification

**Status:** Phase 0 Proof of Concept (Evidence Trust-Boundary Hardened)
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
4. Mandatory evidence verification at the approval verification boundary (preventing approval verification from being executed without verified evidence records).
5. Asymmetric Ed25519-signed release approvals bound to immutable manifest digests and verified via `PrincipalVerifier` (RFC 8032).
6. Monotonic, authoritative approval revocation via `ReleaseApprovalRevocationRegistry`, preventing resurrection attacks via in-memory or serialized object mutation.
7. Deterministic change detection and fail-closed evidence invalidation.
8. Fail-closed audit logging semantics for release authorization decisions.

---

## 2. Architectural Boundaries & Trust Model

### 2.1 Cryptographic Distinction Matrix

It is vital to distinguish the separate claims made by each cryptographic mechanism:

| Operation | Mechanism | Security Claim Made | What It Does NOT Claim |
| :--- | :--- | :--- | :--- |
| **Manifest Hashing** | SHA-256 over canonical JSON | Exact byte/content identity of the release specification | Does NOT prove the referenced binaries or models are safe or authentic |
| **Evidence Record Integrity** | Manifest digest in `VerificationEvidenceRecord` | The test or benchmark record was generated for this specific manifest configuration | Does NOT guarantee the test suite is bug-free or covers all threat vectors |
| **Evidence Artifact Authenticity** | SHA-256 digest validation against actual artifact bytes & evaluator Ed25519 signature | Artifact byte content matches declared digest, originates from an authorized evaluator, and attests to exact component scope | Does NOT prove the test harness host OS was uncompromised |
| **Approval Signing** | Asymmetric RFC 8032 Ed25519 signature | An authorized human or cryptographic reviewer explicitly authorized this exact manifest digest | Does NOT prove the live deployment matches the signed artifact |
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
|   |    - Evaluator signature verified via PrincipalVerifier (RFC 8032)               |   |
|   |    - Signature binds evaluated_component_ids and metadata                       |   |
|   +---------------------------------------+-----------------------------------------+   |
|                                           |                                             |
|                                           v                                             |
|   +---------------------------------------------------------------------------------+   |
|   | 3. ASYMMETRIC APPROVAL VERIFICATION (`ReleaseApprovalRecord`)                   |   |
|   |    - manifest_digest == D_manifest                                              |   |
|   |    - approver_id in allowed_approvers allowlist                                 |   |
|   |    - Ed25519 signature verified via PrincipalVerifier (RFC 8032)                |   |
|   |    - Mandatory verified evidence records check at approval boundary             |   |
|   |    - Authoritative Revocation Registry check (anti-resurrection)                |   |
|   |    - Expiration & Policy Version consistency checks                             |   |
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

## 3. Evidence Trust Boundary Hardening

### 3.1 Explicit Artifact Byte Verification (P0)
- `verify_single_evidence()` provides shared, deterministic verification for both `evaluate_release_readiness()` and `verify_release_approval()`.
- When `require_artifact_bytes_verification=True` (default), artifact bytes must be retrievable via `artifact_bytes_provider(evidence_id)` and their SHA-256 digest must strictly match `artifact_digest`. If the provider is missing or returns `None`, verification returns `EvidenceValidationResultStatus.UNAVAILABLE`, preventing silent pass-through of uninspected artifacts.

### 3.2 Mandatory Evidence Verification at Approval Boundary (P0)
- `verify_release_approval()` mandates `evidence_records: List[VerificationEvidenceRecord]`. Missing evidence records strictly fail closed.
- Every referenced digest in `approval.required_evidence_digests` must correspond to a record that has passed `verify_single_evidence()` (including artifact bytes and evaluator signatures).
- Approval verification cannot be bypassed by directly submitting pre-cooked digest strings without the underlying evidence records.

### 3.3 Evaluator Signature Scope Binding (P0)
- `compute_signature_payload()` on `VerificationEvidenceRecord` binds all security-relevant fields into a domain-separated canonical structured JSON payload (`EpistemicOS:VerificationEvidenceRecord:v1`):
  - `evidence_id`, `manifest_digest`, `evidence_type`, `status`, `artifact_digest`, `evaluator_id`, `evaluator_issuer`, `evaluated_at_utc`, sorted `evaluated_component_ids`, and `metadata`.
- Any mutation of component scope (e.g. attempting to claim a test evaluated `diagnostic_model` when it only evaluated `core_runtime`) or metadata invalidates the evaluator signature.

### 3.4 Authoritative Revocation & Anti-Resurrection
- Revocation state is tracked authoritatively in `ReleaseApprovalRevocationRegistry`.
- Monotonic revocation records cannot be undone by mutating in-memory `approval.revoked` attributes or replaying previously signed approvals.
- *Limitation:* The revocation registry is currently in-memory and process-local. Durable disk journaling is deferred to Phase 1.

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
