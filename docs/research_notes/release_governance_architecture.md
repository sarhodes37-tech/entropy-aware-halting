# EpistemicOS Change & Release Governance Architecture Specification

**Status:** Phase 0 Proof of Concept (Hardened)
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
3. Asymmetric Ed25519-signed release approvals bound to immutable manifest digests and verified via `PrincipalVerifier` (RFC 8032).
4. Monotonic, authoritative approval revocation via `ReleaseApprovalRevocationRegistry`, preventing resurrection attacks via in-memory or serialized object mutation.
5. Deterministic change detection and fail-closed evidence invalidation.
6. Fail-closed audit logging semantics for release authorization decisions.

---

## 2. Architectural Boundaries & Trust Model

### 2.1 Cryptographic Distinction Matrix

It is vital to distinguish the separate claims made by each cryptographic mechanism:

| Operation | Mechanism | Security Claim Made | What It Does NOT Claim |
| :--- | :--- | :--- | :--- |
| **Manifest Hashing** | SHA-256 over canonical JSON | Exact byte/content identity of the release specification | Does NOT prove the referenced binaries or models are safe or authentic |
| **Evidence Record Integrity** | Manifest digest in `VerificationEvidenceRecord` | The test or benchmark record was generated for this specific manifest configuration | Does NOT guarantee the test suite is bug-free or covers all threat vectors |
| **Evidence Artifact Authenticity** | SHA-256 digest validation against actual artifact bytes & evaluator Ed25519 signature | Artifact byte content matches declared digest and originates from an authorized evaluator | Does NOT prove the test harness environment was uncompromised |
| **Approval Signing** | Asymmetric RFC 8032 Ed25519 signature | An authorized human or cryptographic reviewer explicitly authorized this exact manifest digest | Does NOT prove the live deployment matches the signed artifact |
| **Authoritative Revocation** | `ReleaseApprovalRevocationRegistry` | Monotonically marks an approval ID as revoked, preventing resurrection by object mutation | Relies on registry persistence across restart boundaries |
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
|   |    - Evaluator signature verified via PrincipalVerifier                         |   |
|   +---------------------------------------+-----------------------------------------+   |
|                                           |                                             |
|                                           v                                             |
|   +---------------------------------------------------------------------------------+   |
|   | 3. ASYMMETRIC APPROVAL VERIFICATION (`ReleaseApprovalRecord`)                   |   |
|   |    - manifest_digest == D_manifest                                              |   |
|   |    - approver_id in allowed_approvers allowlist                                 |   |
|   |    - Ed25519 signature verified via PrincipalVerifier (RFC 8032)                |   |
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

## 3. Security Hardening Implementation & Trust Guarantees

### 3.1 Authoritative Revocation Registry & Anti-Resurrection (P0)
- `ReleaseApprovalRecord` contains immutable metadata and an asymmetric Ed25519 signature.
- Revocation state is decoupled from mutable fields on the approval object: `ReleaseApprovalRevocationRegistry` holds monotonic, irreversible `RevocationRecord` entries keyed by `approval_id`.
- Calling `verify_release_approval()` checks the authoritative registry. Even if an attacker mutates an in-memory approval or replays a signed approval with `revoked = False`, the engine looks up the registry and strictly rejects the approval.
- *Persistence Assumption:* In Phase 0, the registry is in-memory and thread-safe. Phase 1 will extend this to multi-process journaled storage mirroring `FileAuthorizationStore`.

### 3.2 Evidence Verification & Evaluator Authenticity (P0)
- Evidence verification strictly distinguishes **evidence record integrity** from **evidence artifact authenticity**.
- `evaluate_release_readiness` accepts an optional `artifact_bytes_provider` to re-hash raw disk or stored artifact bytes against `ev.artifact_digest`.
- If an evaluator signature is present on `VerificationEvidenceRecord`, the engine cryptographically validates it against `PrincipalVerifier` and fails closed if the issuer is untrusted or the signature fails.
- In `verify_release_approval`, the engine verifies that all evidence digests cited in `approval.required_evidence_digests` exist within the verified evidence records.

### 3.3 Strict SHA-256 Digest Validation & Domain Separation (P1)
- `validate_sha256_hex` validates all digests (`manifest_digest`, component `digest`, `config_digest`, `policy_digest`, `artifact_digest`, and required evidence digests) to require exactly 64 hexadecimal characters.
- Serialized signature payloads in `compute_signature_payload()` now use deterministic canonical JSON (`domain: "EpistemicOS:ReleaseApprovalRecord:v1"` and `"EpistemicOS:VerificationEvidenceRecord:v1"`) with sorted keys and separators `(",", ":")`, eliminating delimiter ambiguity attacks.

### 3.4 Approval Identity & Policy Version Consistency (P1)
- The approval signature represents an **independently authenticated human or release authority principal** holding an RFC 8032 Ed25519 private key.
- `verify_release_approval` enforces that `approval.policy_version == manifest.policy_version`, preventing an approval issued under an older, more permissive authorization policy from certifying a manifest configured under a newer, stricter policy.

### 3.5 Fail-Closed Audit Semantics (Finding 5)
- In safety-critical release governance, audit recording cannot be silent or best-effort.
- `ReleaseGovernanceEngine` defaults to `fail_closed_audit = True`. If the underlying `TamperEvidentAuditTrail` encounters an OS/disk failure, the engine raises `RuntimeError` and refuses to declare the release authorized.

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
