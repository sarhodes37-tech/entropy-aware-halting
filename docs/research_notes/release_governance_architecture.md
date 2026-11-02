# EpistemicOS Change & Release Governance Architecture Specification

**Status:** Phase 0 Proof of Concept
**Subsystem:** `epistemicos/release/`
**Date:** May 2026
**Audience:** EpistemicOS Core Architecture & Safety Engineering

---

## 1. Executive Summary & Objective

EpistemicOS was initially conceived as an **in-process runtime execution governance system** (governing runtime tool execution via `TrustedExecutionBoundary`, capability checking via `AuthorizationAuthority`, and cryptographic provenance logging via `LocalProvenanceStore`).

This subsystem extends EpistemicOS into **Change & Release Governance**. The fundamental security property enforced is:

> **A release approval must authorize one exact, identifiable system configuration. Any material change to that configuration must strictly invalidate the previous approval.**

This implementation establishes an isolated subsystem under `epistemicos/release/` that formalizes:
1. Deterministic canonical release manifests and cryptographic digest calculation.
2. Cryptographic binding of verification evidence to exact release manifest digests.
3. Asymmetric Ed25519-signed release approvals bound to immutable manifest digests.
4. Deterministic change detection and fail-closed evidence invalidation.

---

## 2. Architectural Boundaries & Trust Model

### 2.1 Cryptographic Distinction Matrix

It is vital to distinguish the separate claims made by each cryptographic mechanism:

| Operation | Mechanism | Security Claim Made | What It Does NOT Claim |
| :--- | :--- | :--- | :--- |
| **Manifest Hashing** | SHA-256 over canonical JSON | Exact byte/content identity of the release specification | Does NOT prove the referenced binaries or models are safe or authentic |
| **Evidence Binding** | Manifest digest in `VerificationEvidenceRecord` | The test or benchmark was executed against this specific manifest configuration | Does NOT guarantee the test suite is bug-free or covers all threat vectors |
| **Approval Signing** | Asymmetric RFC 8032 Ed25519 signature | An authorized human or cryptographic reviewer explicitly authorized this exact manifest digest | Does NOT prove the live deployment matches the signed artifact |
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
|   |    => SHA-256 Digest: D_manifest                                                |   |
|   +---------------------------------------+-----------------------------------------+   |
|                                           |                                             |
|                                           v                                             |
|   +---------------------------------------------------------------------------------+   |
|   | 2. VERIFICATION EVIDENCE BINDING (`VerificationEvidenceRecord`)                 |   |
|   |    - manifest_digest == D_manifest (Exact match required)                       |   |
|   |    - status: PASS (Fails closed on FAIL, PARTIAL, or INCONCLUSIVE)              |   |
|   |    - artifact_digest: SHA-256 of test run output                                |   |
|   +---------------------------------------+-----------------------------------------+   |
|                                           |                                             |
|                                           v                                             |
|   +---------------------------------------------------------------------------------+   |
|   | 3. ASYMMETRIC APPROVAL VERIFICATION (`ReleaseApprovalRecord`)                   |   |
|   |    - manifest_digest == D_manifest                                              |   |
|   |    - approver_id in allowed_approvers allowlist                                 |   |
|   |    - Ed25519 signature verified via PrincipalVerifier (RFC 8032)                |   |
|   |    - Expiration & Revocation Checks                                             |   |
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

## 3. Data Structures & Canonicalization

### 3.1 Canonical Manifest vs. Informational Metadata
To avoid semantic canonicalization bugs, `ReleaseManifest` strictly distinguishes between **canonical fields** (included in the SHA-256 digest) and **informational metadata**:

- **Canonical Fields:**
  - `schema_version`: Version of manifest specification.
  - `release_id`: Release label or ticket identifier.
  - `target_environment`: Target deployment enclave.
  - `runtime_identity`: EpistemicOS runtime version / commit.
  - `policy_version` & `policy_digest`: Authorization policy reference.
  - `required_evidence_types`: Sorted set of required evidence categories.
  - `components`: Deterministically sorted list of `ComponentSpec` objects (sorted by `component_id`).

- **Informational Metadata (Excluded from digest):**
  - `created_at_utc`, `display_name`, `description`, `tags`, `notes`.
  - Changes to informational fields do NOT alter the manifest digest or invalidate approvals.

---

## 4. Motivating Case: FDA Warning-Letter Scenario

To ground this architecture in a real-world setting without claiming regulatory adjudication, consider the three change classes highlighted in recent medical device software enforcement actions:

### Change 1: New Machine-Learning Algorithm
- **Scenario:** A diagnostic model's weights and architecture are updated (`v1.0.0` -> `v2.0.0`).
- **EpistemicOS Representation:**
  - `ComponentSpec(component_id="diagnostic_model", digest="new_weights_sha256")`.
  - The manifest digest changes from $D_1 \to D_2$.
- **Governance Consequence:**
  - `EvidenceInvalidator` flags `diagnostic_model` as changed (`ChangeCategory.MODEL_CHANGE`).
  - Evidence records covering `clinical_diagnostic_benchmark` bound to $D_1$ are marked **INVALIDATED**.
  - Any previously signed `ReleaseApprovalRecord` bound to $D_1$ is **strictly rejected** for $D_2$.
  - A new clinical benchmark must be executed against $D_2$, and a qualified clinical reviewer must issue a new Ed25519 approval.

### Change 2: Transition from Desktop Software to Web Architecture
- **Scenario:** The system transitions from a standalone workstation application to an HTTP client-server model.
- **EpistemicOS Representation:**
  - `runtime_identity` changes from `desktop-standalone-v1` to `web-gateway-v2`.
  - New network exposure components (`ingress_proxy`, `api_server`) are added.
- **Governance Consequence:**
  - `EvidenceInvalidator` detects `ChangeCategory.RUNTIME_CHANGE` and `ChangeCategory.COMPONENT_ADDED`.
  - All local attack surface evidence (e.g. `layer4_security_audit`) is invalidated.
  - Network containment and penetration test evidence must be re-executed.

### Change 3: Technology Platform Migration
- **Scenario:** Python runtime upgrade or OS base image migration (e.g., Debian 11 -> Alpine Linux).
- **EpistemicOS Representation:**
  - `runtime_identity` or dependency lockfile digests change.
- **Governance Consequence:**
  - Flagged as `ChangeCategory.DEPENDENCY_CHANGE` or `ChangeCategory.INFRASTRUCTURE_CHANGE`.
  - Requires re-execution of core runtime regression suites.

**Regulatory Boundary Note:**
EpistemicOS provides the deterministic evidence and authorization boundary. It **does not** decide whether a change legally requires a new FDA 510(k) submission or European CE-mark reassessment; it ensures that whatever verification policy is mandated cannot be silently bypassed.

---

## 5. Explicitly Deferred Capabilities & Trust Limitations

The following capabilities are **explicitly out of scope** for Phase 0:

1. **Deployment Attestation:**
   - *Limitation:* Phase 0 verifies that a release candidate specification was approved in CI/CD. It does *not* prove that a live OS process running in a data center or edge device is executing that exact code.
   - *Future Work:* Integration with Sigstore/Cosign, TPM 2.0 measurements, or confidential container enclave quotes.

2. **Automated SBOM Discovery:**
   - *Limitation:* Components and dependency digests are supplied as inputs. EpistemicOS does not crawl container images or package managers in this layer.

3. **Generalized Dependency Graph & Dynamic Impact Scoring:**
   - *Limitation:* Impact analysis uses set-based component intersection. It does not compute transitive graph reachability.
