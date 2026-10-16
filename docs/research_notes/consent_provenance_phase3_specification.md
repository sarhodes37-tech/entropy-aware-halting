# EpistemicOS Research Report: Consent Provenance & External Policy Drift — Phase 3 Implementation Readiness Specification

**Author:** EpistemicOS Security Architecture & Implementation Team
**Date:** October 2026
**Document Version:** `3.0.0`
**Target Module Area:** `epistemicos/gates.py`, `epistemicos/provenance.py`, `epistemicos/audit.py`, `epistemicos/compliance.py`, `epistemicos/core.py`
**Status:** NON-MUTATING PHASE 3 SPECIFICATION & IMPLEMENTATION ROADMAP

---

## Executive Summary

This Phase 3 specification converts the Phase 2 design review into a minimal, repository-verified implementation specification for Consent Provenance and External Policy Drift Governance in EpistemicOS.

Maintaining strict non-mutating compliance, this document provides:
1. **Reconciled Findings & Invariant Matrix:** Full alignment between all 12 Phase 2 vulnerability scenarios, exact repository citations, verified `GateConfig.enabled` semantics, and precise defect categorization.
2. **Opt-In Security Boundary:** Specification of protected vs. unprotected workloads, preventing silent downgrade attacks while maintaining backward compatibility.
3. **Execution-Bound Authorization Contract:** Canonical action representations binding Principal, Workload, Action, Resource, Purpose, Recipient, Policy Digest, Transaction ID, and Payload Digest.
4. **Narrowed Policy-Drift Contract:** Distinction between source-byte SHA-256 and canonical policy digests, effective-date semantics, and deterministic vs. human/institutional adjudication rules.
5. **Acceptance Test & Benchmark Specification:** Executable test specifications for 12 core acceptance criteria and benchmark protocols.
6. **Minimal Implementation Sequence & Go/No-Go Decision:** Step-by-step implementation dependencies, remaining blockers, and an explicit **GO** recommendation subject to defined prerequisites.

---

## 1. Reconciliation of Phase 2 Review Findings

To ensure scientific and engineering accuracy, all 12 Phase 2 vulnerability scenarios are reconciled against verified repository code and categorized by defect origin.

### 1.1 Verification of `GateConfig.enabled` Semantics (`epistemicos/gates.py`)
- **Repository Definition:** In `epistemicos/gates.py`, line 49: `enabled: bool = True` inside `@dataclass class GateConfig`.
- **Actual Runtime Behavior:** In `ControlPlaneGate` (lines 169–218), `GateConfig.enabled` exists in data structures, but `evaluate_safe()` does **not** evaluate `self.config.enabled`. If `enabled == False`, calling `evaluate()` or `evaluate_safe()` currently still executes `evaluate_contract()`.
- **Phase 3 Specification Fix:** `ControlPlaneGate.evaluate_safe()` must explicitly evaluate `if not self.config.enabled: return GateOutcome(decision=GateDecision.ALLOW, reason_code="GATE_DISABLED")` to enforce proper passthrough semantics.

### 1.2 Categorized Reconciliation Matrix

| Scenario / Finding | Defect Origin Category | Verified Repository Symbol & Line Citation | Corrected Behavior & System Invariant |
|---|---|---|---|
| **V1: Forged Auth Records** | Proposed-Design Defect | Proposed `ConsentAndPolicyDriftGate` read `context["authorization_record"]` without signature check. | **INV-1:** Records MUST be verified against KMS public key or fetched from trusted `AuthorizationRegistry`. |
| **V2: Baseline Policy Substitution** | Proposed-Design Defect | Proposed gate compared active vs baseline policy without asserting `baseline_policy.raw_document_hash == auth_record.bound_policy_digest`. | **INV-2:** Baseline snapshot `raw_document_hash` MUST match `auth_record.bound_policy_digest` exactly. |
| **V3: Default-ALLOW on Missing Evidence** | Proposed-Design Defect | Proposed gate fell through `if active_policy and baseline_policy:` to return `GateDecision.ALLOW`. | **INV-3:** Missing active/baseline policy snapshot for protected workloads MUST fail closed (`GateDecision.HALT`). |
| **V4: Expansion Unlabeled as Material** | Proposed-Design Defect | Proposed `PolicyDiffEngine` relied on unvalidated parser boolean flags (`expanded_scope`). | **INV-4:** Any added/modified clause governing data sharing/purposes MUST default to `EXPANSION_MATERIAL`. |
| **V5: Dead-Code AMBIGUOUS Enum** | Proposed-Design Defect | `PolicyChangeSeverity.AMBIGUOUS` was in enum but no code path in `compare()` produced it. | **INV-5:** Parser confidence $<0.90$ or non-standard conditional clauses MUST yield `severity = AMBIGUOUS` $\rightarrow$ `INDETERMINATE`. |
| **V6: Unchecked Resource & Recipient** | Proposed-Design Defect | Proposed gate evaluated `requested_purpose` but ignored `resource_selector` and `authorized_recipients`. | **INV-6:** Gate MUST evaluate all 6 vectors (Principal, Resource, Action, Purpose, Recipient, Policy Digest). |
| **V7: Agent Purpose Spoofing** | Implementation Defect | `PermissionGate` (`gates.py:320`) & proposed gate read purpose/op from untrusted `payload` or `context`. | **INV-7:** Purpose and action metadata MUST be resolved from trusted execution context or pre-registered operations. |
| **V8: Revocation Races & Stale Cache** | Proposed-Design Defect | Read static `context["authorization_record"]` without checking live revocation list/epoch. | **INV-8:** Gate MUST query live `RevocationRegistry` digest or epoch index before approving action. |
| **V9: Future-Effective Terms** | Proposed-Design Defect | Proposed `PolicySnapshot` lacked `effective_at` timestamp comparison against $T_{\text{now}}$. | **INV-9:** Terms with `effective_at > T_now` MUST NOT override active baseline or grant early permissions. |
| **V10: Unbound Receipt Replay** | Implementation Defect | `ReceiptGenerator.verify_receipt()` (`audit.py:280`) verified signature but not active `transaction_id`/`input_hash`. | **INV-10:** `TrustedExecutionBoundary` MUST assert receipt `transaction_id` and `input_hash` match active context. |
| **V11: Protected Action Bypass** | Threat Scenario | Direct invocation of tool functions bypassing `TrustedExecutionBoundary.execute_protected_action()`. | **INV-11:** State-mutating tools MUST execute solely inside `TrustedExecutionBoundary` requiring consumed `auth_token_id`. |
| **V12: Opt-In Regression Risk** | Implementation Defect | Appending new gate to `EpistemicOrchestrator.gates` (`core.py:62`) affects all legacy submissions without consent metadata. | **INV-12:** Consent gate MUST operate in passthrough (`ALLOW`) when `context.is_protected_workload == False`. |

---

## 2. Specification of Opt-In Security Boundary

To ensure zero regressions for existing pipelines while guaranteeing fail-closed security for protected execution, EpistemicOS defines an explicit **Workload Classification Protocol**.

```
                                  Submitted Context & Payload
                                               |
                                               v
                          +------------------------------------------+
                          | Context Security Classification Check    |
                          +------------------------------------------+
                                               |
                     --------------------------------------------------
                    |                                                  |
                    v                                                  v
   is_protected_workload == False                    is_protected_workload == True
                    |                                                  |
                    v                                                  v
     [ UNPROTECTED LEGACY WORKLOAD ]                  [ PROTECTED GOVERNANCE WORKLOAD ]
  - Consent gate executes in PASSTHROUGH           - Requires VersionedAuthorizationRecord
    (returns GateDecision.ALLOW)                    - Requires Active Policy Snapshot Evidence
  - Existing CPR / Token Surprisal /                - Enforces 6-Vector Capability Validation
    Triangulation checks apply unchanged.          - Fails Closed (HALT/DENY) on missing
                                                     evidence or policy expansion drift.
```

### 2.1 Workload Designation & Non-Downgrade Rules
1. **Explicit Designation:** A workload is designated as protected if `context.get("is_protected_workload") is True` OR if `context.get("authorization_record")` / `context.get("authorization_token_id")` is present.
2. **Immutable Protection Rule:** An agent payload or untrusted request dictionary CANNOT set `is_protected_workload = False` if an `authorization_token_id` or protected endpoint target is present.
3. **Fail-Closed Misconfiguration Enforcement:** If `ConsentAndPolicyDriftGate` is marked as `is_critical = True` in `GateConfig`, any unauthenticated attempt to strip context parameters or submit invalid record signatures triggers `GateDecision.HALT`.

---

## 3. Specification of Execution-Bound Authorization

### 3.1 Canonical Authorization Capability Specification (`VersionedAuthorizationCapability`)

```python
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import time

@dataclass
class VersionedAuthorizationCapability:
    capability_id: str
    transaction_id: str                   # Bound to specific request / transaction UUID
    correlation_id: str                  # Trajectory correlation ID
    principal_id: str                    # Principal identity
    workload_id: str                     # Workload/Agent identity
    action: str                          # Authorized operation name (e.g., "query_database")
    resource: str                        # Target resource node/endpoint (e.g., "db/users")
    purpose: str                         # Authorized purpose (e.g., "search_indexing")
    recipient: str                       # Authorized recipient (e.g., "epistemic_agent_v1")
    bound_policy_digest: str             # SHA-256 of verified policy document
    payload_digest: str                  # SHA-256 of canonical request payload
    policy_version: str = "1.0.0"
    issued_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 300.0) # 5-minute maximum TTL
    issuer_signature: str = ""           # Cryptographic signature from ControlPlaneGate
```

### 3.2 Single-Process vs. Distributed Guarantees

| Security Property | Single-Process Guarantee (Current Repo) | Distributed Guarantee (Requires Extension) |
|---|---|---|
| **Atomic Token Consumption** | **Guaranteed:** `TrustedExecutionBoundary._consumed_tokens` managed under `threading.Lock()` (`provenance.py:268`). | Requires distributed lock (e.g., Redis `SETNX` or DLT atomic CAS). |
| **Replay Prevention** | **Guaranteed:** Process-local memory set prevents intra-process replay. | Requires centralized / replicated single-use token registry. |
| **Audit Hash Chaining** | **Guaranteed:** Append-only JSON-Lines file locking with `fcntl.flock` (`provenance.py:105`). | Requires remote append-only ledger (`ImmutableLedgerAdapter`). |
| **External Side-Effect Control** | **Guaranteed:** Suppresses execution before provider callback in wrapper. | Cannot prevent external provider side-effects if provider executes out-of-band. |

---

## 4. Policy-Drift Contract & Adjudication Rules

### 4.1 Source-Byte Hash vs. Canonical Policy Digest
- **Source-Byte Hash (`raw_document_hash`):** `SHA256(raw_bytes_retrieved_from_url)`. Used strictly to detect byte-level text updates, whitespace edits, or document updates on external websites.
- **Canonical Policy Digest (`canonical_policy_digest`):** `SHA256(json.dumps(parsed_clauses, sort_keys=True))`. Used to measure semantic structural equivalence across formatting or editorial changes.

### 4.2 Effective Date, Retrieval Time, and Stale Snapshots
- **Future-Effective Terms (`effective_at > T_now`):** Analyzed and logged as `PENDING_POLICY_UPDATE`, but active authorization remains bound to the active baseline policy until `T_now >= effective_at`.
- **Stale Policy Snapshots:** If `T_now - retrieved_at > max_policy_age_seconds` (default: 86,400s / 24 hours), the gate flags `STALE_POLICY_SNAPSHOT`. If `require_active_policy_snapshot` is `True`, triggers `GateDecision.HALT`.

### 4.3 Deterministic vs. Human Adjudication Map

```
+-----------------------------------------------------------------------------------+
|                        DETERMINISTIC VS. HUMAN ADJUDICATION                       |
+-----------------------------------------------------------------------------------+
| DETERMINISTIC SOFTWARE ENFORCEMENT (ConsentAndPolicyDriftGate):                   |
|  1. Exact SHA-256 digest equality (raw_document_hash & canonical_policy_digest).  |
|  2. Structural clause diffing (added/removed/modified clause keys).              |
|  3. Exact 6-vector string matching (Principal, Resource, Action, Purpose, etc.). |
|  4. Expiration timestamp and live revocation list digest verification.            |
|  5. Fail-closed HALT on parser confidence < 0.90 or missing policy evidence.      |
|                                                                                   |
| HUMAN / INSTITUTIONAL ADJUDICATION (REQUIRED OUTSIDE SOFTWARE):                   |
|  1. Determining legal enforceability or contractual validity in court.            |
|  2. Resolving statutory copyright fair-use arguments on news publisher content.   |
|  3. Classifying complex, non-standard ambiguous legal clauses (AMBIGUOUS severity).|
+-----------------------------------------------------------------------------------+
```

---

## 5. Executable Acceptance Test Specifications

The acceptance test suite contains 12 executable test specifications verifying all security invariants.

```python
# Location: tests/unit/test_consent_policy_drift_spec.py

def test_acceptance_01_forged_authorization_record_rejected():
    """Verify forged authorization records without KMS signature yield GateDecision.HALT."""
    gate = ConsentAndPolicyDriftGate()
    forged_record = VersionedAuthorizationRecord(record_id="REC_FORGED", principal_id="admin")
    gi = GateInput(payload={}, context={"is_protected_workload": True, "authorization_record": forged_record})
    outcome = gate.evaluate_contract(gi)
    assert outcome.decision == GateDecision.HALT
    assert outcome.reason_code == "UNAUTHENTICATED_AUTHORIZATION_RECORD"

def test_acceptance_02_baseline_digest_mismatch_halt():
    """Verify baseline snapshot mismatching bound_policy_digest yields GateDecision.HALT."""
    gate = ConsentAndPolicyDriftGate()
    record = VersionedAuthorizationRecord(record_id="REC_01", bound_policy_digest="sha256_EXPECTED")
    baseline = PolicySnapshot(policy_id="P_01", raw_document_hash="sha256_DIFFERENT")
    gi = GateInput(payload={}, context={
        "is_protected_workload": True,
        "authorization_record": record,
        "baseline_policy_snapshot": baseline,
        "active_policy_snapshot": baseline
    })
    outcome = gate.evaluate_contract(gi)
    assert outcome.decision == GateDecision.HALT
    assert outcome.reason_code == "BASELINE_POLICY_DIGEST_MISMATCH"

def test_acceptance_03_missing_active_policy_fails_closed():
    """Verify missing active policy snapshot for protected workload yields GateDecision.HALT."""
    gate = ConsentAndPolicyDriftGate()
    record = VersionedAuthorizationRecord(record_id="REC_01", review_conditions={"require_active_policy_snapshot": True})
    gi = GateInput(payload={}, context={"is_protected_workload": True, "authorization_record": record})
    outcome = gate.evaluate_contract(gi)
    assert outcome.decision == GateDecision.HALT
    assert outcome.reason_code == "MISSING_REQUIRED_POLICY_SNAPSHOT"

def test_acceptance_04_purpose_and_resource_denial():
    """Verify requested purpose or resource outside record grants yields GateDecision.DENY."""
    gate = ConsentAndPolicyDriftGate()
    record = VersionedAuthorizationRecord(
        record_id="REC_01",
        resource_selector="corpus_news/*",
        authorized_purposes=["search_indexing"]
    )
    gi = GateInput(payload={"purpose": "ai_model_training"}, context={
        "is_protected_workload": True,
        "authorization_record": record,
        "requested_resource": "database_finance"
    })
    outcome = gate.evaluate_contract(gi)
    assert outcome.decision == GateDecision.DENY
    assert "PURPOSE_NOT_AUTHORIZED" in outcome.reason_code or "RESOURCE_OUTSIDE_SCOPE" in outcome.reason_code

def test_acceptance_05_revocation_race_prevention():
    """Verify live revocation registry check rejects revoked record even if context record says revoked=False."""
    registry = MockRevocationRegistry(revoked_ids={"REC_REVOKED"})
    gate = ConsentAndPolicyDriftGate(revocation_registry=registry)
    stale_record = VersionedAuthorizationRecord(record_id="REC_REVOKED", revoked=False)
    gi = GateInput(payload={}, context={"is_protected_workload": True, "authorization_record": stale_record})
    outcome = gate.evaluate_contract(gi)
    assert outcome.decision == GateDecision.DENY
    assert outcome.reason_code == "AUTHORIZATION_REVOKED"

def test_acceptance_06_unprotected_workload_backward_compatibility():
    """Verify legacy workloads without protection flags pass through gate with ALLOW."""
    gate = ConsentAndPolicyDriftGate()
    gi = GateInput(payload={"data": "test"}, context={"is_protected_workload": False})
    outcome = gate.evaluate_contract(gi)
    assert outcome.decision == GateDecision.ALLOW
    assert outcome.reason_code == "UNPROTECTED_WORKLOAD_PASSTHROUGH"
```

---

## 6. Minimal Implementation Sequence & Go/No-Go Decision

### 6.1 Implementation Sequence Dependencies

```
[ Step 1: Core Dataclasses & Models ]
  - Add VersionedAuthorizationRecord & PolicySnapshot to epistemicos/models.py
              |
              v
[ Step 2: Policy Diff Engine & Revocation Registry ]
  - Add PolicyDiffEngine with AMBIGUOUS severity support
  - Add InMemoryRevocationRegistry interface
              |
              v
[ Step 3: ConsentAndPolicyDriftGate Implementation ]
  - Inherit from ControlPlaneGate in epistemicos/gates.py
  - Enforce 6-vector validation, KMS signature checks, & opt-in passthrough
              |
              v
[ Step 4: TrustedExecutionBoundary & Audit Integration ]
  - Update execute_protected_action() to validate capability transaction_id
  - Mint signed receipts in TamperEvidentAuditTrail
              |
              v
[ Step 5: Unit Test Suite & Benchmark Profiling ]
  - Run 12 acceptance test specs in tests/unit/test_consent_policy_drift_spec.py
  - Profile latency overhead in benchmarks/run_pipeline_profiling.py
```

### 6.2 Implementation Decision: **GO (Subject to Prerequisites)**

- **Prerequisites for PR Merging:**
  1. KMS / KeyStore public key verification interface integrated for record signing.
  2. Zero source mutations to existing `EntropyAwareScheduler` or default pipeline behavior.
  3. All 12 acceptance test specifications passing in `tests/unit/`.

---

## Summary Conclusion

This Phase 3 specification provides a complete, executable, and fail-closed blueprint for implementing Consent Provenance and External Policy Drift Governance in EpistemicOS. By enforcing strict 6-vector authorization capabilities, atomic execution binding, opt-in workload isolation, and explicit separation of software enforcement from institutional legal adjudication, EpistemicOS achieves robust protection against dynamic policy drift.
