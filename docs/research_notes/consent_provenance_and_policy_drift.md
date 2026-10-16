# EpistemicOS Research Report: Consent Provenance and External Policy Drift Governance

**Author:** EpistemicOS Research & Security Architecture Team
**Date:** October 2026
**Document Version:** `1.0.0`
**Target Module Area:** `epistemicos/gates.py`, `epistemicos/provenance.py`, `epistemicos/audit.py`, `epistemicos/compliance.py`
**Status:** ARCHITECTURAL DESIGN & THREAT MODEL (NON-MUTATING RESEARCH PROPOSAL)

---

## Executive Summary

This research report investigates how EpistemicOS can be extended to support explicit, versioned authorization records and detect material drift in external service terms, API permissions, and data-use policies.

### Case Study Motivation: Meta's October 2026 Commercial-Terms Update
In October 2026, Meta updated its commercial terms and data-use policies governing content indexed across its platforms (as reported by Nieman Journalism Lab). The update shifted background default permissions regarding publisher content reuse, indexing, and AI training assertions. This event illustrates a fundamental problem in modern AI agent governance: **external service terms, API access grants, and consent declarations are dynamic and subject to retroactive or silent policy drift.**

**Crucial System Boundary:** EpistemicOS does **not** evaluate or decide legal enforceability. Legal enforceability is an unresolved, external institutional question that software cannot determine automatically. EpistemicOS provides deterministic authorization enforcement, cryptographic provenance tracking, and policy-drift delta verification. It treats vendor terms summaries, `robots.txt` files, or unverified AI policy scrapers as **untrusted claims**, requiring explicit, versioned, principal-backed authorization evidence.

### Core Architectural Finding
A pluggable governance gate (`ConsentAndPolicyDriftGate`) can be integrated into the existing EpistemicOS governance pipeline (`epistemicos/gates.py` and `epistemicos/core.py`) **without modifying the default `EntropyAwareScheduler` behavior** or weakening any existing security guarantees.

- **EntropyAwareScheduler Isolation:** `EntropyAwareScheduler` computes autoregressive token logprob decay, information yield, and trajectory convergence ($\Delta H_{\text{token}}$). Consent provenance and policy drift operate strictly at the control-plane boundary as a `ControlPlaneGate` prior to action execution.
- **Fail-Closed Governance:** Like `PermissionGate` and `CryptoAttestationGate`, missing policy evidence, expired consents, or unparseable policy diffs trigger an immediate `GateDecision.HALT` or `GateDecision.DENY` outcome, ensuring unverified or drifted actions cannot execute.

---

## 1. Phase 1: Repository Reconnaissance & Reusable Abstractions

An exhaustive audit of EpistemicOS identifies key existing abstractions that must be reused to prevent functionality duplication:

```
+-----------------------------------------------------------------------------------+
|                            EXISTING REUSABLE SUB-SYSTEMS                          |
+-----------------------------------------------------------------------------------+
| 1. Control-Plane Gate Abstraction (epistemicos/gates.py)                           |
|    - ControlPlaneGate, GateInput, GateConfig, GateOutcome, GateDecision, GateResult  |
| 2. Execution Provenance Subsystem (epistemicos/provenance.py)                     |
|    - ProvenanceEvent, ExecutionContext, LocalProvenanceStore, TrustedExecutionBoundary|
|    - ProvenanceReconciler, ProvenanceEventType, ProvenanceSource                 |
| 3. Tamper-Evident Audit Trail & Receipts (epistemicos/audit.py)                     |
|    - TamperEvidentAuditTrail, AuditEvent, ReceiptGenerator, _sanitize_sensitive_data|
| 4. Off-Chain Compliance & Ledger Anchoring (epistemicos/compliance.py)              |
|    - OffChainStoreAdapter, ImmutableLedgerAdapter, TransactionalComplianceBroker   |
| 5. Canonical Domain Model (epistemicos/models.py)                                 |
|    - CanonicalProblemRepresentation (CPR), BeliefObject                          |
+-----------------------------------------------------------------------------------+
```

### 1.1 Gate Interfaces and Gate Composition
In `epistemicos/gates.py`:
- `ControlPlaneGate`: Abstract base class enforcing the typed `evaluate_contract(gate_input: GateInput) -> GateOutcome` interface.
- `evaluate_safe(gate_input: GateInput)`: Wraps gate execution in a try-except block, failing closed (`GateDecision.HALT`) on unhandled exceptions if `config.is_critical` is `True`.
- Decision outcomes utilize `GateDecision` (`ALLOW`, `DENY`, `HALT`, `INDETERMINATE`).
- Backward compatibility with `EpistemicOrchestrator` is maintained via `outcome.to_gate_result()`, returning a `GateResult` where `passed` is `True` strictly when `decision == GateDecision.ALLOW`.

### 1.2 PermissionGate & Scope Resolution
`PermissionGate` in `epistemicos/gates.py` provides crucial patterns for scope resolution and action matching:
- **Scope Resolution Priority:** Prioritizes explicit `self.trusted_scope` (gate config) and `context.get("trusted_scope")` over unauthenticated request payload dictionaries.
- **Action Schema Validation:** Enforces non-empty `op` (operation) and `node`/`endpoint` (target resource) fields.
- **Fail-Closed Execution:** Halts if executable operation identities do not match trusted operation registries.

### 1.3 Provenance and Cryptographic Receipts
In `epistemicos/provenance.py` and `epistemicos/audit.py`:
- `ProvenanceEvent`: Records schema-versioned, sequence-numbered events linked via SHA-256 hash chains (`prev_hash`).
- `TrustedExecutionBoundary`: Enforces single-use consumption of `authorization_token_id` values under thread locks (`threading.Lock`), preventing replay attacks.
- `ReceiptGenerator`: Mints signed receipts (`HMAC-SHA256` or `SHA256`) binding `input_hash`, configuration, `gate_version`, decision details, and execution outcomes.
- `ReceiptGenerator.verify_receipt()`: Strict fail-closed receipt verification rejecting unknown fields, mismatched algorithms, or invalid signatures.

### 1.4 Off-Chain Data and Right to Be Forgotten
In `epistemicos/compliance.py`:
- `TransactionalComplianceBroker`: Coordinates mutable off-chain PII storage (`OffChainStoreAdapter`) and immutable block commitment (`ImmutableLedgerAdapter`).
- `execute_right_to_be_forgotten`: Enforces IDOR checks via `requestor_id` vs `owner_id` and utilizes safe file-descriptor handling (`os.open(..., os.O_RDWR | os.O_NOFOLLOW)`) to prevent Time-of-Check/Time-of-Use (TOCTOU) symlink attacks.

---

## 2. Phase 2: Threat Model and Trust-Boundary Architecture

### 2.1 Threat Model Matrix

| Threat Code | Threat Description | Attack Vector / Failure Mode | Mitigating System Mechanism |
|---|---|---|---|
| **T1** | **Silent Expansion of Authorized Data Uses** | External service quietly expands terms (e.g., Meta Oct 2026 update) to permit AI model training or data resale without principal consent. | `PolicyDiffEngine` compares active external policy snapshot hash against `VersionedAuthorizationRecord.effective_scope`. Triggers `POLICY_DRIFT_EXPANSION_DETECTED` and halts execution. |
| **T2** | **Stale Authorization and Revocation Failures** | Principal revokes consent or authorization expires, but agent continues executing actions using cached credentials or legacy approvals. | `ConsentAndPolicyDriftGate` checks `expires_at` timestamp and queries `revocation_list` digest before every step. Expired/revoked approvals yield `GateDecision.DENY`. |
| **T3** | **Ambiguous or Misleading TOS Summaries** | Vendor or third-party LLM scraper generates an overly favorable or ambiguous legal summary masking restrictions. | System strictly rejects unverified summaries. External terms require explicit, machine-readable `PolicySnapshot` with cryptographic source provenance and structural schema parsing. Ambiguity yields `GateDecision.INDETERMINATE` / `HALT`. |
| **T4** | **Forged or Incomplete Policy Evidence** | Adversary supplies synthetic or altered terms-of-service evidence matching required authorization hashes. | Evidence must include a verifiable cryptographic signature from a trusted policy authority or be anchored to an immutable ledger (`ImmutableLedgerAdapter`). |
| **T5** | **Permission vs Contract Conflicts** | Technical API access token succeeds, but contractual or organizational permissions forbid the specific action or purpose. | `ConsentAndPolicyDriftGate` evaluates purpose (`authorized_purposes`) and recipient constraints independently of technical API scope. Technical success without contractual alignment is blocked. |
| **T6** | **Time-of-Check / Time-of-Use (TOCTOU) Races** | Policy terms or consent records are modified or swapped in the microsecond interval between gate check and action execution. | `TrustedExecutionBoundary` binds `authorized_digest` to `authorization_token_id`. Payload or policy digest changes at execution time trigger immediate execution failure. |
| **T7** | **Unauthorized Reuse of Approved Receipts** | Attacker captures a valid signed decision receipt from a prior session and re-submits it to authorize a new transaction. | Receipts bind single-use `transaction_id`, `correlation_id`, and `input_hash`. `TrustedExecutionBoundary` atomically tracks and rejects consumed token IDs. |

### 2.2 Trust-Boundary Diagram

```
+---------------------------------------------------------------------------------------------------+
|                                      UNTRUSTED ENVIRONMENT                                        |
|  +---------------------------+       +-----------------------------------+                         |
|  | Agent / LLM Tool Adapter  |       | External Provider (e.g., Meta API)|                         |
|  | - Action Proposals        |       | - Dynamic Terms / Policy Scraping |                         |
|  +---------------------------+       +-----------------------------------+                         |
+-----------------------------------------------|---------------------------------------------------+
                                                | Boundary Crossing: GateInput (payload, context)
                                                v
+---------------------------------------------------------------------------------------------------+
|                                  EPISTEMICOS TRUSTED CONTROL PLANE                                |
|                                                                                                   |
|  +---------------------------------------------------------------------------------------------+  |
|  | ConsentAndPolicyDriftGate (ControlPlaneGate)                                                |  |
|  |                                                                                             |  |
|  |  1. Validate VersionedAuthorizationRecord (Principal, Resource, Purpose, Expiry, Revocation) |  |
|  |  2. Invoke PolicyDiffEngine (Compare Active PolicySnapshot vs Bound PolicyDigest)          |  |
|  |  3. Detect Material Scope/Purpose Expansion or Term Ambiguity                               |  |
|  |  4. Yield GateOutcome (ALLOW / DENY / HALT / INDETERMINATE)                                  |  |
|  +---------------------------------------------------------------------------------------------+  |
|                                                |                                                  |
|                                                v                                                  |
|  +---------------------------------------------------------------------------------------------+  |
|  | TrustedExecutionBoundary & LocalProvenanceStore                                             |  |
|  | - Single-Use Token Consumption (threading.Lock)                                             |  |
|  | - Atomic Payload Digest Verification (TOCTOU Defense)                                       |  |
|  | - Append-Only SHA-256 Hash Chain Logging (ProvenanceEvent)                                 |  |
|  +---------------------------------------------------------------------------------------------+  |
|                                                |                                                  |
|                                                v                                                  |
|  +---------------------------------------------------------------------------------------------+  |
|  | TamperEvidentAuditTrail & ReceiptGenerator                                                  |  |
|  | - Signed Decision Receipts (HMAC-SHA256)                                                    |  |
|  | - PII Sanitization (_sanitize_sensitive_data)                                               |  |
|  +---------------------------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------------------------+
```

---

## 3. System Design: Interfaces and Data Schemas

The proposed abstractions are lightweight, strongly typed Python dataclasses adhering strictly to existing EpistemicOS conventions.

### 3.1 Versioned Authorization Record (`VersionedAuthorizationRecord`)

```python
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import time

@dataclass
class VersionedAuthorizationRecord:
    """
    Explicit, versioned consent record defining principal-backed boundaries.
    """
    record_id: str
    schema_version: str = "1.0.0"
    principal_id: str = ""                # E.g., "user_123" or "org_publisher_a"
    resource_selector: str = ""           # E.g., "article_corpus/*" or "api/v1/content"
    authorized_actions: List[str] = field(default_factory=list)  # ["read", "index"]
    authorized_purposes: List[str] = field(default_factory=list) # ["search_indexing", "summarization"]
    prohibited_purposes: List[str] = field(default_factory=list) # ["ai_model_training", "third_party_resale"]
    authorized_recipients: List[str] = field(default_factory=list)# ["epistemic_agent_v2"]
    bound_policy_version: str = ""        # Hash or version of external terms at consent time
    bound_policy_digest: str = ""         # SHA-256 digest of verified policy document
    issued_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None     # Unix timestamp expiration
    revoked: bool = False
    revocation_reason: Optional[str] = None
    review_conditions: Dict[str, Any] = field(default_factory=dict) # E.g., {"re_evaluate_on_policy_change": True}
    cryptographic_signature: Optional[str] = None # Signature from approving authority

    def is_valid_at(self, timestamp: Optional[float] = None) -> bool:
        ts = timestamp if timestamp is not None else time.time()
        if self.revoked:
            return False
        if self.expires_at is not None and ts >= self.expires_at:
            return False
        return True
```

### 3.2 Policy Snapshot and Policy Diff Engine (`PolicyDiffEngine`)

```python
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from enum import Enum
import hashlib
import json

class PolicyChangeSeverity(Enum):
    NONE = "NONE"
    EDITORIAL = "EDITORIAL"             # Formatting, non-substantive text edits
    RESTRICTION_ADDED = "RESTRICTION_ADDED" # External terms became more restrictive
    EXPANSION_MATERIAL = "EXPANSION_MATERIAL" # Terms expanded permitted uses or added forced consent
    AMBIGUOUS = "AMBIGUOUS"             # Clause semantics cannot be deterministically resolved

@dataclass
class PolicySnapshot:
    policy_id: str
    provider_id: str                     # E.g., "meta_commercial_terms"
    version: str                         # E.g., "2026-10-15"
    retrieved_at: float
    source_url: str
    raw_document_hash: str
    parsed_clauses: Dict[str, Any]       # Map of clause_key -> clause_definition
    provenance_attestation: Dict[str, Any]# Signature/attestation of retriever

@dataclass
class PolicyDiffResult:
    is_material: bool
    severity: PolicyChangeSeverity
    baseline_digest: str
    active_digest: str
    added_clauses: List[str]
    removed_clauses: List[str]
    modified_clauses: Dict[str, Dict[str, Any]] # clause_key -> {"old": ..., "new": ...}
    expanded_purposes_detected: List[str]
    summary_reason: str


class PolicyDiffEngine:
    """
    Identifies material policy drift between baseline consent snapshots and active vendor policies.
    """
    def compare(self, baseline: PolicySnapshot, active: PolicySnapshot) -> PolicyDiffResult:
        if baseline.raw_document_hash == active.raw_document_hash:
            return PolicyDiffResult(
                is_material=False,
                severity=PolicyChangeSeverity.NONE,
                baseline_digest=baseline.raw_document_hash,
                active_digest=active.raw_document_hash,
                added_clauses=[],
                removed_clauses=[],
                modified_clauses={},
                expanded_purposes_detected=[],
                summary_reason="Policy snapshots are identical"
            )

        added = []
        removed = []
        modified = {}
        expanded_purposes = []

        baseline_clauses = baseline.parsed_clauses or {}
        active_clauses = active.parsed_clauses or {}

        for k, v in active_clauses.items():
            if k not in baseline_clauses:
                added.append(k)
                if isinstance(v, dict) and v.get("grants_data_use"):
                    expanded_purposes.append(v.get("purpose", k))
            elif baseline_clauses[k] != v:
                modified[k] = {"old": baseline_clauses[k], "new": v}
                if isinstance(v, dict) and v.get("expanded_scope"):
                    expanded_purposes.append(v.get("purpose", k))

        for k in baseline_clauses:
            if k not in active_clauses:
                removed.append(k)

        is_material = len(expanded_purposes) > 0 or len(modified) > 0 or len(removed) > 0
        severity = PolicyChangeSeverity.EXPANSION_MATERIAL if expanded_purposes else (
            PolicyChangeSeverity.RESTRICTION_ADDED if is_material else PolicyChangeSeverity.EDITORIAL
        )

        return PolicyDiffResult(
            is_material=is_material,
            severity=severity,
            baseline_digest=baseline.raw_document_hash,
            active_digest=active.raw_document_hash,
            added_clauses=added,
            removed_clauses=removed,
            modified_clauses=modified,
            expanded_purposes_detected=expanded_purposes,
            summary_reason=f"Detected {len(expanded_purposes)} expanded purpose grants and {len(modified)} clause modifications."
        )
```

### 3.3 Pluggable Governance Gate (`ConsentAndPolicyDriftGate`)

```python
from epistemicos.gates import ControlPlaneGate, GateInput, GateOutcome, GateDecision, GateConfig
import time

class ConsentAndPolicyDriftGate(ControlPlaneGate):
    """
    Pluggable control-plane gate evaluating consent record validity and detecting external policy drift.
    """
    def __init__(
        self,
        diff_engine: Optional[PolicyDiffEngine] = None,
        config: Optional[GateConfig] = None
    ):
        super().__init__(config=config or GateConfig(version="1.0.0", is_critical=True))
        self.diff_engine = diff_engine or PolicyDiffEngine()

    def evaluate_contract(self, gate_input: GateInput) -> GateOutcome:
        t0 = time.perf_counter()
        context = gate_input.context
        payload = gate_input.payload

        # 1. Retrieve VersionedAuthorizationRecord from trusted context
        auth_record: Optional[VersionedAuthorizationRecord] = context.get("authorization_record")
        active_policy: Optional[PolicySnapshot] = context.get("active_policy_snapshot")
        baseline_policy: Optional[PolicySnapshot] = context.get("baseline_policy_snapshot")

        # Missing authorization record yields immediate HALT
        if not auth_record:
            return GateOutcome(
                decision=GateDecision.HALT,
                reason_code="MISSING_AUTHORIZATION_RECORD",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={"status": "HALTED", "error": "No versioned authorization record supplied in trusted context"},
                latency_ms=(time.perf_counter() - t0) * 1000.0
            )

        # 2. Check Expiry and Revocation
        if auth_record.revoked:
            return GateOutcome(
                decision=GateDecision.DENY,
                reason_code="AUTHORIZATION_REVOKED",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={"revocation_reason": auth_record.revocation_reason},
                latency_ms=(time.perf_counter() - t0) * 1000.0
            )

        if not auth_record.is_valid_at():
            return GateOutcome(
                decision=GateDecision.DENY,
                reason_code="AUTHORIZATION_EXPIRED",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={"expires_at": auth_record.expires_at},
                latency_ms=(time.perf_counter() - t0) * 1000.0
            )

        # 3. Action Purpose Verification
        requested_purpose = context.get("requested_purpose") or payload.get("purpose")
        if requested_purpose:
            if requested_purpose in auth_record.prohibited_purposes:
                return GateOutcome(
                    decision=GateDecision.DENY,
                    reason_code=f"PURPOSE_EXPLICITLY_PROHIBITED: '{requested_purpose}'",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={"prohibited_purposes": auth_record.prohibited_purposes},
                    latency_ms=(time.perf_counter() - t0) * 1000.0
                )

            if auth_record.authorized_purposes and requested_purpose not in auth_record.authorized_purposes:
                return GateOutcome(
                    decision=GateDecision.DENY,
                    reason_code=f"PURPOSE_NOT_AUTHORIZED: '{requested_purpose}'",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={"authorized_purposes": auth_record.authorized_purposes},
                    latency_ms=(time.perf_counter() - t0) * 1000.0
                )

        # 4. External Policy Drift Analysis
        if active_policy and baseline_policy:
            diff = self.diff_engine.compare(baseline_policy, active_policy)
            if diff.severity == PolicyChangeSeverity.AMBIGUOUS:
                return GateOutcome(
                    decision=GateDecision.INDETERMINATE,
                    reason_code="AMBIGUOUS_POLICY_DRIFT_DETECTED",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={"diff": diff.__dict__},
                    latency_ms=(time.perf_counter() - t0) * 1000.0
                )

            if diff.is_material and diff.severity == PolicyChangeSeverity.EXPANSION_MATERIAL:
                return GateOutcome(
                    decision=GateDecision.HALT,
                    reason_code=f"MATERIAL_POLICY_DRIFT_EXPANSION: {diff.summary_reason}",
                    gate_name=self.gate_name,
                    gate_version=self.config.version,
                    evidence={"diff": diff.__dict__, "expanded_purposes": diff.expanded_purposes_detected},
                    latency_ms=(time.perf_counter() - t0) * 1000.0
                )

        # 5. Missing Policy Snapshot Evidence when required by review conditions
        if auth_record.review_conditions.get("require_active_policy_snapshot") and not active_policy:
            return GateOutcome(
                decision=GateDecision.HALT,
                reason_code="MISSING_REQUIRED_POLICY_SNAPSHOT",
                gate_name=self.gate_name,
                gate_version=self.config.version,
                evidence={"status": "HALTED"},
                latency_ms=(time.perf_counter() - t0) * 1000.0
            )

        return GateOutcome(
            decision=GateDecision.ALLOW,
            reason_code="CONSENT_AND_POLICY_DRIFT_VALIDATED",
            gate_name=self.gate_name,
            gate_version=self.config.version,
            evidence={"record_id": auth_record.record_id, "bound_policy_version": auth_record.bound_policy_version},
            latency_ms=(time.perf_counter() - t0) * 1000.0
        )
```

---

## 4. Phase 3: Evaluation & Adversarial Test Matrix

To rigorously test the proposed capability, a 10-scenario adversarial test suite is defined.

| Test Case | Inputs / Initial State | Injected Adversarial Condition | Expected Gate Outcome | Expected Reason Code | Falsification Criteria |
|---|---|---|---|---|---|
| **TC1: Unchanged Terms** | Active policy snapshot hash matches baseline hash exactly. Valid active consent record. | Normal execution request. | `GateDecision.ALLOW` | `CONSENT_AND_POLICY_DRIFT_VALIDATED` | Gate halts or denies despite unchanged policies. |
| **TC2: Unilateral Data-Use Purpose Expansion** | Meta Oct 2026 update added forced AI model training consent. | Active policy snapshot introduces new `ai_model_training` grant clause. | `GateDecision.HALT` | `MATERIAL_POLICY_DRIFT_EXPANSION` | Gate allows action without flagging material purpose expansion. |
| **TC3: Expanded Access Scope** | Vendor API scope expanded from `read_public` to `read_private_contacts`. | Action attempts to access private endpoint without updated principal record. | `GateDecision.HALT` | `PERMISSION_SCOPE_VALIDATED` (blocked by scope mismatch) | Gate allows access based solely on vendor technical scope expansion. |
| **TC4: Ambiguous Legal Clause** | External terms modified with conflicting or non-parseable indemnification clause. | `PolicyDiffEngine` marks clause severity as `AMBIGUOUS`. | `GateDecision.INDETERMINATE` | `AMBIGUOUS_POLICY_DRIFT_DETECTED` | System defaults to `ALLOW` on unresolvable clause semantics. |
| **TC5: Stale Consent Approval** | Consent record timestamp `expires_at = T_now - 100s`. | Agent submits request using expired consent ID. | `GateDecision.DENY` | `AUTHORIZATION_EXPIRED` | Expired approval passes gate check. |
| **TC6: Explicit Consent Revocation** | Principal sets `revoked = True` in consent record. | Agent attempts action 1 second post-revocation. | `GateDecision.DENY` | `AUTHORIZATION_REVOKED` | Action executes after revocation flag is written. |
| **TC7: Forged Policy Evidence Signature** | Policy snapshot attestation contains invalid RSA/HMAC signature. | Adversary alters `parsed_clauses` text while retaining old signature. | `GateDecision.HALT` | `GATE_EXECUTION_ERROR` or signature failure | Forged policy snapshot is accepted as valid baseline. |
| **TC8: Technical vs Contract Conflict** | Technical API token permits `HTTP POST /export`, but contract forbids commercial reuse. | Request header succeeds on API server; purpose is `commercial_resale`. | `GateDecision.DENY` | `PURPOSE_EXPLICITLY_PROHIBITED` | Technical API success overrides contractual purpose prohibition. |
| **TC9: Future Effective Date** | Vendor terms state update becomes effective on `T_future = T_now + 30 days`. | Agent attempts action governed by future terms before effective date. | `GateDecision.ALLOW` (governed by active baseline) or `HALT` if unhandled | `CONSENT_AND_POLICY_DRIFT_VALIDATED` | System enforces future restrictions prematurely or accepts future grants early. |
| **TC10: Replay of Approving Receipt** | Re-submitting a previously minted signed decision receipt from session `S1` into session `S2`. | Replayed `transaction_id` and token ID submitted to `TrustedExecutionBoundary`. | `PermissionError` in `TrustedExecutionBoundary` | `Token already consumed` | Replayed receipt executes protected action in new session. |

### 4.1 Evaluation Metrics

1. **Unauthorized-Action Prevention Rate ($100\%$ Target):** Fraction of unauthorized/drifted requests correctly blocked (`DENY` or `HALT`).
2. **False Block Rate ($<1.0\%$ Target):** Fraction of valid, non-drifted requests incorrectly halted.
3. **Missed Scope Expansion Rate ($0.0\%$ Target):** Fraction of material terms expansions that bypass detection.
4. **Latency Overhead ($<5.0\text{ ms}$ Target):** Additional latency added to `EpistemicOrchestrator.process_submission`.
5. **Audit Reconstruction Fidelity ($100\%$ Target):** Success rate of reconstructing exact decision context from `TamperEvidentAuditTrail` and signed receipts.

### 4.2 Deterministic vs. Human Adjudication Boundary

```
+-----------------------------------------------------------------------------------+
|                        SYSTEM BOUNDARY & ADJUDICATION MAP                         |
+-----------------------------------------------------------------------------------+
| DETERMINISTICALLY EXECUTED BY EPISTEMICOS SOFTWARE:                              |
|   1. Hash equivalence checks on PolicySnapshot documents.                         |
|   2. Structural clause diffing (added/removed/modified keys).                    |
|   3. Expiration timestamp and explicit revocation flag checks.                    |
|   4. Exact purpose and resource string matching against authorization records.    |
|   5. Single-use token consumption and atomic payload digest validation.           |
|   6. Cryptographic receipt verification and append-only hash chain logging.        |
|                                                                                   |
| REQUIRES INDEPENDENT HUMAN / LEGAL ADJUDICATION (EXTERNAL TO SOFTWARE):           |
|   1. Determining whether a contract clause is legally enforceable in court.       |
|   2. Resolving statutory copyright fair-use arguments on news publisher content.   |
|   3. Evaluating jurisdiction-specific breach-of-contract liabilities.             |
+-----------------------------------------------------------------------------------+
```

---

## 5. Integration Plan and Touchpoints

The proposal integrates seamlessly into the existing repository structure:

```
epistemicos/
├── gates.py                  <-- Add ConsentAndPolicyDriftGate class definition
├── provenance.py             <-- Reused without breaking changes
├── audit.py                  <-- Reused for receipt generation and logging
├── compliance.py             <-- Reused for off-chain consent/PII management
└── core.py                   <-- Register ConsentAndPolicyDriftGate in EpistemicOrchestrator.gates
```

### 5.1 Registration in `EpistemicOrchestrator` (`epistemicos/core.py`)

In `EpistemicOrchestrator.__init__`:
```python
# Initialize Governance Gates in priority order
self.gates = [
    PermissionGate(),
    ConsentAndPolicyDriftGate(), # <-- Pluggable consent and policy drift gate
    EntropyGate(z_threshold=1.5, window_size=10),
    TriangulationGate()
]
```

---

## 6. Minimal Implementation Proposal & Explicit Non-Goals

### 6.1 Proposed Minimal Scope
1. Implement `VersionedAuthorizationRecord` and `PolicySnapshot` dataclasses in `epistemicos/models.py` or `epistemicos/gates.py`.
2. Implement `PolicyDiffEngine` for exact structural and hash-based policy diffing in a new or gate module.
3. Implement `ConsentAndPolicyDriftGate` inheriting from `ControlPlaneGate` in `epistemicos/gates.py`.
4. Add unit tests in `tests/unit/test_consent_policy_drift.py` covering all 10 adversarial test scenarios.

### 6.2 Explicit Non-Goals
- **No Natural Language LLM Scraping in Gate Critical Path:** The gate does not perform live, non-deterministic LLM summarization of web legal pages. All policy snapshots must be pre-parsed into deterministic JSON clause structures before gate evaluation.
- **No Automated Legal Claims:** The system does not generate legal opinions or assert enforceability.
- **No Mutation of `EntropyAwareScheduler`:** The scheduler remains entirely untouched.
- **No Modification of Default Production Execution Loop in this Phase:** This report and design proposal introduce zero mutations to existing codebase source files during this research phase.

---

## Conclusion & Next Steps

This research report establishes that EpistemicOS can natively support explicit, versioned authorization records and detect dynamic external policy drift. By leveraging existing abstractions (`ControlPlaneGate`, `TrustedExecutionBoundary`, `ReceiptGenerator`, and `TransactionalComplianceBroker`), the proposed `ConsentAndPolicyDriftGate` provides fail-closed security against unconsented data uses while preserving the mathematical independence of the core `EntropyAwareScheduler`.
